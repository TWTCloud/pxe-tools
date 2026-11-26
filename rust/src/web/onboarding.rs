// SPDX-License-Identifier: LGPL-3.0-only

mod image_setup;

use super::{
    admin::escape,
    images, plain,
    setup::redirect,
    ui::{self, WizardStep},
    ErrorBox, Reply,
};
use crate::{connect, pxe::parse_subnet, setting};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, path::Path};

const NETWORK_DRAFT: &str = "rust_wizard_network";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Console,
    External,
    Proxy,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Network {
    role: Role,
    interface: String,
    address: Ipv4Addr,
    subnet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy_subnet: Option<String>,
}

impl Network {
    pub(super) fn parse(fields: &HashMap<String, String>) -> Option<Self> {
        let role = match field(fields, "role") {
            "console" => Role::Console,
            "external" => Role::External,
            "proxy" => Role::Proxy,
            _ => return None,
        };
        if role == Role::Console {
            return Some(Self {
                role,
                interface: String::new(),
                address: Ipv4Addr::UNSPECIFIED,
                subnet: String::new(),
                proxy_subnet: None,
            });
        }
        let detected = field(fields, "network_address");
        let (interface, address, subnet) = if detected.is_empty() {
            (
                field(fields, "pxe_interface").to_owned(),
                field(fields, "pxe_ip").parse::<Ipv4Addr>().ok()?,
                field(fields, "pxe_subnet").to_owned(),
            )
        } else {
            detected_networks()
                .into_iter()
                .find(|(interface, address, _)| format!("{interface}|{address}") == detected)?
        };
        let (network, mask) = parse_subnet(&subnet)?;
        if address.is_unspecified()
            || address.is_multicast()
            || address.is_broadcast()
            || u32::from(address) & mask != network
            || (mask.count_ones() <= 30
                && (u32::from(address) == network || u32::from(address) == (network | !mask)))
        {
            return None;
        }
        let plan = Self {
            role,
            interface,
            address,
            subnet: format!("{}/{}", Ipv4Addr::from(network), mask.count_ones()),
            proxy_subnet: if role == Role::Proxy && !field(fields, "dhcp_proxy_cidr").is_empty() {
                let (network, mask) = parse_subnet(field(fields, "dhcp_proxy_cidr"))?;
                if u32::from(address) & mask != network {
                    return None;
                }
                Some(format!("{}/{}", Ipv4Addr::from(network), mask.count_ones()))
            } else {
                None
            },
        };
        plan.assigned().then_some(plan)
    }

    pub(super) fn current(db: &Connection) -> rusqlite::Result<Self> {
        let address = setting(db, "pxe_ip")?
            .parse()
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let enabled = setting(db, "pxe_enabled")?;
        let role = if enabled == "off" || (enabled.is_empty() && address.is_unspecified()) {
            Role::Console
        } else if setting(db, "dhcp_proxy_enabled")? == "on" {
            Role::Proxy
        } else {
            Role::External
        };
        let proxy = setting(db, "dhcp_proxy_network")?;
        let proxy_subnet = proxy
            .parse::<Ipv4Addr>()
            .ok()
            .zip(setting(db, "dhcp_proxy_netmask")?.parse::<Ipv4Addr>().ok())
            .and_then(|(network, mask)| {
                let mask = u32::from(mask);
                (mask.leading_ones() == mask.count_ones())
                    .then(|| format!("{network}/{}", mask.count_ones()))
            });
        Ok(Self {
            role,
            interface: setting(db, "pxe_interface")?,
            address,
            subnet: setting(db, "pxe_subnet")?,
            proxy_subnet,
        })
    }

    pub(super) fn enabled(&self) -> bool {
        self.role != Role::Console
    }

    pub(super) fn save(&self, db: &Connection) -> Result<(), ErrorBox> {
        if self.enabled() {
            store(db, "pxe_interface", &self.interface)?;
            store(db, "pxe_ip", &self.address.to_string())?;
            store(db, "pxe_subnet", &self.subnet)?;
            store(db, "network_override", "off")?;
        }
        if self.role == Role::Proxy {
            let (network, mask) =
                parse_subnet(self.proxy_subnet.as_deref().unwrap_or(&self.subnet))
                    .ok_or("Invalid staged DHCP proxy subnet")?;
            store(
                db,
                "dhcp_proxy_network",
                &Ipv4Addr::from(network).to_string(),
            )?;
            store(db, "dhcp_proxy_netmask", &Ipv4Addr::from(mask).to_string())?;
        }
        store(db, "pxe_enabled", if self.enabled() { "on" } else { "off" })?;
        store(
            db,
            "dhcp_proxy_enabled",
            if self.role == Role::Proxy {
                "on"
            } else {
                "off"
            },
        )?;
        Ok(())
    }

    fn assigned(&self) -> bool {
        if self.role == Role::Console {
            return true;
        }
        #[cfg(target_os = "linux")]
        return super::validate_interface(self.address, &self.interface).is_ok();
        #[cfg(not(target_os = "linux"))]
        false
    }
}

fn detected_networks() -> Vec<(String, Ipv4Addr, String)> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let Ok(output) = std::process::Command::new("/usr/bin/ip")
        .args(["-j", "-4", "addr", "show", "up"])
        .output()
    else {
        return Vec::new();
    };
    let Ok(links) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) else {
        return Vec::new();
    };
    let mut choices = Vec::new();
    for link in links {
        let (Some(interface), Some(addresses)) =
            (link["ifname"].as_str(), link["addr_info"].as_array())
        else {
            continue;
        };
        for entry in addresses {
            let (Some(address), Some(prefix)) = (
                entry["local"]
                    .as_str()
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
                entry["prefixlen"].as_u64(),
            ) else {
                continue;
            };
            if entry["family"] == "inet"
                && prefix <= 32
                && !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && address.octets()[0] < 240
            {
                choices.push((interface.to_owned(), address, format!("{address}/{prefix}")));
            }
        }
    }
    choices
}

pub(super) fn is_route(path: &str) -> bool {
    matches!(
        path,
        "/init/network" | "/init/images" | "/init/images/status" | "/init/done" | "/init/complete"
    )
}

pub(super) fn serve(db: &Connection, path: &Path, endpoint: &str, form: Option<&[u8]>) -> Reply {
    let reply = if let Some(data) = form {
        let mut values = HashMap::new();
        for (field, value) in form_urlencoded::parse(data) {
            if values
                .insert(field.into_owned(), value.into_owned())
                .is_some()
            {
                return invalid(endpoint, "Le formulaire est ambigu.");
            }
        }
        change(path, endpoint, &values)
    } else {
        view(db, endpoint)
    };
    reply.unwrap_or_else(|error| {
        eprintln!("Rust onboarding: {error}");
        plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "Configuration initiale indisponible\n",
        )
    })
}

fn pending(db: &Connection) -> rusqlite::Result<bool> {
    Ok(setting(db, "db_init_done")? == "1"
        && setting(db, "wizard_completed")? != "1"
        && setting(db, "pxe_enabled")? != "on")
}

fn draft(db: &Connection) -> Result<Option<Network>, ErrorBox> {
    let saved = setting(db, NETWORK_DRAFT)?;
    if saved.is_empty() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&saved)?))
}

fn field<'a>(fields: &'a HashMap<String, String>, name: &str) -> &'a str {
    fields.get(name).map_or("", |value| value.trim())
}

fn view(db: &Connection, endpoint: &str) -> Result<Reply, ErrorBox> {
    if !pending(db)? {
        return Ok(redirect(StatusCode::FOUND, "/admin/inventaire"));
    }
    let plan = draft(db)?;
    if endpoint == "/init/network" {
        return Ok(network_page(plan.as_ref()));
    }
    let Some(plan) = plan else {
        return Ok(redirect(StatusCode::FOUND, "/init/network"));
    };
    match endpoint {
        "/init/images" if plan.role != Role::Console => image_setup::page(db),
        "/init/images/status" if plan.role != Role::Console => image_setup::status(db),
        "/init/images" => Ok(redirect(StatusCode::FOUND, "/init/done")),
        "/init/done" => done_page(db, &plan),
        _ => Ok(plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed\n",
        )),
    }
}

fn change(
    path: &Path,
    endpoint: &str,
    fields: &HashMap<String, String>,
) -> Result<Reply, ErrorBox> {
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !pending(&tx)? {
        return Ok(plain(
            StatusCode::CONFLICT,
            "La configuration initiale est terminée.\n",
        ));
    }
    if endpoint == "/init/network" {
        let Some(plan) = Network::parse(fields) else {
            return Ok(invalid(endpoint, "Sélectionnez une interface, une adresse IPv4 attribuée et un sous-réseau cohérent."));
        };
        store(&tx, NETWORK_DRAFT, &serde_json::to_string(&plan)?)?;
        let next = if plan.role == Role::Console {
            "/init/done"
        } else {
            if image_setup::needs_catalog(&tx)? {
                images::refresh_catalog(&tx)?;
            }
            "/init/images"
        };
        tx.commit()?;
        return Ok(redirect(StatusCode::SEE_OTHER, next));
    }
    let Some(plan) = draft(&tx)? else {
        return Ok(redirect(StatusCode::SEE_OTHER, "/init/network"));
    };
    if endpoint == "/init/images" && plan.role != Role::Console {
        let reply = image_setup::submit(&tx, fields)?;
        tx.commit()?;
        return Ok(reply);
    }
    if endpoint != "/init/complete" {
        return Ok(plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed\n",
        ));
    }
    if field(fields, "confirmation") != "yes" {
        return Ok(invalid(
            endpoint,
            "Confirmez la configuration affichée avant de l’appliquer.",
        ));
    }
    if !plan.assigned() {
        return Ok(invalid(
            "/init/network",
            "L’adresse IPv4 sélectionnée a changé. Confirmez de nouveau le réseau.",
        ));
    }
    // Bind the confirmation to the exact staged network and image.
    if field(fields, "plan") != serde_json::to_string(&plan)? {
        return Ok(invalid(
            endpoint,
            "Le réseau a changé depuis l’affichage du récapitulatif.",
        ));
    }
    if plan.role != Role::Console {
        let current = image_setup::base(&tx)?;
        if current
            .as_ref()
            .map(|image| (image.id.to_string(), image.status.as_str()))
            != Some((field(fields, "image").to_owned(), "downloaded"))
        {
            return Ok(invalid(
                endpoint,
                "Attendez la fin du téléchargement de l’image Debian sélectionnée.",
            ));
        }
        enqueue(&tx, "bootstrap:build_grub", "Préparation du chargeur UEFI")?;
        enqueue(
            &tx,
            "bootstrap:render_templates",
            "Préparation des menus PXE",
        )?;
        enqueue(&tx, "bootstrap:restart_dnsmasq", "Activation du réseau PXE")?;
    }
    plan.save(&tx)?;
    store(&tx, "https_enabled", "on")?;
    store(&tx, "network_override", "off")?;
    store(&tx, "wizard_completed", "1")?;
    tx.execute(
        "DELETE FROM settings WHERE key IN (?1, ?2, ?3, 'init_completed')",
        params![
            NETWORK_DRAFT,
            image_setup::BASE_DRAFT,
            image_setup::EXTRAS_DRAFT
        ],
    )?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, "/admin/inventaire"))
}

pub(super) fn store(db: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn enqueue(db: &Connection, kind: &str, message: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO init_jobs(job_type,status,message)
                SELECT ?1,'pending',?2 WHERE NOT EXISTS (
                    SELECT 1 FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running')
                )",
        params![kind, message],
    )?;
    Ok(())
}

fn invalid(endpoint: &str, message: &'static str) -> Reply {
    let (step, back) = match endpoint {
        "/init/network" => (WizardStep::Network, "/init/network"),
        "/init/images" => (WizardStep::Images, "/init/images"),
        _ => (WizardStep::Confirmation, "/init/done"),
    };
    ui::wizard_error(step, StatusCode::UNPROCESSABLE_ENTITY, message, back)
}

fn network_page(plan: Option<&Network>) -> Reply {
    let html = network_form(plan, "/init/network", "Continuer");
    ui::wizard(
        Some(WizardStep::Network),
        "Réseau PXE",
        &html,
        StatusCode::OK,
    )
}

pub(super) fn network_form(
    plan: Option<&Network>,
    action: &'static str,
    submit: &'static str,
) -> String {
    let mut html = format!(
        r#"<form class="form-stack" method="post" action="{action}">
<fieldset class="form-stack network-modes"><legend>Mode de fonctionnement</legend>"#,
    );
    let current_role = plan.map_or(Role::Proxy, |saved| saved.role);
    for (name, label, help, role) in [
        (
            "proxy",
            "Ajouter PXE au DHCP existant (recommandé)",
            "Votre DHCP continue d’attribuer les adresses IP. PXE Tools fournit les informations de démarrage par le réseau (proxy DHCP).",
            Role::Proxy,
        ),
        (
            "external",
            "Utiliser un DHCP déjà configuré pour PXE",
            "Votre DHCP attribue les adresses IP et indique aux appareils comment démarrer. PXE Tools fournit les fichiers de démarrage.",
            Role::External,
        ),
        (
            "console",
            "Console seule",
            "Utiliser uniquement la console, sans démarrage par le réseau.",
            Role::Console,
        ),
    ] {
        let checked = if current_role == role { " checked" } else { "" };
        html.push_str(&format!(
            r#"<label class="check-label"><input type="radio" name="role" value="{name}"{checked}>
<span>{label}<small>{help}</small></span></label>"#
        ));
    }
    html.push_str(
        r#"</fieldset><fieldset class="form-stack wizard-network"><legend>Paramètres PXE</legend>"#,
    );
    let choices = detected_networks();
    let saved_network = plan.filter(|saved| !saved.address.is_unspecified());
    let selected = if let Some(saved) = saved_network {
        let subnet = parse_subnet(&saved.subnet);
        choices.iter().position(|(interface, ip, cidr)| {
            *interface == saved.interface && *ip == saved.address && parse_subnet(cidr) == subnet
        })
    } else {
        (choices.len() == 1).then_some(0)
    };
    let manual = choices.is_empty() || (saved_network.is_some() && selected.is_none());
    if choices.is_empty() {
        html.push_str(r#"<p class="muted">Aucune adresse IPv4 utilisable n’a été détectée. Vérifiez que l’interface est active ou renseignez ses paramètres ci-dessous.</p>"#);
    } else {
        html.push_str(r#"<div class="field"><label for="network-address">Interface et adresse IPv4 pour PXE</label>
<select id="network-address" name="network_address" aria-describedby="network-address-help">"#);
        if selected.is_none() && !manual {
            html.push_str(r#"<option value="" selected disabled>Choisir une interface et une adresse IPv4</option>"#);
        }
        for (index, (interface, ip, subnet)) in choices.iter().enumerate() {
            html.push_str("<option value=\"");
            escape(&mut html, &format!("{interface}|{ip}"));
            html.push('"');
            if selected == Some(index) {
                html.push_str(" selected");
            }
            html.push('>');
            escape(&mut html, &format!("{interface} · {subnet}"));
            html.push_str("</option>");
        }
        let manual_selected = if manual { " selected" } else { "" };
        html.push_str(&format!(r#"<option value=""{manual_selected}>Saisie manuelle</option></select>
<small id="network-address-help">Choisissez l’interface reliée au réseau des appareils à démarrer.</small></div>"#));
    }
    let open = if manual { " open" } else { "" };
    html.push_str(&format!(r#"<details{open}><summary>Saisir les paramètres IPv4</summary><div class="form-stack network-details">"#));
    if !choices.is_empty() {
        html.push_str(r#"<p class="muted">Sélectionnez « Saisie manuelle » dans la liste pour utiliser ces valeurs.</p>"#);
    }
    let address = saved_network.map_or_else(String::new, |saved| saved.address.to_string());
    for (key, label, value, placeholder) in [
        (
            "pxe_interface",
            "Interface PXE",
            plan.map_or("", |plan| &plan.interface),
            "enp1s0",
        ),
        ("pxe_ip", "Adresse IPv4 attribuée", &address, "192.168.10.2"),
        (
            "pxe_subnet",
            "Sous-réseau PXE",
            plan.map_or("", |plan| &plan.subnet),
            "192.168.10.0/24",
        ),
    ] {
        html.push_str(&format!(r#"<div class="field"><label for="{key}">{label}</label><input id="{key}" name="{key}" placeholder="{placeholder}" autocomplete="off" spellcheck="false" value=""#));
        escape(&mut html, value);
        html.push_str(r#""></div>"#);
    }
    let proxy_subnet = plan
        .filter(|saved| saved.role == Role::Proxy)
        .and_then(|saved| {
            saved
                .proxy_subnet
                .as_deref()
                .filter(|cidr| parse_subnet(cidr) != parse_subnet(&saved.subnet))
        });
    let proxy_open = if proxy_subnet.is_some() { " open" } else { "" };
    html.push_str(&format!(r#"</div></details><details class="network-proxy-subnet"{proxy_open}>
<summary>Sous-réseau personnalisé pour le proxy DHCP</summary><div class="field network-details">
<label for="dhcp_proxy_cidr">Sous-réseau du proxy DHCP (facultatif)</label>
<input id="dhcp_proxy_cidr" name="dhcp_proxy_cidr" placeholder="Même sous-réseau que PXE" autocomplete="off" spellcheck="false" value=""#));
    escape(&mut html, proxy_subnet.unwrap_or_default());
    html.push_str(r#""></div></details>"#);
    html.push_str(&format!(r#"</fieldset><div class="form-actions"><button type="submit">{submit}</button></div></form>"#));
    html
}

fn done_page(db: &Connection, plan: &Network) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<p class="wizard-intro">Relisez les paramètres avant de les appliquer.</p><dl class="wizard-summary"><dt>Mode</dt><dd>"#,
    );
    let mut image = String::new();
    if plan.role == Role::Console {
        html.push_str("Console seule</dd>");
    } else {
        html.push_str(if plan.role == Role::Proxy {
            "Ajouter PXE au DHCP existant (proxy DHCP)"
        } else {
            "Utiliser un DHCP déjà configuré pour PXE"
        });
        html.push_str("</dd><dt>Interface</dt><dd>");
        escape(&mut html, &plan.interface);
        html.push_str("</dd><dt>Adresse IPv4</dt><dd>");
        escape(&mut html, &plan.address.to_string());
        html.push_str("</dd><dt>Sous-réseau</dt><dd>");
        escape(&mut html, &plan.subnet);
        html.push_str("</dd>");
        if let Some(cidr) = &plan.proxy_subnet {
            html.push_str("<dt>Sous-réseau du proxy DHCP</dt><dd>");
            escape(&mut html, cidr);
            html.push_str("</dd>");
        }
        if let Some(base) = image_setup::base(db)? {
            html.push_str("<dt>Image de service</dt><dd>");
            escape(&mut html, &base.label());
            if base.status == "downloaded" {
                html.push_str(" · Prête");
                image = base.id.to_string();
            }
            html.push_str("</dd>");
        }
    }
    html.push_str("</dl>");
    if plan.role == Role::Console || !image.is_empty() {
        html.push_str(r#"<form class="form-stack" method="post" action="/init/complete"><input type="hidden" name="plan" value=""#);
        escape(&mut html, &serde_json::to_string(plan)?);
        html.push_str(&format!(r#""><input type="hidden" name="image" value="{image}"><div class="form-actions">
<button type="submit" name="confirmation" value="yes">Appliquer la configuration</button><a class="button button--quiet" href="/init/network">Modifier le réseau</a></div></form>"#));
        if plan.enabled() {
            html.push_str(r#"<p class="muted">Les systèmes supplémentaires continuent à se préparer en arrière-plan. Retrouvez-les dans Images PXE.</p>"#);
        }
    } else {
        html.push_str(r#"<p class="muted">Suivez la préparation de l’image de service pour pouvoir activer PXE.</p><div class="form-actions">
<a class="button" href="/init/images">Voir les téléchargements</a><a class="button button--quiet" href="/init/network">Modifier le réseau</a></div>"#);
    }
    Ok(ui::wizard(
        Some(WizardStep::Confirmation),
        "Confirmer la configuration",
        &html,
        StatusCode::OK,
    ))
}
