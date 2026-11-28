// SPDX-License-Identifier: LGPL-3.0-only

mod image_setup;

use super::{
    admin::escape,
    images, plain,
    setup::redirect,
    ui::{self, WizardStep},
    ErrorBox, Reply,
};
use crate::{
    boot_networks::{self, Network as Link},
    connect,
    pxe::parse_subnet,
    setting,
};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, path::Path};

const NETWORK_DRAFT: &str = "rust_wizard_network";
pub(super) const PENDING_PXE_ADDRESS: &str = "pending_pxe_address";

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    additional: Vec<Link>,
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
                additional: Vec::new(),
            });
        }
        let mut selections: Vec<_> = fields
            .iter()
            .filter(|(name, value)| network_address_field(name) && !value.is_empty())
            .collect();
        selections.sort_unstable_by_key(|(key, _)| *key);
        let mut links = Vec::new();
        if !selections.is_empty() {
            let detected = boot_networks::detected();
            for (_, selection) in selections {
                let network = detected
                    .iter()
                    .find(|item| format!("{}|{}", item.interface, item.address) == *selection)?;
                links.push(network.clone());
            }
        }
        if links.len() > 1 {
            if !boot_networks::valid(&links) || !field(fields, "dhcp_proxy_cidr").is_empty() {
                return None;
            }
        }
        let (interface, address, subnet) = if links.is_empty() {
            (
                field(fields, "pxe_interface").to_owned(),
                field(fields, "pxe_ip").parse::<Ipv4Addr>().ok()?,
                field(fields, "pxe_subnet").to_owned(),
            )
        } else {
            let first = links.remove(0);
            (first.interface, first.address, first.subnet)
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
            additional: links,
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
            additional: boot_networks::configured(db)?
                .map_or_else(Vec::new, |items| items.into_iter().skip(1).collect()),
        })
    }

    pub(super) fn enabled(&self) -> bool {
        self.role != Role::Console
    }

    pub(super) fn save(&self, db: &Connection) -> Result<(), ErrorBox> {
        store(db, PENDING_PXE_ADDRESS, "")?;
        if self.enabled() {
            store(db, "pxe_interface", &self.interface)?;
            store(db, "pxe_ip", &self.address.to_string())?;
            store(db, "pxe_subnet", &self.subnet)?;
            store(db, "network_override", "off")?;
            let values = if self.additional.is_empty() {
                String::new()
            } else {
                let mut links = vec![
                    Link::new(self.interface.clone(), self.address, &self.subnet)
                        .ok_or("Invalid primary PXE network")?,
                ];
                links.extend(self.additional.iter().cloned());
                serde_json::to_string(&links)?
            };
            store(db, boot_networks::KEY, &values)?;
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
        return super::validate_interface(self.address, &self.interface).is_ok()
            && self
                .additional
                .iter()
                .all(|link| super::validate_interface(link.address, &link.interface).is_ok());
        #[cfg(not(target_os = "linux"))]
        false
    }
}

/// Keep the last usable address as the preference when the interface has aliases.
/// A replacement must belong to the configured boot subnet and proxy scope.
pub(crate) fn refresh_pxe_address(config: &Path) -> Result<String, ErrorBox> {
    if !config.try_exists()? {
        return Ok("unchanged".into());
    }
    let path = crate::configured_database(config).ok_or("SQLite configuration unavailable")?;
    let mut db = connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let plan = Network::current(&tx)?;
    if !plan.enabled() {
        return Ok("unchanged".into());
    }
    if !plan.additional.is_empty() {
        return Ok("multiple".into());
    }
    let networks = boot_networks::detected();
    if networks
        .iter()
        .any(|item| item.interface == plan.interface && item.address == plan.address)
    {
        let pending = setting(&tx, PENDING_PXE_ADDRESS)?;
        return Ok(if pending.is_empty() {
            "unchanged".into()
        } else {
            pending
        });
    }

    let mut candidates: Vec<_> = networks
        .into_iter()
        .map(|item| (item.interface, item.address, item.subnet))
        .filter(|(interface, address, connected_subnet)| {
            let same_network = if plan.address.is_unspecified() {
                crate::pxe::client_in_subnet(*address, &plan.subnet)
            } else {
                crate::pxe::client_in_subnet(plan.address, connected_subnet)
            };
            *interface == plan.interface
                && same_network
                && (plan.role != Role::Proxy
                    || plan
                        .proxy_subnet
                        .as_ref()
                        .is_some_and(|subnet| crate::pxe::client_in_subnet(*address, subnet)))
        })
        .map(|(_, address, _)| address)
        .collect();
    candidates.sort_unstable();
    candidates.dedup();
    let [address] = candidates.as_slice() else {
        return Ok("suspended".into());
    };
    let address = address.to_string();
    store(&tx, "pxe_ip", &address)?;
    store(&tx, PENDING_PXE_ADDRESS, &address)?;
    tx.commit()?;
    Ok(address)
}

pub(crate) fn finish_pxe_address(config: &Path, address: Ipv4Addr) -> Result<(), ErrorBox> {
    let path = crate::configured_database(config).ok_or("SQLite configuration unavailable")?;
    let mut db = connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let plan = Network::current(&tx)?;
    if !plan.enabled()
        || plan.address != address
        || setting(&tx, PENDING_PXE_ADDRESS)? != address.to_string()
        || !plan.assigned()
    {
        return Err("PXE address changed while preparing the boot files".into());
    }
    store(&tx, PENDING_PXE_ADDRESS, "")?;
    tx.commit()?;
    Ok(())
}

pub(super) fn network_address_field(name: &str) -> bool {
    name == "network_address"
        || name
            .strip_prefix("network_address_")
            .and_then(|index| index.parse::<usize>().ok())
            .is_some_and(|index| index < 128)
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
        "/init/done" => done_page(&plan),
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
            return Ok(invalid(endpoint, "Sélectionnez une IPv4 attribuée par interface, sur des sous-réseaux distincts. Le sous-réseau DHCP personnalisé est réservé à une seule interface."));
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
        if field(fields, "image") != crate::alpine::version() || !crate::alpine::all_ready() {
            return Ok(invalid(
                endpoint,
                "Attendez la fin de la préparation de l’image Alpine.",
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
            "rust_wizard_image",
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
    let choices = boot_networks::detected();
    let saved_network = plan.filter(|saved| !saved.address.is_unspecified());
    let saved_links = saved_network.map_or_else(Vec::new, |saved| {
        Link::new(saved.interface.clone(), saved.address, &saved.subnet)
            .into_iter()
            .chain(saved.additional.iter().cloned())
            .collect()
    });
    let saved_count = saved_links.len();
    let selected = boot_networks::resolve(saved_links, &choices);
    let manual = choices.is_empty() || (saved_network.is_some() && selected.is_empty());
    if choices.is_empty() {
        html.push_str(r#"<p class="muted">Aucune interface avec une IPv4 active. Connectez le réseau ou renseignez son adresse ci-dessous.</p>"#);
    } else {
        html.push_str(r#"<fieldset class="form-stack"><legend>Réseaux desservis</legend>
<p class="muted">Cochez une IPv4 par interface. Chaque client reçoit l’adresse indiquée sur sa ligne.</p>"#);
        for (index, link) in choices.iter().take(128).enumerate() {
            let Link {
                interface,
                address: ip,
                subnet,
            } = link;
            let checked = if selected.contains(link) || (plan.is_none() && choices.len() == 1) {
                " checked"
            } else {
                ""
            };
            html.push_str(&format!(r#"<label class="check-label"><input type="checkbox" name="network_address_{index}" value=""#));
            escape(&mut html, &format!("{interface}|{ip}"));
            html.push_str(&format!(r#""{checked}><span>"#));
            escape(&mut html, interface);
            html.push_str("<small>");
            escape(&mut html, &format!("{subnet} · Serveur PXE {ip}"));
            html.push_str("</small></span></label>");
        }
        html.push_str("</fieldset>");
        if saved_count > selected.len() {
            html.push_str(r#"<p class="muted">Certaines interfaces configurées sont indisponibles. Réactivez-les avant d’enregistrer pour les conserver.</p>"#);
        }
    }
    let open = if manual { " open" } else { "" };
    html.push_str(&format!(r#"<details{open}><summary>Saisir les paramètres IPv4</summary><div class="form-stack network-details">"#));
    if !choices.is_empty() {
        html.push_str(r#"<p class="muted">Décochez les réseaux détectés pour utiliser la saisie manuelle.</p>"#);
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
<label for="dhcp_proxy_cidr">Sous-réseau du proxy DHCP pour une seule interface (facultatif)</label>
<input id="dhcp_proxy_cidr" name="dhcp_proxy_cidr" placeholder="Même sous-réseau que PXE" autocomplete="off" spellcheck="false" value=""#));
    escape(&mut html, proxy_subnet.unwrap_or_default());
    html.push_str(r#""></div></details>"#);
    html.push_str(&format!(r#"</fieldset><div class="form-actions"><button type="submit">{submit}</button></div></form>"#));
    html
}

fn done_page(plan: &Network) -> Result<Reply, ErrorBox> {
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
        for item in &plan.additional {
            html.push_str("<dt>Autre interface</dt><dd>");
            escape(
                &mut html,
                &format!("{} · {} · {}", item.interface, item.subnet, item.address),
            );
            html.push_str("</dd>");
        }
        if let Some(cidr) = &plan.proxy_subnet {
            html.push_str("<dt>Sous-réseau du proxy DHCP</dt><dd>");
            escape(&mut html, cidr);
            html.push_str("</dd>");
        }
        html.push_str("<dt>Image de service</dt><dd>Alpine ");
        escape(&mut html, crate::alpine::version());
        if crate::alpine::all_ready() {
            html.push_str(" · Prête");
            image = crate::alpine::version().to_owned();
        }
        html.push_str("</dd>");
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
