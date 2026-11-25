// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    images, plain,
    setup::redirect,
    ui::{self, WizardStep},
    ErrorBox, Reply,
};
use crate::{connect, pxe::parse_subnet, setting};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    net::Ipv4Addr,
    path::Path,
};

const NETWORK_DRAFT: &str = "rust_wizard_network";
const IMAGE_DRAFT: &str = "rust_wizard_image";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Role {
    Console,
    External,
    Proxy,
}

#[derive(Serialize, Deserialize)]
struct Network {
    role: Role,
    interface: String,
    address: Ipv4Addr,
    subnet: String,
}

impl Network {
    fn parse(fields: &HashMap<String, String>) -> Option<Self> {
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
            });
        }
        let interface = field(fields, "pxe_interface").to_owned();
        let address: Ipv4Addr = field(fields, "pxe_ip").parse().ok()?;
        let input = field(fields, "pxe_subnet");
        let (network, mask) = parse_subnet(input)?;
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
        };
        plan.assigned().then_some(plan)
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

pub(super) fn is_route(path: &str) -> bool {
    matches!(
        path,
        "/init/network" | "/init/images" | "/init/done" | "/init/complete"
    )
}

pub(super) fn serve(db: &Connection, path: &Path, endpoint: &str, form: Option<&[u8]>) -> Reply {
    let reply = if let Some(data) = form {
        let mut values = HashMap::new();
        let mut extras = BTreeSet::new();
        for (field, value) in form_urlencoded::parse(data) {
            if endpoint == "/init/images" && field == "extra[]" {
                let Some(id) = value.parse::<i64>().ok().filter(|id| *id > 0) else {
                    return invalid(endpoint, "Une image supplémentaire est invalide.");
                };
                extras.insert(id);
                continue;
            }
            if values
                .insert(field.into_owned(), value.into_owned())
                .is_some()
            {
                return invalid(endpoint, "Le formulaire est ambigu.");
            }
        }
        change(path, endpoint, &values, extras)
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
        return Ok(redirect(StatusCode::FOUND, "/admin/devices"));
    }
    let plan = draft(db)?;
    if endpoint == "/init/network" {
        return Ok(network_page(plan.as_ref()));
    }
    let Some(plan) = plan else {
        return Ok(redirect(StatusCode::FOUND, "/init/network"));
    };
    match endpoint {
        "/init/images" if plan.role != Role::Console => images_page(db),
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
    extras: BTreeSet<i64>,
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
            "/init/images"
        };
        tx.commit()?;
        return Ok(redirect(StatusCode::SEE_OTHER, next));
    }
    let Some(plan) = draft(&tx)? else {
        return Ok(redirect(StatusCode::SEE_OTHER, "/init/network"));
    };
    if endpoint == "/init/images" && plan.role != Role::Console {
        if field(fields, "action") == "refresh" {
            images::refresh_catalog(&tx)?;
            tx.commit()?;
            return Ok(redirect(StatusCode::SEE_OTHER, "/init/images"));
        }
        let Some(entry) = field(fields, "image")
            .parse::<i64>()
            .ok()
            .filter(|id| *id > 0)
        else {
            return Ok(invalid(endpoint, "Choisissez une image Debian."));
        };
        let rescue: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM catalog_entries
             WHERE id=?1 AND distro='debian' AND extract_method='direct')",
            [entry],
            |row| row.get(0),
        )?;
        if !rescue {
            return Ok(invalid(
                endpoint,
                "Choisissez une image Debian pour le secours PXE.",
            ));
        }
        let Some(id) = images::queue_image(&tx, entry, true)? else {
            return Ok(invalid(endpoint, "Cette image Debian est indisponible."));
        };
        for extra in extras {
            if extra != entry && images::queue_image(&tx, extra, true)?.is_none() {
                return Ok(invalid(
                    endpoint,
                    "Une image supplémentaire est indisponible.",
                ));
            }
        }
        store(&tx, IMAGE_DRAFT, &id.to_string())?;
        tx.commit()?;
        return Ok(redirect(StatusCode::SEE_OTHER, "/init/done"));
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
        let current = selected_image(&tx)?;
        if current
            .as_ref()
            .map(|(id, _, status)| (id.to_string(), status.as_str()))
            != Some((field(fields, "image").to_owned(), "downloaded"))
        {
            return Ok(invalid(
                endpoint,
                "Attendez la fin du téléchargement de l’image Debian sélectionnée.",
            ));
        }
        let (network, mask) = parse_subnet(&plan.subnet).ok_or("Invalid staged PXE subnet")?;
        store(&tx, "pxe_interface", &plan.interface)?;
        store(&tx, "pxe_ip", &plan.address.to_string())?;
        store(&tx, "pxe_subnet", &plan.subnet)?;
        if plan.role == Role::Proxy {
            store(
                &tx,
                "dhcp_proxy_network",
                &Ipv4Addr::from(network).to_string(),
            )?;
            store(&tx, "dhcp_proxy_netmask", &Ipv4Addr::from(mask).to_string())?;
        }
        enqueue(&tx, "bootstrap:build_grub", "Préparation du chargeur UEFI")?;
        enqueue(
            &tx,
            "bootstrap:render_templates",
            "Préparation des menus PXE",
        )?;
        enqueue(&tx, "bootstrap:restart_dnsmasq", "Activation du réseau PXE")?;
        store(&tx, "pxe_enabled", "on")?;
        store(
            &tx,
            "dhcp_proxy_enabled",
            if plan.role == Role::Proxy {
                "on"
            } else {
                "off"
            },
        )?;
    }
    if plan.role == Role::Console {
        store(&tx, "pxe_enabled", "off")?;
        store(&tx, "dhcp_proxy_enabled", "off")?;
    }
    store(&tx, "https_enabled", "on")?;
    store(&tx, "network_override", "off")?;
    store(&tx, "wizard_completed", "1")?;
    tx.execute(
        "DELETE FROM settings WHERE key IN (?1, ?2, 'init_completed')",
        params![NETWORK_DRAFT, IMAGE_DRAFT],
    )?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, "/admin/devices"))
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

fn selected_image(db: &Connection) -> rusqlite::Result<Option<(i64, String, String)>> {
    let id = setting(db, IMAGE_DRAFT)?.parse::<i64>().unwrap_or_default();
    db.query_row(
        "SELECT id,version_full || ' · ' || arch,status FROM os_images
                  WHERE id=?1 AND distro='debian' AND extract_method='direct' AND enabled=1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .optional()
}

fn invalid(endpoint: &str, message: &'static str) -> Reply {
    let (step, back) = match endpoint {
        "/init/network" => (WizardStep::Network, "/init/network"),
        "/init/images" => (WizardStep::Network, "/init/images"),
        _ => (WizardStep::Confirmation, "/init/done"),
    };
    ui::wizard_error(step, StatusCode::UNPROCESSABLE_ENTITY, message, back)
}

fn network_page(plan: Option<&Network>) -> Reply {
    let mut html = String::from(
        r#"<p class="wizard-intro">Choisissez si cette instance doit servir des clients PXE ou héberger uniquement la console.</p>
<form class="form-stack" method="post" action="/init/network">
<div class="field"><label for="setup-role">Mode de fonctionnement</label><select id="setup-role" name="role">"#,
    );
    for (name, label, role) in [
        ("console", "Console seule", Role::Console),
        ("external", "PXE avec DHCP externe", Role::External),
        ("proxy", "PXE avec proxy DHCP", Role::Proxy),
    ] {
        let selected = if plan.map(|saved| saved.role) == Some(role) {
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{name}"{selected}>{label}</option>"#
        ));
    }
    html.push_str(r#"</select></div><fieldset class="form-stack wizard-network"><legend>Paramètres PXE</legend>
<p class="muted">Renseignez ces champs si vous avez choisi un mode PXE.</p>"#);
    let address = plan
        .filter(|plan| plan.role != Role::Console)
        .map(|plan| plan.address.to_string())
        .unwrap_or_default();
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
    html.push_str(r#"</fieldset><div class="form-actions"><button type="submit">Continuer</button></div></form>"#);
    ui::wizard(
        Some(WizardStep::Network),
        "Réseau PXE",
        &html,
        StatusCode::OK,
    )
}

fn images_page(db: &Connection) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<p class="wizard-intro">Choisissez une image Debian pour la découverte et le secours. Les autres installateurs sont téléchargés en arrière-plan et apparaissent dans le menu PXE lorsqu’ils sont prêts.</p>"#,
    );
    html.push_str(&images::catalog_form(db, "/init/images")?);
    html.push_str(r#"<p class="muted">Proxmox VE utilise un média préparé séparément après cette configuration.</p>"#);
    html.push_str(r#"<p class="wizard-back"><a href="/init/network">Modifier le réseau</a></p>"#);
    Ok(ui::wizard(
        Some(WizardStep::Network),
        "Image de démarrage",
        &html,
        StatusCode::OK,
    ))
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
            "PXE avec proxy DHCP"
        } else {
            "PXE avec DHCP externe"
        });
        html.push_str("</dd><dt>Interface</dt><dd>");
        escape(&mut html, &plan.interface);
        html.push_str("</dd><dt>Adresse IPv4</dt><dd>");
        escape(&mut html, &plan.address.to_string());
        html.push_str("</dd><dt>Sous-réseau</dt><dd>");
        escape(&mut html, &plan.subnet);
        html.push_str("</dd>");
        if let Some((id, label, status)) = selected_image(db)? {
            html.push_str("<dt>Image</dt><dd>Debian ");
            escape(&mut html, &label);
            html.push_str(" · ");
            escape(
                &mut html,
                match status.as_str() {
                    "downloaded" => "Prête",
                    "downloading" => "Téléchargement en cours",
                    "pending" => "En attente",
                    "error" | "failed" => "Échec du téléchargement",
                    _ => "Indisponible",
                },
            );
            html.push_str("</dd>");
            if status == "downloaded" {
                image = id.to_string();
            }
        }
    }
    html.push_str("</dl>");
    if plan.role == Role::Console || !image.is_empty() {
        html.push_str(r#"<form class="form-stack" method="post" action="/init/complete"><input type="hidden" name="plan" value=""#);
        escape(&mut html, &serde_json::to_string(plan)?);
        html.push_str(&format!(r#""><input type="hidden" name="image" value="{image}"><div class="form-actions">
<button type="submit" name="confirmation" value="yes">Appliquer la configuration</button><a class="button button--quiet" href="/init/network">Modifier le réseau</a></div></form>"#));
    } else {
        html.push_str(r#"<p class="muted">L’image Debian doit être prête pour appliquer la configuration.</p><div class="form-actions">
<a class="button" href="/init/images">Revenir au choix de l’image</a><a class="button button--quiet" href="/init/network">Modifier le réseau</a></div>"#);
    }
    Ok(ui::wizard(
        Some(WizardStep::Confirmation),
        "Confirmer la configuration",
        &html,
        StatusCode::OK,
    ))
}
