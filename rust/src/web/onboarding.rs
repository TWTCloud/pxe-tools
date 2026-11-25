// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    images, plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::{connect, pxe::parse_subnet, setting};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::Ipv4Addr, path::Path};

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
        for (field, value) in form_urlencoded::parse(data) {
            if values
                .insert(field.into_owned(), value.into_owned())
                .is_some()
            {
                return invalid("Le formulaire est ambigu.\n");
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
            return Ok(invalid("Sélectionnez une interface, une adresse IPv4 attribuée et un sous-réseau cohérent.\n"));
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
            return Ok(invalid("Choisissez une image Debian.\n"));
        };
        let Some(id) = images::queue_image(&tx, entry, true)? else {
            return Ok(invalid("Cette image Debian est indisponible.\n"));
        };
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
            "Confirmez la configuration affichée avant de l’appliquer.\n",
        ));
    }
    if !plan.assigned() {
        return Ok(invalid(
            "L’adresse IPv4 sélectionnée a changé. Confirmez de nouveau le réseau.\n",
        ));
    }
    // Bind the confirmation to the exact staged network and image.
    if field(fields, "plan") != serde_json::to_string(&plan)? {
        return Ok(invalid(
            "Le réseau a changé depuis l’affichage du récapitulatif.\n",
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
                "Attendez la fin du téléchargement de l’image Debian sélectionnée.\n",
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

fn invalid(message: &'static str) -> Reply {
    plain(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn network_page(plan: Option<&Network>) -> Reply {
    let mut html = String::from(
        r#"<form method="post" action="/init/network">
<label>Mode <select name="role">"#,
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
    html.push_str("</select></label>");
    let address = plan
        .filter(|plan| plan.role != Role::Console)
        .map(|plan| plan.address.to_string())
        .unwrap_or_default();
    for (key, label, value) in [
        (
            "pxe_interface",
            "Interface PXE",
            plan.map_or("", |plan| &plan.interface),
        ),
        ("pxe_ip", "Adresse IPv4 attribuée", &address),
        (
            "pxe_subnet",
            "Sous-réseau PXE",
            plan.map_or("", |plan| &plan.subnet),
        ),
    ] {
        html.push_str(&format!(r#"<p><label>{label} <input name="{key}" value=""#));
        escape(&mut html, value);
        html.push_str(r#""></label></p>"#);
    }
    html.push_str("<button>Continuer</button></form>");
    page("Réseau PXE", &html)
}

fn images_page(db: &Connection) -> Result<Reply, ErrorBox> {
    Ok(page(
        "Image de démarrage",
        &images::catalog_form(db, "/init/images")?,
    ))
}

fn done_page(db: &Connection, plan: &Network) -> Result<Reply, ErrorBox> {
    let mut html = String::new();
    let mut image = String::new();
    if plan.role == Role::Console {
        html.push_str("<p>Console seule.</p>");
    } else {
        html.push_str("<p>Interface ");
        escape(&mut html, &plan.interface);
        html.push_str(" · ");
        escape(&mut html, &plan.address.to_string());
        html.push_str(" · ");
        escape(&mut html, &plan.subnet);
        html.push_str(if plan.role == Role::Proxy {
            " · proxy DHCP</p>"
        } else {
            " · DHCP externe</p>"
        });
        if let Some((id, label, status)) = selected_image(db)? {
            html.push_str("<p>Debian ");
            escape(&mut html, &label);
            html.push_str(" · ");
            escape(&mut html, &status);
            html.push_str("</p>");
            if status == "downloaded" {
                image = id.to_string();
            }
        }
        if image.is_empty() {
            html.push_str(r#"<p><a href="/init/images">Choisir une image et attendre son téléchargement</a></p>"#);
        }
    }
    if plan.role == Role::Console || !image.is_empty() {
        html.push_str(r#"<form method="post" action="/init/complete"><input type="hidden" name="plan" value=""#);
        escape(&mut html, &serde_json::to_string(plan)?);
        html.push_str(&format!(r#""><input type="hidden" name="image" value="{image}"><button name="confirmation" value="yes">Appliquer la configuration</button></form>"#));
    }
    html.push_str(r#"<p><a href="/init/network">Modifier le réseau</a></p>"#);
    Ok(page("Confirmer la configuration", &html))
}
