// SPDX-License-Identifier: LGPL-3.0-only

use super::{record_plan, schedule_allowed, Device};
use crate::{
    connect,
    linux_install::{Plan, Source},
    preseed, pxe,
    web::{
        admin::escape,
        linux_boot::{self, Entry, RhelRepositories},
        plain,
        setup::redirect,
        ui::{page, ConsoleSection},
        ErrorBox, Reply,
    },
};
use hyper::StatusCode;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fmt::Write, net::Ipv4Addr, path::Path};

pub(in crate::web) fn route(path: &str) -> Option<i64> {
    path.strip_prefix("/admin/inventaire/")?
        .strip_suffix("/install/linux")?
        .parse()
        .ok()
        .filter(|id| *id > 0)
}

pub(super) fn supports(device: &Device) -> bool {
    matches!(device.arch.as_deref(), Some("amd64" | "arm64"))
        && device.inventory["inventory"]["boot_mode"] == "UEFI"
}

fn serial_disks(device: &Device) -> impl Iterator<Item = (String, String)> {
    device.disks().filter_map(|(path, serial, identity)| {
        (identity["kind"] == "serial"
            && serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
        .then_some((path, serial))
    })
}

fn selector(entry: &Entry) -> String {
    match &entry.source {
        Source::Ubuntu(version) => format!("ubuntu-{version}"),
        Source::Proxmox(version) => format!("proxmox-{version}"),
        Source::Rpm { distro, version } => format!("{distro}-{version}"),
        Source::Rhel9(url) => match url.trim_end_matches('/').rsplit_once('/') {
            Some((base, digest))
                if base.ends_with("/pxe/rhel9") && crate::media::digest(digest) =>
            {
                format!("rhel9-{digest}")
            }
            _ => "rhel9".into(),
        },
    }
}

fn form(
    db: &Connection,
    root: &Path,
    repositories: &RhelRepositories,
    id: i64,
    device: &Device,
) -> Result<Reply, ErrorBox> {
    let title = "Installation automatique Linux";
    let entries = linux_boot::available(
        db,
        root,
        repositories,
        device.arch.as_deref().unwrap_or_default(),
        "127.0.0.1",
    )?;
    let disks: Vec<_> = serial_disks(device).collect();
    if entries.is_empty() || disks.is_empty() {
        return Ok(page(ConsoleSection::Devices, title, "<p>Une image de l’architecture de l’appareil et un disque avec un numéro de série unique sont nécessaires.</p>"));
    }
    let mut html = format!(
        r#"<form method="post" action="/admin/inventaire/{id}/install/linux">
<label>Image <select name="image" required><option value="" selected disabled>Choisir</option>"#
    );
    for entry in entries {
        write!(html, "<option value=\"{}\">", selector(&entry))?;
        escape(&mut html, &entry.title);
        html.push_str("</option>");
    }
    html.push_str(r#"</select></label><label>Disque à partitionner <select name="disk" required><option value="" selected disabled>Choisir</option>"#);
    for (path, serial) in disks {
        html.push_str("<option value=\"");
        escape(&mut html, &format!("{path}:{serial}"));
        html.push_str("\">");
        escape(&mut html, &format!("{path} · {serial}"));
        html.push_str("</option>");
    }
    html.push_str(r#"</select></label><label>Nom d’hôte <input name="hostname" required maxlength="253" value=""#);
    escape(&mut html, &device.hostname);
    html.push_str(r#""></label>
<label>Compte administrateur Linux <input name="login" maxlength="32"></label>
<p class="record-meta">Pour Proxmox VE, indiquez un nom complet (par exemple pve01.exemple.fr). Le compte est root.</p>
<label>Adresse e-mail Proxmox VE <input name="proxmox_email" type="email" maxlength="254"></label>
<label>Mot de passe <input name="password" type="password" autocomplete="new-password" required minlength="12" maxlength="128"></label>
<label>Confirmer le mot de passe <input name="password_confirm" type="password" autocomplete="new-password" required></label>
<p><label><input type="checkbox" name="confirm" value="yes" required> Confirmer le repartitionnement du disque sélectionné au prochain démarrage PXE UEFI</label></p>
<button>Programmer l’installation</button></form>"#);
    Ok(page(ConsoleSection::Devices, title, &html))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    image: String,
    disk: String,
    hostname: String,
    login: String,
    #[serde(default)]
    proxmox_email: String,
    password: String,
    password_confirm: String,
    confirm: String,
}

fn selection(form: &[u8]) -> Option<Selection> {
    let mut values = serde_json::Map::new();
    for (key, value) in form_urlencoded::parse(form) {
        if values
            .insert(key.into_owned(), Value::String(value.into_owned()))
            .is_some()
        {
            return None;
        }
    }
    serde_json::from_value(Value::Object(values)).ok()
}

pub(in crate::web) fn serve(
    read: &Connection,
    path: &Path,
    id: i64,
    root: &Path,
    repositories: &RhelRepositories,
    input: Option<&[u8]>,
    username: &str,
) -> Result<Reply, ErrorBox> {
    let missing = || plain(StatusCode::NOT_FOUND, "Appareil introuvable\n");
    let unavailable = || {
        plain(
            StatusCode::CONFLICT,
            "Inventaire UEFI, disque ou image Linux indisponibles\n",
        )
    };
    let invalid = || {
        plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Nom, compte ou confirmation invalide\n",
        )
    };
    let Some(device) = Device::get(read, id)? else {
        return Ok(missing());
    };
    if !supports(&device) {
        return Ok(unavailable());
    }
    let Some(input) = input else {
        return form(read, root, repositories, id, &device);
    };
    let Some(input) = selection(input) else {
        return Ok(invalid());
    };
    let hostname = input.hostname.trim().to_ascii_lowercase();
    if input.confirm != "yes"
        || !(12..=128).contains(&input.password.len())
        || input.password.chars().any(char::is_control)
        || input.password != input.password_confirm
    {
        return Ok(invalid());
    }
    let hash = preseed::hash_installation_password(&input.password)?;
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(device) = Device::get(&tx, id)? else {
        return Ok(missing());
    };
    if !supports(&device) || !schedule_allowed(&tx, id, &device, None)? {
        return Ok(unavailable());
    }
    let arch = device.arch.as_deref().unwrap_or_default();
    let Some(boot_mac) = device.inventory["boot_mac"]
        .as_str()
        .and_then(pxe::normalize_mac)
    else {
        return Ok(unavailable());
    };
    let Some(client) = device.inventory["discovery_ip"]
        .as_str()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        .map(|client| {
            crate::boot_networks::contains_client(&tx, client)
                .map(|allowed| allowed.then_some(client))
        })
        .transpose()?
        .flatten()
    else {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Relancez l’inventaire sur le sous-réseau PXE avant de programmer l’installation.\n",
        ));
    };
    let Some((disk, serial)) =
        serial_disks(&device).find(|(path, serial)| input.disk == format!("{path}:{serial}"))
    else {
        return Ok(unavailable());
    };
    let Some(entry) = linux_boot::available(&tx, root, repositories, arch, "127.0.0.1")?
        .into_iter()
        .find(|entry| selector(entry) == input.image)
    else {
        return Ok(unavailable());
    };
    let (distro, version) = match &entry.source {
        Source::Ubuntu(version) => ("ubuntu", version.as_str()),
        Source::Proxmox(version) => ("proxmox", version.as_str()),
        Source::Rhel9(_) => ("rhel", "9"),
        Source::Rpm { distro, version } => (distro.as_str(), version.as_str()),
    };
    let plan = Plan {
        source: entry.source.clone(),
        arch: arch.into(),
        boot_mac,
        client,
        disk,
        serial,
        hostname,
        login: if distro == "proxmox" {
            "root".into()
        } else {
            input.login
        },
        password_hash: hash,
        proxmox_email: input.proxmox_email.trim().to_ascii_lowercase(),
    };
    if !plan.valid() {
        return Ok(invalid());
    }
    let snapshot = json!({"distro": distro, "version_full": version, "hostname": plan.hostname,
                          "network_mode": "dhcp", "linux_deployment": plan});
    let action = record_plan(&tx, id, username, None, snapshot, None)?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/tasks/{action}")))
}
