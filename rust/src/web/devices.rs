// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    plain,
    presets::GUIDED,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::{connect, disk_identity, preseed, setting};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{fmt::Write, io::Read, path::Path};

pub(super) fn register(path: &Path, form: Option<&[u8]>) -> Result<Reply, ErrorBox> {
    let Some(form) = form else {
        return Ok(page(
            "Ajouter un appareil",
            r#"
<form method="post" action="/machines">
<label>Adresse MAC <input name="mac" required placeholder="02:00:00:00:00:01"></label>
<label>Nom d’hôte (facultatif) <input name="hostname"></label>
<button>Créer</button>
</form>
<p><a href="/admin/devices">Retour aux appareils</a></p>
"#,
        ));
    };
    let mut mac = None;
    let mut hostname = None;
    for (key, value) in form_urlencoded::parse(form) {
        match key.as_ref() {
            "mac" if mac.is_none() => mac = Some(value),
            "hostname" if hostname.is_none() => hostname = Some(value),
            _ => return Ok(plain(StatusCode::UNPROCESSABLE_ENTITY, "Saisie invalide\n")),
        }
    }
    let Some(mac) = mac.as_deref().and_then(crate::pxe::normalize_mac) else {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Adresse MAC invalide\n",
        ));
    };
    let db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let created: Option<i64> = db
        .query_row(
            "INSERT INTO machines(mac,hostname,status) VALUES(?1,?2,'discovered')
         ON CONFLICT(mac) DO NOTHING RETURNING id",
            params![mac, hostname.as_deref()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(match created {
        Some(id) => redirect(StatusCode::SEE_OTHER, format!("/machines/{id}")),
        None => plain(
            StatusCode::CONFLICT,
            "Cette adresse MAC est déjà enregistrée\n",
        ),
    })
}

pub(super) struct DeviceRoute {
    id: i64,
    section: Section,
}

enum Section {
    Detail,
    Install,
    Status,
}

pub(super) fn route(path: &str) -> Option<DeviceRoute> {
    let rest = path.strip_prefix("/machines/")?;
    let (id, section) = rest.split_once('/').unwrap_or((rest, ""));
    let id = id.parse().ok().filter(|id| *id > 0)?;
    let section = match section {
        "" => Section::Detail,
        "install" => Section::Install,
        "status" => Section::Status,
        _ => return None,
    };
    Some(DeviceRoute { id, section })
}

impl DeviceRoute {
    pub(super) fn form_limit(&self, method: &hyper::Method) -> Option<usize> {
        match (&self.section, method) {
            (Section::Install | Section::Status, &hyper::Method::POST) => Some(2048),
            (Section::Detail, &hyper::Method::PUT | &hyper::Method::POST) => Some(64 * 1024),
            _ => None,
        }
    }

    pub(super) fn serve(
        &self,
        db: &Connection,
        path: &Path,
        method: &hyper::Method,
        form: Option<&[u8]>,
        username: &str,
    ) -> Result<Reply, ErrorBox> {
        if let Some(form) = form {
            return match self.section {
                Section::Install => schedule(path, self.id, form, username),
                Section::Detail | Section::Status => super::device_settings::update(
                    path,
                    self.id,
                    method,
                    form,
                    matches!(self.section, Section::Status),
                ),
            };
        }
        let Some(device) = Device::get(db, self.id)? else {
            return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
        };
        match self.section {
            Section::Install => install_form(db, self.id, &device),
            Section::Detail => detail(db, self.id, &device),
            Section::Status => super::device_settings::badge(db, self.id, &device.status),
        }
    }
}

struct Device {
    mac: String,
    hostname: String,
    domain: Option<String>,
    status: String,
    arch: Option<String>,
    inventory: Value,
}

impl Device {
    fn get(db: &Connection, id: i64) -> rusqlite::Result<Option<Self>> {
        db.query_row(
            "SELECT mac,COALESCE(hostname,''),domain,status,boot_arch,inventory_json FROM machines WHERE id=?",
            [id],
            |row| Ok(Self {
                mac: row.get(0)?, hostname: row.get(1)?, domain: row.get(2)?,
                status: row.get(3)?, arch: row.get(4)?,
                inventory: row.get::<_, Option<String>>(5)?
                    .and_then(|raw| serde_json::from_str(&raw).ok()).unwrap_or_default(),
            }),
        ).optional()
    }

    fn disks(&self) -> impl Iterator<Item = (String, String, Value)> {
        // Normalize identities again when reading older saved inventories.
        disk_identity::normalize_inventory(&self.inventory["disks"])
            .into_iter()
            .filter_map(|disk| {
                let name = disk["name"].as_str()?;
                let path = format!("/dev/{}", name.strip_prefix("/dev/").unwrap_or(name));
                if !preseed::whole_disk(&path) || disk["identity"]["status"] != "valid" {
                    return None;
                }
                let identity = disk["identity"].clone();
                let value = identity["value"].as_str()?.to_owned();
                (value.len() <= 128 && !value.chars().any(char::is_control))
                    .then_some((path, value, identity))
            })
    }
}

fn detail(db: &Connection, id: i64, device: &Device) -> Result<Reply, ErrorBox> {
    let mut output = String::from("<p>");
    escape(&mut output, &device.hostname);
    output.push_str(" · ");
    escape(&mut output, &device.mac);
    output.push_str(" · ");
    escape(&mut output, &device.status);
    output.push_str("</p><h2>Disques identifiés</h2><ul>");
    for (path, serial, _) in device.disks() {
        output.push_str("<li>");
        escape(&mut output, &path);
        output.push_str(" · ");
        escape(&mut output, &serial);
        output.push_str("</li>");
    }
    write!(output, "</ul><nav><a href=\"/machines/{id}/install\">Programmer une installation Debian</a> · <a href=\"/activity?machine={id}\">Activité</a> · <a href=\"/admin/devices\">Appareils</a></nav>")?;
    super::device_settings::form(db, id, &mut output)?;
    output.push_str("<h2>Derniers événements</h2><ul>");
    let mut events = db.prepare(
        "SELECT message FROM machine_events WHERE machine_id=? ORDER BY id DESC LIMIT 25",
    )?;
    let mut rows = events.query([id])?;
    while let Some(row) = rows.next()? {
        output.push_str("<li>");
        escape(&mut output, &row.get::<_, String>(0)?);
        output.push_str("</li>");
    }
    output.push_str("</ul>");
    Ok(page("Appareil", &output))
}

fn install_form(db: &Connection, id: i64, device: &Device) -> Result<Reply, ErrorBox> {
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(plain(StatusCode::CONFLICT, "Inventaire PXE requis\n"));
    };
    let mut output = format!("<form method=\"post\" action=\"/machines/{id}/install\"><p><label>Nom d’hôte <input name=\"hostname\" maxlength=\"63\" required value=\"");
    escape(&mut output, &device.hostname);
    output.push_str("\"></label></p><p><label>Disque vérifié <select name=\"disk\" required><option value=\"\">Sélectionner</option>");
    for (path, serial, _) in device.disks() {
        output.push_str("<option value=\"");
        escape(&mut output, &format!("{path}:{serial}"));
        output.push_str("\">");
        escape(&mut output, &path);
        output.push_str(" · ");
        escape(&mut output, &serial);
        output.push_str("</option>");
    }
    output.push_str("</select></label></p><p><label>Image Debian <select name=\"image\" required><option value=\"\">Sélectionner</option>");
    let mut images = db.prepare(
        "SELECT id,version_full FROM os_images WHERE enabled=1 AND status='downloaded'
         AND arch=? AND distro='debian' AND codename='trixie' AND version_full IS NOT NULL
         AND extract_method='direct' ORDER BY id DESC",
    )?;
    let mut rows = images.query([arch])?;
    while let Some(row) = rows.next()? {
        write!(output, "<option value=\"{}\">", row.get::<_, i64>(0)?)?;
        escape(&mut output, &row.get::<_, String>(1)?);
        write!(output, " · {arch}</option>")?;
    }
    output.push_str("</select></label></p><p><label>Modèle DHCP <select name=\"preset\" required><option value=\"\">Sélectionner</option>");
    let mut presets = db.prepare(&format!(
        "SELECT id,name FROM presets WHERE {GUIDED} ORDER BY name"
    ))?;
    let mut rows = presets.query([])?;
    while let Some(row) = rows.next()? {
        write!(output, "<option value=\"{}\">", row.get::<_, i64>(0)?)?;
        escape(&mut output, &row.get::<_, String>(1)?);
        output.push_str("</option>");
    }
    output.push_str("</select></label> <a href=\"/presets\">Gérer les modèles</a></p><p><label><input type=\"checkbox\" name=\"confirm\" value=\"yes\" required> Confirmer le repartitionnement du disque sélectionné au prochain démarrage PXE</label></p><button>Programmer</button></form>");
    Ok(page("Installation Debian guidée", &output))
}

#[derive(serde::Deserialize)]
struct Selection {
    hostname: String,
    disk: String,
    image: i64,
    preset: i64,
    confirm: String,
}

fn selection(form: &[u8]) -> Option<Selection> {
    let mut fields = serde_json::Map::new();
    for (key, value) in form_urlencoded::parse(form) {
        let value = match key.as_ref() {
            "image" | "preset" => json!(value.parse::<i64>().ok().filter(|id| *id > 0)?),
            "hostname" | "disk" | "confirm" => json!(value),
            _ => return None,
        };
        if fields.insert(key.into_owned(), value).is_some() {
            return None;
        }
    }
    serde_json::from_value(Value::Object(fields)).ok()
}

fn schedule(path: &Path, id: i64, form: &[u8], username: &str) -> Result<Reply, ErrorBox> {
    let Some(selection) = selection(form) else {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Sélection incomplète\n",
        ));
    };
    let hostname = selection.hostname.trim().to_ascii_lowercase();
    if selection.confirm != "yes"
        || hostname.is_empty()
        || hostname.len() > 63
        || hostname.starts_with('-')
        || hostname.ends_with('-')
        || !hostname
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Nom ou confirmation invalide\n",
        ));
    }

    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(device) = Device::get(&tx, id)? else {
        return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
    };
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(plain(StatusCode::CONFLICT, "Inventaire PXE requis\n"));
    };
    let blocked: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM actions WHERE machine_id=? AND status IN ('pending','running'))
         OR EXISTS(SELECT 1 FROM init_jobs WHERE job_type='bootstrap:auto_refresh_catalog_v2' AND status='running')",
        [id], |row| row.get(0),
    )?;
    if setting(&tx, "pxe_enabled")? != "on"
        || blocked
        || !matches!(
            device.status.as_str(),
            "discovered" | "tested" | "wiped" | "installed" | "provisioned"
        )
    {
        return Ok(plain(
            StatusCode::CONFLICT,
            "L’appareil ou le serveur PXE est occupé ou indisponible\n",
        ));
    }
    let Some((disk, _, proof)) = device
        .disks()
        .find(|(path, serial, _)| selection.disk == format!("{path}:{serial}"))
    else {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Le disque sélectionné ne correspond plus à l’inventaire\n",
        ));
    };
    let Some(version) = tx
        .query_row(
            "SELECT version_full FROM os_images WHERE id=? AND arch=? AND distro='debian'
         AND codename='trixie' AND extract_method='direct' AND enabled=1 AND status='downloaded'
         AND version_full IS NOT NULL",
            params![selection.image, arch],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Image Debian indisponible pour cet appareil\n",
        ));
    };
    let Some((login, password, fullname, keys)) = tx.query_row(
        &format!("SELECT admin_user_login,admin_user_pwhash,admin_user_fullname,admin_user_pubkeys FROM presets
                 WHERE id=? AND {GUIDED} AND (version_full IS NULL OR version_full='' OR version_full=?)"),
        params![selection.preset, version],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                   row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?)),
    ).optional()? else {
        return Ok(plain(StatusCode::CONFLICT, "Modèle incompatible ou indisponible\n"));
    };
    if !preseed::technical_account(&login)
        || !password.starts_with("$6$")
        || preseed::sanitized_hash(&password).is_none()
    {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Compte d’installation du modèle invalide\n",
        ));
    }

    let mut random = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let token = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    tx.execute("INSERT INTO actions(machine_id,type,status,token,created_by) VALUES(?,'install_only','pending',?,?)",
               params![id, token, username])?;
    let action = tx.last_insert_rowid();
    let snapshot = json!({
        "distro":"debian", "codename":"trixie", "version_full":version, "variant":"debian",
        "hostname":hostname, "domain":device.domain, "network_mode":"dhcp", "partition_mode":"default",
        "system_disk_path":disk, "system_disk_identity":proof, "root_login_mode":"disabled",
        "admin_user_login":login,"admin_user_pwhash":password,"admin_user_fullname":fullname,
        "admin_user_pubkeys":keys,"admin_user_groups":"sudo","_pending_action_id":action,
    });
    tx.execute("UPDATE machines SET status='configured',hostname=?,install_config_json=?,next_action=NULL WHERE id=?",
               params![hostname, snapshot.to_string(), id])?;
    tx.execute(
        "INSERT INTO init_jobs(job_type,status) VALUES(?,'pending'),('bootstrap:render_templates','pending')",
        [format!("action:render_postboot:{action}")],
    )?;
    tx.execute(
        "INSERT INTO machine_events(machine_id,level,message,action_id)
                VALUES(?,'action','Installation programmée au prochain démarrage PXE.',?)",
        params![id, action],
    )?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/tasks/{action}")))
}
