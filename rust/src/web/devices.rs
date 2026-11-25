// SPDX-License-Identifier: LGPL-3.0-only

mod advanced;
pub(super) mod bulk;
mod diagnostics;
pub(super) mod linux;
mod removal;
mod wipe;

use super::{
    admin::escape,
    device_ansible,
    device_operations::{self, Operation},
    plain,
    presets::GUIDED,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{connect, disk_identity, preseed, pxe, setting};
use hyper::StatusCode;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fmt::Write, net::Ipv4Addr, path::Path};

pub(super) fn register(path: &Path, form: Option<&[u8]>) -> Result<Reply, ErrorBox> {
    let Some(form) = form else {
        return Ok(page(
            ConsoleSection::Devices,
            "Ajouter un appareil",
            r#"
<form class="panel panel--form form-stack" method="post" action="/machines">
<div class="field"><label for="device-mac">Adresse MAC</label><input id="device-mac" name="mac" required autocapitalize="none" spellcheck="false" aria-describedby="device-mac-help"><small id="device-mac-help">Exemple : 02:00:00:00:00:01</small></div>
<div class="field"><label for="device-hostname">Nom d’hôte (facultatif)</label><input id="device-hostname" name="hostname" autocapitalize="none" spellcheck="false"></div>
<div class="form-actions"><button>Ajouter l’appareil</button><a class="button button--quiet" href="/admin/devices">Annuler</a></div>
</form>
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
    HardwareContext,
    Command(Operation),
    Ansible(device_ansible::Action),
    Advanced(advanced::Route),
    Diagnostics(diagnostics::Route),
    Wipe,
}

pub(super) fn route(path: &str) -> Option<DeviceRoute> {
    let rest = path.strip_prefix("/machines/")?;
    let (id, section) = rest.split_once('/').unwrap_or((rest, ""));
    let id = id.parse().ok().filter(|id| *id > 0)?;
    let section = match section {
        "" => Section::Detail,
        "install" => Section::Install,
        "install/advanced" => Section::Advanced(advanced::Route::Form),
        "install-preview" => Section::Advanced(advanced::Route::Review),
        "disktest" => Section::Diagnostics(diagnostics::Route::Start),
        "wipe" | "wipe-disks" => Section::Wipe,
        "disktest-cancel" => Section::Diagnostics(diagnostics::Route::Cancel),
        "disktest-post-action" => Section::Diagnostics(diagnostics::Route::After),
        "status" => Section::Status,
        "hardware-context.json" => Section::HardwareContext,
        "rediscover" => Section::Command(Operation::Rediscover),
        "rescue" => Section::Command(Operation::Rescue),
        "rescue/exit" => Section::Command(Operation::ExitRescue),
        "wake" | "reboot" => Section::Command(Operation::Reboot),
        "shutdown" => Section::Command(Operation::Shutdown),
        "power" => Section::Command(Operation::SchedulePower),
        "ansible/pull" => Section::Ansible(device_ansible::Action::Pull),
        "ansible/retry" => Section::Ansible(device_ansible::Action::Retry),
        "ansible/redeploy" => Section::Ansible(device_ansible::Action::Redeploy),
        "auto-deploy" => Section::Ansible(device_ansible::Action::AutoDeploy),
        _ => return None,
    };
    Some(DeviceRoute { id, section })
}

impl DeviceRoute {
    pub(super) fn form_limit(&self, method: &hyper::Method) -> Option<usize> {
        match (&self.section, method) {
            (
                Section::Install
                | Section::Status
                | Section::Command(_)
                | Section::Ansible(_)
                | Section::Advanced(_)
                | Section::Diagnostics(_)
                | Section::Wipe,
                &hyper::Method::POST,
            ) => Some(2048),
            (Section::Detail, &hyper::Method::PUT | &hyper::Method::POST) => Some(64 * 1024),
            (Section::Detail, &hyper::Method::DELETE) => Some(0),
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
            return match &self.section {
                Section::Detail if removal::requested(method, form) => {
                    removal::remove(path, self.id, method, form)
                }
                Section::Install => schedule(path, self.id, form, username),
                Section::Wipe => wipe::submit(path, self.id, form, username),
                Section::Diagnostics(route) => {
                    diagnostics::submit(route, path, self.id, form, username)
                }
                Section::Advanced(route) => advanced::submit(route, path, self.id, form, username),
                Section::Command(operation) => operation.run(path, self.id, form),
                Section::Ansible(action) => action.run(path, self.id, form),
                Section::HardwareContext => Ok(plain(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Method not allowed\n",
                )),
                Section::Detail | Section::Status => super::device_settings::update(
                    path,
                    self.id,
                    method,
                    form,
                    matches!(self.section, Section::Status),
                ),
            };
        }
        let device = Device::get(db, self.id)?;
        if matches!(self.section, Section::HardwareContext) {
            return super::hardware_context::serve(
                device
                    .as_ref()
                    .map(|device| (device.mac.as_str(), &device.inventory)),
            );
        }
        let Some(device) = device else {
            return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
        };
        match self.section {
            Section::Install => install_form(db, self.id, &device),
            Section::Wipe => wipe::form(&device, self.id),
            Section::Diagnostics(diagnostics::Route::Start) => diagnostics::form(&device, self.id),
            Section::Advanced(advanced::Route::Form) => advanced::form(db, self.id, &device),
            Section::Detail => detail(db, self.id, &device),
            Section::Status => super::device_settings::badge(db, self.id, &device.status),
            Section::HardwareContext
            | Section::Command(_)
            | Section::Ansible(_)
            | Section::Diagnostics(_)
            | Section::Advanced(advanced::Route::Review) => Ok(plain(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed\n",
            )),
        }
    }
}

struct Device {
    mac: String,
    hostname: String,
    domain: Option<String>,
    status: String,
    arch: Option<String>,
    rescue: bool,
    inventory: Value,
}

impl Device {
    fn get(db: &Connection, id: i64) -> rusqlite::Result<Option<Self>> {
        db.query_row(
            "SELECT mac,COALESCE(hostname,''),domain,status,boot_arch,rescue_mode=1,inventory_json FROM machines WHERE id=?",
            [id],
            |row| Ok(Self {
                mac: row.get(0)?, hostname: row.get(1)?, domain: row.get(2)?,
                status: row.get(3)?, arch: row.get(4)?,
                rescue: row.get(5)?,
                inventory: row.get::<_, Option<String>>(6)?
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

    fn serial_target(&self, selected: &str) -> Option<(&str, Value)> {
        let mut candidates = self.disks().filter(|(path, value, proof)| {
            selected == format!("{path}:{value}") && proof["kind"] == "serial"
        });
        let (disk, _, proof) = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        let mut reports = crate::pxe::array_values(&self.inventory["disks"]).filter_map(|entry| {
            entry["name"]
                .as_str()
                .filter(|name| *name == disk || disk.strip_prefix("/dev/") == Some(*name))
        });
        let report = reports.next()?;
        reports.next().is_none().then_some((report, proof))
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
    write!(output, "</ul><nav class=\"device-actions\" aria-label=\"Actions de l’appareil\"><a class=\"button\" href=\"/machines/{id}/install\">Programmer une installation Debian</a><a class=\"button button--quiet\" href=\"/activity?machine={id}\">Activité</a>")?;
    if linux::supports(device) {
        write!(output, "<a class=\"button button--quiet\" href=\"/machines/{id}/install/linux\">Programmer une installation Ubuntu ou RHEL</a>")?;
    }
    output.push_str(r#"<a class="button button--quiet" href="/admin/devices">Inventaire</a></nav><h2>Opérations PXE</h2><div class="form-actions">"#);
    write!(
        output,
        r#"<a class="button button--danger" href="/machines/{id}/wipe-disks">Effacer des disques</a>"#
    )?;
    if device.status == "testing" {
        write!(
            output,
            r#"<form method="post" action="/machines/{id}/disktest-cancel"><button class="button--quiet">Annuler le diagnostic</button></form>"#
        )?;
    } else {
        write!(
            output,
            r#"<a class="button button--quiet" href="/machines/{id}/disktest">Programmer un diagnostic de disque</a>"#
        )?;
    }
    write!(
        output,
        r#"<form method="post" action="/machines/{id}/reboot"><button class="button--quiet">Redémarrer</button></form>
<form method="post" action="/machines/{id}/shutdown"><button class="button--quiet">Arrêter</button></form>"#
    )?;
    if device.rescue {
        write!(
            output,
            r#"<form method="post" action="/machines/{id}/rescue/exit"><button class="button--quiet">Quitter le mode récupération</button></form>"#
        )?;
    } else {
        write!(
            output,
            r#"<form method="post" action="/machines/{id}/rediscover"><button class="button--quiet">Redémarrer pour refaire l’inventaire</button></form>
<form method="post" action="/machines/{id}/rescue"><button class="button--quiet">Redémarrer en mode récupération</button></form>"#
        )?;
    }
    output.push_str("</div>");
    super::device_settings::form(db, id, &mut output)?;
    write!(
        output,
        r#"<details><summary>Supprimer cet appareil</summary>
<form method="post" action="/machines/{id}">
<input type="hidden" name="_method" value="DELETE">
<p>La suppression efface la fiche et son historique. Une opération déjà lancée peut continuer sur l’appareil.</p>
<label>Saisissez SUPPRIMER <input name="confirm" required autocomplete="off"></label>
<button class="button--danger">Supprimer l’appareil</button></form></details>"#
    )?;
    device_ansible::form(db, id, &mut output)?;
    write!(
        output,
        "<p><a href=\"/activity?machine={id}\">Historique de l’appareil</a></p>"
    )?;
    if let Some(progress) = super::activity::progress::render(db, id)? {
        output.push_str(&progress);
    }
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
    Ok(page(ConsoleSection::Devices, "Appareil", &output))
}

fn install_form(db: &Connection, id: i64, device: &Device) -> Result<Reply, ErrorBox> {
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(plain(StatusCode::CONFLICT, "Inventaire PXE requis\n"));
    };
    let mut output = format!(
        r#"<form class="panel panel--form form-stack" method="post" action="/machines/{id}/install">
<div class="field"><label for="install-hostname">Nom d’hôte</label><input id="install-hostname" name="hostname" maxlength="63" required value=""#
    );
    escape(&mut output, &device.hostname);
    output.push_str(r#""></div><div class="field"><label for="install-disk">Disque vérifié</label><select id="install-disk" name="disk" required><option value="">Sélectionner</option>"#);
    for (path, serial, _) in device.disks() {
        output.push_str("<option value=\"");
        escape(&mut output, &format!("{path}:{serial}"));
        output.push_str("\">");
        escape(&mut output, &path);
        output.push_str(" · ");
        escape(&mut output, &serial);
        output.push_str("</option>");
    }
    output.push_str(r#"</select></div><div class="field"><label for="install-image">Image Debian</label><select id="install-image" name="image" required><option value="">Sélectionner</option>"#);
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
    output.push_str(r#"</select></div><div class="field"><label for="install-preset">Modèle DHCP</label><select id="install-preset" name="preset" required><option value="">Sélectionner</option>"#);
    let mut presets = db.prepare(&format!(
        "SELECT id,name FROM presets WHERE {GUIDED} ORDER BY name"
    ))?;
    let mut rows = presets.query([])?;
    while let Some(row) = rows.next()? {
        write!(output, "<option value=\"{}\">", row.get::<_, i64>(0)?)?;
        escape(&mut output, &row.get::<_, String>(1)?);
        output.push_str("</option>");
    }
    output.push_str(r#"</select><small><a href="/presets">Gérer les modèles</a></small></div>
<div class="field"><label for="install-network">Réseau de l’appareil</label><select id="install-network" name="network_mode"><option value="dhcp">DHCP</option><option value="static">IPv4 statique</option></select></div>
<details><summary>Paramètres IPv4 statiques</summary>
<p><label>Adresse IPv4 <input name="static_ip"></label></p>
<p><label>Préfixe réseau <input name="static_cidr" type="number" min="1" max="32" value="24"></label></p>
<p><label>Passerelle IPv4 <input name="static_gateway"></label></p>
<p><label>DNS IPv4 <input name="static_dns" value=""#);
    let defaults = crate::migrations::dns_list(&Value::String(setting(db, "default_dns")?));
    escape(&mut output, &defaults.join(" "));
    output.push_str(r#""></label></p></details>"#);
    if device.status == "testing" {
        output.push_str(r#"<label class="check-label"><input type="checkbox" name="after_diagnostic" value="yes" required> Attendre la qualification du disque avant d’autoriser le prochain démarrage PXE</label>"#);
    }
    output.push_str(r#"<label class="check-label"><input type="checkbox" name="confirm" value="yes" required> Confirmer le repartitionnement du disque sélectionné au prochain démarrage PXE</label><div class="form-actions"><button>Programmer l’installation</button></div></form>"#);
    write!(
        output,
        r#"<p><a href="/machines/{id}/install/advanced">Utiliser un modèle de partition personnalisée</a></p>"#
    )?;
    Ok(page(
        ConsoleSection::Devices,
        "Installation Debian guidée",
        &output,
    ))
}

#[derive(serde::Deserialize)]
struct Selection {
    hostname: String,
    disk: String,
    image: i64,
    preset: i64,
    confirm: String,
    #[serde(default)]
    after_diagnostic: String,
    #[serde(default)]
    network_mode: String,
    #[serde(default)]
    static_ip: String,
    #[serde(default)]
    static_cidr: String,
    #[serde(default)]
    static_gateway: String,
    #[serde(default)]
    static_dns: String,
}

impl Selection {
    fn network(&self, db: &Connection) -> rusqlite::Result<Option<Value>> {
        if matches!(self.network_mode.as_str(), "" | "dhcp") {
            return Ok(Some(json!({"network_mode":"dhcp"})));
        }
        if self.network_mode != "static" {
            return Ok(None);
        }
        let Ok(address) = self.static_ip.trim().parse::<Ipv4Addr>() else {
            return Ok(None);
        };
        let Ok(cidr @ 1..=32) = self.static_cidr.trim().parse::<u8>() else {
            return Ok(None);
        };
        let gateway = match self.static_gateway.trim() {
            "" => None,
            raw => {
                let Ok(gateway) = raw.parse::<Ipv4Addr>() else {
                    return Ok(None);
                };
                Some(gateway)
            }
        };
        let dns = crate::migrations::dns_list(&Value::String(self.static_dns.clone()));
        if dns.iter().any(|value| value.parse::<Ipv4Addr>().is_err()) {
            return Ok(None);
        }
        if !static_pxe_address(db, address, cidr, gateway)? {
            return Ok(None);
        }
        Ok(Some(
            json!({"network_mode":"static", "static_ip":address, "static_cidr":cidr,
            "static_gateway":gateway,"static_dns":dns}),
        ))
    }
}

fn static_ipv4_host(ip: Ipv4Addr, address: Ipv4Addr, cidr: u8) -> bool {
    let ip = u32::from(ip);
    let mask = u32::MAX.checked_shl(32 - u32::from(cidr)).unwrap_or(0);
    let network = u32::from(address) & mask;
    ip & mask == network && (cidr > 30 || (ip != network && ip != (network | !mask)))
}

fn static_pxe_address(
    db: &Connection,
    address: Ipv4Addr,
    cidr: u8,
    gateway: Option<Ipv4Addr>,
) -> rusqlite::Result<bool> {
    let Some((network, mask)) = pxe::parse_subnet(&setting(db, "pxe_subnet")?) else {
        return Ok(false);
    };
    let Ok(server) = setting(db, "pxe_ip")?.parse::<Ipv4Addr>() else {
        return Ok(false);
    };
    Ok(
        static_ipv4_host(address, Ipv4Addr::from(network), mask.count_ones() as u8)
            && address != server
            && static_ipv4_host(address, address, cidr)
            && match gateway {
                Some(gateway) => gateway != address && static_ipv4_host(gateway, address, cidr),
                None => static_ipv4_host(server, address, cidr),
            },
    )
}

fn selection(form: &[u8]) -> Option<Selection> {
    let mut fields = serde_json::Map::new();
    for (key, value) in form_urlencoded::parse(form) {
        let value = match key.as_ref() {
            "image" | "preset" => json!(value.parse::<i64>().ok().filter(|id| *id > 0)?),
            "hostname" | "disk" | "confirm" | "after_diagnostic" | "network_mode" | "static_ip"
            | "static_cidr" | "static_dns" | "static_gateway" => json!(value),
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
        || !matches!(selection.after_diagnostic.as_str(), "" | "yes")
        || !valid_hostname(&hostname)
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
    let Some((disk, serial, proof)) = device
        .disks()
        .find(|(path, serial, _)| selection.disk == format!("{path}:{serial}"))
    else {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Le disque sélectionné ne correspond plus à l’inventaire\n",
        ));
    };
    let diagnostic = if selection.after_diagnostic == "yes" && device.status == "testing" {
        active_disk_diagnostic(&tx, id, &disk, &serial, &proof)?
    } else {
        None
    };
    if (selection.after_diagnostic == "yes" && diagnostic.is_none())
        || !schedule_allowed(&tx, id, &device, diagnostic)?
    {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Appareil ou PXE indisponible, ou le disque sélectionné n’est pas couvert par le diagnostic actif\n",
        ));
    }
    let Some(version) = image_version(&tx, selection.image, arch)? else {
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

    let Some(Value::Object(network)) = selection.network(&tx)? else {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Adresse, préfixe ou DNS IPv4 invalides pour le réseau PXE\n",
        ));
    };
    let mut snapshot = json!({
        "distro":"debian", "codename":"trixie", "version_full":version, "variant":"debian",
        "hostname":hostname, "domain":device.domain, "partition_mode":"default",
        "system_disk_path":disk, "system_disk_identity":proof, "root_login_mode":"disabled",
        "admin_user_login":login,"admin_user_pwhash":password,"admin_user_fullname":fullname,
        "admin_user_pubkeys":keys,"admin_user_groups":"sudo",
    });
    snapshot
        .as_object_mut()
        .expect("installation object")
        .extend(network);
    let action = record_plan(
        &tx,
        id,
        username,
        Some(selection.preset),
        snapshot,
        diagnostic,
    )?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/tasks/{action}")))
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn image_version(db: &Connection, id: i64, arch: &str) -> rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT version_full FROM os_images WHERE id=? AND arch=? AND distro='debian'
         AND codename='trixie' AND extract_method='direct' AND enabled=1 AND status='downloaded'
         AND version_full IS NOT NULL",
        params![id, arch],
        |row| row.get(0),
    )
    .optional()
}

fn active_disk_diagnostic(
    db: &Connection,
    id: i64,
    path: &str,
    serial: &str,
    proof: &Value,
) -> rusqlite::Result<Option<(i64, i64)>> {
    if proof["kind"] != "serial" {
        return Ok(None);
    }
    let active: Option<(i64, i64, String)> = db
        .query_row(
            "SELECT t.id,a.id,t.jobs_json FROM disk_tests t
             JOIN actions a ON a.id=t.action_id AND a.machine_id=t.machine_id
             WHERE t.machine_id=?1 AND t.job_status IN ('pending','running')
             AND a.type='disktest' AND a.status IN ('pending','running')
             ORDER BY t.id DESC LIMIT 1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((test, action, raw)) = active else {
        return Ok(None);
    };
    let jobs: Value = serde_json::from_str(&raw).unwrap_or_default();
    let matches_disk = pxe::array_values(&jobs).any(|job| {
        job["disk"]
            .as_str()
            .is_some_and(|disk| disk == path || path.strip_prefix("/dev/") == Some(disk))
            && pxe::disk_test::job_serial(job).as_deref() == Some(serial)
    });
    Ok(matches_disk.then_some((test, action)))
}

fn schedule_allowed(
    db: &Connection,
    id: i64,
    device: &Device,
    diagnostic: Option<(i64, i64)>,
) -> rusqlite::Result<bool> {
    let refreshing: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM init_jobs WHERE job_type='bootstrap:auto_refresh_catalog_v2' AND status='running')",
        [], |row| row.get(0),
    )?;
    Ok(setting(db, "pxe_enabled")? == "on"
        && !refreshing
        && !device.rescue
        && !device_operations::busy_except_diagnostic(db, id, false, diagnostic)?
        && (diagnostic.is_some()
            || matches!(
                device.status.as_str(),
                "discovered" | "tested" | "wiped" | "installed" | "provisioned"
            )))
}

fn record_plan(
    tx: &Transaction<'_>,
    id: i64,
    username: &str,
    preset: Option<i64>,
    mut snapshot: Value,
    diagnostic: Option<(i64, i64)>,
) -> Result<i64, ErrorBox> {
    let token = crate::random_hex::<32>()?;
    tx.execute("INSERT INTO actions(machine_id,type,status,token,created_by) VALUES(?,'install_only','pending',?,?)",
               params![id, token, username])?;
    let action = tx.last_insert_rowid();
    snapshot["_pending_action_id"] = json!(action);
    if let Some((test, _)) = diagnostic {
        snapshot["wake_now"] = json!(true);
        tx.execute(
            "UPDATE disk_tests SET post_action=CASE WHEN in_session=1 THEN 'wait' ELSE 'poweroff' END WHERE id=?1",
            [test],
        )?;
    }
    let hostname = snapshot["hostname"]
        .as_str()
        .ok_or("A validated hostname is required")?;
    let state = if diagnostic.is_some() {
        "testing"
    } else {
        "configured"
    };
    tx.execute("UPDATE machines SET status=?1,hostname=?2,install_config_json=?3,preset_id=?4,next_action=NULL WHERE id=?5",
               params![state, hostname, snapshot.to_string(), preset, id])?;
    if preset.is_some() {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status) VALUES(?,'pending'),('bootstrap:render_templates','pending')",
            [format!("action:render_postboot:{action}")],
        )?;
    } else {
        pxe::enqueue_menus(tx)?;
    }
    tx.execute(
        "INSERT INTO machine_events(machine_id,level,message,action_id) VALUES(?1,'action',?2,?3)",
        params![id, if diagnostic.is_some() {
            "Installation programmée après qualification du disque, au prochain démarrage PXE manuel."
        } else {
            "Installation programmée au prochain démarrage PXE."
        }, action],
    )?;
    Ok(action)
}

fn review_fingerprint(plan: Value) -> Result<String, ErrorBox> {
    Ok(Sha256::digest(serde_json::to_vec(&plan)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn record_reinstall(
    tx: &Transaction<'_>,
    id: i64,
    username: &str,
    preset: i64,
    mut snapshot: Value,
    current_status: &str,
    wipe: &[Value],
) -> Result<i64, ErrorBox> {
    let token = crate::random_hex::<32>()?;
    tx.execute(
        "INSERT INTO actions(machine_id,type,status,token,created_by)
                VALUES(?1,'reinstall','pending',?2,?3)",
        params![id, token, username],
    )?;
    let action = tx.last_insert_rowid();
    snapshot["_pending_action_id"] = json!(action);
    let chain = json!({"hostname":snapshot["hostname"],"domain":snapshot["domain"],"install_config":snapshot});
    wipe::track(tx, id, action, wipe, "reboot", Some(&chain))?;
    pxe::set_machine_status(tx, id, current_status, "wiping")?;
    tx.execute(
        "UPDATE machines SET preset_id=?2,next_action=NULL WHERE id=?1",
        params![id, preset],
    )?;
    tx.execute(
        "INSERT INTO init_jobs(job_type,status) VALUES(?1,'pending')",
        [format!("action:render_postboot:{action}")],
    )?;
    pxe::log_event(
        tx,
        id,
        "action",
        "Effacement et installation programmés au prochain démarrage PXE.",
        None,
        Some(action),
    )?;
    Ok(action)
}
