// SPDX-License-Identifier: LGPL-3.0-only

use super::{escape, page, plain, record_plan, redirect, Device, ErrorBox, Reply};
use crate::{connect, install, migrations, preseed, pxe};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write, path::Path};

pub(super) enum Route {
    Form,
    Review,
}

const MODELS: &str = "distro='debian' AND variant='debian' AND partition_mode='custom'
    AND root_login_mode='disabled' AND COALESCE(admin_user_pwhash,'')<>''
    AND COALESCE(NULLIF(codename,''),'trixie')='trixie'";

#[derive(serde::Deserialize)]
struct Selection {
    preset: i64,
    image: i64,
    hostname: String,
    #[serde(default)]
    review: String,
    #[serde(default)]
    confirm: String,
    #[serde(default)]
    erase: String,
}

pub(super) fn form(db: &Connection, id: i64, device: &Device) -> Result<Reply, ErrorBox> {
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(rejected(StatusCode::CONFLICT, "Inventaire PXE requis"));
    };
    let mut html = format!(
        r#"<form method="post" action="/machines/{id}/install-preview">
<p><label>Nom d’hôte <input name="hostname" required maxlength="63" value=""#
    );
    escape(&mut html, &device.hostname);
    html.push_str(
        r#""></label></p>
<p><label>Image Debian 13 <select name="image" required><option value="">Sélectionner</option>"#,
    );
    let mut statements = db.prepare(
        "SELECT id,version_full FROM os_images WHERE arch=?1 AND distro='debian' AND codename='trixie'
         AND extract_method='direct' AND enabled=1 AND status='downloaded' AND version_full IS NOT NULL
         ORDER BY id DESC"
    )?;
    let mut rows = statements.query([arch])?;
    while let Some(row) = rows.next()? {
        write!(html, r#"<option value="{}">"#, row.get::<_, i64>(0)?)?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str("</option>");
    }
    html.push_str(r#"</select></label></p>
<p><label>Modèle de partition <select name="preset" required><option value="">Sélectionner</option>"#);
    let mut statements = db.prepare(&format!(
        "SELECT id,name FROM presets WHERE {MODELS} ORDER BY name,id"
    ))?;
    let mut rows = statements.query([])?;
    while let Some(row) = rows.next()? {
        write!(html, r#"<option value="{}">"#, row.get::<_, i64>(0)?)?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str("</option>");
    }
    html.push_str("</select></label></p><button>Vérifier les disques</button></form>");
    Ok(page(
        "Installation Debian avec partition personnalisée",
        &html,
    ))
}

pub(super) fn submit(
    route: &Route,
    path: &Path,
    id: i64,
    data: &[u8],
    username: &str,
) -> Result<Reply, ErrorBox> {
    let Some(selection) = selection(data) else {
        return Ok(rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Formulaire de partition invalide",
        ));
    };
    let hostname = selection.hostname.trim().to_ascii_lowercase();
    if !super::valid_hostname(&hostname)
        || matches!(route, Route::Form)
            && (selection.confirm != "yes" || selection.review.len() != 64)
        || matches!(route, Route::Review)
            && (!selection.confirm.is_empty()
                || !selection.review.is_empty()
                || !selection.erase.is_empty())
    {
        return Ok(rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Nom d’hôte ou confirmation invalide",
        ));
    }

    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(device) = Device::get(&tx, id)? else {
        return Ok(rejected(StatusCode::NOT_FOUND, "Appareil introuvable"));
    };
    if !super::schedule_allowed(&tx, id, &device)? {
        return Ok(rejected(
            StatusCode::CONFLICT,
            "L’appareil ou le serveur PXE est occupé ou indisponible",
        ));
    }
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(rejected(StatusCode::CONFLICT, "Inventaire PXE requis"));
    };
    let Some(version) = super::image_version(&tx, selection.image, arch)? else {
        return Ok(rejected(
            StatusCode::CONFLICT,
            "Image Debian indisponible pour cet appareil",
        ));
    };
    let allowed: bool = tx.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM presets WHERE id=?1 AND {MODELS}
           AND COALESCE(NULLIF(version_full,''),?2)=?2)"
        ),
        params![selection.preset, version],
        |row| row.get(0),
    )?;
    if !allowed {
        return Ok(rejected(
            StatusCode::CONFLICT,
            "Modèle de partition incompatible ou indisponible",
        ));
    }
    let Some(mut snapshot) = migrations::snapshot_for_preset(&tx, selection.preset)? else {
        return Ok(rejected(StatusCode::NOT_FOUND, "Modèle introuvable"));
    };
    let Ok((plan, review)) = bind(&device, &snapshot) else {
        return Ok(rejected(
            StatusCode::CONFLICT,
            "Les disques, leur capacité ou le firmware ne correspondent pas au modèle",
        ));
    };
    if !bind_network(&device, &mut snapshot["network"]) {
        return Ok(rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Vérifiez le mode DHCP et la correspondance des interfaces réseau du modèle",
        ));
    }
    if !snapshot["admin_user_login"]
        .as_str()
        .is_some_and(preseed::technical_account)
        || !snapshot["admin_user_pwhash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("$6$") && preseed::sanitized_hash(hash).is_some())
    {
        return Ok(rejected(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Compte d’installation du modèle invalide",
        ));
    }
    let Some(wipe) = wipe_targets(&device, &snapshot) else {
        return Ok(rejected(
            StatusCode::CONFLICT,
            "Les disques à effacer ou leurs identités ne correspondent pas au modèle",
        ));
    };
    let candidate = install::machine(&tx, &device.mac, false)?.ok_or("Missing device for plan")?;
    snapshot["hostname"] = json!(hostname);
    snapshot["codename"] = json!("trixie");
    snapshot["version_full"] = json!(version);
    snapshot["review_boot_mode"] = device.inventory["inventory"]["boot_mode"].clone();
    snapshot["partition_custom_json"] = json!(plan.to_string());
    if let Err(reason) = preseed::validate_plan(&tx, &candidate, &snapshot)? {
        return Ok(rejected(StatusCode::UNPROCESSABLE_ENTITY, reason));
    }
    let fingerprint: String = Sha256::digest(serde_json::to_vec(&json!({
        "machine":id,"model":selection.preset,"image":selection.image,"snapshot":snapshot,
        "targets":review,"erase":wipe,
    }))?)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect();
    match route {
        Route::Review => {
            let mut html = String::from(
                "<p>Le prochain démarrage PXE repartitionnera les disques vérifiés.</p><ul>",
            );
            for (disk, serial, capacity) in review {
                html.push_str("<li>");
                escape(&mut html, &disk);
                html.push_str(" · ");
                escape(&mut html, &serial);
                write!(html, " · {capacity} Mo</li>")?;
            }
            html.push_str("</ul>");
            if !wipe.is_empty() {
                html.push_str("<h2>Disques à effacer avant l’installation</h2><ul>");
                for target in &wipe {
                    html.push_str("<li>");
                    escape(&mut html, target["name"].as_str().unwrap_or_default());
                    html.push_str(" · ");
                    escape(
                        &mut html,
                        target["identity"]["value"].as_str().unwrap_or_default(),
                    );
                    html.push_str(if target["mode"] == "full" {
                        " · effacement complet</li>"
                    } else {
                        " · effacement partiel</li>"
                    });
                }
                html.push_str("</ul>");
            }
            let preset = selection.preset;
            let image = selection.image;
            write!(
                html,
                r#"<form method="post" action="/machines/{id}/install/advanced">
<input type="hidden" name="preset" value="{preset}"><input type="hidden" name="image" value="{image}">
<input type="hidden" name="review" value="{fingerprint}"><input type="hidden" name="hostname" value="{hostname}">
<p><label><input type="checkbox" name="confirm" value="yes" required> Confirmer le repartitionnement des disques indiqués</label></p>"#
            )?;
            if !wipe.is_empty() {
                html.push_str(r#"<p><label>Saisissez EFFACER pour confirmer le pré-effacement <input name="erase" autocomplete="off" required></label></p>"#);
            }
            html.push_str("<button>Programmer l’installation</button></form>");
            Ok(page("Vérifier la partition Debian", &html))
        }
        Route::Form => {
            if selection.review != fingerprint {
                return Ok(rejected(
                    StatusCode::CONFLICT,
                    "Le modèle, l’image ou l’inventaire a changé depuis la vérification",
                ));
            }
            let action = if wipe.is_empty() {
                record_plan(&tx, id, username, selection.preset, snapshot)?
            } else {
                if selection.erase != "EFFACER" {
                    return Ok(rejected(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Confirmez l’effacement des disques affichés",
                    ));
                }
                let token = crate::random_hex::<32>()?;
                tx.execute(
                    "INSERT INTO actions(machine_id,type,status,token,created_by)
                            VALUES(?1,'reinstall','pending',?2,?3)",
                    params![id, token, username],
                )?;
                let action = tx.last_insert_rowid();
                snapshot["_pending_action_id"] = json!(action);
                let chain = json!({"hostname":hostname,"domain":snapshot["domain"],"install_config":snapshot});
                super::wipe::track(&tx, id, action, &wipe, "reboot", Some(&chain))?;
                pxe::set_machine_status(&tx, id, &device.status, "wiping")?;
                tx.execute(
                    "UPDATE machines SET preset_id=?2,next_action=NULL WHERE id=?1",
                    params![id, selection.preset],
                )?;
                tx.execute(
                    "INSERT INTO init_jobs(job_type,status) VALUES(?1,'pending')",
                    [format!("action:render_postboot:{action}")],
                )?;
                pxe::log_event(
                    &tx,
                    id,
                    "action",
                    "Effacement et installation programmés au prochain démarrage PXE.",
                    None,
                    Some(action),
                )?;
                action
            };
            tx.commit()?;
            Ok(redirect(StatusCode::SEE_OTHER, format!("/tasks/{action}")))
        }
    }
}

fn selection(data: &[u8]) -> Option<Selection> {
    let mut fields = Map::new();
    for (name, value) in form_urlencoded::parse(data) {
        let value = match name.as_ref() {
            "preset" | "image" => json!(value.parse::<i64>().ok().filter(|id| *id > 0)?),
            "hostname" | "review" | "confirm" | "erase" => json!(value),
            _ => return None,
        };
        if fields.insert(name.into_owned(), value).is_some() {
            return None;
        }
    }
    serde_json::from_value(Value::Object(fields)).ok()
}

type VerifiedDisks = Vec<(String, String, i64)>;

fn bind(device: &Device, snapshot: &Value) -> Result<(Value, VerifiedDisks), ErrorBox> {
    if !matches!(
        device.inventory["inventory"]["boot_mode"].as_str(),
        Some("BIOS" | "UEFI")
    ) {
        return Err("Unknown client firmware".into());
    }
    let mut plan: Value = serde_json::from_str(
        snapshot["partition_custom_json"]
            .as_str()
            .ok_or("Missing recipe")?,
    )?;
    let targets = plan["target_disks"]
        .as_array()
        .filter(|paths| !paths.is_empty())
        .ok_or("Missing target disks")?;
    let inventory: Vec<_> = device.disks().collect();
    let mut identities = Map::new();
    let mut review = Vec::new();
    for path in targets {
        let path = path.as_str().ok_or("Invalid target disk")?;
        let mut matches = inventory.iter().filter(|(name, _, _)| name == path);
        let (_, serial, identity) = matches.next().ok_or("Missing target identity")?;
        let mut disks = pxe::array_values(&device.inventory["disks"]).filter(|disk| {
            disk["name"]
                .as_str()
                .is_some_and(|name| name == path || path.strip_prefix("/dev/") == Some(name))
        });
        let disk = disks.next().ok_or("Missing target capacity")?;
        if matches.next().is_some() || disks.next().is_some() {
            return Err("Ambiguous target disk".into());
        }
        let capacity = migrations::integer(&disk["size_bytes"])
            .filter(|bytes| *bytes > 0)
            .ok_or("Unknown target capacity")?
            / 1_000_000;
        let recipe = pxe::array_values(&plan["disks"])
            .find(|disk| disk["path"] == path)
            .ok_or("Missing disk recipe")?;
        let reserved = pxe::array_values(&recipe["partitions"])
            .try_fold(0_i64, |total, part| {
                if crate::php_truthy(&part["fill"]) {
                    Some(total)
                } else {
                    total.checked_add(migrations::integer(&part["size_mb"])?)
                }
            })
            .ok_or("Invalid partition capacity")?;
        if capacity <= reserved
            || identities
                .insert(path.to_owned(), identity.clone())
                .is_some()
        {
            return Err("Insufficient capacity or ambiguous disk".into());
        }
        review.push((path.to_owned(), serial.clone(), capacity));
    }
    plan["target_disk_identities"] = Value::Object(identities);
    Ok((plan, review))
}

fn wipe_targets(device: &Device, snapshot: &Value) -> Option<Vec<Value>> {
    let legacy = snapshot["pre_wipe_mode"]
        .as_str()
        .unwrap_or_default()
        .trim();
    let modern = snapshot["pre_wipe_mode_json"]
        .as_str()
        .unwrap_or_default()
        .trim();
    let spec = if modern.is_empty() { legacy } else { modern };
    let configured: HashMap<String, String> = match spec {
        "" | "none" | "aucun" | "[]" | "{}" => return Some(Vec::new()),
        "full" | "partial" => HashMap::from([("*".to_owned(), spec.to_owned())]),
        raw => serde_json::from_str(raw).ok()?,
    };
    let choices: Vec<_> = device.disks().collect();
    let mut modes = HashMap::new();
    for (name, mode) in configured {
        if !matches!(mode.as_str(), "full" | "partial" | "none" | "aucun") {
            return None;
        }
        let path = if name == "*" || name.starts_with("/dev/") {
            name
        } else {
            format!("/dev/{name}")
        };
        if !matches!(mode.as_str(), "none" | "aucun")
            && path != "*"
            && !choices.iter().any(|(present, _, _)| present == &path)
        {
            return None;
        }
        if modes.insert(path, mode).is_some() {
            return None;
        }
    }
    let fallback = modes.get("*").map(String::as_str).unwrap_or("aucun");
    let constraints = &snapshot["disk_target_constraints"];
    let required = pxe::array_values(constraints).next();
    let mut targets = Vec::new();
    for inventory in pxe::array_values(&device.inventory["disks"]) {
        let name = inventory["name"].as_str()?;
        let path = if name.starts_with("/dev/") {
            name.to_owned()
        } else {
            format!("/dev/{name}")
        };
        let mode = modes.get(&path).map(String::as_str).unwrap_or(fallback);
        if !matches!(mode, "partial" | "full") {
            continue;
        }
        let (_, value, _) = choices
            .iter()
            .find(|(candidate, _, _)| candidate == &path)?;
        let (name, proof) = device.serial_target(&format!("{path}:{value}"))?;
        if required.is_some_and(|entry| {
            crate::disk_identity::serial(entry).as_deref() != Some(value.as_str())
        }) {
            return None;
        }
        targets.push(json!({"name":name,"mode":mode,"identity":proof}));
    }
    Some(targets)
}

fn bind_network(device: &Device, plan: &mut Value) -> bool {
    let Some(primary) = plan["primary"]
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
    else {
        return false;
    };
    let Some(interfaces) = plan["interfaces"].as_array_mut() else {
        return false;
    };
    if primary >= interfaces.len() || interfaces[primary]["mode"] != "dhcp" {
        return false;
    }
    let inventory: Vec<_> = pxe::array_values(&device.inventory["interfaces"])
        .map(|nic| nic["mac"].as_str().and_then(pxe::normalize_mac))
        .collect();
    for (index, interface) in interfaces.iter_mut().enumerate() {
        if interface["mode"] == "disabled" && interface["bond"].is_null() {
            continue;
        }
        if interface["mode"] == "static" {
            return false;
        }
        let expected = match interface["match_by"].as_str() {
            Some("primary") if index == primary => continue,
            Some("mac") => interface["match"]["mac"]
                .as_str()
                .and_then(pxe::normalize_mac),
            Some("index") => interface["index"]
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| inventory.get(index))
                .cloned()
                .flatten(),
            _ => return false,
        };
        let Some(mac) = expected.filter(|mac| inventory.iter().flatten().any(|known| known == mac))
        else {
            return false;
        };
        interface["match_by"] = json!("mac");
        interface["match"] = json!({"mac":mac});
    }
    true
}

fn rejected(status: StatusCode, message: &'static str) -> Reply {
    plain(status, message)
}
