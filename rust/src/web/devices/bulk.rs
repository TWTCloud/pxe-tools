// SPDX-License-Identifier: LGPL-3.0-only

use super::{advanced, escape, page, removal, Device, ErrorBox, Reply};
use crate::web::ui::ConsoleSection;
use crate::{connect, install, migrations, preseed, pxe, web::jobs::json_reply};
use hyper::{Method, StatusCode};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{collections::HashMap, fmt::Write, path::Path};

pub(in crate::web) enum Route {
    Form,
    Preview,
    Install,
    Delete,
}

impl Route {
    pub(in crate::web) fn for_path(path: &str) -> Option<Self> {
        Some(match path {
            "/admin/inventaire/bulk" => Self::Form,
            "/admin/inventaire/bulk-preflight" => Self::Preview,
            "/admin/inventaire/bulk-install" => Self::Install,
            "/admin/inventaire/bulk-delete" => Self::Delete,
            _ => return None,
        })
    }

    pub(in crate::web) fn allows(&self, method: &Method) -> bool {
        match self {
            Self::Form => matches!(*method, Method::GET | Method::HEAD),
            Self::Delete => matches!(*method, Method::GET | Method::HEAD | Method::POST),
            _ => *method == Method::POST,
        }
    }

    pub(in crate::web) fn serve(
        &self,
        db: &Connection,
        path: &Path,
        form: Option<&[u8]>,
        username: &str,
        number: u32,
    ) -> Result<Reply, ErrorBox> {
        if matches!(self, Self::Form) {
            return selection_form(db, number);
        }
        if matches!(self, Self::Delete) {
            return match form {
                Some(form) => removal::bulk(path, form),
                None => delete_form(db, number),
            };
        }
        let Some(selection) = form.and_then(Selection::parse) else {
            return json_reply(
                StatusCode::UNPROCESSABLE_ENTITY,
                json!({"error":"Sélectionnez un modèle et au moins un appareil."}),
            );
        };
        match self {
            Self::Preview => preview(db, &selection),
            Self::Install => queue(path, username, &selection),
            Self::Form | Self::Delete => unreachable!("handled above"),
        }
    }
}

#[derive(Default)]
struct Selection {
    preset: i64,
    devices: Vec<i64>,
    fingerprints: HashMap<i64, String>,
    html: bool,
    wake: bool,
    erase: bool,
}

impl Selection {
    fn parse(form: &[u8]) -> Option<Self> {
        let mut result = Self::default();
        let mut fields = HashMap::new();
        for (key, value) in form_urlencoded::parse(form) {
            match key.as_ref() {
                "machine_ids[]" | "machine_ids" => {
                    let id = value.parse::<i64>().ok().filter(|id| *id > 0)?;
                    if !result.devices.contains(&id) {
                        result.devices.push(id);
                    }
                }
                key if key.starts_with("fingerprints[") => {
                    let id = key
                        .strip_prefix("fingerprints[")?
                        .strip_suffix(']')?
                        .parse()
                        .ok()?;
                    if result.fingerprints.insert(id, value.into_owned()).is_some() {
                        return None;
                    }
                }
                "preset_id" | "format" | "wake_now" | "erase" => {
                    if fields
                        .insert(key.into_owned(), value.into_owned())
                        .is_some()
                    {
                        return None;
                    }
                }
                _ => return None,
            }
        }
        result.preset = fields.get("preset_id")?.parse().ok()?;
        result.html = fields.get("format").is_some_and(|value| value == "html");
        result.wake = fields
            .get("wake_now")
            .is_some_and(|value| matches!(value.as_str(), "1" | "on" | "yes"));
        result.erase = fields.get("erase").is_some_and(|value| value == "EFFACER");
        (result.preset > 0 && !result.devices.is_empty() && result.devices.len() <= 100)
            .then_some(result)
    }
}

const MODELS: &str = "distro='debian' AND variant='debian' AND root_login_mode='disabled'
    AND partition_mode IN ('default','custom') AND COALESCE(NULLIF(codename,''),'trixie')='trixie'";

fn selection_form(db: &Connection, number: u32) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<nav><a href="/admin/inventaire">Appareils</a></nav>
<form method="post" action="/admin/inventaire/bulk-preflight"><input type="hidden" name="format" value="html">
<p><label>Modèle Debian <select name="preset_id" required><option value="">Sélectionner</option>"#,
    );
    let mut models = db.prepare(&format!(
        "SELECT id,name FROM presets WHERE {MODELS} ORDER BY name,id"
    ))?;
    let mut rows = models.query([])?;
    while let Some(row) = rows.next()? {
        write!(html, "<option value=\"{}\">", row.get::<_, i64>(0)?)?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str("</option>");
    }
    html.push_str("</select></label></p>");
    let next = device_checkboxes(db, number, &mut html)?;
    html.push_str("<p><label><input type=\"checkbox\" name=\"wake_now\" value=\"1\"> Demander le redémarrage des appareils</label></p><button>Vérifier les cibles</button></form>");
    pagination(&mut html, "/admin/inventaire/bulk", number, next)?;
    Ok(page(
        ConsoleSection::Devices,
        "Déploiement Debian par lots",
        &html,
    ))
}

fn delete_form(db: &Connection, number: u32) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<nav><a href="/admin/inventaire">Appareils</a></nav>
<p>La suppression retire les fiches sélectionnées et leurs historiques, même si une opération est en cours.</p>
<form method="post" action="/admin/inventaire/bulk-delete">"#,
    );
    let next = device_checkboxes(db, number, &mut html)?;
    html.push_str(r#"<p><label>Saisissez SUPPRIMER <input name="confirm" required autocomplete="off"></label></p>
<button>Supprimer les appareils sélectionnés</button></form>"#);
    pagination(&mut html, "/admin/inventaire/bulk-delete", number, next)?;
    Ok(page(ConsoleSection::Devices, "Suppression par lots", &html))
}

fn device_checkboxes(db: &Connection, number: u32, html: &mut String) -> Result<bool, ErrorBox> {
    html.push_str("<fieldset><legend>Appareils cibles</legend>");
    let mut devices = db.prepare(
        "SELECT id,COALESCE(hostname,''),mac,status FROM machines ORDER BY id LIMIT 101 OFFSET ?",
    )?;
    let mut rows = devices.query([i64::from(number - 1) * 100])?;
    for _ in 0..100 {
        let Some(row) = rows.next()? else { break };
        write!(
            html,
            "<p><label><input type=\"checkbox\" name=\"machine_ids[]\" value=\"{}\"> ",
            row.get::<_, i64>(0)?
        )?;
        let hostname: String = row.get(1)?;
        if !hostname.is_empty() {
            escape(html, &hostname);
            html.push_str(" · ");
        }
        escape(html, &row.get::<_, String>(2)?);
        if removal::in_progress(&row.get::<_, String>(3)?) {
            html.push_str(" · opération en cours");
        }
        html.push_str("</label></p>");
    }
    html.push_str("</fieldset>");
    Ok(rows.next()?.is_some())
}

fn pagination(html: &mut String, route: &str, number: u32, next: bool) -> std::fmt::Result {
    if number > 1 {
        write!(
            html,
            "<a href=\"{route}?page={}\">Précédente</a> ",
            number - 1
        )?;
    }
    if next && number < u32::MAX {
        write!(html, "<a href=\"{route}?page={}\">Suivante</a>", number + 1)?;
    }
    Ok(())
}

struct Plan {
    snapshot: Value,
    disks: advanced::VerifiedDisks,
    wipe: Vec<Value>,
    fingerprint: String,
    status: String,
}

#[derive(Clone, Copy)]
struct Rejection {
    state: &'static str,
    reason: &'static str,
}

impl Rejection {
    fn block(reason: &'static str) -> Self {
        Self {
            state: "blocked",
            reason,
        }
    }
    fn adapt(reason: &'static str) -> Self {
        Self {
            state: "adapt",
            reason,
        }
    }
}

fn model(db: &Connection, id: i64) -> Result<Option<Value>, ErrorBox> {
    let available: bool = db.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM presets WHERE id=?1 AND {MODELS})"),
        [id],
        |row| row.get(0),
    )?;
    if available {
        migrations::snapshot_for_preset(db, id)
    } else {
        Ok(None)
    }
}

fn make_plan(
    db: &Connection,
    selection: &Selection,
    id: i64,
    device: &Device,
    mut snapshot: Value,
) -> Result<Result<Plan, Rejection>, ErrorBox> {
    if !super::schedule_allowed(db, id, device, None)? {
        return Ok(Err(Rejection::block(
            "L’appareil ou le serveur PXE est occupé ou indisponible.",
        )));
    }
    let hostname = device.hostname.trim().to_ascii_lowercase();
    if !super::valid_hostname(&hostname) {
        return Ok(Err(Rejection::adapt(
            "Définissez un nom d’hôte valide dans l’assistant individuel.",
        )));
    }
    let Some(arch @ ("amd64" | "arm64")) = device.arch.as_deref() else {
        return Ok(Err(Rejection::block("Inventaire PXE requis.")));
    };
    let image = db
        .query_row(
            "SELECT id,version_full FROM os_images
         WHERE arch=?1 AND distro='debian' AND codename='trixie' AND extract_method='direct'
           AND enabled=1 AND status='downloaded' AND version_full IS NOT NULL AND version_full<>''
           AND (?2='' OR version_full=?2)
         ORDER BY id DESC LIMIT 1",
            params![arch, snapshot["version_full"].as_str().unwrap_or_default()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((image_id, version)) = image else {
        return Ok(Err(Rejection::block(
            "Image Debian indisponible pour cet appareil.",
        )));
    };
    if selection.devices.len() > 1
        && pxe::array_values(&snapshot["network"]["interfaces"]).any(|nic| nic["mode"] == "static")
    {
        return Ok(Err(Rejection::adapt(
            "Le modèle attribuerait la même adresse statique à plusieurs appareils.",
        )));
    }
    if !advanced::bind_network(db, device, &mut snapshot["network"])? {
        return Ok(Err(Rejection::adapt(
            "Vérifiez les interfaces et le plan IPv4 du modèle.",
        )));
    }
    let disks = if snapshot["partition_mode"] == "custom" {
        let Ok((recipe, disks)) = advanced::bind(device, &snapshot) else {
            return Ok(Err(Rejection::adapt(
                "Les disques identifiés ne correspondent pas à la recette.",
            )));
        };
        snapshot["partition_custom_json"] = json!(recipe.to_string());
        disks
    } else {
        let candidates: Vec<_> = device.disks().collect();
        let [(path, serial, identity)] = candidates.as_slice() else {
            return Ok(Err(Rejection::adapt(
                "Sélectionnez le disque dans l’assistant individuel.",
            )));
        };
        let reported: Vec<_> = pxe::array_values(&device.inventory["disks"]).collect();
        if reported.len() != 1
            || pxe::array_values(&snapshot["disk_target_constraints"])
                .next()
                .is_some()
        {
            return Ok(Err(Rejection::adapt(
                "Vérifiez le disque et les contraintes dans l’assistant individuel.",
            )));
        }
        let capacity =
            migrations::integer(&reported[0]["size_bytes"]).unwrap_or_default() / 1_000_000;
        snapshot["system_disk_path"] = json!(path);
        snapshot["system_disk_identity"] = identity.clone();
        vec![(path.clone(), serial.clone(), capacity)]
    };
    let Some(wipe) = advanced::wipe_targets(device, &snapshot) else {
        return Ok(Err(Rejection::adapt(
            "Les cibles de pré-effacement ne correspondent pas à l’inventaire.",
        )));
    };
    let machine = install::machine(db, &device.mac, false)?.ok_or("Missing device for plan")?;
    snapshot["hostname"] = json!(hostname);
    if let Some(domain) = device.domain.as_ref() {
        snapshot["domain"] = json!(domain);
    }
    snapshot["codename"] = json!("trixie");
    snapshot["version_full"] = json!(version);
    snapshot["review_boot_mode"] = device.inventory["inventory"]["boot_mode"].clone();
    if let Err(reason) = preseed::validate_plan(db, &machine, &snapshot)? {
        return Ok(Err(Rejection::adapt(reason)));
    }
    let fingerprint = super::review_fingerprint(json!({
            "machine":id,"model":selection.preset,"image":image_id,"snapshot":snapshot,
            "targets":disks,"wipe":wipe,"wake":selection.wake,
    }))?;
    Ok(Ok(Plan {
        snapshot,
        disks,
        wipe,
        fingerprint,
        status: device.status.clone(),
    }))
}

fn preview(db: &Connection, selection: &Selection) -> Result<Reply, ErrorBox> {
    let tx = db.unchecked_transaction()?;
    let Some(snapshot) = model(&tx, selection.preset)? else {
        return json_reply(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"error":"Modèle Debian indisponible."}),
        );
    };
    let mut targets = Vec::new();
    let mut ready = 0;
    for &id in &selection.devices {
        let device = Device::get(&tx, id)?;
        let name = device.as_ref().map_or_else(
            || format!("Appareil #{id}"),
            |device| {
                if device.hostname.is_empty() {
                    device.mac.clone()
                } else {
                    device.hostname.clone()
                }
            },
        );
        let result = if let Some(device) = device {
            make_plan(&tx, selection, id, &device, snapshot.clone())?
        } else {
            Err(Rejection::block("Appareil introuvable."))
        };
        targets.push(match result {
            Ok(plan) => {
                ready += 1;
                let disks: Vec<_> = plan.disks.iter().map(|(path, serial, capacity)|
                    json!({"path":path,"serial":serial,"size_mb":capacity})).collect();
                json!({"id":id,"label":name,"state":"ready","reasons":[],"network":plan.snapshot["network"],
                       "disks":disks,"pre_wipe":plan.wipe,"fingerprint":plan.fingerprint})
            }
            Err(error) => json!({"id":id,"label":name,"state":error.state,"reasons":[error.reason],
                                "network":[],"disks":[],"pre_wipe":[]}),
        });
    }
    tx.commit()?;
    if !selection.html {
        return json_reply(
            StatusCode::OK,
            json!({"targets":targets,"ready_count":ready,"total":targets.len()}),
        );
    }
    preview_page(selection, &targets, ready)
}

fn preview_page(selection: &Selection, targets: &[Value], ready: usize) -> Result<Reply, ErrorBox> {
    let mut html = format!(
        r#"<form method="post" action="/admin/inventaire/bulk-install">
<input type="hidden" name="preset_id" value="{}"><input type="hidden" name="format" value="html"><ol>"#,
        selection.preset
    );
    let mut erase = false;
    for target in targets {
        html.push_str("<li><strong>");
        escape(&mut html, target["label"].as_str().unwrap_or_default());
        html.push_str("</strong>");
        if let Some(fingerprint) = target["fingerprint"].as_str() {
            let id = target["id"].as_i64().unwrap_or_default();
            write!(
                html,
                r#"<input type="hidden" name="machine_ids[]" value="{id}">
<input type="hidden" name="fingerprints[{id}]" value="{fingerprint}"><ul>"#
            )?;
            for disk in pxe::array_values(&target["disks"]) {
                html.push_str("<li>");
                escape(&mut html, disk["path"].as_str().unwrap_or_default());
                html.push_str(" · ");
                escape(&mut html, disk["serial"].as_str().unwrap_or_default());
                html.push_str("</li>");
            }
            for disk in pxe::array_values(&target["pre_wipe"]) {
                erase = true;
                html.push_str("<li>Pré-effacement · ");
                escape(&mut html, disk["name"].as_str().unwrap_or_default());
                html.push_str(if disk["mode"] == "full" {
                    " · complet</li>"
                } else {
                    " · partiel</li>"
                });
            }
            html.push_str("</ul>");
            if pxe::array_values(&target["network"]["interfaces"]).any(|nic| {
                nic["mode"] == "static" || !nic["vlan"].is_null() || !nic["bond"].is_null()
            }) {
                advanced::network_review(&target["network"], &mut html);
            }
        } else {
            for reason in pxe::array_values(&target["reasons"]) {
                html.push_str("<p>");
                escape(&mut html, reason.as_str().unwrap_or_default());
                html.push_str("</p>");
            }
        }
        html.push_str("</li>");
    }
    html.push_str("</ol>");
    if selection.wake {
        html.push_str(r#"<input type="hidden" name="wake_now" value="1"><p>Le serveur demandera le redémarrage des appareils prêts.</p>"#);
    }
    if erase {
        html.push_str(r#"<p><label>Saisissez EFFACER pour confirmer le pré-effacement des disques indiqués <input name="erase" required autocomplete="off"></label></p>"#);
    }
    if ready > 0 {
        write!(html, "<button>Programmer le repartitionnement et l’installation sur {ready} appareil(s)</button>")?;
    }
    html.push_str("</form><a href=\"/admin/inventaire/bulk\">Modifier la sélection</a>");
    Ok(page(
        ConsoleSection::Devices,
        "Contrôle du déploiement par lots",
        &html,
    ))
}

fn queue(path: &Path, username: &str, selection: &Selection) -> Result<Reply, ErrorBox> {
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let mut results = Vec::new();
    let mut count = 0;
    for &id in &selection.devices {
        let outcome = queue_target(&mut db, id, username, selection);
        results.push(match outcome {
            Ok(Ok(action)) => {
                count += 1;
                json!({"id":id,"ok":true,"action_id":action})
            }
            Ok(Err(reason)) => json!({"id":id,"ok":false,"reason":reason}),
            Err(_) => {
                json!({"id":id,"ok":false,"reason":"La programmation de cet appareil a échoué."})
            }
        });
    }
    if !selection.html {
        return json_reply(
            StatusCode::OK,
            json!({"results":results,"started_count":count}),
        );
    }
    let mut html = format!("<p>{count} installation(s) programmée(s).</p><ul>");
    for result in results {
        let id = result["id"].as_i64().unwrap_or_default();
        write!(html, "<li>Appareil #{id} · ")?;
        if let Some(action) = result["action_id"].as_i64() {
            write!(
                html,
                "<a href=\"/tasks/{action}\">Suivre l’installation</a>"
            )?;
        } else {
            escape(&mut html, result["reason"].as_str().unwrap_or_default());
        }
        html.push_str("</li>");
    }
    html.push_str("</ul><a href=\"/admin/inventaire\">Appareils</a>");
    Ok(page(
        ConsoleSection::Devices,
        "Déploiement Debian par lots",
        &html,
    ))
}

fn queue_target(
    db: &mut Connection,
    id: i64,
    username: &str,
    selection: &Selection,
) -> Result<Result<i64, &'static str>, ErrorBox> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (Some(device), Some(snapshot)) = (Device::get(&tx, id)?, model(&tx, selection.preset)?)
    else {
        return Ok(Err("Appareil ou modèle introuvable."));
    };
    let plan = match make_plan(&tx, selection, id, &device, snapshot)? {
        Ok(plan) => plan,
        Err(error) => return Ok(Err(error.reason)),
    };
    if selection.fingerprints.get(&id) != Some(&plan.fingerprint)
        || (!plan.wipe.is_empty() && !selection.erase)
    {
        return Ok(Err("Contrôle préalable ou confirmation à renouveler."));
    }
    let action = if plan.wipe.is_empty() {
        super::record_plan(
            &tx,
            id,
            username,
            Some(selection.preset),
            plan.snapshot,
            None,
        )?
    } else {
        super::record_reinstall(
            &tx,
            id,
            username,
            selection.preset,
            plan.snapshot,
            &plan.status,
            &plan.wipe,
        )?
    };
    if selection.wake {
        tx.execute("UPDATE machines SET next_action='reboot' WHERE id=?1", [id])?;
        tx.execute(
            "INSERT INTO init_jobs(job_type,status) VALUES(?1,'pending')",
            [format!("action:reboot:{action}")],
        )?;
    }
    tx.commit()?;
    Ok(Ok(action))
}
