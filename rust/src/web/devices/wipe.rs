// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    connect, device_operations, escape, page, plain, redirect, setting, Device, ErrorBox, Reply,
};
use crate::pxe::{log_event, set_machine_status};
use crate::web::ui::ConsoleSection;
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    path::Path,
};

pub(super) fn form(device: &Device, id: i64) -> Result<Reply, ErrorBox> {
    let mut html = String::new();
    write!(
        html,
        r#"<p>L’effacement détruit les données des disques sélectionnés.</p>
<form method="post" action="/admin/inventaire/{id}/wipe-disks">"#
    )?;
    for (path, serial, _) in device
        .disks()
        .filter(|(_, _, proof)| proof["kind"] == "serial")
    {
        html.push_str(r#"<p><label><input type="checkbox" name="targets[]" value=""#);
        escape(&mut html, &format!("{path}:{serial}"));
        html.push_str(r#""> "#);
        escape(&mut html, &format!("{path} · {serial}"));
        html.push_str(r#"</label> <label>Mode <select name="mode["#);
        escape(&mut html, &path);
        html.push_str(r#"]"><option value="partial">Partiel</option><option value="full">Complet</option></select></label></p>"#);
    }
    html.push_str(r#"<p><label>Après l’effacement <select name="post_action">
<option value="poweroff">Arrêter</option><option value="reboot">Redémarrer</option></select></label></p>
<p><label>Saisissez EFFACER pour confirmer <input name="confirm" autocomplete="off" required></label></p>
<button>Programmer l’effacement</button></form>"#);
    Ok(page(ConsoleSection::Devices, "Effacer les disques", &html))
}

pub(super) fn submit(path: &Path, id: i64, data: &[u8], username: &str) -> Result<Reply, ErrorBox> {
    let mut targets = Vec::new();
    let mut modes = HashMap::new();
    let mut after = None;
    let mut confirmed = None;
    for (key, value) in form_urlencoded::parse(data) {
        match key.as_ref() {
            "targets[]" if targets.len() < 64 => targets.push(value),
            "post_action" if after.is_none() => after = Some(value),
            "confirm" if confirmed.is_none() => confirmed = Some(value),
            field if field.starts_with("mode[") && field.ends_with(']') => {
                if modes
                    .insert(field[5..field.len() - 1].to_owned(), value)
                    .is_some()
                {
                    return Ok(invalid());
                }
            }
            _ => return Ok(invalid()),
        }
    }
    let after = after.as_deref().unwrap_or("poweroff");
    if targets.is_empty()
        || confirmed.as_deref() != Some("EFFACER")
        || !matches!(after, "poweroff" | "reboot")
    {
        return Ok(invalid());
    }
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(device) = Device::get(&tx, id)? else {
        return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
    };
    if setting(&tx, "pxe_enabled")? != "on"
        || device.rescue
        || device_operations::running(&device.status)
        || device_operations::busy(&tx, id, false)?
    {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Appareil ou serveur PXE indisponible\n",
        ));
    }
    let mut chosen = Vec::new();
    let mut used = HashSet::new();
    for selected in targets {
        let Some((name, proof)) = device
            .serial_target(&selected)
            .filter(|(name, _)| used.insert(*name))
        else {
            return Ok(plain(
                StatusCode::CONFLICT,
                "Un disque n’a plus l’identité confirmée\n",
            ));
        };
        let path = if name.starts_with("/dev/") {
            name.to_owned()
        } else {
            format!("/dev/{name}")
        };
        let Some(mode) = modes
            .get(&path)
            .map(|mode| mode.as_ref())
            .filter(|mode| matches!(*mode, "partial" | "full"))
        else {
            return Ok(invalid());
        };
        chosen.push(json!({"name":name,"mode":mode,"identity":proof}));
    }
    let token = crate::random_hex::<32>()?;
    tx.execute("INSERT INTO actions(machine_id,type,status,token,created_by) VALUES(?1,'wipe_only','pending',?2,?3)",
               params![id,token,username])?;
    let action = tx.last_insert_rowid();
    track(&tx, id, action, &chosen, after, None)?;
    set_machine_status(&tx, id, &device.status, "wiping")?;
    let queued = tx.execute(
        "UPDATE machines SET next_action='reboot' WHERE id=?1
                          AND julianday(awaiting_action_until)>julianday('now')",
        [id],
    )?;
    if queued == 0 {
        tx.execute("INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending','Redémarrage pour effacement')",
                   [format!("action:reboot:{action}")])?;
    }
    log_event(&tx, id, "action", "Effacement demandé", None, Some(action))?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/tasks/{action}")))
}

pub(super) fn track(
    db: &Connection,
    id: i64,
    action: i64,
    disks: &[Value],
    after: &str,
    chain: Option<&Value>,
) -> rusqlite::Result<()> {
    let mut kinds = disks
        .iter()
        .map(|disk| disk["mode"].as_str().unwrap_or_default());
    let first = kinds.next().unwrap_or_default();
    let aggregate = if kinds.any(|mode| mode != first) {
        "mixed"
    } else {
        first
    };
    db.execute("INSERT INTO wipes(machine_id,disks_json,wipe_mode,wipe_status,post_action,action_id,started_at,chain_install_config_json)
                VALUES(?1,?2,?3,'pending',?4,?5,CURRENT_TIMESTAMP,?6)",
               params![id,json!(disks).to_string(),aggregate,after,action,chain.map(Value::to_string)])?;
    Ok(())
}

fn invalid() -> Reply {
    plain(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Vérifiez les disques, leur mode et la confirmation d’effacement\n",
    )
}
