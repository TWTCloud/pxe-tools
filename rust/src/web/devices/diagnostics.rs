// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    connect, device_operations, escape, page, plain, redirect, setting, Device, ErrorBox, Reply,
};
use crate::pxe::{log_event, set_machine_status};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{fmt::Write, path::Path};

pub(super) enum Route {
    Start,
    Cancel,
    After,
}

const TEST_MODES: &[(&str, &str)] = &[
    ("smart_short", "Test SMART court"),
    ("smart_long", "Test SMART long"),
    ("badblocks_quick_ro", "Lecture de la surface"),
    ("badblocks_fixed_rw", "Écriture avec motif fixe"),
    ("badblocks_quick_rw", "Écriture avec motif aléatoire"),
    ("badblocks_long_rw", "Écriture avec plusieurs motifs"),
];

pub(super) fn form(device: &Device, id: i64) -> Result<Reply, ErrorBox> {
    let mut html=String::from("<p>Le test est exécuté au démarrage PXE. Les modes d’écriture effacent les données du disque choisi.</p>");
    write!(
        html,
        r#"<form method="post" action="/machines/{id}/disktest">
<label>Disque vérifié <select name="disk" required><option value="">Sélectionner</option>"#
    )?;
    for (path, id, _) in device
        .disks()
        .filter(|(_, _, proof)| proof["kind"] == "serial")
    {
        html.push_str(r#"<option value=""#);
        escape(&mut html, &format!("{path}:{id}"));
        html.push_str(r#"">"#);
        escape(&mut html, &format!("{path} · {id}"));
        html.push_str("</option>");
    }
    html.push_str(
        r#"</select></label>
<p><label>Type de test <select name="mode">"#,
    );
    for (value, label) in TEST_MODES {
        write!(html, r#"<option value="{value}">{label}</option>"#)?;
    }
    html.push_str(r#"</select></label></p>
<p><label>Action après le test <select name="post_action">
<option value="">Automatique</option><option value="reboot">Redémarrer</option>
<option value="poweroff">Arrêter</option><option value="wait">Attendre</option></select></label></p>
<p><label>Pour un test en écriture, saisissez DETRUIRE <input name="confirm" autocomplete="off"></label></p>
<button>Programmer le test</button></form>"#);
    Ok(page("Diagnostic du disque", &html))
}

pub(super) fn submit(
    route: &Route,
    path: &Path,
    id: i64,
    form: &[u8],
    username: &str,
) -> Result<Reply, ErrorBox> {
    let mut fields = std::collections::HashMap::new();
    for (key, value) in form_urlencoded::parse(form) {
        if !matches!(key.as_ref(), "disk" | "mode" | "confirm" | "post_action")
            || fields.insert(key, value).is_some()
        {
            return Ok(bad("Formulaire de diagnostic invalide
"));
        }
    }
    let field = |name| {
        fields
            .get(name)
            .map(|value| value.as_ref())
            .unwrap_or_default()
    };
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(device) = Device::get(&tx, id)? else {
        return Ok(plain(
            StatusCode::NOT_FOUND,
            "Appareil introuvable
",
        ));
    };
    let after = field("post_action");
    let task = match route {
        Route::Start => {
            let mode = field("mode");
            if !TEST_MODES.iter().any(|(option, _)| *option == mode)
                || !matches!(after, "" | "wait" | "reboot" | "poweroff")
                || !mode.ends_with("_ro")
                    && mode.starts_with("badblocks_")
                    && field("confirm") != "DETRUIRE"
            {
                return Ok(bad("Vérifiez le mode et la confirmation du test
"));
            }
            if setting(&tx, "pxe_enabled")? != "on"
                || device.rescue
                || device_operations::running(&device.status)
                || device_operations::busy(&tx, id, false)?
            {
                return Ok(busy());
            }
            let Some((report, proof)) = device.serial_target(field("disk")) else {
                return Ok(busy());
            };
            let in_session: bool = tx.query_row(
                "SELECT COALESCE(julianday(awaiting_action_until)>julianday('now','+60 seconds'),0)
                 FROM machines WHERE id=?1",
                [id],
                |row| row.get(0),
            )?;
            let after = match after {
                "" if in_session => "wait",
                "" if !mode.ends_with("_rw")
                    && matches!(device.status.as_str(), "installed" | "provisioned") =>
                {
                    "reboot"
                }
                "" => "poweroff",
                "wait" if !in_session => {
                    return Ok(bad(
                        "L’appareil doit être en attente pour reprendre la session
",
                    ))
                }
                value => value,
            };
            let token = crate::random_hex::<32>()?;
            tx.execute(
                "INSERT INTO actions(machine_id,type,status,token,created_by)
                        VALUES(?1,'disktest','pending',?2,?3)",
                params![id, token, username],
            )?;
            let action = tx.last_insert_rowid();
            let specs = json!([{"disk":report,"mode":mode,"identity":proof}]).to_string();
            tx.execute("INSERT INTO disk_tests(machine_id,jobs_json,job_status,post_action,action_id,started_at,in_session)
                        VALUES(?1,?2,'pending',?3,?4,CURRENT_TIMESTAMP,?5)",params![id,specs,after,action,in_session])?;
            set_machine_status(&tx, id, &device.status, "testing")?;
            if !in_session {
                tx.execute("INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending','Redémarrage pour diagnostic')",
                           [format!("action:reboot:{action}")])?;
            }
            log_event(
                &tx,
                id,
                "action",
                "Diagnostic du disque demandé",
                None,
                Some(action),
            )?;
            format!("/tasks/{action}")
        }
        Route::Cancel | Route::After => {
            let test = tx
                .query_row(
                    "SELECT id,in_session,action_id FROM disk_tests WHERE machine_id=?1
                      AND job_status IN ('pending','running') ORDER BY id DESC LIMIT 1",
                    [id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)? == 1,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((test, in_session, action)) = test {
                if matches!(route, Route::After) {
                    if !matches!(after, "wait" | "reboot" | "poweroff")
                        || after == "wait" && !in_session
                    {
                        return Ok(bad("Action de fin invalide
"));
                    }
                    tx.execute(
                        "UPDATE disk_tests SET post_action=?2 WHERE id=?1",
                        params![test, after],
                    )?;
                } else {
                    cancel(&tx, id, test, in_session, action, &device)?;
                }
            }
            format!("/machines/{id}")
        }
    };
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, task))
}

fn cancel(
    db: &Connection,
    id: i64,
    test: i64,
    in_session: bool,
    action: Option<i64>,
    device: &Device,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE disk_tests SET job_status='aborted',ended_at=CURRENT_TIMESTAMP WHERE id=?1",
        [test],
    )?;
    if let Some(action) = action {
        db.execute("UPDATE actions SET status='cancelled',ended_at=CURRENT_TIMESTAMP WHERE id=?1 AND machine_id=?2",
                   params![action,id])?;
        db.execute("UPDATE init_jobs SET status='failed',ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
                   WHERE job_type=?1 AND status='pending'",[format!("action:reboot:{action}")])?;
    }
    let raw: Option<String> = db.query_row(
        "SELECT install_config_json FROM machines WHERE id=?1",
        [id],
        |row| row.get(0),
    )?;
    let config: Value = raw
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    if let Some(pending) = crate::migrations::integer(&config["_pending_action_id"]) {
        db.execute(
            "UPDATE actions SET status='cancelled',ended_at=CURRENT_TIMESTAMP
                   WHERE id=?1 AND machine_id=?2 AND status='pending' AND type='install_only'",
            params![pending, id],
        )?;
    }
    set_machine_status(db, id, &device.status, "discovered")?;
    db.execute(
        "UPDATE machines SET next_action=NULL, awaiting_action_until=CASE WHEN ?2
              THEN datetime('now','+1 hour') END WHERE id=?1",
        params![id, in_session],
    )?;
    log_event(
        db,
        id,
        "action",
        "Suivi du test annulé. L’agent recevra l’arrêt au prochain contact.",
        None,
        action,
    )
}

fn bad(message: &'static str) -> Reply {
    plain(StatusCode::UNPROCESSABLE_ENTITY, message)
}
fn busy() -> Reply {
    plain(
        StatusCode::CONFLICT,
        "Appareil occupé ou disque indisponible. Vérifiez l’inventaire.\n",
    )
}
