// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, bytes, plain, setup::redirect, ErrorBox, Reply};
use crate::connect;
use hyper::{Method, Response, StatusCode};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{fmt::Write, path::Path};

const STATUSES: &[(&str, &str)] = &[
    ("unknown", "Inconnu"),
    ("inventorying", "Inventaire en cours"),
    ("discovered", "Inventorié"),
    ("configured", "Configuré"),
    ("installing", "Installation en cours"),
    ("installed", "Installé"),
    ("provisioned", "Provisionné"),
    ("failed", "Échec"),
    ("wiping", "Effacement en cours"),
    ("wiped", "Effacé"),
    ("testing", "Test en cours"),
    ("tested", "Testé"),
];

pub(super) fn form(db: &Connection, id: i64, output: &mut String) -> Result<(), ErrorBox> {
    let (notes, boot, local, status): (Option<String>, String, String, String) = db.query_row(
        "SELECT notes,boot_mode,local_boot_source,status FROM machines WHERE id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    write!(output, "<h2>Notes</h2><form method=\"post\" action=\"/admin/inventaire/{id}\"><input type=\"hidden\" name=\"_method\" value=\"PUT\"><label>Notes <textarea name=\"notes\">")?;
    escape(output, notes.as_deref().unwrap_or_default());
    output.push_str("</textarea></label><button>Enregistrer les notes</button></form>");
    write!(output, "<h2>Démarrage</h2><form method=\"post\" action=\"/admin/inventaire/{id}\"><input type=\"hidden\" name=\"_method\" value=\"PUT\"><label>Protocole <select name=\"boot_mode\">")?;
    option(output, "http", "HTTP", &boot)?;
    option(output, "tftp", "TFTP", &boot)?;
    output.push_str("</select></label><label>Démarrage local <select name=\"local_boot_source\">");
    option(output, "none", "Désactivé", &local)?;
    option(output, "manual", "Activé manuellement", &local)?;
    if local == "pxe" {
        option(output, "pxe", "Activé après installation PXE", &local)?;
    }
    output.push_str("</select></label><button>Enregistrer le démarrage</button></form>");
    write!(output, "<details id=\"settings\"><summary>Corriger le suivi</summary><p>Cette action clôture le suivi des opérations actives. Elle ne garantit aucun arrêt à distance.</p><form method=\"post\" action=\"/admin/inventaire/{id}/status\"><label>État <select name=\"status\">")?;
    for &(value, label) in STATUSES {
        option(output, value, label, &status)?;
    }
    output.push_str("</select></label><button>Corriger le suivi</button></form></details>");
    Ok(())
}

fn option(output: &mut String, value: &str, label: &str, current: &str) -> std::fmt::Result {
    let selected = if current == value { " selected" } else { "" };
    write!(
        output,
        "<option value=\"{value}\"{selected}>{label}</option>"
    )
}

pub(super) fn badge(db: &Connection, id: i64, status: &str) -> Result<Reply, ErrorBox> {
    let (rescue, awaiting, offline): (bool, bool, bool) = db.query_row(
        "SELECT rescue_mode=1,COALESCE(julianday(awaiting_action_until)>julianday('now'),0),
           CASE WHEN COALESCE(awaiting_action_until,'')='' THEN
             status='discovered' AND COALESCE(inventory_json,'') NOT IN ('','0')
             AND COALESCE(julianday(last_seen_at)<=julianday('now','-1 hour'),0)
           ELSE COALESCE(julianday(awaiting_action_until)<=julianday('now'),0)
             AND status NOT IN ('inventorying','installing','wiping','testing','failed') END
         FROM machines WHERE id=?1",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let (style, label) = if rescue {
        ("state-rescue", "Mode rescue")
    } else if awaiting && !matches!(status, "installing" | "wiping" | "testing") {
        ("state-ready", "En attente après inventaire")
    } else if offline {
        ("state-offline", "Hors ligne")
    } else {
        match status {
            "provisioned" | "installed" => ("state-online", "En ligne"),
            "installing" => ("state-running", "Installation en cours"),
            "wiping" => ("state-running", "Effacement en cours"),
            "testing" => ("state-running", "Tests en cours"),
            "inventorying" => ("state-running", "Inventaire en cours…"),
            "failed" => ("state-offline", "En échec"),
            _ => ("state-ready", "En attente"),
        }
    };
    Ok(Response::builder()
        .header("Content-Type","text/html; charset=utf-8")
        .header("Cache-Control","no-store")
        .body(bytes(format!("<span class=\"status-dot {style}\" aria-hidden=\"true\"></span>\n<strong>{label}</strong>\n")))?)
}

#[derive(Default)]
struct Changes {
    notes: Option<String>,
    boot: Option<String>,
    local: Option<String>,
    status: Option<String>,
    method: Option<String>,
}

impl Changes {
    fn parse(form: &[u8]) -> Option<Self> {
        let mut changes = Self::default();
        for (field, value) in form_urlencoded::parse(form) {
            let target = match field.as_ref() {
                "notes" => &mut changes.notes,
                "boot_mode" => &mut changes.boot,
                "local_boot_source" => &mut changes.local,
                "status" => &mut changes.status,
                "_method" => &mut changes.method,
                // Changing these fields requires the installation form.
                "hostname" | "domain" => continue,
                _ => return None,
            };
            if target.replace(value.into_owned()).is_some() {
                return None;
            }
        }
        Some(changes)
    }
}

pub(super) fn update(
    path: &Path,
    id: i64,
    method: &Method,
    form: &[u8],
    force_status: bool,
) -> Result<Reply, ErrorBox> {
    let Some(changes) = Changes::parse(form) else {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Réglages invalides\n",
        ));
    };
    if !force_status && method != Method::PUT && changes.method.as_deref() != Some("PUT") {
        return Ok(plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "Méthode non autorisée\n",
        ));
    }
    let requested_status =
        changes
            .status
            .as_deref()
            .map(|status| if force_status { status.trim() } else { status });
    if (force_status
        && (changes.notes.is_some()
            || changes.local.is_some()
            || changes.boot.is_some()
            || requested_status.is_none()))
        || requested_status
            .is_some_and(|status| !STATUSES.iter().any(|(value, _)| *value == status))
    {
        return Ok(plain(StatusCode::UNPROCESSABLE_ENTITY, "Statut invalide\n"));
    }
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current: Option<(String, String)> = tx
        .query_row(
            "SELECT status,local_boot_source FROM machines WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((status, local)) = current else {
        return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
    };
    let mut render = false;
    if changes.local.as_deref().is_some_and(|source| {
        !(matches!(source, "none" | "manual") || source == "pxe" && local == "pxe")
    }) {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Choix de démarrage local invalide\n",
        ));
    }
    if let Some(source) = changes.local.as_deref().filter(|source| *source != local) {
        let message = match source {
            "manual" => "Démarrage local : activé manuellement par administrateur",
            "none" => "Démarrage local : désactivé",
            _ => unreachable!("validated local boot source"),
        };
        tx.execute(
            "UPDATE machines SET local_boot_source=?1 WHERE id=?2",
            params![source, id],
        )?;
        event(&tx, id, "action", message)?;
        render = true;
    }
    if let Some(target) = requested_status.filter(|requested| *requested != status || force_status)
    {
        correct_status(&tx, id, &status, target)?;
        render = true;
    }
    if let Some(notes) = changes.notes {
        tx.execute(
            "UPDATE machines SET notes=NULLIF(?1,'') WHERE id=?2",
            params![notes, id],
        )?;
    }
    if let Some(boot) = changes.boot {
        let boot = if boot == "tftp" { "tftp" } else { "http" };
        tx.execute(
            "UPDATE machines SET boot_mode=?1 WHERE id=?2",
            params![boot, id],
        )?;
    }
    if render {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message)
             SELECT 'bootstrap:render_templates','pending','Régénération des menus PXE par appareil'
             WHERE NOT EXISTS(SELECT 1 FROM init_jobs WHERE job_type='bootstrap:render_templates' AND status='pending')",
            [],
        )?;
    }
    tx.commit()?;
    let anchor = if force_status { "#settings" } else { "" };
    Ok(redirect(
        StatusCode::SEE_OTHER,
        format!("/admin/inventaire/{id}{anchor}"),
    ))
}

fn correct_status(db: &Connection, id: i64, current: &str, target: &str) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE init_jobs SET status='failed',message='Clôture administrative : demande en attente annulée.'
         WHERE status='pending' AND (job_type IN ('machine:reboot:'||?1,'machine:shutdown:'||?1,'machine:ansible_redeploy:'||?1)
         OR EXISTS(SELECT 1 FROM actions a WHERE a.machine_id=?1 AND a.status IN ('pending','running')
            AND init_jobs.job_type IN ('action:reboot:'||a.id,'action:ansible_retry:'||a.id,'action:render_postboot:'||a.id)))",
        [id],
    )?;
    let closed = db.execute(
        "UPDATE actions SET status='cancelled',ended_at=CURRENT_TIMESTAMP WHERE machine_id=?1 AND status IN ('pending','running')",
        [id],
    )?;
    for (table, column, states) in [
        ("wipes", "wipe_status", "'pending','running'"),
        (
            "installations",
            "install_status",
            "'pending','running','installing','in_progress'",
        ),
        (
            "discoveries",
            "discovery_status",
            "'pending','running','in_progress'",
        ),
        ("disk_tests", "job_status", "'pending','running'"),
    ] {
        db.execute(&format!("UPDATE {table} SET {column}='aborted',ended_at=CURRENT_TIMESTAMP WHERE machine_id=?1 AND {column} IN ({states})"),[id])?;
    }
    db.execute(
        "UPDATE installations SET ansible_status='aborted' WHERE machine_id=?1 AND ansible_status IN ('pending','running','in_progress')",
        [id],
    )?;
    db.execute(
        "UPDATE machines SET status=?1,next_action=NULL,awaiting_action_until=NULL WHERE id=?2",
        params![target, id],
    )?;
    if matches!(target,"installing"|"wiping"|"wiped") && db.execute(
        "UPDATE machines SET local_boot_source='none' WHERE id=?1 AND local_boot_source<>'none'",[id],
    )? > 0 {
        event(db,id,"info","Démarrage local désactivé au début de l’opération")?;
    }
    if target != current {
        event(db, id, "info", &format!("Status: {current} → {target}"))?;
    }
    event(db,id,"action",&format!("Correction administrative du suivi : {current} → {target}. {closed} action(s) clôturée(s). Aucun arrêt distant garanti."))
}

fn event(db: &Connection, id: i64, level: &str, message: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO machine_events(machine_id,level,message) VALUES(?1,?2,?3)",
        params![id, level, message],
    )?;
    Ok(())
}
