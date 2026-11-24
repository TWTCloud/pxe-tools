// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, pxe::log_event, setting};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{error::Error, path::Path};

const RETRY_PREFIX: &str = "action:ansible_retry:";

pub(crate) fn retry(database: &Path, id: i64) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !database.is_absolute() || id <= 0 {
        return Err("Expected a positive job ID and an absolute database path".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let kind = tx
        .query_row(
            "SELECT job_type FROM init_jobs WHERE id=?1 AND status='pending'",
            [id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(kind) = kind else { return Ok(()) };
    let suffix = kind
        .strip_prefix(RETRY_PREFIX)
        .ok_or("Unsupported Ansible job")?;
    let action = suffix
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0 && suffix.bytes().all(|byte| byte.is_ascii_digit()));
    let (status, message) = if setting(&tx, "ansible_enabled")? != "on" {
        (
            "failed",
            "Module Ansible désactivé ; aucune synchronisation ou exécution.".to_owned(),
        )
    } else if let Some(action) = action {
        match requeue(&tx, action)? {
            Ok(installation) => (
                "success",
                format!("Nouvel essai Ansible programmé pour l’installation #{installation}."),
            ),
            Err(reason) => ("failed", reason),
        }
    } else {
        ("failed", "Identifiant d’action invalide.".to_owned())
    };
    tx.execute(
        "UPDATE init_jobs SET status=?2,message=?3,started_at=CURRENT_TIMESTAMP,
         ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        params![id, status, message],
    )?;
    tx.commit()?;
    Ok(())
}

fn requeue(db: &Connection, action: i64) -> rusqlite::Result<Result<i64, String>> {
    let target = db
        .query_row(
            "SELECT machine_id,status FROM actions WHERE id=?1",
            [action],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((machine, status)) = target else {
        return Ok(Err(format!("Action #{action} introuvable.")));
    };
    if matches!(status.as_str(), "success" | "cancelled") {
        return Ok(Err(format!("Action #{action} déjà clôturée.")));
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM installations WHERE action_id=?1 AND ansible_status IN ('pending','running','in_progress'))",
        [action], |row| row.get::<_, bool>(0),
    )? {
        return Ok(Err(format!("Un essai Ansible est déjà actif pour l’action #{action}.")));
    }
    let installation = db.query_row(
        "SELECT id FROM installations WHERE action_id=?1 AND ansible_status IN ('failed','aborted')
         ORDER BY id DESC LIMIT 1",
        [action],
        |row| row.get::<_, i64>(0),
    ).optional()?;
    let Some(installation) = installation else {
        return Ok(Err(format!(
            "Aucune phase Ansible à relancer pour l’action #{action}."
        )));
    };
    db.execute(
        "UPDATE actions SET status='running',ended_at=NULL WHERE id=?1 AND status='failed'",
        [action],
    )?;
    db.execute(
        "UPDATE installations SET ansible_status='pending',ended_at=NULL WHERE id=?1",
        [installation],
    )?;
    // The OS is already on disk and must remain the local boot target.
    db.execute(
        "UPDATE machines SET status='installed' WHERE id=?1 AND status='failed'",
        [machine],
    )?;
    log_event(
        db,
        machine,
        "action",
        &format!("Réessai de la phase Ansible déclenché par admin (install_id={installation})"),
        None,
        Some(action),
    )?;
    Ok(Ok(installation))
}
