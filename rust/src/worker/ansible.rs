// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, pxe::log_event, setting};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::{error::Error, path::Path};

const RETRY_PREFIX: &str = "action:ansible_retry:";
const FIRST_BOOT_TIMEOUT: u64 = 600;

fn pending_installation(db: &Connection, enabled: bool) -> rusqlite::Result<Option<i64>> {
    db.query_row(
            "SELECT i.id FROM installations i JOIN machines m ON i.machine_id=m.id
             LEFT JOIN actions a ON i.action_id=a.id
             WHERE i.ansible_status='pending' AND (
                a.id IS NULL OR a.status NOT IN ('pending','running')
                OR a.type NOT IN ('install_only','reinstall') OR COALESCE(i.install_status,'')<>'success'
                OR COALESCE(unixepoch(i.ended_at),0)+?1<=unixepoch()
                OR EXISTS(SELECT 1 FROM machine_events WHERE action_id=a.id AND checkpoint='os_first_boot')
                OR NOT (?2 AND CASE WHEN json_valid(m.install_config_json) THEN
                    COALESCE(json_type(m.install_config_json,'$.ansible_role')='text'
                    AND trim(json_extract(m.install_config_json,'$.ansible_role'))<>'',0)
                    ELSE 0 END)
             ) ORDER BY i.created_at,i.id LIMIT 1",
            params![FIRST_BOOT_TIMEOUT, enabled],
            |row| row.get::<_, i64>(0),
        )
        .optional()
}

pub(super) fn dispatch_installation(
    db: &Connection,
    path: &Path,
    enabled: bool,
    unlocked: bool,
    playbook: impl FnOnce(i64) -> Result<(), Box<dyn Error + Send + Sync>>,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let Some(id) = pending_installation(db, enabled)? else {
        return Ok(false);
    };
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let still_enabled = setting(&tx, "ansible_enabled")? == "on";
    if still_enabled != enabled && pending_installation(&tx, still_enabled)? != Some(id) {
        return Ok(true);
    }
    let entry = tx.query_row(
        "SELECT i.machine_id,i.action_id,a.status,COALESCE(m.hostname,''),COALESCE(m.install_config_json,'')
         FROM installations i JOIN machines m ON i.machine_id=m.id LEFT JOIN actions a ON a.id=i.action_id
         WHERE i.id=?1 AND i.ansible_status='pending'",
        [id],
        |row| Ok((
            row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?, row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?, row.get::<_, String>(4)?,
        )),
    ).optional()?;
    let Some((machine, action, state, hostname, config)) = entry else {
        return Ok(true);
    };
    if matches!(state.as_deref(), Some("success" | "cancelled")) {
        tx.execute(
            "UPDATE installations SET ansible_status='aborted' WHERE id=?1",
            [id],
        )?;
        tx.commit()?;
        return Ok(true);
    }
    let config: Value = serde_json::from_str(&config).unwrap_or_default();
    let role = config["ansible_role"].as_str().unwrap_or_default().trim();
    let (machine_status, status, message) =
        if role == "proxmox_ve" || config["variant"] == "proxmox-ve" {
            (
                "failed",
                "failed",
                "[worker] Cette configuration n’est pas disponible dans cette édition.\n",
            )
        } else if !still_enabled {
            (
                "installed",
                "no_role",
                "[worker] Ansible désactivé. OS installé, machine non provisionnée.\n",
            )
        } else if role.is_empty() {
            (
                "installed",
                "no_role",
                "[worker] Aucun rôle Ansible défini. OS installé, machine non provisionnée.\n",
            )
        } else if hostname.trim().is_empty() {
            ("failed", "failed", "[worker] Nom d’hôte manquant.\n")
        } else {
            tx.commit()?;
            if unlocked {
                playbook(id)?;
            }
            return Ok(unlocked);
        };
    tx.execute(
        "UPDATE machines SET status=?2 WHERE id=?1",
        params![machine, machine_status],
    )?;
    tx.execute(
        "UPDATE installations SET ansible_status=?2,ansible_log=COALESCE(ansible_log,'')||?3 WHERE id=?1",
        params![id, status, message],
    )?;
    if let Some(action) = action {
        crate::install::recompute(&tx, action)?;
    }
    tx.commit()?;
    Ok(true)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_requested_provisioning_waits_for_first_boot() -> rusqlite::Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(include_str!("../../../app/db/schema.sqlite.sql"))?;
        db.execute_batch(
            "INSERT INTO machines(id,mac,status,install_config_json) VALUES
                (1,'02:00:00:00:00:01','installed','{}'),
                (2,'02:00:00:00:00:02','installed','{\"ansible_role\":\"base\"}');
             INSERT INTO actions(id,machine_id,type,status,token) VALUES
                (1,1,'install_only','running','plain'),
                (2,2,'install_only','running','ansible');
             INSERT INTO installations(id,action_id,machine_id,install_status,ansible_status,ended_at)
             VALUES (1,1,1,'success','pending',CURRENT_TIMESTAMP),
                    (2,2,2,'success','pending',CURRENT_TIMESTAMP);",
        )?;

        assert_eq!(pending_installation(&db, true)?, Some(1));
        db.execute(
            "UPDATE installations SET ansible_status='no_role' WHERE id=1",
            [],
        )?;
        assert_eq!(pending_installation(&db, true)?, None);
        assert_eq!(pending_installation(&db, false)?, Some(2));

        db.execute(
            "UPDATE installations SET ended_at=datetime('now','-601 seconds') WHERE id=2",
            [],
        )?;
        assert_eq!(pending_installation(&db, true)?, Some(2));
        db.execute(
            "UPDATE installations SET ended_at=CURRENT_TIMESTAMP WHERE id=2",
            [],
        )?;
        log_event(
            &db,
            2,
            "info",
            "checkpoint:os_first_boot",
            Some("os_first_boot"),
            Some(2),
        )?;
        assert_eq!(pending_installation(&db, true)?, Some(2));
        Ok(())
    }
}
