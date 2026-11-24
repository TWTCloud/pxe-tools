// SPDX-License-Identifier: LGPL-3.0-only

use super::{plain, setup::redirect, ErrorBox, Reply};
use crate::{connect, pxe};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::path::Path;

pub(super) enum Operation {
    Rediscover,
    Rescue,
    ExitRescue,
    Reboot,
    Shutdown,
    SchedulePower,
}

pub(super) fn busy(
    db: &Connection,
    id: i64,
    pending_install_allowed: bool,
) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM actions WHERE machine_id=?1 AND status IN ('pending','running')
                AND NOT (?2 AND type='install_only' AND status='pending')
            UNION ALL SELECT 1 FROM wipes WHERE machine_id=?1 AND wipe_status IN ('pending','running')
            UNION ALL SELECT 1 FROM installations WHERE machine_id=?1 AND (
                install_status IN ('pending','running','installing','in_progress')
                OR ansible_status IN ('pending','running','in_progress'))
            UNION ALL SELECT 1 FROM discoveries WHERE machine_id=?1 AND discovery_status IN ('pending','running','in_progress')
            UNION ALL SELECT 1 FROM disk_tests WHERE machine_id=?1 AND job_status IN ('pending','running')
            UNION ALL SELECT 1 FROM init_jobs WHERE status IN ('pending','running') AND job_type IN (
                'machine:reboot:' || ?1, 'machine:shutdown:' || ?1, 'machine:ansible_redeploy:' || ?1)
            UNION ALL SELECT 1 FROM init_jobs j JOIN actions a
                ON j.job_type IN ('action:reboot:' || a.id, 'action:ansible_retry:' || a.id)
                WHERE a.machine_id=?1 AND j.status IN ('pending','running')
        )",
        params![id, pending_install_allowed],
        |row| row.get(0),
    )
}

impl Operation {
    pub(super) fn run(&self, path: &Path, id: i64, form: &[u8]) -> Result<Reply, ErrorBox> {
        let power = match self {
            Self::SchedulePower => {
                let mut fields = form_urlencoded::parse(form);
                match (fields.next(), fields.next()) {
                    (Some((name, value)), None) if name == "action" => match value.as_ref() {
                        "reboot" => Some((Some("reboot"), true)),
                        "poweroff" => Some((Some("poweroff"), true)),
                        "cancel" => Some((None, true)),
                        _ => return Ok(invalid()),
                    },
                    _ => return Ok(invalid()),
                }
            }
            _ if !form.is_empty() => return Ok(invalid()),
            Self::Reboot => Some((Some("reboot"), false)),
            Self::Shutdown => Some((Some("poweroff"), false)),
            _ => None,
        };
        let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device: Option<(String, bool, bool)> = tx
            .query_row(
                "SELECT status,rescue_mode=1,COALESCE(julianday(awaiting_action_until)>julianday('now'),0)
                 FROM machines WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((status, rescue, awaiting)) = device else {
            return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
        };
        if let Some((command, queued_for_poll)) = power {
            if command.is_some() && (running(&status) || busy(&tx, id, status == "configured")?) {
                return Ok(conflict());
            }
            if queued_for_poll || awaiting {
                tx.execute(
                    "UPDATE machines SET next_action=?2 WHERE id=?1",
                    params![id, command],
                )?;
            } else if let Some(command) = command {
                let verb = if command == "poweroff" {
                    "shutdown"
                } else {
                    command
                };
                enqueue(
                    &tx,
                    id,
                    verb,
                    "Commande d’alimentation demandée depuis la console",
                )?;
            }
            let event = match command {
                Some("reboot") => "Redémarrage demandé par l’administrateur",
                Some("poweroff") => "Arrêt demandé par l’administrateur",
                _ => "Action programmée annulée par l’administrateur",
            };
            pxe::log_event(&tx, id, "action", event, None, None)?;
        } else if matches!(self, Self::ExitRescue) {
            if rescue {
                tx.execute("UPDATE machines SET rescue_mode=0 WHERE id=?1", [id])?;
                pxe::enqueue_menus(&tx)?;
                pxe::log_event(&tx, id, "action", "Mode récupération désactivé", None, None)?;
            }
        } else {
            if rescue || running(&status) || busy(&tx, id, false)? {
                return Ok(conflict());
            }
            let (event, job) = match self {
                Self::Rediscover => {
                    pxe::set_machine_status(&tx, id, &status, "inventorying")?;
                    ("Nouvel inventaire demandé", "Redémarrage pour inventaire")
                }
                Self::Rescue => {
                    tx.execute("UPDATE machines SET rescue_mode=1 WHERE id=?1", [id])?;
                    pxe::enqueue_menus(&tx)?;
                    ("Mode récupération demandé", "Redémarrage en récupération")
                }
                _ => unreachable!(),
            };
            tx.execute(
                "UPDATE machines SET next_action='reboot',awaiting_action_until=NULL WHERE id=?1",
                [id],
            )?;
            enqueue(&tx, id, "reboot", job)?;
            pxe::log_event(&tx, id, "action", event, None, None)?;
        }
        tx.commit()?;
        Ok(redirect(StatusCode::SEE_OTHER, format!("/machines/{id}")))
    }
}

fn enqueue(db: &Connection, id: i64, command: &str, message: &str) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
        params![format!("machine:{command}:{id}"), message],
    )?;
    Ok(())
}

fn running(status: &str) -> bool {
    matches!(status, "installing" | "wiping" | "inventorying" | "testing")
}

fn invalid() -> Reply {
    plain(StatusCode::UNPROCESSABLE_ENTITY, "Commande invalide\n")
}

fn conflict() -> Reply {
    plain(
        StatusCode::CONFLICT,
        "Une opération est déjà programmée ou en cours\n",
    )
}
