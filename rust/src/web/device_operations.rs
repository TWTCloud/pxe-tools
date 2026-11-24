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
}

pub(super) fn busy(db: &Connection, id: i64) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM actions WHERE machine_id=?1 AND status IN ('pending','running')
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
        [id],
        |row| row.get(0),
    )
}

impl Operation {
    pub(super) fn run(&self, path: &Path, id: i64, form: &[u8]) -> Result<Reply, ErrorBox> {
        if !form.is_empty() {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Corps de commande invalide\n",
            ));
        }
        let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device: Option<(String, bool)> = tx
            .query_row(
                "SELECT status,rescue_mode=1 FROM machines WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((status, rescue)) = device else {
            return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
        };
        if matches!(self, Self::ExitRescue) {
            if rescue {
                tx.execute("UPDATE machines SET rescue_mode=0 WHERE id=?1", [id])?;
                pxe::enqueue_menus(&tx)?;
                pxe::log_event(&tx, id, "action", "Mode récupération désactivé", None, None)?;
            }
        } else {
            if rescue
                || matches!(
                    status.as_str(),
                    "installing" | "wiping" | "inventorying" | "testing"
                )
                || busy(&tx, id)?
            {
                return Ok(plain(
                    StatusCode::CONFLICT,
                    "Une opération est déjà programmée ou en cours\n",
                ));
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
                Self::ExitRescue => unreachable!(),
            };
            tx.execute(
                "UPDATE machines SET next_action='reboot',awaiting_action_until=NULL WHERE id=?1",
                [id],
            )?;
            tx.execute(
                "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
                params![format!("machine:reboot:{id}"), job],
            )?;
            pxe::log_event(&tx, id, "action", event, None, None)?;
        }
        tx.commit()?;
        Ok(redirect(StatusCode::SEE_OTHER, format!("/machines/{id}")))
    }
}
