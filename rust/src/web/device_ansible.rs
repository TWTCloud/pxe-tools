// SPDX-License-Identifier: LGPL-3.0-only

use super::{device_operations, plain, setup::redirect, ErrorBox, Reply};
use crate::{connect, pxe};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::{fmt::Write, path::Path};

pub(super) enum Action {
    Pull,
    Retry,
    Redeploy,
    AutoDeploy,
}

impl Action {
    pub(super) fn run(&self, path: &Path, id: i64, form: &[u8]) -> Result<Reply, ErrorBox> {
        if matches!(self, Self::AutoDeploy) {
            return auto_deploy(path, id, form);
        }
        if !form.is_empty() {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Demande Ansible invalide\n",
            ));
        }
        let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let device = tx
            .query_row(
                "SELECT COALESCE(hostname,''),status,rescue_mode=1,COALESCE(install_config_json,'')
             FROM machines WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((hostname, status, rescue, config)) = device else {
            return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
        };
        let role = serde_json::from_str::<Value>(&config).unwrap_or_default();
        let mut related = None;
        let (kind, message) = match self {
            Self::Pull => (
                "ansible_repo:pull".to_owned(),
                "Synchronisation du dépôt Ansible demandée",
            ),
            Self::Redeploy => {
                if hostname.trim().is_empty() {
                    return Ok(invalid("Nom d’hôte absent\n"));
                }
                match redeploy_eligibility(&tx, id, &status, rescue, &role)? {
                    RedeployEligibility::Ready => {}
                    RedeployEligibility::MissingRole => {
                        return Ok(invalid("Cet appareil n’a pas de rôle Ansible\n"))
                    }
                    RedeployEligibility::Pending(job) => {
                        return Ok(redirect(StatusCode::SEE_OTHER, format!("/jobs/{job}")))
                    }
                    RedeployEligibility::Busy => {
                        return Ok(invalid("Une opération est déjà programmée ou en cours\n"))
                    }
                }
                (
                    format!("machine:ansible_redeploy:{id}"),
                    "Redéploiement Ansible demandé",
                )
            }
            Self::Retry => {
                let action = tx
                    .query_row(
                        "SELECT a.id FROM actions a JOIN installations i ON i.action_id=a.id
                     WHERE a.machine_id=?1 AND i.ansible_status='failed' AND a.status!='cancelled'
                     ORDER BY a.id DESC LIMIT 1",
                        [id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                let Some(action) = action else {
                    return Ok(invalid("Aucune phase Ansible en échec\n"));
                };
                related = Some(action);
                (
                    format!("action:ansible_retry:{action}"),
                    "Réessai Ansible demandé",
                )
            }
            Self::AutoDeploy => unreachable!("handled above"),
        };
        if matches!(self, Self::Pull) {
            if let Some(job) = pending(&tx, &kind)? {
                return Ok(redirect(StatusCode::SEE_OTHER, format!("/jobs/{job}")));
            }
        }
        if matches!(self, Self::Retry)
            && (rescue
                || device_operations::running(&status)
                || device_operations::busy(&tx, id, false)?)
        {
            return Ok(invalid("Une opération est déjà programmée ou en cours\n"));
        }
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
            params![kind, message],
        )?;
        let job = tx.last_insert_rowid();
        pxe::log_event(&tx, id, "action", message, None, related)?;
        tx.commit()?;
        let target = related.map_or_else(
            || format!("/jobs/{job}"),
            |action| format!("/tasks/{action}"),
        );
        Ok(redirect(StatusCode::SEE_OTHER, target))
    }
}

pub(super) enum RedeployEligibility {
    Ready,
    MissingRole,
    Pending(i64),
    Busy,
}

pub(super) fn redeploy_eligibility(
    db: &Connection,
    id: i64,
    status: &str,
    rescue: bool,
    config: &Value,
) -> rusqlite::Result<RedeployEligibility> {
    if config["ansible_role"]
        .as_str()
        .is_none_or(|name| name.trim().is_empty())
    {
        return Ok(RedeployEligibility::MissingRole);
    }
    if let Some(job) = pending(db, &format!("machine:ansible_redeploy:{id}"))? {
        return Ok(RedeployEligibility::Pending(job));
    }
    if rescue || device_operations::running(status) || device_operations::busy(db, id, false)? {
        return Ok(RedeployEligibility::Busy);
    }
    Ok(RedeployEligibility::Ready)
}

fn auto_deploy(path: &Path, id: i64, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut fields = form_urlencoded::parse(form);
    let enabled = match (fields.next(), fields.next()) {
        (None, None) => false,
        (Some((key, value)), None)
            if key == "auto_deploy" && matches!(value.as_ref(), "1" | "on") =>
        {
            true
        }
        _ => {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Réglage Ansible invalide\n",
            ))
        }
    };
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE machines SET auto_deploy=?2 WHERE id=?1",
        params![id, enabled],
    )? == 0
    {
        return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
    }
    let message = if enabled {
        "Auto-déploiement Ansible activé"
    } else {
        "Auto-déploiement Ansible désactivé"
    };
    pxe::log_event(&tx, id, "action", message, None, None)?;
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/machines/{id}")))
}

fn pending(db: &Connection, kind: &str) -> rusqlite::Result<Option<i64>> {
    db.query_row(
        "SELECT id FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running') LIMIT 1",
        [kind],
        |row| row.get(0),
    )
    .optional()
}

fn invalid(message: &'static str) -> Reply {
    plain(StatusCode::CONFLICT, message)
}

pub(super) fn form(db: &Connection, id: i64, output: &mut String) -> Result<(), ErrorBox> {
    if crate::setting(db, "ansible_enabled")? != "on" {
        return Ok(());
    }
    output.push_str("<h2>Automatisation Ansible</h2>");
    let auto: bool = db.query_row(
        "SELECT auto_deploy=1 FROM machines WHERE id=?1",
        [id],
        |row| row.get(0),
    )?;
    let checked = if auto { " checked" } else { "" };
    write!(
        output,
        r#"<form method="post" action="/machines/{id}/ansible/pull"><button>Synchroniser le dépôt</button></form>
<form method="post" action="/machines/{id}/ansible/redeploy"><button>Redéployer le rôle</button></form>
<form method="post" action="/machines/{id}/ansible/retry"><button>Réessayer une exécution en échec</button></form>
<form method="post" action="/machines/{id}/auto-deploy"><label><input type="checkbox" name="auto_deploy" value="1"{checked}> Redéployer après les changements GitHub qui concernent cet appareil</label>
<button>Enregistrer le redéploiement automatique</button></form>"#
    )?;
    Ok(())
}
