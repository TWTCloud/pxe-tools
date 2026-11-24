// SPDX-License-Identifier: LGPL-3.0-only

use crate::monitoring::Catalog;
use crate::pxe::{
    enqueue_menus, is_php_array, log_event, machine_for_mac, normalize_mac, set_machine_status,
};
use crate::{failure, ApiResult};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::net::IpAddr;
use subtle::ConstantTimeEq;

pub const LOG_CHUNK_MAX: usize = 262_144;
pub const CHECKPOINT_BODY_MAX: usize = 4_096;

pub struct Machine {
    pub id: i64,
    pub mac: String,
    pub status: String,
    pub config: Option<String>,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub root_hash: Option<String>,
}

struct Action {
    id: i64,
    machine: i64,
    status: String,
    kind: String,
}

pub fn machine(
    db: &Connection,
    raw_mac: &str,
    secondary: bool,
) -> rusqlite::Result<Option<Machine>> {
    let Some(mac) = normalize_mac(raw_mac) else {
        return Ok(None);
    };
    let mut stmt = db.prepare(
        "SELECT id, mac, status, install_config_json, hostname, domain, root_password_hash
         FROM machines WHERE id = ? OR (? IS NULL AND mac = ?)",
    )?;
    let id = if secondary {
        let Some(id) = machine_for_mac(db, &mac)? else {
            return Ok(None);
        };
        Some(id)
    } else {
        None
    };
    stmt.query_row(params![id, id, mac], |row| {
        Ok(Machine {
            id: row.get(0)?,
            mac: row.get(1)?,
            status: row.get(2)?,
            config: row.get(3)?,
            hostname: row.get(4)?,
            domain: row.get(5)?,
            root_hash: row.get(6)?,
        })
    })
    .optional()
}

fn terminal(status: &str) -> bool {
    matches!(status, "success" | "failed" | "cancelled")
}

fn authorized_action(db: &Connection, token: &str) -> rusqlite::Result<Option<Action>> {
    if !valid_token(token) {
        return Ok(None);
    }
    db.query_row(
        "SELECT id, machine_id, type, status, token FROM actions WHERE token = ?",
        [token],
        |row| {
            let actual: String = row.get(4)?;
            if !bool::from(actual.as_bytes().ct_eq(token.as_bytes())) {
                return Ok(None);
            }
            Ok(Some(Action {
                id: row.get(0)?,
                machine: row.get(1)?,
                kind: row.get(2)?,
                status: row.get(3)?,
            }))
        },
    )
    .optional()
    .map(Option::flatten)
}

pub fn valid_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn installation_action(kind: &str) -> bool {
    matches!(kind, "reinstall" | "install_only")
}

pub fn installable_machine(machine: &Machine) -> bool {
    matches!(machine.status.as_str(), "configured" | "installing")
}

pub fn latest_action(db: &Connection, machine: i64) -> rusqlite::Result<Option<(i64, String)>> {
    db.query_row(
        "SELECT id, token FROM actions WHERE machine_id = ? AND type IN ('reinstall','install_only')
           AND status IN ('pending','running') ORDER BY id DESC LIMIT 1",
        [machine],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()
}

pub fn prior_install_actions(db: &Connection, machine: i64) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM actions WHERE machine_id = ? AND type IN ('install_only','reinstall'))",
        [machine], |row| row.get(0),
    )
}

pub fn installation_closed(
    db: &Connection,
    machine: i64,
    action: Option<i64>,
) -> rusqlite::Result<bool> {
    let status = db.query_row(
        "SELECT install_status FROM installations WHERE machine_id = ? AND (?2 IS NULL OR action_id = ?2)
         ORDER BY id DESC LIMIT 1", params![machine, action], |row| row.get::<_,Option<String>>(0),
    ).optional()?;
    Ok(status.is_some_and(|s| s.as_deref() != Some("in_progress")))
}

pub fn snapshot_action(
    db: &Connection,
    machine: &Machine,
    config: &Value,
) -> rusqlite::Result<Option<i64>> {
    if let Some(action) = config
        .get("_pending_action_id")
        .filter(|value| !value.is_null())
    {
        return Ok(Some(
            action
                .as_i64()
                .unwrap_or_else(|| crate::decimal(&crate::php_string(action))),
        ));
    }
    db.query_row(
        "SELECT action_id FROM wipes WHERE machine_id = ? ORDER BY id DESC LIMIT 1",
        [machine.id],
        |row| row.get::<_, Option<i64>>(0),
    )
    .optional()
    .map(|id| id.flatten().filter(|id| *id != 0))
}

pub fn eligible(db: &Connection, machine: &Machine, action: Option<i64>) -> rusqlite::Result<bool> {
    if !installable_machine(machine) {
        return Ok(false);
    }
    if let Some(action) = action {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM actions WHERE id = ? AND machine_id = ? AND type IN ('install_only','reinstall')
             AND status IN ('pending','running'))",
            params![action, machine.id], |row| row.get(0),
        )
    } else {
        Ok(!prior_install_actions(db, machine.id)?)
    }
}

pub fn start_row(db: &Connection, machine: &Machine, action: Option<i64>) -> rusqlite::Result<i64> {
    let id = db.query_row(
        "SELECT id FROM installations WHERE machine_id = ? AND install_status = 'in_progress' ORDER BY id DESC LIMIT 1",
        [machine.id], |row| row.get::<_,i64>(0),
    ).optional()?;
    let id = if let Some(id) = id {
        if let Some(action) = action {
            db.execute("UPDATE installations SET action_id = ? WHERE id = ? AND COALESCE(action_id, 0) = 0",
                       params![action, id])?;
        }
        id
    } else {
        db.execute(
            "INSERT INTO installations (machine_id,started_at,install_status,action_id)
             VALUES (?,CURRENT_TIMESTAMP,'in_progress',?)",
            params![machine.id, action],
        )?;
        db.last_insert_rowid()
    };
    set_machine_status(db, machine.id, &machine.status, "installing")?;
    Ok(id)
}

pub fn start(db: &mut Connection, local: bool, mac: &str) -> ApiResult {
    if !local {
        return failure(404, "not found");
    }
    if normalize_mac(mac).is_none() {
        return failure(400, "mac required");
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = machine(&tx, mac, true)? else {
        return failure(404, "machine not found");
    };
    let config = machine
        .config
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    let action = snapshot_action(&tx, &machine, &config)?;
    if !eligible(&tx, &machine, action)? {
        return failure(409, "installation not available");
    }
    if other_active_install(&tx, machine.id, action)? {
        return failure(409, "installation not available");
    }
    if installation_closed(&tx, machine.id, action)? {
        return failure(409, "installation already finished");
    }
    let id = start_row(&tx, &machine, action)?;
    tx.commit()?;
    Ok((200, json!({"status":"ok","installation_id":id})))
}

pub fn end(
    db: &mut Connection,
    client_allowed: bool,
    raw_mac: &str,
    token: &str,
    status: &str,
    fingerprint: &str,
) -> ApiResult {
    if normalize_mac(raw_mac).is_none() {
        return failure(400, "mac required");
    }
    if !client_allowed {
        return failure(404, "not found");
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = machine(&tx, raw_mac, true)? else {
        return failure(404, "machine not found");
    };
    let Some(action) = authorized_action(&tx, token)?
        .filter(|a| a.machine == machine.id && installation_action(&a.kind))
    else {
        return failure(404, "not found");
    };
    let latest = tx.query_row(
        "SELECT id, action_id, install_status FROM installations WHERE machine_id = ? ORDER BY id DESC LIMIT 1",
        [machine.id], |row| Ok((row.get::<_,i64>(0)?, row.get::<_,Option<i64>>(1)?, row.get::<_,Option<String>>(2)?)),
    ).optional()?.filter(|(_, parent, _)| *parent == Some(action.id));
    let Some((id, _, prior_status)) = latest else {
        return failure(409, "no matching installation");
    };
    let status = match status {
        "failed" => "failed",
        "aborted" => "aborted",
        _ => "success",
    };
    if prior_status.as_deref() != Some("in_progress") {
        if status == "success"
            && prior_status.as_deref() == Some("success")
            && matches!(machine.status.as_str(), "installed" | "provisioned")
        {
            return Ok((
                200,
                json!({"status":"ok","machine_status":machine.status,"installation_id":id}),
            ));
        }
        return failure(409, "no installation in progress");
    }
    let ansible_status = (status == "success").then_some("pending");
    let machine_status = if status == "success" {
        "installed"
    } else {
        "failed"
    };
    tx.execute(
        "UPDATE installations SET ended_at = CURRENT_TIMESTAMP, install_status = ?, ansible_status = ? WHERE id = ?",
        params![status, ansible_status, id],
    )?;
    set_machine_status(&tx, machine.id, &machine.status, machine_status)?;
    if status == "success" && tx.execute(
        "UPDATE machines SET local_boot_source = 'pxe' WHERE id = ? AND local_boot_source != 'pxe'",
        [machine.id],
    )? != 0 {
        log_event(&tx, machine.id, "action", "Démarrage local : activé après installation PXE réussie", None, None)?;
        enqueue_menus(&tx)?;
    }
    if status == "success"
        && fingerprint.strip_prefix("SHA256:").is_some_and(|hash| {
            hash.len() == 43
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        })
    {
        log_event(
            &tx,
            machine.id,
            "info",
            &format!("Empreinte SSH déclarée par Debian Installer : {fingerprint}"),
            None,
            Some(action.id),
        )?;
    }
    tx.commit()?;
    Ok((
        200,
        json!({"status":"ok","machine_status":machine_status,"installation_id":id}),
    ))
}

pub fn machine_ready(db: &mut Connection, raw_mac: &str) -> ApiResult {
    let Some(mac) = normalize_mac(raw_mac) else {
        return failure(400, "mac required");
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = machine_for_mac(&tx, &mac)? else {
        return failure(404, "machine not found");
    };
    tx.execute(
        "UPDATE machines SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?",
        [machine],
    )?;
    log_event(
        &tx,
        machine,
        "info",
        "Machine signalée online (post-reboot, sshd up)",
        None,
        None,
    )?;
    tx.commit()?;
    Ok((200, json!({"status":"ok"})))
}

pub(crate) fn cancel_pending(db: &Connection, id: i64) -> rusqlite::Result<()> {
    close_action(db, id, true)?;
    Ok(())
}

pub(crate) fn force_complete(db: &Connection, id: i64) -> rusqlite::Result<bool> {
    close_action(db, id, false)
}

fn close_action(db: &Connection, id: i64, pending_only: bool) -> rusqlite::Result<bool> {
    if db.execute(
        "UPDATE actions SET status='cancelled',ended_at=CURRENT_TIMESTAMP WHERE id=?1
         AND (status='pending' OR (NOT ?2 AND status NOT IN ('success','failed','cancelled')))",
        params![id, pending_only],
    )? == 0
    {
        return Ok(false);
    }
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
        db.execute(
            &format!("UPDATE {table} SET {column}='aborted',ended_at=CURRENT_TIMESTAMP WHERE action_id=?1 AND {column} IN ({states})"),
            [id],
        )?;
    }
    db.execute(
        "UPDATE installations SET ansible_status='aborted' WHERE action_id=?1
         AND ansible_status IN ('pending','running','in_progress')",
        [id],
    )?;
    db.execute(
        "UPDATE init_jobs SET status='failed',message='Clôture administrative : demande en attente annulée.'
         WHERE status='pending'
         AND job_type IN ('action:reboot:'||?1,'action:ansible_retry:'||?1,'action:render_postboot:'||?1)",
        [id],
    )?;
    Ok(true)
}

pub fn recompute(db: &Connection, id: i64) -> rusqlite::Result<()> {
    db.execute(
        "WITH subjobs(status) AS (
             SELECT wipe_status FROM wipes WHERE action_id = ?1 UNION ALL
             SELECT discovery_status FROM discoveries WHERE action_id = ?1 UNION ALL
             SELECT job_status FROM disk_tests WHERE action_id = ?1 UNION ALL
             SELECT COALESCE(ansible_status, install_status) FROM installations WHERE action_id = ?1
         ), result(status) AS (
             SELECT CASE
               WHEN NOT EXISTS(SELECT 1 FROM subjobs WHERE status <> '') THEN 'pending'
               WHEN EXISTS(SELECT 1 FROM subjobs WHERE status = 'failed') THEN 'failed'
               WHEN EXISTS(SELECT 1 FROM subjobs WHERE status NOT IN ('success','no_role','')) THEN 'running'
               WHEN (SELECT type FROM actions WHERE id = ?1) = 'reinstall'
                 AND NOT EXISTS(SELECT 1 FROM installations WHERE action_id = ?1) THEN 'running'
               ELSE 'success'
             END
         )
         UPDATE actions SET status = result.status,
             ended_at = CASE WHEN result.status IN ('success','failed') THEN CURRENT_TIMESTAMP END
         FROM result WHERE id = ?1 AND actions.status <> 'cancelled'",
        [id],
    )?;
    Ok(())
}

pub struct Checkpoint<'a> {
    pub token: &'a str,
    pub mac: &'a str,
    pub code: &'a str,
    pub level: &'a str,
    pub acknowledge: bool,
    pub ip: IpAddr,
    pub proxy_headers_seen: bool,
    pub body: &'a [u8],
}

pub fn checkpoint(
    db: &mut Connection,
    catalog: &Catalog,
    input: Checkpoint<'_>,
) -> rusqlite::Result<&'static str> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(action) = authorized_action(&tx, input.token)? else {
        return Ok("");
    };
    let mac = normalize_mac(input.mac);
    if !catalog
        .get(&action.kind)
        .is_some_and(|steps| steps.iter().any(|step| step.has_code(input.code)))
        || match mac {
            Some(mac) => machine_for_mac(&tx, &mac)? != Some(action.machine),
            None => true,
        }
    {
        return Ok("");
    }
    let acknowledge = input.acknowledge && input.code == "os_first_boot";
    if acknowledge
        && tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM machine_events WHERE action_id = ? AND checkpoint = 'os_first_boot')",
            [action.id],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Ok("accepted\n");
    }
    if terminal(&action.status) {
        return Ok(if acknowledge { "closed\n" } else { "" });
    }
    let mut payload =
        serde_json::from_slice::<Value>(&input.body[..input.body.len().min(CHECKPOINT_BODY_MAX)])
            .ok()
            .filter(is_php_array);
    if input.code == "os_first_boot" {
        let data = match payload.take() {
            Some(Value::Object(map)) => map,
            Some(Value::Array(items)) => items
                .into_iter()
                .enumerate()
                .map(|(index, item)| (index.to_string(), item))
                .collect(),
            _ => Default::default(),
        };
        let mut data = Value::Object(data);
        data["_observed_remote_ip"] = json!(input.ip.to_string());
        data["_received_at_unix"] = json!(crate::now());
        data["_proxy_headers_seen"] = json!(input.proxy_headers_seen);
        payload = Some(data);
    }
    let mut message = format!("checkpoint:{}", input.code);
    if let Some(data) = payload {
        message.push(' ');
        message.push_str(&data.to_string());
    }
    let level = if input.level == "error" {
        "error"
    } else {
        "info"
    };
    log_event(
        &tx,
        action.machine,
        level,
        &message,
        Some(input.code),
        Some(action.id),
    )?;
    tx.execute("UPDATE actions SET status = 'running', ended_at = NULL WHERE id = ? AND status = 'pending'",
               [action.id])?;
    tx.commit()?;
    Ok(if acknowledge { "accepted\n" } else { "" })
}

pub fn append_log(
    db: &mut Connection,
    allowed: bool,
    token: &str,
    install: i64,
    seq: i64,
    body: &[u8],
) -> ApiResult {
    const CAP: usize = 5_242_880;
    const MARKER: &[u8] = b"\n[LOG TRUNCATED AT 5MB]\n";
    if !allowed {
        return failure(401, "unauthorized");
    }
    if token.is_empty() {
        return failure(401, "invalid token");
    }
    if install <= 0 {
        return failure(400, "install_id required");
    }

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(action) = authorized_action(&tx, token)? else {
        return failure(401, "invalid token");
    };
    if terminal(&action.status) {
        return failure(410, "action terminated");
    }
    let length = tx.query_row(
        "SELECT COALESCE(length(CAST(install_log AS BLOB)), 0) FROM installations WHERE id = ? AND action_id = ?",
        params![install, action.id], |row| row.get::<_, usize>(0),
    ).optional()?;
    let Some(length) = length else {
        return failure(401, "invalid token");
    };
    if body.len() > LOG_CHUNK_MAX {
        return failure(413, "chunk too large");
    }
    if body.is_empty() {
        return Ok((200, json!({"status":"ok","bytes":0,"appended":0,"seq":seq})));
    }
    let available = CAP.saturating_sub(length);
    let truncated = body.len() > available;
    let reserve = if truncated {
        available.min(MARKER.len())
    } else {
        0
    };
    let appended = body.len().min(available - reserve);
    let payload = [&body[..appended], &MARKER[..reserve]].concat();
    if !payload.is_empty() {
        tx.execute("UPDATE installations SET install_log = COALESCE(install_log, '') || CAST(? AS TEXT) WHERE id = ?",
                   params![payload, install])?;
    }
    tx.commit()?;
    let status = if truncated { "truncated" } else { "ok" };
    Ok((
        200,
        json!({"status":status,"bytes":length + payload.len(),"appended":appended,"seq":seq}),
    ))
}

pub fn ping_phase(
    db: &Connection,
    kind: &str,
    id: i64,
    phase: &str,
    status: &str,
    message: Option<&str>,
) -> rusqlite::Result<()> {
    if !matches!(kind, "install" | "wipe" | "ansible")
        || !matches!(
            status,
            "running" | "success" | "pending" | "failed" | "skipped"
        )
    {
        return Ok(());
    }
    db.execute(
        "INSERT INTO task_phases (task_type,task_id,phase_key,status,started_at,ended_at,message)
         VALUES (?1,?2,?3,?4,
             CASE WHEN ?4 IN ('running','success','failed') THEN CURRENT_TIMESTAMP END,
             CASE WHEN ?4 IN ('success','failed','skipped') THEN CURRENT_TIMESTAMP END,?5)
         ON CONFLICT (task_type,task_id,phase_key) DO UPDATE SET status=excluded.status,
             started_at=COALESCE(NULLIF(task_phases.started_at, ''),excluded.started_at),
             ended_at=COALESCE(NULLIF(task_phases.ended_at, ''),excluded.ended_at),
             message=COALESCE(excluded.message,task_phases.message)",
        params![kind, id, phase, status, message],
    )?;
    Ok(())
}

pub fn phase_for_request(
    db: &Connection,
    kind: &str,
    id: i64,
    mac: &str,
    phase: &str,
    status: &str,
    message: Option<&str>,
) -> rusqlite::Result<u16> {
    if kind.is_empty() || phase.is_empty() {
        return Ok(400);
    }
    let id = if id > 0 || mac.is_empty() {
        id
    } else {
        let sql = match kind {
            "install" | "ansible" => "SELECT i.id FROM installations i JOIN machines m ON i.machine_id=m.id
                    WHERE LOWER(m.mac)=LOWER(?) AND i.install_status='in_progress' ORDER BY i.id DESC LIMIT 1",
            "wipe" => "SELECT w.id FROM wipes w JOIN machines m ON w.machine_id=m.id
                    WHERE LOWER(m.mac)=LOWER(?) AND w.wipe_status IN ('pending','running') ORDER BY w.id DESC LIMIT 1",
            _ => return Ok(404),
        };
        db.query_row(sql, [mac], |row| row.get(0))
            .optional()?
            .unwrap_or(0)
    };
    if id <= 0 {
        return Ok(404);
    }
    ping_phase(db, kind, id, phase, status, message)?;
    Ok(204)
}

pub fn application_file_allowed(db: &Connection, id: i64) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS (SELECT 1 FROM actions WHERE id=?1 AND status NOT IN ('success','failed','cancelled')
           AND (type NOT IN ('reinstall','install_only') OR
               (SELECT install_status FROM installations WHERE action_id=?1 ORDER BY id DESC LIMIT 1)='in_progress'))",
        [id], |row| row.get(0),
    )
}

pub fn other_active_install(
    db: &Connection,
    machine: i64,
    action: Option<i64>,
) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM installations WHERE machine_id = ?1 AND install_status = 'in_progress'
         AND action_id IS NOT NULL AND action_id IS NOT ?2)", params![machine, action], |row| row.get(0)
    )
}
