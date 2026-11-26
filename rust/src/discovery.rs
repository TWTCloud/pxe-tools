// SPDX-License-Identifier: LGPL-3.0-only

use crate::disk_identity;
use crate::pxe::{
    interface_macs, is_php_array, log_event, machine_for_mac, normalize_mac, set_machine_status,
};
use crate::{failure, ApiResult};
use base64::{
    alphabet, engine::DecodePaddingMode, engine::GeneralPurpose, engine::GeneralPurposeConfig,
    Engine,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::IpAddr;

const MAX_JSON: usize = 1_048_576;
pub const MAX_BODY: usize = 4_198_400;
const MAX_BASE64: usize = 4 * MAX_JSON.div_ceil(3);
const CONFLICT: &str = "Conflit de découverte multi-NIC : plusieurs fiches correspondent aux MAC déclarées. Vérifiez leur identité avant rapprochement manuel.";

fn decode_base64(encoded: &str) -> Result<Vec<u8>, (u16, &'static str)> {
    if encoded.len() > MAX_BASE64 {
        return Err((413, "discovery payload too large"));
    }
    if encoded.is_empty() {
        return Err((400, "invalid discovery base64"));
    }
    let input = crate::php_trim(encoded).replace('-', "+").replace('_', "/");
    let payload = input.trim_end_matches('=');
    if input.len() - payload.len() > 2
        || input.len() % 4 == 1
        || !payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
    {
        return Err((400, "invalid discovery base64"));
    }
    let engine = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    engine
        .decode(payload)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .ok_or((400, "invalid discovery base64"))
}

fn decode(
    body: &[u8],
    form: Option<&str>,
    query: Option<&str>,
) -> Result<Value, (u16, &'static str)> {
    if body.len() > MAX_BODY {
        return Err((413, "discovery payload too large"));
    }
    let decoded;
    let raw = if let Some(form) = form {
        decoded = decode_base64(form)?;
        decoded.as_slice()
    } else if body
        .iter()
        .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0 | 11))
    {
        body
    } else if let Some(query) = query {
        decoded = decode_base64(query)?;
        decoded.as_slice()
    } else {
        return Err((
            422,
            "complete inventory required; MAC-only discovery is incomplete",
        ));
    };
    if raw.len() > MAX_JSON {
        return Err((413, "discovery payload too large"));
    }
    let data: Value = serde_json::from_slice(raw).map_err(|_| (400, "invalid discovery JSON"))?;
    if too_deep(&data, 1) {
        return Err((400, "invalid discovery JSON"));
    }
    if data["mac"]
        .as_str()
        .is_none_or(|s| crate::php_trim(s).is_empty())
    {
        return Err((400, "invalid JSON or missing mac"));
    }
    if ["inventory", "disks", "interfaces"]
        .iter()
        .any(|key| !is_php_array(&data[*key]))
    {
        return Err((422, "complete inventory, disks and interfaces required"));
    }
    Ok(data)
}

fn too_deep(value: &Value, depth: usize) -> bool {
    is_php_array(value)
        && (depth >= 64 || crate::pxe::array_values(value).any(|item| too_deep(item, depth + 1)))
}

pub fn report(
    db: &mut Connection,
    ip: Option<IpAddr>,
    body: &[u8],
    form: Option<&str>,
    query: Option<&str>,
) -> ApiResult {
    let data = match decode(body, form, query) {
        Ok(data) => data,
        Err((status, message)) => return failure(status, message),
    };
    let Some(mac) = normalize_mac(data["mac"].as_str().unwrap_or_default()) else {
        return failure(400, "invalid mac format");
    };
    let boot_arch = match data["inventory"]["cpu_arch"].as_str() {
        Some("aarch64") => Some("arm64"),
        Some("x86_64") => Some("amd64"),
        Some("armv7l" | "armv6l") => Some("armhf"),
        Some("i686" | "i386") => Some("i386"),
        _ => None,
    };
    let macs: HashSet<_> = std::iter::once(mac.clone())
        .chain(interface_macs(&data["interfaces"]))
        .collect();
    let ip = ip.map(|ip| ip.to_string());
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let started: String = tx.query_row(
        "SELECT strftime('%Y-%m-%dT%H:%M:%S+00:00','now')",
        [],
        |row| row.get(0),
    )?;
    let inventory = json!({
        "boot_mac": mac, "inventory": data["inventory"],
        "disks": disk_identity::normalize_inventory(&data["disks"]),
        "interfaces": data["interfaces"],
        "gpus": data.get("gpus").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!([])),
        "usb_devices": data.get("usb_devices").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!([])),
        "memory_modules": data.get("memory_modules").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!([])),
        "display_probe": data["display_probe"], "boot_probe": data["boot_probe"],
        "discovered_at": started, "discovery_ip": ip,
    }).to_string();
    let mut matches = Vec::new();
    {
        let mut stmt =
            tx.prepare("SELECT id, mac, status, inventory_json FROM machines ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let primary: String = row.get(1)?;
            let matches_secondary = || -> rusqlite::Result<bool> {
                let raw: Option<String> = row.get(3)?;
                let matched = raw
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .is_some_and(|v| {
                        interface_macs(&v["interfaces"]).any(|addr| macs.contains(&addr))
                    });
                Ok(matched)
            };
            if macs.contains(&primary.to_ascii_lowercase()) || matches_secondary()? {
                matches.push((row.get::<_, i64>(0)?, primary, row.get::<_, String>(2)?));
            }
        }
    }
    let (machine, reply) = match matches.as_slice() {
        [] => {
            tx.execute(
                "INSERT INTO machines (mac, status, inventory_json, last_seen_at, awaiting_action_until, boot_arch)
                 VALUES (?, 'discovered', ?, CURRENT_TIMESTAMP, datetime('now', '+1 hour'), ?)",
                params![mac, inventory, boot_arch],
            )?;
            let machine = tx.last_insert_rowid();
            (machine, json!({"status":"created", "machine_id":machine}))
        }
        [(machine, primary, status)] => {
            tx.execute(
                "UPDATE machines SET inventory_json = ?, last_seen_at = CURRENT_TIMESTAMP,
                 awaiting_action_until = datetime('now', '+1 hour'), boot_arch = COALESCE(?, boot_arch)
                 WHERE id = ?",
                params![inventory, boot_arch, machine],
            )?;
            if !matches!(
                status.as_str(),
                "configured" | "installing" | "installed" | "provisioned" | "wiping" | "discovered"
            ) {
                set_machine_status(&tx, *machine, status, "discovered")?;
            }
            let via = if *primary == mac {
                "primary_mac"
            } else {
                "secondary_nic"
            };
            (
                *machine,
                json!({"status":"updated", "machine_id":machine, "matched_via":via, "merged_ids":[]}),
            )
        }
        conflicts => {
            for (machine, _, _) in conflicts {
                log_event(&tx, *machine, "warning", CONFLICT, None, None)?;
            }
            tx.commit()?;
            return failure(409, "conflicting machine identities");
        }
    };
    let cycle = tx.query_row(
        "UPDATE discoveries SET ended_at = CURRENT_TIMESTAMP, discovery_status = 'success', inventory_snapshot_json = ?
         WHERE id = (SELECT id FROM discoveries WHERE machine_id = ? AND discovery_status = 'running' ORDER BY id DESC LIMIT 1)
         RETURNING action_id",
        params![inventory, machine], |row| row.get::<_, Option<i64>>(0),
    ).optional()?;
    match cycle {
        Some(Some(action)) => crate::install::recompute(&tx, action)?,
        Some(None) => (),
        None => {
            tx.execute(
                "INSERT INTO discoveries (machine_id, started_at, ended_at, ip_addr, discovery_status, last_phase, inventory_snapshot_json)
                 VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, 'success', 'started', ?)",
                params![machine, ip, inventory],
            )?;
        }
    }
    tx.commit()?;
    Ok((200, reply))
}

pub fn poll(db: &mut Connection, mac: &str) -> ApiResult {
    let Some(mac) = normalize_mac(mac) else {
        return Ok((
            400,
            json!({"action":"wait","remaining_seconds":0,"error":"mac required"}),
        ));
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = machine_for_mac(&tx, &mac)? else {
        tx.execute(
            "INSERT INTO machines (mac,status,last_seen_at,awaiting_action_until)
             VALUES (?,'discovered',CURRENT_TIMESTAMP,datetime('now','+1 hour'))",
            [&mac],
        )?;
        log_event(&tx, tx.last_insert_rowid(), "warning",
            "Appareil réinscrit dans l’inventaire après suppression. Choisissez une action ou attendez l’arrêt automatique dans une heure.",
            None, None)?;
        tx.commit()?;
        return Ok((200, json!({"action":"wait","remaining_seconds":3600})));
    };
    let (action, mut deadline): (Option<String>, Option<String>) = tx.query_row(
        "SELECT next_action, awaiting_action_until FROM machines WHERE id = ?",
        [machine],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut reply = json!({"action":"wait","remaining_seconds":0});
    if let Some(action) = action.filter(|s| !s.is_empty() && s != "0") {
        tx.execute("UPDATE machines SET next_action = NULL,
                    awaiting_action_until = CASE WHEN ? = 'poweroff' THEN CURRENT_TIMESTAMP END WHERE id = ?",
                    params![action, machine])?;
        deadline = None;
        if action != "wait" {
            log_event(
                &tx,
                machine,
                "action",
                &format!("Action récupérée par l’appareil : {action}"),
                None,
                None,
            )?;
            tx.commit()?;
            return Ok((200, json!({"action":action,"remaining_seconds":0})));
        }
    }
    let disk = tx
        .query_row(
            "SELECT in_session, job_status, action_id FROM disk_tests
         WHERE machine_id = ? AND job_status IN ('pending','running') ORDER BY id DESC LIMIT 1",
            [machine],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((1, status, action)) = disk {
        if status == "pending" {
            log_event(
                &tx,
                machine,
                "action",
                "Tests de disque enchaînés sans redémarrage (in-session)",
                None,
                None,
            )?;
            if let Some(action) = action.filter(|id| *id > 0) {
                for (code, message) in [
                    (
                        "dhcp_request_disktest",
                        "Appareil déjà démarré (diagnostic dans la session en cours)",
                    ),
                    (
                        "grub_config_served_disktest",
                        "Tests préparés — transmis à l’appareil sans redémarrage",
                    ),
                ] {
                    tx.execute(
                        "INSERT INTO machine_events (machine_id,level,message,checkpoint,action_id)
                         SELECT ?, 'info', ?, ?, ? WHERE NOT EXISTS (
                         SELECT 1 FROM machine_events WHERE action_id = ? AND checkpoint = ?)",
                        params![machine, message, code, action, action, code],
                    )?;
                }
            }
        }
        reply["action"] = json!("disktest");
    } else if let Some(deadline) = deadline.filter(|s| !s.is_empty() && s != "0") {
        let remaining: i64 = tx.query_row(
            "SELECT max(0, COALESCE(unixepoch(?), 0) - unixepoch('now'))",
            [deadline],
            |row| row.get(0),
        )?;
        reply["remaining_seconds"] = json!(remaining);
        if remaining == 0 {
            reply["action"] = json!("poweroff");
            log_event(
                &tx,
                machine,
                "action",
                "Auto-poweroff serveur après 1h sans action",
                None,
                None,
            )?;
        }
    }
    tx.commit()?;
    Ok((200, reply))
}
