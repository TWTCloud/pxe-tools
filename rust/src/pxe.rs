// SPDX-License-Identifier: LGPL-3.0-only

mod agent;
pub(crate) mod boot_events;
pub(crate) mod disk_test;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::net::Ipv4Addr;

pub fn menu_label(menu: &str) -> Option<&'static str> {
    match menu {
        "discovery" => Some("Discovery"),
        "wipe" => Some("Effacement des disques"),
        "install" => Some("Installation"),
        "disktest" => Some("Tests de disques"),
        "rescue" => Some("Mode de récupération"),
        "local" => Some("Démarrage sur le disque local"),
        "other" => Some("Autres options de démarrage"),
        _ => None,
    }
}

pub fn parse_subnet(subnet: &str) -> Option<(u32, u32)> {
    let (network, prefix) = subnet.split_once('/')?;
    let network: Ipv4Addr = network.parse().ok()?;
    let prefix_len: u32 = prefix.parse().ok()?;
    if prefix_len > 32 || prefix != prefix_len.to_string() {
        return None;
    }
    let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
    Some((u32::from(network) & mask, mask))
}

pub fn client_in_subnet(ip: Ipv4Addr, subnet: &str) -> bool {
    parse_subnet(super::php_trim(subnet))
        .is_some_and(|(network, mask)| u32::from(ip) & mask == network)
}

pub fn record_boot_selection(
    db: &mut Connection,
    id: &str,
    token: &str,
    menu: &str,
) -> rusqlite::Result<bool> {
    let Some(label) = menu_label(menu) else {
        return Ok(false);
    };
    if id.is_empty()
        || !id.bytes().all(|byte| byte.is_ascii_digit())
        || token.len() != 32
        || !token
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Ok(false);
    }
    let id = id.parse::<i64>().unwrap_or(i64::MAX);
    if id == 0 {
        return Ok(false);
    }

    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let boot = transaction
        .query_row(
            "UPDATE boot_sessions SET selected_menu = ?, selected_at = CURRENT_TIMESTAMP
             WHERE id = ? AND token = ? AND selected_menu IS NULL
             RETURNING machine_id, action_id",
            params![menu, id, token],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let accepted = if let Some((machine, action)) = boot {
        transaction.execute(
            "INSERT INTO machine_events (machine_id, level, message, action_id)
             VALUES (?, 'action', ?, ?)",
            params![machine, format!("Entrée GRUB lancée : {label}"), action],
        )?;
        if menu == "local" {
            transaction.execute(
                "INSERT INTO machine_events (machine_id, level, message, checkpoint, action_id)
                 SELECT ?, 'info', 'checkpoint:install_reboot_done', 'install_reboot_done', id
                 FROM actions WHERE id = ? AND type IN ('reinstall', 'install_only')
                   AND NOT EXISTS (SELECT 1 FROM machine_events
                                   WHERE action_id = actions.id AND checkpoint = 'install_reboot_done')",
                params![machine, action],
            )?;
        }
        true
    } else {
        let previous = transaction
            .query_row(
                "SELECT selected_menu FROM boot_sessions WHERE id = ? AND token = ?",
                params![id, token],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        previous.as_deref() == Some(menu)
    };
    transaction.commit()?;
    Ok(accepted)
}

pub fn discovery_phase(db: &mut Connection, phase: &str, mac: &str) -> rusqlite::Result<Value> {
    if let Some(mac) = normalize_mac(mac) {
        let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(machine) = machine_for_mac(&transaction, &mac)? {
            let level = if phase.starts_with("post_0_")
                || phase.contains("fail")
                || phase.contains("error")
            {
                "warning"
            } else {
                "info"
            };
            transaction.execute(
                "INSERT INTO machine_events (machine_id, level, message) VALUES (?, ?, ?)",
                params![machine, level, format!("discover.sh phase: {phase}")],
            )?;
            if matches!(phase, "action_poweroff" | "action_timeout_poweroff") {
                transaction.execute(
                    "UPDATE machines SET awaiting_action_until = CURRENT_TIMESTAMP
                     WHERE id = ? AND awaiting_action_until NOT IN ('', '0')",
                    [machine],
                )?;
            }
        }
        transaction.commit()?;
    }
    Ok(json!({"status": "phase_ack", "phase": phase}))
}

pub fn normalize_mac(raw: &str) -> Option<String> {
    let raw = super::php_trim(raw).to_ascii_lowercase();
    let raw = raw
        .strip_prefix("01-")
        .or_else(|| raw.strip_prefix("01:"))
        .unwrap_or(&raw);
    let hex: String = raw.chars().filter(|ch| ch.is_ascii_hexdigit()).collect();
    (hex.len() == 12).then(|| {
        (0..12)
            .step_by(2)
            .map(|start| &hex[start..start + 2])
            .collect::<Vec<_>>()
            .join(":")
    })
}

pub fn machine_for_mac(db: &Connection, mac: &str) -> rusqlite::Result<Option<i64>> {
    let primary = db
        .query_row("SELECT id FROM machines WHERE mac = ?", [mac], |row| {
            row.get(0)
        })
        .optional()?;
    if primary.is_some() {
        return Ok(primary);
    }
    let mut stmt = db.prepare("SELECT id, inventory_json FROM machines ORDER BY id")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let Some(raw) = row.get::<_, Option<String>>(1)? else {
            continue;
        };
        let Ok(inventory) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if interface_macs(&inventory["interfaces"]).any(|address| address == mac) {
            return row.get(0).map(Some);
        }
    }
    Ok(None)
}

pub fn array_values(value: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    match value {
        Value::Array(items) => Box::new(items.iter()),
        Value::Object(items) => Box::new(items.values()),
        _ => Box::new(std::iter::empty()),
    }
}

pub fn interface_macs(value: &Value) -> impl Iterator<Item = String> + '_ {
    array_values(value).filter_map(|item| normalize_mac(&super::php_string(&item["mac"])))
}

pub fn is_php_array(value: &Value) -> bool {
    value.is_array() || value.is_object()
}

pub fn log_event(
    db: &Connection,
    machine: i64,
    level: &str,
    message: &str,
    checkpoint: Option<&str>,
    action: Option<i64>,
) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO machine_events (machine_id, level, message, checkpoint, action_id)
         VALUES (?, ?, ?, ?, ?)",
        params![machine, level, message, checkpoint, action],
    )?;
    Ok(())
}

pub fn set_machine_status(
    db: &Connection,
    machine: i64,
    old: &str,
    new: &str,
) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE machines SET status = ? WHERE id = ?",
        params![new, machine],
    )?;
    let clear = matches!(new, "installing" | "wiping" | "wiped") &&
        db.execute(
            "UPDATE machines SET local_boot_source = 'none' WHERE id = ? AND local_boot_source != 'none'",
            [machine],
        )? != 0;
    if clear {
        log_event(
            db,
            machine,
            "info",
            "Démarrage local désactivé au début de l’opération",
            None,
            None,
        )?;
    }
    if old != new {
        log_event(
            db,
            machine,
            "info",
            &format!("Status: {old} → {new}"),
            None,
            None,
        )?;
    }
    if old != new || clear {
        enqueue_menus(db)?;
    }
    Ok(())
}

pub fn enqueue_menus(db: &Connection) -> rusqlite::Result<()> {
    db.execute(
        "INSERT INTO init_jobs (job_type, status, message)
         SELECT 'bootstrap:render_templates', 'pending', 'Régénération des menus PXE par machine'
         WHERE NOT EXISTS (SELECT 1 FROM init_jobs WHERE job_type = 'bootstrap:render_templates' AND status = 'pending')",
        [],
    )?;
    Ok(())
}
