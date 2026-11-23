// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::net::Ipv4Addr;

fn menu_label(menu: &str) -> Option<&'static str> {
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

pub fn client_in_subnet(ip: Ipv4Addr, subnet: &str) -> bool {
    let Some((network, prefix)) = super::php_trim(subnet).split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix_len)) = (network.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
        return false;
    };
    if prefix_len > 32 || prefix != prefix_len.to_string() {
        return false;
    }
    let mask = u32::MAX.checked_shl(32 - prefix_len).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
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

fn normalize_mac(raw: &str) -> Option<String> {
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

fn machine_for_mac(db: &Connection, mac: &str) -> rusqlite::Result<Option<i64>> {
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
        let interfaces = match &inventory["interfaces"] {
            Value::Array(interfaces) => interfaces.iter().any(|item| match_interface(item, mac)),
            Value::Object(interfaces) => interfaces.values().any(|item| match_interface(item, mac)),
            _ => false,
        };
        if interfaces {
            return row.get(0).map(Some);
        }
    }
    Ok(None)
}

fn match_interface(interface: &Value, mac: &str) -> bool {
    let address = super::php_string(&interface["mac"]);
    normalize_mac(&address).as_deref() == Some(mac)
}
