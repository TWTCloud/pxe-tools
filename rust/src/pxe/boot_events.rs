// SPDX-License-Identifier: LGPL-3.0-only

use super::{log_event, machine_for_mac, normalize_mac};
use crate::monitoring::Catalog;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::json;
use std::net::Ipv4Addr;

pub(crate) fn dhcp(
    db: &mut Connection,
    catalog: &Catalog,
    raw_mac: &str,
    ip: Option<Ipv4Addr>,
    proxy: bool,
) -> rusqlite::Result<()> {
    let Some(mac) = normalize_mac(raw_mac) else {
        return Ok(());
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let known = machine_for_mac(&tx, &mac)?;
    let machine = if let Some(id) = known {
        id
    } else {
        tx.execute(
            "INSERT INTO machines(mac,status,last_seen_at)
             VALUES (?1,'inventorying',CURRENT_TIMESTAMP)",
            [&mac],
        )?;
        let id = tx.last_insert_rowid();
        let source = if proxy { "DHCP proxy" } else { "DHCP" };
        let address = ip.map(|ip| format!(" (IP {ip})")).unwrap_or_default();
        log_event(
            &tx,
            id,
            "info",
            &format!("Appareil détecté en {source}{address} — en attente de discover.sh"),
            None,
            None,
        )?;
        id
    };
    if let Some(ip) = ip {
        if crate::boot_networks::contains_client(&tx, ip)? {
            // Preserve the PHP observation format for databases shared across editions.
            let message = format!(r#"PXE DHCP observed {{"mac":"{mac}","ip":"{ip}"}}"#);
            log_event(
                &tx,
                machine,
                "info",
                &message,
                Some("pxe_boot_observed"),
                None,
            )?;
        }
    }

    if known.is_some() {
        let action = tx.query_row(
            "SELECT id, type FROM actions WHERE machine_id=?1 AND status IN ('pending','running')
             ORDER BY id DESC LIMIT 1", [machine],
            |row| Ok((row.get::<_,i64>(0)?, row.get::<_,String>(1)?)),
        ).optional()?;
        if let Some((action, kind)) = action {
            if let Some(phase) = phase(&tx, action, &kind)? {
                let mut code = format!("dhcp_request_{phase}");
                if proxy && phase == "install" && installation_succeeded(&tx, action)? {
                    code = "install_reboot_done".to_owned();
                }
                if valid(catalog, &kind, &code) && (!proxy || !seen_proxy(&tx, action, &code)?) {
                    let mut data = if proxy {
                        json!({"mac": mac,"src":"dnsmasq-tail"})
                    } else {
                        json!({"dhcp_ip":""})
                    };
                    if let Some(ip) = ip {
                        data["dhcp_ip"] = json!(ip);
                    }
                    let message = format!("checkpoint:{code} {data}");
                    log_event(&tx, machine, "info", &message, Some(&code), Some(action))?;
                }
            }
        }
    }
    tx.commit()
}

pub(crate) fn tftp(
    db: &mut Connection,
    catalog: &Catalog,
    ip: Ipv4Addr,
    file: &str,
) -> rusqlite::Result<()> {
    if !matches!(
        file,
        "lpxelinux.0" | "grubnetx64.efi" | "grubnetaa64.efi" | "grubx64.efi"
    ) {
        return Ok(());
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let pattern = format!(r#"%"dhcp_ip":"{ip}"%"#);
    let action = tx
        .query_row(
            "SELECT e.machine_id, a.id, a.type
         FROM machine_events e JOIN actions a ON a.id = e.action_id AND a.machine_id = e.machine_id
         WHERE e.checkpoint IN ('dhcp_request_wipe','dhcp_request_install','dhcp_request_disktest')
           AND e.message LIKE ?1 AND e.created_at >= datetime('now','-5 minutes')
         ORDER BY e.id DESC LIMIT 1",
            [pattern],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((machine, action, kind)) = action {
        if let Some(phase) = phase(&tx, action, &kind)? {
            let code = format!("grub_config_served_{phase}");
            if valid(catalog, &kind, &code) {
                let data = json!({"bootloader":file,"ip":ip,"src":"dnsmasq-tail"});
                tx.execute(
                    "INSERT INTO machine_events(machine_id, level, message, checkpoint, action_id)
                     SELECT ?1,'info',?2,?3,?4 WHERE NOT EXISTS (
                        SELECT 1 FROM machine_events WHERE action_id=?4 AND checkpoint=?3
                        AND created_at >= datetime('now','-10 seconds'))",
                    params![machine, format!("checkpoint:{code} {data}"), code, action],
                )?;
            }
        }
    }
    tx.commit()
}

fn phase(db: &Connection, action: i64, kind: &str) -> rusqlite::Result<Option<&'static str>> {
    Ok(match kind {
        "install_only" => Some("install"),
        "wipe_only" => Some("wipe"),
        "disktest" => Some("disktest"),
        "reinstall" => {
            let wiped = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM machine_events WHERE action_id=?1
                 AND checkpoint IN ('wipe_reboot_signaled','wipe_poweroff'))",
                [action],
                |row| row.get::<_, bool>(0),
            )?;
            Some(if wiped { "install" } else { "wipe" })
        }
        _ => None,
    })
}

fn valid(catalog: &Catalog, kind: &str, code: &str) -> bool {
    catalog
        .get(kind)
        .is_some_and(|steps| steps.iter().any(|step| step.has_code(code)))
}

fn installation_succeeded(db: &Connection, action: i64) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM installations WHERE action_id=?1 AND install_status='success')",
        [action], |row| row.get(0),
    )
}

fn seen_proxy(db: &Connection, action: i64, code: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_events WHERE action_id=?1 AND checkpoint=?2)",
        params![action, code],
        |row| row.get(0),
    )
}
