// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::Value;
use std::{collections::HashSet, error::Error, path::Path};

pub fn network_settings(config: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = crate::configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = crate::connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "INSERT INTO settings(key,value) VALUES('wizard_completed','0')
         ON CONFLICT(key) DO NOTHING;
         INSERT INTO settings(key,value)
             SELECT 'pxe_ip', value FROM settings WHERE key='orchestrator_ip'
             ON CONFLICT(key) DO NOTHING;
         INSERT INTO settings(key,value)
             SELECT 'dhcp_proxy_enabled', CASE value WHEN 'proxy' THEN 'on' ELSE 'off' END
             FROM settings WHERE key='dhcp_mode'
             ON CONFLICT(key) DO NOTHING;",
    )?;
    tx.commit()?;
    println!("Rust migrated network settings, preserving explicit choices");
    Ok(())
}

const SCHEMA: &str = include_str!("../../app/db/schema.sqlite.sql");

// Keep the historical ALTER defaults, including the legacy enabled root
// login. The current schema supplies the defaults for newly created databases.
const LEGACY_COLUMNS: &[(&str, &[(&str, &str)])] = &[
    ("init_jobs", &[("updated_at", "DATETIME")]),
    (
        "machines",
        &[
            ("root_password_hash", "TEXT"),
            ("root_password_encrypted", "BLOB"),
            ("root_password_kdf_salt", "BLOB"),
            ("root_password_nonce", "BLOB"),
            ("root_password_cipher", "TEXT"),
            ("boot_arch", "TEXT"),
            ("awaiting_action_until", "DATETIME"),
            ("auto_deploy", "INTEGER NOT NULL DEFAULT 0"),
            ("local_boot_source", "TEXT NOT NULL DEFAULT 'none'"),
        ],
    ),
    (
        "presets",
        &[
            ("advanced_config_json", "TEXT"),
            ("root_login_mode", "TEXT NOT NULL DEFAULT 'enabled'"),
            ("admin_user_fullname", "TEXT"),
            ("domain", "TEXT"),
            ("pre_wipe_mode", "TEXT NOT NULL DEFAULT 'aucun'"),
            ("version_full", "TEXT"),
            ("variant", "TEXT NOT NULL DEFAULT 'debian'"),
            ("admin_user_password_cipher", "TEXT"),
            ("codename", "TEXT"),
            ("based_on_machine_id", "INTEGER"),
            ("hostname_pattern", "TEXT"),
            ("hostname_random", "INTEGER NOT NULL DEFAULT 0"),
            ("pre_wipe_mode_json", "TEXT"),
        ],
    ),
    (
        "os_images",
        &[
            ("firmware_url", "TEXT"),
            ("size_bytes", "INTEGER"),
            ("error_msg", "TEXT"),
            ("progress_percent", "INTEGER NOT NULL DEFAULT 0"),
            ("message", "TEXT"),
            ("updated_at", "DATETIME"),
            ("minor_version", "TEXT"),
            ("channel", "TEXT"),
            ("codename", "TEXT"),
            ("major", "INTEGER"),
            ("version_full", "TEXT"),
            ("iso_url", "TEXT"),
            ("extract_method", "TEXT NOT NULL DEFAULT 'direct'"),
        ],
    ),
    (
        "discoveries",
        &[("action_id", "INTEGER REFERENCES actions(id)")],
    ),
    (
        "installations",
        &[
            ("action_id", "INTEGER REFERENCES actions(id)"),
            ("install_log", "TEXT"),
        ],
    ),
    (
        "machine_events",
        &[
            ("action_id", "INTEGER REFERENCES actions(id)"),
            ("checkpoint", "TEXT"),
        ],
    ),
    (
        "wipes",
        &[
            ("action_id", "INTEGER REFERENCES actions(id)"),
            ("chain_install_config_json", "TEXT"),
        ],
    ),
    (
        "disk_tests",
        &[
            ("action_id", "INTEGER REFERENCES actions(id)"),
            ("progress_json", "TEXT"),
            ("in_session", "INTEGER NOT NULL DEFAULT 0"),
        ],
    ),
];

pub fn schema(config: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = crate::configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = crate::connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_upgrade_compatibility(&tx)?;
    let mut initialize_local_boot = false;
    for (table, additions) in LEGACY_COLUMNS {
        // Missing tables are handled by the embedded current schema below.
        let mut prepare = tx.prepare("SELECT name FROM pragma_table_info(?1)")?;
        let columns = prepare
            .query_map([table], |row| row.get::<_, String>(0))?
            .collect::<Result<HashSet<_>, _>>()?;
        if columns.is_empty() {
            continue;
        }
        for (column, declaration) in *additions {
            if !columns.contains(*column) {
                tx.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {declaration}"),
                    [],
                )?;
                initialize_local_boot |= *table == "machines" && *column == "local_boot_source";
            }
        }
    }
    tx.execute_batch(SCHEMA)?;
    if initialize_local_boot {
        tx.execute(
            "UPDATE machines SET local_boot_source='pxe'
             WHERE status IN ('installed','provisioned') AND EXISTS(
                 SELECT 1 FROM installations i WHERE i.machine_id=machines.id AND i.install_status='success'
             )",
            [],
        )?;
    }
    tx.commit()?;
    println!("Rust applied the SQLite schema evolution");
    Ok(())
}

fn check_upgrade_compatibility(db: &Connection) -> Result<(), Box<dyn Error + Send + Sync>> {
    for (table, column) in [
        ("presets", "static_cidr"),
        ("machines", "install_config_json"),
    ] {
        let found: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name=?2)",
            [table, column],
            |row| row.get(0),
        )?;
        if !found {
            return Err(format!("Migration refusée : colonne {table}.{column} absente.").into());
        }
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('presets') WHERE name IN ('partition_target_disk','partition_lvm_vg'))",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Err("Migration refusée : colonnes historiques de partition à examiner.".into());
    }
    let mut presets = db.prepare("SELECT partition_mode,partition_custom_json FROM presets")?;
    let mut rows = presets.query([])?;
    while let Some(row) = rows.next()? {
        let mode: Option<String> = row.get(0)?;
        let layout: Option<String> = row.get(1)?;
        if legacy_partition_mode(mode.as_deref()) || layout.as_deref().is_some_and(legacy_layout) {
            return Err("Migration refusée : recette de partition historique à examiner.".into());
        }
    }

    let mut machines = db.prepare(
        "SELECT install_config_json FROM machines WHERE install_config_json IS NOT NULL",
    )?;
    let mut rows = machines.query([])?;
    while let Some(row) = rows.next()? {
        let snapshot: String = row.get(0)?;
        let Ok(snapshot) = serde_json::from_str::<Value>(&snapshot) else {
            continue;
        };
        let layout = &snapshot["partition_custom_json"];
        if legacy_partition_mode(snapshot["partition_mode"].as_str())
            || layout.as_str().is_some_and(legacy_layout)
            || list_layout(layout)
        {
            return Err("Migration refusée : configuration machine historique à examiner.".into());
        }
    }

    let sensitive: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM settings WHERE key IN ('ansible_vault_password','ansible_vault_applied_hash'))",
        [],
        |row| row.get(0),
    )?;
    if sensitive {
        return Err("Migration refusée : anciennes données sensibles à traiter séparément.".into());
    }
    let unknown_dhcp: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM settings WHERE key='dhcp_mode' AND (value IS NULL OR value NOT IN ('proxy','tftp_only')))",
        [],
        |row| row.get(0),
    )?;
    if unknown_dhcp {
        return Err("Migration refusée : ancien mode réseau non reconnu.".into());
    }

    let supported: HashSet<_> = SCHEMA
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("CREATE TABLE IF NOT EXISTS ")
        })
        .filter_map(|definition| definition.split_ascii_whitespace().next())
        .collect();
    let mut tables = db.prepare(
        "SELECT name FROM sqlite_schema WHERE type='table' AND substr(name,1,7)<>'sqlite_'",
    )?;
    let mut rows = tables.query([])?;
    while let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        if supported.contains(table.as_str()) {
            continue;
        }
        let quoted = table.replace('"', "\"\"");
        let populated = db.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM \"{quoted}\")"),
            [],
            |row| row.get::<_, bool>(0),
        );
        if !matches!(populated, Ok(false)) {
            return Err("Migration refusée : données externes ou tables non reconnues à examiner séparément.".into());
        }
    }
    Ok(())
}

fn legacy_partition_mode(mode: Option<&str>) -> bool {
    matches!(
        mode,
        Some("atomic_lvm" | "home_separate" | "var_separate" | "encrypted")
    )
}

fn legacy_layout(raw: &str) -> bool {
    serde_json::from_str(raw).is_ok_and(|value| list_layout(&value))
}

fn list_layout(value: &Value) -> bool {
    match value {
        Value::Array(_) => true,
        // PHP decodes objects with sequential numeric keys as lists.
        Value::Object(fields) => {
            (0..fields.len()).all(|index| fields.contains_key(&index.to_string()))
        }
        _ => false,
    }
}

pub fn preset_network(config: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = crate::configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = crate::connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut updates = Vec::new();
    {
        let mut presets = tx.prepare(
            "SELECT id,static_netmask,static_cidr IS NULL,static_dns FROM presets
                                      WHERE (static_cidr IS NULL AND static_netmask IS NOT NULL)
                                         OR (static_dns IS NOT NULL AND static_dns<>'')",
        )?;
        let mut rows = presets.query([])?;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let mask: Option<String> = row.get(1)?;
            let missing_cidr: bool = row.get(2)?;
            let raw: Option<String> = row.get(3)?;
            let cidr = if missing_cidr {
                mask.as_deref().and_then(legacy_netmask)
            } else {
                None
            };
            let dns = raw
                .as_deref()
                .filter(|value| !value.is_empty())
                .and_then(legacy_dns);
            if cidr.is_some() || dns.is_some() {
                updates.push((cidr, dns, id));
            }
        }
    }
    let updated = updates.len();
    for (cidr, dns, id) in updates {
        tx.execute(
            "UPDATE presets SET static_cidr=COALESCE(?1,static_cidr),static_dns=COALESCE(?2,static_dns) WHERE id=?3",
            rusqlite::params![cidr,dns,id],
        )?;
    }
    tx.commit()?;
    println!("Rust normalized legacy network settings for {updated} preset(s)");
    Ok(())
}

fn legacy_netmask(value: &str) -> Option<u32> {
    let address = crate::php_trim(value).parse::<std::net::Ipv4Addr>().ok()?;
    let mask = u32::from(address);
    (mask.leading_ones() == mask.count_ones()).then_some(mask.count_ones())
}

fn legacy_dns(value: &str) -> Option<String> {
    if matches!(
        serde_json::from_str::<serde_json::Value>(value),
        Ok(serde_json::Value::Object(_) | serde_json::Value::Array(_))
    ) {
        return None;
    }
    let list: Vec<_> = value
        .split(|character: char| {
            matches!(character, ',' | '\x0b') || character.is_ascii_whitespace()
        })
        .map(crate::php_trim)
        .filter(|item| !item.is_empty())
        .collect();
    serde_json::to_string(&list).ok()
}
