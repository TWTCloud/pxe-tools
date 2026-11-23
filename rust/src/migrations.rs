// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{OpenFlags, TransactionBehavior};
use std::{error::Error, path::Path};

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
    let mut initialize_local_boot = false;
    for (table, additions) in LEGACY_COLUMNS {
        // Missing tables are handled by the embedded current schema below.
        let mut prepare = tx.prepare("SELECT name FROM pragma_table_info(?1)")?;
        let columns = prepare
            .query_map([table], |row| row.get::<_, String>(0))?
            .collect::<Result<std::collections::HashSet<_>, _>>()?;
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
