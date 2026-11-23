// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{OpenFlags, TransactionBehavior};
use std::{error::Error, path::Path};

pub fn network_settings(config: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let path = crate::configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = crate::connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let invalid: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM settings WHERE key='dhcp_mode' AND
                       (value IS NULL OR value NOT IN ('proxy','tftp_only')))",
        [],
        |row| row.get(0),
    )?;
    if invalid {
        return Err("Unsupported historical DHCP mode".into());
    }
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
