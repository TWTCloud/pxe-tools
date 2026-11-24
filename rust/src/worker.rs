// SPDX-License-Identifier: LGPL-3.0-only

pub(crate) mod ansible;
pub(crate) mod bootstrap;
pub(crate) mod download;
pub(crate) mod factory_reset;
mod image_delete;
pub(crate) mod postboot;
pub(crate) mod power;
pub(crate) mod schedule;
pub(crate) mod service;
mod storage;

use crate::connect;
use rusqlite::{OpenFlags, TransactionBehavior};
use serde_json::json;
use std::{error::Error, path::Path};

pub fn recover(path: &Path) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let deletions = tx.execute(
        "UPDATE init_jobs SET status='pending', updated_at=CURRENT_TIMESTAMP
         WHERE status='running' AND (job_type GLOB 'image:delete:[0-9]*' OR job_type IN (?1,?2))",
        [factory_reset::JOB, crate::media::JOB],
    )?;
    let failed = tx.execute(
        "UPDATE init_jobs SET status='failed', ended_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP,
         message=COALESCE(message,'') || ' [reaper: worker redémarré]'
         WHERE status='running'",
        [],
    )?;
    let downloads = tx.execute(
        "UPDATE os_images SET status='pending', updated_at=CURRENT_TIMESTAMP,
         error_msg=COALESCE(error_msg,'') || ' [reaper: worker redémarré]'
         WHERE status='downloading'",
        [],
    )?;
    tx.commit()?;
    println!(
        "{}",
        json!({"deletions":deletions,"failed":failed,"downloads":downloads})
    );
    Ok(())
}
