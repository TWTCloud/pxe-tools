// SPDX-License-Identifier: LGPL-3.0-only

use super::schedule::{catalog_blocked, AUTO_CATALOG};
use crate::connect;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    error::Error,
    io::{BufRead, BufReader},
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

type ErrorBox = Box<dyn Error + Send + Sync>;

const JOBS: &[(&str, &str, Option<&str>)] = &[
    (
        "bootstrap:install_pxe_bins",
        "bootstrap-install-pxe-bins.sh",
        None,
    ),
    ("bootstrap:generate_mok", "bootstrap-generate-mok.sh", None),
    (
        "bootstrap:download_images",
        "bootstrap-download-images.sh",
        None,
    ),
    ("bootstrap:build_grub", "bootstrap-build-grub.sh", None),
    (
        "bootstrap:render_templates",
        "bootstrap-render-templates.sh",
        None,
    ),
    (
        "bootstrap:regen_mok",
        "bootstrap-generate-mok.sh",
        Some("REGEN"),
    ),
    (
        "bootstrap:rebuild_grub",
        "bootstrap-build-grub.sh",
        Some("REBUILD"),
    ),
    (
        "bootstrap:restart_dnsmasq",
        "bootstrap-restart-dnsmasq.sh",
        None,
    ),
    (
        "bootstrap:refresh_catalog",
        "bootstrap-refresh-catalog.sh",
        None,
    ),
    (
        "bootstrap:refresh_catalog_v2",
        "bootstrap-refresh-catalog-v2.sh",
        None,
    ),
    (AUTO_CATALOG, "bootstrap-refresh-catalog-v2.sh", None),
];

pub(crate) fn run(database: &Path, id: i64, scripts: &Path) -> Result<(), ErrorBox> {
    if !database.is_absolute() || !scripts.is_absolute() || id <= 0 {
        return Err("Expected a positive job ID and absolute worker paths".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let kind = tx
        .query_row(
            "SELECT job_type FROM init_jobs WHERE id=?1 AND status='pending'",
            [id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(kind) = kind else {
        return Ok(());
    };
    let (_, script, option) = JOBS
        .iter()
        .find(|(job, _, _)| *job == kind)
        .ok_or("Unsupported bootstrap job")?;
    let automatic = kind == AUTO_CATALOG;
    if automatic && catalog_blocked(&tx, false)? {
        return Ok(());
    }
    let path = scripts.join(script);
    if !path.is_file() {
        tx.execute(
            "UPDATE init_jobs SET status='failed',message=?2,ended_at=CURRENT_TIMESTAMP,
            updated_at=CURRENT_TIMESTAMP WHERE id=?1",
            params![id, format!("Script introuvable : {}", path.display())],
        )?;
        tx.commit()?;
        return Ok(());
    }
    tx.execute("UPDATE init_jobs SET status='running',started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
                progress_percent=10 WHERE id=?1", [id])?;
    tx.commit()?;

    let (logs, output) = UnixStream::pair()?;
    let stderr = output.try_clone()?;
    let mut invocation = Command::new("/bin/bash");
    invocation
        .arg(&path)
        .env("WORKER_JOB_ID", id.to_string())
        .process_group(0);
    if let Some(key) = option {
        invocation.env(key, "1");
    }
    let started = invocation
        .stdout(Stdio::from(OwnedFd::from(output)))
        .stderr(Stdio::from(OwnedFd::from(stderr)))
        .spawn();
    drop(invocation);
    let mut child = match started {
        Ok(child) => child,
        Err(error) => {
            finish(
                &mut db,
                id,
                false,
                automatic,
                &format!("[worker] Échec lancement : {error}\n"),
            )?;
            return Ok(());
        }
    };
    if let Err(error) = collect(&db, id, logs, &path, *option) {
        // The child owns its process group, including commands launched by Bash.
        unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        let _ = child.wait();
        return Err(error);
    }
    let status = child.wait()?;
    let code = status
        .code()
        .map_or_else(|| status.to_string(), |code| code.to_string());
    finish(
        &mut db,
        id,
        status.success(),
        automatic,
        &format!("\n[worker] exit code = {code}\n"),
    )?;
    let state = if status.success() {
        "success"
    } else {
        "failed"
    };
    println!("[worker] {kind} → {state}");
    Ok(())
}

fn collect(
    db: &Connection,
    id: i64,
    logs: UnixStream,
    path: &Path,
    option: Option<&str>,
) -> Result<(), ErrorBox> {
    let mut logs = BufReader::new(logs);
    let prefix = option.map_or_else(String::new, |name| format!("{name}=1 "));
    let mut batch = format!("[worker] $ {prefix}{}\n", path.display()).into_bytes();
    let mut last = Instant::now();
    while logs.read_until(b'\n', &mut batch)? != 0 {
        if batch.len() >= 16_384 || last.elapsed() >= Duration::from_secs(1) {
            append(db, id, &batch)?;
            batch.clear();
            last = Instant::now();
        }
    }
    if !batch.is_empty() {
        append(db, id, &batch)?;
    }
    Ok(())
}

fn append(db: &Connection, id: i64, text: &[u8]) -> rusqlite::Result<()> {
    db.execute(
        "UPDATE init_jobs SET log=COALESCE(log,'') || ?2, updated_at=CURRENT_TIMESTAMP
                WHERE id=?1 AND status='running'",
        params![id, String::from_utf8_lossy(text)],
    )?;
    Ok(())
}

fn finish(
    db: &mut Connection,
    id: i64,
    ok: bool,
    automatic: bool,
    log: &str,
) -> rusqlite::Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (status, percent) = if ok { ("success", 100) } else { ("failed", 0) };
    let updated=tx.execute("UPDATE init_jobs SET log=COALESCE(log,'') || ?2, status=?3, progress_percent=?4,
                ended_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
               params![id,log,status,percent])?;
    if updated == 1 && ok && automatic {
        tx.execute("INSERT INTO settings(key,value) VALUES('catalog_auto_refresh_last_at',?1)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP",
                   [crate::now().to_string()])?;
    }
    tx.commit()
}
