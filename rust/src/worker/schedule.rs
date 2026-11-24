// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, setting};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{error::Error, path::Path};

type ErrorBox = Box<dyn Error + Send + Sync>;
pub(super) const AUTO_CATALOG: &str = "bootstrap:auto_refresh_catalog_v2";

pub(crate) fn run(database: &Path, kind: &str, workspace: &Path) -> Result<(), ErrorBox> {
    if !database.is_absolute() || !workspace.is_absolute() {
        return Err("Expected absolute worker paths".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = match kind {
        "catalog" => catalog(&tx)?,
        "presets" if workspace.join(".git").is_dir() => presets(&tx)?,
        "presets" => None,
        _ => return Err("Unknown scheduled worker job family".into()),
    };
    if let Some((name, message)) = &job {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
            params![name, message],
        )?;
    }
    tx.commit()?;
    if let Some((name, _)) = job {
        println!("[worker] {name} mis en attente");
    }
    Ok(())
}

pub(super) fn catalog_blocked(db: &Connection, include_automatic: bool) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machines WHERE status IN ('installing','wiping','testing'))
         OR EXISTS(SELECT 1 FROM actions WHERE status IN ('pending','running'))
         OR EXISTS(SELECT 1 FROM init_jobs WHERE status IN ('pending','running')
                   AND (job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2')
                        OR (?1 AND job_type=?2)))",
        params![include_automatic, AUTO_CATALOG],
        |row| row.get(0),
    )
}

fn catalog(db: &Connection) -> rusqlite::Result<Option<(String, &'static str)>> {
    if setting(db, "catalog_auto_refresh_enabled")? != "on" {
        return Ok(None);
    }
    let hours: i64 = setting(db, "catalog_auto_refresh_interval_hours")?
        .trim()
        .parse()
        .ok()
        .filter(|hours| matches!(hours, 24 | 168 | 720))
        .unwrap_or(168);
    let last: i64 = setting(db, "catalog_auto_refresh_last_at")?
        .trim()
        .parse()
        .unwrap_or_default();
    if (last > 0 && crate::now().saturating_sub(last) < hours * 3_600) || catalog_blocked(db, true)?
    {
        return Ok(None);
    }
    Ok(Some((
        AUTO_CATALOG.to_owned(),
        "Actualisation automatique du catalogue",
    )))
}

fn presets(db: &Connection) -> rusqlite::Result<Option<(String, &'static str)>> {
    if setting(db, "ansible_enabled")? != "on" || setting(db, "ansible_repo_url")?.is_empty() {
        return Ok(None);
    }
    if db.query_row(
        "SELECT EXISTS (SELECT 1 FROM init_jobs WHERE status IN ('pending','running')
           AND (job_type LIKE 'preset:push_github:%' OR job_type LIKE 'preset:delete_github:%'
              OR job_type LIKE 'preset:pull_github%'))",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(None);
    }
    let failed = db
        .query_row(
            "SELECT job_type FROM init_jobs AS j WHERE status='failed'
         AND (job_type LIKE 'preset:push_github:%' OR job_type LIKE 'preset:delete_github:%')
         AND id=(SELECT MAX(id) FROM init_jobs WHERE job_type=j.job_type)
         AND ended_at<=datetime('now','-5 minutes') ORDER BY id LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if let Some(job) = failed {
        let relevant = if let Some(id) = job.strip_prefix("preset:push_github:") {
            match id.parse::<i64>() {
                Ok(id) if id > 0 => db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM presets WHERE id=?1)",
                    [id],
                    |row| row.get(0),
                )?,
                _ => false,
            }
        } else if let Some(deleted) = job.strip_prefix("preset:delete_github:") {
            let mut query = db.prepare("SELECT name FROM presets")?;
            let mut names = query.query([])?;
            let mut still_present = false;
            while let Some(row) = names.next()? {
                if slug(&row.get::<_, String>(0)?) == deleted {
                    still_present = true;
                    break;
                }
            }
            !still_present
        } else {
            false
        };
        if relevant {
            return Ok(Some((job, "Nouvelle tentative de synchronisation GitHub")));
        }
    }
    Ok(Some((
        "preset:pull_github".to_owned(),
        "Actualisation automatique des modèles depuis GitHub",
    )))
}

fn slug(name: &str) -> String {
    name.to_lowercase()
        .split(|letter: char| {
            !letter.is_ascii_lowercase() && !letter.is_ascii_digit() && letter != '-'
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .trim_matches('-')
        .to_owned()
}
