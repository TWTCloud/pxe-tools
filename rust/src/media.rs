// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, instance_secrets, setting};
use hyper::Uri;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub const JOB: &str = "media:prepare";
pub const RHEL_PREFIX: &str = "/pxe/rhel9/";
type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Serialize, Deserialize)]
pub struct Import {
    pub kind: String,
    pub source: String,
    pub sha256: String,
    pub profile: String,
    pub remote: bool,
}

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn download_hosts() -> Vec<String> {
    std::env::var("PXE_MEDIA_DOWNLOAD_HOSTS")
        .unwrap_or_default()
        .split(',')
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

fn allowed_url(value: &str) -> bool {
    if value.len() > 4096 || value.contains(['#', '\\']) {
        return false;
    }
    let Ok(uri) = value.parse::<Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && !authority.as_str().contains('@')
        && authority.port_u16().is_none_or(|port| port == 443)
        && download_hosts().contains(&authority.host().to_ascii_lowercase())
}

impl Import {
    pub fn valid(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "rhel9" | "windows-iso" | "windows-wim" | "windows-esd" | "winpe"
        ) && digest(&self.sha256)
            && (if self.kind == "winpe" {
                profile_id(&self.profile)
            } else {
                self.profile.is_empty()
            })
            && (if self.remote {
                allowed_url(&self.source)
            } else {
                self.source.len() <= 200
                    && self
                        .source
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && self
                        .source
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
    }
}

fn request_key(id: i64) -> String {
    format!("media_import_request_{id}")
}

pub fn enqueue(db: &mut Connection, mut request: Import) -> Result<i64, ErrorBox> {
    if request.remote {
        request.source = instance_secrets::seal(request.source.as_bytes())?;
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO init_jobs(job_type,status,message)
         VALUES(?1,'pending','Préparation du média PXE demandée')",
        [JOB],
    )?;
    let id = tx.last_insert_rowid();
    tx.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2)",
        params![request_key(id), serde_json::to_string(&request)?],
    )?;
    tx.commit()?;
    Ok(id)
}

pub fn run(database: &Path, id: i64, scripts: &Path) -> Result<(), ErrorBox> {
    if id <= 0 || !database.is_absolute() || !scripts.is_absolute() {
        return Err("Invalid media worker paths".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE init_jobs SET status='running',progress_percent=5,started_at=CURRENT_TIMESTAMP,
         updated_at=CURRENT_TIMESTAMP,message='Vérification de la source du média'
         WHERE id=?1 AND job_type=?2 AND status='pending'",
        params![id, JOB],
    )? != 1
    {
        return Ok(());
    }
    let key = request_key(id);
    let request = setting(&tx, &key)?;
    tx.commit()?;
    let result = prepare(scripts, &request);
    let (state, message) = match result {
        Ok(summary) => ("success", summary),
        Err(message) => ("failed", message),
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE init_jobs SET status=?2,message=?3,progress_percent=100,
         ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
        params![id, state, message],
    )?;
    if state == "success" {
        tx.execute("DELETE FROM settings WHERE key=?1", [&key])?;
    }
    tx.commit()?;
    Ok(())
}

fn prepare(scripts: &Path, raw: &str) -> Result<String, String> {
    let invalid = || "Source média indisponible ou non autorisée.".to_owned();
    let mut request: Import = serde_json::from_str(raw).map_err(|_| invalid())?;
    if request.remote {
        let source = instance_secrets::open(&request.source).map_err(|_| invalid())?;
        request.source = std::str::from_utf8(&source)
            .map_err(|_| invalid())?
            .to_owned();
    }
    if !request.valid() {
        return Err(invalid());
    }
    let failure = || "Impossible de préparer le média PXE.".to_owned();
    let encoded = serde_json::to_vec(&request).map_err(|_| failure())?;
    let mut child = Command::new("/usr/bin/python3")
        .arg(scripts.join("prepare-pxe-media.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure())?;
    // The worker never passes signed URLs through argv or the job log.
    let accepted = child
        .stdin
        .take()
        .is_some_and(|mut pipe| pipe.write_all(&encoded).is_ok());
    let output = child.wait_with_output().map_err(|_| failure())?;
    let summary = std::str::from_utf8(&output.stdout)
        .map_err(|_| failure())?
        .trim();
    if !accepted
        || summary.is_empty()
        || summary.len() > 512
        || summary.chars().any(char::is_control)
    {
        return Err(failure());
    }
    if output.status.success() {
        Ok(summary.into())
    } else {
        Err(summary.into())
    }
}
