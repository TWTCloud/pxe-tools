// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, instance_secrets, setting};
use hyper::Uri;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Stdio},
};

pub const JOB: &str = "media:prepare";
pub const REDHAT_JOB: &str = "media:prepare:rhel";
pub const REDHAT_ROUTE: &str = "/settings/images/rhel";
pub const REDHAT_TOKEN_LIMIT: usize = 4096;

// DVD checksums and advertised sizes from the Red Hat Developer release catalogue.
pub const RHEL_DVDS: [(&str, &str, &str, &str); 4] = [
    (
        "9.9",
        "amd64",
        "15,1 Go",
        "9833bfb1888a307228cc2487912c0529d5253ffe96c79ef1a5219011e4ab067e",
    ),
    (
        "9.9",
        "arm64",
        "12,98 Go",
        "54ee36b11b18e0b419856af603cff66880e500b4b804645c74cee62ac7cf66ed",
    ),
    (
        "9.8",
        "amd64",
        "14,47 Go",
        "c0dd53b73406b85b40d6168d1748e605d71361b2992d282c408b7d7d2e1d2c80",
    ),
    (
        "9.8",
        "arm64",
        "12,39 Go",
        "1da7c7f9b30f2587d44f8ef6b34b2a27f2f0571bf09da6046195a74df275fa92",
    ),
];
pub const RHEL_PREFIX: &str = "/pxe/rhel9/";
type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Serialize, Deserialize)]
pub struct Import {
    pub kind: String,
    pub source: String,
    pub sha256: String,
    pub profile: String,
    pub remote: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redhat_token: Option<String>,
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
        if let Some(token) = &self.redhat_token {
            return self.kind == "rhel9"
                && !self.remote
                && self.source.is_empty()
                && self.profile.is_empty()
                && digest(&self.sha256)
                && (1..=REDHAT_TOKEN_LIMIT).contains(&token.len())
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b));
        }
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
    let job = if let Some(token) = &mut request.redhat_token {
        *token = instance_secrets::seal(token.as_bytes())?;
        REDHAT_JOB
    } else {
        if request.remote {
            request.source = instance_secrets::seal(request.source.as_bytes())?;
        }
        JOB
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO init_jobs(job_type,status,message)
         VALUES(?1,'pending','Préparation du média PXE demandée')",
        [job],
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
    let key = request_key(id);
    let job = tx
        .query_row(
            "UPDATE init_jobs SET status='running',progress_percent=5,started_at=CURRENT_TIMESTAMP,
         updated_at=CURRENT_TIMESTAMP,message='Vérification de la source du média'
         WHERE id=?1 AND job_type IN (?2,?3) AND status='pending' RETURNING job_type",
            params![id, JOB, REDHAT_JOB],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(job) = job else {
        return Ok(());
    };
    let redhat = job == REDHAT_JOB;
    let request = setting(&tx, &key)?;
    if redhat {
        // A new request is required if the job fails or the worker is interrupted.
        tx.execute("DELETE FROM settings WHERE key=?1", [&key])?;
    }
    tx.commit()?;
    let result = prepare(scripts, &request, redhat, |percent, message| {
        let _ = db.execute(
            "UPDATE init_jobs SET progress_percent=?2,message=?3,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='running' AND progress_percent<?2",
            params![id, percent, message],
        );
    });
    let (state, message) = match result {
        Ok(summary) => ("success", summary),
        Err(message) => ("failed", message),
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE init_jobs SET status=?2,message=?3,
         progress_percent=CASE WHEN ?4 AND ?2='failed' THEN progress_percent ELSE 100 END,
         ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='running'",
        params![id, state, message, redhat],
    )?;
    if state == "success" && !redhat {
        tx.execute("DELETE FROM settings WHERE key=?1", [&key])?;
    }
    tx.commit()?;
    Ok(())
}

fn prepare(
    scripts: &Path,
    raw: &str,
    redhat: bool,
    mut progress: impl FnMut(u8, &str),
) -> Result<String, String> {
    let invalid = || "Source média indisponible ou non autorisée.".to_owned();
    let mut request: Import = serde_json::from_str(raw).map_err(|_| invalid())?;
    if redhat != request.redhat_token.is_some() {
        return Err(invalid());
    }
    if let Some(token) = &mut request.redhat_token {
        let plaintext = instance_secrets::open(token).map_err(|_| invalid())?;
        *token = std::str::from_utf8(&plaintext)
            .map_err(|_| invalid())?
            .to_owned();
    }
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
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&request).map_err(|_| failure())?);
    let mut child = Command::new("/usr/bin/python3")
        .arg(scripts.join("prepare-pxe-media.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure())?;
    // The worker never passes signed URLs or credentials through argv or the job log.
    let accepted = child
        .stdin
        .take()
        .is_some_and(|mut pipe| pipe.write_all(&encoded).is_ok());
    let reader = BufReader::new(child.stdout.take().expect("piped media output"));
    let mut summary = None;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if redhat {
            if let Some(pct) = line
                .strip_prefix("progress:")
                .and_then(|value| value.parse().ok())
            {
                if let Some(message) = redhat_progress(pct) {
                    progress(pct, message);
                    continue;
                }
            }
        }
        summary = Some(line);
    }
    let status = child.wait().map_err(|_| failure())?;
    let summary = summary.as_deref().unwrap_or_default().trim();
    if !accepted
        || summary.is_empty()
        || summary.len() > 512
        || summary.chars().any(char::is_control)
    {
        return Err(failure());
    }
    if status.success() {
        Ok(summary.into())
    } else {
        Err(summary.into())
    }
}

fn redhat_progress(percent: u8) -> Option<&'static str> {
    Some(match percent {
        10 => "Connexion à Red Hat",
        15..=80 => "Téléchargement du DVD depuis Red Hat",
        85 => "Vérification de l’empreinte SHA-256 du DVD",
        95 => "Extraction des fichiers de démarrage et des dépôts RHEL",
        _ => return None,
    })
}
