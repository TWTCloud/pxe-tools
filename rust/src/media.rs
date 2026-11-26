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
pub const WINDOWS_ROUTE: &str = "/settings/images/windows";
pub const WINDOWS_DOWNLOAD_PAGE: &str =
    "https://www.microsoft.com/fr-fr/software-download/windows11";
pub const WINDOWS_CDN: &str = "software.download.prss.microsoft.com";
// Windows 11 x64 consumer ISO checksums from the official download page.
pub const WINDOWS_ISOS: [(&str, &str, &str); 3] = [
    (
        "fr-fr",
        "Français",
        "aa515279f02fb2b425eff341f0a1f158d61288c72cca5f9d87b79b5a23f7f918",
    ),
    (
        "en-us",
        "Anglais",
        "bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650",
    ),
    (
        "en-gb",
        "Anglais international",
        "7e3f373bd3c2321b5d5125dfcf718dfbf1a0abc50a267118669951890df98a5d",
    ),
];

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
pub const PROXMOX_VERSION: &str = "9.2-1";
pub const PROXMOX_ISOS: [(&str, &str); 2] = [
    (
        "amd64",
        "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    ),
    (
        "arm64",
        "b1619dcd1f5b1a6d67d77b59e7e2fa2033174551d1e1b9dc22b2171ec093abbd",
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

fn allowed_url(value: &str, hosts: impl IntoIterator<Item = impl AsRef<str>>) -> bool {
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
        && hosts
            .into_iter()
            .any(|host| authority.host().eq_ignore_ascii_case(host.as_ref()))
}

impl Import {
    pub fn valid(&self) -> bool {
        if self.kind == "proxmox" {
            let mut parts = self.profile.split(':');
            return !self.remote
                && self.redhat_token.is_none()
                && PROXMOX_ISOS.contains(&(self.source.as_str(), self.sha256.as_str()))
                && parts
                    .next()
                    .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                && parts
                    .next()
                    .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port > 0))
                && parts.next().is_some_and(digest)
                && parts.next().is_none();
        }
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
        if self.kind == "windows-official" {
            return self.remote
                && WINDOWS_ISOS
                    .iter()
                    .any(|(language, _, hash)| *language == self.profile && *hash == self.sha256)
                && allowed_url(&self.source, [WINDOWS_CDN])
                && self.source.parse::<Uri>().is_ok_and(|uri| {
                    uri.path().starts_with("/dbazure/") && uri.path().ends_with(".iso")
                });
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
                allowed_url(&self.source, download_hosts())
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
        if redhat || request.kind == "windows-official" {
            if let Some(pct) = line
                .strip_prefix("progress:")
                .and_then(|value| value.parse().ok())
            {
                let message = if redhat {
                    redhat_progress(pct)
                } else {
                    windows_progress(pct)
                };
                if let Some(message) = message {
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

fn windows_progress(percent: u8) -> Option<&'static str> {
    Some(match percent {
        15..=80 => "Téléchargement de l’ISO depuis Microsoft",
        85 => "Vérification de l’empreinte publiée par Microsoft",
        95 => "Préparation de WinPE et lecture des éditions Windows",
        _ => return None,
    })
}
