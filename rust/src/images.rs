// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, php_string};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde::Deserialize;
use serde_json::Value;
use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, BufRead, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ImageKey {
    id: i64,
    distro: String,
    version: String,
    version_full: Option<String>,
    arch: String,
}

struct Image {
    key: ImageKey,
    codename: Option<String>,
    extract_method: String,
    status: String,
    enabled: bool,
}

pub(super) fn reserve_deletion(path: &Path, image_id: i64, job_id: i64) -> Result<(), ErrorBox> {
    // geteuid() reads the identity of this process and has no pointer arguments.
    if unsafe { libc::geteuid() } == 0 || image_id <= 0 || job_id <= 0 || !path.is_absolute() {
        return Err("Invalid image deletion request".into());
    }
    let http = std::env::var_os("PXE_HTTP_ROOT")
        .filter(|root| !root.is_empty())
        .or_else(|| std::env::var_os("HTTP_ROOT").filter(|root| !root.is_empty()))
        .map(PathBuf::from)
        .ok_or("Missing HTTP root")?;
    if !http.is_absolute() {
        return Err("Invalid HTTP root".into());
    }
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    // BEGIN IMMEDIATE reserves writes before the first snapshot read, including
    // changes to replacements and assignments while the parent stages files.
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let image = transaction.query_row(
        "SELECT id,distro,version,version_full,arch,codename,extract_method,status,enabled
         FROM os_images WHERE id=?",
        [image_id],
        |row| {
            Ok(Image {
                key: ImageKey {
                    id: row.get(0)?,
                    distro: row.get(1)?,
                    version: row.get(2)?,
                    version_full: row.get(3)?,
                    arch: row.get(4)?,
                },
                codename: row.get(5)?,
                extract_method: row.get(6)?,
                status: row.get(7)?,
                enabled: row.get::<_, i64>(8)? == 1,
            })
        },
    )?;
    let snapshot: String = transaction.query_row(
        "SELECT log FROM init_jobs WHERE id=? AND job_type=? AND status='running'",
        params![job_id, format!("image:delete:{image_id}")],
        |row| row.get(0),
    )?;
    if serde_json::from_str::<ImageKey>(&snapshot)? != image.key
        || !can_delete(&transaction, &image, &http)?
    {
        return Err("Image deletion refused".into());
    }

    let mut output = io::stdout().lock();
    output.write_all(b"READY\n")?;
    output.flush()?;
    let mut signal = String::new();
    io::stdin().lock().take(8).read_line(&mut signal)?;
    if signal != "COMMIT\n" {
        return Err("Worker did not confirm staging".into());
    }
    if transaction.execute("DELETE FROM os_images WHERE id=?", [image_id])? != 1
        || transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM os_images WHERE id=?)",
            [image_id],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err("SQLite did not confirm image deletion".into());
    }
    transaction.commit()?;
    output.write_all(b"COMMITTED\n")?;
    output.flush()?;
    Ok(())
}

fn can_delete(db: &Connection, image: &Image, http: &Path) -> Result<bool, ErrorBox> {
    if image.status == "downloading" || (image.status == "pending" && image.enabled) {
        return Ok(false);
    }
    let base = image.key.distro == "debian" && image.extract_method == "direct";
    if base {
        let mut replacements = db.prepare(
            "SELECT id,distro,version,version_full,arch FROM os_images
             WHERE distro='debian' AND arch=? AND extract_method='direct'
             AND id<>? AND enabled=1 AND status='downloaded'",
        )?;
        let mut rows = replacements.query(params![image.key.arch, image.key.id])?;
        let mut available = false;
        while let Some(row) = rows.next()? {
            let candidate = ImageKey {
                id: row.get(0)?,
                distro: row.get(1)?,
                version: row.get(2)?,
                version_full: row.get(3)?,
                arch: row.get(4)?,
            };
            available |= candidate.available(http)?;
        }
        if image.enabled && image.status == "downloaded" && image.key.available(http)? && !available
        {
            return Ok(false);
        }
    }
    let mut assigned = db.prepare(
        "WITH active AS (
           SELECT machine_id FROM actions WHERE status IN ('pending','running')
           UNION
           SELECT machine_id FROM installations
             WHERE install_status IN ('pending','running','installing','in_progress')
                OR ansible_status IN ('pending','running','in_progress')
         )
         SELECT m.status, m.boot_arch, m.rescue_mode, m.install_config_json, a.machine_id IS NOT NULL
         FROM machines m LEFT JOIN active a ON a.machine_id=m.id",
    )?;
    let mut rows = assigned.query([])?;
    while let Some(row) = rows.next()? {
        let status: String = row.get(0)?;
        let arch: Option<String> = row.get(1)?;
        let in_rescue: bool = row.get(2)?;
        let raw: Option<String> = row.get(3)?;
        let active: bool = row.get(4)?;
        let config = parse_config(raw.as_deref());
        let base_operation = matches!(status.as_str(), "inventorying" | "wiping" | "testing");
        let uses_base = base
            && arch
                .as_deref()
                .filter(|arch| !arch.is_empty())
                .unwrap_or("amd64")
                == image.key.arch
            && (in_rescue || base_operation);
        if uses_base
            || (image.matches(&config, arch.as_deref())
                && (active || base_operation || status == "installing"))
        {
            return Ok(false);
        }
    }
    let mut chains = db.prepare(
        "SELECT w.chain_install_config_json, m.boot_arch
         FROM wipes w JOIN machines m ON m.id=w.machine_id
         WHERE w.wipe_status IN ('pending','running') AND w.chain_install_config_json IS NOT NULL",
    )?;
    let mut rows = chains.query([])?;
    while let Some(row) = rows.next()? {
        let raw: String = row.get(0)?;
        let arch: Option<String> = row.get(1)?;
        let config = parse_config(Some(&raw));
        let inner = config
            .get("install_config")
            .filter(|value| value.is_object());
        if image.matches(inner.unwrap_or(&config), arch.as_deref()) {
            return Ok(false);
        }
    }
    image.key.available(http)?;
    Ok(true)
}

fn parse_config(raw: Option<&str>) -> Value {
    raw.and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default()
}

impl Image {
    fn matches(&self, config: &Value, arch: Option<&str>) -> bool {
        if arch.is_some_and(|arch| !arch.is_empty() && arch != self.key.arch) {
            return false;
        }
        let distro = php_string(&config["distro"]);
        let version = php_string(&config["version_full"]);
        !distro.is_empty()
            && (distro == self.key.distro
                || self.codename.as_deref() == Some(distro.as_str())
                || distro == self.key.version)
            && (version.is_empty()
                || self.key.version_full.as_deref() == Some(version.as_str())
                || version == self.key.version)
    }
}

impl ImageKey {
    fn available(&self, root: &Path) -> Result<bool, ErrorBox> {
        let mut path = root.join("netboot");
        let mut push = |component: &str| -> Result<(), ErrorBox> {
            if !component
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                || component.contains("..")
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err("Invalid netboot image path".into());
            }
            path.push(component);
            Ok(())
        };
        if let Some(version) = self
            .version_full
            .as_deref()
            .filter(|version| !version.is_empty())
        {
            push(&self.distro)?;
            push(version)?;
        } else {
            push(&self.version)?;
        }
        push(&self.arch)?;
        Ok(["linux", "initrd.gz"].iter().all(|name| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path.join(name))
                .and_then(|file| file.metadata())
                .is_ok_and(|info| info.is_file() && info.len() > 0)
        }))
    }
}
