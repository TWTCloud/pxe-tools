// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, php_string};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, BufRead, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageKey {
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

impl Image {
    fn get(db: &Connection, id: i64) -> rusqlite::Result<Option<Self>> {
        db.query_row(
            "SELECT id,distro,version,version_full,arch,codename,extract_method,status,enabled
             FROM os_images WHERE id=?1",
            [id],
            |row| {
                Ok(Self {
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
        )
        .optional()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Change {
    Enable(Option<bool>),
    Download,
    Delete,
}

pub(crate) enum Changed {
    Updated,
    Unavailable,
    Blocked(BlockReason),
    Queued(i64),
}

pub(crate) enum BlockReason {
    Transfer,
    InUse,
    Rescue,
    Deleting,
}

pub(crate) fn change(db: &Connection, id: i64, requested: Change) -> Result<Changed, ErrorBox> {
    let Some(image) = Image::get(db, id)? else {
        return Ok(Changed::Unavailable);
    };
    let name = format!("image:delete:{id}");
    let existing = db.query_row(
        "SELECT id FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running') LIMIT 1",
        [&name], |row| row.get::<_,i64>(0),
    ).optional()?;
    if let Some(job) = existing {
        return Ok(if matches!(requested, Change::Delete) {
            Changed::Queued(job)
        } else {
            Changed::Blocked(BlockReason::Deleting)
        });
    }
    let http = http_root()?;
    image.key.path(&http)?;
    let transfer_active = transferring(&image);
    let active = active_operations(db, &image)?;
    let last_rescue = last_rescue_image(db, &image, &http)?;
    let reason = if transfer_active {
        Some(BlockReason::Transfer)
    } else if active {
        Some(BlockReason::InUse)
    } else if last_rescue {
        Some(BlockReason::Rescue)
    } else {
        None
    };
    match requested {
        Change::Enable(enabled) => {
            let enabled = enabled.unwrap_or(!image.enabled);
            let requeue = enabled && matches!(image.status.as_str(), "pending" | "failed");
            if !enabled {
                if let Some(reason) = reason {
                    return Ok(Changed::Blocked(reason));
                }
            } else if requeue && active {
                return Ok(Changed::Blocked(BlockReason::InUse));
            }
            db.execute(
                "UPDATE os_images SET enabled=?2,
                        status=CASE WHEN ?3 THEN 'pending' ELSE status END,
                        error_msg=CASE WHEN ?3 THEN NULL ELSE error_msg END WHERE id=?1",
                params![id, enabled, requeue],
            )?;
        }
        Change::Download => {
            if let Some(reason) = reason {
                return Ok(Changed::Blocked(reason));
            }
            db.execute(
                "UPDATE os_images SET enabled=1,status='pending',error_msg=NULL WHERE id=?1",
                [id],
            )?;
        }
        Change::Delete => {
            if let Some(reason) = reason {
                return Ok(Changed::Blocked(reason));
            }
            db.execute(
                "INSERT INTO init_jobs(job_type,status,message,log)
                        VALUES(?1,'pending','Suppression de l’image en attente',?2)",
                params![name, serde_json::to_string(&image.key)?],
            )?;
            return Ok(Changed::Queued(db.last_insert_rowid()));
        }
    }
    Ok(Changed::Updated)
}

pub(crate) fn is_last_rescue(db: &Connection, id: i64) -> Result<bool, ErrorBox> {
    match Image::get(db, id)? {
        Some(image) => last_rescue_image(db, &image, &http_root()?),
        None => Ok(false),
    }
}

fn http_root() -> Result<PathBuf, ErrorBox> {
    let http = std::env::var_os("PXE_HTTP_ROOT")
        .filter(|root| !root.is_empty())
        .or_else(|| std::env::var_os("HTTP_ROOT").filter(|root| !root.is_empty()))
        .map(PathBuf::from)
        .ok_or("Missing HTTP root")?;
    if !http.is_absolute() {
        return Err("Invalid HTTP root".into());
    }
    Ok(http)
}

pub(super) fn reserve_deletion(path: &Path, image_id: i64, job_id: i64) -> Result<(), ErrorBox> {
    // These calls read the identity of this process.
    if unsafe { libc::geteuid() == 0 || libc::getegid() == 0 }
        || image_id <= 0
        || job_id <= 0
        || !path.is_absolute()
    {
        return Err("Invalid image deletion request".into());
    }
    let http = http_root()?;
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    // BEGIN IMMEDIATE reserves writes before the first snapshot read, including
    // changes to replacements and assignments while the parent stages files.
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let image = Image::get(&transaction, image_id)?.ok_or("Image unavailable")?;
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
    image.key.path(http)?;
    Ok(!transferring(image)
        && !last_rescue_image(db, image, http)?
        && !active_operations(db, image)?)
}

fn transferring(image: &Image) -> bool {
    image.status == "downloading" || (image.status == "pending" && image.enabled)
}

fn last_rescue_image(db: &Connection, image: &Image, http: &Path) -> Result<bool, ErrorBox> {
    let base = image.key.distro == "debian" && image.extract_method == "direct";
    if base
        && image.enabled
        && image.status == "downloaded"
        && !crate::alpine::menus_ready(db)?
        && image.key.available(http)?
    {
        let mut replacements = db.prepare(
            "SELECT id,distro,version,version_full,arch FROM os_images
             WHERE distro='debian' AND arch=? AND extract_method='direct'
             AND id<>? AND enabled=1 AND status='downloaded'",
        )?;
        let mut rows = replacements.query(params![image.key.arch, image.key.id])?;
        while let Some(row) = rows.next()? {
            let candidate = ImageKey {
                id: row.get(0)?,
                distro: row.get(1)?,
                version: row.get(2)?,
                version_full: row.get(3)?,
                arch: row.get(4)?,
            };
            if candidate.available(http)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    Ok(false)
}

fn active_operations(db: &Connection, image: &Image) -> Result<bool, ErrorBox> {
    let base = image.key.distro == "debian" && image.extract_method == "direct";
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
            return Ok(true);
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
            return Ok(true);
        }
    }
    Ok(false)
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
    pub(crate) fn from_deletion(raw: &str, id: i64) -> Result<Self, ErrorBox> {
        let key: Self = serde_json::from_str(raw)?;
        if id <= 0 || key.id != id {
            return Err("Identifiant d’image invalide".into());
        }
        Ok(key)
    }

    pub(crate) fn current(&self, db: &Connection) -> rusqlite::Result<Option<bool>> {
        Ok(Image::get(db, self.id)?.map(|image| image.key == *self))
    }

    pub(crate) fn path(&self, root: &Path) -> Result<PathBuf, ErrorBox> {
        let mut path = root.join("netboot");
        let mut push = |component: &str| -> Result<(), ErrorBox> {
            if !safe_netboot_component(component) {
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
        Ok(path)
    }

    fn available(&self, root: &Path) -> Result<bool, ErrorBox> {
        let path = self.path(root)?;
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

pub(crate) fn safe_netboot_component(component: &str) -> bool {
    component
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && !component.contains("..")
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}
