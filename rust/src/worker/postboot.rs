// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, postboot, setting};
use rusqlite::{params, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    error::Error,
    fs,
    io::{self, Write},
    os::unix::fs::{chown, fchown, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

type ErrorBox = Box<dyn Error + Send + Sync>;

pub(crate) fn run(
    database: &Path,
    id: i64,
    templates: &Path,
    output: &Path,
) -> Result<(), ErrorBox> {
    if id <= 0
        || ![database, templates, output]
            .iter()
            .all(|path| path.is_absolute())
    {
        return Err("Expected a positive job ID and absolute postboot paths".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let kind: Option<String> = tx
        .query_row(
            "SELECT job_type FROM init_jobs WHERE id=?1 AND status='pending'",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(kind) = kind else {
        return Ok(());
    };
    let action = kind
        .strip_prefix("action:render_postboot:")
        .ok_or("Unsupported postboot job")?
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0);
    tx.execute(
        "UPDATE init_jobs SET status='running',started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        [id],
    )?;
    let target: Option<(i64, String, String)> = tx.query_row(
        "SELECT a.id,a.token,m.mac FROM actions a JOIN machines m ON m.id=a.machine_id
         WHERE a.id=?1 AND a.type IN ('install_only','reinstall') AND a.status IN ('pending','running')",
        [action], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let result = if let Some((action, token, mac)) = target {
        if let Ok(pxe_ip) = setting(&tx, "pxe_ip")?.parse() {
            let context = postboot::Context { pxe_ip, token, mac };
            match postboot::rendered(templates, &context) {
                Ok(rendered) => publish(output, action, rendered)
                    .map(|_| {
                        format!(
                            "Postboot rendu dans {}",
                            output.join(action.to_string()).display()
                        )
                    })
                    .map_err(|_| "Écriture des fichiers postboot impossible"),
                Err(_) => Err("Paramètres ou modèles postboot invalides"),
            }
        } else {
            Err("Adresse PXE indisponible")
        }
    } else {
        Err("Action d’installation introuvable ou clôturée")
    };
    let (status, message) = match result {
        Ok(message) => ("success", message),
        Err(error) => ("failed", error.to_owned()),
    };
    tx.execute(
        "UPDATE init_jobs SET status=?2,message=?3,ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
         WHERE id=?1 AND status='running'",
        params![id,status,message],
    )?;
    tx.commit()?;
    Ok(())
}

fn publish(root: &Path, action: i64, rendered: postboot::Postboot) -> io::Result<()> {
    let gid = web_group();
    create_directory(root, gid)?;
    let folder = root.join(action.to_string());
    create_directory(&folder, gid)?;

    for (name, body) in [
        ("postboot.sh", rendered.script),
        ("pxe-postboot.service", rendered.service),
    ] {
        let staging = folder.join(format!(".{name}.{}", crate::random_hex::<16>()?));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?;
        let result = (|| {
            if let Some(gid) = gid {
                fchown(&file, None, Some(gid))?;
            }
            file.write_all(body.as_bytes())?;
            file.set_permissions(fs::Permissions::from_mode(0o640))?;
            fs::rename(&staging, folder.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging);
            return result;
        }
    }
    Ok(())
}

fn create_directory(path: &Path, web: Option<u32>) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o750).create(path) {
        Ok(()) => {
            if let Some(gid) = web {
                chown(path, None, Some(gid))?;
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unsafe postboot directory",
        ));
    }
    Ok(())
}

fn web_group() -> Option<u32> {
    if unsafe { libc::geteuid() } == 0 {
        // The worker subcommand is single threaded and reads but never mutates
        // the libc group record.
        unsafe { libc::getgrnam(c"www-data".as_ptr()).as_ref() }.map(|group| group.gr_gid)
    } else {
        None
    }
}
