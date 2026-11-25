// SPDX-License-Identifier: LGPL-3.0-only

use crate::connect;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{error::Error, path::Path, process::Command};

type ErrorBox = Box<dyn Error + Send + Sync>;

pub(crate) fn run(database: &Path, id: i64, scripts: &Path) -> Result<(), ErrorBox> {
    if !database.is_absolute() || !scripts.is_absolute() || id <= 0 {
        return Err("Expected a positive image ID and absolute worker paths".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let image = tx
        .query_row(
            "SELECT distro, COALESCE(version_full,version), arch, COALESCE(extract_method,'direct')
         FROM os_images WHERE id=?1 AND enabled=1 AND status='pending'",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((distro, version, arch, method)) = image else {
        return Ok(());
    };
    if crate::catalog::rpm_label(&distro).is_some() {
        let Some(repo) =
            crate::catalog::rpm_repository(&distro, &version, &arch).filter(|_| method == "direct")
        else {
            fail(
                &tx,
                id,
                "pending",
                "Version ou architecture RPM indisponible",
            )?;
            tx.commit()?;
            return Ok(());
        };
        tx.execute(
            "UPDATE os_images SET kernel_url=?2, initrd_url=?3, firmware_url=NULL WHERE id=?1",
            params![
                id,
                format!("{repo}/images/pxeboot/vmlinuz"),
                format!("{repo}/images/pxeboot/initrd.img")
            ],
        )?;
    }
    let label = format!("{distro} {version} {arch}");
    let name = if method.eq_ignore_ascii_case("iso_extract") {
        "bootstrap-download-image-iso.sh"
    } else {
        "bootstrap-download-image.sh"
    };
    let script = scripts.join(name);
    if !script.is_file() {
        fail(
            &tx,
            id,
            "pending",
            &format!("Script introuvable : {}", script.display()),
        )?;
        tx.commit()?;
        return Ok(());
    }
    tx.execute(
        "UPDATE os_images SET status='downloading', message=?2, progress_percent=0,
             error_msg=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        params![id, format!("{label} · initialisation…")],
    )?;
    tx.commit()?;

    // The download helpers publish a verified image and its database metadata
    // together. Their output goes to the service log.
    println!("[worker:image:{id}] {label} · téléchargement");
    let result = Command::new("/bin/bash")
        .arg(&script)
        .env("IMAGE_ID", id.to_string())
        .status();
    let exit = match result {
        Ok(status) if status.success() => {
            // A successful helper must have published the new database state.
            // Preserve a verified old image when the helper leaves one in place.
            let published = db.execute(
                "UPDATE os_images SET updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status='downloaded'",
                [id],
            )?;
            if published == 1 {
                println!("[worker:image:{id}] {label} → downloaded");
            } else {
                let error = "Le script n’a pas publié l’image";
                if fail(&db, id, "downloading", error)? == 1 {
                    println!("[worker:image:{id}] {label} → failed ({error})");
                }
            }
            return Ok(());
        }
        Ok(status) => format!(
            "Script exit code {}",
            status
                .code()
                .map_or_else(|| status.to_string(), |code| code.to_string())
        ),
        Err(error) => format!("Échec lancement : {error}"),
    };
    fail(&db, id, "downloading", &exit)?;
    println!("[worker:image:{id}] {label} → failed ({exit})");
    Ok(())
}

fn fail(db: &Connection, id: i64, expected: &str, error: &str) -> rusqlite::Result<usize> {
    db.execute(
        "UPDATE os_images SET status='failed', error_msg=?3, updated_at=CURRENT_TIMESTAMP
                WHERE id=?1 AND status=?2",
        params![id, expected, error],
    )
}
