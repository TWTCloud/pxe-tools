// SPDX-License-Identifier: LGPL-3.0-only

use super::{page, plain, redirect, ErrorBox, Reply};
use crate::web::ui::ConsoleSection;
use crate::{connect, menu_store::Menus};
use hyper::{Method, StatusCode};
use rusqlite::{params, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(super) fn requested(method: &Method, form: &[u8]) -> bool {
    *method == Method::DELETE
        || form_urlencoded::parse(form).any(|(name, value)| name == "_method" && value == "DELETE")
}

pub(super) fn remove(
    path: &Path,
    id: i64,
    method: &Method,
    form: &[u8],
) -> Result<Reply, ErrorBox> {
    if *method != Method::DELETE {
        let fields = form_urlencoded::parse(form).collect::<Vec<_>>();
        if fields.len() != 2
            || !fields
                .iter()
                .any(|(name, value)| name == "_method" && value == "DELETE")
            || !fields
                .iter()
                .any(|(name, value)| name == "confirm" && value == "SUPPRIMER")
        {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Confirmez la suppression\n",
            ));
        }
    }
    match remove_selected(path, &[id]) {
        Ok(_) => Ok(redirect(StatusCode::SEE_OTHER, "/admin/devices")),
        Err(error) => Ok(conflict(error)),
    }
}

pub(super) fn bulk(path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut ids = Vec::new();
    let mut confirmed = false;
    let invalid = || {
        plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Sélection et confirmation requises\n",
        )
    };
    for (key, value) in form_urlencoded::parse(form) {
        match key.as_ref() {
            "machine_ids" | "machine_ids[]" => {
                let Ok(id) = value.parse::<i64>() else {
                    return Ok(invalid());
                };
                if id <= 0 {
                    return Ok(invalid());
                }
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            "confirm" if !confirmed && value == "SUPPRIMER" => confirmed = true,
            _ => return Ok(invalid()),
        }
    }
    if !confirmed || ids.is_empty() || ids.len() > 100 {
        return Ok(invalid());
    }
    match remove_selected(path, &ids) {
        Ok(result) => Ok(page(
            ConsoleSection::Devices,
            "Suppression par lots",
            &format!(
                r#"<p>{} appareil(s) supprimé(s), dont {} en cours d’opération. {} appareil(s) déjà absent(s).</p><a href="/admin/devices">Revenir aux appareils</a>"#,
                result.deleted,
                result.active,
                ids.len() - result.deleted,
            ),
        )),
        Err(error) => Ok(conflict(error)),
    }
}

struct Removal {
    deleted: usize,
    active: usize,
}

pub(super) fn in_progress(status: &str) -> bool {
    matches!(status, "wiping" | "installing" | "inventorying" | "testing")
}

fn conflict(error: ErrorBox) -> Reply {
    eprintln!("Rust PXE device removal: {error}");
    plain(
        StatusCode::CONFLICT,
        "Suppression des appareils interrompue\n",
    )
}

fn remove_selected(path: &Path, ids: &[i64]) -> Result<Removal, ErrorBox> {
    let menus = Menus::lock_configured()?;
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut targets = Vec::new();
    let mut result = Removal {
        deleted: 0,
        active: 0,
    };
    for id in ids {
        let device = tx
            .query_row("SELECT mac,status FROM machines WHERE id=?1", [id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .optional()?;
        let Some((mac, status)) = device else {
            continue;
        };
        targets.push(menus.path_for(&mac)?);
        if tx.execute(
            "DELETE FROM machines WHERE id=?1 AND mac=?2",
            params![id, mac],
        )? != 1
        {
            return Err("Appareil modifié pendant la suppression".into());
        }
        result.deleted += 1;
        if in_progress(&status) {
            result.active += 1;
        }
    }
    commit_with_menus(&targets, || {
        tx.commit()?;
        Ok(())
    })?;
    Ok(result)
}

fn stage(target: &Path) -> Result<Option<PathBuf>, ErrorBox> {
    match fs::symlink_metadata(target) {
        Ok(meta) => {
            if !meta.is_file() && !meta.is_symlink() {
                return Err("Type de fichier de menu inattendu".into());
            }
            let temporary =
                target.with_extension(format!("pending-delete-{}", crate::random_hex::<16>()?));
            if temporary.symlink_metadata().is_ok() {
                return Err("Nom temporaire du menu déjà présent".into());
            }
            fs::rename(target, &temporary)?;
            Ok(Some(temporary))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn commit_with_menus(
    targets: &[PathBuf],
    commit: impl FnOnce() -> Result<(), ErrorBox>,
) -> Result<(), ErrorBox> {
    let mut saved = Vec::new();
    let mut result = (|| {
        for target in targets {
            if let Some(temporary) = stage(target)? {
                saved.push((target, temporary));
            }
        }
        commit()
    })();
    for (target, temporary) in saved {
        if result.is_ok() {
            if let Err(error) = fs::remove_file(&temporary) {
                eprintln!(
                    "Rust PXE retained a detached menu at {}: {error}",
                    temporary.display()
                );
            }
        } else if target.symlink_metadata().is_ok() || fs::rename(&temporary, target).is_err() {
            eprintln!(
                "Restauration manuelle nécessaire depuis {}",
                temporary.display()
            );
            result = Err("Échec de la restauration d’un menu PXE".into());
        }
    }
    result
}
