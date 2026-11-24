// SPDX-License-Identifier: LGPL-3.0-only

use super::{plain, redirect, ErrorBox, Reply};
use crate::{connect, menu_store::Menus};
use hyper::{Method, StatusCode};
use rusqlite::{params, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{fs, io, path::Path};

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
    let menus = match Menus::lock_configured() {
        Ok(menus) => menus,
        Err(error) => {
            eprintln!("Rust PXE menu lock: {error}");
            return Ok(plain(
                StatusCode::CONFLICT,
                "Menus PXE indisponibles. Réessayez la suppression.\n",
            ));
        }
    };
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mac = tx
        .query_row("SELECT mac FROM machines WHERE id=?1", [id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    let Some(mac) = mac else {
        return Ok(redirect(StatusCode::SEE_OTHER, "/admin/devices"));
    };
    let target = menus.path_for(&mac)?;
    let result = stage(&target, || {
        if tx.execute(
            "DELETE FROM machines WHERE id=?1 AND mac=?2",
            params![id, mac],
        )? != 1
        {
            return Err("Appareil modifié pendant la suppression".into());
        }
        tx.commit()?;
        Ok(())
    });
    match result {
        Ok(()) => Ok(redirect(StatusCode::SEE_OTHER, "/admin/devices")),
        Err(error) => {
            eprintln!("Rust PXE device removal #{id}: {error}");
            Ok(plain(
                StatusCode::CONFLICT,
                "Suppression de l’appareil interrompue\n",
            ))
        }
    }
}

fn stage(target: &Path, commit: impl FnOnce() -> Result<(), ErrorBox>) -> Result<(), ErrorBox> {
    let saved = match fs::symlink_metadata(target) {
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
            Some(temporary)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let result = commit();
    if let Some(temporary) = saved {
        if result.is_ok() {
            if let Err(error) = fs::remove_file(&temporary) {
                eprintln!(
                    "Rust PXE retained a detached menu at {}: {error}",
                    temporary.display()
                );
            }
        } else if target.symlink_metadata().is_ok() || fs::rename(&temporary, target).is_err() {
            return Err(format!(
                "Restauration manuelle nécessaire depuis {}",
                temporary.display()
            )
            .into());
        }
    }
    result
}
