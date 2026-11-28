// SPDX-License-Identifier: LGPL-3.0-only

use super::storage::{descriptor_path, directory, invalid};
use crate::menu_store::Menus;
use rusqlite::Connection;
use std::{
    fs::{self, File},
    io,
    path::Path,
    process::Command,
};

pub(crate) const JOB: &str = "system:factory_reset_wipe";

pub(crate) fn pending(db: &Connection) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running'))",
        [JOB],
        |row| row.get(0),
    )
}

pub(super) fn wipe(http: &Path, tftp: &Path, mok: &Path, scripts: &Path) -> io::Result<()> {
    if !http.is_absolute()
        || !tftp.is_absolute()
        || !mok.is_absolute()
        || [http, tftp, mok].contains(&Path::new("/"))
        || [(http, tftp), (http, mok), (tftp, mok)]
            .iter()
            .any(|(first, second)| first.starts_with(second) || second.starts_with(first))
    {
        return Err(invalid(
            "Les répertoires PXE doivent être distincts et absolus",
        ));
    }
    let netboot = http.join("netboot");
    let profiles = http.join(crate::boot_networks::DIRECTORY);
    let _menus = Menus::lock_all(tftp)?;
    let transfer = directory(tftp, true)?.ok_or_else(|| invalid("Racine TFTP indisponible"))?;
    let bios_menus = directory(&tftp.join("pxelinux.cfg"), true)?
        .ok_or_else(|| invalid("Répertoire des menus PXE indisponible"))?;
    let images = directory(&netboot, true)?;
    let scripts_by_network = directory(&profiles, true)?;
    let keys = directory(mok, true)?;
    for root in [tftp, &netboot, &profiles, mok] {
        refuse_submounts(root)?;
    }

    // Wait for the product's normal network shutdown before removing boot files.
    let off = Command::new("/bin/bash")
        .arg(scripts.join("bootstrap-restart-dnsmasq.sh"))
        .status()?;
    if !off.success() {
        return Err(invalid("Arrêt des services PXE non confirmé"));
    }
    clear_directory(&transfer, &[".pxe-menu.lock", "pxelinux.cfg"])?;
    clear_directory(&bios_menus, &[])?;
    for directory in [images, scripts_by_network, keys].into_iter().flatten() {
        clear_directory(&directory, &[])?;
    }
    Ok(())
}

fn refuse_submounts(path: &Path) -> io::Result<()> {
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let target = line
            .split_ascii_whitespace()
            .nth(4)
            .ok_or_else(|| invalid("Table des montages illisible"))?
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\");
        let target = Path::new(&target);
        if target != path && target.starts_with(path) {
            return Err(invalid("Un montage imbriqué occupe le stockage PXE"));
        }
    }
    Ok(())
}

fn clear_directory(directory: &File, keep: &[&str]) -> io::Result<()> {
    for entry in fs::read_dir(descriptor_path(directory))? {
        let entry = entry?;
        if keep.iter().any(|name| entry.file_name() == *name) {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    directory.sync_all()?;
    Ok(())
}
