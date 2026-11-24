// SPDX-License-Identifier: LGPL-3.0-only

use crate::menu_store::Menus;
use rusqlite::Connection;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
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
    let _menus = Menus::lock(tftp)?;
    let transfer = protected(tftp)?.ok_or_else(|| invalid("Racine TFTP indisponible"))?;
    let bios_menus = protected(&tftp.join("pxelinux.cfg"))?
        .ok_or_else(|| invalid("Répertoire des menus PXE indisponible"))?;
    let images = protected(&netboot)?;
    let keys = protected(mok)?;
    for root in [tftp, &netboot, mok] {
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
    if let Some(images) = images {
        clear_directory(&images, &[])?;
    }
    if let Some(keys) = keys {
        clear_directory(&keys, &[])?;
    }
    Ok(())
}

fn descriptor_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn protected(path: &Path) -> io::Result<Option<File>> {
    let mut directory = File::open("/")?;
    let mut walked = PathBuf::from("/");
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err(invalid("Composant de chemin PXE invalide"));
        };
        walked.push(name);
        directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(descriptor_path(&directory).join(name))
        {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let info = directory.metadata()?;
        let shared_config = walked == Path::new("/etc/pxe-tools") && info.mode() & 0o002 == 0;
        let shared_menus = name == "pxelinux.cfg" && walked == path && info.mode() & 0o002 == 0;
        if info.uid() != 0 || (info.mode() & 0o022 != 0 && !shared_config && !shared_menus) {
            return Err(invalid("Répertoire PXE insuffisamment protégé"));
        }
    }
    Ok(Some(directory))
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

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
