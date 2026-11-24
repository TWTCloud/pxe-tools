// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub(super) fn descriptor_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

pub(super) fn directory(path: &Path, allow_pxe_shared: bool) -> io::Result<Option<File>> {
    if !path.is_absolute() {
        return Err(invalid("Le répertoire PXE doit être absolu"));
    }
    let mut directory = File::open("/")?;
    let root = directory.metadata()?;
    if root.uid() != 0 || root.mode() & 0o022 != 0 {
        return Err(invalid("Racine du système de fichiers non protégée"));
    }
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
        let shared = allow_pxe_shared
            && info.mode() & 0o002 == 0
            && (walked == Path::new("/etc/pxe-tools")
                || (name == "pxelinux.cfg" && walked == path));
        if info.uid() != 0 || (info.mode() & 0o022 != 0 && !shared) {
            return Err(invalid("Répertoire PXE insuffisamment protégé"));
        }
    }
    Ok(Some(directory))
}

pub(super) fn marker(directory: &File, name: &str) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(descriptor_path(directory).join(name))?;
    let info = file.metadata()?;
    if !protected_file(&info) || info.len() > 4096 {
        return Err(invalid("Marqueur PXE invalide"));
    }
    let mut content = Vec::new();
    file.take(4097).read_to_end(&mut content)?;
    if content.len() as u64 != info.len() {
        return Err(invalid("Le marqueur PXE a changé pendant la lecture"));
    }
    Ok(content)
}

pub(super) fn protected_file(info: &fs::Metadata) -> bool {
    info.is_file() && info.nlink() == 1 && info.uid() == 0 && info.mode() & 0o022 == 0
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
