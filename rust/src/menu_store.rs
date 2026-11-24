// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::HashSet,
    env,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Menus {
    _lock: File,
    directory: PathBuf,
}

impl Menus {
    pub(crate) fn lock_configured() -> io::Result<Self> {
        let root = env::var_os("TFTP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/srv/tftp".into());
        Self::lock(&root)
    }

    pub(crate) fn lock(root: &Path) -> io::Result<Self> {
        if !root.is_absolute() || root == Path::new("/") {
            return Err(invalid("The TFTP root must be a protected directory"));
        }
        let mut path = PathBuf::new();
        let mut components = root.components().peekable();
        while let Some(component) = components.next() {
            if !matches!(component, Component::RootDir | Component::Normal(_)) {
                return Err(invalid("Invalid TFTP path component"));
            }
            path.push(component);
            let info = fs::symlink_metadata(&path)?;
            let sticky = components.peek().is_some() && info.mode() & 0o1000 != 0;
            if !info.is_dir() || info.uid() != 0 || (info.mode() & 0o022 != 0 && !sticky) {
                return Err(invalid("Untrusted TFTP directory"));
            }
        }
        let directory = root.join("pxelinux.cfg");
        let info = fs::symlink_metadata(&directory)?;
        if !info.is_dir() || info.uid() != 0 || info.mode() & 0o002 != 0 {
            return Err(invalid("Untrusted MAC menu directory"));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join(".pxe-menu.lock"))?;
        let info = file.metadata()?;
        if !info.is_file() || info.uid() != 0 || info.nlink() != 1 || info.mode() & 0o002 != 0 {
            return Err(invalid("Untrusted MAC menu lock"));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            // The renderer uses flock on the same protected inode.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self {
                    _lock: file,
                    directory,
                });
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PXE menus are busy",
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub(crate) fn path_for(&self, mac: &str) -> io::Result<PathBuf> {
        let raw = mac.trim().to_ascii_lowercase();
        let canonical =
            crate::pxe::normalize_mac(&raw).ok_or_else(|| invalid("Invalid MAC address"))?;
        let hyphenated = canonical.replace(':', "-");
        if raw != canonical && raw != hyphenated && raw != canonical.replace(':', "") {
            return Err(invalid("Invalid MAC address"));
        }
        Ok(self.directory.join(format!("01-{hyphenated}")))
    }

    pub(crate) fn remove_obsolete<'a>(
        &self,
        retained_macs: impl IntoIterator<Item = &'a str>,
    ) -> io::Result<usize> {
        let retained: HashSet<_> = retained_macs
            .into_iter()
            .filter_map(|mac| self.path_for(mac).ok())
            .collect();
        let mut removed = 0;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.file_name().as_encoded_bytes().starts_with(b"01-")
                && !retained.contains(&entry.path())
            {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
