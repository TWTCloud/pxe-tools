// SPDX-License-Identifier: LGPL-3.0-only

use super::DEBIAN_RELEASES;
use crate::{configured_database, connect, images::safe_netboot_component};
use rusqlite::{params, OpenFlags, TransactionBehavior};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fs::{self, Metadata},
    io::{self, ErrorKind},
    path::Path,
    process::Command,
};

type ErrorBox = Box<dyn Error + Send + Sync>;
const IMAGE_FILES: &[&str] = &["initrd.gz", "firmware.cpio.gz", "linux"];
const DEBIAN_MIRROR: &str = "https://deb.debian.org/debian";
const CANDIDATES: &str =
    "distro='debian' AND (extract_method='iso_extract' OR COALESCE(kernel_url,'')='')";

pub(crate) fn current_debian_images(config: &Path) -> Result<(), ErrorBox> {
    let path = configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    normalize_current_images(&mut db, current_release)
}

fn normalize_current_images(
    db: &mut rusqlite::Connection,
    current: impl Fn(u32, &'static str, Option<&'static str>) -> Option<String>,
) -> Result<(), ErrorBox> {
    let images = {
        let mut read = db.prepare(&format!(
            "SELECT id,arch,version_full FROM os_images WHERE {CANDIDATES} AND COALESCE(version_full,'')<>''"
        ))?;
        let rows = read.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut cache = HashMap::new();
    let mut updates = Vec::new();
    for (id, arch, version) in images {
        let arch = if arch.is_empty() || arch == "0" {
            "amd64"
        } else {
            &arch
        };
        if !matches!(arch, "amd64" | "arm64") {
            continue;
        }
        let Some(major) = version.split('.').next().and_then(|part| part.parse().ok()) else {
            continue;
        };
        let Some(&(_, codename, _, default)) =
            DEBIAN_RELEASES.iter().find(|release| release.0 == major)
        else {
            continue;
        };
        let release = cache
            .entry(major)
            .or_insert_with(|| current(major, codename, default));
        if release.as_deref() == Some(version.as_str()) {
            updates.push((id, arch.to_owned(), version, codename));
        }
    }
    if updates.is_empty() {
        return Ok(());
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut changed = 0;
    for (id, arch, version, codename) in updates {
        let installer = format!("{DEBIAN_MIRROR}/dists/{codename}/main/installer-{arch}/current/images/netboot/debian-installer/{arch}");
        let firmware = format!(
            "https://cdimage.debian.org/cdimage/firmware/{codename}/current/firmware.cpio.gz"
        );
        changed += tx.execute(
            &format!(
                "UPDATE os_images SET extract_method='direct',kernel_url=?1,initrd_url=?2,firmware_url=?3,
                 iso_url=NULL,status='pending',error_msg=NULL,progress_percent=0,updated_at=CURRENT_TIMESTAMP
                 WHERE id=?4 AND version_full=?5 AND (CASE arch WHEN '' THEN 'amd64' WHEN '0' THEN 'amd64' ELSE arch END)=?6
                 AND {CANDIDATES}"
            ),
            params![format!("{installer}/linux"), format!("{installer}/initrd.gz"), firmware, id, version, arch],
        )?;
    }
    if changed > 0 {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message)
             SELECT 'bootstrap:refresh_catalog_v2','pending','Refresh catalogue post-migration netboot Debian'
             WHERE NOT EXISTS(SELECT 1 FROM init_jobs WHERE job_type='bootstrap:refresh_catalog_v2' AND status IN ('pending','running'))",
            [],
        )?;
    }
    tx.commit()?;
    println!("Rust converted {changed} current Debian image(s) to direct netboot");
    Ok(())
}

fn current_release(major: u32, codename: &str, default: Option<&str>) -> Option<String> {
    let response = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--proto",
            "=https",
            "--max-time",
            "5",
            "--max-filesize",
            "2097152",
            &format!("{DEBIAN_MIRROR}/dists/{codename}/Release"),
        ])
        .output()
        .ok()
        .filter(|response| response.status.success());
    response
        .as_ref()
        .and_then(|output| std::str::from_utf8(&output.stdout).ok())
        .and_then(|release| release_version(release, major))
        .or_else(|| default.map(str::to_owned))
}

fn release_version(release: &str, major: u32) -> Option<String> {
    for line in release.lines() {
        let Some(version) = line.strip_prefix("Version:").map(str::trim) else {
            continue;
        };
        let fields: Vec<_> = version.split('.').collect();
        if matches!(fields.len(), 2 | 3)
            && fields
                .iter()
                .all(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return (fields[0].parse() == Ok(major)).then(|| {
                if fields.len() == 2 {
                    format!("{version}.0")
                } else {
                    version.to_owned()
                }
            });
        }
    }
    None
}

pub(crate) fn legacy_image_files(config: &Path, http: &Path) -> Result<(), ErrorBox> {
    let path = configured_database(config).ok_or("Existing SQLite database required")?;
    let netboot = http.join("netboot");
    let Some(root) = contained_path(&http.canonicalize()?, &netboot)? else {
        return Ok(());
    };
    let mut db = connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let images = {
        let mut statement = tx.prepare(
            "SELECT id,version,arch,status='pending' AND enabled=1
             FROM os_images ORDER BY arch='amd64' DESC,id",
        )?;
        let records = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        records.collect::<Result<Vec<_>, _>>()?
    };
    let mut downloaded = 0;
    let mut moved_versions = HashSet::new();
    for (id, version, arch, pending) in images {
        if !safe_netboot_component(&version) || !safe_netboot_component(&arch) {
            continue;
        }
        let Some(version_dir) = contained_path(&root, &root.join(version))? else {
            continue;
        };
        let destination = version_dir.join(arch);
        if moved_versions.insert(version_dir.clone()) {
            move_layout(&root, &version_dir, &destination)?;
        }
        if !pending || asset_size(&root, &destination.join("linux"))?.is_none() {
            continue;
        }
        let mut size = 0_u64;
        for name in IMAGE_FILES {
            size = size.saturating_add(asset_size(&root, &destination.join(name))?.unwrap_or(0));
        }
        tx.execute(
            "UPDATE os_images SET status='downloaded',downloaded_at=CURRENT_TIMESTAMP,size_bytes=?1
             WHERE id=?2",
            params![size, id],
        )?;
        downloaded += 1;
    }
    tx.commit()?;
    println!("Rust registered {downloaded} legacy netboot image(s) from disk");
    Ok(())
}

fn move_layout(root: &Path, version: &Path, destination: &Path) -> io::Result<()> {
    if regular_file(&version.join("linux"))?.is_none() {
        return Ok(());
    }
    if fs::symlink_metadata(destination).is_ok_and(|entry| entry.is_symlink()) {
        return Ok(());
    }
    if regular_file(&destination.join("linux"))?.is_some() {
        return Ok(());
    }
    fs::create_dir_all(destination)?;
    if contained_path(root, destination)?.is_none() {
        return Err(io::Error::other(
            "Legacy netboot destination escaped its root",
        ));
    }
    for name in IMAGE_FILES {
        let source = version.join(name);
        if regular_file(&source)?.is_some() {
            // Publish the kernel last so an interrupted move can finish on restart.
            rename_without_replacing(&source, &destination.join(name))?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_without_replacing(source: &Path, target: &Path) -> io::Result<()> {
    use std::ffi::CString;

    let source = CString::new(source.as_os_str().as_encoded_bytes())?;
    let target = CString::new(target.as_os_str().as_encoded_bytes())?;
    // Both C strings are NUL-terminated and remain valid for the call.
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_without_replacing(source: &Path, target: &Path) -> io::Result<()> {
    fs::hard_link(source, target)?;
    fs::remove_file(source)
}

fn regular_file(path: &Path) -> io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(entry) => Ok(entry.is_file().then_some(entry)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn contained_path(root: &Path, path: &Path) -> io::Result<Option<std::path::PathBuf>> {
    match path.canonicalize() {
        Ok(path) => Ok(path.starts_with(root).then_some(path)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn asset_size(root: &Path, path: &Path) -> io::Result<Option<u64>> {
    contained_path(root, path)?
        .map(|path| regular_file(&path).map(|metadata| metadata.map(|entry| entry.len())))
        .transpose()
        .map(Option::flatten)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_only_current_images_and_queues_catalog_once() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(super::super::SCHEMA).unwrap();
        db.execute_batch(
            "INSERT INTO os_images(distro,version,version_full,arch,extract_method,status,iso_url)
             VALUES ('debian','trixie','13.5.0','amd64','iso_extract','downloaded','old-iso'),
                    ('debian','trixie','13.5.0','arm64','iso_extract','failed','old-iso'),
                    ('debian','13.4.0','13.4.0','amd64','iso_extract','downloaded','archive'),
                    ('ubuntu','noble','24.04','amd64','iso_extract','downloaded','archive')",
        )
        .unwrap();
        for _ in 0..2 {
            normalize_current_images(&mut db, |_, _, version| version.map(str::to_owned)).unwrap();
        }
        let direct: i64 = db.query_row(
            "SELECT COUNT(*) FROM os_images WHERE extract_method='direct' AND status='pending'
             AND iso_url IS NULL AND kernel_url LIKE '%installer-' || arch || '/%/' || arch || '/linux'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(direct, 2);
        let archives: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM os_images WHERE iso_url='archive' AND status='downloaded'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(archives, 2);
        let refreshes: i64 = db.query_row(
            "SELECT COUNT(*) FROM init_jobs WHERE job_type='bootstrap:refresh_catalog_v2' AND status='pending'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(refreshes, 1);
    }

    #[test]
    fn parses_only_the_expected_debian_major() {
        assert_eq!(
            release_version("Suite: stable\nVersion: 13.7\n", 13).as_deref(),
            Some("13.7.0")
        );
        assert_eq!(
            release_version("Version: 13.7.1\n", 13).as_deref(),
            Some("13.7.1")
        );
        assert_eq!(release_version("Version: 12.14\n", 13), None);
        assert_eq!(release_version("Version: 13.7x\n", 13), None);
    }
}
