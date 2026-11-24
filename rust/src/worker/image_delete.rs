// SPDX-License-Identifier: LGPL-3.0-only

use super::storage;
use crate::{connect, images::ImageKey};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type ErrorBox = Box<dyn Error + Send + Sync>;
const FILES: [&str; 3] = ["linux", "initrd.gz", "firmware.cpio.gz"];

pub(super) fn run(database: &Path, job: i64, kind: &str, http: &Path) -> Result<(), ErrorBox> {
    let id: i64 = kind
        .strip_prefix("image:delete:")
        .ok_or("Type de tâche de suppression invalide")?
        .parse()?;
    if id <= 0 || kind != format!("image:delete:{id}") {
        return Err("Identifiant d’image invalide".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let snapshot: Option<String> = tx
        .query_row(
            "SELECT log FROM init_jobs WHERE id=?1 AND job_type=?2 AND status='pending'",
            params![job, kind],
            |row| row.get(0),
        )
        .optional()?;
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let key = ImageKey::from_deletion(&snapshot, id)?;
    tx.execute(
        "UPDATE init_jobs SET status='running',started_at=CURRENT_TIMESTAMP,
         updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        [job],
    )?;
    tx.commit()?;

    trusted_http_root(http)?;
    let image = key.path(http)?;
    if image
        .strip_prefix(http)?
        .components()
        .any(|part| part.as_os_str().len() > 128)
    {
        return Err("Chemin de l’image trop long".into());
    }
    let directory = storage::directory(&image, false)?;
    let files = directory
        .as_ref()
        .map(|directory| ImageFiles::new(directory, job));
    if let Err(error) = remove_image(&db, database, id, job, http, &key, files.as_ref()) {
        if key.current(&db).is_ok_and(|matched| matched.is_some()) {
            if let Some(files) = files.as_ref() {
                if let Err(restore_error) = files.restore() {
                    eprintln!("Rust image deletion #{job} restoration: {restore_error}");
                }
            }
        }
        return Err(error);
    }
    db.execute(
        "UPDATE init_jobs SET status='success', message='Image et fichiers locaux supprimés.',
         progress_percent=100, ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        [job],
    )?;
    Ok(())
}

fn trusted_http_root(http: &Path) -> Result<(), ErrorBox> {
    // The installed worker owns the on-disk assets. The SQLite reservation
    // runs with the web account, which cannot write these directories.
    if unsafe { libc::geteuid() } != 0 {
        return Err("Suppression réservée au worker de l’instance".into());
    }
    match env::var("PXE_SERVICE_MANAGER").as_deref() {
        Ok("systemd") => {
            let base = storage::directory(Path::new("/var/lib/pxe-tools-native"), false)?
                .ok_or("Configuration native protégée introuvable")?;
            let marker = storage::marker(&base, "runtime.env")?;
            let mut values = marker
                .split(|byte| *byte == b'\n')
                .filter_map(|line| line.strip_prefix(b"HTTP_ROOT="));
            if values.next() != Some(http.as_os_str().as_encoded_bytes()) || values.next().is_some()
            {
                return Err("La racine HTTP diffère de la configuration native".into());
            }
        }
        Ok("s6") if http == Path::new("/srv/http") && Path::new("/.dockerenv").is_file() => {
            let root = storage::directory(http, false)?.ok_or("Racine HTTP Docker absente")?;
            if storage::marker(&root, ".pxe-netboot-root-v1")? != b"pxe-netboot-root-v1\n" {
                return Err("Marqueur HTTP Docker invalide".into());
            }
            for name in ["netboot", "static-bin"] {
                storage::directory(&http.join(name), false)?
                    .ok_or("Répertoire de démarrage Docker absent")?;
            }
        }
        _ => return Err("Superviseur ou racine HTTP non pris en charge".into()),
    }
    Ok(())
}

fn remove_image(
    db: &Connection,
    database: &Path,
    id: i64,
    job: i64,
    http: &Path,
    key: &ImageKey,
    files: Option<&ImageFiles<'_>>,
) -> Result<(), ErrorBox> {
    match key.current(db)? {
        Some(false) => return Err("L’image a changé depuis la demande".into()),
        None => {}
        Some(true) => {
            if let Some(files) = files {
                files.restore()?;
            }
            reserve(database, id, job, http, files)?;
            if key.current(db)?.is_some() {
                return Err("La base n’a pas confirmé la suppression de l’image".into());
            }
        }
    }
    if let Some(files) = files {
        files.cleanup()?;
    }
    Ok(())
}

fn reserve(
    database: &Path,
    id: i64,
    job: i64,
    http: &Path,
    files: Option<&ImageFiles<'_>>,
) -> Result<(), ErrorBox> {
    let (mut control, peer) = UnixStream::pair()?;
    let reader = peer.try_clone()?;
    control.set_read_timeout(Some(Duration::from_secs(15)))?;
    control.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut invocation = Command::new("/usr/bin/setpriv");
    invocation
        .args([
            "--reuid=www-data",
            "--regid=www-data",
            "--clear-groups",
            "--no-new-privs",
            "--",
        ])
        .arg(env::current_exe()?)
        .arg("--reserve-image-deletion")
        .arg(id.to_string())
        .arg(job.to_string())
        .arg(database)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("PXE_HTTP_ROOT", http)
        .stdin(Stdio::from(OwnedFd::from(reader)))
        .stdout(Stdio::from(OwnedFd::from(peer)))
        .stderr(Stdio::null());
    let mut child = invocation.spawn()?;
    drop(invocation);
    let result = (|| {
        signal(&mut control, b"READY\n")?;
        if let Some(files) = files {
            files.stage()?;
        }
        control.write_all(b"COMMIT\n")?;
        control.shutdown(Shutdown::Write)?;
        signal(&mut control, b"COMMITTED\n")?;
        wait(&mut child)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn signal<const N: usize>(control: &mut UnixStream, expected: &[u8; N]) -> Result<(), ErrorBox> {
    let mut reply = [0u8; N];
    control.read_exact(&mut reply)?;
    if &reply != expected {
        return Err("Réponse de réservation invalide".into());
    }
    Ok(())
}

fn wait(child: &mut Child) -> Result<(), ErrorBox> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err("Réservation interrompue".into())
            };
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("La réservation ne s’est pas terminée".into())
}

struct ImageFiles<'a> {
    directory: &'a File,
    files: [(PathBuf, PathBuf); FILES.len()],
}

impl<'a> ImageFiles<'a> {
    fn new(directory: &'a File, job: i64) -> Self {
        let root = storage::descriptor_path(directory);
        Self {
            directory,
            files: FILES.map(|name| {
                (
                    root.join(name),
                    root.join(format!("{name}.pxe-delete-{job}")),
                )
            }),
        }
    }

    fn restore(&self) -> io::Result<()> {
        let entries = self.entries()?;
        if entries.contains(&(true, true)) {
            return Err(storage::invalid("Fichier et réserve présents ensemble"));
        }
        for ((target, staged), (_, reserved)) in self.files.iter().zip(entries) {
            if reserved {
                fs::rename(staged, target)?;
            }
        }
        self.directory.sync_all()
    }

    fn stage(&self) -> io::Result<()> {
        let entries = self.entries()?;
        if entries.iter().any(|(_, staged)| *staged) {
            return Err(storage::invalid("Une réserve existe déjà pour cette image"));
        }
        for ((target, staged), (present, _)) in self.files.iter().zip(entries) {
            if present {
                fs::rename(target, staged)?;
            }
        }
        self.directory.sync_all()
    }

    fn cleanup(&self) -> io::Result<()> {
        for ((_, staged), (_, reserved)) in self.files.iter().zip(self.entries()?) {
            if reserved {
                fs::remove_file(staged)?;
            }
        }
        self.directory.sync_all()
    }

    fn entries(&self) -> io::Result<Vec<(bool, bool)>> {
        self.files
            .iter()
            .map(|(original, staged)| Ok((exists(original)?, exists(staged)?)))
            .collect()
    }
}

fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(info) if storage::protected_file(&info) => Ok(true),
        Ok(_) => Err(storage::invalid("Artefact d’image non protégé")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
