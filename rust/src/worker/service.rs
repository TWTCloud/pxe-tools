// SPDX-License-Identifier: LGPL-3.0-only

use super::{ansible, bootstrap, download, postboot, power, schedule};
use crate::{configured_database, connect, setting};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

type ErrorBox = Box<dyn Error + Send + Sync>;

struct Worker<'a> {
    config: &'a Path,
    helper: &'a Path,
    scripts: PathBuf,
    templates: PathBuf,
    postboot: PathBuf,
    tftp: PathBuf,
    workspace: PathBuf,
    unlock: PathBuf,
}

fn directory(key: &str, default: &str) -> PathBuf {
    env::var_os(key).map_or_else(|| default.into(), PathBuf::from)
}

pub(crate) fn run(config: &Path, helper: &Path) -> Result<(), ErrorBox> {
    if !config.is_absolute() || !helper.is_absolute() {
        return Err("Expected absolute worker configuration and helper paths".into());
    }
    let worker = Worker {
        config,
        helper,
        scripts: directory("BOOTSTRAP_SCRIPTS_DIR", "/opt/pxe-tools/scripts"),
        templates: directory("BOOTSTRAP_TEMPLATES_DIR", "/opt/pxe-tools/templates"),
        postboot: directory("POSTBOOT_OUTPUT_DIR", "/var/lib/pxe-tools/postboot"),
        tftp: directory("TFTP_ROOT", "/srv/tftp"),
        workspace: directory("ANSIBLE_WORKDIR", "/home/ansible/ansible"),
        unlock: directory("PXE_VAULT_UNLOCK_DIR", "/dev/shm/pxe-vault").join("unlock"),
    };
    let pause = Duration::from_secs(
        env::var("WORKER_POLL_S")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|seconds| *seconds > 0)
            .unwrap_or(5),
    );
    worker.python("clean-vault", None, None)?;
    println!("[worker] Rust attend la base SQLite et son schéma");
    let database = loop {
        if let Some(database) = configured_database(config).filter(|path| schema_ready(path)) {
            break database;
        }
        thread::sleep(pause);
    };
    super::recover(&database)?;
    enqueue_initial(&database, &worker.tftp)?;
    println!("[worker] Boucle Rust active");
    let mut last_runtime = None;
    let mut last_catalog = None;
    let mut last_presets = None;
    let mut workspace_ready = false;
    let mut paused = false;
    loop {
        if configured_database(config).as_ref() != Some(&database) {
            if !paused {
                eprintln!("[worker] Configuration SQLite modifiée. Redémarrez après vérification.");
                paused = true;
            }
            thread::sleep(pause);
            continue;
        }
        paused = false;
        let work = (|| -> Result<bool, ErrorBox> {
            let db = open(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let ansible_enabled = setting(&db, "ansible_enabled")? == "on";
            if ansible_enabled && !workspace_ready {
                if let Err(error) = worker.python("startup", Some(&database), None) {
                    eprintln!("[worker] Préparation de l’espace de travail Ansible : {error}");
                }
                workspace_ready = true;
            }
            if !ansible_enabled {
                workspace_ready = false;
            }
            if due(&mut last_runtime, 60) {
                worker.runtime(&database)?;
            }
            if due(&mut last_catalog, 60) {
                schedule::run(&database, "catalog", &worker.workspace)?;
            }
            if ansible_enabled && due(&mut last_presets, 300) {
                schedule::run(&database, "presets", &worker.workspace)?;
            }
            let unlocked = worker.unlock.is_file();
            if let Some((id, kind)) = next_init(&db, ansible_enabled && !unlocked)? {
                println!("[worker] Tâche #{id} ({kind})");
                if let Err(error) = worker.dispatch(&database, id, &kind, ansible_enabled) {
                    eprintln!("[worker] La tâche #{id} a échoué : {error}");
                    fail_job(&database, id, "Exécution du worker interrompue.")?;
                }
                return Ok(true);
            }
            if let Some(image) = db.query_row(
                "SELECT id FROM os_images WHERE enabled=1 AND status='pending' ORDER BY id LIMIT 1",
                [], |row| row.get::<_, i64>(0),
            ).optional()? {
                if let Err(error) = download::run(&database, image, &worker.scripts) {
                    eprintln!("[worker] Le téléchargement #{image} a échoué : {error}");
                    open(&database, OpenFlags::SQLITE_OPEN_READ_WRITE)?.execute(
                        "UPDATE os_images SET status='failed',error_msg='Exécution du worker interrompue.',
                         updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status IN ('pending','downloading')",
                        [image],
                    )?;
                }
                return Ok(true);
            }
            ansible::dispatch_installation(&db, &database, ansible_enabled, unlocked, |id| {
                worker.python("playbook", Some(&database), Some(id))
            })
        })();
        match work {
            Ok(true) => continue,
            Ok(false) => {}
            Err(error) => eprintln!("[worker] {error}"),
        }
        thread::sleep(pause);
    }
}

fn open(path: &Path, mode: OpenFlags) -> rusqlite::Result<Connection> {
    connect(path, mode | OpenFlags::SQLITE_OPEN_NOFOLLOW)
}

fn schema_ready(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() > 0)
        && open(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .and_then(|db| db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='init_jobs')",
                [], |row| row.get::<_, bool>(0),
            ))
            .unwrap_or(false)
}

fn due(last: &mut Option<Instant>, seconds: u64) -> bool {
    if last.is_some_and(|time| time.elapsed() < Duration::from_secs(seconds)) {
        return false;
    }
    *last = Some(Instant::now());
    true
}

fn enqueue_initial(database: &Path, tftp: &Path) -> Result<(), ErrorBox> {
    if tftp.join("grubx64.efi").is_file() && tftp.join("lpxelinux.0").is_file() {
        return Ok(());
    }
    let mut db = open(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (kind, message) in [
        ("bootstrap:install_pxe_bins", "Copie des binaires PXE"),
        ("bootstrap:generate_mok", "Initialisation de la clé MOK"),
        (
            "bootstrap:build_grub",
            "Construction du chargeur UEFI signé",
        ),
        ("bootstrap:render_templates", "Génération des menus PXE"),
    ] {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message)
             SELECT ?1,'pending',?2 WHERE NOT EXISTS(
                 SELECT 1 FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running','success')
             )",
            params![kind, message],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn next_init(db: &Connection, vault_locked: bool) -> rusqlite::Result<Option<(i64, String)>> {
    let catalog_blocked = schedule::catalog_blocked(db, false)?;
    db.query_row(
        "SELECT id,job_type FROM init_jobs WHERE status='pending'
         AND NOT (?1 AND job_type GLOB 'machine:ansible_redeploy:*')
         AND NOT (?2 AND job_type=?3)
         AND NOT (job_type='bootstrap:build_grub' AND EXISTS(
             SELECT 1 FROM init_jobs WHERE job_type='bootstrap:generate_mok' AND status IN ('pending','running')
         )) ORDER BY id LIMIT 1",
        params![vault_locked, catalog_blocked, schedule::AUTO_CATALOG],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()
}

fn fail_job(database: &Path, id: i64, message: &str) -> rusqlite::Result<()> {
    open(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?.execute(
        "UPDATE init_jobs SET status='failed',message=?2,ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
         WHERE id=?1 AND status IN ('pending','running')",
        params![id, message],
    )?;
    Ok(())
}

impl Worker<'_> {
    fn dispatch(
        &self,
        database: &Path,
        id: i64,
        kind: &str,
        ansible_enabled: bool,
    ) -> Result<(), ErrorBox> {
        if matches!(kind, "system:nginx_reload" | "system:release_nginx_port") {
            fail_job(
                database,
                id,
                "Tâche historique Nginx. Consultez l’état du serveur Rust.",
            )?;
        } else if bootstrap::supports(kind) {
            return bootstrap::run(database, id, &self.scripts);
        } else if kind.starts_with("action:render_postboot:") {
            return postboot::run(database, id, &self.templates, &self.postboot);
        } else if ["action:reboot:", "machine:reboot:", "machine:shutdown:"]
            .iter()
            .any(|prefix| kind.starts_with(prefix))
        {
            return power::run(database, id);
        } else if kind.starts_with("action:ansible_retry:") {
            return ansible::retry(database, id);
        } else if matches!(
            kind,
            "bootstrap:cleanup_per_mac_files" | "system:factory_reset_wipe"
        ) || kind.starts_with("image:delete:")
        {
            return self.python("job", Some(database), Some(id));
        } else if matches!(
            kind,
            "ansible_repo:pull" | "preset:pull_github" | "preset:pull_github:autoseed"
        ) || [
            "machine:ansible_redeploy:",
            "preset:push_github:",
            "preset:delete_github:",
        ]
        .iter()
        .any(|prefix| kind.starts_with(prefix))
        {
            if ansible_enabled {
                return self.python("job", Some(database), Some(id));
            }
            fail_job(
                database,
                id,
                "Module Ansible désactivé ; aucune synchronisation ou exécution.",
            )?;
        } else {
            fail_job(database, id, "Type de tâche inconnu ou non disponible.")?;
        }
        Ok(())
    }

    fn python(&self, step: &str, database: Option<&Path>, id: Option<i64>) -> Result<(), ErrorBox> {
        let mut child = Command::new("/usr/bin/python3");
        child
            .arg(self.helper)
            .arg("--rust-worker-step")
            .arg(step)
            .arg(self.config);
        if let Some(database) = database {
            child.arg(database);
        }
        if let Some(id) = id {
            child.arg(id.to_string());
        }
        if !child.status()?.success() {
            return Err(format!("L’opération du worker {step} a échoué.").into());
        }
        Ok(())
    }

    fn runtime(&self, database: &Path) -> Result<(), ErrorBox> {
        if env::var("PXE_ANSIBLE_MODE").as_deref().unwrap_or("volume") != "volume"
            || env::var_os("PXE_ANSIBLE_RUNTIME").is_some_and(|runtime| !runtime.is_empty())
        {
            return self.python("runtime", Some(database), None);
        }
        let state = serde_json::json!({"state":"not_configured","checked_at":crate::now()});
        open(database, OpenFlags::SQLITE_OPEN_READ_WRITE)?.execute(
            "INSERT INTO settings(key,value) VALUES('ansible_runtime_status',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",
            [state.to_string()],
        )?;
        Ok(())
    }
}
