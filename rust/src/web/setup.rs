// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, credential_directory, plain, ErrorBox, Reply};
use crate::{configured_database, connect, setting};
use hyper::{header::LOCATION, Response, StatusCode};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::{sync::Semaphore, task};

const SCHEMA: &str = include_str!("../../../app/db/schema.sqlite.sql");

enum Stage {
    Database,
    Admin,
    Closed,
}

pub(super) struct Wizard {
    code: Option<String>,
    write: Arc<Semaphore>,
}

impl Wizard {
    pub(super) fn new() -> Self {
        let code = credential_directory()
            .ok()
            .and_then(|directory| fs::read_to_string(directory.join("setup-code")).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| valid_setup_code(value));
        Self {
            code,
            write: Arc::new(Semaphore::new(1)),
        }
    }

    pub(super) async fn landing(&self, config: &Path) -> Option<Reply> {
        match read_stage(config).await {
            Some(Stage::Database) => Some(redirect(StatusCode::FOUND, "/init/welcome")),
            Some(Stage::Admin) => Some(redirect(StatusCode::FOUND, "/init/admin")),
            Some(Stage::Closed) => None,
            None => Some(unavailable()),
        }
    }

    pub(super) async fn page(&self, path: &str, config: &Path) -> Reply {
        match (read_stage(config).await, path) {
            (Some(Stage::Database), "/init" | "/init/welcome") => page(
                "Configuration initiale",
                "<p>Préparez la base SQLite, puis créez le compte d’administration.</p>
                 <p><a href=\"/init/db\">Configurer la base</a></p>",
            ),
            (Some(Stage::Database), "/init/db") => page(
                "Base SQLite",
                r#"<form method="post" action="/init/db">
<label>Code de configuration <input name="code" type="password" required></label>
<button>Initialiser SQLite</button></form>"#,
            ),
            (Some(Stage::Database), _) => redirect(StatusCode::FOUND, "/init/db"),
            (Some(Stage::Admin), "/init/admin") => page(
                "Compte d’administration",
                r#"<form method="post" action="/init/admin">
<label>Code de configuration <input name="code" type="password" required></label>
<label>Identifiant <input name="username" autocomplete="username" required maxlength="256"></label>
<label>Mot de passe <input name="password" type="password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<label>Confirmer <input name="password_confirm" type="password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<button>Créer le compte</button></form>"#,
            ),
            (Some(Stage::Admin), _) => redirect(StatusCode::FOUND, "/init/admin"),
            (Some(Stage::Closed), _) => redirect(StatusCode::FOUND, "/admin/devices"),
            (None, _) => unavailable(),
        }
    }

    pub(super) async fn submit(&self, path: &str, config: &Path, form: &[u8]) -> Reply {
        let mut fields = HashMap::new();
        for (name, value) in form_urlencoded::parse(form) {
            if fields
                .insert(name.into_owned(), value.into_owned())
                .is_some()
            {
                return plain(StatusCode::BAD_REQUEST, "Formulaire invalide\n");
            }
        }
        let supplied = fields.remove("code").unwrap_or_default();
        if !valid_setup_code(&supplied)
            || !self
                .code
                .as_ref()
                .is_some_and(|expected| bool::from(supplied.as_bytes().ct_eq(expected.as_bytes())))
        {
            return plain(StatusCode::FORBIDDEN, "Code de configuration invalide\n");
        }
        let credentials = if path == "/init/db" {
            None
        } else {
            let username = fields.remove("username").unwrap_or_default();
            let username = username.trim().to_owned();
            let password = fields.remove("password").unwrap_or_default();
            let confirm = fields.remove("password_confirm").unwrap_or_default();
            if username.is_empty()
                || username.len() > 256
                || username.contains(':')
                || username.chars().any(char::is_control)
                || !(8..=72).contains(&password.len())
                || password.contains('\0')
                || password != confirm
            {
                return plain(
                    StatusCode::BAD_REQUEST,
                    "Identifiant ou mot de passe invalide\n",
                );
            }
            Some((username, password))
        };
        let Ok(permit) = self.write.clone().try_acquire_owned() else {
            return plain(StatusCode::CONFLICT, "Configuration en cours\n");
        };
        let config = config.to_owned();
        let reply = task::spawn_blocking(move || {
            // Retain the permit even if the HTTP client disconnects.
            let _permit = permit;
            if let Some((username, password)) = credentials {
                return create_admin(&config, &username, &password);
            }
            match stage(&config)? {
                Stage::Database => {
                    initialize_database(&config)?;
                    Ok(redirect(StatusCode::SEE_OTHER, "/init/admin"))
                }
                Stage::Admin => Ok(redirect(StatusCode::SEE_OTHER, "/init/admin")),
                Stage::Closed => Ok(closed()),
            }
        })
        .await;
        match reply {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => {
                eprintln!("Rust setup: {error}");
                unavailable()
            }
            Err(_) => unavailable(),
        }
    }
}

fn valid_setup_code(code: &str) -> bool {
    code.len() == 48 && code.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn read_stage(config: &Path) -> Option<Stage> {
    let config = config.to_owned();
    task::spawn_blocking(move || stage(&config))
        .await
        .ok()?
        .ok()
}

fn stage(config: &Path) -> Result<Stage, ErrorBox> {
    match fs::symlink_metadata(config) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Stage::Database),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let path = configured_database(config).ok_or("Invalid SQLite configuration")?;
    let db = connect(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if setup_closed(&db)? {
        return Ok(Stage::Closed);
    }
    if setting(&db, "db_init_done")? == "1" {
        return Ok(Stage::Admin);
    }
    Err("Existing SQLite database is not initialized".into())
}

fn setup_closed(db: &Connection) -> rusqlite::Result<bool> {
    let users: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))?;
    Ok(users || setting(db, "admin_created")? == "1" || setting(db, "wizard_completed")? == "1")
}

fn initialize_database(config: &Path) -> Result<(), ErrorBox> {
    let root = std::env::var_os("PXE_SETUP_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/var/lib/pxe-tools".into());
    let path = std::env::var_os("PXE_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("pxe-tools.sqlite"));
    if !path.is_absolute()
        || path.parent() != Some(root.as_path())
        || path
            .extension()
            .is_none_or(|extension| extension != "sqlite")
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(u8::is_ascii_control)
        || !fs::symlink_metadata(&root)?.is_dir()
        || path.to_str().is_none()
    {
        return Err("Invalid path for a new SQLite database".into());
    }
    let driver = std::env::var("PXE_DB_DRIVER").unwrap_or_default();
    if !driver.is_empty() && !driver.eq_ignore_ascii_case("sqlite") {
        return Err("Only SQLite is supported by the setup wizard".into());
    }
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err("Existing SQLite path must be a private regular file".into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let mut db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let empty: bool = transaction.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM sqlite_schema)",
        [],
        |row| row.get(0),
    )?;
    if empty {
        transaction.execute_batch(SCHEMA)?;
        transaction.execute_batch(
            "INSERT INTO settings(key, value) VALUES
             ('db_init_done', '1'), ('admin_created', '0'), ('wizard_completed', '0'),
             ('pxe_enabled', 'off'), ('dhcp_proxy_enabled', 'off'),
             ('rust_setup_pending', '1');",
        )?;
    } else if setting(&transaction, "rust_setup_pending")? != "1" || setup_closed(&transaction)? {
        return Err("Existing SQLite data requires its original db.conf".into());
    }
    transaction.commit()?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    write_config(config, &path)?;
    Ok(())
}

fn write_config(config: &Path, sqlite_path: &Path) -> Result<(), ErrorBox> {
    let parent = config.parent().ok_or("Missing SQLite config directory")?;
    let temporary = parent.join(format!(".db.conf-{}", crate::random_token()?));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<(), ErrorBox> {
        let mut file = file;
        serde_json::to_writer(
            &mut file,
            &serde_json::json!({"driver": "sqlite", "path": sqlite_path}),
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::hard_link(&temporary, config)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    fs::remove_file(temporary)?;
    result
}

fn create_admin(config: &Path, username: &str, password: &str) -> Result<Reply, ErrorBox> {
    match stage(config)? {
        Stage::Database => return Ok(redirect(StatusCode::SEE_OTHER, "/init/db")),
        Stage::Closed => return Ok(closed()),
        Stage::Admin => {}
    }
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    let path = configured_database(config).ok_or("Invalid SQLite configuration")?;
    let mut db = connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if setup_closed(&transaction)? || setting(&transaction, "db_init_done")? != "1" {
        return Ok(closed());
    }
    transaction.execute(
        "INSERT INTO users(username, password_hash) VALUES (?1, ?2)",
        params![username, hash],
    )?;
    transaction.execute(
        "INSERT INTO settings(key, value) VALUES ('admin_created', '1')
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [],
    )?;
    transaction.execute("DELETE FROM settings WHERE key='rust_setup_pending'", [])?;
    transaction.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, "/admin/devices"))
}

fn closed() -> Reply {
    plain(
        StatusCode::CONFLICT,
        "Le compte initial est déjà configuré\n",
    )
}

fn unavailable() -> Reply {
    plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "Configuration initiale indisponible\n",
    )
}

pub(super) fn redirect(status: StatusCode, target: &'static str) -> Reply {
    Response::builder()
        .status(status)
        .header(LOCATION, target)
        .header("Cache-Control", "no-store")
        .body(bytes(""))
        .expect("valid setup redirect")
}

pub(super) fn page(title: &str, form: &str) -> Reply {
    let html = format!(
        r#"<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · PXE Tools</title><main><h1>{title}</h1>{form}</main></html>"#,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        .body(bytes(html))
        .expect("valid setup page")
}
