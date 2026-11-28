// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    bytes, credential_directory, plain, sessions,
    ui::{self, SetupCodeHelp, WizardStep},
    ErrorBox, Reply,
};
use crate::{configured_database, connect, setting, worker::factory_reset};
use hyper::{
    header::{HeaderMap, LOCATION, SET_COOKIE},
    Response, StatusCode,
};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{sync::Semaphore, task};

const SCHEMA: &str = include_str!("../../../app/db/schema.sqlite.sql");
const SETUP_COOKIE: &str = "__Host-pxe-setup";
const GRANT_AGE: u64 = 15 * 60;
const MAX_GRANTS: usize = 64;

enum Stage {
    Database,
    Admin,
    Resetting,
    Closed,
}

pub(super) struct Wizard {
    code: Option<String>,
    code_help: SetupCodeHelp,
    write: Arc<Semaphore>,
    grants: Arc<Mutex<HashMap<String, Instant>>>,
}

impl Wizard {
    pub(super) fn new() -> Self {
        let code = credential_directory()
            .ok()
            .and_then(|directory| fs::read_to_string(directory.join("setup-code")).ok())
            .and_then(|value| normalize_setup_code(value.trim()));
        Self {
            code,
            code_help: if std::env::var("PXE_SETUP_IN_CONTAINER").as_deref() == Ok("1") {
                SetupCodeHelp::Container
            } else {
                SetupCodeHelp::Host
            },
            write: Arc::new(Semaphore::new(1)),
            grants: Arc::default(),
        }
    }

    pub(super) async fn landing(&self, config: &Path) -> Option<Reply> {
        match read_stage(config).await {
            Some(Stage::Database | Stage::Admin) => {
                Some(redirect(StatusCode::FOUND, "/init/welcome"))
            }
            Some(Stage::Resetting) => Some(redirect(StatusCode::FOUND, "/init")),
            Some(Stage::Closed) => None,
            None => Some(unavailable()),
        }
    }

    pub(super) async fn page(&self, path: &str, config: &Path, headers: &HeaderMap) -> Reply {
        match (read_stage(config).await, path) {
            (Some(Stage::Database | Stage::Admin), "/init/welcome") => ui::wizard_welcome(),
            (Some(Stage::Database), "/init") => ui::wizard_welcome(),
            (Some(Stage::Admin), "/init") => redirect(StatusCode::FOUND, "/init/welcome"),
            (Some(Stage::Database | Stage::Admin), "/init/code") => self.code_page(StatusCode::OK),
            (Some(Stage::Database | Stage::Admin), "/init/admin") if self.authorized(headers) => {
                ui::wizard(
                    Some(WizardStep::Account),
                    "Créer le compte d’administration",
                    r#"<form class="form-stack" method="post" action="/init/admin">
<div class="field"><label for="setup-user">Identifiant</label><input id="setup-user" name="username" autocomplete="username" required maxlength="256"></div>
<div class="field"><label for="setup-password">Mot de passe</label><input id="setup-password" name="password" type="password" autocomplete="new-password" minlength="8" maxlength="72" aria-describedby="setup-password-help" required><small id="setup-password-help">Au moins 8 caractères.</small></div>
<div class="field"><label for="setup-confirm">Confirmer le mot de passe</label><input id="setup-confirm" name="password_confirm" type="password" autocomplete="new-password" minlength="8" maxlength="72" required></div>
<div class="form-actions"><button type="submit">Créer le compte</button></div>
</form>"#,
                    StatusCode::OK,
                )
            }
            (Some(Stage::Database | Stage::Admin), "/init/admin") => {
                redirect(StatusCode::FOUND, "/init/code")
            }
            (Some(Stage::Database | Stage::Admin), _) => redirect(StatusCode::FOUND, "/init/admin"),
            (Some(Stage::Resetting), _) => ui::wizard(
                None,
                "Réinitialisation PXE en cours",
                r#"<p class="wizard-intro">Le service libère le réseau et efface les fichiers de démarrage.</p><a class="button button--quiet" href="/init">Vérifier l’avancement</a>"#,
                StatusCode::OK,
            ),
            (Some(Stage::Closed), _) => redirect(StatusCode::FOUND, "/admin/inventaire"),
            (None, _) => unavailable(),
        }
    }

    fn code_page(&self, status: StatusCode) -> Reply {
        let message = if status == StatusCode::FORBIDDEN {
            r#"<p class="wizard-error" role="alert">Code de configuration invalide. Vérifiez le code affiché sur le serveur.</p>"#
        } else {
            ""
        };
        ui::wizard_with_setup_code(
            self.code_help,
            &format!(
                r#"<p class="wizard-intro">Validez le code affiché à la fin de l’installation pour créer le compte d’administration.</p>
{message}<form class="form-stack" method="post" action="/init/code">
<div class="field"><label for="setup-code">Code de configuration</label><input id="setup-code" name="code" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="setup-code-prefilled" required>
<small id="setup-code-prefilled" role="status" hidden>Le code a été renseigné depuis le lien d’installation.</small></div>
<div class="form-actions"><button type="submit">Valider le code</button></div></form>"#
            ),
            status,
        )
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        sessions::token_named(headers, SETUP_COOKIE).is_some_and(|token| {
            self.grants.lock().is_ok_and(|grants| {
                grants
                    .get(&token)
                    .is_some_and(|deadline| *deadline > Instant::now())
            })
        })
    }

    async fn validate_code(&self, config: &Path) -> Reply {
        let Ok(_permit) = self.write.try_acquire() else {
            return plain(StatusCode::CONFLICT, "Configuration en cours\n");
        };
        match read_stage(config).await {
            Some(Stage::Database | Stage::Admin) => {}
            Some(Stage::Closed) => return closed(),
            Some(Stage::Resetting) => return resetting(),
            None => return unavailable(),
        }
        let Ok(token) = crate::random_token() else {
            return unavailable();
        };
        let Ok(mut grants) = self.grants.lock() else {
            return unavailable();
        };
        let now = Instant::now();
        grants.retain(|_, deadline| *deadline > now);
        if grants.len() == MAX_GRANTS {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Trop de validations de code en cours\n",
            );
        }
        grants.insert(token.clone(), now + Duration::from_secs(GRANT_AGE));
        setup_cookie(&token, "/init/admin")
    }

    pub(super) async fn submit(
        &self,
        path: &str,
        config: &Path,
        headers: &HeaderMap,
        form: &[u8],
    ) -> Reply {
        let (step, back) = if path == "/init/admin" {
            (WizardStep::Account, "/init/admin")
        } else {
            (WizardStep::Code, "/init/code")
        };
        let mut fields = HashMap::new();
        for (name, value) in form_urlencoded::parse(form) {
            if fields
                .insert(name.into_owned(), value.into_owned())
                .is_some()
            {
                return ui::wizard_error(
                    step,
                    StatusCode::BAD_REQUEST,
                    "Formulaire invalide.",
                    back,
                );
            }
        }
        let supplied = fields.remove("code");
        let granted = path == "/init/admin" && supplied.is_none() && self.authorized(headers);
        let valid_code = supplied
            .as_deref()
            .and_then(normalize_setup_code)
            .zip(self.code.as_ref())
            .is_some_and(|(supplied, expected)| {
                bool::from(supplied.as_bytes().ct_eq(expected.as_bytes()))
            });
        if path == "/init/code" {
            if !valid_code || !fields.is_empty() {
                return self.code_page(StatusCode::FORBIDDEN);
            }
            return self.validate_code(config).await;
        }
        if !granted && !valid_code {
            let (message, back) = if supplied.is_none() && path == "/init/admin" {
                ("Validez le code de configuration pour continuer. Une validation est valable 15 minutes.", "/init/code")
            } else {
                ("Code de configuration invalide.", "/init/code")
            };
            return ui::wizard_error(step, StatusCode::FORBIDDEN, message, back);
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
                return ui::wizard_error(
                    step,
                    StatusCode::BAD_REQUEST,
                    "Vérifiez l’identifiant, la longueur du mot de passe et sa confirmation.",
                    back,
                );
            }
            Some((username, password))
        };
        let Ok(permit) = self.write.clone().try_acquire_owned() else {
            return plain(StatusCode::CONFLICT, "Configuration en cours\n");
        };
        let config = config.to_owned();
        let grants = self.grants.clone();
        let reply = task::spawn_blocking(move || -> Result<Reply, ErrorBox> {
            // Retain the permit even if the HTTP client disconnects.
            let _permit = permit;
            if let Some((username, password)) = credentials {
                let reply = create_admin(&config, &username, &password)?;
                if reply.status() == StatusCode::SEE_OTHER {
                    if let Ok(mut grants) = grants.lock() {
                        grants.clear();
                    }
                    return Ok(setup_cookie(
                        "",
                        if granted {
                            "/login"
                        } else {
                            "/admin/inventaire"
                        },
                    ));
                }
                return Ok(reply);
            }
            match stage(&config)? {
                Stage::Database => {
                    initialize_database(&config)?;
                    Ok(redirect(StatusCode::SEE_OTHER, "/init/admin"))
                }
                Stage::Admin => Ok(redirect(StatusCode::SEE_OTHER, "/init/admin")),
                Stage::Resetting => Ok(resetting()),
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

fn setup_cookie(token: &str, target: &str) -> Reply {
    let age = if token.is_empty() { 0 } else { GRANT_AGE };
    let value =
        format!("{SETUP_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}");
    let mut reply = redirect(StatusCode::SEE_OTHER, target);
    reply
        .headers_mut()
        .insert(SET_COOKIE, value.parse().expect("valid setup cookie"));
    reply
}

fn normalize_setup_code(code: &str) -> Option<String> {
    let code = code.replace(['-', ' '], "");
    // Also accept credentials generated by older launchers during an upgrade.
    (matches!(code.len(), 12 | 48) && code.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| code.to_ascii_lowercase())
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
    if factory_reset::pending(&db)? {
        return Ok(Stage::Resetting);
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

pub(crate) fn adopt_existing_database(config: &Path, path: &Path) -> Result<(), ErrorBox> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || path.to_str().is_none()
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(u8::is_ascii_control)
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
    {
        return Err("Existing SQLite path must be an absolute, private regular file".into());
    }
    write_config(config, path)
}

fn create_admin(config: &Path, username: &str, password: &str) -> Result<Reply, ErrorBox> {
    match stage(config)? {
        Stage::Database => initialize_database(config)?,
        Stage::Closed => return Ok(closed()),
        Stage::Resetting => return Ok(resetting()),
        Stage::Admin => {}
    }
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;
    let path = configured_database(config).ok_or("Invalid SQLite configuration")?;
    let mut db = connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let transaction = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if factory_reset::pending(&transaction)? {
        return Ok(resetting());
    }
    if setup_closed(&transaction)? || setting(&transaction, "db_init_done")? != "1" {
        return Ok(closed());
    }
    transaction.execute(
        "INSERT INTO users(username, password_hash, is_admin) VALUES (?1, ?2, 1)",
        params![username, hash],
    )?;
    transaction.execute(
        "INSERT INTO settings(key, value) VALUES ('admin_created', '1')
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [],
    )?;
    transaction.execute("DELETE FROM settings WHERE key='rust_setup_pending'", [])?;
    transaction.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, "/admin/inventaire"))
}

fn closed() -> Reply {
    plain(
        StatusCode::CONFLICT,
        "Le compte initial est déjà configuré\n",
    )
}

fn resetting() -> Reply {
    plain(StatusCode::CONFLICT, "Réinitialisation en cours\n")
}

fn unavailable() -> Reply {
    plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "Configuration initiale indisponible\n",
    )
}

pub(super) fn redirect(status: StatusCode, target: impl AsRef<str>) -> Reply {
    Response::builder()
        .status(status)
        .header(LOCATION, target.as_ref())
        .header("Cache-Control", "no-store")
        .body(bytes(""))
        .expect("valid setup redirect")
}
