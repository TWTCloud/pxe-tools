// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    onboarding::store,
    plain,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{connect, instance_secrets, preseed, setting};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use hyper::{body::Bytes, StatusCode};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::Value;
use std::{
    collections::HashMap,
    env, fs,
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) const ROUTE: &str = "/settings/ansible";
pub(super) const VAULT: &str = "/settings/ansible/vault-unlock";
const DEFAULT_WORKDIR: &str = "/home/ansible/ansible";

pub(super) fn serve(
    db: &Connection,
    path: &Path,
    vault: bool,
    form: Option<Bytes>,
) -> Result<Reply, ErrorBox> {
    let Some(body) = form else {
        return if vault {
            Ok(plain(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed\n",
            ))
        } else {
            render(db, None)
        };
    };
    let mut fields = HashMap::new();
    for (name, value) in form_urlencoded::parse(&body) {
        if fields.insert(name, value).is_some() {
            return Ok(invalid("Formulaire Ansible invalide\n"));
        }
    }
    if vault {
        let Some(password) = fields.get("vault_password").filter(|value| {
            fields.len() == 1 && (1..=1024).contains(&value.len()) && !value.contains('\0')
        }) else {
            return Ok(invalid("Mot de passe Vault invalide\n"));
        };
        return Ok(match save_vault(password.as_bytes()) {
            Ok(()) => redirect(StatusCode::SEE_OTHER, ROUTE),
            Err(_) => plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Déverrouillage Vault indisponible\n",
            ),
        });
    }
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (values, secret) = match settings(&tx, &fields)? {
        Ok(settings) => settings,
        Err(message) => return Ok(invalid(message)),
    };
    for (key, value) in values {
        store(&tx, key, &value)?;
    }
    tx.commit()?;
    if let Some(secret) = secret {
        render(&db, Some(&secret))
    } else {
        Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
    }
}

fn render(db: &Connection, issued: Option<&str>) -> Result<Reply, ErrorBox> {
    let checked = if setting(db, "ansible_enabled")? == "on" {
        " checked"
    } else {
        ""
    };
    let mut html = format!(
        r#"<p><a href="/settings">Paramètres PXE</a></p><p>État du module · {}</p>
<form method="post" action="{ROUTE}"><p><label><input type="checkbox" name="ansible_enabled" value="on"{checked}> Activer le module</label></p>"#,
        runtime_status(db)?
    );
    for (label, field, key, fallback) in [
        (
            "Utilisateur technique",
            "target_user",
            "ansible_target_user",
            "ansible",
        ),
        ("Dépôt Git (facultatif)", "repo_url", "ansible_repo_url", ""),
        ("Branche", "repo_branch", "ansible_repo_branch", "main"),
        (
            "Manifeste JSON du profil",
            "repo_profile",
            "ansible_repo_profile",
            "",
        ),
        (
            "Répertoire des playbooks",
            "playbooks_dir",
            "ansible_playbooks_dir",
            DEFAULT_WORKDIR,
        ),
        (
            "Identifiant GitHub",
            "github_push_user",
            "github_push_user",
            "",
        ),
    ] {
        html.push_str(&format!(
            r#"<p><label>{label} <input name="{field}" value=""#
        ));
        escape(&mut html, &with_default(db, key, fallback)?);
        html.push_str(r#""></label></p>"#);
    }
    let key_path = env::var_os("PXE_ANSIBLE_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/ansible"))
        .join(".ssh/ansible_automation");
    let mut public_key = setting(db, "ansible_ssh_pubkey")?;
    if public_key.is_empty() {
        if let Ok(file) = fs::File::open(key_path.with_extension("pub")) {
            let mut raw = String::new();
            if file.take(8192).read_to_string(&mut raw).is_ok() && valid_pubkey(raw.trim()) {
                public_key = raw.trim().to_owned();
            }
        }
    }
    html.push_str(r#"<p><label>Clé publique SSH <textarea name="ssh_pubkey">"#);
    escape(&mut html, &public_key);
    html.push_str("</textarea></label></p>");
    let key_installed = if key_path.is_file() {
        "présente sur le worker"
    } else {
        "indisponible sur le worker"
    };
    html.push_str(&format!("<p>Clé privée SSH · {key_installed}</p>"));
    if !setting(db, "ansible_ssh_privkey")?.is_empty() {
        html.push_str(r#"<p><label><input type="checkbox" name="ssh_privkey_clear" value="1"> Supprimer l’ancienne clé privée enregistrée en base</label></p>"#);
    }
    let token = if setting(db, "github_push_token")?.is_empty() {
        "absent"
    } else {
        "enregistré"
    };
    let webhook = if setting(db, "ansible_repo_webhook_enabled")? == "on" {
        " checked"
    } else {
        ""
    };
    let webhook_secret = if setting(db, "ansible_repo_webhook_secret")?.is_empty() {
        "absent"
    } else {
        "enregistré"
    };
    if let Some(secret) = issued {
        html.push_str("<p>Copiez le nouveau secret du webhook GitHub <code id=\"webhook-secret\">");
        escape(&mut html, secret);
        html.push_str("</code></p>");
    }
    let pending = if vault_dir().join("unlock").is_file() {
        "Déverrouillage en attente"
    } else {
        "En attente d’un mot de passe"
    };
    html.push_str(&format!(
        r#"<p>Jeton GitHub · {token}</p>
<p><label>Remplacer le jeton GitHub <input type="password" name="github_push_token" autocomplete="new-password"></label></p>
<p><label><input type="checkbox" name="github_push_token_clear" value="1"> Supprimer le jeton enregistré</label></p>
<h2>Webhook GitHub</h2>
<p>Point d’entrée HTTPS <code>{}</code></p>
<p><label><input type="checkbox" name="webhook_enabled" value="on"{webhook}> Activer les redéploiements automatiques</label></p>
<p>Secret de signature · {webhook_secret}</p>
<p><label>Remplacer le secret <input type="password" name="webhook_secret" autocomplete="new-password"></label></p>
<p><label><input type="checkbox" name="webhook_secret_clear" value="1"> Supprimer le secret enregistré</label></p>
<button name="webhook_action" value="regen_secret">Générer un secret de signature</button>
<button>Enregistrer</button></form>
<h2>Vault Ansible</h2><p>{pending}</p>
<form method="post" action="{VAULT}"><p><label>Mot de passe pour la prochaine exécution
<input type="password" name="vault_password" autocomplete="off" maxlength="1024" required></label></p>
<button>Déverrouiller</button></form>"#,
        super::ansible_webhook::ROUTE,
    ));
    Ok(page(ConsoleSection::Settings, "Module Ansible", &html))
}

fn runtime_status(db: &Connection) -> rusqlite::Result<&'static str> {
    let raw = setting(db, "ansible_runtime_status")?;
    let state: Value = serde_json::from_str(&raw).unwrap_or_default();
    let now = crate::now();
    Ok(
        match (state["state"].as_str(), state["checked_at"].as_i64()) {
            (state, Some(checked)) if (now - 180..=now + 30).contains(&checked) => match state {
                Some("ready") => "prêt",
                Some("unavailable") => "indisponible",
                Some("not_configured") => "à configurer",
                _ => "état inconnu",
            },
            _ => "état inconnu",
        },
    )
}

type Mutation = (Vec<(&'static str, String)>, Option<String>);

fn settings(
    db: &Connection,
    fields: &HashMap<std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>>,
) -> Result<Result<Mutation, &'static str>, ErrorBox> {
    let get = |key| fields.get(key).map(|value| value.as_ref());
    let value = |key| get(key).unwrap_or_default().trim();
    if fields.keys().any(|name| {
        !matches!(
            name.as_ref(),
            "ansible_enabled"
                | "repo_url"
                | "repo_branch"
                | "repo_profile"
                | "target_user"
                | "playbooks_dir"
                | "github_push_user"
                | "github_push_token"
                | "github_push_token_clear"
                | "ssh_pubkey"
                | "ssh_privkey"
                | "ssh_privkey_clear"
                | "webhook_enabled"
                | "webhook_action"
                | "webhook_secret"
                | "webhook_secret_clear"
        )
    }) || !value("ssh_privkey").is_empty()
        || [
            "ssh_privkey_clear",
            "github_push_token_clear",
            "webhook_secret_clear",
        ]
        .into_iter()
        .any(|field| !matches!(value(field), "" | "1"))
        || !matches!(value("webhook_action"), "" | "regen_secret")
    {
        return Ok(Err("Formulaire invalide ou clé privée SSH fournie\n"));
    }
    let enabled = fields.contains_key("ansible_enabled");
    let rotate = value("webhook_action") == "regen_secret";
    let webhook = fields.contains_key("webhook_enabled");
    let webhook_value = if webhook { "on" } else { "off" }.to_owned();
    let current_repo = setting(db, "ansible_repo_url")?;
    if rotate {
        if webhook && current_repo.trim().is_empty() {
            return Ok(Err("Enregistrez le dépôt Git avant d’activer le webhook\n"));
        }
        let secret = crate::random_hex::<32>()?;
        let Ok(encoded) = instance_secrets::seal(secret.as_bytes()) else {
            return Ok(Err(
                "Clé maître de l’instance ou chiffrement indisponible\n",
            ));
        };
        return Ok(Ok((
            vec![
                ("ansible_repo_webhook_secret", encoded),
                ("ansible_repo_webhook_enabled", webhook_value),
            ],
            Some(secret),
        )));
    }
    let current_branch = with_default(db, "ansible_repo_branch", "main")?;
    let branch = get("repo_branch").unwrap_or(&current_branch).trim();
    if !valid_branch(branch) {
        return Ok(Err("Branche Git invalide\n"));
    }
    let current_profile = setting(db, "ansible_repo_profile")?;
    let profile = get("repo_profile").unwrap_or(&current_profile).trim();
    let current_directory = with_default(db, "ansible_playbooks_dir", DEFAULT_WORKDIR)?;
    if !valid_profile(profile)
        || profile.is_empty()
            && fs::symlink_metadata(workdir(&current_directory).join(".git/info/sparse-checkout"))
                .is_ok()
    {
        return Ok(Err("Profil Git invalide ou clone partiel encore actif\n"));
    }
    let mut values = vec![
        (
            "ansible_enabled",
            if enabled { "on" } else { "off" }.to_owned(),
        ),
        ("ansible_repo_branch", branch.to_owned()),
        ("ansible_repo_profile", profile.to_owned()),
    ];
    if value("ssh_privkey_clear") == "1" {
        values.push(("ansible_ssh_privkey", String::new()));
    }
    if !enabled {
        return Ok(Ok((values, None)));
    }
    let repository = get("repo_url").unwrap_or(&current_repo).trim();
    let current_user = with_default(db, "ansible_target_user", "ansible")?;
    let user = get("target_user").unwrap_or(&current_user).trim();
    let directory = get("playbooks_dir").unwrap_or(&current_directory).trim();
    let directory = if directory.is_empty() {
        DEFAULT_WORKDIR
    } else {
        directory
    };
    let current_key = setting(db, "ansible_ssh_pubkey")?;
    let public_key = get("ssh_pubkey").unwrap_or(&current_key).trim();
    if !valid_repository(repository) {
        return Ok(Err("URL du dépôt Git invalide\n"));
    }
    if webhook && repository.is_empty() {
        return Ok(Err(
            "Désactivez le webhook pour utiliser des playbooks locaux\n",
        ));
    }
    if !preseed::technical_account(user)
        || !directory.starts_with('/')
        || directory.bytes().any(|byte| byte.is_ascii_control())
    {
        return Ok(Err(
            "Compte technique ou répertoire des playbooks invalide\n",
        ));
    }
    if !public_key.is_empty() && !valid_pubkey(public_key) {
        return Ok(Err("Clé publique SSH invalide\n"));
    }
    values.extend([
        ("ansible_repo_url", repository.to_owned()),
        ("ansible_ssh_pubkey", public_key.to_owned()),
        ("ansible_playbooks_dir", directory.to_owned()),
        ("ansible_target_user", user.to_owned()),
        ("ansible_repo_webhook_enabled", webhook_value),
    ]);
    if !value("github_push_user").is_empty() {
        values.push(("github_push_user", value("github_push_user").to_owned()));
    }
    for (field, clear, key) in [
        (
            "github_push_token",
            "github_push_token_clear",
            "github_push_token",
        ),
        (
            "webhook_secret",
            "webhook_secret_clear",
            "ansible_repo_webhook_secret",
        ),
    ] {
        if value(clear) == "1" {
            values.push((key, String::new()));
        } else if let Some(secret) = get(field).filter(|secret| !secret.is_empty()) {
            let Ok(ciphertext) = instance_secrets::seal(secret.as_bytes()) else {
                return Ok(Err(
                    "Clé maître de l’instance ou chiffrement indisponible\n",
                ));
            };
            values.push((key, ciphertext));
        }
    }
    Ok(Ok((values, None)))
}

pub(super) fn workdir(configured: &str) -> PathBuf {
    env::var_os("ANSIBLE_WORKDIR")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(if configured.trim().is_empty() {
                DEFAULT_WORKDIR
            } else {
                configured
            })
        })
}

fn with_default(db: &Connection, key: &str, default: &str) -> rusqlite::Result<String> {
    let configured = setting(db, key)?;
    Ok(if configured.is_empty() {
        default.to_owned()
    } else {
        configured
    })
}

fn valid_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 255
        && branch != "HEAD"
        && !branch.contains("..")
        && branch.split('/').all(|segment| {
            segment
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && !segment.ends_with('.')
                && !segment.ends_with(".lock")
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

fn valid_profile(profile: &str) -> bool {
    profile.is_empty()
        || profile.len() <= 512
            && profile.ends_with(".json")
            && !profile.contains("..")
            && profile.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && !segment.eq_ignore_ascii_case(".git")
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
}

fn valid_repository(repo: &str) -> bool {
    repo.is_empty()
        || repo.ends_with(".git")
            && !repo.chars().any(char::is_whitespace)
            && !repo.bytes().any(|byte| byte.is_ascii_control())
            && (["https://", "http://", "ssh://"].into_iter().any(|prefix| {
                repo.strip_prefix(prefix)
                    .and_then(|tail| tail.split_once('/'))
                    .is_some_and(|(host, path)| !host.is_empty() && path.len() > 4)
            }) || repo
                .strip_prefix("git@")
                .and_then(|tail| tail.split_once(':'))
                .is_some_and(|(host, path)| {
                    !host.is_empty()
                        && path.len() > 4
                        && host
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                }))
}

fn valid_pubkey(key: &str) -> bool {
    if key.contains(['\r', '\n', '\0']) {
        return false;
    }
    let mut parts = key.split_whitespace();
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(data) = parts.next() else {
        return false;
    };
    (matches!(kind, "ssh-ed25519" | "ssh-rsa" | "ssh-dss")
        || kind.strip_prefix("ecdsa-sha2-").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }))
        && !data.is_empty()
        && (STANDARD.decode(data).is_ok() || STANDARD_NO_PAD.decode(data).is_ok())
}

fn vault_dir() -> PathBuf {
    env::var_os("PXE_VAULT_UNLOCK_DIR")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/shm/pxe-vault"))
}

fn save_vault(password: &[u8]) -> io::Result<()> {
    let directory = vault_dir();
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Unsafe Vault directory",
        ));
    }
    let staging = directory.join(format!("unlock-{}", crate::random_hex::<16>()?));
    let result = (|| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)?
            .write_all(password)?;
        fs::rename(&staging, directory.join("unlock"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

fn invalid(message: &'static str) -> Reply {
    plain(StatusCode::UNPROCESSABLE_ENTITY, message)
}
