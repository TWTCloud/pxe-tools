// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    bytes, plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::{connect, preseed, setting};
use hyper::{Method, Response, StatusCode};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha_crypt::{PasswordHasher, ShaCrypt};
use std::{fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/presets";
pub(super) const GUIDED: &str = "distro='debian' AND variant='debian' AND network_mode='dhcp'
     AND partition_mode='default' AND root_login_mode='disabled'
     AND COALESCE(pre_wipe_mode,'aucun') IN ('aucun','none') AND COALESCE(pre_wipe_mode_json,'')=''
     AND COALESCE(ansible_role,'')='' AND COALESCE(ansible_extra_vars,'')=''
     AND COALESCE(advanced_config_json,'') IN ('','{}','[]')
     AND COALESCE(NULLIF(admin_user_groups,''),'sudo')='sudo'
     AND (codename IS NULL OR codename='' OR codename='trixie')
     AND COALESCE(admin_user_pwhash,'')<>''";

#[derive(Clone, Copy)]
pub(super) enum Route {
    New,
    Detail(i64),
    Snapshot(i64),
    Push(i64),
}

impl Route {
    pub(super) fn for_path(path: &str) -> Option<Self> {
        let suffix = path.strip_prefix("/presets/")?;
        if suffix == "new" {
            return Some(Self::New);
        }
        let parse = |part: &str| part.parse::<i64>().ok().filter(|id| *id > 0);
        if let Some(id) = suffix.strip_suffix(".json") {
            return parse(id).map(Self::Snapshot);
        }
        if let Some(id) = suffix.strip_suffix("/push-github") {
            return parse(id).map(Self::Push);
        }
        parse(suffix).map(Self::Detail)
    }

    pub(super) fn allows(self, method: &Method) -> bool {
        match (self, method) {
            (Self::Push(_), &Method::POST) => true,
            (Self::Push(_), _) => false,
            (_, &Method::GET | &Method::HEAD) => true,
            (Self::Detail(_), &Method::PUT | &Method::POST | &Method::DELETE) => true,
            _ => false,
        }
    }
}

pub(super) fn item(
    route: Route,
    method: &Method,
    db: &Connection,
    path: &Path,
    form: Option<&[u8]>,
) -> Result<Reply, ErrorBox> {
    let id = match route {
        Route::New => return Ok(page("Nouveau modèle Debian 13", create_form())),
        Route::Detail(id) | Route::Snapshot(id) | Route::Push(id) => id,
    };
    if matches!(route, Route::Snapshot(_)) {
        let snapshot = crate::migrations::snapshot_for_preset(db, id)?;
        let (code, data) = if let Some(mut payload) = snapshot {
            for key in ["partition_custom_json", "pre_wipe_mode"] {
                if let Some(decoded) = payload[key]
                    .as_str()
                    .filter(|raw| key != "pre_wipe_mode" || raw.trim_start().starts_with('{'))
                    .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                    .filter(crate::pxe::is_php_array)
                {
                    payload[key] = decoded;
                }
            }
            (StatusCode::OK, payload)
        } else {
            (StatusCode::NOT_FOUND, json!({"error":"preset not found"}))
        };
        return Ok(Response::builder()
            .status(code)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(bytes(data.to_string()))?);
    }
    if let Some(form) = form {
        return change(path, id, route, method, form);
    }
    detail(db, id)
}

pub(super) fn serve(
    db: &Connection,
    path: &Path,
    form: Option<&[u8]>,
    number: u32,
) -> Result<Reply, ErrorBox> {
    if let Some(form) = form {
        return create(path, form);
    }
    let mut statement = db.prepare(&format!(
        "SELECT name,distro,COALESCE(codename,''),({GUIDED}),id FROM presets ORDER BY name,id LIMIT 51 OFFSET ?",
    ))?;
    let mut presets = statement.query([u64::from(number - 1) * 50])?;
    let mut content = String::from("<table><thead><tr><th>Modèle</th><th>Système</th><th>Installation guidée</th></tr></thead><tbody>");
    for _ in 0..50 {
        let Some(row) = presets.next()? else { break };
        write!(
            content,
            "<tr><td><a href=\"{ROUTE}/{}\">",
            row.get::<_, i64>(4)?
        )?;
        escape(&mut content, &row.get::<_, String>(0)?);
        content.push_str("</a></td><td>");
        escape(&mut content, &row.get::<_, String>(1)?);
        let codename: String = row.get(2)?;
        if !codename.is_empty() {
            content.push(' ');
            escape(&mut content, &codename);
        }
        let kind: bool = row.get(3)?;
        content.push_str(if kind {
            "</td><td>Compatible</td></tr>"
        } else {
            "</td><td>Profil avancé</td></tr>"
        });
    }
    content.push_str("</tbody></table><nav aria-label=\"Pagination\">");
    if number > 1 {
        write!(
            content,
            "<a href=\"{ROUTE}?page={}\">Précédente</a> ",
            number - 1
        )?;
    }
    if presets.next()?.is_some() && number < u32::MAX {
        write!(
            content,
            "<a href=\"{ROUTE}?page={}\">Suivante</a> ",
            number + 1
        )?;
    }
    content.push_str(r#"<a href="/admin/devices">Appareils</a></nav>"#);
    if !crate::setting(db, "ansible_repo_url")?.trim().is_empty() {
        content.push_str(r#"<form method="post" action="/presets/pull-github"><button>Synchroniser depuis le dépôt Ansible</button></form>"#);
    }
    content.push_str("<h2>Nouveau modèle Debian 13</h2>");
    content.push_str(create_form());
    Ok(page("Modèles d’installation", &content))
}

fn create_form() -> &'static str {
    r#"
<p>DHCP, LVM sur le disque sélectionné et connexion root désactivée.</p>
<form method="post" action="/presets">
<p><label>Nom du modèle <input name="name" maxlength="100" required></label></p>
<p><label>Compte administrateur installé <input name="login" maxlength="32" required></label></p>
<p><label>Mot de passe <input type="password" name="password" minlength="12" maxlength="128" autocomplete="new-password" required></label></p>
<p><label>Confirmation <input type="password" name="confirm" minlength="12" maxlength="128" autocomplete="new-password" required></label></p>
<button>Créer le modèle</button></form>"#
}

fn detail(db: &Connection, id: i64) -> Result<Reply, ErrorBox> {
    let row: Option<(String, String, String, Option<String>)> = db
        .query_row(
            "SELECT name,admin_user_login,variant,description FROM presets WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((name, login, variant, description)) = row else {
        return Ok(not_found());
    };
    let mut html = format!(
        r#"<nav><a href="{ROUTE}">Liste des modèles</a> · <a href="{ROUTE}/{id}.json">Configuration JSON</a></nav><p>"#
    );
    escape(&mut html, &name);
    html.push_str("</p>");
    if variant != "proxmox-ve" {
        write!(
            html,
            r#"<form method="post" action="{ROUTE}/{id}"><input type="hidden" name="_method" value="PUT">
<p><label>Nom du modèle <input name="name" required maxlength="100" value=""#
        )?;
        escape(&mut html, &name);
        html.push_str(
            r#""></label></p><p><label>Description <textarea name="description" maxlength="5000">"#,
        );
        escape(&mut html, description.as_deref().unwrap_or_default());
        html.push_str(r#"</textarea></label></p><p><label>Compte administrateur installé <input name="login" required maxlength="32" value=""#);
        escape(&mut html, &login);
        html.push_str(r#""></label></p><p><label>Nouveau mot de passe <input type="password" name="password" autocomplete="new-password" maxlength="128"></label></p>
<p><label>Confirmation <input type="password" name="confirm" autocomplete="new-password" maxlength="128"></label></p>
<button>Enregistrer</button></form>"#);
    }
    if repository_configured(db)? {
        write!(
            html,
            r#"<form method="post" action="{ROUTE}/{id}/push-github"><button>Publier le modèle dans le dépôt Ansible</button></form>"#
        )?;
    }
    write!(
        html,
        r#"<details><summary>Suppression</summary><form method="post" action="{ROUTE}/{id}">
<input type="hidden" name="_method" value="DELETE"><button>Supprimer le modèle</button></form></details>"#
    )?;
    Ok(page("Modèle d’installation", &html))
}

fn change(
    path: &Path,
    id: i64,
    route: Route,
    method: &Method,
    form: &[u8],
) -> Result<Reply, ErrorBox> {
    let mut fields = std::collections::HashMap::new();
    for (key, value) in form_urlencoded::parse(form) {
        if fields.insert(key, value).is_some() {
            return Ok(invalid());
        }
    }
    let method = match (method, fields.remove("_method").as_deref()) {
        (&Method::POST, Some("PUT")) => Method::PUT,
        (&Method::POST, Some("DELETE")) => Method::DELETE,
        (method, None) => method.clone(),
        _ => return Ok(invalid()),
    };
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let old: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT name,variant,admin_user_password_cipher FROM presets WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((old_name, variant, cipher)) = old else {
        return Ok(not_found());
    };
    let synchronize = repository_configured(&tx)?;
    let target = match (route, method) {
        (Route::Push(_), Method::POST) if fields.is_empty() && synchronize => {
            format!(
                "/jobs/{}",
                enqueue(
                    &tx,
                    &format!("preset:push_github:{id}"),
                    "Synchronisation du modèle demandée"
                )?
            )
        }
        (Route::Detail(_), Method::DELETE) if fields.is_empty() => {
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM machines WHERE preset_id=?1 AND COALESCE(install_config_json,'')='')",
                [id],|row|row.get::<_,bool>(0),
            )? {
                return Ok(plain(StatusCode::CONFLICT,"Le modèle est encore utilisé par une configuration historique\n"));
            }
            tx.execute("DELETE FROM presets WHERE id=?1", [id])?;
            tx.execute(
                "UPDATE init_jobs SET status='failed',ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
                 message='Modèle supprimé avant la synchronisation'
                 WHERE job_type=?1 AND status='pending'",
                [format!("preset:push_github:{id}")],
            )?;
            if synchronize {
                enqueue_removal(&tx, &old_name)?;
            }
            ROUTE.to_owned()
        }
        (Route::Detail(_), Method::PUT) if variant != "proxmox-ve" => {
            let get = |key| {
                fields
                    .get(key)
                    .map(|value| value.as_ref())
                    .unwrap_or_default()
            };
            let name = get("name").trim();
            let login = get("login").trim();
            let description = get("description").trim();
            let password = get("password");
            if fields.keys().any(|name| {
                !matches!(
                    name.as_ref(),
                    "name" | "login" | "description" | "password" | "confirm"
                )
            }) || !valid_profile_name(name)
                || !preseed::technical_account(login)
                || description.len() > 5000
                || description.contains('\0')
                || (!password.is_empty() && !valid_password(password))
                || get("confirm") != password
            {
                return Ok(invalid());
            }
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM presets WHERE name=?2 AND id<>?1)",
                params![id, name],
                |row| row.get::<_, bool>(0),
            )? {
                return Ok(plain(
                    StatusCode::CONFLICT,
                    "Ce nom de modèle est déjà utilisé\n",
                ));
            }
            let generated = if password.is_empty() {
                None
            } else {
                Some(
                    ShaCrypt::default()
                        .hash_password(password.as_bytes())
                        .map_err(|_| "Unable to generate the installation password hash")?,
                )
            };
            let cipher =
                if generated.is_some() && cipher.as_deref().is_some_and(|raw| !raw.is_empty()) {
                    Some(crate::instance_secrets::seal(password.as_bytes())?)
                } else {
                    cipher
                };
            tx.execute(
                "UPDATE presets SET name=?2,description=NULLIF(?3,''),admin_user_login=?4,
                 admin_user_pwhash=COALESCE(?5,admin_user_pwhash),admin_user_password_cipher=?6,
                 updated_at=CURRENT_TIMESTAMP WHERE id=?1",
                params![
                    id,
                    name,
                    description,
                    login,
                    generated.as_ref().map(|hash| hash.as_str()),
                    cipher
                ],
            )?;
            if synchronize {
                if name != old_name
                    && crate::worker::schedule::preset_slug(name)
                        != crate::worker::schedule::preset_slug(&old_name)
                {
                    enqueue_removal(&tx, &old_name)?;
                }
                enqueue(
                    &tx,
                    &format!("preset:push_github:{id}"),
                    "Synchronisation du modèle demandée",
                )?;
            }
            format!("{ROUTE}/{id}")
        }
        (Route::Push(_), _) => {
            return Ok(plain(StatusCode::CONFLICT, "Dépôt Ansible indisponible\n"))
        }
        _ => return Ok(invalid()),
    };
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, target))
}

fn not_found() -> Reply {
    plain(StatusCode::NOT_FOUND, "Modèle introuvable\n")
}

fn repository_configured(db: &Connection) -> rusqlite::Result<bool> {
    Ok(setting(db, "ansible_enabled")? == "on"
        && !setting(db, "ansible_repo_url")?.trim().is_empty())
}

fn enqueue(db: &Connection, kind: &str, message: &str) -> rusqlite::Result<i64> {
    if let Some(existing) = db
        .query_row(
            "SELECT id FROM init_jobs WHERE job_type=?1 AND status='pending' ORDER BY id LIMIT 1",
            [kind],
            |row| row.get(0),
        )
        .optional()?
    {
        return Ok(existing);
    }
    db.execute(
        "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
        params![kind, message],
    )?;
    Ok(db.last_insert_rowid())
}

fn enqueue_removal(db: &Connection, name: &str) -> rusqlite::Result<()> {
    let slug = crate::worker::schedule::preset_slug(name);
    if slug.is_empty() {
        return Ok(());
    }
    let mut query = db.prepare("SELECT name FROM presets")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        if crate::worker::schedule::preset_slug(&row.get::<_, String>(0)?) == slug {
            return Ok(());
        }
    }
    enqueue(
        db,
        &format!("preset:delete_github:{slug}"),
        "Retrait du modèle du dépôt Ansible demandé",
    )?;
    Ok(())
}

fn valid_profile_name(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= 100 && !name.chars().any(char::is_control)
}

fn valid_password(password: &str) -> bool {
    (12..=128).contains(&password.len()) && !password.chars().any(char::is_control)
}

pub(super) fn pull(path: &Path) -> Result<Reply, ErrorBox> {
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if crate::setting(&tx, "ansible_repo_url")?.trim().is_empty() {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Aucun dépôt Ansible configuré\n",
        ));
    }
    let existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM init_jobs
         WHERE (job_type='preset:pull_github' OR job_type LIKE 'preset:pull_github:%')
           AND status IN ('pending','running') ORDER BY id LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let id = if let Some(id) = existing {
        id
    } else {
        tx.execute(
            "INSERT INTO init_jobs(job_type,status,message)
             VALUES('preset:pull_github','pending','Synchronisation des modèles depuis GitHub')",
            [],
        )?;
        tx.last_insert_rowid()
    };
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/jobs/{id}")))
}

fn create(path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let (mut name, mut login, mut password, mut confirmation) = (None, None, None, None);
    for (field, value) in form_urlencoded::parse(form) {
        let slot = match field.as_ref() {
            "name" => &mut name,
            "login" => &mut login,
            "password" => &mut password,
            "confirm" => &mut confirmation,
            _ => return Ok(invalid()),
        };
        if slot.replace(value).is_some() {
            return Ok(invalid());
        }
    }
    let (Some(name), Some(login), Some(password), Some(confirmation)) =
        (name, login, password, confirmation)
    else {
        return Ok(invalid());
    };
    let name = name.trim();
    let login = login.trim();
    if !valid_profile_name(name)
        || !preseed::technical_account(login)
        || !valid_password(&password)
        || password != confirmation
    {
        return Ok(invalid());
    }

    let hash = ShaCrypt::default()
        .hash_password(password.as_bytes())
        .map_err(|_| "Unable to generate the installation password hash")?;
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let created = tx.execute(
        "INSERT INTO presets(name,distro,codename,network_mode,partition_mode,root_login_mode,
                             admin_user_login,admin_user_pwhash)
         VALUES(?,'debian','trixie','dhcp','default','disabled',?,?) ON CONFLICT(name) DO NOTHING",
        params![name, login, hash.as_str()],
    )?;
    if created == 0 {
        return Ok(plain(
            StatusCode::CONFLICT,
            "Ce nom de modèle est déjà utilisé\n",
        ));
    }
    if repository_configured(&tx)? {
        let id = tx.last_insert_rowid();
        enqueue(
            &tx,
            &format!("preset:push_github:{id}"),
            "Synchronisation du modèle demandée",
        )?;
    }
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
}

fn invalid() -> Reply {
    plain(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Vérifiez le compte, le nom du modèle et la confirmation du mot de passe\n",
    )
}
