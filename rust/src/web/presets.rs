// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::{connect, preseed};
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
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
        "SELECT name,distro,COALESCE(codename,''),({GUIDED}) FROM presets ORDER BY name,id LIMIT 51 OFFSET ?",
    ))?;
    let mut presets = statement.query([u64::from(number - 1) * 50])?;
    let mut content = String::from("<table><thead><tr><th>Modèle</th><th>Système</th><th>Installation guidée</th></tr></thead><tbody>");
    for _ in 0..50 {
        let Some(row) = presets.next()? else { break };
        content.push_str("<tr><td>");
        escape(&mut content, &row.get::<_, String>(0)?);
        content.push_str("</td><td>");
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
    content.push_str(r#"<h2>Nouveau modèle Debian 13</h2>
<p>DHCP, LVM sur le disque sélectionné et connexion root désactivée.</p>
<form method="post" action="/presets">
<p><label>Nom du modèle <input name="name" maxlength="100" required></label></p>
<p><label>Compte administrateur installé <input name="login" maxlength="32" required></label></p>
<p><label>Mot de passe <input type="password" name="password" minlength="12" maxlength="128" autocomplete="new-password" required></label></p>
<p><label>Confirmation <input type="password" name="confirm" minlength="12" maxlength="128" autocomplete="new-password" required></label></p>
<button>Créer le modèle</button></form>"#);
    Ok(page("Modèles d’installation", &content))
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
    if name.is_empty()
        || name.chars().count() > 100
        || name.chars().any(char::is_control)
        || !preseed::technical_account(login)
        || !(12..=128).contains(&password.len())
        || password.chars().any(char::is_control)
        || password != confirmation
    {
        return Ok(invalid());
    }

    let hash = ShaCrypt::default()
        .hash_password(password.as_bytes())
        .map_err(|_| "Unable to generate the installation password hash")?;
    let db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let created = db.execute(
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
    Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
}

fn invalid() -> Reply {
    plain(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Vérifiez le compte, le nom du modèle et la confirmation du mot de passe\n",
    )
}
