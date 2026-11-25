// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    access::{self, Account},
    admin::escape,
    sessions::{self, Sessions},
    ui::{self, ConsoleSection},
    ErrorBox, Reply,
};
use crate::connect;
use hyper::StatusCode;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use std::{fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/admin/profile";
const UPDATED: &str = "/admin/profile?password=updated";

pub(super) fn page(account: &Account, updated: bool) -> Reply {
    render(account, updated, None)
}

fn render(account: &Account, updated: bool, warning: Option<&str>) -> Reply {
    let method = if account.is_external() {
        "Authentik"
    } else {
        "Compte local"
    };
    let mut html = String::from(
        r#"<div class="panel-stack profile-settings"><section class="panel"><h2>Identité</h2>
<dl class="wizard-summary"><dt>Identifiant</dt><dd>"#,
    );
    escape(&mut html, &account.username);
    write!(
        html,
        "</dd><dt>Connexion</dt><dd>{method}</dd></dl></section>"
    )
    .expect("write to String");
    if let Some(warning) = warning {
        html.push_str(r#"<p class="profile-feedback profile-feedback--error" role="alert">"#);
        escape(&mut html, warning);
        html.push_str("</p>");
    } else if updated && !account.is_external() {
        html.push_str(r#"<p class="profile-feedback" role="status">Mot de passe modifié. Vos autres sessions ont été fermées.</p>"#);
    }
    if account.is_external() {
        html.push_str(r#"<section class="panel"><h2>Mot de passe</h2><p>Votre mot de passe et votre session sont gérés par Authentik.</p></section>"#);
    } else {
        write!(html, r#"<section class="panel"><h2>Mot de passe</h2>
<form class="form-stack" method="post" action="{ROUTE}">
<div class="field"><label for="current-password">Mot de passe actuel</label><input id="current-password" name="current" type="password" autocomplete="current-password" required></div>
<div class="field"><label for="new-password">Nouveau mot de passe</label><input id="new-password" name="password" type="password" autocomplete="new-password" minlength="12" maxlength="72" required aria-describedby="password-help"><small id="password-help">Au moins 12 caractères. Les autres sessions seront fermées après l’enregistrement.</small></div>
<div class="field"><label for="confirm-password">Confirmer le nouveau mot de passe</label><input id="confirm-password" name="confirm" type="password" autocomplete="new-password" minlength="12" maxlength="72" required></div>
<div class="form-actions"><button>Modifier le mot de passe</button></div>
</form></section>"#).expect("write to String");
    }
    if account.id.is_some() {
        write!(html, r#"<section class="panel"><h2>Jetons d’API</h2><p>Gérez les accès à l’API créés avec votre compte.</p>
<a class="button button--quiet" href="{}">Mes jetons d’API</a></section>"#, access::PERSONAL_TOKENS).expect("write to String");
    }
    html.push_str("</div>");
    ui::page(ConsoleSection::Profile, "Mon profil", &html)
}

fn password_error(account: &Account, status: StatusCode, message: &str) -> Reply {
    let mut response = render(account, false, Some(message));
    *response.status_mut() = status;
    response
}

pub(super) fn change_password(
    db: &Connection,
    path: &Path,
    account: &Account,
    body: &[u8],
    sessions: &Sessions,
    token: Option<&str>,
) -> Result<Reply, ErrorBox> {
    let Some(id) = account.id.filter(|_| !account.is_external()) else {
        return Ok(access::denied());
    };
    let invalid = |message| password_error(account, StatusCode::UNPROCESSABLE_ENTITY, message);
    let (mut current, mut password, mut confirm) = (None, None, None);
    for (name, value) in form_urlencoded::parse(body) {
        let field = match name.as_ref() {
            "current" => &mut current,
            "password" => &mut password,
            "confirm" => &mut confirm,
            _ => return Ok(invalid("Formulaire invalide.")),
        };
        if field.replace(value).is_some() {
            return Ok(invalid("Formulaire invalide."));
        }
    }
    let (Some(current), Some(password), Some(confirm)) = (current, password, confirm) else {
        return Ok(invalid("Renseignez les trois champs du formulaire."));
    };
    if password != confirm {
        return Ok(invalid(
            "Les deux saisies du nouveau mot de passe diffèrent.",
        ));
    }
    if password.chars().count() < 12
        || password.len() > 72
        || password.contains('\0')
        || password == current
    {
        return Ok(invalid("Choisissez un mot de passe différent, d’au moins 12 caractères et de 72 octets maximum."));
    }
    let Some((old_hash, epoch)) = sessions::credential(db, &account.username)? else {
        return Ok(access::denied());
    };
    if !bcrypt::verify(current.as_bytes(), &old_hash).unwrap_or(false) {
        return Ok(invalid("Le mot de passe actuel est incorrect."));
    }
    let hash = bcrypt::hash(password.as_bytes(), bcrypt::DEFAULT_COST)?;
    let mut write = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = write.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE users SET managed_password_hash=?2,password_hash='!',session_epoch=session_epoch+1
         WHERE id=?1 AND enabled=1 AND external=0 AND session_epoch=?3
           AND COALESCE(managed_password_hash,password_hash)=?4",
        params![id, hash, epoch, old_hash],
    )? != 1
    {
        return Ok(password_error(
            account,
            StatusCode::CONFLICT,
            "Le compte a changé. Rechargez la page et réessayez.",
        ));
    }
    access::record(&tx, account, "account.password_change", &account.username)?;
    tx.commit()?;
    Ok(
        match sessions.issue(account.username.clone(), &hash, epoch + 1, token) {
            Ok(token) => sessions::cookie(&token, UPDATED),
            Err(_) => sessions::cookie("", "/login"),
        },
    )
}
