// SPDX-License-Identifier: LGPL-3.0-only

use super::{enqueue, invalid, not_found, repository_configured, ROUTE};
use crate::web::{
    admin::escape,
    plain,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use hyper::{Response, StatusCode};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{Map, Value};
use std::{collections::HashMap, fmt::Write, path::Path};

// The same setting groups are consumed by the Debian installer snapshot.
const FIELDS: &[(&str, &str, &str, &str)] = &[
    ("localization", "locale", "Langue et région", "fr_FR.UTF-8"),
    (
        "localization",
        "keymap",
        "Disposition du clavier",
        "fr(latin9)",
    ),
    ("timezone", "zone", "Fuseau horaire", "Europe/Paris"),
    ("timezone", "ntp_server", "Serveur NTP", ""),
    (
        "mirror",
        "hostname",
        "Hôte du miroir Debian",
        "deb.debian.org",
    ),
    ("mirror", "directory", "Répertoire du miroir", "/debian"),
    (
        "packages",
        "pkgsel_include",
        "Paquets à installer (séparés par des espaces)",
        "sudo openssh-server python3 ca-certificates curl",
    ),
];

fn display(value: Option<&Value>) -> String {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        Some(Value::String(value)) => value.clone(),
        _ => String::new(),
    }
}

fn read(db: &Connection, id: i64) -> Result<Option<Map<String, Value>>, ErrorBox> {
    let raw: Option<Option<String>> = db.query_row(
        "SELECT advanced_config_json FROM presets WHERE id=?1 AND distro='debian' AND variant='debian'",
        [id], |row| row.get(0),
    ).optional()?;
    match raw {
        None => Ok(None),
        Some(None) => Ok(Some(Map::new())),
        Some(Some(raw)) if matches!(raw.trim(), "" | "[]" | "{}") => Ok(Some(Map::new())),
        Some(Some(raw)) => Ok(Some(serde_json::from_str(&raw)?)),
    }
}

pub(super) fn serve(
    db: &Connection,
    path: &Path,
    id: i64,
    form: Option<&[u8]>,
) -> Result<Reply, ErrorBox> {
    let Some(form) = form else {
        let Some(config) = read(db, id)? else {
            return Ok(not_found());
        };
        let mut html = format!(
            r#"<section class="panel panel--form">
<form class="form-stack" method="post" action="{ROUTE}/{id}/options">"#
        );
        for &(group, key, label, default) in FIELDS {
            let value = config.get(group).and_then(|group| group.get(key));
            let current = display(value);
            write!(
                html,
                r#"<div class="field"><label for="option-{key}">{label}</label><input id="option-{key}" name="{key}" value=""#
            )?;
            escape(&mut html, &current);
            html.push_str(r#"" placeholder=""#);
            escape(&mut html, default);
            html.push_str(r#"" maxlength="1024"></div>"#);
        }
        write!(
            html,
            r#"<p class="muted">Un champ vide utilise le réglage par défaut.</p><div class="form-actions"><button>Enregistrer</button>
<a class="button button--quiet" href="{ROUTE}/{id}">Retour au modèle</a></div></form></section>"#
        )?;
        return Ok(page(
            ConsoleSection::Presets,
            "Réglages de déploiement Debian",
            &html,
        ));
    };
    let mut fields = HashMap::new();
    for (name, value) in form_urlencoded::parse(form) {
        if !FIELDS.iter().any(|&(_, key, _, _)| key == name) || fields.insert(name, value).is_some()
        {
            return Ok(invalid());
        }
    }
    if fields.is_empty() {
        return Ok(invalid());
    }
    let mut target = crate::connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = target.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(mut config) = read(&tx, id)? else {
        return Ok(not_found());
    };
    for &(group, key, _, _) in FIELDS {
        let Some(value) = fields.get(key).map(|value| value.trim()) else {
            continue;
        };
        if value.len() > 1024 || value.chars().any(char::is_control) {
            return Ok(invalid());
        }
        if display(config.get(group).and_then(|section| section.get(key))) == value {
            continue;
        }
        if value.is_empty() {
            if let Some(section) = config.get_mut(group).and_then(Value::as_object_mut) {
                section.remove(key);
                if section.is_empty() {
                    config.remove(group);
                }
            }
            continue;
        }
        let value = if key == "pkgsel_include" {
            let packages = value.split_ascii_whitespace().collect::<Vec<_>>();
            if packages.iter().any(|name| {
                !name
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".+-".contains(&byte)
                    })
            }) {
                return Ok(invalid());
            }
            serde_json::json!(packages)
        } else {
            if key == "directory"
                && (!value.starts_with('/')
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)))
            {
                return Ok(invalid());
            }
            Value::String(value.to_owned())
        };
        let section = config
            .entry(group)
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(section) = section.as_object_mut() else {
            return Ok(plain(
                StatusCode::CONFLICT,
                "Réglage historique incompatible avec ce formulaire\n",
            ));
        };
        section.insert(key.to_owned(), value);
    }
    let json = Value::Object(config);
    if let Err(error) = crate::preset_import::validate_advanced(&json) {
        return Ok(Response::builder()
            .status(StatusCode::UNPROCESSABLE_ENTITY)
            .header("Content-Type", "text/plain; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(crate::web::bytes(format!("{error}\n")))?);
    }
    tx.execute(
        "UPDATE presets SET advanced_config_json=NULLIF(?2,'{}'),updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        params![id, serde_json::to_string(&json)?],
    )?;
    if repository_configured(&tx)? {
        enqueue(
            &tx,
            &format!("preset:push_github:{id}"),
            "Synchronisation du modèle demandée",
        )?;
    }
    tx.commit()?;
    Ok(redirect(
        StatusCode::SEE_OTHER,
        format!("{ROUTE}/{id}/options"),
    ))
}
