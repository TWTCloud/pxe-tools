// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, escape, label, plain, ErrorBox, Reply, STATUSES};
use hyper::{Response, StatusCode};
use rusqlite::{params, Connection, OptionalExtension};
use std::{collections::HashMap, fmt::Write};

const WIPE: &[(&str, &str)] = &[
    ("preseed-loaded", "Preseed d’effacement chargé"),
    ("disks-detected", "Disques détectés"),
    ("wiping", "Effacement en cours"),
    ("post-action", "Action après l’effacement"),
];
const INSTALL: &[(&str, &str)] = &[
    ("preseed-loaded", "Preseed Debian chargé"),
    ("network-configured", "Configuration réseau"),
    ("disk-guard", "Vérification de l’identité des disques"),
    ("mirror-fetched", "Miroir Debian contacté"),
    ("partman-start", "Début du partitionnement"),
    ("partman-done", "Disques partitionnés"),
    ("base-install-start", "Installation du système de base"),
    ("base-install-done", "Système de base installé"),
    ("apt-setup", "Configuration APT"),
    ("tasksel", "Sélection des paquets"),
    ("bootloader", "Installation de GRUB"),
    ("late-command", "Configuration finale"),
    ("finished", "Installation terminée"),
];

pub(super) fn fragment(db: &Connection, machine: i64) -> Result<Reply, ErrorBox> {
    if !db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machines WHERE id=?1)",
        [machine],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(plain(StatusCode::NOT_FOUND, "Appareil introuvable\n"));
    }
    let response = Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Cache-Control", "no-store");
    Ok(match render(db, machine)? {
        Some(fragment) => response.body(bytes(fragment))?,
        None => response
            .header("HX-Redirect", format!("/admin/inventaire/{machine}"))
            .body(bytes(""))?,
    })
}

pub(in crate::web) fn render(db: &Connection, machine: i64) -> Result<Option<String>, ErrorBox> {
    let active = db
        .query_row(
            "SELECT kind,id,action_id,started_at FROM (
           SELECT 0 AS priority,'wipe' AS kind,w.id,w.action_id,w.started_at
           FROM wipes w LEFT JOIN actions a ON a.id=w.action_id
           WHERE w.machine_id=?1 AND w.wipe_status IN ('pending','running')
             AND (w.action_id IS NULL OR a.status NOT IN ('success','failed','cancelled'))
           UNION ALL
           SELECT 1,'install',i.id,i.action_id,i.started_at
           FROM installations i LEFT JOIN actions a ON a.id=i.action_id
           WHERE i.machine_id=?1 AND i.install_status='in_progress'
             AND (i.action_id IS NULL OR a.status NOT IN ('success','failed','cancelled'))
         ) ORDER BY priority,id DESC LIMIT 1",
            [machine],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((kind, id, action, started)) = active else {
        return Ok(None);
    };
    let (title, declared, section) = if kind == "wipe" {
        ("Effacement des disques", WIPE, "wipes")
    } else {
        ("Installation Debian", INSTALL, "installations")
    };
    let mut query = db.prepare(
        "SELECT phase_key,status,message,unixepoch(ended_at)-unixepoch(started_at)
         FROM task_phases WHERE task_type=?1 AND task_id=?2",
    )?;
    let states: HashMap<_, _> = query
        .query_map(params![kind, id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let target = action.map_or_else(|| format!("/{section}/{id}"), |id| format!("/tasks/{id}"));
    let mut html =
        format!("<section id=\"task-progress\"><h2><a href=\"{target}\">{title}</a></h2>");
    if let Some(started) = started {
        html.push_str("<p>Démarrée le <time>");
        escape(&mut html, &started);
        html.push_str("</time> UTC</p>");
    }
    let done = declared
        .iter()
        .filter(|(code, _)| {
            states
                .get(*code)
                .is_some_and(|(status, _, _)| matches!(status.as_str(), "success" | "skipped"))
        })
        .count();
    write!(
        html,
        "<p><progress value=\"{done}\" max=\"{}\"></progress> {done}/{} étapes</p><ol>",
        declared.len(),
        declared.len()
    )?;
    for (code, title) in declared {
        write!(html, "<li>{title} · ")?;
        if let Some((state, message, seconds)) = states.get(*code) {
            escape(&mut html, label(STATUSES, state));
            if let Some(seconds) = seconds.filter(|seconds| *seconds >= 0) {
                write!(html, " · {seconds} s")?;
            }
            if let Some(message) = message.as_deref().filter(|message| !message.is_empty()) {
                html.push_str("<br>");
                escape(&mut html, message);
            }
        } else {
            html.push_str("En attente");
        }
        html.push_str("</li>");
    }
    write!(
        html,
        "</ol><p><a href=\"/admin/inventaire/{machine}#task-progress\">Actualiser</a></p></section>"
    )?;
    Ok(Some(html))
}
