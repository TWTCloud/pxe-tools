// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, single, Reply};
use crate::{configured_database, connect};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    body::Bytes,
    header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE},
    http::request::Parts,
    Response, StatusCode,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task};

pub(super) const DEVICE_SETTINGS: &str = "/admin/settings/device-terminology";
const PAGE_SIZE: usize = 100;
const DEVICE_TERMS: [(&str, &str, &str); 4] = [
    ("machine", "Machine", "Machines"),
    ("client", "Client PXE", "Clients PXE"),
    ("ordinateur", "Ordinateur", "Ordinateurs"),
    ("serveur", "Serveur", "Serveurs"),
];

pub(super) fn device_term(term: &str) -> Option<&'static str> {
    DEVICE_TERMS
        .iter()
        .find(|(key, _, _)| *key == term)
        .map(|(key, _, _)| *key)
}

pub(super) enum Action {
    Devices,
    Device(super::devices::DeviceRoute, Option<Bytes>),
    Register(Option<Bytes>),
    Images(Option<Bytes>),
    Presets(Option<Bytes>),
    PullPresets,
    Jobs(super::jobs::View),
    Activity(super::activity::View),
    Terminology(&'static str),
    Setup(String, Option<Bytes>),
    Certificates(Arc<super::certificates::Certificates>, Option<Bytes>),
    Acme(Arc<super::certificates::Certificates>, Bytes),
}

pub(super) struct Console {
    attempts: Mutex<HashMap<IpAddr, (Instant, u8)>>,
    jobs: Semaphore,
}

impl Console {
    pub(super) fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            jobs: Semaphore::new(2),
        }
    }

    pub(super) async fn serve(
        &self,
        request: &Parts,
        peer: IpAddr,
        config: &Path,
        action: Action,
    ) -> Reply {
        if request.uri.path() == "/admin/" {
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(LOCATION, "/admin/devices")
                .body(bytes(""))
                .expect("valid admin redirect");
        }
        if !matches!(
            std::env::var("AUTH_MODE").unwrap_or_default().as_str(),
            "" | "local"
        ) {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Local authentication is unavailable\n",
            );
        }
        let Some((username, password)) =
            single(&request.headers, AUTHORIZATION.as_str()).and_then(credentials)
        else {
            return unauthorized();
        };
        let Ok(_permit) = self.jobs.try_acquire() else {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "Busy\n");
        };
        let Some(window) = self.reserve_attempt(peer) else {
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .body(bytes("Try again later\n"))
                .expect("valid rate limit response");
        };
        let page = request
            .uri
            .query()
            .and_then(|query| {
                form_urlencoded::parse(query.as_bytes()).find_map(|(key, value)| {
                    (key == "page").then(|| value.parse::<u32>().ok()).flatten()
                })
            })
            .unwrap_or(1)
            .max(1);
        let config = config.to_owned();
        let path = request.uri.path().to_owned();
        let method = request.method.clone();
        let query = request.uri.query().unwrap_or_default().to_owned();
        let reply = task::spawn_blocking(move || {
            let db_path = configured_database(&config)?;
            let db = connect(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
            let hash: Option<String> = db
                .query_row(
                    "SELECT password_hash FROM users WHERE username = ?",
                    [&username],
                    |row| row.get(0),
                )
                .optional()
                .ok()?;
            let authenticated = hash
                .as_deref()
                .is_some_and(|hash| bcrypt::verify(password, hash).unwrap_or(false));
            if !authenticated {
                return Some(unauthorized());
            }
            if let Action::Device(route, form) = &action {
                return route
                    .serve(&db, &db_path, &method, form.as_deref(), &username)
                    .ok();
            }
            if let Action::Register(form) = &action {
                return super::devices::register(&db_path, form.as_deref()).ok();
            }
            if let Action::Activity(view) = &action {
                return view.serve(&db, &path, &query, page).ok();
            }
            if let Action::Jobs(view) = &action {
                return view.serve(&db, page).ok();
            }
            if let Action::Presets(form) = &action {
                return super::presets::serve(&db, &db_path, form.as_deref(), page).ok();
            }
            if let Action::PullPresets = &action {
                return super::presets::pull(&db_path).ok();
            }
            if let Action::Images(form) = &action {
                return Some(super::images::serve(&db, &db_path, page, form.as_deref()));
            }
            if let Action::Setup(endpoint, form) = &action {
                return Some(super::onboarding::serve(
                    &db,
                    &db_path,
                    endpoint,
                    form.as_deref(),
                ));
            }
            if let Action::Acme(tls, form) = &action {
                return Some(tls.configure_acme(form));
            }
            if let Action::Certificates(tls, form) = &action {
                return Some(match form {
                    Some(data) => tls.import(data),
                    None => tls.page(),
                });
            }
            if let Action::Terminology(label) = action {
                let db = connect(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE).ok()?;
                db.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params!["ui_device_term", label],
                )
                .ok()?;
                return Some(
                    Response::builder()
                        .status(StatusCode::SEE_OTHER)
                        .header(LOCATION, "/admin/devices")
                        .header("Cache-Control", "no-store")
                        .body(bytes(""))
                        .expect("valid settings redirect"),
                );
            }
            let output = render_devices(&db, page).ok()?;
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("Cache-Control", "no-store")
                    .header("X-Content-Type-Options", "nosniff")
                    .header(
                        "Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; form-action 'self'",
                    )
                    .body(bytes(output))
                    .expect("valid console response"),
            )
        })
        .await;
        if reply.as_ref().is_ok_and(|result| {
            result
                .as_ref()
                .is_some_and(|response| response.status() != StatusCode::UNAUTHORIZED)
        }) {
            self.refund_attempt(peer, window);
        }
        reply
            .ok()
            .flatten()
            .unwrap_or_else(|| plain(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable\n"))
    }

    fn reserve_attempt(&self, ip: IpAddr) -> Option<Instant> {
        let mut attempts = self.attempts.lock().ok()?;
        let now = Instant::now();
        attempts.retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(60));
        if attempts.len() >= 512 && !attempts.contains_key(&ip) {
            return None;
        }
        let (started, count) = attempts.entry(ip).or_insert((now, 0));
        if *count >= 20 {
            return None;
        }
        *count += 1;
        Some(*started)
    }

    fn refund_attempt(&self, ip: IpAddr, window: Instant) {
        let Ok(mut attempts) = self.attempts.lock() else {
            return;
        };
        if let Some((started, count)) = attempts.get_mut(&ip) {
            if *started == window {
                *count -= 1;
                if *count == 0 {
                    attempts.remove(&ip);
                }
            }
        }
    }
}

fn credentials(value: &str) -> Option<(String, Vec<u8>)> {
    let (scheme, payload) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || payload.len() > 1024 {
        return None;
    }
    let decoded = STANDARD.decode(payload).ok()?;
    let colon = decoded.iter().position(|byte| *byte == b':')?;
    let (username, password) = decoded.split_at(colon);
    let username = std::str::from_utf8(username).ok()?;
    if username.is_empty() || username.len() > 256 {
        return None;
    }
    Some((username.to_owned(), password[1..].to_vec()))
}

fn unauthorized() -> Reply {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            WWW_AUTHENTICATE,
            r#"Basic realm="PXE Tools", charset="UTF-8""#,
        )
        .header("Cache-Control", "no-store")
        .body(bytes("Authentication required\n"))
        .expect("valid challenge response")
}

fn render_devices(db: &Connection, page: u32) -> rusqlite::Result<String> {
    let term = crate::setting(db, "ui_device_term")?;
    let (term, _, label) = DEVICE_TERMS
        .iter()
        .find(|(key, _, _)| *key == term)
        .unwrap_or(&DEVICE_TERMS[0]);
    let mut rows = db.prepare(
        "SELECT COALESCE(hostname,''), mac, status, id FROM machines ORDER BY id LIMIT ? OFFSET ?",
    )?;
    let mut rows = rows.query([PAGE_SIZE as u64 + 1, u64::from(page - 1) * PAGE_SIZE as u64])?;
    let mut html = format!(
        r#"<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{label} · PXE Tools</title>
<main><h1>{label}</h1>
<form method="post" action="{DEVICE_SETTINGS}">
<label for="ui-device-term">Appellation dans la console</label>
<select name="ui_device_term" id="ui-device-term">"#
    );
    for (key, option, _) in DEVICE_TERMS {
        let selected = if key == *term { " selected" } else { "" };
        html.push_str(&format!(
            r#"<option value="{key}"{selected}>{option}</option>"#
        ));
    }
    html.push_str("</select><button>Enregistrer</button></form>");
    html.push_str(r#"<nav><a href="/machines/new">Ajouter un appareil</a> · <a href="/activity">Activité</a> · <a href="/jobs">Tâches</a> · <a href="/presets">Modèles</a> · <a href="/settings/images">Images PXE</a> · <a href="/admin/certificates">Certificats TLS</a></nav>"#);
    if crate::setting(db, "wizard_completed")? != "1" {
        html.push_str(r#"<p><a href="/init/network">Poursuivre la configuration initiale</a></p>"#);
    }
    html.push_str("<table><thead><tr><th>Nom d’hôte</th><th>Adresse MAC</th><th>État</th></tr></thead><tbody>");
    let mut count = 0;
    let mut has_next = false;
    while let Some(row) = rows.next()? {
        if count == PAGE_SIZE {
            has_next = true;
            break;
        }
        let id = row.get::<_, i64>(3)?;
        html.push_str(&format!("<tr><td><a href=\"/machines/{id}\">"));
        let hostname = row.get::<_, String>(0)?;
        escape(
            &mut html,
            if hostname.is_empty() {
                "Ouvrir"
            } else {
                &hostname
            },
        );
        html.push_str("</a></td>");
        for column in 1..3 {
            html.push_str("<td>");
            escape(&mut html, &row.get::<_, String>(column)?);
            html.push_str("</td>");
        }
        html.push_str("</tr>");
        count += 1;
    }
    html.push_str("</tbody></table><nav aria-label=\"Pagination\">");
    if page > 1 {
        html.push_str(&format!(
            r#"<a rel="prev" href="/admin/devices?page={}">Précédente</a> "#,
            page - 1
        ));
    }
    if has_next && page < u32::MAX {
        html.push_str(&format!(
            r#"<a rel="next" href="/admin/devices?page={}">Suivante</a>"#,
            page + 1
        ));
    }
    html.push_str("</nav></main></html>");
    Ok(html)
}

pub(super) fn escape(output: &mut String, value: &str) {
    for char in value.chars() {
        match char {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(char),
        }
    }
}
