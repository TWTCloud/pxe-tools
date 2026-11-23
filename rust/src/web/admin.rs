// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, single, Reply};
use crate::configured_database;
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE},
    http::request::Parts,
    Response, StatusCode,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task};

const PAGE_SIZE: usize = 100;

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

    pub(super) async fn serve(&self, request: &Parts, peer: IpAddr, config: &Path) -> Reply {
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
        if !self.allow_attempt(peer) {
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("Retry-After", "60")
                .body(bytes("Try again later\n"))
                .expect("valid rate limit response");
        }
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
        let reply = task::spawn_blocking(move || {
            let db_path = configured_database(&config)?;
            let db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
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
            let output = render_devices(&db, page).ok()?;
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("Cache-Control", "no-store")
                    .header("X-Content-Type-Options", "nosniff")
                    .header(
                        "Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'; form-action 'none'",
                    )
                    .body(bytes(output))
                    .expect("valid console response"),
            )
        })
        .await;
        reply
            .ok()
            .flatten()
            .unwrap_or_else(|| plain(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable\n"))
    }

    fn allow_attempt(&self, ip: IpAddr) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        attempts.retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(60));
        if attempts.len() >= 512 && !attempts.contains_key(&ip) {
            return false;
        }
        let count = &mut attempts.entry(ip).or_insert((now, 0)).1;
        *count = count.saturating_add(1);
        *count <= 20
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
    let label = match term.as_str() {
        "client" => "Clients PXE",
        "ordinateur" => "Ordinateurs",
        "serveur" => "Serveurs",
        _ => "Machines",
    };
    let mut rows = db.prepare(
        "SELECT COALESCE(hostname,''), mac, status FROM machines ORDER BY id LIMIT ? OFFSET ?",
    )?;
    let mut rows = rows.query([PAGE_SIZE as u64 + 1, u64::from(page - 1) * PAGE_SIZE as u64])?;
    let mut html = format!(
        r#"<!doctype html><html lang="fr"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{label} · PXE Tools</title>
<main><h1>{label}</h1><table><thead><tr><th>Nom d’hôte</th><th>Adresse MAC</th><th>État</th></tr></thead><tbody>"#
    );
    let mut count = 0;
    let mut has_next = false;
    while let Some(row) = rows.next()? {
        if count == PAGE_SIZE {
            has_next = true;
            break;
        }
        html.push_str("<tr>");
        for column in 0..3 {
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

fn escape(output: &mut String, value: &str) {
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
