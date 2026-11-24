// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    auth_proxy::TrustedProxies,
    bytes, plain,
    sessions::{self, Sessions},
    single, Reply,
};
use crate::{configured_database, connect};
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    body::Bytes,
    header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE},
    http::request::Parts,
    Response, StatusCode,
};
use rusqlite::{params, Connection, OpenFlags};
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
    Bulk(super::devices::bulk::Route, Option<Bytes>),
    Images(super::images::Route, Option<Bytes>),
    Presets(Option<Bytes>),
    Preset(super::presets::Route, Option<Bytes>),
    PullPresets,
    Jobs(super::jobs::View),
    Windows(Arc<super::winpe::Editions>, Option<Bytes>),
    Activity(super::activity::View, Arc<crate::monitoring::Catalog>),
    Terminology(&'static str, &'static str),
    Settings(super::settings::Route, Option<Bytes>),
    Setup(String, Option<Bytes>),
    Certificates(Arc<super::certificates::Certificates>, Option<Bytes>),
    Acme(Arc<super::certificates::Certificates>, Bytes),
}

enum Identity {
    Basic(String, Vec<u8>),
    Session(String),
    Forwarded(String),
}

pub(super) struct Console {
    attempts: Mutex<HashMap<IpAddr, (Instant, u8)>>,
    jobs: Semaphore,
    proxies: TrustedProxies,
    sessions: Sessions,
}

impl Console {
    pub(super) fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            jobs: Semaphore::new(2),
            proxies: TrustedProxies::from_environment(),
            sessions: Sessions::from_environment(),
        }
    }

    pub(super) fn trusted_proxy(&self, peer: IpAddr) -> bool {
        self.proxies.contains(peer)
    }

    pub(super) async fn login(
        &self,
        request: &Parts,
        peer: IpAddr,
        config: &Path,
        form: Option<Bytes>,
    ) -> Reply {
        let query = request.uri.query().unwrap_or_default();
        let query_next = form_urlencoded::parse(query.as_bytes())
            .find(|(key, _)| key == "next")
            .map(|(_, value)| value);
        let next = sessions::local_next(query_next.as_deref().unwrap_or_default());
        match std::env::var("AUTH_MODE").unwrap_or_default().as_str() {
            "" | "local" => {}
            "authentik" => {
                return if form.is_none() && self.proxies.identity(peer, &request.headers).is_some()
                {
                    super::setup::redirect(StatusCode::FOUND, next)
                } else {
                    sso_required()
                };
            }
            _ => return auth_unavailable(),
        }
        let Some(form) = form else {
            return sessions::login_page(next, None, StatusCode::OK);
        };
        let mut username = None;
        let mut password = None;
        let mut target = None;
        for (key, value) in form_urlencoded::parse(&form) {
            let field = match key.as_ref() {
                "username" => &mut username,
                "password" => &mut password,
                "next" => &mut target,
                _ => continue,
            };
            if field.replace(value).is_some() {
                return plain(StatusCode::BAD_REQUEST, "Invalid login form\n");
            }
        }
        let next = sessions::local_next(target.as_deref().unwrap_or(next));
        let username = username.as_deref().map(str::trim).unwrap_or_default();
        let password = password.as_deref().unwrap_or_default();
        if username.is_empty() || username.len() > 256 || password.is_empty() {
            return sessions::login_page(
                next,
                Some("Saisissez votre identifiant et votre mot de passe."),
                StatusCode::UNPROCESSABLE_ENTITY,
            );
        }
        let Ok(_permit) = self.jobs.try_acquire() else {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "Busy\n");
        };
        let Some(window) = self.reserve_attempt(peer) else {
            return rate_limited();
        };
        let config = config.to_owned();
        let sessions = self.sessions.clone();
        let current_token = sessions::token(&request.headers);
        let username = username.to_owned();
        let password = password.to_owned();
        let next = next.to_owned();
        let result = task::spawn_blocking(move || {
            // Exercise bcrypt for unknown accounts as well as existing accounts.
            const UNKNOWN_ACCOUNT_HASH: &str =
                "$2y$12$BivNwfeaFgD7FobF2xFxFeacHAMld9a7bYBP0yCpqXk/Ve6YOFioi";
            let db_path = configured_database(&config)?;
            let db = connect(&db_path, OpenFlags::SQLITE_OPEN_READ_WRITE).ok()?;
            let hash = sessions::password_hash(&db, &username).ok()?;
            let verified = bcrypt::verify(password, hash.as_deref().unwrap_or(UNKNOWN_ACCOUNT_HASH))
                .unwrap_or(false);
            let Some(hash) = hash.filter(|_| verified) else {
                return Some(sessions::login_page(
                    &next,
                    Some("Identifiants incorrects."),
                    StatusCode::UNAUTHORIZED,
                ));
            };
            if db.execute(
                "UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE username=?1 AND password_hash=?2",
                params![username, hash],
            ).ok()? != 1 {
                return Some(unauthorized());
            }
            let next = if crate::setting(&db, "wizard_completed").ok()? == "1" {
                &next
            } else {
                "/init/network"
            };
            let token = sessions
                .issue(username, &hash, current_token.as_deref())
                .ok()?;
            Some(sessions::cookie(&token, next))
        })
        .await;
        if result.as_ref().is_ok_and(|result| {
            result
                .as_ref()
                .is_some_and(|reply| reply.status() == StatusCode::SEE_OTHER)
        }) {
            self.refund_attempt(peer, window);
        }
        result.ok().flatten().unwrap_or_else(auth_unavailable)
    }

    pub(super) async fn logout(&self, headers: &hyper::HeaderMap) -> Reply {
        match std::env::var("AUTH_MODE").unwrap_or_default().as_str() {
            "" | "local" => {}
            "authentik" => return sso_required(),
            _ => return auth_unavailable(),
        }
        if let Some(token) = sessions::token(headers) {
            let sessions = self.sessions.clone();
            if !task::spawn_blocking(move || sessions.remove(&token))
                .await
                .is_ok_and(|result| result.is_ok())
            {
                return auth_unavailable();
            }
        }
        sessions::cookie("", "/login")
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
        let identity = match std::env::var("AUTH_MODE").unwrap_or_default().as_str() {
            "" | "local" => {
                if request.headers.contains_key(AUTHORIZATION) {
                    let Some((username, password)) =
                        single(&request.headers, AUTHORIZATION.as_str()).and_then(credentials)
                    else {
                        return unauthorized();
                    };
                    Identity::Basic(username, password)
                } else if let Some(token) = sessions::token(&request.headers) {
                    Identity::Session(token)
                } else {
                    return sessions::login_required(request);
                }
            }
            "authentik" => {
                let Some(user) = self.proxies.identity(peer, &request.headers) else {
                    return sso_required();
                };
                Identity::Forwarded(user.to_owned())
            }
            _ => return auth_unavailable(),
        };
        let Ok(_permit) = self.jobs.try_acquire() else {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "Busy\n");
        };
        let window = if matches!(identity, Identity::Basic(..)) {
            let Some(window) = self.reserve_attempt(peer) else {
                return rate_limited();
            };
            Some(window)
        } else {
            None
        };
        let sessions = self.sessions.clone();
        let missing_session =
            matches!(identity, Identity::Session(_)).then(|| sessions::login_required(request));
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
            let mut authenticated = false;
            let reply = (|| {
                let db_path = configured_database(&config)?;
                let db = connect(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
                let username = match identity {
                    Identity::Basic(username, password) => {
                        if !sessions::password_hash(&db, &username)
                            .ok()?
                            .is_some_and(|hash| bcrypt::verify(password, &hash).unwrap_or(false))
                        {
                            return Some(unauthorized());
                        }
                        username
                    }
                    Identity::Session(token) => {
                        let Some(username) = sessions.user(&db, &token).ok()? else {
                            return missing_session;
                        };
                        username
                    }
                    Identity::Forwarded(username) => username,
                };
                authenticated = true;
                if let Action::Device(route, form) = &action {
                    return route
                        .serve(&db, &db_path, &method, form.as_deref(), &username)
                        .ok();
                }
                if let Action::Register(form) = &action {
                    return super::devices::register(&db_path, form.as_deref()).ok();
                }
                if let Action::Bulk(route, form) = &action {
                    return route
                        .serve(&db, &db_path, form.as_deref(), &username, page)
                        .ok();
                }
                if let Action::Activity(view, catalog) = &action {
                    return view.serve(&db, &db_path, &path, &query, page, catalog).ok();
                }
                if let Action::Jobs(view) = &action {
                    return view.serve(&db, &db_path, page).ok();
                }
                if let Action::Windows(editions, form) = &action {
                    return editions.settings(&db, &db_path, form.as_deref()).ok();
                }
                if let Action::Presets(form) = &action {
                    return super::presets::serve(&db, &db_path, form.as_deref(), page).ok();
                }
                if let Action::Preset(route, form) = &action {
                    return super::presets::item(*route, &method, &db, &db_path, form.as_deref())
                        .ok();
                }
                if let Action::PullPresets = &action {
                    return super::presets::pull(&db_path).ok();
                }
                if let Action::Images(route, form) = &action {
                    return Some(super::images::serve(
                        *route,
                        &method,
                        &db,
                        &db_path,
                        page,
                        form.as_deref(),
                    ));
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
                if let Action::Settings(route, form) = action {
                    return route.serve(&db, &db_path, form).ok();
                }
                if let Action::Terminology(label, target) = action {
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
                            .header(LOCATION, target)
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
            })();
            (reply, authenticated)
        })
        .await;
        match reply {
            Ok((reply, authenticated)) => {
                if authenticated {
                    if let Some(window) = window {
                        self.refund_attempt(peer, window);
                    }
                }
                reply.unwrap_or_else(console_unavailable)
            }
            Err(_) => console_unavailable(),
        }
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

fn console_unavailable() -> Reply {
    plain(StatusCode::SERVICE_UNAVAILABLE, "Console unavailable\n")
}

fn auth_unavailable() -> Reply {
    plain(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authentication is unavailable\n",
    )
}

fn sso_required() -> Reply {
    plain(
        StatusCode::UNAUTHORIZED,
        "Authentik authentication required\n",
    )
}

fn rate_limited() -> Reply {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "60")
        .body(bytes("Try again later\n"))
        .expect("valid rate limit response")
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

pub(super) fn unauthorized() -> Reply {
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

pub(super) fn terminology_form(html: &mut String, action: &str, term: &str) {
    html.push_str(&format!(
        r#"<form method="post" action="{action}">
<label for="ui-device-term">Appellation dans la console</label>
<select name="ui_device_term" id="ui-device-term">"#
    ));
    for (key, option, _) in DEVICE_TERMS {
        let selected = if key == term { " selected" } else { "" };
        html.push_str(&format!(
            r#"<option value="{key}"{selected}>{option}</option>"#
        ));
    }
    html.push_str("</select><button>Enregistrer</button></form>");
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
<main><h1>{label}</h1>"#
    );
    terminology_form(&mut html, DEVICE_SETTINGS, term);
    html.push_str(r#"<nav><a href="/machines/new">Ajouter un appareil</a> · <a href="/machines/bulk">Déployer par lots</a> · <a href="/machines/bulk-delete">Supprimer par lots</a> · <a href="/activity">Activité</a> · <a href="/jobs">Tâches</a> · <a href="/presets">Modèles</a> · <a href="/settings/images">Images PXE</a> · <a href="/settings">Paramètres</a> · <a href="/admin/certificates">Certificats TLS</a></nav>"#);
    if matches!(
        std::env::var("AUTH_MODE").unwrap_or_default().as_str(),
        "" | "local"
    ) {
        html.push_str(
            r#"<form method="post" action="/logout"><button>Se déconnecter</button></form>"#,
        );
    }
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
