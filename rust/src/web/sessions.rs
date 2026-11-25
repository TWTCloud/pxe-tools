// SPDX-License-Identifier: LGPL-3.0-only

use super::{setup::redirect, ui, ErrorBox, Reply};
use hyper::{
    header::{HeaderMap, ACCEPT, COOKIE, SET_COOKIE},
    StatusCode,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const NAME: &str = "__Host-pxe-session";
const LIFETIME: i64 = 8 * 60 * 60;

#[derive(Clone)]
pub(super) struct Sessions(PathBuf);

#[derive(Deserialize, Serialize)]
struct Session {
    user: String,
    fingerprint: String,
    expires: i64,
}

impl Sessions {
    pub(super) fn from_environment() -> Self {
        Self(
            std::env::var_os("PXE_SESSION_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/lib/pxe-tools/sessions".into()),
        )
    }

    fn directory(&self) -> Result<&Path, ErrorBox> {
        if !self.0.is_absolute() {
            return Err("Invalid session directory".into());
        }
        let info = fs::symlink_metadata(&self.0)?;
        // geteuid has no pointer arguments and reads the process identity.
        if !info.is_dir() || info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() } {
            return Err("Unprotected session directory".into());
        }
        Ok(&self.0)
    }

    pub(super) fn issue(
        &self,
        user: String,
        password_hash: &str,
        obsolete: Option<&str>,
    ) -> Result<String, ErrorBox> {
        let dir = self.directory()?;
        let token = crate::random_token()?;
        let session = Session {
            user,
            fingerprint: digest(password_hash),
            expires: crate::now() + LIFETIME,
        };
        let stored = dir.join(format!("rust-{}", digest(&token)));
        let bytes = serde_json::to_vec(&session)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stored)?;
        if let Err(error) = output.write_all(&bytes).and_then(|()| output.sync_all()) {
            let _ = fs::remove_file(&stored);
            return Err(error.into());
        }
        if let Some(token) = obsolete {
            if let Err(error) = self.remove(token) {
                let _ = fs::remove_file(&stored);
                return Err(error);
            }
        }
        self.sweep(dir);
        Ok(token)
    }

    pub(super) fn user(&self, db: &Connection, token: &str) -> Result<Option<String>, ErrorBox> {
        let Some(session) = self.read(token)? else {
            return Ok(None);
        };
        let current: Option<String> = password_hash(db, &session.user)?;
        Ok(current
            .filter(|hash| digest(hash) == session.fingerprint)
            .map(|_| session.user))
    }

    fn read(&self, token: &str) -> Result<Option<Session>, ErrorBox> {
        let dir = self.directory()?;
        let path = dir.join(format!("rust-{}", digest(token)));
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        else {
            return Ok(None);
        };
        let info = file.metadata()?;
        if !info.is_file() || info.len() > 4096 || info.nlink() != 1 || info.mode() & 0o077 != 0 {
            return Ok(None);
        }
        let session: Session = serde_json::from_reader(file.take(4097))?;
        Ok((session.expires > crate::now()).then_some(session))
    }

    pub(super) fn remove(&self, token: &str) -> Result<(), ErrorBox> {
        let path = self.directory()?.join(format!("rust-{}", digest(token)));
        match fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    fn sweep(&self, dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name
                .to_str()
                .and_then(|name| name.strip_prefix("rust-"))
                .is_some_and(|name| {
                    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                continue;
            }
            if fs::symlink_metadata(entry.path()).is_ok_and(|info| {
                info.is_file()
                    && info
                        .modified()
                        .ok()
                        .and_then(|time| time.elapsed().ok())
                        .is_some_and(|duration| duration.as_secs() as i64 >= LIFETIME)
            }) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn password_hash(db: &Connection, user: &str) -> rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT password_hash FROM users WHERE username=?1",
        [user],
        |row| row.get(0),
    )
    .optional()
}

pub(super) fn token(headers: &HeaderMap) -> Option<String> {
    let mut tokens = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter_map(|(key, value)| (key == NAME).then_some(value));
    let value = tokens.next()?;
    (tokens.next().is_none()
        && value.len() == 32
        && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| value.to_owned())
}

pub(super) fn cookie(token: &str, next: &str) -> Reply {
    let mut ret = redirect(StatusCode::SEE_OTHER, next);
    let age = if token.is_empty() { 0 } else { LIFETIME };
    let value = format!("{NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}");
    ret.headers_mut()
        .insert(SET_COOKIE, value.parse().expect("valid session cookie"));
    ret
}

pub(super) fn local_next(next: &str) -> &str {
    let decoded = percent_encoding::percent_decode_str(next).decode_utf8();
    if next.is_ascii()
        && next.starts_with('/')
        && decoded.is_ok_and(|path| {
            path.starts_with('/')
                && !path.starts_with("//")
                && !path.contains('\\')
                && !path
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b' ')
        })
    {
        next
    } else {
        "/admin/"
    }
}

pub(super) fn login_required(request: &hyper::http::request::Parts) -> Reply {
    if matches!(request.method, hyper::Method::GET | hyper::Method::HEAD)
        && request
            .headers
            .get_all(ACCEPT)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|mime| {
                mime.split(';')
                    .next()
                    .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("text/html"))
            })
    {
        let next = local_next(
            request
                .uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/admin/"),
        );
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("next", next)
            .finish();
        return redirect(StatusCode::FOUND, format!("/login?{query}"));
    }
    super::admin::unauthorized()
}

pub(super) fn login_page(next: &str, warning: Option<&str>, status: StatusCode) -> Reply {
    let mut form = String::from("<p>Utilisez votre compte d’administration.</p>");
    if let Some(warning) = warning {
        form.push_str(r#"<p class="notice" role="alert">"#);
        super::admin::escape(&mut form, warning);
        form.push_str("</p>");
    }
    form.push_str(
        r#"<form class="form-stack" method="post" action="/login"><input type="hidden" name="next" value=""#,
    );
    super::admin::escape(&mut form, next);
    form.push_str(r#"">
<div class="field"><label for="login-username">Identifiant</label><input id="login-username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required></div>
<div class="field"><label for="login-password">Mot de passe</label><input id="login-password" type="password" name="password" autocomplete="current-password" required></div>
<button type="submit">Se connecter</button></form>"#);
    ui::guest("Connexion", &form, status)
}
