// SPDX-License-Identifier: LGPL-3.0-only

mod monitoring;
mod pxe;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server};

const MONITORING: &str = "/api/monitoring/installs";
const BOOT_SELECTED: &str = "/api/boot-selected";
const DISCOVERY: &str = "/api/discovery";
const CLIENT_IP: &str = "X-Pxe-Client-Ip";
const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";
type HttpResponse = Response<std::io::Cursor<Vec<u8>>>;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [db, socket] = args.as_slice() else {
        return Err(
            "Usage: pxe-tools-rust /absolute/path/to/test.sqlite /private/dir/http.sock".into(),
        );
    };
    let db = Path::new(db);
    let socket = Path::new(socket);
    if !db.is_absolute() || !db.is_file() {
        return Err("An absolute path to an existing SQLite database is required".into());
    }
    if !socket.is_absolute()
        || socket.parent().is_none_or(|dir| {
            fs::metadata(dir).map_or(true, |meta| meta.permissions().mode() & 0o077 != 0)
        })
    {
        return Err("The Unix socket must be in a private directory".into());
    }
    let catalog = serde_json::from_str(include_str!("checkpoints.json"))?;
    let server = Server::http_unix(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    std::thread::scope(|scope| {
        for _ in 0..3 {
            let server = &server;
            let catalog = &catalog;
            scope.spawn(move || {
                for request in server.incoming_requests() {
                    let response = handle(&request, db, catalog).unwrap_or_else(|error| {
                        eprintln!("SQLite request failed: {error}");
                        response(
                            500,
                            JSON,
                            json!({"error": "SQLite request failed"}).to_string(),
                        )
                    });
                    let _ = request.respond(response);
                }
            });
        }
    });
    Ok(())
}

fn handle(
    request: &Request,
    path_to_db: &Path,
    catalog: &monitoring::Catalog,
) -> rusqlite::Result<HttpResponse> {
    let (path, query) = request.url().split_once('?').unwrap_or((request.url(), ""));
    let method = request.method();
    match (method, path) {
        (&Method::Get, MONITORING) => {
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let subnet = subnet(&db)?;
            let allowed = client_ip(request)
                .is_some_and(|ip| ip.is_loopback() || pxe::client_in_subnet(ip, &subnet));
            let reply = if allowed {
                let snapshot = monitoring::snapshot(&mut db, catalog, now())?;
                response(
                    200,
                    JSON,
                    serde_json::to_string(&snapshot).expect("serializable snapshot"),
                )
            } else {
                response(403, JSON, json!({"error": "forbidden"}).to_string())
            };
            Ok(reply.with_header(header("Cache-Control", "no-store")))
        }
        (&Method::Get, BOOT_SELECTED) => {
            let db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let subnet = subnet(&db)?;
            if !client_ip(request).is_some_and(|ip| pxe::client_in_subnet(ip, &subnet)) {
                return Ok(response(404, TEXT, "# boot signal unavailable\n"));
            }
            let args = parse_query(query);
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let accepted = pxe::record_boot_selection(
                &mut db,
                query_arg(&args, "boot_id"),
                query_arg(&args, "token"),
                query_arg(&args, "menu"),
            )?;
            Ok(if accepted {
                response(200, TEXT, "# boot selection recorded\n")
            } else {
                response(404, TEXT, "# boot selection rejected\n")
            })
        }
        (&Method::Get | &Method::Post, DISCOVERY) => {
            let args = parse_query(query);
            let phase = query_arg(&args, "phase");
            if phase.is_empty() || phase == "0" {
                return Ok(response(
                    501,
                    JSON,
                    json!({"error": "inventory discovery is not ported"}).to_string(),
                ));
            }
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let body = pxe::discovery_phase(&mut db, phase, query_arg(&args, "mac"))?;
            Ok(response(200, JSON, body.to_string()))
        }
        _ => Ok(response(
            404,
            TEXT,
            format!("404 Not Found: {method} {path}\n"),
        )),
    }
}

fn connect(path: &Path, mode: OpenFlags) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(path, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(Duration::from_secs(5))?;
    if mode == OpenFlags::SQLITE_OPEN_READ_WRITE {
        db.pragma_update(None, "foreign_keys", true)?;
    }
    Ok(db)
}

fn subnet(db: &Connection) -> rusqlite::Result<String> {
    let subnet = db
        .query_row(
            "SELECT value FROM settings WHERE key = 'pxe_subnet'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?;
    Ok(subnet.flatten().unwrap_or_default())
}

fn client_ip(request: &Request) -> Option<Ipv4Addr> {
    // The Unix socket is private. The proxy replaces this header with its actual peer address.
    let mut values = request
        .headers()
        .iter()
        .filter(|entry| entry.field.equiv(CLIENT_IP));
    let ip = values.next()?.value.as_str().parse().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(ip)
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut args = HashMap::new();
    for (name, value) in form_urlencoded::parse(query.as_bytes()).take(1000) {
        if let Some((name, suffix)) = name.split_once('[') {
            if suffix.contains(']') {
                // Array syntax must never leave a previously parsed scalar credential active.
                args.remove(name);
                continue;
            }
        }
        args.insert(name.into_owned(), value.into_owned());
    }
    args
}

fn query_arg<'a>(args: &'a HashMap<String, String>, key: &str) -> &'a str {
    args.get(key).map(String::as_str).unwrap_or_default()
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("valid static HTTP header")
}

fn response(code: u16, content_type: &str, body: impl Into<String>) -> HttpResponse {
    Response::from_string(body.into())
        .with_status_code(code)
        .with_header(header("Content-Type", content_type))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs() as i64
}

fn php_trim(s: &str) -> &str {
    s.trim_matches([' ', '\t', '\n', '\r', '\0', '\x0b'])
}

fn php_string(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(false) => String::new(),
        Value::Bool(true) => "1".to_owned(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => "Array".to_owned(),
    }
}
