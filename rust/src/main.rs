// SPDX-License-Identifier: LGPL-3.0-only

mod catalog;
mod discovery;
mod disk_identity;
mod grub;
mod images;
mod install;
mod instance_secrets;
mod menu_store;
mod migrations;
mod monitoring;
mod postboot;
mod preseed;
mod preset_import;
mod pxe;
mod web;
mod worker;

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Response, Server};

const MONITORING: &str = "/api/monitoring/installs";
const BOOT_SELECTED: &str = "/api/boot-selected";
const CLIENT_IP: &str = "X-Pxe-Client-Ip";
const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";
type ApiResult = rusqlite::Result<(u16, Value)>;
type HttpResponse = Response<std::io::Cursor<Vec<u8>>>;

struct PxeRequest<'a> {
    uri: String,
    method: Method,
    headers: Vec<(String, String)>,
    body: &'a mut dyn Read,
}

enum Routes<'a> {
    Full(&'a Path),
    Monitor(&'a Path),
    Guided(&'a Path),
}

#[derive(Deserialize)]
struct DatabaseConfig {
    driver: String,
    path: Option<PathBuf>,
}

fn random_token() -> std::io::Result<String> {
    random_hex::<16>()
}

fn random_hex<const N: usize>() -> std::io::Result<String> {
    let mut random = [0; N];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn configured_database(config: &Path) -> Option<PathBuf> {
    let config: DatabaseConfig = serde_json::from_slice(&fs::read(config).ok()?).ok()?;
    if !config.driver.eq_ignore_ascii_case("sqlite") {
        return None;
    }
    let path = config.path?;
    (path.is_absolute()
        && !path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|b| b.is_ascii_control())
        && path.is_file())
    .then_some(path)
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if let [flag, config] = args.as_slice() {
        if flag == "--migrate-schema" && Path::new(config).is_absolute() {
            return migrations::schema(Path::new(config));
        }
        if flag == "--migrate-preset-network" && Path::new(config).is_absolute() {
            return migrations::preset_network(Path::new(config));
        }
        if flag == "--migrate-preset-distributions" && Path::new(config).is_absolute() {
            return migrations::preset_distributions(Path::new(config));
        }
        if flag == "--migrate-image-metadata" && Path::new(config).is_absolute() {
            return migrations::image_metadata(Path::new(config));
        }
        if flag == "--migrate-assigned-presets" && Path::new(config).is_absolute() {
            return migrations::assigned_presets(Path::new(config));
        }
        if flag == "--migrate-network-settings" && Path::new(config).is_absolute() {
            return migrations::network_settings(Path::new(config));
        }
        if flag == "--refresh-catalog" && Path::new(config).is_absolute() {
            return catalog::refresh(Path::new(config));
        }
        if flag == "--import-preset" && Path::new(config).is_absolute() {
            return preset_import::run(Path::new(config));
        }
        if flag == "--recover-interrupted-jobs" && Path::new(config).is_absolute() {
            return worker::recover(Path::new(config));
        }
        if flag == "--render-postboot" {
            return postboot::render(Path::new(config));
        }
        if flag == "--serve-guided" && Path::new(config).is_absolute() {
            return web::serve(Path::new(config));
        }
    }
    if let [flag, config, path] = args.as_slice() {
        if flag == "--work-guided" {
            return worker::service::run(Path::new(config), Path::new(path));
        }
        if flag == "--run-ansible-retry" {
            let id = path
                .to_str()
                .ok_or("Invalid Ansible retry job ID")?
                .parse()?;
            return worker::ansible::retry(Path::new(config), id);
        }
        if flag == "--run-power-job" {
            let id = path.to_str().ok_or("Invalid power job ID")?.parse()?;
            return worker::power::run(Path::new(config), id);
        }
        if flag == "--adopt-existing-sqlite" && Path::new(config).is_absolute() {
            return web::adopt_existing_database(Path::new(config), Path::new(path));
        }
        if Path::new(config).is_absolute() && Path::new(path).is_absolute() {
            if flag == "--migrate-netboot-files" {
                return migrations::legacy_image_files(Path::new(config), Path::new(path));
            }
            if flag == "--migrate-sqlite" {
                return migrations::upgrade(Path::new(config), Path::new(path));
            }
        }
    }
    if let [flag, database, id, scripts] = args.as_slice() {
        if flag == "--schedule-worker-jobs" {
            let family = id.to_str().ok_or("Invalid job family")?;
            return worker::schedule::run(Path::new(database), family, Path::new(scripts));
        }
        if flag == "--run-bootstrap-job" {
            let id = id.to_str().ok_or("Invalid bootstrap job ID")?.parse()?;
            return worker::bootstrap::run(Path::new(database), id, Path::new(scripts));
        }
        if flag == "--run-image-download" {
            let id = id.to_str().ok_or("Invalid image ID")?.parse()?;
            return worker::download::run(Path::new(database), id, Path::new(scripts));
        }
    }
    if let [flag, id, job, db] = args.as_slice() {
        if flag == "--reserve-image-deletion" {
            let id = id.to_str().ok_or("Invalid image ID")?.parse()?;
            let job = job.to_str().ok_or("Invalid job ID")?.parse()?;
            return images::reserve_deletion(Path::new(db), id, job);
        }
    }
    if let [flag, database, id, templates, output] = args.as_slice() {
        if flag == "--run-postboot-job" {
            let id = id.to_str().ok_or("Invalid postboot job ID")?.parse()?;
            return worker::postboot::run(
                Path::new(database),
                id,
                Path::new(templates),
                Path::new(output),
            );
        }
    }
    let (routes, socket) = match args.as_slice() {
        [db, socket] if Path::new(db).is_absolute() && Path::new(db).is_file() => {
            (Routes::Full(Path::new(db)), socket)
        }
        [flag, config, socket] if flag == "--monitor-only" && Path::new(config).is_absolute() => {
            (Routes::Monitor(Path::new(config)), socket)
        }
        [flag, config, socket] if flag == "--guided" && Path::new(config).is_absolute() => {
            (Routes::Guided(Path::new(config)), socket)
        }
        _ => return Err(
            "Usage: pxe-tools-rust [--monitor-only|--guided] /absolute/path/to/database-or-config /private/dir/http.sock".into(),
        ),
    };
    let socket = Path::new(socket);
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
            let routes = &routes;
            scope.spawn(move || {
                for mut request in server.incoming_requests() {
                    let headers = request
                        .headers()
                        .iter()
                        .map(|entry| (entry.field.as_str().to_string(), entry.value.to_string()))
                        .collect();
                    let mut input = PxeRequest {
                        uri: request.url().to_owned(),
                        method: request.method().clone(),
                        headers,
                        body: request.as_reader(),
                    };
                    // This legacy listener only accepts requests on its private
                    // Unix socket. nginx supplies the original client address.
                    let peer =
                        request_header(&input, CLIENT_IP).and_then(|value| value.parse().ok());
                    let response = handle_request(&mut input, routes, catalog, peer);
                    let response = if matches!(routes, Routes::Guided(_)) {
                        response.with_header(header("X-PXE-Backend", "rust-guided"))
                    } else {
                        response
                    };
                    let _ = request.respond(response);
                }
            });
        }
    });
    Ok(())
}

fn handle(
    request: &mut PxeRequest<'_>,
    routes: &Routes<'_>,
    catalog: &monitoring::Catalog,
    ip: Option<IpAddr>,
) -> rusqlite::Result<HttpResponse> {
    let uri = request.uri.clone();
    let (path, query) = uri.split_once('?').unwrap_or((&uri, ""));
    let method = request.method.clone();
    if matches!(routes, Routes::Monitor(_)) && (method != Method::Get || path != MONITORING) {
        return Ok(not_found(&method, path));
    }
    let configured_db;
    let path_to_db = match routes {
        Routes::Full(db) => *db,
        Routes::Monitor(config) | Routes::Guided(config) => {
            // Read each time so an atomic wizard/administrator change takes effect
            // immediately and requests cannot keep going to the previous database.
            let Some(db) = configured_database(config) else {
                if method == Method::Post
                    && matches!(
                        path,
                        "/api/internal/dhcp-event" | "/api/internal/dnsmasq-event"
                    )
                {
                    return Ok(internal_reply(response(200, TEXT, "")));
                }
                return Ok(response(
                    503,
                    JSON,
                    r#"{"error":"SQLite configuration unavailable"}"#,
                ));
            };
            configured_db = db;
            &configured_db
        }
    };
    match (method, path) {
        (Method::Get, MONITORING) => {
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let subnet = setting(&db, "pxe_subnet")?;
            let result = if matches!(ip, Some(IpAddr::V4(ip)) if ip.is_loopback())
                || in_subnet(ip, &subnet)
            {
                let snapshot = monitoring::snapshot(&mut db, catalog, now())?;
                response(
                    200,
                    JSON,
                    serde_json::to_string(&snapshot).expect("serializable snapshot"),
                )
            } else {
                json_response(failure(403, "forbidden"))?
            };
            let result = result.with_header(header("Cache-Control", "no-store"));
            Ok(match routes {
                Routes::Full(_) | Routes::Guided(_) => result,
                Routes::Monitor(_) => result.with_header(header("X-PXE-Monitor-Backend", "rust")),
            })
        }
        (Method::Get, BOOT_SELECTED) => {
            let db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            if !in_subnet(ip, &setting(&db, "pxe_subnet")?) {
                return Ok(response(404, TEXT, "# boot signal unavailable\n"));
            }
            let args = parse_query(query.as_bytes());
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let accepted = pxe::record_boot_selection(
                &mut db,
                param(&args, "boot_id"),
                param(&args, "token"),
                param(&args, "menu"),
            )?;
            Ok(if accepted {
                response(200, TEXT, "# boot selection recorded\n")
            } else {
                response(404, TEXT, "# boot selection rejected\n")
            })
        }
        (
            method @ (Method::Get | Method::Post),
            "/api/discovery"
            | "/api/discovery-action"
            | "/api/install-start"
            | "/api/install-end"
            | "/api/machine-ready",
        ) => {
            let args = parse_query(query.as_bytes());
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            if path == "/api/discovery" {
                let phase = param(&args, "phase");
                if !phase.is_empty() && phase != "0" {
                    let body = pxe::discovery_phase(&mut db, phase, param(&args, "mac"))?;
                    return json_response(Ok((200, body)));
                }
            }
            let form_data = method == Method::Post
                && request_header(request, "Content-Type").is_some_and(|ct| {
                    ct.split(';').next().is_some_and(|ty| {
                        ty.trim()
                            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                    })
                });
            let cap = if path == "/api/discovery" {
                discovery::MAX_BODY
            } else {
                65_536
            };
            let body = if path == "/api/discovery" || form_data {
                match read_body(request, cap + 1) {
                    Ok(body) if body.len() <= cap => body,
                    Ok(_) => {
                        return json_response(failure(
                            413,
                            if path == "/api/discovery" {
                                "discovery payload too large"
                            } else {
                                "form payload too large"
                            },
                        ))
                    }
                    Err(_) => return json_response(failure(400, "invalid request body")),
                }
            } else {
                Vec::new()
            };
            let form = if form_data {
                parse_query(&body)
            } else {
                Params::new()
            };
            if matches!(
                param(&form, "_method").to_ascii_uppercase().as_str(),
                "PUT" | "DELETE" | "PATCH"
            ) {
                return Ok(response(
                    404,
                    TEXT,
                    format!(
                        "404 Not Found: {} {path}\n",
                        param(&form, "_method").to_ascii_uppercase()
                    ),
                ));
            }
            let value = |key| {
                arg(&args, key)
                    .or_else(|| arg(&form, key))
                    .unwrap_or_default()
            };
            let mac = value("mac");
            let result = match path {
                "/api/discovery" => {
                    discovery::report(&mut db, ip, &body, arg(&form, "b64"), arg(&args, "b64"))
                }
                "/api/discovery-action" => discovery::poll(&mut db, mac),
                "/api/install-start" => install::start(
                    &mut db,
                    ip.is_some_and(|peer| {
                        peer == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                            || peer == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                    }),
                    mac,
                ),
                "/api/install-end" => {
                    let allowed = in_subnet(ip, &setting(&db, "pxe_subnet")?);
                    install::end(
                        &mut db,
                        allowed,
                        mac,
                        bearer(request),
                        value("status"),
                        param(&form, "ssh_host_fingerprint"),
                        param(&form, "first_boot") == "1",
                    )
                }
                "/api/machine-ready" => install::machine_ready(&mut db, mac),
                _ => unreachable!(),
            };
            json_response(result)
        }
        (
            Method::Get | Method::Post,
            "/api/disktest-job"
            | "/api/disktest-progress"
            | "/api/disktest-disk-progress"
            | "/api/disktest-end",
        )
        | (Method::Post, "/api/disktest-result" | "/api/disktest-smart") => {
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            pxe::disk_test::serve(&mut db, ip, path, query, request)
        }
        (Method::Get, "/wipe.sh")
        | (Method::Get | Method::Post, "/api/wipe-progress" | "/api/wipe-end") => {
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            pxe::wipe::serve(&mut db, ip, path, query, request)
        }
        (Method::Post, "/api/internal/dhcp-event" | "/api/internal/dnsmasq-event") => {
            let result = (|| -> rusqlite::Result<()> {
                let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                if !(ip.is_some_and(|ip| ip.is_loopback() || is_mapped_loopback(ip))
                    || in_subnet(ip, &setting(&db, "docker_internal_cidr")?))
                {
                    return Ok(());
                }
                let query = parse_query(query.as_bytes());
                let direct = path == "/api/internal/dhcp-event";
                let form = if !direct
                    && request_header(request, "Content-Type").is_some_and(|ct| {
                        ct.split(';').next().is_some_and(|ty| {
                            ty.trim()
                                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
                        })
                    }) {
                    match read_body(request, 4097) {
                        Ok(data) if data.len() <= 4096 => parse_query(&data),
                        _ => return Ok(()),
                    }
                } else {
                    Params::new()
                };
                let value = |key| {
                    arg(&query, key)
                        .or_else(|| arg(&form, key))
                        .unwrap_or_default()
                };
                let address = value("ip").parse::<std::net::Ipv4Addr>().ok();
                if direct || value("type") == "dhcp_proxy" {
                    pxe::boot_events::dhcp(&mut db, catalog, value("mac"), address, !direct)?;
                } else if let (Some(address), "tftp_serve") = (address, value("type")) {
                    pxe::boot_events::tftp(&mut db, catalog, address, value("file"))?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("DHCP/TFTP event write failed: {error}");
            }
            Ok(internal_reply(response(200, TEXT, "")))
        }
        (Method::Post, "/api/internal/checkpoint") => {
            let result = (|| -> rusqlite::Result<&'static str> {
                let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                let Some(ip) = ip.filter(|ip| {
                    ip.is_loopback()
                        || is_mapped_loopback(*ip)
                        || in_subnet(Some(*ip), &setting(&db, "pxe_subnet").unwrap_or_default())
                        || in_subnet(
                            Some(*ip),
                            &setting(&db, "docker_internal_cidr").unwrap_or_default(),
                        )
                }) else {
                    return Ok("");
                };
                let body = match read_body(request, install::CHECKPOINT_BODY_MAX) {
                    Ok(body) => body,
                    Err(_) => return Ok(""),
                };
                let args = parse_query(query.as_bytes());
                let proxy_headers_seen =
                    ["Forwarded", "X-Forwarded-For", "X-Real-IP"]
                        .iter()
                        .any(|name| {
                            request.headers.iter().any(|(field, value)| {
                                field.eq_ignore_ascii_case(name)
                                    && !matches!(value.as_str(), "" | "0")
                            })
                        });
                install::checkpoint(
                    &mut db,
                    catalog,
                    install::Checkpoint {
                        token: bearer(request),
                        mac: param(&args, "mac"),
                        code: param(&args, "code"),
                        level: param(&args, "level"),
                        acknowledge: param(&args, "ack") == "1",
                        ip,
                        proxy_headers_seen,
                        body: &body,
                    },
                )
            })();
            let receipt = result.unwrap_or_else(|error| {
                eprintln!("Checkpoint write failed: {error}");
                ""
            });
            Ok(internal_reply(response(200, TEXT, receipt)))
        }
        (Method::Post, "/api/internal/install-log") => {
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let allowed = in_subnet(ip, &setting(&db, "pxe_subnet")?);
            let args = parse_query(query.as_bytes());
            let body = read_body(request, install::LOG_CHUNK_MAX + 1).unwrap_or_default();
            let result = install::append_log(
                &mut db,
                allowed,
                bearer(request),
                decimal(param(&args, "install_id")),
                decimal(param(&args, "seq")),
                &body,
            )
            .or_else(|error| {
                eprintln!("Install log write failed: {error}");
                failure(500, "internal error")
            });
            Ok(internal_reply(json_response(result)?))
        }
        (Method::Get, "/api/task-phase") => {
            let args = parse_query(query.as_bytes());
            let db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let status = install::phase_for_request(
                &db,
                param(&args, "task"),
                decimal(param(&args, "id")),
                param(&args, "mac"),
                param(&args, "phase"),
                arg(&args, "status").unwrap_or("running"),
                arg(&args, "message"),
            )?;
            Ok(response(status, TEXT, ""))
        }
        (Method::Post, path)
            if path.starts_with("/api/internal/action/") && path.ends_with("/recompute") =>
        {
            let result = (|| -> rusqlite::Result<()> {
                let db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
                let route_id = path
                    .trim_start_matches("/api/internal/action/")
                    .trim_end_matches("/recompute");
                if !route_id.contains('/') {
                    let id = decimal(route_id);
                    if id > 0
                        && (ip.is_some_and(|ip| ip.is_loopback() || is_mapped_loopback(ip))
                            || in_subnet(ip, &setting(&db, "docker_internal_cidr")?))
                    {
                        install::recompute(&db, id)?;
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("Action recompute failed: {error}");
            }
            Ok(internal_reply(response(200, TEXT, "")))
        }
        (Method::Get, "/preseed.php") => {
            let args = parse_query(query.as_bytes());
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let source = match ip {
                Some(IpAddr::V4(ip)) => Some(ip),
                _ => None,
            };
            preseed::serve(&mut db, source, param(&args, "mac"))
        }
        (Method::Get, "/grub.php") => {
            let args = parse_query(query.as_bytes());
            let mut db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            grub::serve(&mut db, ip, param(&args, "mac"), param(&args, "arch"))
        }
        (Method::Get, path) if path.starts_with("/pxe/postboot/") => {
            let db = connect(path_to_db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            serve_postboot(&db, ip, path)
        }
        (method, path) => Ok(not_found(&method, path)),
    }
}

fn not_found(method: &Method, path: &str) -> HttpResponse {
    response(404, TEXT, format!("404 Not Found: {method} {path}\n"))
}

fn serve_postboot(
    db: &Connection,
    ip: Option<IpAddr>,
    path: &str,
) -> rusqlite::Result<HttpResponse> {
    let not_found = || response(404, "text/plain", "Not found\n");
    let Some((id, name)) = path.trim_start_matches("/pxe/postboot/").split_once('/') else {
        return Ok(not_found());
    };
    let mime = match name {
        "postboot.sh" => "text/x-shellscript",
        "pxe-postboot.service" => "text/plain",
        _ => return Ok(not_found()),
    };
    let id = decimal(id);
    if id <= 0
        || !in_subnet(ip, &setting(db, "pxe_subnet")?)
        || !install::application_file_allowed(db, id)?
    {
        return Ok(not_found());
    }
    let root = std::env::var_os("POSTBOOT_OUTPUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/pxe-tools/postboot".into());
    let (Ok(root), Ok(file)) = (
        root.canonicalize(),
        root.join(id.to_string()).join(name).canonicalize(),
    ) else {
        return Ok(not_found());
    };
    if !file.starts_with(&root) || !file.is_file() {
        return Ok(not_found());
    }
    let Ok(data) = fs::read(file) else {
        return Ok(not_found());
    };
    Ok(internal_reply(
        Response::from_data(data).with_header(header("Content-Type", mime)),
    ))
}

fn read_body(request: &mut PxeRequest<'_>, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut data = Vec::new();
    request.body.take(limit as u64).read_to_end(&mut data)?;
    Ok(data)
}

fn is_mapped_loopback(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback()))
}

fn in_subnet(ip: Option<IpAddr>, subnet: &str) -> bool {
    matches!(ip, Some(IpAddr::V4(ip)) if pxe::client_in_subnet(ip, subnet))
}

fn failure(status: u16, message: &str) -> ApiResult {
    Ok((status, json!({"error":message})))
}

fn json_response(result: ApiResult) -> rusqlite::Result<HttpResponse> {
    let (status, value) = result?;
    Ok(response(status, JSON, value.to_string()))
}

fn internal_reply(reply: HttpResponse) -> HttpResponse {
    reply
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
}

fn connect(path: &Path, mode: OpenFlags) -> rusqlite::Result<Connection> {
    let db = Connection::open_with_flags(path, mode | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    db.busy_timeout(Duration::from_secs(5))?;
    if mode.contains(OpenFlags::SQLITE_OPEN_READ_WRITE) {
        db.pragma_update(None, "foreign_keys", true)?;
    }
    Ok(db)
}

fn setting(db: &Connection, key: &str) -> rusqlite::Result<String> {
    let subnet = db
        .query_row("SELECT value FROM settings WHERE key = ?", [key], |row| {
            row.get::<_, Option<String>>(0)
        })
        .optional()?;
    Ok(subnet.flatten().unwrap_or_default())
}

fn request_header<'a>(request: &'a PxeRequest<'_>, name: &str) -> Option<&'a str> {
    let mut values = request
        .headers
        .iter()
        .filter(|(field, _)| field.eq_ignore_ascii_case(name));
    let value = values.next()?.1.as_str();
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

fn bearer<'a>(request: &'a PxeRequest<'_>) -> &'a str {
    let raw = request_header(request, "Authorization").unwrap_or_default();
    match raw.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("bearer ") => php_trim(&raw[7..]),
        _ => "",
    }
}

fn handle_request(
    request: &mut PxeRequest<'_>,
    routes: &Routes<'_>,
    catalog: &monitoring::Catalog,
    ip: Option<IpAddr>,
) -> HttpResponse {
    handle(request, routes, catalog, ip).unwrap_or_else(|error| {
        eprintln!("SQLite request failed: {error}");
        response(
            500,
            JSON,
            json!({"error": "SQLite request failed"}).to_string(),
        )
    })
}

type Params = HashMap<String, Option<String>>;

fn parse_query(query: &[u8]) -> Params {
    let mut args = Params::new();
    for (name, value) in form_urlencoded::parse(query).take(1000) {
        if let Some((name, suffix)) = name.split_once('[') {
            if suffix.contains(']') {
                args.insert(name.to_owned(), None);
                continue;
            }
        }
        args.insert(name.into_owned(), Some(value.into_owned()));
    }
    args
}

fn arg<'a>(args: &'a Params, key: &str) -> Option<&'a str> {
    args.get(key)
        .map(|value| value.as_deref().unwrap_or_default())
}

fn param<'a>(args: &'a Params, key: &str) -> &'a str {
    arg(args, key).unwrap_or_default()
}

fn decimal(value: &str) -> i64 {
    let s = php_trim(value);
    if let Ok(number) = s.parse::<i64>() {
        return number;
    }
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let end = digits.bytes().take_while(u8::is_ascii_digit).count();
    if end == 0 {
        return 0;
    }
    let abs = digits[..end].parse::<u64>().unwrap_or(u64::MAX);
    if negative {
        -(abs.min(i64::MAX as u64) as i64)
    } else {
        abs.min(i64::MAX as u64) as i64
    }
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

fn php_truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) => true,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !matches!(value.as_str(), "" | "0"),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
