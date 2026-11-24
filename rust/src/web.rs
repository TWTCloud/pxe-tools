// SPDX-License-Identifier: LGPL-3.0-only

mod acme;
mod activity;
mod admin;
mod assets;
mod auth_proxy;
mod certificates;
mod device_operations;
mod device_settings;
mod devices;
mod images;
mod jobs;
mod onboarding;
mod presets;
mod sessions;
mod settings;
mod setup;
mod winpe;

pub(crate) use setup::adopt_existing_database;

use crate::{configured_database, handle_request, monitoring, setting, PxeRequest, Routes};
use http::uri::Authority;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    header::{
        HeaderMap, HeaderName, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, ORIGIN, USER_AGENT,
    },
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rusqlite::OpenFlags;
use std::{
    convert::Infallible,
    env,
    error::Error,
    fs::File,
    io::{self, BufReader, Cursor},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task,
    time::timeout,
};
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

type ErrorBox = Box<dyn Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, io::Error>;
type Reply = Response<Body>;

struct Site {
    database: PathBuf,
    assets: assets::Assets,
    catalog: monitoring::Catalog,
    pxe_ip: Option<Ipv4Addr>,
    https_port: u16,
    http_port: u16,
    winpe_client: Option<Ipv4Addr>,
    public_host: Option<String>,
    requests: Semaphore,
    admin: admin::Console,
    setup: setup::Wizard,
    tls: Arc<certificates::Certificates>,
    acme_challenge: Arc<acme::ChallengeResponse>,
}

pub fn serve(config: &Path) -> Result<(), ErrorBox> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(12)
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

async fn run(config: &Path) -> Result<(), ErrorBox> {
    let pxe_ip = active_pxe_address(config)?;
    let public_host = env::var("PXE_PUBLIC_HOST")
        .ok()
        .filter(|name| !name.is_empty())
        .map(|name| {
            let uri = Authority::from_str(&name)?;
            if uri.port().is_some() || uri.host() != name || name.contains('@') {
                return Err("PXE_PUBLIC_HOST must be a hostname or IPv4 address".into());
            }
            Ok::<String, ErrorBox>(name)
        })
        .transpose()?;
    let http_port = port("PXE_HTTP_PORT", 80)?;
    let https_port = port("PXE_HTTPS_PORT", 443)?;
    let default_tls = tls_config().map_err(|error| format!("TLS configuration: {error}"))?;
    let tls = Arc::new(certificates::Certificates::new(
        default_tls,
        public_host.clone(),
    )?);
    let acme_challenge = Arc::new(acme::ChallengeResponse::default());
    let site = Arc::new(Site {
        database: config.to_owned(),
        assets: assets::Assets::new(
            env::var_os("HTTP_ROOT")
                .map(PathBuf::from)
                .ok_or("HTTP_ROOT is required")?,
        )?,
        catalog: serde_json::from_str(include_str!("checkpoints.json"))?,
        pxe_ip,
        https_port,
        http_port,
        winpe_client: winpe::configured_client()?,
        public_host,
        requests: Semaphore::new(8),
        admin: admin::Console::new(),
        setup: setup::Wizard::new(),
        tls,
        acme_challenge,
    });
    let mut listeners = Vec::new();
    // Keep the loopback API used by the worker while exposing PXE only on its configured address.
    for address in std::iter::once(Ipv4Addr::LOCALHOST).chain(pxe_ip.filter(|ip| !ip.is_loopback()))
    {
        listeners.push((TcpListener::bind((address, http_port)).await?, false));
        listeners.push((TcpListener::bind((address, https_port)).await?, true));
    }
    let connections = Arc::new(Semaphore::new(64));
    let mut servers = task::JoinSet::new();
    for (listener, tls) in listeners {
        servers.spawn(accept(listener, tls, site.clone(), connections.clone()));
    }
    let tls = site.tls.clone();
    let challenge = site.acme_challenge.clone();
    task::spawn(async move { acme::run(tls.acme_configuration(), &challenge, &tls).await });
    notify_ready().map_err(|error| format!("Systemd readiness notification: {error}"))?;
    let ip = pxe_ip.unwrap_or(Ipv4Addr::LOCALHOST);
    println!("PXE Tools Rust HTTP/HTTPS ready on {ip}:{http_port} and {ip}:{https_port}");
    tokio::select! {
        result = servers.join_next() => result.ok_or("HTTP listeners unavailable")??,
        signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
    }
}

fn active_pxe_address(config: &Path) -> Result<Option<Ipv4Addr>, ErrorBox> {
    match std::fs::symlink_metadata(config) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let path = configured_database(config).ok_or("SQLite configuration unavailable")?;
    let db = crate::connect(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let enabled = setting(&db, "pxe_enabled")?;
    if enabled == "off" {
        return Ok(None);
    }
    let address = setting(&db, "pxe_ip")?;
    if enabled.is_empty() && address.is_empty() {
        return Ok(None);
    }
    if !matches!(enabled.as_str(), "" | "on") {
        return Err("Invalid PXE activation setting".into());
    }
    let ip: Ipv4Addr = address.parse()?;
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return Err("Invalid PXE address".into());
    }
    #[cfg(target_os = "linux")]
    validate_interface(ip, &setting(&db, "pxe_interface")?)?;
    Ok(Some(ip))
}

#[cfg(target_os = "linux")]
fn validate_interface(ip: Ipv4Addr, interface: &str) -> Result<(), ErrorBox> {
    use serde_json::Value;
    use std::process::Command;

    if ip.is_loopback()
        || ip.octets()[0] >= 240
        || interface.is_empty()
        || interface.len() > 64
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err("Invalid PXE interface or address".into());
    }
    let output = Command::new("/usr/bin/ip")
        .args(["-j", "-4", "addr", "show", "dev", interface])
        .output()
        .map_err(|error| format!("PXE interface inspection: {error}"))?;
    if output.status.success() {
        let links: Vec<Value> = serde_json::from_slice(&output.stdout)?;
        let address = ip.to_string();
        if let [link] = links.as_slice() {
            if link["ifname"] == interface
                && link["addr_info"].as_array().is_some_and(|addresses| {
                    addresses
                        .iter()
                        .any(|entry| entry["family"] == "inet" && entry["local"] == address)
                })
            {
                return Ok(());
            }
        }
    }
    Err("PXE address is not assigned to the selected interface".into())
}

fn port(name: &str, default: u16) -> Result<u16, ErrorBox> {
    let configured = env::var(name).map_or(Ok(default), |value| value.parse::<u16>())?;
    if configured == 0 {
        return Err(format!("Invalid TCP port in {name}").into());
    }
    Ok(configured)
}

fn tls_config() -> Result<TlsAcceptor, ErrorBox> {
    let directory = credential_directory()?;
    let open = |name| {
        let path = directory.join(name);
        File::open(&path)
            .map(BufReader::new)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))
    };
    let certs = rustls_pemfile::certs(&mut open("cert.pem")?).collect::<Result<Vec<_>, _>>()?;
    let private_key =
        rustls_pemfile::private_key(&mut open("key.pem")?)?.ok_or("TLS private key missing")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn credential_directory() -> Result<PathBuf, ErrorBox> {
    env::var_os("CREDENTIALS_DIRECTORY")
        .or_else(|| env::var_os("TLS_DIR"))
        .map(PathBuf::from)
        .ok_or_else(|| "TLS_DIR is required".into())
}

#[cfg(target_os = "linux")]
fn notify_ready() -> io::Result<()> {
    use std::os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    };
    if let Some(socket) = env::var_os("NOTIFY_SOCKET") {
        let address = if let Some(name) = socket.as_bytes().strip_prefix(b"@") {
            SocketAddr::from_abstract_name(name)?
        } else {
            SocketAddr::from_pathname(socket)?
        };
        UnixDatagram::unbound()?.send_to_addr(b"READY=1", &address)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn notify_ready() -> io::Result<()> {
    Ok(())
}

async fn accept(
    listener: TcpListener,
    tls: bool,
    site: Arc<Site>,
    connections: Arc<Semaphore>,
) -> Result<(), ErrorBox> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let site = site.clone();
        task::spawn(async move {
            let _permit = permit;
            if tls {
                let tls = site.tls.acceptor();
                if let Ok(Ok(stream)) = timeout(Duration::from_secs(10), tls.accept(stream)).await {
                    connection(stream, peer, true, site).await;
                }
            } else {
                connection::<TcpStream>(stream, peer, false, site).await;
            }
        });
    }
}

async fn connection<S>(stream: S, peer: SocketAddr, secure: bool, site: Arc<Site>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let service = service_fn(|request: Request<Incoming>| {
        let site = site.clone();
        async move {
            let grub = !secure
                && single(request.headers(), USER_AGENT.as_str())
                    .is_some_and(|agent| agent.starts_with("GRUB "));
            let asset = if grub && request.uri().path().starts_with("/netboot/") {
                match request.uri().path().rsplit('/').next() {
                    Some("linux") => Some("linux"),
                    Some("initrd.gz") => Some("initrd.gz"),
                    Some("firmware.cpio.gz") => Some("firmware.cpio.gz"),
                    _ => None,
                }
            } else {
                None
            };
            let reply = dispatch(request, peer.ip(), secure, &site).await;
            if let Some(asset) = asset {
                let length = single(reply.headers(), CONTENT_LENGTH.as_str()).unwrap_or("-");
                println!(
                    "PXE GRUB asset={asset} status={} bytes={length}",
                    reply.status().as_u16()
                );
            }
            Ok::<_, Infallible>(reply)
        }
    });
    let connection = http1::Builder::new()
        // GRUB 2.12 matches Content-Length case-sensitively in its HTTP
        // client. Secure Boot verification requires a known kernel size.
        .title_case_headers(true)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32 * 1024)
        .serve_connection(TokioIo::new(stream), service);
    // A stalled receiver can keep at most one connection slot for this period.
    let _ = timeout(Duration::from_secs(300), connection).await;
}

async fn dispatch(
    request: Request<Incoming>,
    peer: IpAddr,
    secure: bool,
    site: &Arc<Site>,
) -> Reply {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    let readable = matches!(parts.method, Method::GET | Method::HEAD);
    if !secure && parts.method == Method::GET && path.starts_with(acme::PREFIX) {
        return site
            .acme_challenge
            .serve(path, single(&parts.headers, HOST.as_str()));
    }
    if path == "/healthz" && readable {
        return plain(StatusCode::OK, "ok\n");
    }
    if path == "/" && readable {
        let location = if secure {
            "/admin/".to_owned()
        } else {
            let host = site
                .pxe_ip
                .and(site.public_host.as_deref())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    single(&parts.headers, HOST.as_str())
                        .and_then(|value| value.parse::<Authority>().ok())
                        .filter(|authority| authority.host() == "localhost" && peer.is_loopback())
                        .map_or_else(
                            || site.pxe_ip.unwrap_or(Ipv4Addr::LOCALHOST).to_string(),
                            |_| "localhost".to_owned(),
                        )
                });
            let port = if site.https_port == 443 {
                String::new()
            } else {
                format!(":{}", site.https_port)
            };
            format!("https://{host}{port}/admin/")
        };
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(LOCATION, location)
            .body(bytes(""))
            .expect("valid redirect");
    }
    if secure && readable && path == "/admin/" && peer.is_loopback() && site.pxe_ip.is_none() {
        if let Some(reply) = site.setup.landing(&site.database).await {
            return reply;
        }
    }
    if matches!(path, "/init" | "/init/welcome" | "/init/db" | "/init/admin") {
        if !secure || !peer.is_loopback() || site.pxe_ip.is_some() {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        if readable {
            return site.setup.page(path, &site.database).await;
        }
        if parts.method == Method::POST && matches!(path, "/init/db" | "/init/admin") {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            let form = match read_form(&parts.headers, body, 2048).await {
                Ok(form) => form,
                Err(reply) => return reply,
            };
            return site.setup.submit(path, &site.database, &form).await;
        }
        return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
    }
    if matches!(path, "/login" | "/logout") {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        if path == "/login" && readable {
            return site.admin.login(&parts, peer, &site.database, None).await;
        }
        if parts.method != Method::POST {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
        }
        if !admin_origin(&parts.headers, peer, site) {
            return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
        }
        if path == "/logout" {
            return site.admin.logout(&parts.headers).await;
        }
        let form = match read_form(&parts.headers, body, 2048).await {
            Ok(form) => form,
            Err(reply) => return reply,
        };
        return site
            .admin
            .login(&parts, peer, &site.database, Some(form))
            .await;
    }
    if matches!(path, "/admin/" | "/admin/devices") && readable {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        return site
            .admin
            .serve(&parts, peer, &site.database, admin::Action::Devices)
            .await;
    }
    if path == "/machines" && readable {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        return setup::redirect(StatusCode::FOUND, "/admin/devices");
    }
    if path == "/presets/pull-github" && parts.method == Method::POST {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        if !admin_origin(&parts.headers, peer, site) {
            return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
        }
        return site
            .admin
            .serve(&parts, peer, &site.database, admin::Action::PullPresets)
            .await;
    }
    if (path == "/machines/new" && readable)
        || (path == "/machines" && parts.method == Method::POST)
    {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        let form = if readable {
            None
        } else {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            match read_form(&parts.headers, body, 1024).await {
                Ok(form) => Some(form),
                Err(reply) => return reply,
            }
        };
        return site
            .admin
            .serve(&parts, peer, &site.database, admin::Action::Register(form))
            .await;
    }
    if let Some(view) = jobs::View::for_route(path, parts.uri.query().unwrap_or_default()) {
        if !secure || !readable {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        return site
            .admin
            .serve(&parts, peer, &site.database, admin::Action::Jobs(view))
            .await;
    }
    if let Some(route) = devices::route(path) {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        let form = if readable {
            None
        } else if let Some(limit) = route.form_limit(&parts.method) {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            match read_form(&parts.headers, body, limit).await {
                Ok(form) => Some(form),
                Err(reply) => return reply,
            }
        } else {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
        };
        return site
            .admin
            .serve(
                &parts,
                peer,
                &site.database,
                admin::Action::Device(route, form),
            )
            .await;
    }
    if let Some(view) = activity::View::for_route(path) {
        if !secure || !readable {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        return site
            .admin
            .serve(&parts, peer, &site.database, admin::Action::Activity(view))
            .await;
    }
    if onboarding::is_route(path) {
        if !secure || !peer.is_loopback() || site.pxe_ip.is_some() {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        let endpoint = path.to_owned();
        let form = if parts.method == Method::POST {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            match read_form(&parts.headers, body, 2048).await {
                Ok(form) => Some(form),
                Err(reply) => return reply,
            }
        } else if readable {
            None
        } else {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
        };
        return site
            .admin
            .serve(
                &parts,
                peer,
                &site.database,
                admin::Action::Setup(endpoint, form),
            )
            .await;
    }
    if matches!(
        path,
        certificates::ROUTE | certificates::ACME_ROUTE | images::ROUTE | presets::ROUTE
    ) {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        let form = if parts.method == Method::POST {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            let limit = if path == certificates::ROUTE {
                certificates::MAX_FORM
            } else if path == presets::ROUTE {
                2048
            } else {
                256
            };
            match read_form(&parts.headers, body, limit).await {
                Ok(form) => Some(form),
                Err(reply) => return reply,
            }
        } else if readable {
            None
        } else {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
        };
        let action = match (path, form) {
            (certificates::ROUTE, form) => admin::Action::Certificates(site.tls.clone(), form),
            (certificates::ACME_ROUTE, Some(form)) => admin::Action::Acme(site.tls.clone(), form),
            (certificates::ACME_ROUTE, None) => {
                return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n")
            }
            (presets::ROUTE, form) => admin::Action::Presets(form),
            (_, form) => admin::Action::Images(form),
        };
        return site.admin.serve(&parts, peer, &site.database, action).await;
    }
    if path == "/settings/https" && secure && readable {
        return setup::redirect(StatusCode::FOUND, certificates::ROUTE);
    }
    if let Some(route) = settings::Route::for_path(path) {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        let form = if readable {
            None
        } else if parts.method == Method::POST {
            if !admin_origin(&parts.headers, peer, site) {
                return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
            }
            match read_form(&parts.headers, body, 2048).await {
                Ok(form) => Some(form),
                Err(reply) => return reply,
            }
        } else {
            return plain(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed\n");
        };
        return site
            .admin
            .serve(
                &parts,
                peer,
                &site.database,
                admin::Action::Settings(route, form),
            )
            .await;
    }
    if matches!(path, admin::DEVICE_SETTINGS | "/settings/terminology")
        && parts.method == Method::POST
        && secure
    {
        if !admin_origin(&parts.headers, peer, site) {
            return plain(StatusCode::FORBIDDEN, "Invalid origin\n");
        }
        let data = match read_form(&parts.headers, body, 256).await {
            Ok(data) => data,
            Err(reply) => return reply,
        };
        let mut fields = form_urlencoded::parse(&data);
        let update = match (fields.next(), fields.next()) {
            (Some((key, value)), None) if key == "ui_device_term" => admin::device_term(&value),
            _ => None,
        };
        let Some(update) = update else {
            return plain(StatusCode::BAD_REQUEST, "Invalid device label\n");
        };
        return site
            .admin
            .serve(
                &parts,
                peer,
                &site.database,
                admin::Action::Terminology(
                    update,
                    if path == admin::DEVICE_SETTINGS {
                        "/admin/devices"
                    } else {
                        "/settings"
                    },
                ),
            )
            .await;
    }

    let Some(server) = site.pxe_ip else {
        return plain(StatusCode::NOT_FOUND, "Not found\n");
    };
    let winpe = winpe::allowed(site.winpe_client, peer);
    if winpe && readable {
        if path == winpe::BOOT {
            return winpe::script(server, site.http_port);
        }
        if path == "/boot.ipxe" && parts.uri.query() != Some("menu=debian") {
            return winpe::menu(server, site.http_port);
        }
    }
    if readable {
        if let Some(reply) = site
            .assets
            .serve(path, &parts.headers, parts.method == Method::HEAD, winpe)
            .await
        {
            return reply;
        }
    }
    let dynamic = matches!(path, "/preseed.php" | "/grub.php")
        || path.starts_with("/api/")
        || path.starts_with("/pxe/postboot/");
    if !dynamic {
        return plain(StatusCode::NOT_FOUND, "Not found\n");
    }

    let Ok(_permit) = site.requests.try_acquire() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "Busy\n");
    };
    // Legacy CPL callbacks have smaller limits inside their respective handlers.
    let data = match timeout(
        Duration::from_secs(15),
        Limited::new(body, crate::discovery::MAX_BODY).collect(),
    )
    .await
    {
        Ok(Ok(data)) => data.to_bytes(),
        Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
            return plain(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large\n");
        }
        Ok(Err(_)) => return plain(StatusCode::BAD_REQUEST, "Invalid request body\n"),
        Err(_) => return plain(StatusCode::REQUEST_TIMEOUT, "Request timeout\n"),
    };
    let uri = parts
        .uri
        .path_and_query()
        .map_or(path, |value| value.as_str())
        .to_owned();
    let method = tiny_http::Method::from_str(parts.method.as_str()).expect("valid HTTP method");
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let site = site.clone();
    let result = task::spawn_blocking(move || {
        let mut body = Cursor::new(data);
        let mut request = PxeRequest {
            uri,
            method,
            headers,
            body: &mut body,
        };
        handle_request(
            &mut request,
            &Routes::Guided(&site.database),
            &site.catalog,
            Some(peer),
        )
    })
    .await;
    let Ok(result) = result else {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "Request failed\n");
    };
    let status = result.status_code().0;
    let mut reply = Response::builder()
        .status(status)
        .header("X-PXE-Backend", "rust-guided");
    for header in result.headers() {
        reply = reply.header(header.field.as_str().as_str(), header.value.as_str());
    }
    let body = result.into_reader().into_inner();
    let route = match path {
        "/api/discovery" => Some("/api/discovery"),
        "/preseed.php" => Some("/preseed.php"),
        "/api/install-end" => Some("/api/install-end"),
        "/api/machine-ready" => Some("/api/machine-ready"),
        path if path.starts_with("/pxe/postboot/") => Some("/pxe/postboot/"),
        _ => None,
    };
    if let Some(route) = route {
        println!("PXE request peer={peer} route={route} status={status}");
    }
    // Record the actual receipt status and response length, with no bearer token or query values.
    if path == "/api/internal/checkpoint"
        && parts.uri.query().is_some_and(|query| {
            let args = crate::parse_query(query.as_bytes());
            crate::param(&args, "code") == "os_first_boot" && crate::param(&args, "ack") == "1"
        })
    {
        println!(
            "PXE first boot peer={peer} status={status} bytes={}",
            body.len()
        );
    }
    reply.body(bytes(body)).expect("valid application response")
}

async fn read_form(headers: &HeaderMap, body: Incoming, max: usize) -> Result<Bytes, Reply> {
    let is_form = single(headers, CONTENT_TYPE.as_str())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return Err(plain(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected an HTML form\n",
        ));
    }
    match timeout(Duration::from_secs(5), Limited::new(body, max).collect()).await {
        Ok(Ok(data)) => Ok(data.to_bytes()),
        _ => Err(plain(StatusCode::BAD_REQUEST, "Invalid form data\n")),
    }
}

fn admin_origin(headers: &HeaderMap, peer: IpAddr, site: &Site) -> bool {
    let forwarded = site.admin.trusted_proxy(peer) && headers.contains_key("x-forwarded-host");
    let header = if forwarded {
        "x-forwarded-host"
    } else {
        HOST.as_str()
    };
    let Some(host) = single(headers, header)
        .filter(|raw| !raw.contains('@'))
        .and_then(|raw| raw.parse::<Authority>().ok())
    else {
        return false;
    };
    let name = host.host();
    let external_port = host.port_u16().unwrap_or(443);
    if (!forwarded && external_port != site.https_port)
        || !(site.pxe_ip.is_some_and(|ip| name == ip.to_string())
            || name.eq_ignore_ascii_case("localhost")
            || name == "127.0.0.1"
            || site
                .public_host
                .as_ref()
                .is_some_and(|v| v.eq_ignore_ascii_case(name)))
    {
        return false;
    }
    let expected = if external_port == 443 {
        format!("https://{name}")
    } else {
        format!("https://{host}")
    };
    single(headers, ORIGIN.as_str()).is_some_and(|origin| origin.eq_ignore_ascii_case(&expected))
}

fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(first)
}

fn bytes(value: impl Into<Bytes>) -> Body {
    Full::new(value.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn plain(status: StatusCode, value: &'static str) -> Reply {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(bytes(value))
        .expect("valid text response")
}
