// SPDX-License-Identifier: LGPL-3.0-only

mod admin;
mod assets;

use crate::{configured_database, handle_request, monitoring, setting, PxeRequest, Routes};
use http::uri::Authority;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    header::{HeaderMap, HeaderName, HOST, LOCATION},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rusqlite::{Connection, OpenFlags};
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
    ip: Ipv4Addr,
    https_port: u16,
    public_host: Option<String>,
    requests: Semaphore,
    admin: admin::Console,
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
    let db_path = configured_database(config).ok_or("SQLite configuration unavailable")?;
    let (ip, public_host) = {
        let db = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        if !matches!(setting(&db, "pxe_enabled")?.as_str(), "" | "on") {
            return Err("PXE network is disabled".into());
        }
        // An absent or unrelated NIC must not expose the boot service.
        let ip: Ipv4Addr = setting(&db, "pxe_ip")?.parse()?;
        #[cfg(target_os = "linux")]
        validate_interface(ip, &setting(&db, "pxe_interface")?)?;
        if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return Err("Invalid PXE address".into());
        }
        let host = env::var("PXE_PUBLIC_HOST")
            .ok()
            .filter(|name| !name.is_empty());
        let host = host
            .map(|name| {
                let uri = Authority::from_str(&name)?;
                if uri.port().is_some() || uri.host() != name || name.contains('@') {
                    return Err("PXE_PUBLIC_HOST must be a hostname or IPv4 address".into());
                }
                Ok::<String, ErrorBox>(name)
            })
            .transpose()?;
        (ip, host)
    };
    let http_port = port("PXE_HTTP_PORT", 80)?;
    let https_port = port("PXE_HTTPS_PORT", 443)?;
    let site = Arc::new(Site {
        database: config.to_owned(),
        assets: assets::Assets::new(
            env::var_os("HTTP_ROOT")
                .map(PathBuf::from)
                .ok_or("HTTP_ROOT is required")?,
        )?,
        catalog: serde_json::from_str(include_str!("checkpoints.json"))?,
        ip,
        https_port,
        public_host,
        requests: Semaphore::new(8),
        admin: admin::Console::new(),
    });
    let tls = tls_config()?;
    let mut listeners = Vec::new();
    // Keep the loopback API used by the worker while exposing PXE only on its configured address.
    for address in [ip, Ipv4Addr::LOCALHOST]
        .into_iter()
        .take(if ip == Ipv4Addr::LOCALHOST { 1 } else { 2 })
    {
        listeners.push((TcpListener::bind((address, http_port)).await?, None));
        listeners.push((
            TcpListener::bind((address, https_port)).await?,
            Some(tls.clone()),
        ));
    }
    let connections = Arc::new(Semaphore::new(64));
    let mut servers = task::JoinSet::new();
    for (listener, tls) in listeners {
        servers.spawn(accept(listener, tls, site.clone(), connections.clone()));
    }
    notify_ready()?;
    println!("PXE Tools Rust HTTP/HTTPS ready on {ip}:{http_port} and {ip}:{https_port}");
    tokio::select! {
        result = servers.join_next() => result.ok_or("HTTP listeners unavailable")??,
        signal = tokio::signal::ctrl_c() => signal.map_err(Into::into),
    }
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
    let output = Command::new("/usr/sbin/ip")
        .args(["-j", "-4", "addr", "show", "dev", interface])
        .output()?;
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
    let directory = env::var_os("CREDENTIALS_DIRECTORY")
        .or_else(|| env::var_os("TLS_DIR"))
        .map(PathBuf::from)
        .ok_or("TLS_DIR is required")?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(directory.join("cert.pem"))?))
        .collect::<Result<Vec<_>, _>>()?;
    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(directory.join("key.pem"))?))?
            .ok_or("TLS private key missing")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
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
    tls: Option<TlsAcceptor>,
    site: Arc<Site>,
    connections: Arc<Semaphore>,
) -> Result<(), ErrorBox> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let (tls, site) = (tls.clone(), site.clone());
        task::spawn(async move {
            let _permit = permit;
            if let Some(tls) = tls {
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
    let service = service_fn(|request| {
        let site = site.clone();
        async move { Ok::<_, Infallible>(dispatch(request, peer.ip(), secure, &site).await) }
    });
    let connection = http1::Builder::new()
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
    if path == "/healthz" && readable {
        return plain(StatusCode::OK, "ok\n");
    }
    if path == "/" && readable {
        let location = if secure {
            "/admin/".to_owned()
        } else {
            let host = site
                .public_host
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    single(&parts.headers, HOST.as_str())
                        .and_then(|value| value.parse::<Authority>().ok())
                        .filter(|authority| authority.host() == "localhost" && peer.is_loopback())
                        .map_or_else(|| site.ip.to_string(), |_| "localhost".to_owned())
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
    if matches!(path, "/admin/" | "/admin/devices") && readable {
        if !secure {
            return plain(StatusCode::NOT_FOUND, "Not found\n");
        }
        return site.admin.serve(&parts, peer, &site.database).await;
    }

    if readable {
        if let Some(reply) = site
            .assets
            .serve(path, &parts.headers, parts.method == Method::HEAD)
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
