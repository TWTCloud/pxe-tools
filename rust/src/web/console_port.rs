// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    accept, admin::escape, setup::redirect, ui::page, ui::ConsoleSection, ErrorBox, Reply, Site,
};
use hyper::{body::Bytes, StatusCode};
use rusqlite::Connection;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::TcpSocket,
    task::JoinSet,
    time::{sleep_until, Instant},
};

pub(super) const ROUTE: &str = "/settings/console";
const TRIAL_DURATION: Duration = Duration::from_secs(120);
const FILE: &str = "console-https-port";

fn parse(value: &str) -> Option<u16> {
    value.parse().ok().filter(|port| *port != 0)
}

pub(crate) fn configured(config: &Path) -> Result<u16, ErrorBox> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config.with_file_name(FILE))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return super::port("PXE_HTTPS_PORT", 443);
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 6 {
        return Err("Invalid HTTPS console port file".into());
    }
    let mut value = String::new();
    file.take(7).read_to_string(&mut value)?;
    parse(value.trim()).ok_or_else(|| "Invalid HTTPS console port".into())
}

pub(crate) fn set_configured(config: &Path, value: &str) -> Result<(), ErrorBox> {
    let port = parse(value).ok_or("Choisissez un port entre 1 et 65535.")?;
    if port == super::port("PXE_HTTP_PORT", 80)? {
        return Err("Ce port est utilisé pour le démarrage PXE en HTTP.".into());
    }
    persist(config, port)
}

fn persist(config: &Path, port: u16) -> Result<(), ErrorBox> {
    let temporary =
        config.with_file_name(format!(".console-https-port-{}", crate::random_token()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        writeln!(file, "{port}")?;
        file.sync_all()?;
        fs::rename(&temporary, config.with_file_name(FILE))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    } else if let Some(directory) = config.parent() {
        if let Err(error) = File::open(directory).and_then(|file| file.sync_all()) {
            eprintln!("Unable to flush the console port configuration directory: {error}");
        }
    }
    Ok(result?)
}

pub(super) struct ConsolePort(Mutex<State>);

struct State {
    active: Https,
    trial: Option<Trial>,
}

struct Https {
    port: u16,
    listeners: JoinSet<()>,
}

impl Https {
    fn bind(site: &Arc<Site>, port: u16) -> Result<Self, ErrorBox> {
        let sockets = site
            .addresses
            .iter()
            .map(|address| {
                let socket = TcpSocket::new_v4()?;
                socket.set_reuseaddr(true)?;
                socket.bind(SocketAddr::from((*address, port)))?;
                socket.listen(128)
            })
            .collect::<io::Result<Vec<_>>>()
            .map_err(|error| {
                format!("Unable to listen for console HTTPS on port {port}: {error}")
            })?;
        let mut listeners = JoinSet::new();
        for socket in sockets {
            let weak = Arc::downgrade(site);
            let connections = site.connections.clone();
            listeners.spawn(async move {
                if let Err(error) = accept(socket, true, weak, connections).await {
                    eprintln!("HTTPS listener on port {port} stopped: {error}");
                }
            });
        }
        Ok(Self { port, listeners })
    }
}

impl Drop for Https {
    fn drop(&mut self) {
        self.listeners.abort_all();
    }
}

struct Trial {
    listener: Https,
    owner: String,
    token: String,
    deadline: Instant,
}

impl State {
    fn discard_expired(&mut self) {
        if self
            .trial
            .as_ref()
            .is_some_and(|trial| trial.deadline <= Instant::now())
        {
            self.trial = None;
        }
    }
}

impl ConsolePort {
    pub(super) fn new(port: u16) -> Self {
        Self(Mutex::new(State {
            active: Https {
                port,
                listeners: JoinSet::new(),
            },
            trial: None,
        }))
    }

    pub(super) fn start(&self, site: &Arc<Site>) -> Result<(), ErrorBox> {
        let mut state = self.0.lock().expect("console port state");
        state.active = Https::bind(site, state.active.port)?;
        Ok(())
    }

    pub(super) fn active(&self) -> u16 {
        self.0.lock().expect("console port state").active.port
    }

    pub(super) fn access(&self, port: u16) -> (u16, bool) {
        let mut state = self.0.lock().expect("console port state");
        state.discard_expired();
        (
            state.active.port,
            state
                .trial
                .as_ref()
                .is_some_and(|trial| trial.listener.port == port),
        )
    }
}

pub(super) struct Visit {
    pub(super) site: Arc<Site>,
    pub(super) port: u16,
    pub(super) host: Option<String>,
    pub(super) form: Option<Bytes>,
}

impl Visit {
    pub(super) fn serve(self, db: &Connection, user: &str) -> Result<Reply, ErrorBox> {
        let mut state = self.site.console_port.0.lock().expect("console port state");
        state.discard_expired();
        let Some(form) = &self.form else {
            return Ok(self.render(&state, user, None));
        };
        let mut fields = form_urlencoded::parse(form);
        let (Some((field, value)), None) = (fields.next(), fields.next()) else {
            return Ok(self.render(
                &state,
                user,
                Some((StatusCode::BAD_REQUEST, "Demande de modification invalide.")),
            ));
        };
        if field == "port" && self.port == state.active.port {
            let Some(port) = parse(&value).filter(|port| *port != self.site.http_port) else {
                return Ok(self.render(&state, user, Some((StatusCode::UNPROCESSABLE_ENTITY,
                    "Choisissez un port entre 1 et 65535 différent du port HTTP de démarrage PXE."))));
            };
            if state.trial.is_some() {
                return Ok(self.render(
                    &state,
                    user,
                    Some((StatusCode::CONFLICT, "Un essai de port est déjà en cours.")),
                ));
            }
            if port == state.active.port {
                return Ok(redirect(StatusCode::SEE_OTHER, ROUTE));
            }
            let token = crate::random_token()?;
            let listener = match Https::bind(&self.site, port) {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("{error}");
                    return Ok(self.render(&state, user, Some((StatusCode::CONFLICT, "Ce port ne peut pas être ouvert. Vérifiez qu’il est disponible sur les adresses de PXE Tools."))));
                }
            };
            let deadline = Instant::now() + TRIAL_DURATION;
            state.trial = Some(Trial {
                listener,
                owner: user.to_owned(),
                token,
                deadline,
            });
            let site = Arc::downgrade(&self.site);
            tokio::spawn(async move {
                sleep_until(deadline).await;
                if let Some(site) = site.upgrade() {
                    site.console_port
                        .0
                        .lock()
                        .expect("console port state")
                        .discard_expired();
                }
            });
            return Ok(redirect(StatusCode::SEE_OTHER, ROUTE));
        }
        let Some(trial) = state
            .trial
            .as_ref()
            .filter(|trial| trial.owner == user && trial.token == value)
        else {
            return Ok(self.render(
                &state,
                user,
                Some((
                    StatusCode::CONFLICT,
                    "Cet essai de port a expiré ou a déjà été traité.",
                )),
            ));
        };
        match field.as_ref() {
            "cancel" if self.port == state.active.port => state.trial = None,
            "confirm" if self.port == trial.listener.port => {
                if proxmox_busy(db)? {
                    return Ok(self.render(&state, user, Some((StatusCode::CONFLICT, "Attendez la fin des déploiements et des préparations de média Proxmox VE avant de confirmer."))));
                }
                if let Err(error) = persist(&self.site.database, self.port) {
                    eprintln!("Unable to save HTTPS console port: {error}");
                    return Ok(self.render(
                        &state,
                        user,
                        Some((
                            StatusCode::SERVICE_UNAVAILABLE,
                            "L’enregistrement du port a échoué. Réessayez avant la fin de l’essai.",
                        )),
                    ));
                }
                state.active = state.trial.take().expect("validated trial").listener;
            }
            _ => {
                return Ok(self.render(
                    &state,
                    user,
                    Some((
                        StatusCode::FORBIDDEN,
                        "Ouvrez la console sur le nouveau port pour confirmer.",
                    )),
                ))
            }
        }
        Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
    }

    fn render(&self, state: &State, user: &str, error: Option<(StatusCode, &str)>) -> Reply {
        let active = state.active.port;
        let mut html = format!(
            r#"<nav class="page-links"><a href="/settings">Paramètres PXE</a></nav>
<section class="panel panel--form"><p>Port HTTPS actuel <strong>{active}</strong></p>"#,
        );
        let status = error.map_or(StatusCode::OK, |(code, message)| {
            html.push_str(r#"<p role="alert">"#);
            escape(&mut html, message);
            html.push_str("</p>");
            code
        });
        match (&self.host, &state.trial) {
            (None, _) => html.push_str("<p>Accédez directement à cette instance pour modifier le port HTTPS.</p>"),
            (Some(host), Some(trial)) if trial.owner == user => {
                let proposed = trial.listener.port;
                let token = &trial.token;
                if self.port == proposed {
                    html.push_str(&format!(r#"<h2>Confirmer le port {proposed}</h2>
<p>Le nouveau port répond. Confirmez pour l’utiliser et fermer le port {active}.</p>
<form method="post" action="{ROUTE}"><button name="confirm" value="{token}">Confirmer le nouveau port</button></form>"#));
                } else {
                    let authority = if proposed == 443 { host.clone() } else { format!("{host}:{proposed}") };
                    let mut url = String::new();
                    escape(&mut url, &format!("https://{authority}{ROUTE}"));
                    html.push_str(&format!(r#"<h2>Essai du port {proposed}</h2>
<p>Ouvrez la console dans un nouvel onglet et confirmez le port dans les deux minutes qui suivent le début de l’essai. À l’expiration du délai, la console conserve le port {active}.</p>
<p><a href="{url}" target="_blank" rel="noopener">{url}</a></p>
<div class="form-actions"><a class="button" href="{url}" target="_blank" rel="noopener">Ouvrir le nouveau port</a>
<form method="post" action="{ROUTE}"><button class="button--quiet" name="cancel" value="{token}">Annuler l’essai</button></form></div>"#));
                }
            }
            (Some(_), Some(_)) => html.push_str("<p>Un autre administrateur teste actuellement un port HTTPS.</p>"),
            (Some(_), None) => html.push_str(&format!(r#"<form class="form-stack" method="post" action="{ROUTE}">
<div class="field"><label for="console-https-port">Port HTTPS de la console</label>
<input id="console-https-port" name="port" type="number" inputmode="numeric" min="1" max="65535" value="{active}" aria-describedby="console-https-help" required></div>
<p id="console-https-help">Autorisez d’abord le nouveau port dans votre pare-feu. Les médias Proxmox VE déjà préparés devront être préparés de nouveau après le changement.</p>
<div class="form-actions"><button>Tester le port</button></div></form>"#)),
        }
        html.push_str("</section>");
        let mut response = page(ConsoleSection::Settings, "Accès à la console", &html);
        *response.status_mut() = status;
        response
    }
}

fn proxmox_busy(db: &Connection) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM machines WHERE status IN ('configured', 'installing')
             AND CASE WHEN json_valid(install_config_json)
                 THEN json_type(install_config_json, '$.linux_deployment.source.Proxmox') = 'text'
                 ELSE 0 END
           UNION ALL
           SELECT 1 FROM init_jobs j JOIN settings s ON s.key = 'media_import_request_' || j.id
             WHERE j.job_type = ?1 AND j.status IN ('pending', 'running')
             AND CASE WHEN json_valid(s.value) THEN json_extract(s.value, '$.kind') = 'proxmox' ELSE 0 END
         )",
        [crate::media::JOB],
        |row| row.get(0),
    )
}
