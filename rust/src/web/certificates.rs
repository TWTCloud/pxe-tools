// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    acme,
    admin::escape,
    hostnames, plain,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use hyper::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    env,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

pub(super) const ROUTE: &str = "/admin/certificates";
pub(super) const ACME_ROUTE: &str = "/admin/certificates/acme";
pub(super) const MAX_FORM: usize = 64 * 1024;
const MAX_BUNDLE: u64 = 2 * MAX_FORM as u64;
const BUNDLE: &str = "external.json";
const MANAGED: &str = "acme-certificate.json";
const PREFERENCE: &str = "acme-settings.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    certificate: String,
    private_key: String,
}

#[derive(Deserialize, Serialize)]
struct Managed {
    directory: String,
    host: String,
    #[serde(default)]
    trust_pin: Option<String>,
    pair: Pair,
}

#[derive(Clone)]
pub(super) struct Endpoint {
    acceptor: TlsAcceptor,
    pin: String,
    dns_names: Vec<String>,
}

impl Endpoint {
    pub(super) fn new(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, ErrorBox> {
        let leaf = certs.first().ok_or("TLS certificate leaf missing")?;
        let pin = super::certificate_pin(leaf);
        let dns_names = certificate_dns_names(leaf);
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            pin,
            dns_names,
        })
    }
}

fn certificate_dns_names(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::GeneralName::DNSName;
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|entry| match entry {
            DNSName(name) if hostnames::dns_name(name) => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

struct Active {
    endpoint: Endpoint,
    external: bool,
    renewal: Option<Renewal>,
}

struct Renewal {
    directory: String,
    host: String,
    trust_pin: Option<String>,
    timestamp: i64,
    expires: i64,
}

impl Renewal {
    fn matches(&self, config: &acme::Config) -> bool {
        self.directory == config.directory
            && self.host == config.host
            && self.trust_pin == config.trust_pin()
    }
}

#[derive(Clone, Copy, Default)]
pub(super) enum AcmeProgress {
    #[default]
    Waiting,
    Issuing,
    Failed,
}

pub(super) struct Certificates {
    directory: PathBuf,
    active: RwLock<Active>,
    default: Endpoint,
    public_host: Option<String>,
    acme_from_env: bool,
    acme_progress: RwLock<AcmeProgress>,
    acme: watch::Sender<Option<Arc<acme::Config>>>,
}

impl Certificates {
    pub(super) fn new(default: Endpoint, public_host: Option<String>) -> Result<Self, ErrorBox> {
        let directory = env::var_os("PXE_TLS_IMPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/var/lib/pxe-tools/tls-import".into());
        if !directory.is_absolute() {
            return Err("TLS import directory must have an absolute path".into());
        }
        let acme_from_env = env::var_os("PXE_ACME").is_some_and(|mode| !mode.is_empty());
        let acme = if acme_from_env {
            acme::Config::from_env(public_host.as_deref())?
        } else {
            let configured = load::<acme::Preference>(&directory, PREFERENCE)
                .and_then(|pref| pref.unwrap_or_default().config(public_host.as_deref()));
            configured.unwrap_or_else(|error| {
                eprintln!("Console ACME settings suspended: {error}");
                None
            })
        };
        let external: Option<Pair> = load(&directory, BUNDLE)?;
        let active = if let Some(pair) = external {
            Active {
                endpoint: pair.endpoint()?,
                external: true,
                renewal: None,
            }
        } else {
            let cached = acme.as_ref().and_then(|config| {
                let certificate = load::<Managed>(&directory, MANAGED);
                match certificate {
                    Ok(Some(managed)) => match managed.active() {
                        Ok(active) => Some(active),
                        Err(error) => {
                            eprintln!("Ignoring stale ACME certificate: {error}");
                            None
                        }
                    },
                    Err(error) => {
                        eprintln!("Unable to load the managed ACME certificate: {error}");
                        None
                    }
                    _ => None,
                }
            });
            cached.unwrap_or(Active {
                endpoint: default.clone(),
                external: false,
                renewal: None,
            })
        };
        Ok(Self {
            directory,
            active: RwLock::new(active),
            default,
            public_host,
            acme_from_env,
            acme_progress: RwLock::new(AcmeProgress::default()),
            acme: watch::Sender::new(acme.map(Arc::new)),
        })
    }

    pub(super) fn pin(&self) -> String {
        self.active
            .read()
            .expect("TLS config lock")
            .endpoint
            .pin
            .clone()
    }

    pub(super) fn acceptor(&self) -> TlsAcceptor {
        self.active
            .read()
            .expect("TLS config lock")
            .endpoint
            .acceptor
            .clone()
    }

    pub(super) fn acme_configuration(&self) -> watch::Receiver<Option<Arc<acme::Config>>> {
        self.acme.subscribe()
    }

    pub(super) fn managed_delay(&self, config: &acme::Config) -> Option<Duration> {
        let active = self.active.read().ok()?;
        if active.external || self.acme.borrow().as_deref() != Some(config) {
            return None;
        }
        let seconds = active
            .renewal
            .as_ref()
            .filter(|renewal| renewal.matches(config))
            .map_or(0, |renewal| renewal.timestamp.saturating_sub(now()));
        Some(Duration::from_secs(seconds.max(0) as u64))
    }

    pub(super) fn install_managed(
        &self,
        config: &acme::Config,
        certificate: String,
        private_key: String,
    ) -> Result<(), ErrorBox> {
        let managed = Managed {
            directory: config.directory.clone(),
            host: config.host.clone(),
            trust_pin: config.trust_pin(),
            pair: Pair {
                certificate,
                private_key,
            },
        };
        let next = managed.active()?;
        let mut active = self.active.write().map_err(|_| "TLS config lock")?;
        if !active.external && self.acme.borrow().as_deref() == Some(config) {
            persist(&self.directory, MANAGED, &managed)?;
            *active = next;
            *self.acme_progress.write().expect("ACME progress lock") = AcmeProgress::Waiting;
        }
        Ok(())
    }

    pub(super) fn issued_host(&self) -> Option<String> {
        self.active
            .read()
            .expect("TLS config lock")
            .renewal
            .as_ref()
            .map(|renewal| renewal.host.clone())
    }

    pub(super) fn allowed_acme_host(&self, host: &str) -> bool {
        let active = self.active.read().expect("TLS config lock");
        self.acme
            .borrow()
            .as_ref()
            .is_some_and(|config| config.host.eq_ignore_ascii_case(host))
            || active
                .renewal
                .as_ref()
                .is_some_and(|renewal| renewal.host.eq_ignore_ascii_case(host))
    }

    pub(super) fn covers_dns_name(&self, host: &str) -> bool {
        let active = self.active.read().expect("TLS config lock");
        hostnames::contains(&active.endpoint.dns_names, host)
    }

    pub(super) fn report_acme(&self, config: &acme::Config, progress: AcmeProgress) {
        let active = self.active.read().expect("TLS config lock");
        if !active.external && self.acme.borrow().as_deref() == Some(config) {
            *self.acme_progress.write().expect("ACME progress lock") = progress;
        }
    }

    pub(super) fn load_private<T: DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, ErrorBox> {
        load(&self.directory, name)
    }

    pub(super) fn persist_private<T: Serialize>(
        &self,
        name: &str,
        value: &T,
    ) -> Result<(), ErrorBox> {
        persist(&self.directory, name, value)
    }

    pub(super) fn page(&self) -> Reply {
        self.render_page(None, None)
    }

    fn render_page(&self, error: Option<&str>, draft: Option<&acme::Preference>) -> Reply {
        let active = self.active.read().expect("TLS config lock");
        let status = if active.external {
            "Certificat externe"
        } else if active.renewal.is_some() {
            "Certificat ACME"
        } else {
            "Certificat auto-signé de l’instance"
        };
        let mut feedback = String::new();
        if let Some(error) = error {
            feedback.push_str(r#"<p role="alert" class="image-error">"#);
            escape(&mut feedback, error);
            feedback.push_str("</p>");
        }
        let acme = self.acme_form(&active, &feedback, draft);
        let restore = if active.external {
            format!(
                r#"<details><summary>Revenir au certificat de l’instance</summary>
<p>Le certificat importé et sa clé seront retirés. Si ACME est configuré, une demande sera lancée.</p>
<form class="form-actions" method="post" action="{ROUTE}"><button class="button--quiet" name="restore_default" value="1">Retirer le certificat importé</button></form></details>"#
            )
        } else {
            String::new()
        };
        let mut reply = page(
            ConsoleSection::Certificates,
            "Certificats TLS",
            &format!(
                r#"<p class="active-certificate">Certificat actif · <strong>{status}</strong></p>
<div class="panel-grid">
<section class="panel"><h2>Renouvellement ACME</h2>{acme}</section>
<section class="panel"><h2>Importer un certificat</h2>
<form class="form-stack" method="post" action="{ROUTE}">
<div class="field"><label for="tls-certificate">Certificat et chaîne PEM</label><textarea id="tls-certificate" name="certificate" rows="6" required spellcheck="false"></textarea></div>
<div class="field"><label for="tls-key">Clé privée PEM</label><textarea id="tls-key" name="private_key" rows="6" required spellcheck="false" autocomplete="off"></textarea></div>
<div class="form-actions"><button>Importer le certificat</button></div>
</form>{restore}</section></div>"#
            ),
        );
        if error.is_some() {
            *reply.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        }
        reply
    }

    fn acme_form(
        &self,
        active: &Active,
        feedback: &str,
        draft: Option<&acme::Preference>,
    ) -> String {
        let mut status = String::new();
        if let Some(config) = self.acme.borrow().as_ref() {
            status.push_str(r#"<p class="record-meta" role="status">"#);
            let progress = *self.acme_progress.read().expect("ACME progress lock");
            match (progress, active.renewal.as_ref().filter(|renewal| renewal.matches(config))) {
                (AcmeProgress::Issuing, _) => status.push_str("Demande de certificat en cours."),
                (AcmeProgress::Failed, _) => status.push_str("La demande a échoué. Vérifiez l’accès à l’autorité et au port HTTP 80. PXE Tools réessaiera automatiquement."),
                (_, Some(renewal)) => {
                    status.push_str("Renouvellement automatique actif pour ");
                    escape(&mut status, &renewal.host);
                    if let Ok(expires) = x509_parser::time::ASN1Time::from_timestamp(renewal.expires) {
                        status.push_str(" · Expiration le ");
                        status.push_str(&expires.to_datetime().date().to_string());
                    }
                    status.push('.');
                }
                _ => status.push_str("Demande de certificat en attente."),
            }
            status.push_str("</p>");
        }
        if active.external {
            return "<p>Le certificat importé est actif. Retirez-le pour reprendre la gestion ACME.</p>".into();
        }
        if self.acme_from_env {
            return format!(
                "{status}<p>Le mode ACME est défini dans la configuration du service.</p>"
            );
        }
        let saved: acme::Preference = load(&self.directory, PREFERENCE)
            .ok()
            .flatten()
            .unwrap_or_default();
        let pref = draft.unwrap_or(&saved);
        let selection = |value| if value { " selected" } else { "" };
        let off = selection(matches!(pref.mode, acme::Mode::Off));
        let staging = selection(matches!(pref.mode, acme::Mode::Staging));
        let production = selection(matches!(pref.mode, acme::Mode::Production));
        let private = selection(matches!(pref.mode, acme::Mode::Private));
        let open = if !private.is_empty() || !feedback.is_empty() {
            " open"
        } else {
            ""
        };
        let mut email = String::new();
        let mut host = String::new();
        let mut directory = String::new();
        let mut root = String::new();
        escape(&mut email, &pref.contact);
        escape(
            &mut host,
            pref.host
                .as_deref()
                .or(self.public_host.as_deref())
                .unwrap_or_default(),
        );
        escape(
            &mut directory,
            pref.private_url.as_deref().unwrap_or_default(),
        );
        escape(&mut root, saved.root_pem.as_deref().unwrap_or_default());
        let existing = if acme::Config::private_endpoint().is_ok() && pref.private_url.is_none() {
            "<p class=\"record-meta\">Si ces deux champs restent vides, PXE Tools utilise l’autorité privée définie par le service.</p>"
        } else {
            ""
        };
        format!(
            r#"{feedback}{status}<form class="form-stack" method="post" action="{ACME_ROUTE}">
<div class="field"><label for="acme-mode">Mode</label><select id="acme-mode" name="mode" data-acme-mode>
<option value="off"{off}>Désactivé</option>
<option value="staging"{staging}>Let’s Encrypt · Test</option>
<option value="production"{production}>Let’s Encrypt · Production</option>
<option value="private"{private}>Autorité privée</option>
</select></div>
<div class="field"><label for="acme-host">Nom DNS de cette instance</label><input id="acme-host" name="host" type="text" maxlength="253" autocomplete="off" spellcheck="false" aria-describedby="acme-host-help" value="{host}">
<small id="acme-host-help">L’autorité doit pouvoir résoudre ce nom et atteindre le port HTTP 80.</small></div>
<details data-acme-private{open}><summary>Configuration de l’autorité privée</summary>
<div class="form-stack">{existing}
<div class="field"><label for="acme-directory">URL HTTPS du répertoire ACME</label><input id="acme-directory" name="directory" type="url" maxlength="2048" autocomplete="off" spellcheck="false" value="{directory}"></div>
<div class="field"><label for="acme-root">Certificat racine PEM</label><textarea id="acme-root" name="root_ca" rows="5" maxlength="12288" spellcheck="false" autocomplete="off" aria-describedby="acme-root-help">{root}</textarea>
<small id="acme-root-help">Collez le certificat racine public de votre autorité.</small></div>
</div></details>
<div class="field"><label for="acme-email">Adresse de contact (facultative)</label><input id="acme-email" name="email" type="email" maxlength="254" value="{email}"></div>
<label class="check-label"><input type="checkbox" name="terms"> J’accepte les conditions de l’autorité choisie.</label>
<div class="form-actions"><button>Enregistrer le mode ACME</button><a class="button button--quiet" href="{ROUTE}">Actualiser l’état</a></div>
</form>"#
        )
    }

    pub(super) fn configure_acme(&self, form: &[u8]) -> Reply {
        let Some(mut pref) = acme::Preference::parse(form) else {
            return self.render_page(
                Some("Vérifiez le mode ACME et confirmez les conditions d’utilisation."),
                None,
            );
        };
        let config = match pref.config(self.public_host.as_deref()) {
            Ok(config) => config,
            Err(error) => {
                pref.root_pem = None;
                return self.render_page(Some(&error.to_string()), Some(&pref));
            }
        };
        let Ok(mut active) = self.active.write() else {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configuration ACME indisponible\n",
            );
        };
        if self.acme_from_env || active.external {
            return plain(
                StatusCode::CONFLICT,
                "Le mode ACME est géré par le service ou un certificat externe est actif.\n",
            );
        }
        if persist(&self.directory, PREFERENCE, &pref).is_err() {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Enregistrement du mode ACME impossible\n",
            );
        }
        if config.is_none() && active.renewal.is_some() {
            *active = Active {
                endpoint: self.default.clone(),
                external: false,
                renewal: None,
            };
        }
        *self.acme_progress.write().expect("ACME progress lock") = AcmeProgress::Waiting;
        self.acme.send_replace(config.map(Arc::new));
        redirect(StatusCode::SEE_OTHER, ROUTE)
    }

    pub(super) fn import(&self, form: &[u8]) -> Reply {
        if form == b"restore_default=1" {
            return self.restore_default();
        }
        let Some(pair) = Pair::parse(form) else {
            return invalid();
        };
        let Ok(endpoint) = pair.endpoint() else {
            return invalid();
        };
        // Serialize persist-and-activate so concurrent imports cannot leave
        // the running listener and the next startup on different certificates.
        let Ok(mut current) = self.active.write() else {
            return plain(StatusCode::SERVICE_UNAVAILABLE, "Import TLS indisponible\n");
        };
        if persist(&self.directory, BUNDLE, &pair).is_err() {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Enregistrement du certificat impossible\n",
            );
        }
        *current = Active {
            endpoint,
            external: true,
            renewal: None,
        };
        redirect(StatusCode::SEE_OTHER, ROUTE)
    }
    fn restore_default(&self) -> Reply {
        let Ok(mut active) = self.active.write() else {
            return plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configuration TLS indisponible\n",
            );
        };
        if active.external {
            let result = fs::symlink_metadata(&self.directory).and_then(|metadata| {
                if metadata.is_dir() && private(&metadata) {
                    fs::remove_file(self.directory.join(BUNDLE))
                } else {
                    Err(io::ErrorKind::PermissionDenied.into())
                }
            });
            if result.is_err() {
                return plain(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Retrait du certificat impossible\n",
                );
            }
            if let Err(error) = File::open(&self.directory).and_then(|folder| folder.sync_all()) {
                eprintln!("Could not flush TLS import directory: {error}");
            }
            *active = Active {
                endpoint: self.default.clone(),
                external: false,
                renewal: None,
            };
            let config = self.acme.borrow().clone();
            *self.acme_progress.write().expect("ACME progress lock") = AcmeProgress::Waiting;
            self.acme.send_replace(config);
        }
        redirect(StatusCode::SEE_OTHER, ROUTE)
    }
}

impl Pair {
    fn parse(form: &[u8]) -> Option<Self> {
        let mut certificate = None;
        let mut private_key = None;
        for (name, value) in form_urlencoded::parse(form) {
            match name.as_ref() {
                "certificate" if certificate.is_none() => certificate = Some(value.into_owned()),
                "private_key" if private_key.is_none() => private_key = Some(value.into_owned()),
                _ => return None,
            }
        }
        Some(Self {
            certificate: certificate?,
            private_key: private_key?,
        })
    }

    fn endpoint(&self) -> Result<Endpoint, ErrorBox> {
        let mut cert_pem = BufReader::new(self.certificate.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_pem).collect::<Result<Vec<_>, _>>()?;
        let mut key_pem = BufReader::new(self.private_key.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_pem)?.ok_or("TLS private key missing")?;
        if rustls_pemfile::private_key(&mut key_pem)?.is_some() {
            return Err("Expected exactly one TLS private key".into());
        }
        Endpoint::new(certs, key)
    }
}

impl Managed {
    fn active(&self) -> Result<Active, ErrorBox> {
        let leaf = rustls_pemfile::certs(&mut BufReader::new(self.pair.certificate.as_bytes()))
            .next()
            .transpose()?
            .ok_or("ACME certificate leaf missing")?;
        let (_, parsed) = x509_parser::parse_x509_certificate(&leaf)
            .map_err(|_| "Invalid ACME leaf certificate")?;
        let names = parsed
            .subject_alternative_name()
            .map_err(|_| "Invalid ACME certificate DNS names")?;
        use x509_parser::extensions::GeneralName;
        if !names.is_some_and(|names| {
            names.value.general_names.iter().any(|entry|
            matches!(entry, GeneralName::DNSName(name) if name.eq_ignore_ascii_case(&self.host)))
        }) {
            return Err("ACME certificate does not cover the configured DNS name".into());
        }
        let first = parsed.validity().not_before.timestamp();
        let last = parsed.validity().not_after.timestamp();
        let current = now();
        if first > current || last <= current {
            return Err("ACME certificate is outside its validity period".into());
        }
        // Renew with one third of the actual lifetime left, for both standard
        // and shorter-lived certificates.
        let renew_at = last - (last - first) / 3;
        Ok(Active {
            endpoint: self.pair.endpoint()?,
            external: false,
            renewal: Some(Renewal {
                directory: self.directory.clone(),
                host: self.host.clone(),
                trust_pin: self.trust_pin.clone(),
                timestamp: renew_at,
                expires: last,
            }),
        })
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn private(metadata: &fs::Metadata) -> bool {
    // geteuid() reads the process identity without dereferencing pointers.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

fn load<T: DeserializeOwned>(directory: &Path, name: &str) -> Result<Option<T>, ErrorBox> {
    let meta = match fs::symlink_metadata(directory) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_dir() || !private(&meta) {
        return Err("Unprotected TLS import directory".into());
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(name))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || !private(&metadata)
        || metadata.nlink() != 1
        || metadata.len() > MAX_BUNDLE
    {
        return Err("Unprotected TLS state file".into());
    }
    Ok(Some(serde_json::from_reader(file.take(MAX_BUNDLE))?))
}

fn persist<T: Serialize>(directory: &Path, name: &str, value: &T) -> Result<(), ErrorBox> {
    match DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || !private(&metadata) {
        return Err("Unprotected TLS import directory".into());
    }
    let temporary = directory.join(format!(".tls-{}", crate::random_token()?));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<(), ErrorBox> {
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, directory.join(name))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    } else if let Err(error) = File::open(directory).and_then(|folder| folder.sync_all()) {
        // The rename has committed. Keep the running certificate on the same
        // pair and report only the failure to flush the directory metadata.
        eprintln!("Could not flush TLS import directory: {error}");
    }
    result
}

fn invalid() -> Reply {
    plain(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Le certificat et la clé privée ne forment pas une paire PEM valide.\n",
    )
}
