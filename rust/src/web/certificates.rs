// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    acme,
    admin::escape,
    plain,
    setup::{page, redirect},
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
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};

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
    pair: Pair,
}

struct Active {
    acceptor: TlsAcceptor,
    external: bool,
    renewal: Option<(String, i64)>,
}

pub(super) struct Certificates {
    directory: PathBuf,
    active: RwLock<Active>,
    default: TlsAcceptor,
    public_host: Option<String>,
    acme_from_env: bool,
    acme: watch::Sender<Option<Arc<acme::Config>>>,
}

impl Certificates {
    pub(super) fn new(default: TlsAcceptor, public_host: Option<String>) -> Result<Self, ErrorBox> {
        let directory = env::var_os("PXE_TLS_IMPORT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/var/lib/pxe-tools/tls-import".into());
        if !directory.is_absolute() {
            return Err("TLS import directory must have an absolute path".into());
        }
        let acme_from_env = env::var_os("PXE_ACME").is_some();
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
                acceptor: pair.acceptor()?,
                external: true,
                renewal: None,
            }
        } else {
            let cached = acme.as_ref().and_then(|config| {
                let certificate = load::<Managed>(&directory, MANAGED);
                match certificate {
                    Ok(Some(managed))
                        if managed.host == config.host && managed.directory == config.directory =>
                    {
                        match managed.active() {
                            Ok(active) => Some(active),
                            Err(error) => {
                                eprintln!("Ignoring stale ACME certificate: {error}");
                                None
                            }
                        }
                    }
                    Err(error) => {
                        eprintln!("Unable to load the managed ACME certificate: {error}");
                        None
                    }
                    _ => None,
                }
            });
            cached.unwrap_or(Active {
                acceptor: default.clone(),
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
            acme: watch::Sender::new(acme.map(Arc::new)),
        })
    }

    pub(super) fn acceptor(&self) -> TlsAcceptor {
        self.active
            .read()
            .expect("TLS config lock")
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
            .filter(|(directory, _)| directory == &config.directory)
            .map_or(0, |(_, timestamp)| timestamp.saturating_sub(now()));
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
        }
        Ok(())
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
        let active = self.active.read().expect("TLS config lock");
        let status = if active.external {
            "Certificat externe"
        } else if active.renewal.is_some() {
            "Certificat ACME"
        } else {
            "Certificat auto-signé de l’instance"
        };
        let acme = self.acme_form(&active);
        page(
            "Certificats TLS",
            &format!(
                r#"<p>Certificat actif · {status}</p>
<form method="post" action="{ROUTE}">
<p><label>Certificat et chaîne PEM<br><textarea name="certificate" rows="8" cols="64" required spellcheck="false"></textarea></label></p>
<p><label>Clé privée PEM<br><textarea name="private_key" rows="8" cols="64" required spellcheck="false" autocomplete="off"></textarea></label></p>
<button>Importer et appliquer</button>
</form>{acme}<p><a href="/admin/devices">Retour à la console</a></p>"#
            ),
        )
    }

    fn acme_form(&self, active: &Active) -> String {
        let heading = "<h2>Renouvellement ACME</h2>";
        if self.acme_from_env {
            return format!("{heading}<p>Mode défini dans la configuration du service.</p>");
        }
        if active.external {
            return format!("{heading}<p>Le certificat externe est prioritaire.</p>");
        }
        let Some(host) = self
            .public_host
            .as_deref()
            .filter(|host| acme::dns_name(host))
        else {
            return format!("{heading}<p>Renseignez le nom DNS dans PXE_PUBLIC_HOST pour utiliser Let’s Encrypt.</p>");
        };
        let pref: acme::Preference = load(&self.directory, PREFERENCE)
            .ok()
            .flatten()
            .unwrap_or_default();
        let selection = |value| if value { " selected" } else { "" };
        let off = selection(matches!(pref.mode, acme::Mode::Off));
        let staging = selection(matches!(pref.mode, acme::Mode::Staging));
        let production = selection(matches!(pref.mode, acme::Mode::Production));
        let mut email = String::new();
        escape(&mut email, &pref.contact);
        let private = if acme::Config::private_endpoint().is_ok() {
            let selected = selection(matches!(pref.mode, acme::Mode::Private));
            format!("<option value=\"private\"{selected}>Autorité privée</option>")
        } else {
            String::new()
        };
        format!(
            r#"{heading}<p>L’autorité doit pouvoir joindre {host} sur le port HTTP 80.</p>
<form method="post" action="{ACME_ROUTE}">
<p><label>Mode <select name="mode">
<option value="off"{off}>Désactivé</option>
<option value="staging"{staging}>Test</option>
<option value="production"{production}>Production</option>
{private}</select></label></p>
<p><label>Adresse de contact <input name="email" type="email" maxlength="254" value="{email}"></label></p>
<p><label><input type="checkbox" name="terms"> J’accepte les conditions de l’autorité choisie. <a href="https://letsencrypt.org/repository/">Conditions de Let’s Encrypt</a>.</label></p>
<button>Enregistrer le mode ACME</button>
</form>"#
        )
    }

    pub(super) fn configure_acme(&self, form: &[u8]) -> Reply {
        let Some(pref) = acme::Preference::parse(form) else {
            return plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Vérifiez le mode ACME et les conditions d’utilisation.\n",
            );
        };
        let Ok(config) = pref.config(self.public_host.as_deref()) else {
            return plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Nom DNS ou adresse de contact ACME invalide.\n",
            );
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
                acceptor: self.default.clone(),
                external: false,
                renewal: None,
            };
        }
        self.acme.send_replace(config.map(Arc::new));
        redirect(StatusCode::SEE_OTHER, ROUTE)
    }

    pub(super) fn import(&self, form: &[u8]) -> Reply {
        let Some(pair) = Pair::parse(form) else {
            return invalid();
        };
        let Ok(acceptor) = pair.acceptor() else {
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
            acceptor,
            external: true,
            renewal: None,
        };
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

    fn acceptor(&self) -> Result<TlsAcceptor, ErrorBox> {
        let mut cert_pem = BufReader::new(self.certificate.as_bytes());
        let certs = rustls_pemfile::certs(&mut cert_pem).collect::<Result<Vec<_>, _>>()?;
        let mut key_pem = BufReader::new(self.private_key.as_bytes());
        let key = rustls_pemfile::private_key(&mut key_pem)?.ok_or("TLS private key missing")?;
        if rustls_pemfile::private_key(&mut key_pem)?.is_some() {
            return Err("Expected exactly one TLS private key".into());
        }
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Ok(TlsAcceptor::from(Arc::new(config)))
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
            acceptor: self.pair.acceptor()?,
            external: false,
            renewal: Some((self.directory.clone(), renew_at)),
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
