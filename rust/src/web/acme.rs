// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    bytes,
    certificates::{AcmeProgress, Certificates},
    plain, ErrorBox, Reply,
};
use http::uri::Authority;
use hyper::StatusCode;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::BufReader,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{sleep, timeout},
};

use tokio_rustls::rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};

pub(super) const PREFIX: &str = "/.well-known/acme-challenge/";
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
const STATE_FILE: &str = "acme-account.json";

const MAX_CA_PEM: usize = 12 * 1024;

#[derive(PartialEq, Eq)]
enum TrustRoot {
    File(PathBuf),
    Certificate(CertificateDer<'static>),
}

#[derive(PartialEq, Eq)]
pub(super) struct Config {
    pub(super) host: String,
    pub(super) directory: String,
    root: Option<TrustRoot>,
    contact: Option<String>,
}

impl Config {
    pub(super) fn from_env(host: Option<&str>) -> Result<Option<Self>, ErrorBox> {
        let mode = env::var("PXE_ACME").unwrap_or_default();
        let (directory, root) = match mode.as_str() {
            "" | "off" => return Ok(None),
            "production" => (LetsEncrypt::Production.url().to_owned(), None),
            "staging" => (LetsEncrypt::Staging.url().to_owned(), None),
            "private" => {
                let (url, root) = Self::private_endpoint()?;
                (url, Some(TrustRoot::File(root)))
            }
            _ => return Err("Invalid PXE_ACME mode".into()),
        };
        let contact = env::var("PXE_ACME_EMAIL").ok();
        Self::new(host, directory, root, contact).map(Some)
    }

    pub(super) fn private_endpoint() -> Result<(String, PathBuf), ErrorBox> {
        let url = env::var("PXE_ACME_DIRECTORY_URL")?;
        let path = PathBuf::from(env::var_os("PXE_ACME_CA_FILE").ok_or("ACME CA file required")?);
        validate_directory(&url)?;
        if !path.is_absolute() {
            return Err("ACME private mode requires an absolute CA path".into());
        }
        Ok((url, path))
    }

    pub(super) fn trust_pin(&self) -> Option<String> {
        match &self.root {
            Some(TrustRoot::Certificate(cert)) => Some(super::certificate_pin(cert)),
            _ => None,
        }
    }

    fn account_builder(&self) -> Result<AccountBuilder, ErrorBox> {
        Ok(match &self.root {
            None => Account::builder()?,
            Some(TrustRoot::File(path)) => Account::builder_with_root(path)?,
            Some(TrustRoot::Certificate(cert)) => {
                let mut roots = RootCertStore::empty();
                roots.add(cert.clone())?;
                let tls = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let connector = HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_only()
                    .enable_http1()
                    .build();
                let client = Client::builder(TokioExecutor::new()).build(connector);
                Account::builder_with_http(Box::new(client))
            }
        })
    }

    fn new(
        host: Option<&str>,
        directory: String,
        root: Option<TrustRoot>,
        contact: Option<String>,
    ) -> Result<Self, ErrorBox> {
        let host = host
            .filter(|host| dns_name(host))
            .ok_or("Saisissez un nom DNS complet pour cette instance.")?;
        let contact = contact.filter(|email| !email.is_empty());
        if contact.as_ref().is_some_and(|email| {
            !email.is_ascii()
                || email.len() > 254
                || !email.contains('@')
                || email
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        }) {
            return Err("Vérifiez l’adresse de contact.".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            directory,
            root,
            contact,
        })
    }
}

fn validate_directory(url: &str) -> Result<(), ErrorBox> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| "Saisissez une URL de répertoire ACME valide.")?;
    if url.len() > 2048
        || uri.scheme_str() != Some("https")
        || uri
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err("L’URL du répertoire ACME doit utiliser HTTPS.".into());
    }
    Ok(())
}

fn parse_root(pem: &str) -> Result<CertificateDer<'static>, ErrorBox> {
    let error = "Collez uniquement le certificat racine public de l’autorité au format PEM.";
    let pem = pem.trim();
    let body = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----"))
        .filter(|value| {
            value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte.is_ascii_whitespace() || b"+/=".contains(&byte)
            })
        })
        .ok_or(error)?;
    if pem.len() > MAX_CA_PEM || body.trim().is_empty() {
        return Err(error.into());
    }
    let der = rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .next()
        .transpose()
        .map_err(|_| error)?
        .ok_or(error)?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|_| error)?;
    if !parsed.tbs_certificate.is_ca() || !parsed.validity().is_valid() {
        return Err(
            "Le certificat doit être un certificat d’autorité en cours de validité.".into(),
        );
    }
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).map_err(|_| error)?;
    Ok(der)
}

pub(super) fn dns_name(name: &str) -> bool {
    name.contains('.') && super::hostnames::dns_name(name)
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Mode {
    #[default]
    Off,
    Staging,
    Production,
    Private,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Preference {
    pub(super) mode: Mode,
    pub(super) contact: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) private_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) root_pem: Option<String>,
}

impl Preference {
    pub(super) fn parse(form: &[u8]) -> Option<Self> {
        let mut mode = None;
        let mut contact = None;
        let mut accepted = false;
        let (mut host, mut private_url, mut root_pem) = (None, None, None);
        for (field, value) in form_urlencoded::parse(form) {
            match field.as_ref() {
                "mode" if mode.is_none() => {
                    mode = Some(match value.as_ref() {
                        "off" => Mode::Off,
                        "staging" => Mode::Staging,
                        "production" => Mode::Production,
                        "private" => Mode::Private,
                        _ => return None,
                    })
                }
                "email" if contact.is_none() => contact = Some(value.into_owned()),
                "host" if host.is_none() => host = Some(value.trim().to_owned()),
                "directory" if private_url.is_none() => private_url = Some(value.trim().to_owned()),
                "root_ca" if root_pem.is_none() => root_pem = Some(value.trim().to_owned()),
                "terms" if !accepted && value == "on" => accepted = true,
                _ => return None,
            }
        }
        let mode = mode?;
        if !matches!(mode, Mode::Off) && !accepted {
            return None;
        }
        if matches!(mode, Mode::Off) {
            return Some(Self::default());
        }
        Some(Self {
            mode,
            contact: contact.unwrap_or_default(),
            host: host.filter(|value| !value.is_empty()),
            private_url: private_url
                .filter(|value| matches!(mode, Mode::Private) && !value.is_empty()),
            root_pem: root_pem.filter(|value| matches!(mode, Mode::Private) && !value.is_empty()),
        })
    }

    pub(super) fn config(&self, host: Option<&str>) -> Result<Option<Config>, ErrorBox> {
        let host = self.host.as_deref().or(host);
        let root = self.root_pem.as_deref().map(parse_root).transpose()?;
        if let Some(url) = self.private_url.as_deref() {
            validate_directory(url)?;
        }
        let (directory, root) = match self.mode {
            Mode::Off => return Ok(None),
            Mode::Staging => (LetsEncrypt::Staging.url().to_owned(), None),
            Mode::Production => (LetsEncrypt::Production.url().to_owned(), None),
            Mode::Private => match (self.private_url.as_deref(), root) {
                (Some(url), Some(root)) => (url.to_owned(), Some(TrustRoot::Certificate(root))),
                (None, None) => {
                    let (url, root) = Config::private_endpoint().map_err(|_| {
                        "Renseignez l’URL du répertoire ACME et le certificat racine."
                    })?;
                    (url, Some(TrustRoot::File(root)))
                }
                _ => {
                    return Err(
                        "Renseignez l’URL du répertoire ACME et le certificat racine.".into(),
                    )
                }
            },
        };
        Config::new(host, directory, root, Some(self.contact.clone())).map(Some)
    }
}

struct Challenge {
    host: String,
    token: String,
    answer: String,
}

#[derive(Default)]
pub(super) struct ChallengeResponse {
    active: RwLock<Option<Challenge>>,
}

impl ChallengeResponse {
    pub(super) fn serve(&self, path: &str, host: Option<&str>) -> Reply {
        let token = path.strip_prefix(PREFIX);
        let host = host.and_then(|value| value.parse::<Authority>().ok());
        let active = self.active.read().ok();
        if let Some(challenge) = active
            .as_deref()
            .and_then(Option::as_ref)
            .filter(|challenge| {
                host.as_ref()
                    .is_some_and(|host| host.host().eq_ignore_ascii_case(&challenge.host))
                    && token == Some(challenge.token.as_str())
            })
        {
            return hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Cache-Control", "no-store")
                .body(bytes(challenge.answer.clone()))
                .expect("valid ACME response");
        }
        plain(StatusCode::NOT_FOUND, "Not found\n")
    }
}

// The slot is cleared on CA failure, timeout, completion and task cancellation.
struct ChallengeSession<'a>(&'a ChallengeResponse);

impl Drop for ChallengeSession<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.0.active.write() {
            *active = None;
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AccountState {
    directory: String,
    #[serde(default)]
    trust_pin: Option<String>,
    credentials: AccountCredentials,
}

pub(super) async fn run(
    mut configuration: watch::Receiver<Option<Arc<Config>>>,
    challenges: &ChallengeResponse,
    certificates: &Certificates,
) {
    loop {
        let current = configuration.borrow_and_update().clone();
        if let Some(config) = current {
            tokio::select! {
                changed = configuration.changed() => if changed.is_err() { return; },
                () = renew(&config, challenges, certificates) => {
                    if configuration.changed().await.is_err() { return; }
                }
            }
        } else if configuration.changed().await.is_err() {
            return;
        }
    }
}

async fn renew(config: &Config, challenges: &ChallengeResponse, certificates: &Certificates) {
    loop {
        let Some(delay) = certificates.managed_delay(config) else {
            return;
        };
        if !delay.is_zero() {
            sleep(delay.min(CHECK_INTERVAL)).await;
            continue;
        }
        certificates.report_acme(config, AcmeProgress::Issuing);
        match timeout(
            Duration::from_secs(180),
            issue(config, challenges, certificates),
        )
        .await
        {
            Ok(Ok(())) => {
                if certificates
                    .managed_delay(config)
                    .is_some_and(|delay| delay.is_zero())
                {
                    sleep(RETRY_INTERVAL).await;
                }
                continue;
            }
            Ok(Err(error)) => eprintln!("TLS ACME issuance: {error}"),
            Err(_) => eprintln!("TLS ACME issuance timed out"),
        }
        certificates.report_acme(config, AcmeProgress::Failed);
        sleep(RETRY_INTERVAL).await;
    }
}

async fn issue(
    config: &Config,
    challenges: &ChallengeResponse,
    certificates: &Certificates,
) -> Result<(), ErrorBox> {
    let builder = config.account_builder()?;
    let trust_pin = config.trust_pin();
    let cached: Option<AccountState> = certificates.load_private(STATE_FILE)?;
    let account = if let Some(cached) =
        cached.filter(|state| state.directory == config.directory && state.trust_pin == trust_pin)
    {
        builder.from_credentials(cached.credentials).await?
    } else {
        let contact: Vec<_> = config
            .contact
            .iter()
            .map(|email| format!("mailto:{email}"))
            .collect();
        let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                config.directory.clone(),
                None,
            )
            .await?;
        certificates.persist_private(
            STATE_FILE,
            &AccountState {
                directory: config.directory.clone(),
                trust_pin,
                credentials,
            },
        )?;
        account
    };
    let identifiers = [Identifier::Dns(config.host.clone())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let session = ChallengeSession(challenges);
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            _ => return Err("ACME authorization is not pending or valid".into()),
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or("ACME HTTP-01 unavailable")?;
        let token = challenge.token.clone();
        if token.is_empty()
            || token.len() > 256
            || !token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err("ACME server returned an invalid challenge token".into());
        }
        let answer = challenge.key_authorization().as_str().to_owned();
        *challenges
            .active
            .write()
            .map_err(|_| "ACME challenge lock")? = Some(Challenge {
            host: config.host.clone(),
            token,
            answer,
        });
        challenge.set_ready().await?;
    }
    let policy = RetryPolicy::default();
    if order.poll_ready(&policy).await? != OrderStatus::Ready {
        return Err("ACME order is not ready for finalization".into());
    }
    drop(session);
    let key = order.finalize().await?;
    let chain = order.poll_certificate(&policy).await?;
    certificates.install_managed(config, chain, key)
}
