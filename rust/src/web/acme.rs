// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, certificates::Certificates, plain, ErrorBox, Reply};
use http::uri::Authority;
use hyper::StatusCode;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::{env, path::PathBuf, sync::RwLock, time::Duration};
use tokio::time::{sleep, timeout};

pub(super) const PREFIX: &str = "/.well-known/acme-challenge/";
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);
const STATE_FILE: &str = "acme-account.json";

pub(super) struct Config {
    pub(super) host: String,
    pub(super) directory: String,
    root: Option<PathBuf>,
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
                let url = env::var("PXE_ACME_DIRECTORY_URL")?;
                let uri: http::Uri = url.parse()?;
                let path =
                    PathBuf::from(env::var_os("PXE_ACME_CA_FILE").ok_or("ACME CA file required")?);
                if uri.scheme_str() != Some("https")
                    || uri
                        .authority()
                        .is_none_or(|authority| authority.as_str().contains('@'))
                    || !path.is_absolute()
                {
                    return Err(
                        "ACME private mode requires an HTTPS directory and absolute CA path".into(),
                    );
                }
                (url, Some(path))
            }
            _ => return Err("Invalid PXE_ACME mode".into()),
        };
        let host = host
            .filter(|host| dns_name(host))
            .ok_or("ACME requires a DNS name in PXE_PUBLIC_HOST")?;
        let contact = env::var("PXE_ACME_EMAIL")
            .ok()
            .filter(|email| !email.is_empty());
        if contact.as_ref().is_some_and(|email| {
            !email.is_ascii()
                || email.len() > 254
                || !email.contains('@')
                || email
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        }) {
            return Err("Invalid PXE_ACME_EMAIL address".into());
        }
        Ok(Some(Self {
            host: host.to_ascii_lowercase(),
            directory,
            root,
            contact,
        }))
    }
}

fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.contains('.')
        && name.parse::<std::net::Ipv4Addr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub(super) struct ChallengeResponse {
    host: String,
    active: RwLock<Option<(String, String)>>,
}

impl ChallengeResponse {
    pub(super) fn new(host: String) -> Self {
        Self {
            host,
            active: RwLock::new(None),
        }
    }

    pub(super) fn serve(&self, path: &str, host: Option<&str>) -> Reply {
        let token = path.strip_prefix(PREFIX);
        let named_host = host.and_then(|value| value.parse::<Authority>().ok());
        let authorized =
            named_host.is_some_and(|host| host.host().eq_ignore_ascii_case(&self.host));
        let active = self.active.read().ok();
        if let Some((_, answer)) = active
            .as_deref()
            .and_then(Option::as_ref)
            .filter(|(pending, _)| authorized && Some(pending.as_str()) == token)
        {
            return hyper::Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .header("Cache-Control", "no-store")
                .body(bytes(answer.clone()))
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
    credentials: AccountCredentials,
}

pub(super) async fn run(
    config: Config,
    challenges: &ChallengeResponse,
    certificates: &Certificates,
) {
    loop {
        let Some(delay) = certificates.managed_delay() else {
            return;
        };
        if !delay.is_zero() {
            sleep(delay.min(CHECK_INTERVAL)).await;
            continue;
        }
        match timeout(
            Duration::from_secs(180),
            issue(&config, challenges, certificates),
        )
        .await
        {
            Ok(Ok(())) => {
                if certificates
                    .managed_delay()
                    .is_some_and(|delay| delay.is_zero())
                {
                    sleep(RETRY_INTERVAL).await;
                }
                continue;
            }
            Ok(Err(error)) => eprintln!("TLS ACME issuance: {error}"),
            Err(_) => eprintln!("TLS ACME issuance timed out"),
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn issue(
    config: &Config,
    challenges: &ChallengeResponse,
    certificates: &Certificates,
) -> Result<(), ErrorBox> {
    let builder = match &config.root {
        Some(path) => Account::builder_with_root(path)?,
        None => Account::builder()?,
    };
    let cached: Option<AccountState> = certificates.load_private(STATE_FILE)?;
    let account = if let Some(cached) = cached.filter(|state| state.directory == config.directory) {
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
            .map_err(|_| "ACME challenge lock")? = Some((token, answer));
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
