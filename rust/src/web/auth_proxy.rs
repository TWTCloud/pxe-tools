// SPDX-License-Identifier: LGPL-3.0-only

use hyper::HeaderMap;
use std::net::IpAddr;

#[derive(Default)]
pub(super) struct TrustedProxies(Vec<(IpAddr, u32)>);

impl TrustedProxies {
    pub(super) fn from_environment() -> Self {
        let raw = std::env::var("AUTHENTIK_TRUSTED_PROXY_CIDRS").unwrap_or_default();
        Self::parse(&raw).unwrap_or_default()
    }

    fn parse(raw: &str) -> Option<Self> {
        if raw.trim().is_empty() {
            return Some(Self::default());
        }
        let networks = raw
            .split(',')
            .map(|entry| {
                let entry = entry.trim();
                let (address, prefix) = entry
                    .split_once('/')
                    .map_or((entry, None), |(address, bits)| (address, Some(bits)));
                let address: IpAddr = address.parse().ok()?;
                let width = if address.is_ipv4() { 32 } else { 128 };
                let prefix = match prefix {
                    None => width,
                    Some(raw)
                        if (1..=3).contains(&raw.len())
                            && raw.bytes().all(|byte| byte.is_ascii_digit()) =>
                    {
                        raw.parse().ok()?
                    }
                    Some(_) => return None,
                };
                (1..=width).contains(&prefix).then_some((address, prefix))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self(networks))
    }

    pub(super) fn contains(&self, address: IpAddr) -> bool {
        self.0
            .iter()
            .any(|(network, bits)| match (address, network) {
                (IpAddr::V4(address), IpAddr::V4(network)) => {
                    u32::from(address) >> (32 - bits) == u32::from(*network) >> (32 - bits)
                }
                (IpAddr::V6(address), IpAddr::V6(network)) => {
                    u128::from(address) >> (128 - bits) == u128::from(*network) >> (128 - bits)
                }
                _ => false,
            })
    }

    pub(super) fn identity<'a>(&self, address: IpAddr, headers: &'a HeaderMap) -> Option<&'a str> {
        if !self.contains(address) {
            return None;
        }
        let mut asserted = headers.get_all("x-forwarded-user").iter();
        let user = std::str::from_utf8(asserted.next()?.as_bytes()).ok()?;
        if asserted.next().is_some() {
            return None;
        }
        (!user.is_empty()
            && user.len() <= 256
            && crate::php_trim(user) == user
            && !user
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b','))
        .then_some(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_proxy_ranges_and_unique_user_headers() {
        assert!(TrustedProxies::parse("192.0.2.7/32,invalid").is_none());
        assert!(TrustedProxies::parse("0.0.0.0/0").is_none());
        assert!(TrustedProxies::parse("::/0").is_none());
        assert!(TrustedProxies::parse("192.0.2.7/33").is_none());
        let proxy = TrustedProxies::parse("192.0.2.7/32, 2001:db8:a::/48").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-user", "fixture".parse().unwrap());
        let addr = |raw: &str| raw.parse::<IpAddr>().unwrap();
        assert_eq!(proxy.identity(addr("192.0.2.7"), &headers), Some("fixture"));
        assert_eq!(
            proxy.identity(addr("2001:db8:a::5"), &headers),
            Some("fixture")
        );
        headers.insert("x-forwarded-for", "192.0.2.7".parse().unwrap());
        assert_eq!(proxy.identity(addr("192.0.2.8"), &headers), None);
        headers.append("x-forwarded-user", "other".parse().unwrap());
        assert_eq!(proxy.identity(addr("192.0.2.7"), &headers), None);
    }
}
