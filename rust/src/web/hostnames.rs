// SPDX-License-Identifier: LGPL-3.0-only

use std::{fs, net::Ipv4Addr, str};

pub(super) fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.parse::<Ipv4Addr>().is_err()
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

pub(super) fn local() -> Vec<String> {
    let mut buffer = [0u8; 256];
    // gethostname writes no more than the length of this buffer.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return Vec::new();
    }
    let Ok(hostname) = str::from_utf8(buffer.split(|byte| *byte == 0).next().unwrap_or_default())
    else {
        return Vec::new();
    };
    let hostname = hostname.trim_end_matches('.');
    if !dns_name(hostname) {
        return Vec::new();
    }

    let mut names = vec![hostname.to_ascii_lowercase()];
    if !hostname.contains('.') {
        let resolver = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        for domain in resolver
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(['#', ';']).next()?.split_ascii_whitespace();
                match fields.next()? {
                    "search" | "domain" => Some(fields),
                    _ => None,
                }
            })
            .last()
            .into_iter()
            .flatten()
        {
            let name = format!("{hostname}.{}", domain.trim_end_matches('.'));
            if dns_name(&name) {
                names.push(name.to_ascii_lowercase());
            }
        }
    }

    // A local hosts entry that names this machine can also specify its FQDN.
    let hosts = fs::read_to_string("/etc/hosts").unwrap_or_default();
    for line in hosts.lines() {
        let record = line.split_once('#').map_or(line, |(record, _)| record);
        let mut fields = record.split_ascii_whitespace();
        if !fields
            .next()
            .is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        {
            continue;
        }
        if fields
            .clone()
            .any(|name| name.trim_end_matches('.').eq_ignore_ascii_case(hostname))
        {
            names.extend(
                fields
                    .map(|name| name.trim_end_matches('.'))
                    .filter(|name| dns_name(name))
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

pub(super) fn contains(names: &[String], host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    names.iter().any(|name| name.eq_ignore_ascii_case(host))
}
