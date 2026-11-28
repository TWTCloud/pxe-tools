// SPDX-License-Identifier: LGPL-3.0-only

use crate::{configured_database, connect, pxe::parse_subnet, setting};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(crate) const KEY: &str = "pxe_networks";
pub(crate) const DIRECTORY: &str = ".pxe-networks";
pub(crate) const MAX_NETWORKS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Network {
    pub interface: String,
    pub address: Ipv4Addr,
    pub subnet: String,
}

impl Network {
    pub(crate) fn new(interface: String, address: Ipv4Addr, cidr: &str) -> Option<Self> {
        let (network, mask) = parse_subnet(cidr)?;
        let raw = u32::from(address);
        if interface.is_empty()
            || interface.len() > 64
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            || address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.octets()[0] >= 240
            || raw & mask != network
            || (mask.count_ones() <= 30 && (raw == network || raw == network | !mask))
        {
            return None;
        }
        Some(Self {
            interface,
            address,
            subnet: format!("{}/{}", Ipv4Addr::from(network), mask.count_ones()),
        })
    }

    pub(crate) fn contains(&self, peer: IpAddr) -> bool {
        matches!(peer, IpAddr::V4(peer) if crate::pxe::client_in_subnet(peer, &self.subnet))
    }

    fn overlaps(&self, other: &Self) -> bool {
        let (a, mask_a) = parse_subnet(&self.subnet).expect("normalized subnet");
        let (b, mask_b) = parse_subnet(&other.subnet).expect("normalized subnet");
        let mask = mask_a & mask_b;
        a & mask == b & mask
    }

    pub(crate) fn directory(&self, root: &Path) -> PathBuf {
        root.join(DIRECTORY).join(self.address.to_string())
    }
}

pub(crate) fn valid(networks: &[Network]) -> bool {
    (2..=MAX_NETWORKS).contains(&networks.len())
        && networks.iter().enumerate().all(|(index, item)| {
            Network::new(item.interface.clone(), item.address, &item.subnet).as_ref() == Some(item)
                && networks[..index]
                    .iter()
                    .all(|other| item.interface != other.interface && !item.overlaps(other))
        })
}

pub(crate) fn configured(db: &Connection) -> rusqlite::Result<Option<Vec<Network>>> {
    let value = setting(db, KEY)?;
    if value.is_empty() {
        return Ok(None);
    }
    let list: Vec<Network> =
        serde_json::from_str(&value).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if !valid(&list) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Some(list))
}

pub(crate) fn contains_client(db: &Connection, peer: Ipv4Addr) -> rusqlite::Result<bool> {
    Ok(match configured(db)? {
        Some(networks) => networks.iter().any(|item| item.contains(IpAddr::V4(peer))),
        None => crate::pxe::client_in_subnet(peer, &setting(db, "pxe_subnet")?),
    })
}

/// Resolve each network independently. An ambiguous or unavailable interface
/// is omitted until it has a usable address again.
pub(crate) fn resolve(configured: Vec<Network>, detected: &[Network]) -> Vec<Network> {
    configured
        .into_iter()
        .filter_map(|network| {
            let candidates = || {
                detected.iter().filter(|item| {
                    item.interface == network.interface && item.subnet == network.subnet
                })
            };
            if candidates().any(|item| item.address == network.address) {
                return Some(network);
            }
            let mut alternatives = candidates();
            let candidate = alternatives.next()?;
            alternatives.next().is_none().then(|| candidate.clone())
        })
        .collect()
}

pub(crate) fn active(
    config: &Path,
    require_ready: bool,
) -> Result<Option<Vec<Network>>, Box<dyn Error + Send + Sync>> {
    if !config.try_exists()? {
        return Ok(None);
    }
    let path = configured_database(config).ok_or("SQLite configuration unavailable")?;
    let db = connect(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let Some(list) = configured(&db)? else {
        return Ok(None);
    };
    if setting(&db, "pxe_enabled")? != "on" {
        return Ok(Some(Vec::new()));
    }
    let mut list = resolve(list, &detected());
    if require_ready {
        let tftp =
            std::env::var_os("TFTP_ROOT").map_or_else(|| PathBuf::from("/srv/tftp"), PathBuf::from);
        list.retain(|item| {
            let marker = item.directory(&tftp).join(".ready");
            std::fs::symlink_metadata(&marker)
                .is_ok_and(|info| info.is_file() && info.uid() == 0 && info.mode() & 0o022 == 0)
                && std::fs::read_to_string(marker)
                    .is_ok_and(|value| value.trim_end() == item.interface)
        });
    }
    Ok(Some(list))
}

pub(crate) fn detected() -> Vec<Network> {
    if !cfg!(target_os = "linux") {
        return Vec::new();
    }
    let Ok(output) = std::process::Command::new("/usr/bin/ip")
        .args(["-j", "-4", "addr", "show", "up"])
        .output()
    else {
        return Vec::new();
    };
    let Ok(links) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) else {
        return Vec::new();
    };
    let mut choices = Vec::new();
    for link in links {
        let (Some(interface), Some(addresses)) =
            (link["ifname"].as_str(), link["addr_info"].as_array())
        else {
            continue;
        };
        for entry in addresses {
            let (Some(address), Some(prefix)) = (
                entry["local"]
                    .as_str()
                    .and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
                entry["prefixlen"].as_u64(),
            ) else {
                continue;
            };
            if entry["family"] == "inet" {
                if let Some(item) = Network::new(
                    interface.to_owned(),
                    address,
                    &format!("{address}/{prefix}"),
                ) {
                    if !choices.contains(&item) {
                        choices.push(item);
                    }
                }
            }
        }
    }
    choices
}
