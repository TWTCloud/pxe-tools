// SPDX-License-Identifier: LGPL-3.0-only

use super::{fallback, list};
use crate::pxe::{array_values, is_php_array, normalize_mac};
use crate::{decimal, php_string, php_truthy};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::{collections::HashSet, net::Ipv4Addr};

const BOND_SCRIPT: &str = include_str!("../../assets/pxe/target-bond.sh").trim_ascii_end();

pub(super) struct Network {
    pub(super) installer: String,
    pub(super) secondary: Vec<String>,
    pub(super) packages: Vec<&'static str>,
}

impl Network {
    pub(super) fn new(config: &Value) -> Option<Self> {
        let plan = &config["network"];
        let interfaces: Vec<_> = array_values(&plan["interfaces"]).collect();
        if interfaces.is_empty() {
            return Some(Self {
                installer: legacy(config)?,
                secondary: Vec::new(),
                packages: Vec::new(),
            });
        }

        let primary_index = usize::try_from(decimal(&php_string(&plan["primary"]))).ok()?;
        let primary = *interfaces.get(primary_index)?;
        if !matches!(mode(primary)?, "dhcp" | "static") || php_truthy(&primary["vlan"]) {
            return None;
        }
        let mut seen = HashSet::new();
        let mut secondary = Vec::new();
        let mut packages = Vec::new();
        let mut selector = String::from("auto");
        let mut bonds = Vec::new();
        for (index, iface) in interfaces.into_iter().enumerate() {
            let mode = mode(iface)?;
            let mac = iface["match"]["mac"].as_str().filter(|raw| !raw.is_empty());
            let mac = if let Some(raw) = mac {
                let mac = normalize_mac(raw)?;
                if !raw.eq_ignore_ascii_case(&mac) || !seen.insert(mac.clone()) {
                    return None;
                }
                Some(mac)
            } else {
                None
            };
            if index == primary_index && iface["match_by"] == "mac" {
                if let Some(mac) = &mac {
                    selector.clone_from(mac);
                }
            }
            let vlan = vlan(&iface["vlan"])?;
            if php_truthy(&iface["bond"]) {
                if vlan.is_some() {
                    return None;
                }
                Bond::add_member(&mut bonds, iface, index, mac?)?;
            } else if index != primary_index && mode != "disabled" {
                if vlan.is_some() && packages.is_empty() {
                    packages.push("vlan");
                }
                secondary.push(render_secondary(iface, &mac?, index, vlan)?);
            }
        }

        let mut installer_address = primary;
        for bond in &mut bonds {
            let (master_index, master, bond_mode) = bond.master?;
            if bond.members.len() < 2 {
                return None;
            }
            if bond
                .members
                .iter()
                .any(|(index, _)| *index == primary_index)
            {
                installer_address = master;
            }
            bond.members
                .sort_by_key(|(index, _)| (*index != primary_index, *index != master_index));
            secondary.push(bond.render(master, bond_mode)?);
        }
        if !bonds.is_empty() {
            packages.push("ifenslave");
        }

        let settings = &installer_address["static"];
        let static_settings = (mode(installer_address)? == "static").then_some([
            &settings["ip"],
            &settings["cidr"],
            &settings["gateway"],
            &settings["dns"],
        ]);
        Some(Self {
            installer: render_installer(&selector, "# Interface primaire : DHCP", static_settings)?,
            secondary,
            packages,
        })
    }
}

struct Bond<'a> {
    name: &'a str,
    members: Vec<(usize, String)>,
    master: Option<(usize, &'a Value, &'a str)>,
}

impl<'a> Bond<'a> {
    fn add_member(
        bonds: &mut Vec<Self>,
        interface: &'a Value,
        index: usize,
        mac: String,
    ) -> Option<()> {
        let config = &interface["bond"];
        let name = config["name"].as_str()?;
        if name.len() > 15
            || !name.as_bytes().first()?.is_ascii_alphabetic()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return None;
        }
        let position = bonds.iter().position(|bond| bond.name == name);
        let group = match position {
            Some(position) => &mut bonds[position],
            None => {
                bonds.push(Self {
                    name,
                    members: Vec::new(),
                    master: None,
                });
                bonds.last_mut()?
            }
        };
        group.members.push((index, mac));
        match config["role"].as_str()? {
            "master" if group.master.is_none() && mode(interface)? != "disabled" => {
                let mode = config["mode"].as_str().unwrap_or("active-backup");
                if !matches!(
                    mode,
                    "active-backup"
                        | "balance-rr"
                        | "balance-xor"
                        | "broadcast"
                        | "802.3ad"
                        | "balance-tlb"
                        | "balance-alb"
                ) {
                    return None;
                }
                group.master = Some((index, interface, mode));
            }
            "slave" => {}
            _ => return None,
        }
        Some(())
    }

    fn render(&self, master: &Value, bond_mode: &str) -> Option<String> {
        let name = self.name;
        let mut stanza = format!("# Genere par PXE Tools : bond {name}\nauto {name}\n");
        stanza.push_str(&interface_stanza(name, master)?);
        stanza.push_str(&format!("    bond-mode {bond_mode}\n    bond-miimon 100"));
        let active_backup = bond_mode == "active-backup";
        if active_backup {
            stanza.push_str("\n    bond-primary-reselect always\n    bond-updelay 5000");
        }
        let macs = self
            .members
            .iter()
            .map(|(_, mac)| mac.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let script = BOND_SCRIPT
            .replace("__MACS__", &macs)
            .replace("__STANZA__", &stanza)
            .replace("__BOND__", name)
            .replace("__ACTIVE_BACKUP__", if active_backup { "1" } else { "0" });
        Some(format!(
            "in-target /bin/bash -c 'echo {} | base64 -d | /bin/bash'",
            STANDARD.encode(script)
        ))
    }
}

fn mode(interface: &Value) -> Option<&str> {
    match interface["mode"].as_str().unwrap_or("dhcp") {
        mode @ ("dhcp" | "static" | "disabled") => Some(mode),
        _ => None,
    }
}

fn vlan(value: &Value) -> Option<Option<u16>> {
    if !php_truthy(value) {
        return Some(None);
    }
    let id = php_string(&value["id"]).parse::<u16>().ok()?;
    (1..=4094).contains(&id).then_some(Some(id))
}

fn legacy(config: &Value) -> Option<String> {
    let static_settings = (config["network_mode"] == "static" && php_truthy(&config["static_ip"]))
        .then_some([
            &config["static_ip"],
            &config["static_cidr"],
            &config["static_gateway"],
            &config["static_dns"],
        ]);
    render_installer("auto", "# Réseau : DHCP (default)", static_settings)
}

fn render_installer(
    selector: &str,
    dhcp_comment: &str,
    static_settings: Option<[&Value; 4]>,
) -> Option<String> {
    let mut block = format!("d-i netcfg/choose_interface select {selector}");
    let Some([address, cidr, gateway, dns]) = static_settings else {
        block.push('\n');
        block.push_str(dhcp_comment);
        return Some(block);
    };
    let (address, netmask, gateway) = static_address(address, cidr, gateway)?;
    let dns = if is_php_array(dns) {
        list(dns, &[])
    } else {
        let raw = php_string(dns);
        if let Some(value) = serde_json::from_str::<Value>(&raw)
            .ok()
            .filter(is_php_array)
        {
            list(&value, &[])
        } else {
            raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        }
    };
    block.push_str(&format!("\nd-i netcfg/disable_autoconfig boolean true\nd-i netcfg/get_ipaddress string {address}\nd-i netcfg/get_netmask string {netmask}\nd-i netcfg/get_gateway string {}\nd-i netcfg/get_nameservers string {}\nd-i netcfg/confirm_static boolean true",
        gateway.map(|ip| ip.to_string()).unwrap_or_default(), dns.join(" ")));
    Some(block)
}

fn static_address(
    address: &Value,
    cidr: &Value,
    gateway: &Value,
) -> Option<(Ipv4Addr, Ipv4Addr, Option<Ipv4Addr>)> {
    let address = address.as_str()?.parse().ok()?;
    let cidr = decimal(&php_string(cidr));
    let cidr = if cidr == 0 {
        24
    } else {
        cidr.clamp(1, 32) as u32
    };
    let netmask = Ipv4Addr::from(u32::MAX << (32 - cidr));
    let gateway = fallback(gateway, "");
    let gateway = if gateway.is_empty() {
        None
    } else {
        Some(gateway.parse().ok()?)
    };
    Some((address, netmask, gateway))
}

fn render_secondary(iface: &Value, mac: &str, index: usize, vlan: Option<u16>) -> Option<String> {
    const DEVICE: &str = "__IFNAME__";
    let name = vlan.map_or_else(|| DEVICE.to_owned(), |id| format!("{DEVICE}.{id}"));
    let mut stanza = format!("# Géré par preseed multi-NIC (PXE Tools)\nauto {name}\n");
    stanza.push_str(&interface_stanza(&name, iface)?);
    if vlan.is_some() {
        stanza.push_str(&format!("    vlan-raw-device {DEVICE}\n"));
    }
    let stanza = STANDARD.encode(stanza);
    let path = format!("/etc/network/interfaces.d/pxe-nic-{index:02}");
    Some(format!(
        r##"in-target /bin/bash -c 'ifname=$(ip -br link 2>/dev/null | awk -v m={mac} "BEGIN{{IGNORECASE=1}} tolower(\$3)==tolower(m){{print \$1; exit}}"); if [ -n "$ifname" ]; then echo {stanza} | base64 -d | sed "s/{DEVICE}/$ifname/g" > {path}; else echo "# NIC {mac} non trouvée au runtime" > {path}; fi'"##
    ))
}

fn interface_stanza(name: &str, iface: &Value) -> Option<String> {
    let mut stanza = String::new();
    if mode(iface)? == "static" {
        let st = &iface["static"];
        let (address, netmask, gateway) = static_address(&st["ip"], &st["cidr"], &st["gateway"])?;
        stanza.push_str(&format!(
            "iface {name} inet static\n    address {address}\n    netmask {netmask}\n"
        ));
        if let Some(gateway) = gateway {
            stanza.push_str(&format!("    gateway {gateway}\n"));
        }
        let dns = list(&st["dns"], &[]);
        if !dns.is_empty() {
            let dns = dns
                .into_iter()
                .map(|ip| ip.parse::<Ipv4Addr>().ok())
                .collect::<Option<Vec<_>>>()?;
            let dns = dns
                .iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            stanza.push_str(&format!("    dns-nameservers {dns}\n"));
        }
    } else {
        stanza.push_str(&format!("iface {name} inet dhcp\n"));
    }
    Some(stanza)
}
