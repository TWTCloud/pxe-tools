// SPDX-License-Identifier: LGPL-3.0-only

use crate::pxe::{log_event, machine_for_mac, menu_label, normalize_mac, parse_subnet};
use crate::{header, linux_install, response, setting, HttpResponse, TEXT};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};

const DISCOVERY: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-discovery.cfg"));
const INSTALL: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-install.cfg"));
const LOCAL: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-local.cfg"));
const RESCUE: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-rescue.cfg"));
const DISK_TEST: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-disktest.cfg"));
const WIPE: &str = include_str!(concat!(env!("OUT_DIR"), "/grub-wipe.cfg"));

struct Machine {
    mac: String,
    status: String,
    hostname: String,
    architecture: Option<String>,
    codename: Option<String>,
    preset_distro: Option<String>,
    config: Option<String>,
    protocol: String,
    rescue: bool,
    local_boot: String,
}

pub fn serve(
    db: &mut Connection,
    peer: Option<IpAddr>,
    raw_mac: &str,
    boot_arch: &str,
) -> rusqlite::Result<HttpResponse> {
    let Some((network, mask)) = parse_subnet(&setting(db, "pxe_subnet")?) else {
        return Ok(reply(
            503,
            "# PXE network configuration missing or invalid\n",
        ));
    };
    let Some(IpAddr::V4(peer)) =
        peer.filter(|peer| matches!(peer, IpAddr::V4(ip) if u32::from(*ip) & mask == network))
    else {
        return Ok(reply(403, "# accès refusé : hôte hors subnet PXE\n"));
    };
    let Ok(server) = setting(db, "pxe_ip")?.parse::<Ipv4Addr>() else {
        return Ok(reply(503, "# PXE address unavailable\n"));
    };
    let mac = normalize_mac(raw_mac).or_else(|| arp_mac(peer));
    let boot_arch = architecture(boot_arch);
    let default_arch = std::env::var("DEBIAN_ARCH").unwrap_or_default();
    let default_distro = std::env::var("DEBIAN_DEFAULT_VERSION").unwrap_or_default();
    let default_distro = codename(&default_distro).unwrap_or("trixie");
    let kernel = std::env::var("KERNEL_OPTS").unwrap_or_else(|_| {
        "language=fr country=FR locale=fr_FR.UTF-8 keymap=fr ipv6.disable=1".to_owned()
    });
    let kernel = kernel.trim_end_matches('\\');
    if kernel.contains(['\r', '\n', '\0']) {
        return Ok(reply(503, "# Invalid PXE kernel options\n"));
    }
    let Ok(token) = crate::random_token() else {
        return Ok(reply(503, "# PXE boot token unavailable\n"));
    };

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut id = match mac.as_deref() {
        Some(mac) => machine_for_mac(&tx, mac)?,
        None => None,
    };
    let machine =
        if let Some(id) = id {
            Some(tx.query_row(
            "SELECT m.mac, m.status, COALESCE(m.hostname,''), m.boot_arch, p.codename, p.distro,
                    m.install_config_json, COALESCE(m.boot_mode,'http'), COALESCE(m.rescue_mode,0),
                    COALESCE(m.local_boot_source,'none')
             FROM machines m LEFT JOIN presets p ON p.id = m.preset_id WHERE m.id = ?",
            [id],
            |row| Ok(Machine {
                mac: row.get(0)?, status: row.get(1)?, hostname: row.get(2)?,
                architecture: row.get(3)?, codename: row.get(4)?, preset_distro: row.get(5)?,
                config: row.get(6)?, protocol: row.get(7)?, rescue: row.get::<_,i64>(8)? == 1,
                local_boot: row.get(9)?,
            }),
        )?)
        } else {
            if let Some(mac) = mac.as_deref() {
                tx.execute(
                    "INSERT INTO machines (mac,status,last_seen_at,boot_arch)
                 VALUES (?,'inventorying',CURRENT_TIMESTAMP,?)",
                    params![mac, boot_arch],
                )?;
                id = Some(tx.last_insert_rowid());
            }
            None
        };

    let menu = match machine.as_ref() {
        Some(machine) if machine.rescue => "rescue",
        Some(machine) if machine.status == "testing" => "disktest",
        Some(machine) if machine.status == "wiping" => "wipe",
        Some(machine) if machine.status == "configured" => "install",
        Some(machine)
            if !matches!(
                machine.status.as_str(),
                "installing"
                    | "inventorying"
                    | "unknown"
                    | "discovered"
                    | "tested"
                    | "failed"
                    | "wiped"
            ) && matches!(machine.local_boot.as_str(), "pxe" | "manual") =>
        {
            "local"
        }
        _ => "discovery",
    };
    let boot = if let (Some(id), Some(mac)) = (id, mac.as_deref()) {
        let action = tx.query_row(
            "SELECT id, type FROM actions WHERE machine_id = ? AND status IN ('pending','running')
             ORDER BY id DESC LIMIT 1",
            [id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        ).optional()?;
        let action_id = action.as_ref().map(|(id, _)| *id);
        tx.execute(
            "INSERT INTO boot_sessions (machine_id,action_id,mac,default_menu,token,client_ip)
             VALUES (?,?,?,?,?,?)",
            params![id, action_id, mac, menu, token, peer.to_string()],
        )?;
        let boot = tx.last_insert_rowid();
        let label = menu_label(menu).expect("known GRUB menu");
        log_event(
            &tx,
            id,
            "info",
            &format!("Menu GRUB servi par défaut : {label}"),
            None,
            action_id,
        )?;
        let code = match action.as_ref().map(|(_, kind)| (menu, kind.as_str())) {
            Some(("install", "install_only" | "reinstall")) => Some("grub_config_served_install"),
            Some(("disktest", "disktest")) => Some("grub_config_served_disktest"),
            Some(("wipe", "wipe_only" | "reinstall")) => Some("grub_config_served_wipe"),
            _ => None,
        };
        if let Some(code) = code {
            let fields = json!({"mac": mac, "ip": peer.to_string(), "src": "grub.php"});
            log_event(
                &tx,
                id,
                "info",
                &format!("checkpoint:{code} {fields}"),
                Some(code),
                action_id,
            )?;
        }
        Some(boot)
    } else {
        None
    };
    let signal = |selected| {
        boot.map(|id| format!(
            "if source \"(http,{server})/api/boot-selected?boot_id={id}&token={token}&menu={selected}\"; then true; fi"
        )).unwrap_or_default()
    };
    let arch = machine
        .as_ref()
        .and_then(|m| m.architecture.as_deref())
        .and_then(architecture)
        .or(boot_arch)
        .or_else(|| architecture(&default_arch))
        .unwrap_or("amd64");
    let proto = if menu == "discovery" {
        setting(&tx, "discovery_boot_proto")?
    } else {
        machine
            .as_ref()
            .map(|m| m.protocol.clone())
            .unwrap_or_default()
    };
    let proto = if proto == "tftp" { "tftp" } else { "http" };
    let mut body = format!("set timeout=3\nset default=0\nset net_default_server={server}\n\n");
    let linux = machine.as_ref().and_then(|machine| {
        serde_json::from_str::<Value>(machine.config.as_deref().unwrap_or_default())
            .ok()
            .and_then(|mut snapshot| snapshot.get_mut("linux_deployment").map(Value::take))
    });
    let render = |template: &str, selected, machine: Option<&Machine>| {
        let hostname: String = machine
            .map(|m| m.hostname.to_ascii_lowercase())
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        let hostname = if hostname.is_empty() {
            "unassigned"
        } else {
            &hostname
        };
        let mac = machine
            .and_then(|m| normalize_mac(&m.mac))
            .unwrap_or_default();
        let distro = machine.and_then(machine_codename).unwrap_or(default_distro);
        template
            .replace("\\$", "$")
            .replace(
                "$label",
                match selected {
                    "discovery" => "Identification du matériel",
                    "rescue" => "Mode de récupération (rescue)",
                    "disktest" => "Tests de disque (SMART + badblocks)",
                    "wipe" => "Effacement sécurisé des disques",
                    _ => "Installation automatique : $hostname (Debian $distro)",
                },
            )
            .replace("$hostname", hostname)
            .replace("$default_distro", default_distro)
            .replace("$distro", distro)
            .replace("$default_arch", arch)
            .replace("$proto", proto)
            .replace(
                "$preseedUrl",
                &format!(
                    "http://{server}/{}-preseed.cfg",
                    match selected {
                        "disktest" | "wipe" => selected,
                        _ => "discovery",
                    }
                ),
            )
            .replace("$orch_ip", &server.to_string())
            .replace("$mac", &mac)
            .replace("$signal", &signal(selected))
            .replace("$kernel_opts", kernel)
    };
    match menu {
        "install" if linux.is_some() => {
            if let Some(id) = boot.filter(|_| {
                linux
                    .and_then(|value| serde_json::from_value::<linux_install::Plan>(value).ok())
                    .is_some_and(|plan| {
                        plan.valid()
                            && plan.client == peer
                            && mac.as_deref() == Some(plan.boot_mac.as_str())
                    })
            }) {
                let port = std::env::var("PXE_HTTP_PORT")
                    .ok()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(80);
                let host = linux_install::authority(server, port);
                let prefix = linux_install::PREFIX;
                body.push_str(&format!(
                    "menuentry 'Installation Linux programmée' {{\n    if [ \"$grub_platform\" = efi ]; then\n\
                         if source \"(http,{host})/api/boot-selected?boot_id={id}&token={token}&menu=install\"; then\n\
                           configfile (http,{host}){prefix}{id}/{token}/grub.cfg\n    fi\n    fi\n}}\n"
                ));
            } else {
                body.push_str("set timeout=-1\nmenuentry 'Installation Linux indisponible' { echo 'Vérifier le bail DHCP de l’appareil'; }\n");
            }
        }
        "install" => body.push_str(&render(INSTALL, menu, machine.as_ref())),
        "rescue" => body.push_str(&render(RESCUE, menu, machine.as_ref())),
        "disktest" => body.push_str(&render(DISK_TEST, menu, machine.as_ref())),
        "wipe" => body.push_str(&render(WIPE, menu, machine.as_ref())),
        "local" => {
            let local = render(LOCAL, menu, machine.as_ref());
            if arch == "arm64" {
                body.push_str(&local.replace("shimx64.efi", "grubaa64.efi"));
            } else {
                body.push_str(&local);
            }
            if linux.is_none() {
                body.push('\n');
                body.push_str(&render(INSTALL, "install", machine.as_ref()));
            }
        }
        _ => body.push_str(&render(DISCOVERY, menu, machine.as_ref())),
    }
    body.push_str(&format!(
        "\nmenuentry 'Autres options de démarrage' {{\n    {}\n    configfile (tftp,{server})/grub/grub.cfg\n}}\n",
        signal("other")
    ));
    tx.commit()?;
    Ok(reply(200, body))
}

fn architecture(raw: &str) -> Option<&'static str> {
    match raw {
        "amd64" | "x86_64" => Some("amd64"),
        "arm64" | "aarch64" => Some("arm64"),
        "i386" | "i686" => Some("i386"),
        _ => None,
    }
}

fn codename(raw: &str) -> Option<&'static str> {
    match raw {
        "bullseye" => Some("bullseye"),
        "bookworm" => Some("bookworm"),
        "trixie" => Some("trixie"),
        "forky" => Some("forky"),
        _ => None,
    }
}

fn machine_codename(machine: &Machine) -> Option<&'static str> {
    let config: Value =
        serde_json::from_str(machine.config.as_deref().unwrap_or_default()).unwrap_or_default();
    let name = machine.codename.as_deref().or(config["codename"].as_str());
    name.and_then(|name| codename(&name.trim().to_ascii_lowercase()))
        .or_else(
            || match config["version_full"].as_str()?.split('.').next()? {
                "11" => Some("bullseye"),
                "12" => Some("bookworm"),
                "13" => Some("trixie"),
                "14" => Some("forky"),
                _ => None,
            },
        )
        .or_else(|| machine.preset_distro.as_deref().and_then(codename))
}

fn arp_mac(peer: Ipv4Addr) -> Option<String> {
    let peer = peer.to_string();
    fs::read_to_string("/proc/net/arp")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            if fields.next()? == peer {
                normalize_mac(fields.nth(2)?).filter(|mac| mac != "00:00:00:00:00:00")
            } else {
                None
            }
        })
}

fn reply(status: u16, body: impl Into<String>) -> HttpResponse {
    response(status, TEXT, body).with_header(header("Cache-Control", "no-store"))
}
