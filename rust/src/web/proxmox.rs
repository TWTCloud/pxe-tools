// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, ErrorBox, Reply, Site};
use crate::{
    configured_database, connect, install,
    linux_install::{authority, Plan, Source},
    media, pxe, setting,
};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, header, Method, Response, StatusCode};
use rusqlite::{params, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    time::Duration,
};
use tokio::time::timeout;

pub(super) const PREFIX: &str = "/pxe/proxmox/";

#[derive(Deserialize)]
struct MediaBinding {
    authority: String,
    pin: String,
}

pub(super) fn media_matches(
    root: &Path,
    version: &str,
    arch: &str,
    authority: &str,
    pin: &str,
) -> bool {
    let marker = root.join(format!("netboot/proxmox/{version}/{arch}/.managed-answer"));
    fs::symlink_metadata(&marker).is_ok_and(|meta| meta.is_file() && meta.len() < 512)
        && fs::read(&marker)
            .ok()
            .and_then(|data| serde_json::from_slice::<MediaBinding>(&data).ok())
            .is_some_and(|binding| binding.authority == authority && binding.pin == pin)
}

fn missing() -> Reply {
    plain(StatusCode::NOT_FOUND, "Installation Proxmox indisponible\n")
}

pub(super) async fn serve(
    site: &Site,
    path: &str,
    method: &Method,
    body: Incoming,
    peer: IpAddr,
    server: Ipv4Addr,
    secure: bool,
) -> Reply {
    let IpAddr::V4(peer) = peer else {
        return missing();
    };
    if !secure || !site.is_pxe_address(server) {
        return missing();
    }
    let route = path.trim_start_matches(PREFIX);
    let Ok(_permit) = site.requests.try_acquire() else {
        return plain(StatusCode::SERVICE_UNAVAILABLE, "Busy\n");
    };
    let payload = match (*method == Method::POST, route) {
        (true, "answer") => {
            let Ok(Ok(body)) = timeout(
                Duration::from_secs(5),
                Limited::new(body, 256 * 1024).collect(),
            )
            .await
            else {
                return missing();
            };
            let Ok(payload) = serde_json::from_slice(&body.to_bytes()) else {
                return missing();
            };
            Some(payload)
        }
        (true, route) if route.starts_with("complete/") => {
            let Ok(Ok(body)) = timeout(
                Duration::from_secs(5),
                Limited::new(body, 256 * 1024).collect(),
            )
            .await
            else {
                return missing();
            };
            let Ok(payload) = serde_json::from_slice(&body.to_bytes()) else {
                return missing();
            };
            Some(payload)
        }
        (false, route) if *method == Method::GET && route.starts_with("hook/") => None,
        _ => return missing(),
    };
    // The handlers execute short SQLite operations and read only media metadata.
    tokio::task::block_in_place(|| {
        handle(site, route, peer, server, payload.as_ref()).unwrap_or_else(|error| {
            eprintln!("Proxmox PXE: {error}");
            plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "Installation Proxmox indisponible\n",
            )
        })
    })
}

fn handle(
    site: &Site,
    route: &str,
    peer: Ipv4Addr,
    server: Ipv4Addr,
    payload: Option<&Value>,
) -> Result<Reply, ErrorBox> {
    let Some(database) = configured_database(&site.database) else {
        return Ok(missing());
    };
    let mut db = connect(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    if setting(&db, "pxe_enabled")? != "on" || !site.pxe_peer(&db, server, IpAddr::V4(peer))? {
        return Ok(missing());
    }
    if let (Some(action), Some(payload)) = (route.strip_prefix("complete/"), payload) {
        let Some(action) = action.parse::<i64>().ok().filter(|id| *id > 0) else {
            return Ok(missing());
        };
        let Some(token) = payload["token"]
            .as_str()
            .filter(|token| install::valid_token(token))
        else {
            return Ok(missing());
        };
        let target = db.query_row(
            "SELECT m.mac,m.install_config_json FROM actions a JOIN machines m ON m.id=a.machine_id
             WHERE a.id=?1 AND a.token=?2 AND a.type='install_only'",
            params![action, token],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).optional()?;
        let Some((mac, config)) = target else {
            return Ok(missing());
        };
        let snapshot: Value = serde_json::from_str(&config)?;
        let Ok(plan) = serde_json::from_value::<Plan>(snapshot["linux_deployment"].clone()) else {
            return Ok(missing());
        };
        if !matches!(plan.source, Source::Proxmox(_))
            || plan.client != peer
            || snapshot["_pending_action_id"].as_i64() != Some(action)
        {
            return Ok(missing());
        }
        let (status, _) = install::end(&mut db, true, &mac, token, "success", true, None)?;
        return Ok(plain(StatusCode::from_u16(status as u16)?, "Proxmox\n"));
    }

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut query = tx.prepare(
        "SELECT b.id,b.token,b.mac,a.id,a.token,m.mac,m.boot_arch,m.install_config_json
         FROM boot_sessions b JOIN machines m ON m.id=b.machine_id
         JOIN actions a ON a.id=b.action_id AND a.machine_id=m.id
         WHERE b.client_ip=?1 AND b.default_menu='install' AND b.selected_menu='install'
           AND b.served_at>=datetime('now','-90 minutes') AND a.type='install_only'
           AND a.status IN ('pending','running') AND m.rescue_mode=0
         ORDER BY b.id DESC LIMIT 1",
    )?;
    let mut rows = query.query([peer.to_string()])?;
    let Some(row) = rows.next()? else {
        return Ok(missing());
    };
    let (boot, key, boot_mac, action, token, mac, arch, config): (
        i64,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
    ) = (
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    );
    drop(rows);
    drop(query);
    let snapshot: Value = serde_json::from_str(&config)?;
    let Ok(plan) = serde_json::from_value::<Plan>(snapshot["linux_deployment"].clone()) else {
        return Ok(missing());
    };
    let Source::Proxmox(version) = &plan.source else {
        return Ok(missing());
    };
    let Some(machine) = install::machine(&tx, &mac, false)? else {
        return Ok(missing());
    };
    if version != media::PROXMOX_VERSION
        || !plan.valid()
        || plan.client != peer
        || plan.arch != arch
        || plan.boot_mac != boot_mac
        || !install::valid_token(&token)
        || snapshot["_pending_action_id"].as_i64() != Some(action)
        || install::latest_action(&tx, machine.id)?.map(|(id, _)| id) != Some(action)
        || !install::eligible(&tx, &machine, Some(action))?
        || install::installation_closed(&tx, machine.id, Some(action))?
        || install::other_active_install(&tx, machine.id, Some(action))?
    {
        return Ok(missing());
    }
    let authority = format!("{server}:{}", site.console_port.active());
    let pin = site.tls.pin();
    if !media_matches(site.assets.http_root(), version, &arch, &authority, &pin) {
        return Ok(missing());
    }
    if route == "answer" {
        let Some(payload) = payload else {
            return Ok(missing());
        };
        let hardware = payload.get("sysinfo").unwrap_or(payload);
        let interfaces = hardware
            .get("network_interfaces")
            .or_else(|| hardware.get("network-interfaces"));
        if !interfaces
            .and_then(Value::as_array)
            .is_some_and(|interfaces| {
                interfaces.iter().any(|nic| {
                    nic["mac"].as_str().and_then(pxe::normalize_mac).as_deref()
                        == Some(boot_mac.as_str())
                })
            })
        {
            return Ok(missing());
        }
        let hook = format!("https://{authority}{PREFIX}hook/{boot}/{key}");
        let complete = format!("https://{authority}{PREFIX}complete/{action}");
        let answer = answer(&plan, &hook, &complete, &pin, &token);
        if machine.status == "configured" {
            let id = install::start_row(&tx, &machine, Some(action))?;
            pxe::log_event(
                &tx,
                machine.id,
                "info",
                "Réponse Proxmox servie à l’installateur",
                Some("preseed_loaded_install"),
                Some(action),
            )?;
            install::ping_phase(&tx, "install", id, "preseed-loaded", "success", None)?;
            install::recompute(&tx, action)?;
        }
        tx.commit()?;
        return text("application/toml", answer);
    }
    if route != format!("hook/{boot}/{key}") || machine.status == "configured" {
        return Ok(missing());
    }
    text(
        "text/plain; charset=utf-8",
        hook(server, site.http_port, &machine.mac, &token),
    )
}

fn text(content_type: &'static str, body: String) -> Result<Reply, ErrorBox> {
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(bytes(body))?)
}

fn answer(plan: &Plan, hook: &str, complete: &str, pin: &str, token: &str) -> String {
    format!(
        r#"[global]
keyboard = "fr"
country = "fr"
fqdn = {host:?}
mailto = {mail:?}
timezone = "Europe/Paris"
root-password-hashed = {hash:?}
reboot-mode = "reboot"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
filter-match = "all"
filter.DEVNAME = {disk:?}
filter.ID_SERIAL_SHORT = {serial:?}

[post-installation-webhook]
url = {complete:?}
cert-fingerprint = {pin:?}
auth-token = {token:?}

[first-boot]
source = "from-url"
ordering = "network-online"
url = {hook:?}
cert-fingerprint = {pin:?}
"#,
        host = plan.hostname,
        mail = plan.proxmox_email,
        hash = plan.password_hash,
        disk = plan.disk,
        serial = plan.serial
    )
}

fn hook(server: Ipv4Addr, port: u16, mac: &str, token: &str) -> String {
    let base = format!("http://{}", authority(server, port));
    format!(
        r#"#!/bin/sh
set -eu
command -v pveversion >/dev/null
for attempt in $(seq 1 60); do
    if systemctl is-active --quiet pveproxy.service; then
        curl -fsS --connect-timeout 5 --max-time 15 --retry 3 -o /dev/null \
            -H 'Authorization: Bearer {token}' -d 'first_boot=1' \
            '{base}/api/install-end?mac={mac}&status=success'
        receipt=$(curl -fsS --connect-timeout 5 --max-time 15 --retry 3 \
            -H 'Authorization: Bearer {token}' -d '' \
            '{base}/api/internal/checkpoint?mac={mac}&code=os_first_boot&ack=1')
        if [ "$receipt" = accepted ]; then
            rm -f -- /var/lib/proxmox-first-boot/proxmox-first-boot
            exit 0
        fi
    fi
    sleep 2
done
exit 1
"#
    )
}
