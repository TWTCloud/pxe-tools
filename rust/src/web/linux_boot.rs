// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, ErrorBox, Reply, Site};
use crate::{
    configured_database, connect, install,
    linux_install::{self, Plan, Source},
    pxe::{client_in_subnet, log_event},
    setting,
};
use hyper::{header, Response, StatusCode, Uri};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fmt::Write,
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

pub(super) const PREFIX: &str = "/pxe/linux/";

#[derive(Clone, Copy)]
pub(super) enum Loader {
    Grub,
    Ipxe,
}

pub(super) fn route(path: &str) -> Option<(&'static str, Loader)> {
    let (architecture, format) = path.strip_prefix(PREFIX)?.split_once('/')?;
    let arch = match architecture {
        "amd64" => "amd64",
        "arm64" => "arm64",
        _ => return None,
    };
    let loader = match format {
        "grub.cfg" => Loader::Grub,
        "boot.ipxe" => Loader::Ipxe,
        _ => return None,
    };
    Some((arch, loader))
}

#[derive(Clone)]
pub(super) struct RhelRepositories {
    amd64: Option<Uri>,
    arm64: Option<Uri>,
}

impl RhelRepositories {
    pub(super) fn from_environment() -> Self {
        fn read(name: &str) -> Option<Uri> {
            let value = std::env::var(name).ok()?;
            if value.is_empty() {
                return None;
            }
            let repo = repository(&value);
            if repo.is_none() {
                eprintln!("{name} must refer to an HTTP installation tree without credentials or query parameters");
            }
            repo
        }
        Self {
            amd64: read("PXE_RHEL9_AMD64_REPO"),
            arm64: read("PXE_RHEL9_ARM64_REPO"),
        }
    }

    fn for_arch(&self, arch: &str) -> Option<&Uri> {
        match arch {
            "amd64" => self.amd64.as_ref(),
            "arm64" => self.arm64.as_ref(),
            _ => None,
        }
    }
}

fn repository(value: &str) -> Option<Uri> {
    let uri: Uri = value.parse().ok()?;
    let authority = uri.authority()?;
    let host = authority.host();
    if value.contains('#')
        || uri.scheme_str() != Some("http")
        || uri.query().is_some()
        || authority.as_str().contains('@')
        || host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || (authority.as_str().contains(':') && authority.port_u16().is_none())
        || !uri.path().trim_matches('/').split('/').all(|part| {
            !matches!(part, "." | "..")
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return None;
    }
    Some(uri)
}

pub(super) struct Entry {
    pub(super) title: String,
    pub(super) source: Source,
    authority: String,
    kernel: String,
    initrd: String,
    arguments: String,
}

fn ubuntu(
    db: &Connection,
    root: &Path,
    arch: &str,
    authority: &str,
) -> Result<Vec<Entry>, ErrorBox> {
    let netboot = root.join("netboot");
    let Ok(canonical) = netboot.canonicalize() else {
        return Ok(Vec::new());
    };
    if !canonical.starts_with(root) {
        return Ok(Vec::new());
    }
    let mut query = db.prepare(
        "SELECT version_full FROM os_images
         WHERE distro='ubuntu' AND arch=? AND extract_method='iso_extract'
         AND enabled=1 AND status='downloaded' AND version_full IS NOT NULL
         ORDER BY major DESC,version_full DESC LIMIT 32",
    )?;
    let versions = query.query_map([arch], |row| row.get::<_, String>(0))?;
    let mut entries = Vec::new();
    for result in versions {
        let version = result?;
        let components: Vec<_> = version.split('.').collect();
        if !(2..=3).contains(&components.len())
            || !components.iter().all(|part| {
                !part.is_empty()
                    && part.len() <= 3
                    && part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            continue;
        }
        let tag = format!("ubuntu/{version}/{arch}");
        let folder = netboot.join(&tag);
        let ready = ["linux", "initrd.gz", "source.iso"].iter().all(|name| {
            let file = folder.join(name);
            file.canonicalize()
                .ok()
                .is_some_and(|file| file.starts_with(&canonical))
                && fs::symlink_metadata(file).is_ok_and(|file| file.is_file() && file.len() > 0)
        });
        if ready {
            let base = format!("/netboot/{tag}");
            entries.push(Entry {
                title: format!("Ubuntu Server {version}"),
                source: Source::Ubuntu(version),
                authority: authority.to_owned(),
                kernel: format!("{base}/linux"),
                initrd: format!("{base}/initrd.gz"),
                arguments: format!("root=/dev/ram0 ip=dhcp cloud-config-url=/dev/null url=http://{authority}{base}/source.iso"),
            });
        }
    }
    Ok(entries)
}

pub(super) fn menu(
    site: &Site,
    peer: IpAddr,
    server: Ipv4Addr,
    route: (&str, Loader),
    head: bool,
) -> Result<Reply, ErrorBox> {
    let Some(database) = configured_database(&site.database) else {
        return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "PXE indisponible\n"));
    };
    let db = connect(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if !matches!(peer, IpAddr::V4(peer) if client_in_subnet(peer, &setting(&db, "pxe_subnet")?)) {
        return Ok(plain(
            StatusCode::FORBIDDEN,
            "Client hors du sous-réseau PXE\n",
        ));
    }
    let (arch, loader) = route;
    let authority = linux_install::authority(server, site.http_port);
    let entries = available(
        &db,
        site.assets.http_root(),
        &site.rhel_repositories,
        arch,
        &authority,
    )?;
    linux_response(render(&entries, loader, server), head)
}

pub(super) fn available(
    db: &Connection,
    root: &Path,
    repositories: &RhelRepositories,
    arch: &str,
    authority: &str,
) -> Result<Vec<Entry>, ErrorBox> {
    let mut entries = ubuntu(db, root, arch, authority)?;
    if let Some(repo) = repositories.for_arch(arch) {
        let base = repo.path().trim_end_matches('/');
        let host = repo.authority().expect("validated HTTP repository");
        let url = format!("http://{host}{base}/");
        entries.push(Entry {
            title: "Red Hat Enterprise Linux 9".into(),
            source: Source::Rhel9(url.clone()),
            authority: host.to_string(),
            kernel: format!("{base}/images/pxeboot/vmlinuz"),
            initrd: format!("{base}/images/pxeboot/initrd.img"),
            arguments: format!("ip=dhcp inst.repo={url}"),
        });
    }
    Ok(entries)
}

pub(super) fn automatic(
    site: &Site,
    peer: IpAddr,
    server: Ipv4Addr,
    path: &str,
    head: bool,
) -> Result<Reply, ErrorBox> {
    let missing = || plain(StatusCode::NOT_FOUND, "Installation Linux indisponible\n");
    let IpAddr::V4(peer) = peer else {
        return Ok(missing());
    };
    let mut segments = path.trim_start_matches(linux_install::PREFIX).split('/');
    let (Some(boot), Some(key), Some(file), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Ok(missing());
    };
    let Ok(boot) = boot.parse::<i64>() else {
        return Ok(missing());
    };
    if boot <= 0 || key.len() != 32 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(missing());
    }
    let Some(database) = configured_database(&site.database) else {
        return Ok(missing());
    };
    let mut db = connect(&database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if setting(&tx, "pxe_enabled")? != "on" || !client_in_subnet(peer, &setting(&tx, "pxe_subnet")?)
    {
        return Ok(missing());
    }
    let session = tx.query_row(
        "SELECT a.id,a.token,b.mac,m.mac,m.boot_arch FROM boot_sessions b
         JOIN machines m ON m.id=b.machine_id JOIN actions a ON a.id=b.action_id AND a.machine_id=m.id
         WHERE b.id=?1 AND b.token=?2 AND b.client_ip=?3 AND b.default_menu='install'
         AND b.selected_menu='install' AND b.served_at>=datetime('now','-90 minutes')
         AND a.type='install_only' AND a.status IN ('pending','running') AND m.rescue_mode=0",
        params![boot, key, peer.to_string()],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                  row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?)),
    ).optional()?;
    let Some((action, token, boot_mac, mac, arch)) = session else {
        return Ok(missing());
    };
    let Some(machine) = install::machine(&tx, &mac, false)? else {
        return Ok(missing());
    };
    let snapshot: serde_json::Value =
        serde_json::from_str(machine.config.as_deref().unwrap_or_default()).unwrap_or_default();
    let Ok(plan) = serde_json::from_value::<Plan>(snapshot["linux_deployment"].clone()) else {
        return Ok(missing());
    };
    if arch.as_deref() != Some(plan.arch.as_str())
        || plan.client != peer
        || plan.boot_mac != boot_mac
        || !plan.valid()
        || snapshot["_pending_action_id"].as_i64() != Some(action)
        || install::latest_action(&tx, machine.id)?.map(|(id, _)| id) != Some(action)
        || !install::eligible(&tx, &machine, Some(action))?
        || install::installation_closed(&tx, machine.id, Some(action))?
        || install::other_active_install(&tx, machine.id, Some(action))?
    {
        return Ok(missing());
    }
    let authority = linux_install::authority(server, site.http_port);
    let Some(mut entry) = available(
        &tx,
        site.assets.http_root(),
        &site.rhel_repositories,
        &plan.arch,
        &authority,
    )?
    .into_iter()
    .find(|entry| entry.source == plan.source) else {
        return Ok(missing());
    };
    let seed = format!("http://{authority}{}{boot}/{key}/", linux_install::PREFIX);
    let body = match (&plan.source, file) {
        (Source::Ubuntu(_), "meta-data") => format!("instance-id: pxe-tools-{action}\n"),
        (Source::Ubuntu(_), "vendor-data") => String::new(),
        (source, "grub.cfg") => {
            match source {
                Source::Ubuntu(_) => write!(
                    entry.arguments,
                    " autoinstall 'ds=nocloud-net;s={seed}' ---"
                )?,
                Source::Rhel9(_) => write!(
                    entry.arguments,
                    " inst.cmdline inst.ks={seed}kickstart.cfg inst.nosave=all_ks"
                )?,
            }
            render_grub_entry(&entry)
        }
        (Source::Ubuntu(_), "user-data") | (Source::Rhel9(_), "kickstart.cfg") => {
            let Some(configuration) = plan.configuration(&mac, &token, server, site.http_port)
            else {
                return Ok(missing());
            };
            if !head && machine.status == "configured" {
                let id = install::start_row(&tx, &machine, Some(action))?;
                log_event(
                    &tx,
                    machine.id,
                    "info",
                    "Configuration Linux servie à l’installateur",
                    Some("preseed_loaded_install"),
                    Some(action),
                )?;
                install::ping_phase(&tx, "install", id, "preseed-loaded", "success", None)?;
                install::recompute(&tx, action)?;
            }
            configuration
        }
        _ => return Ok(missing()),
    };
    tx.commit()?;
    linux_response(body, head)
}

fn linux_response(body: String, head: bool) -> Result<Reply, ErrorBox> {
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, body.len())
        .body(if head { bytes("") } else { bytes(body) })?)
}

fn render_grub_entry(entry: &Entry) -> String {
    let address = &entry.authority;
    format!(
        "set timeout=0\nset default=0\nmenuentry 'Installer {}' {{\n    linux (http,{address}){} {}\n    initrd (http,{address}){}\n}}\n",
        entry.title, entry.kernel, entry.arguments, entry.initrd
    )
}

fn render(entries: &[Entry], loader: Loader, server: Ipv4Addr) -> String {
    let mut script = String::new();
    match loader {
        Loader::Grub => {
            script.push_str("set timeout=-1\n");
            for entry in entries {
                let address = &entry.authority;
                writeln!(script,
                    "menuentry 'Installer {}' {{\n    linux (http,{address}){} {}\n    initrd (http,{address}){}\n}}",
                    entry.title, entry.kernel, entry.arguments, entry.initrd,
                ).expect("write to String");
            }
            writeln!(script, "menuentry 'Retour au menu PXE' {{\n    configfile (tftp,{server})/grub/grub.cfg\n}}")
                .expect("write to String");
        }
        Loader::Ipxe => {
            script.push_str("#!ipxe\n:menu\nmenu Installateurs Linux\n");
            for (id, entry) in entries.iter().enumerate() {
                writeln!(script, "item linux-{id} Installer {}", entry.title)
                    .expect("write to String");
            }
            script.push_str("item return Retour au menu PXE\nchoose selected || goto return\ngoto \x24{selected}\n");
            for (id, entry) in entries.iter().enumerate() {
                let host = &entry.authority;
                writeln!(script,
                    ":linux-{id}\nkernel http://{host}{} initrd=initrd.img {} || goto menu\ninitrd --name initrd.img http://{host}{} || goto menu\nboot || goto menu",
                    entry.kernel, entry.arguments, entry.initrd,
                ).expect("write to String");
            }
            script.push_str(":return\nexit\n");
        }
    }
    script
}
