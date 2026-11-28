// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{params, Connection};
use serde::Deserialize;
use std::{env, fs, net::Ipv4Addr, path::PathBuf, sync::LazyLock};

pub(crate) const JOB: &str = "bootstrap:prepare_alpine_service";

#[derive(Deserialize)]
struct Release {
    version: String,
    branch: String,
}

static RELEASE: LazyLock<Release> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../assets/pxe/alpine-release.json"))
        .expect("bundled Alpine release metadata must be valid")
});

pub(crate) fn version() -> &'static str {
    &RELEASE.version
}

fn repository() -> String {
    if let Ok(value) = env::var("PXE_ALPINE_REPOSITORY") {
        if let Ok(uri) = value.parse::<http::Uri>() {
            if matches!(uri.scheme_str(), Some("http" | "https"))
                && uri
                    .authority()
                    .is_some_and(|authority| !authority.as_str().contains('@'))
                && uri.query().is_none()
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b":/._-".contains(&c))
            {
                return value;
            }
        }
    }
    format!(
        "https://dl-cdn.alpinelinux.org/alpine/{}/main",
        RELEASE.branch
    )
}

pub(crate) fn ready(arch: &str) -> bool {
    path(arch).is_some()
}

pub(crate) fn all_ready() -> bool {
    ready("amd64") && ready("arm64")
}

fn path(arch: &str) -> Option<String> {
    if !matches!(arch, "amd64" | "arm64") {
        return None;
    }
    let path = format!("alpine-service/{}/{arch}", RELEASE.version);
    let root = env::var_os("HTTP_ROOT")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| "/srv/http".into());
    let dir = root.join("netboot").join(&path);
    [
        ".alpine-ready",
        "linux",
        "initrd.gz",
        "modloop",
        "service.apkovl.tar.gz",
    ]
    .iter()
    .all(|name| fs::symlink_metadata(dir.join(name)).is_ok_and(|m| m.is_file() && m.len() > 0))
    .then_some(path)
}

pub(crate) fn queue(db: &Connection, retry: bool) -> rusqlite::Result<()> {
    if all_ready() {
        return Ok(());
    }
    db.execute(
        "INSERT INTO init_jobs(job_type,status,message) SELECT ?1,'pending',?2
         WHERE NOT EXISTS (SELECT 1 FROM init_jobs WHERE job_type=?1 AND status IN ('pending','running'))
           AND (?3 OR COALESCE((SELECT status FROM init_jobs WHERE job_type=?1 ORDER BY id DESC LIMIT 1),'') <> 'failed')",
        params![JOB, "Préparation du système de service Alpine", retry],
    )?;
    Ok(())
}

pub(crate) fn grub(
    server: Ipv4Addr,
    arch: &str,
    mode: &str,
    protocol: &str,
    signal: &str,
    kernel_opts: &str,
) -> Option<String> {
    let label = match mode {
        "discovery" => "Identification du matériel",
        "rescue" => "Mode de récupération",
        "disktest" => "Tests de disque",
        "wipe" => "Effacement des disques",
        _ => return None,
    };
    let media = format!("/netboot/{}", path(arch)?);
    let address = format!("http://{server}{media}");
    let repository = repository();
    let console = kernel_opts
        .split_ascii_whitespace()
        .filter(|option| option.starts_with("console="))
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "menuentry '{label} · Alpine' {{\n\
         \x20   insmod efinet\n\
         \x20   insmod tftp\n\
         \x20   insmod http\n\
         \x20   {signal}\n\
         \x20   linux ({protocol},{server}){media}/linux ip=dhcp modules=loop,squashfs,sd_mod,usb-storage,nvme,virtio_blk,ahci,vmbus,hv_storvsc \
         alpine_repo={repository} modloop={address}/modloop apkovl={address}/service.apkovl.tar.gz \
         pxe_server={server} pxe_service={mode} BOOTIF=01-${{net_default_mac}} {console}\n\
         \x20   initrd ({protocol},{server}){media}/initrd.gz\n}}\n"
    ))
}
