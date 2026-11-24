// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, ErrorBox, Reply, Site};
use crate::{configured_database, connect, pxe::client_in_subnet, setting};
use hyper::{header, Response, StatusCode, Uri};
use rusqlite::{Connection, OpenFlags};
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

struct Entry {
    title: String,
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
    let port = site.http_port;
    let authority = if port == 80 {
        server.to_string()
    } else {
        format!("{server}:{port}")
    };
    let mut entries = ubuntu(&db, site.assets.http_root(), arch, &authority)?;
    if let Some(repo) = site.rhel_repositories.for_arch(arch) {
        let base = repo.path().trim_end_matches('/');
        let host = repo.authority().expect("validated HTTP repository");
        entries.push(Entry {
            title: "Red Hat Enterprise Linux 9".into(),
            authority: host.to_string(),
            kernel: format!("{base}/images/pxeboot/vmlinuz"),
            initrd: format!("{base}/images/pxeboot/initrd.img"),
            arguments: format!("ip=dhcp inst.repo=http://{host}{base}/"),
        });
    }
    let body = render(&entries, loader, server);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, body.len())
        .body(if head { bytes("") } else { bytes(body) })?)
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
