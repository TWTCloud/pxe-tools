// SPDX-License-Identifier: LGPL-3.0-only

use crate::{configured_database, connect};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    env,
    error::Error,
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};

type ErrorBox = Box<dyn Error + Send + Sync>;

pub(crate) const DEBIAN_MIRROR: &str = "https://deb.debian.org/debian";
const DEBIAN_ARCHIVE: &str = "https://cdimage.debian.org/cdimage/archive/";
const UBUNTU_MIRROR: &str = "https://releases.ubuntu.com/";
const UBUNTU_ARM: &str = "https://cdimage.ubuntu.com/releases/";
const UBUNTU_ARCHIVE: &str = "https://old-releases.ubuntu.com/releases/";
const ARCHES: &[(&str, &str)] = &[("amd64", "x86_64"), ("arm64", "aarch64")];

pub(crate) struct DebianRelease {
    pub major: u32,
    pub codename: &'static str,
    pub channel: &'static str,
    pub fallback: Option<&'static str>,
    archives: &'static [&'static str],
}

pub(crate) const DEBIAN_RELEASES: &[DebianRelease] = &[
    DebianRelease {
        major: 12,
        codename: "bookworm",
        channel: "oldstable",
        fallback: Some("12.14.0"),
        archives: &[
            "12.13.0", "12.12.0", "12.11.0", "12.10.0", "12.9.0", "12.8.0", "12.7.0", "12.6.0",
            "12.5.0", "12.4.0", "12.2.0", "12.1.0", "12.0.0",
        ],
    },
    DebianRelease {
        major: 13,
        codename: "trixie",
        channel: "stable",
        fallback: Some("13.5.0"),
        archives: &["13.4.0", "13.3.0", "13.2.0", "13.1.0", "13.0.0"],
    },
    DebianRelease {
        major: 14,
        codename: "forky",
        channel: "testing",
        fallback: None,
        archives: &[],
    },
];

struct UbuntuRelease {
    major: u32,
    base: &'static str,
    codename: &'static str,
    channel: &'static str,
    fallback: &'static str,
    archives: &'static [&'static str],
}

const UBUNTU_RELEASES: &[UbuntuRelease] = &[
    UbuntuRelease {
        major: 22,
        base: "22.04",
        codename: "jammy",
        channel: "oldstable",
        fallback: "22.04.5",
        archives: &["22.04.4", "22.04.3", "22.04.2", "22.04.1"],
    },
    UbuntuRelease {
        major: 24,
        base: "24.04",
        codename: "noble",
        channel: "stable",
        fallback: "24.04.4",
        archives: &["24.04.2", "24.04.1"],
    },
];

struct Entry {
    major: u32,
    codename: Option<&'static str>,
    channel: &'static str,
    version: String,
    arch: &'static str,
    urls: Sources,
}

#[derive(Default)]
struct Sources {
    kernel: Option<String>,
    initrd: Option<String>,
    firmware: Option<String>,
    iso: Option<String>,
}

pub(crate) fn fetch_text(url: &str, timeout: &str) -> Option<String> {
    let output = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            timeout,
            "--max-filesize",
            "2097152",
            url,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

pub(crate) fn release_version(release: &str, major: u32) -> Option<String> {
    for line in release.lines() {
        let Some(version) = line.strip_prefix("Version:").map(str::trim) else {
            continue;
        };
        let Some((first, _, minor)) = version_parts(version) else {
            continue;
        };
        return (first == major).then(|| {
            if minor.is_none() {
                format!("{version}.0")
            } else {
                version.to_owned()
            }
        });
    }
    None
}

pub(crate) fn current_debian_release(
    release: &DebianRelease,
    fetch: impl FnOnce(&str) -> Option<String>,
) -> Option<String> {
    fetch(&format!(
        "{DEBIAN_MIRROR}/dists/{}/Release",
        release.codename
    ))
    .and_then(|contents| release_version(&contents, release.major))
    .or_else(|| release.fallback.map(str::to_owned))
}

pub(crate) fn debian_installer(codename: &str, arch: &str) -> String {
    format!("{DEBIAN_MIRROR}/dists/{codename}/main/installer-{arch}/current/images/netboot/debian-installer/{arch}")
}

pub(crate) fn debian_firmware(codename: &str) -> String {
    format!("https://cdimage.debian.org/cdimage/firmware/{codename}/current/firmware.cpio.gz")
}

fn version_parts(version: &str) -> Option<(u32, u32, Option<u32>)> {
    fn component(raw: &str) -> Option<u32> {
        raw.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| raw.parse().ok())
            .flatten()
    }
    let mut fields = version.split('.');
    let first = component(fields.next()?)?;
    let second = component(fields.next()?)?;
    let third = match fields.next() {
        Some(raw) => Some(component(raw)?),
        None => None,
    };
    fields.next().is_none().then_some((first, second, third))
}

fn strings_or_defaults(body: impl Iterator<Item = String>, default: &[&str]) -> Vec<String> {
    let versions: BTreeSet<_> = body.collect();
    let mut versions: Vec<_> = if versions.is_empty() {
        default
            .iter()
            .map(|version| (*version).to_owned())
            .collect()
    } else {
        versions.into_iter().collect()
    };
    versions.sort_unstable_by_key(|version| std::cmp::Reverse(version_parts(version)));
    versions
}

fn debian(fetch: &impl Fn(&str) -> Option<String>) -> Vec<Entry> {
    let listing = fetch(DEBIAN_ARCHIVE).unwrap_or_default();
    let links: Vec<_> = listing
        .split("href=\"")
        .skip(1)
        .filter_map(|item| item.split_once("/\"").map(|(version, _)| version))
        .collect();
    let mut entries = Vec::new();
    for release in DEBIAN_RELEASES {
        let current = release
            .fallback
            .and_then(|_| current_debian_release(release, fetch));
        let archives = strings_or_defaults(
            links.iter().filter(|version| matches!(version_parts(version), Some((major,_,Some(_))) if major == release.major))
                .map(|version| (*version).to_owned()),
            release.archives,
        );
        for (version, direct) in current.iter().map(|version| (version, true)).chain(
            archives
                .iter()
                .filter(|version| Some(*version) != current.as_ref())
                .map(|version| (version, false)),
        ) {
            for &(arch, _) in ARCHES {
                let mut urls = Sources {
                    firmware: Some(debian_firmware(release.codename)),
                    ..Sources::default()
                };
                if direct {
                    let installer = debian_installer(release.codename, arch);
                    urls.kernel = Some(format!("{installer}/linux"));
                    urls.initrd = Some(format!("{installer}/initrd.gz"));
                } else {
                    urls.iso = Some(format!("{DEBIAN_ARCHIVE}{version}/{arch}/iso-cd/debian-{version}-{arch}-netinst.iso"));
                }
                entries.push(Entry {
                    major: release.major,
                    codename: Some(release.codename),
                    channel: release.channel,
                    version: version.clone(),
                    arch,
                    urls,
                });
            }
        }
    }
    entries
}

fn ubuntu(fetch: &impl Fn(&str) -> Option<String>) -> Vec<Entry> {
    let mut entries = Vec::new();
    for release in UBUNTU_RELEASES {
        let current = ubuntu_versions(fetch, UBUNTU_MIRROR, release.base, &[release.fallback]);
        let archives = ubuntu_versions(fetch, UBUNTU_ARCHIVE, release.base, release.archives);
        for (version, current) in current.iter().map(|version| (version, true)).chain(
            archives
                .iter()
                .filter(|version| !current.contains(version))
                .map(|version| (version, false)),
        ) {
            for &(arch, _) in ARCHES {
                let base = release.base;
                let iso = format!("ubuntu-{version}-live-server-{arch}.iso");
                let url = match (current, arch) {
                    (true, "amd64") => format!("{UBUNTU_MIRROR}{base}/{iso}"),
                    (true, _) => format!("{UBUNTU_ARM}{base}/release/{iso}"),
                    (false, _) => format!("{UBUNTU_ARCHIVE}{base}/{iso}"),
                };
                entries.push(Entry {
                    major: release.major,
                    codename: Some(release.codename),
                    channel: release.channel,
                    version: version.clone(),
                    arch,
                    urls: Sources {
                        iso: Some(url),
                        ..Sources::default()
                    },
                });
            }
        }
    }
    entries
}

fn ubuntu_versions(
    fetch: &impl Fn(&str) -> Option<String>,
    root: &str,
    base: &str,
    fallback: &[&str],
) -> Vec<String> {
    let listing = fetch(&format!("{root}{base}/")).unwrap_or_default();
    strings_or_defaults(
        listing.split("ubuntu-").skip(1).filter_map(|item| {
            let (version, suffix) = item.split_once('-')?;
            if suffix.starts_with("live-server-amd64.iso")
                && version_parts(version).is_some()
                && (version == base
                    || version
                        .strip_prefix(base)
                        .is_some_and(|ending| ending.starts_with('.')))
            {
                Some(version.to_owned())
            } else {
                None
            }
        }),
        fallback,
    )
}

fn rpm(distro: &str) -> Vec<Entry> {
    let versions: &[(u32, &str)] = match distro {
        "fedora" => &[(43, "oldstable"), (44, "stable")],
        "centos" => &[(9, "oldstable"), (10, "stable")],
        _ => &[(8, "oldstable"), (9, "oldstable"), (10, "stable")],
    };
    versions.iter().flat_map(|&(major, channel)| {
        ARCHES.iter().map(move |&(arch, upstream)| {
            let base = match distro {
                "fedora" => format!("https://dl.fedoraproject.org/pub/fedora/linux/releases/{major}/Server/{upstream}/os"),
                "centos" => format!("https://mirror.stream.centos.org/{major}/BaseOS/{upstream}/os"),
                "almalinux" => format!("https://repo.almalinux.org/almalinux/{major}/BaseOS/{upstream}/os"),
                _ => format!("https://download.rockylinux.org/pub/rocky/{major}/BaseOS/{upstream}/os"),
            };
            let dir = format!("{base}/images/pxeboot");
            Entry {
                major, codename:None, channel, version:major.to_string(), arch,
                urls:Sources {
                    kernel:Some(format!("{dir}/vmlinuz")), initrd:Some(format!("{dir}/initrd.img")),
                    ..Sources::default()
                },
            }
        })
    }).collect()
}

fn publish(db: &Connection, job: Option<i64>, percent: u8, message: &str) {
    if let Some(job) = job {
        let _ = db.execute(
            "UPDATE init_jobs SET message=?1,progress_percent=?2,updated_at=CURRENT_TIMESTAMP
             WHERE id=?3 AND status='running' AND job_type IN
               ('bootstrap:refresh_catalog_v2','bootstrap:auto_refresh_catalog_v2')",
            params![message, percent, job],
        );
    }
}

pub(crate) fn refresh(config: &Path) -> Result<(), ErrorBox> {
    let path = configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let job = env::var("WORKER_JOB_ID")
        .ok()
        .and_then(|id| id.parse().ok())
        .filter(|id| *id > 0);
    let total = refresh_entries(&mut db, job, |url| fetch_text(url, "5"))?;
    let http = env::var_os("HTTP_ROOT")
        .filter(|dir| !dir.is_empty())
        .unwrap_or_else(|| "/srv/http".into());
    requeue_outdated_images(&db, Path::new(&http), |url| fetch_text(url, "10"))?;
    publish(
        &db,
        job,
        100,
        &format!("Catalogue à jour ({total} entrées découvertes)"),
    );
    Ok(())
}

fn refresh_entries(
    db: &mut Connection,
    job: Option<i64>,
    fetch: impl Fn(&str) -> Option<String>,
) -> Result<usize, ErrorBox> {
    let mut count = 0;
    for (index, (code, label)) in [
        ("debian", "Debian"),
        ("ubuntu", "Ubuntu"),
        ("fedora", "Fedora"),
        ("centos", "CentOS Stream"),
        ("almalinux", "AlmaLinux"),
        ("rocky", "Rocky Linux"),
    ]
    .into_iter()
    .enumerate()
    {
        publish(
            db,
            job,
            (1 + index * 99 / 6) as u8,
            &format!("Discovery {label}…"),
        );
        let entries = match code {
            "debian" => debian(&fetch),
            "ubuntu" => ubuntu(&fetch),
            _ => rpm(code),
        };
        if entries.is_empty() {
            continue;
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM catalog_entries WHERE distro=?1", [code])?;
        let mut statement = tx.prepare(
            "INSERT INTO catalog_entries(distro,version_full,arch,codename,major,channel,kernel_url,initrd_url,firmware_url,iso_url,extract_method)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        )?;
        for entry in &entries {
            let urls = &entry.urls;
            let method = if urls.iso.is_some() {
                "iso_extract"
            } else {
                "direct"
            };
            statement.execute(params![
                code,
                entry.version,
                entry.arch,
                entry.codename,
                entry.major,
                entry.channel,
                urls.kernel,
                urls.initrd,
                urls.firmware,
                urls.iso,
                method
            ])?;
        }
        drop(statement);
        tx.commit()?;
        count += entries.len();
        println!(
            "Rust refreshed {label} catalog with {} entries",
            entries.len()
        );
    }
    Ok(count)
}

fn requeue_outdated_images(
    db: &Connection,
    http: &Path,
    fetch: impl Fn(&str) -> Option<String>,
) -> Result<(), ErrorBox> {
    let Ok(tree) = http.join("netboot/debian").canonicalize() else {
        return Ok(());
    };
    if !tree.starts_with(http.canonicalize()?) {
        return Ok(());
    }
    let candidates = {
        let mut query = db.prepare(
            "SELECT id,version_full,arch,initrd_url FROM os_images
             WHERE distro='debian' AND status='downloaded' AND extract_method='direct'
             AND version_full IS NOT NULL AND initrd_url LIKE '%/netboot/debian-installer/%'",
        )?;
        let rows = query.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut manifests = HashMap::new();
    for (id, version, arch, initrd) in candidates {
        let Some((major, _, _)) = version_parts(&version) else {
            continue;
        };
        let Some(release) = DEBIAN_RELEASES
            .iter()
            .find(|release| release.major == major)
        else {
            continue;
        };
        if !ARCHES.iter().any(|(candidate, _)| *candidate == arch) {
            continue;
        }
        let installer = debian_installer(release.codename, &arch);
        if initrd != format!("{installer}/initrd.gz") {
            continue;
        }
        let file = tree.join(&version).join(&arch).join("initrd.gz");
        let Ok(canonical) = file.canonicalize() else {
            continue;
        };
        if !canonical.starts_with(&tree) || !canonical.is_file() {
            continue;
        }
        let Some((images, _)) = installer.split_once("/netboot/") else {
            continue;
        };
        let url = format!("{images}/SHA256SUMS");
        let manifest = manifests.entry(url.clone()).or_insert_with(|| fetch(&url));
        let relative = format!("./netboot/debian-installer/{arch}/initrd.gz");
        let Some(expected) = manifest
            .as_deref()
            .and_then(|body| checksum(body, &relative))
        else {
            continue;
        };
        let Ok(actual) = sha256(&canonical) else {
            continue;
        };
        if actual.eq_ignore_ascii_case(expected) {
            continue;
        }
        // The downloader stages and authenticates its replacement before publication.
        let changed = db.execute(
            "UPDATE os_images SET status='pending',error_msg=NULL,progress_percent=0,updated_at=CURRENT_TIMESTAMP
             WHERE id=?1 AND status='downloaded' AND distro='debian' AND extract_method='direct'
               AND version_full=?2 AND arch=?3 AND initrd_url=?4",
            params![id, version, arch, initrd],
        )?;
        if changed > 0 {
            println!(
                "Rust queued a verified replacement for outdated Debian netboot {version}/{arch}"
            );
        }
    }
    Ok(())
}

fn checksum<'a>(contents: &'a str, relative: &str) -> Option<&'a str> {
    contents.lines().find_map(|record| {
        let mut fields = record.split_ascii_whitespace();
        let hash = fields.next()?;
        let filename = fields.next()?.trim_start_matches('*');
        (filename == relative
            && fields.next().is_none()
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(hash)
    })
}

fn sha256(file: &Path) -> io::Result<String> {
    let mut opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(file)?;
    if !opened.metadata()?.is_file() {
        return Err(io::Error::other("Expected a regular Debian initramfs"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = opened.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
