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
const DEBIAN_TESTING: &str = "https://cdimage.debian.org/cdimage/weekly-builds/";
const UBUNTU_MIRROR: &str = "https://releases.ubuntu.com/";
const UBUNTU_ARM: &str = "https://cdimage.ubuntu.com/releases/";
const UBUNTU_ARCHIVE: &str = "https://old-releases.ubuntu.com/releases/";
const ARCHES: &[(&str, &str)] = &[("amd64", "x86_64"), ("arm64", "aarch64")];

pub(crate) fn rpm_label(distro: &str) -> Option<&'static str> {
    match distro {
        "fedora" => Some("Fedora Server"),
        "centos" => Some("CentOS Stream"),
        "almalinux" => Some("AlmaLinux"),
        "rocky" => Some("Rocky Linux"),
        _ => None,
    }
}

fn rpm_source(distro: &str) -> Option<(&'static str, &'static [u32])> {
    Some(match distro {
        "fedora" => (
            "https://dl.fedoraproject.org/pub/fedora/linux/releases/",
            &[43, 44, 45],
        ),
        "centos" => ("https://mirror.stream.centos.org/", &[9, 10]),
        "almalinux" => ("https://repo.almalinux.org/almalinux/", &[8, 9, 10]),
        "rocky" => ("https://download.rockylinux.org/pub/rocky/", &[8, 9, 10]),
        _ => return None,
    })
}

fn rpm_major(version: &str, minimum: u32) -> Option<u32> {
    let major = version.parse::<u32>().ok()?;
    ((minimum..=999).contains(&major) && version == major.to_string()).then_some(major)
}

pub(crate) fn rpm_repository(distro: &str, version: &str, arch: &str) -> Option<String> {
    let (root, known) = rpm_source(distro)?;
    rpm_major(version, known[0])?;
    let upstream = ARCHES.iter().find(|(name, _)| *name == arch)?.1;
    Some(match distro {
        "fedora" => format!("{root}{version}/Server/{upstream}/os"),
        "centos" => format!("{root}{version}-stream/BaseOS/{upstream}/os"),
        _ => format!("{root}{version}/BaseOS/{upstream}/os"),
    })
}

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
        fallback: Some("12.15.0"),
        archives: &[
            "12.14.0", "12.13.0", "12.12.0", "12.11.0", "12.10.0", "12.9.0", "12.8.0", "12.7.0",
            "12.6.0", "12.5.0", "12.4.0", "12.2.0", "12.1.0", "12.0.0",
        ],
    },
    DebianRelease {
        major: 13,
        codename: "trixie",
        channel: "stable",
        fallback: Some("13.8.0"),
        archives: &[
            "13.7.0", "13.6.0", "13.5.0", "13.4.0", "13.3.0", "13.2.0", "13.1.0", "13.0.0",
        ],
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
        archives: &["22.04.4", "22.04.3", "22.04.2", "22.04.1", "22.04"],
    },
    UbuntuRelease {
        major: 24,
        base: "24.04",
        codename: "noble",
        channel: "oldstable",
        fallback: "24.04.5",
        archives: &["24.04.2", "24.04.1", "24.04"],
    },
    UbuntuRelease {
        major: 26,
        base: "26.04",
        codename: "resolute",
        channel: "stable",
        fallback: "26.04.1",
        archives: &[],
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

fn directory_names(contents: &str) -> impl Iterator<Item = &str> {
    contents
        .split("href=\"")
        .skip(1)
        .filter_map(|link| link.split_once('"')?.0.strip_suffix('/'))
}

fn debian(fetch: &impl Fn(&str) -> Option<String>) -> Vec<Entry> {
    let listing = fetch(DEBIAN_ARCHIVE).unwrap_or_default();
    let mut entries = Vec::new();
    for release in DEBIAN_RELEASES {
        if release.channel == "testing" {
            for &(arch, _) in ARCHES {
                let directory = format!("{DEBIAN_TESTING}{arch}/iso-cd/");
                let file = format!("debian-testing-{arch}-netinst.iso");
                if fetch(&format!("{directory}SHA256SUMS"))
                    .is_some_and(|sums| checksum(&sums, &file).is_some())
                {
                    entries.push(Entry {
                        major: release.major,
                        codename: Some(release.codename),
                        channel: release.channel,
                        version: format!("{}-testing", release.major),
                        arch,
                        urls: Sources {
                            firmware: Some(debian_firmware(release.codename)),
                            iso: Some(format!("{directory}{file}")),
                            ..Sources::default()
                        },
                    });
                }
            }
        }
        let current = release
            .fallback
            .and_then(|_| current_debian_release(release, fetch));
        let archives = strings_or_defaults(
            directory_names(&listing).filter(|version| matches!(version_parts(version), Some((major,_,Some(_))) if major == release.major))
                .map(str::to_owned),
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
        let base = release.base;
        let archive_root = format!("{UBUNTU_ARCHIVE}{base}/");
        let archive_index = fetch(&archive_root);
        for &(arch, _) in ARCHES {
            let current_root = if arch == "amd64" {
                format!("{UBUNTU_MIRROR}{base}/")
            } else {
                format!("{UBUNTU_ARM}{base}/release/")
            };
            let current_index = fetch(&format!("{current_root}SHA256SUMS"));
            let current =
                ubuntu_versions(current_index.as_deref(), base, arch, &[release.fallback]);
            let archives = ubuntu_versions(archive_index.as_deref(), base, arch, release.archives);
            for (version, root) in current
                .iter()
                .map(|version| (version, &current_root))
                .chain(
                    archives
                        .iter()
                        .filter(|version| !current.contains(version))
                        .map(|version| (version, &archive_root)),
                )
            {
                entries.push(Entry {
                    major: release.major,
                    codename: Some(release.codename),
                    channel: release.channel,
                    version: version.clone(),
                    arch,
                    urls: Sources {
                        iso: Some(format!("{root}ubuntu-{version}-live-server-{arch}.iso")),
                        ..Sources::default()
                    },
                });
            }
        }
    }
    entries
}

fn ubuntu_versions(
    listing: Option<&str>,
    base: &str,
    arch: &str,
    fallback: &[&str],
) -> Vec<String> {
    let Some(listing) = listing else {
        return fallback.iter().map(|version| (*version).into()).collect();
    };
    let file_suffix = format!("live-server-{arch}.iso");
    strings_or_defaults(
        listing.split("ubuntu-").skip(1).filter_map(|item| {
            let (version, suffix) = item.split_once('-')?;
            if suffix.strip_prefix(&file_suffix).is_some_and(|tail| {
                tail.chars().next().is_none_or(|next| {
                    next.is_ascii_whitespace() || matches!(next, '"' | '\'' | '<')
                })
            }) && version_parts(version).is_some()
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
        &[],
    )
}

fn rpm_bootable(index: &str) -> bool {
    let mut checksums = index
        .lines()
        .skip_while(|line| line.trim() != "[checksums]")
        .skip(1)
        .take_while(|line| !line.trim().starts_with('['))
        .filter_map(|line| {
            let (name, value) = line.split_once('=')?;
            let digest = value.trim().strip_prefix("sha256:")?;
            (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then_some(name.trim())
        });
    let (mut kernel, mut initrd) = (false, false);
    checksums.any(|name| {
        kernel |= name == "images/pxeboot/vmlinuz";
        initrd |= name == "images/pxeboot/initrd.img";
        kernel && initrd
    })
}

fn rpm(distro: &str, fetch: &(impl Fn(&str) -> Option<String> + Sync)) -> Vec<Entry> {
    let Some((root, known)) = rpm_source(distro) else {
        return Vec::new();
    };
    let listing = fetch(root);
    let versions: BTreeSet<_> = match listing.as_deref() {
        Some(index) => directory_names(index)
            .filter_map(|name| {
                let version = if distro == "centos" {
                    name.strip_suffix("-stream")?
                } else {
                    name
                };
                rpm_major(version, known[0])
            })
            .collect(),
        None => known.iter().copied().collect(),
    };
    let verify = listing.is_some();
    let media = std::thread::scope(|scope| {
        let probes = versions
            .iter()
            .rev()
            .take(8)
            .flat_map(|&major| {
                ARCHES.iter().filter_map(move |&(arch, _)| {
                    let repo = rpm_repository(distro, &major.to_string(), arch)?;
                    Some(scope.spawn(move || {
                        if verify
                            && !fetch(&format!("{repo}/.treeinfo"))
                                .is_some_and(|index| rpm_bootable(&index))
                        {
                            return None;
                        }
                        Some((major, arch, format!("{repo}/images/pxeboot")))
                    }))
                })
            })
            .collect::<Vec<_>>();
        probes
            .into_iter()
            .filter_map(|probe| probe.join().ok().flatten())
            .collect::<Vec<_>>()
    });
    let latest = media.first().map(|image| image.0);
    media
        .into_iter()
        .map(|(major, arch, dir)| Entry {
            major,
            codename: None,
            channel: if Some(major) == latest {
                "stable"
            } else {
                "oldstable"
            },
            version: major.to_string(),
            arch,
            urls: Sources {
                kernel: Some(format!("{dir}/vmlinuz")),
                initrd: Some(format!("{dir}/initrd.img")),
                ..Sources::default()
            },
        })
        .collect()
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
    fetch: impl Fn(&str) -> Option<String> + Sync,
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
            &format!("Lecture du catalogue {label}…"),
        );
        let entries = match code {
            "debian" => debian(&fetch),
            "ubuntu" => ubuntu(&fetch),
            _ => rpm(code, &fetch),
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
