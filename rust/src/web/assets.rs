// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, plain, single, ErrorBox, Reply};
use futures_util::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::Frame,
    header::{
        HeaderMap, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, IF_RANGE, RANGE,
    },
    Response, StatusCode,
};
use percent_encoding::percent_decode_str;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};
use tokio_util::io::ReaderStream;

pub(super) struct Assets {
    root: PathBuf,
}

impl Assets {
    pub(super) fn new(root: PathBuf) -> Result<Self, ErrorBox> {
        if !root.is_absolute() || !root.is_dir() {
            return Err("An absolute HTTP_ROOT directory is required".into());
        }
        Ok(Self {
            root: root.canonicalize()?,
        })
    }

    pub(super) fn winpe_root(&self) -> PathBuf {
        self.root.join("winpe/amd64")
    }

    pub(super) fn http_root(&self) -> &Path {
        &self.root
    }

    pub(super) async fn serve_rhel(
        &self,
        route: &str,
        headers: &HeaderMap,
        head: bool,
    ) -> Option<Reply> {
        let (digest, path) = route
            .strip_prefix(crate::media::RHEL_PREFIX)?
            .split_once('/')?;
        if !crate::media::digest(digest) {
            return None;
        }
        let path = percent_decode_str(path).decode_utf8().ok()?;
        let path = path.as_ref();
        let allowed = matches!(
            path,
            ".treeinfo"
                | ".discinfo"
                | "media.repo"
                | "RPM-GPG-KEY-redhat-release"
                | "RPM-GPG-KEY-redhat-beta"
                | "images/install.img"
                | "images/efiboot.img"
                | "images/pxeboot/vmlinuz"
                | "images/pxeboot/initrd.img"
        ) || (matches!(path.split('/').next(), Some("BaseOS" | "AppStream"))
            && path.contains('/')
            && path.split('/').all(|part| {
                !part.is_empty()
                    && !part.starts_with('.')
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+~^-".contains(&byte))
            }));
        if !allowed {
            return None;
        }
        let base = self.root.join("media/rhel9").join(digest);
        if !fs::symlink_metadata(base.join(".pxe-media.json"))
            .await
            .ok()?
            .is_file()
        {
            return None;
        }
        self.serve_file(
            &base,
            Path::new(path),
            "application/octet-stream",
            headers,
            head,
        )
        .await
    }

    pub(super) async fn serve(
        &self,
        path: &str,
        headers: &HeaderMap,
        head: bool,
        winpe: Option<&super::winpe::Editions>,
    ) -> Option<Reply> {
        let segments = path
            .strip_prefix('/')?
            .split('/')
            .map(|part| {
                let value = percent_decode_str(part).decode_utf8().ok()?;
                if value.is_empty()
                    || value.starts_with('.')
                    || value.contains(['/', '\\'])
                    || value.bytes().any(|b| !b.is_ascii())
                    || value.bytes().any(|b| b.is_ascii_control())
                {
                    return None;
                }
                Some(value)
            })
            .collect::<Option<Vec<_>>>()?;
        let names: Vec<&str> = segments.iter().map(|value| value.as_ref()).collect();

        let (base, path, mime) = match names.as_slice() {
            ["pxe", "windows", name]
                if matches!(winpe, Some(super::winpe::Editions::Legacy))
                    && super::winpe::FILES.contains(name) =>
            {
                (
                    self.winpe_root(),
                    PathBuf::from(name),
                    "application/octet-stream",
                )
            }
            ["pxe", "windows", id, name]
                if winpe.is_some_and(|editions| editions.allows_asset(id, name)) =>
            {
                (
                    self.winpe_root().join(id),
                    PathBuf::from(name),
                    "application/octet-stream",
                )
            }
            ["netboot", dirs @ .., name] if !dirs.is_empty() => {
                let mime = match *name {
                    "linux" | "vmlinuz" | "initrd" | "initrd.gz" | "initrd.lz" | "initrd.img"
                    | "firmware.cpio.gz" => "application/octet-stream",
                    "source.iso" => "application/x-iso9660-image",
                    _ => return None,
                };
                let path = dirs.iter().chain([name]).collect::<PathBuf>();
                (self.root.join("netboot"), path, mime)
            }
            ["static-bin", name @ ("smartctl" | "dmidecode" | "badblocks" | "chvt")] => {
                let path = PathBuf::from(name);
                // Native installations publish the system package's trusted static-bin
                // directory as a symlink. It is the only HTTP tree root with that layout.
                (
                    self.root.join("static-bin"),
                    path,
                    "application/octet-stream",
                )
            }
            [name @ ("discovery-preseed.cfg"
            | "disktest-preseed.cfg"
            | "wipe-preseed.cfg"
            | "boot.ipxe")] => (
                self.root.clone(),
                PathBuf::from(name),
                "text/plain; charset=utf-8",
            ),
            [name @ ("discover.sh" | "disktest.sh")] => {
                (self.root.clone(), PathBuf::from(name), "text/x-shellscript")
            }
            ["MOK.der"] => (
                self.root.clone(),
                PathBuf::from("MOK.der"),
                "application/octet-stream",
            ),
            _ => return None,
        };
        self.serve_file(&base, &path, mime, headers, head).await
    }

    async fn serve_file(
        &self,
        base: &Path,
        path: &Path,
        mime: &str,
        headers: &HeaderMap,
        head: bool,
    ) -> Option<Reply> {
        let result = open(&self.root, base, path).await;
        let Some((mut file, size)) = result else {
            return Some(plain(StatusCode::NOT_FOUND, "Not found\n"));
        };
        let requested = single(headers, RANGE.as_str()).filter(|_| !headers.contains_key(IF_RANGE));
        let bounds = requested.map(|range| byte_range(range, size));
        let (status, start, length, content_range) = match bounds {
            Some(Some((start, end))) => (
                StatusCode::PARTIAL_CONTENT,
                start,
                end - start + 1,
                Some(format!("bytes {start}-{end}/{size}")),
            ),
            Some(None) => {
                return Some(
                    Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(CONTENT_RANGE, format!("bytes */{size}"))
                        .body(bytes(""))
                        .expect("valid range response"),
                );
            }
            None => (StatusCode::OK, 0, size, None),
        };
        if start != 0 && file.seek(SeekFrom::Start(start)).await.is_err() {
            return Some(plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read asset\n",
            ));
        }
        let mut reply = Response::builder()
            .status(status)
            .header(CONTENT_TYPE, mime)
            .header(CONTENT_LENGTH, length)
            .header(ACCEPT_RANGES, "bytes")
            .header("X-Content-Type-Options", "nosniff");
        if let Some(range) = content_range {
            reply = reply.header(CONTENT_RANGE, range);
        }
        let body = if head {
            bytes("")
        } else {
            StreamBody::new(
                ReaderStream::with_capacity(file.take(length), 64 * 1024)
                    .map(|data| data.map(Frame::data)),
            )
            .boxed_unsync()
        };
        Some(reply.body(body).expect("valid asset response"))
    }
}

async fn open(root: &Path, base: &Path, path: &Path) -> Option<(File, u64)> {
    let canonical_base = fs::canonicalize(base).await.ok()?;
    let packaged_helpers = base == root.join("static-bin")
        && canonical_base == Path::new("/usr/lib/pxe-tools/static-bin");
    if !(canonical_base.starts_with(root) || packaged_helpers) {
        return None;
    }
    let file = fs::canonicalize(canonical_base.join(path)).await.ok()?;
    if !file.starts_with(canonical_base) || !fs::metadata(&file).await.ok()?.is_file() {
        return None;
    }
    let file = File::open(file).await.ok()?;
    let metadata = file.metadata().await.ok()?;
    metadata.is_file().then_some((file, metadata.len()))
}

fn byte_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let (first, last) = value.strip_prefix("bytes=")?.split_once('-')?;
    if size == 0 {
        return None;
    }
    if first.is_empty() {
        let suffix = last.parse::<u64>().ok()?;
        return (suffix != 0).then(|| (size.saturating_sub(suffix), size - 1));
    }
    let start = first.parse::<u64>().ok()?;
    let end = if last.is_empty() {
        size - 1
    } else {
        last.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end && start < size).then_some((start, end))
}
