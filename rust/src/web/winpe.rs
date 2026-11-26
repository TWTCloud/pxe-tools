// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    bytes, plain,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{configured_database, connect, setting};
use hyper::{Response, StatusCode};
use rusqlite::{params, Connection, OpenFlags};
use serde::Deserialize;
use std::{
    fmt::Write,
    fs::{self, OpenOptions},
    io::{self, Read},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(super) const PREFIX: &str = "/pxe/windows/";
pub(super) const BOOT: &str = "/pxe/windows/boot.ipxe";
pub(super) const SHARED_PREFIX: &str = "/pxe/windows/media/";
pub(super) const SETTINGS: &str = "/settings/windows";
pub(super) const FILES: [&str; 4] = ["wimboot", "BCD", "boot.sdi", "boot.wim"];
const SELECTION: &str = "winpe_edition";
const SHARED_SELECTION: &str = "winpe_shared_media";
const MANIFEST_LIMIT: u64 = 32768;

#[derive(Deserialize)]
pub(super) struct SharedMedia {
    pub(super) iso_sha256: String,
    language: String,
    arch: String,
    editions: Vec<InstallEdition>,
    install_image: String,
    install_sha256: String,
    install_size: u64,
    boot_sha256: String,
}

#[derive(Deserialize)]
struct InstallEdition {
    edition: String,
    index: u8,
}

impl SharedMedia {
    pub(super) fn read(root: &Path, id: &str) -> Option<Self> {
        if !crate::media::digest(id) {
            return None;
        }
        let base = root.join("media");
        let library = base.join("windows");
        let directory = library.join(id);
        if [&base, &library, &directory]
            .into_iter()
            .any(|path| !fs::symlink_metadata(path).is_ok_and(|info| info.is_dir()))
        {
            return None;
        }
        let manifest = directory.join("media.json");
        let media: Self = read_manifest(&manifest).ok()?;
        if media.iso_sha256 != id
            || media.arch != "amd64"
            || !crate::media::WINDOWS_ISOS
                .iter()
                .any(|(language, _, _)| *language == media.language)
            || !matches!(media.install_image.as_str(), "install.wim" | "install.esd")
            || !crate::media::digest(&media.install_sha256)
            || !crate::media::digest(&media.boot_sha256)
            || media.install_size == 0
            || media.editions.is_empty()
            || media.editions.len() > 2
            || media
                .editions
                .iter()
                .any(|edition| !(1..=128).contains(&edition.index) || edition.label().is_none())
            || matches!(media.editions.as_slice(), [a, b] if a.index == b.index || a.edition == b.edition)
            || !fs::symlink_metadata(directory.join(&media.install_image))
                .is_ok_and(|info| info.is_file() && info.len() == media.install_size)
            || ["wimboot", "boot.wim"].iter().any(|file| {
                !fs::symlink_metadata(directory.join(file))
                    .is_ok_and(|info| info.is_file() && info.len() > 0)
            })
        {
            return None;
        }
        Some(media)
    }

    fn collection(root: &Path) -> Vec<Self> {
        let Ok(entries) = fs::read_dir(root.join("media/windows")) else {
            return Vec::new();
        };
        let mut media: Vec<_> = entries
            .flatten()
            .filter_map(|entry| Self::read(root, entry.file_name().to_str()?))
            .take(64)
            .collect();
        media.sort_by(|left, right| {
            left.language
                .cmp(&right.language)
                .then(left.iso_sha256.cmp(&right.iso_sha256))
        });
        media
    }

    pub(super) fn allows_asset(&self, file: &str) -> bool {
        matches!(file, "wimboot" | "boot.wim") || file == self.install_image
    }

    pub(super) fn selected(root: &Path, config: &Path) -> Option<Self> {
        let database = configured_database(config)?;
        let db = connect(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        Self::read(root, &setting(&db, SHARED_SELECTION).ok()?)
    }

    fn description(&self) -> String {
        let language = crate::media::WINDOWS_ISOS
            .iter()
            .find(|(language, _, _)| *language == self.language)
            .map_or(self.language.as_str(), |(_, label, _)| *label);
        let editions = self
            .editions
            .iter()
            .filter_map(InstallEdition::label)
            .collect::<Vec<_>>()
            .join(", ");
        format!("Windows 11 x64 · {language} · {editions}")
    }
}

impl InstallEdition {
    fn label(&self) -> Option<&'static str> {
        match self.edition.as_str() {
            "Core" => Some("Famille"),
            "Professional" => Some("Pro"),
            _ => None,
        }
    }
}

pub(super) struct Edition {
    id: String,
    label: String,
    image_index: u8,
    installation_image: Option<String>,
}

#[derive(Deserialize)]
struct PreparedMedia {
    edition: String,
    edition_label: String,
    image_index: u8,
    install_image: Option<String>,
    install_sha256: Option<String>,
}

pub(super) enum Editions {
    Legacy,
    Imported(Vec<Edition>),
    Invalid,
}

impl Editions {
    pub(super) fn load(root: &Path) -> Result<Self, ErrorBox> {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Legacy),
            Err(error) => return Err(error.into()),
        };
        let mut editions = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str().filter(|name| valid_id(name)) else {
                continue;
            };
            if !entry.file_type()?.is_dir() {
                continue;
            }
            if editions.len() == 32 {
                return Err("Le serveur accepte au plus 32 éditions Windows".into());
            }
            let directory = entry.path();
            let media = prepared_media(&directory)?;
            if media.edition.is_empty()
                || media.edition.len() > 40
                || !media
                    .edition
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric())
                || media.edition_label.trim().is_empty()
                || media.edition_label.len() > 120
                || media.edition_label.chars().any(char::is_control)
                || !(1..=128).contains(&media.image_index)
            {
                return Err("Le manifeste d’une édition Windows est invalide".into());
            }
            for asset in FILES {
                let file = fs::symlink_metadata(directory.join(asset))?;
                if !file.is_file() || file.len() == 0 {
                    return Err(
                        "Une édition Windows nécessite quatre fichiers WinPE ordinaires".into(),
                    );
                }
            }
            match (&media.install_image, &media.install_sha256) {
                (Some(image), Some(sha256))
                    if matches!(image.as_str(), "install.wim" | "install.esd")
                        && sha256.len() == 64
                        && sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                {
                    let image = fs::symlink_metadata(directory.join(image))?;
                    if !image.is_file() || image.len() == 0 {
                        return Err(
                            "L’image d’installation Windows est vide ou indisponible".into()
                        );
                    }
                }
                (None, None) => {}
                _ => {
                    return Err(
                        "Les métadonnées de l’image d’installation Windows sont invalides".into(),
                    )
                }
            }
            editions.push(Edition {
                id: id.to_owned(),
                label: media.edition_label,
                image_index: media.image_index,
                installation_image: media.install_image,
            });
        }
        if editions.is_empty() {
            return Ok(Self::Legacy);
        }
        editions.sort_by(|left, right| left.label.cmp(&right.label));
        Ok(Self::Imported(editions))
    }

    pub(super) fn contains(&self, id: &str) -> bool {
        matches!(self, Self::Imported(editions) if editions.iter().any(|edition| edition.id == id))
    }

    pub(super) fn allows_asset(&self, id: &str, asset: &str) -> bool {
        matches!(self, Self::Imported(editions) if editions.iter().any(|edition| {
            edition.id == id && (FILES.contains(&asset) || edition.installation_image.as_deref() == Some(asset))
        }))
    }

    pub(super) fn selected(&self, config: &Path) -> Option<String> {
        let database = configured_database(config)?;
        let db = connect(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
        let selected = setting(&db, SELECTION).ok()?;
        self.contains(&selected).then_some(selected)
    }

    pub(super) fn settings(
        &self,
        db: &Connection,
        path: &Path,
        root: &Path,
        form: Option<&[u8]>,
        preview_enabled: bool,
    ) -> Result<Reply, ErrorBox> {
        if let Some(form) = form {
            let mut fields = form_urlencoded::parse(form);
            let (key, value) = match (fields.next(), fields.next()) {
                (Some((key, value)), None) if key == "edition" && self.contains(&value) => {
                    (SELECTION, value)
                }
                (Some((key, value)), None)
                    if key == "media"
                        && preview_enabled
                        && SharedMedia::read(root, &value).is_some() =>
                {
                    (SHARED_SELECTION, value)
                }
                _ => {
                    return Ok(plain(
                        StatusCode::BAD_REQUEST,
                        "Média ou édition Windows invalide\\n",
                    ))
                }
            };
            let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            let tx = db.transaction()?;
            tx.execute(
                "INSERT INTO settings(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",
                params![key, value.as_ref()],
            )?;
            if key == SELECTION {
                tx.execute("DELETE FROM settings WHERE key=?1", [SHARED_SELECTION])?;
            }
            tx.commit()?;
            return Ok(redirect(StatusCode::SEE_OTHER, SETTINGS));
        }
        let shared = SharedMedia::collection(root);
        let mut html = format!(
            r#"<div class="panel-stack"><section class="panel">
<h2>Médias officiels en cache</h2><p><a href="{}">Préparer Windows 11 x64</a></p>"#,
            crate::media::WINDOWS_ROUTE
        );
        if shared.is_empty() {
            html.push_str("<p>Aucun média officiel préparé.</p>");
        } else if preview_enabled {
            let selected = setting(db, SHARED_SELECTION)?;
            write!(
                html,
                r#"<form class="form-stack" method="post" action="{SETTINGS}">
<div class="field"><label for="winpe-media">Média WinPE pour le client de test</label>
<select id="winpe-media" name="media" required>"#
            )?;
            if !shared.iter().any(|media| media.iso_sha256 == selected) {
                html.push_str(r#"<option value="" selected disabled>Choisir un média</option>"#);
            }
            for media in &shared {
                let option = if media.iso_sha256 == selected {
                    " selected"
                } else {
                    ""
                };
                write!(html, r#"<option value="{}"{option}>"#, media.iso_sha256)?;
                escape(&mut html, &media.description());
                html.push_str("</option>");
            }
            html.push_str(r#"</select></div><p>Ce mode prépare le démarrage réseau de WinPE sur le client de test configuré.</p>
<div class="form-actions"><button>Choisir le média de test</button></div></form>"#);
        } else {
            html.push_str("<ul>");
            for media in &shared {
                html.push_str("<li>");
                escape(&mut html, &media.description());
                html.push_str("</li>");
            }
            html.push_str("</ul>");
        }
        html.push_str(r#"</section><section class="panel"><h2>Archives WinPE importées</h2>"#);
        match self {
            Self::Imported(editions) => {
                let selected = setting(db, SELECTION)?;
                write!(
                    html,
                    r#"<form class="form-stack" method="post" action="{SETTINGS}">
<div class="field"><label for="winpe-edition">Édition pour le client PXE Windows</label>
<select id="winpe-edition" name="edition" required>"#
                )?;
                if !self.contains(&selected) {
                    html.push_str(
                        r#"<option value="" selected disabled>Choisir une édition</option>"#,
                    );
                }
                for edition in editions {
                    let checked = if edition.id == selected {
                        " selected"
                    } else {
                        ""
                    };
                    write!(html, r#"<option value="{}"{checked}>"#, edition.id)?;
                    escape(&mut html, &edition.label);
                    write!(html, " (index {})</option>", edition.image_index)?;
                }
                html.push_str(r#"</select></div><div class="form-actions"><button>Enregistrer</button></div></form>"#);
            }
            Self::Invalid => {
                html.push_str("<p>Le manifeste des éditions Windows est invalide.</p>")
            }
            Self::Legacy => html.push_str("<p>Aucune archive WinPE importée.</p>"),
        }
        html.push_str("</section></div>");
        Ok(page(
            ConsoleSection::Settings,
            "Installation Windows",
            &html,
        ))
    }
}

pub(super) fn logs_request(path: &str) -> bool {
    if matches!(path, "/boot.ipxe" | BOOT) {
        return true;
    }
    match path.strip_prefix(PREFIX).map(|path| path.split_once('/')) {
        Some(Some((id, asset))) => {
            valid_id(id)
                && (FILES.contains(&asset) || matches!(asset, "install.wim" | "install.esd"))
        }
        Some(None) => FILES.contains(&path.trim_start_matches(PREFIX)),
        None => false,
    }
}

fn prepared_media(directory: &Path) -> Result<PreparedMedia, ErrorBox> {
    read_manifest(&directory.join("case.json"))
}

fn read_manifest<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, ErrorBox> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("Le manifeste Windows doit être un fichier ordinaire".into());
    }
    let mut data = Vec::new();
    file.take(MANIFEST_LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MANIFEST_LIMIT {
        return Err("Le manifeste Windows est trop volumineux".into());
    }
    Ok(serde_json::from_slice(&data)?)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(super) fn configured_client() -> Result<Option<Ipv4Addr>, ErrorBox> {
    let Some(value) = std::env::var_os("PXE_WINPE_CLIENT_IP").filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let client: Ipv4Addr = value
        .to_str()
        .ok_or("Invalid WinPE client IPv4 address")?
        .parse()?;
    if client.is_unspecified()
        || client.is_loopback()
        || client.is_multicast()
        || client.is_broadcast()
    {
        return Err("Invalid WinPE client IPv4 address".into());
    }
    Ok(Some(client))
}

pub(super) fn allowed(client: Option<Ipv4Addr>, peer: IpAddr) -> bool {
    matches!(peer, IpAddr::V4(peer) if client == Some(peer))
}

pub(super) fn menu(server: Ipv4Addr, port: u16) -> Reply {
    let origin = origin(server, port);
    response(format!(
        r#"#!ipxe
iseq ${{platform}} efi || goto debian
iseq ${{buildarch}} x86_64 || goto debian
chain {origin}{BOOT} || goto debian
:debian
chain {origin}/boot.ipxe?menu=debian || exit
"#
    ))
}

pub(super) fn script(server: Ipv4Addr, port: u16, edition: Option<&str>) -> Reply {
    let origin = origin(server, port);
    let base = match edition {
        Some(id) => format!("{origin}{PREFIX}{id}/"),
        None => format!("{origin}{PREFIX}"),
    };
    response(format!(
        r#"#!ipxe
iseq ${{platform}} efi || goto refused
iseq ${{buildarch}} x86_64 || goto refused
set base {base}
kernel ${{base}}wimboot || goto refused
initrd --name BCD ${{base}}BCD || goto refused
initrd --name boot.sdi ${{base}}boot.sdi || goto refused
initrd --name boot.wim ${{base}}boot.wim || goto refused
boot || goto refused
:refused
echo WinPE requiert un amorcage UEFI x86-64 et les fichiers du banc.
exit
"#
    ))
}

pub(super) fn shared_script(server: Ipv4Addr, port: u16, media: &SharedMedia) -> Reply {
    let origin = origin(server, port);
    let id = &media.iso_sha256;
    response(format!(
        r#"#!ipxe
iseq ${{platform}} efi || goto refused
iseq ${{buildarch}} x86_64 || goto refused
set base {origin}{SHARED_PREFIX}{id}/
kernel ${{base}}wimboot || goto refused
initrd --name boot.wim ${{base}}boot.wim || goto refused
boot || goto refused
:refused
echo Ce media WinPE requiert un demarrage UEFI x86-64.
exit
"#
    ))
}

fn origin(server: Ipv4Addr, port: u16) -> String {
    if port == 80 {
        format!("http://{server}")
    } else {
        format!("http://{server}:{port}")
    }
}

fn response(body: String) -> Reply {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(bytes(body))
        .unwrap_or_else(|_| {
            plain(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to render WinPE boot\n",
            )
        })
}
