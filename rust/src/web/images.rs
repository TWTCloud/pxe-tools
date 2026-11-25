// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    plain,
    setup::redirect,
    ui::{icon, page, status_badge, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{
    connect,
    images::{Change, Changed},
    media::{self, REDHAT_ROUTE},
    setting,
};
use hyper::{Method, StatusCode};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/settings/images";
const PAGE_SIZE: u64 = 100;

#[derive(Clone, Copy)]
pub(super) enum Route {
    List,
    Add,
    Media(Option<&'static str>),
    RedHat,
    Refresh,
    RefreshStatus,
    AutoRefresh,
    Status,
    Toggle(i64),
    Download(i64),
    Delete(i64),
}

impl Route {
    pub(super) fn for_path(path: &str, query: &str) -> Option<Self> {
        Some(match path {
            ROUTE => Self::List,
            "/settings/images/add" => Self::Add,
            "/settings/images/media" => Self::Media(
                form_urlencoded::parse(query.as_bytes())
                    .find(|(key, _)| key == "kind")
                    .and_then(|(_, value)| match value.as_ref() {
                        "rhel9" => Some("rhel9"),
                        "windows-iso" => Some("windows-iso"),
                        _ => None,
                    }),
            ),
            REDHAT_ROUTE => Self::RedHat,
            "/settings/images/refresh" => Self::Refresh,
            "/settings/images/refresh-button" => Self::RefreshStatus,
            "/settings/images/auto-refresh" => Self::AutoRefresh,
            "/api/images-status" => Self::Status,
            _ => {
                let route = path.strip_prefix("/settings/images/")?;
                let (id, operation) = route.split_once('/').unwrap_or((route, ""));
                let id = id.parse::<i64>().ok().filter(|id| *id > 0)?;
                match operation {
                    "toggle" => Self::Toggle(id),
                    "download" => Self::Download(id),
                    "" => Self::Delete(id),
                    _ => return None,
                }
            }
        })
    }

    pub(super) fn allows(self, method: &Method) -> bool {
        match *method {
            Method::GET | Method::HEAD => matches!(
                self,
                Self::List
                    | Self::Add
                    | Self::Media(_)
                    | Self::RedHat
                    | Self::RefreshStatus
                    | Self::Status
            ),
            Method::POST => !matches!(self, Self::RefreshStatus | Self::Status),
            Method::DELETE => matches!(self, Self::Delete(_)),
            _ => false,
        }
    }
}

pub(super) fn serve(
    route: Route,
    method: &Method,
    db: &Connection,
    path: &Path,
    number: u32,
    form: Option<&[u8]>,
    can_edit: bool,
) -> Reply {
    let result = match (route, form) {
        (Route::List, None) => list(db, number, can_edit),
        (Route::Media(kind), None) => media_form(db, kind),
        (Route::Media(_), Some(form)) => queue_media(path, form),
        (Route::RedHat, None) if can_edit => redhat_form(None),
        (Route::RedHat, Some(form)) if can_edit => queue_redhat(path, form),
        (Route::RedHat, _) => Ok(plain(StatusCode::FORBIDDEN, "Accès refusé\n")),
        (Route::Add, None) => catalog(db, can_edit).map(|html| {
            page(
                ConsoleSection::Images,
                "Ajouter une image",
                &format!(r#"<nav class="page-links"><a href="{ROUTE}">Images PXE</a></nav>{html}"#),
            )
        }),
        (Route::Status, None) => managed_images(db, number, can_edit)
            .map(|html| page(ConsoleSection::Images, "Images PXE", &html)),
        (Route::RefreshStatus, None) => {
            refresh_button(db).map(|html| page(ConsoleSection::Images, "Catalogue PXE", &html))
        }
        (_, Some(form)) => update(route, method, path, form),
        _ => Ok(plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed\n",
        )),
    };
    result.unwrap_or_else(|error| {
        eprintln!("Rust images: {error}");
        plain(StatusCode::SERVICE_UNAVAILABLE, "Images indisponibles\n")
    })
}

fn media_form(db: &Connection, selected_kind: Option<&str>) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<nav class="page-links" aria-label="Images PXE"><a href="/settings/images">Images PXE</a></nav>
<form class="panel panel--form form-stack" method="post" action="/settings/images/media">
<div class="field"><label for="media-kind">Type de média</label><select id="media-kind" name="kind" required>"#,
    );
    for (kind, label) in [
        ("rhel9", "DVD RHEL 9"),
        ("windows-iso", "ISO Windows"),
        ("windows-wim", "Fichier install.wim"),
        ("windows-esd", "Fichier install.esd"),
        ("winpe", "Archive WinPE préparée"),
    ] {
        let selected = if selected_kind == Some(kind) {
            " selected"
        } else {
            ""
        };
        write!(html, r#"<option value="{kind}"{selected}>{label}</option>"#)?;
    }
    html.push_str(r#"</select></div>
<div class="field"><label for="media-source">Source du média</label>
<input id="media-source" name="source" maxlength="4096" aria-describedby="media-source-help" required>
<small id="media-source-help">Nom du fichier sur le serveur ou URL HTTPS autorisée.</small></div>
<div class="field"><label for="media-sha">Empreinte SHA-256</label>
<input id="media-sha" name="sha256" pattern="[A-Fa-f0-9]{64}" required></div>
<div class="field"><label for="media-profile">Identifiant de l’édition</label>
<input id="media-profile" name="profile" pattern="[a-z0-9-]{1,40}" aria-describedby="media-profile-help">
<small id="media-profile-help">Pour une archive WinPE uniquement.</small></div>
<div class="form-actions"><button>Préparer le média</button></div>
</form>
<p>Les fichiers locaux se placent dans le dossier privé <code>media/inbox</code> du stockage HTTP PXE. Importez le fichier Windows avant l’archive WinPE de l’édition.</p>"#,
    );
    let hosts = crate::media::download_hosts();
    if !hosts.is_empty() {
        html.push_str("<p>Hôtes de téléchargement autorisés&nbsp;: ");
        escape(&mut html, &hosts.join(", "));
        html.push_str("</p>");
    }
    let mut jobs = db.prepare(
        "SELECT id,status,message FROM init_jobs WHERE job_type IN (?1,?2) ORDER BY id DESC LIMIT 10",
    )?;
    let mut rows = jobs.query([media::JOB, media::REDHAT_JOB])?;
    html.push_str("<h2>Préparations récentes</h2>");
    let mut next = rows.next()?;
    if next.is_none() {
        html.push_str(r#"<p class="muted">Aucune préparation lancée.</p>"#);
        return Ok(page(ConsoleSection::Images, "Préparer un média PXE", &html));
    }
    html.push_str("<ul>");
    while let Some(row) = next {
        let id: i64 = row.get(0)?;
        write!(html, "<li><a href=\"/jobs/{id}\">Tâche {id}</a> · ")?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str(" · ");
        escape(
            &mut html,
            &row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        );
        html.push_str("</li>");
        next = rows.next()?;
    }
    html.push_str("</ul>");
    Ok(page(ConsoleSection::Images, "Préparer un média PXE", &html))
}

fn queue_media(path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut fields = std::collections::HashMap::new();
    for (name, value) in form_urlencoded::parse(form) {
        if !matches!(name.as_ref(), "kind" | "source" | "sha256" | "profile")
            || fields.insert(name, value).is_some()
        {
            return Ok(invalid());
        }
    }
    let value = |name: &str| {
        fields
            .get(name)
            .map(|value| value.trim())
            .unwrap_or_default()
    };
    let source = value("source");
    let request = crate::media::Import {
        kind: value("kind").into(),
        source: source.into(),
        sha256: value("sha256").to_ascii_lowercase(),
        profile: value("profile").into(),
        remote: source.starts_with("https://"),
        redhat_token: None,
    };
    if !request.valid() {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Type de média, source ou empreinte invalide\n",
        ));
    }
    enqueue_media(path, request)
}

fn redhat_form(error: Option<&str>) -> Result<Reply, ErrorBox> {
    let mut html = format!(
        r#"<nav class="page-links" aria-label="Images PXE"><a href="{ROUTE}/add">Ajouter une image</a></nav>
<form class="panel panel--form form-stack" method="post" action="{REDHAT_ROUTE}">
<p>PXE Tools télécharge le DVD depuis Red Hat, vérifie son empreinte et prépare les fichiers pour le démarrage réseau.</p>
<details><summary>Où obtenir le jeton Red Hat&nbsp;?</summary>
<ol>
<li>Connectez-vous au <a href="https://access.redhat.com/downloads/content/rhel/">portail Red Hat</a> avec un compte autorisé à télécharger RHEL.</li>
<li>Ouvrez la <a href="https://access.redhat.com/management/api">page des jetons API Red Hat</a> et sélectionnez <strong>Generate Token</strong>.</li>
<li>Copiez le jeton généré dans le champ ci-dessous. Le jeton reste chiffré sur le serveur jusqu’au démarrage de la tâche.</li>
</ol>
<p>Si le portail ne permet pas de générer le jeton, demandez à votre administrateur Red Hat l’autorisation de consulter et renouveler les abonnements.</p>
</details>"#,
    );
    if let Some(error) = error {
        html.push_str(r#"<p class="wizard-error" role="alert">"#);
        escape(&mut html, error);
        html.push_str("</p>");
    }
    html.push_str(
        r#"<div class="field"><label for="rhel-dvd">DVD à télécharger</label>
<select name="image" id="rhel-dvd" required aria-describedby="rhel-dvd-help">"#,
    );
    for (version, arch, size, _) in media::RHEL_DVDS {
        let label = if arch == "amd64" {
            "Intel / AMD (64 bits)"
        } else {
            "ARM64"
        };
        write!(
            html,
            r#"<option value="{version}-{arch}">RHEL {version} · {label} · {size}</option>"#
        )?;
    }
    write!(
        html,
        r#"</select>
<small id="rhel-dvd-help">Choisissez l’architecture de l’appareil à installer. Prévoyez de l’espace pour le DVD et les fichiers extraits.</small></div>
<div class="field"><label for="rhel-token">Jeton API Red Hat</label>
<input type="password" id="rhel-token" name="token" maxlength="{}" autocomplete="off" spellcheck="false" required></div>
<div class="form-actions"><button>Télécharger et préparer le DVD</button>
<a class="button button--quiet" href="{ROUTE}/media?kind=rhel9">Importer un DVD déjà téléchargé</a></div></form>"#,
        media::REDHAT_TOKEN_LIMIT,
    )?;
    let mut reply = page(ConsoleSection::Images, "Télécharger RHEL", &html);
    if error.is_some() {
        *reply.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
    }
    Ok(reply)
}

fn queue_redhat(path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut image = None;
    let mut token = None;
    for (name, value) in form_urlencoded::parse(form) {
        match name.as_ref() {
            "image" if image.is_none() => image = Some(value),
            "token" if token.is_none() => token = Some(value),
            _ => return Ok(invalid()),
        }
    }
    let Some((version, arch)) = image.as_deref().and_then(|input| input.split_once('-')) else {
        return redhat_form(Some("Choisissez le DVD RHEL à télécharger."));
    };
    let Some((_, _, _, sha256)) = media::RHEL_DVDS
        .into_iter()
        .find(|(offered, cpu, _, _)| *offered == version && *cpu == arch)
    else {
        return redhat_form(Some("Ce DVD RHEL ne figure pas dans le catalogue."));
    };
    let request = media::Import {
        kind: "rhel9".into(),
        source: String::new(),
        sha256: sha256.into(),
        profile: String::new(),
        remote: false,
        redhat_token: token.map(|token| token.trim().to_owned()),
    };
    if !request.valid() {
        return redhat_form(Some(
            "Collez le jeton complet généré dans le portail Red Hat.",
        ));
    }
    enqueue_media(path, request)
}

fn enqueue_media(path: &Path, request: media::Import) -> Result<Reply, ErrorBox> {
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let id = media::enqueue(&mut db, request)?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/jobs/{id}")))
}

fn update(route: Route, method: &Method, path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut input = form_urlencoded::parse(form);
    let operation = match route {
        Route::Toggle(id) => {
            let enabled = match (input.next(), input.next()) {
                (None, None) => None,
                (Some((key, value)), None)
                    if key == "enabled" && matches!(value.as_ref(), "0" | "1") =>
                {
                    Some(value == "1")
                }
                _ => return Ok(invalid()),
            };
            Some((id, Change::Enable(enabled)))
        }
        Route::Download(id) if form.is_empty() => Some((id, Change::Download)),
        Route::Delete(id)
            if *method == Method::DELETE && form.is_empty() || form == b"_method=DELETE" =>
        {
            Some((id, Change::Delete))
        }
        Route::Refresh if form.is_empty() => {
            refresh_catalog(&tx)?;
            None
        }
        Route::AutoRefresh => {
            if !auto_refresh(&tx, input)? {
                return Ok(invalid());
            }
            None
        }
        Route::List | Route::Add => {
            if let Some(reply) = queue_form(&tx, input)? {
                return Ok(reply);
            }
            None
        }
        _ => return Ok(invalid()),
    };
    if let Some((id, operation)) = operation {
        match crate::images::change(&tx,id,operation)? {
            Changed::Unavailable => return Ok(plain(StatusCode::NOT_FOUND,"Image introuvable\n")),
            Changed::Blocked => return Ok(plain(StatusCode::CONFLICT,
                "Image en cours de transfert, utilisée par une opération, ou requise pour le secours PXE\n")),
            Changed::Queued(job) => {
                tx.commit()?;
                return Ok(redirect(StatusCode::SEE_OTHER,format!("/jobs/{job}")));
            }
            Changed::Updated => {}
        }
    }
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
}

fn invalid() -> Reply {
    plain(StatusCode::UNPROCESSABLE_ENTITY, "Formulaire invalide\n")
}

fn queue_form(
    db: &Connection,
    fields: form_urlencoded::Parse<'_>,
) -> Result<Option<Reply>, ErrorBox> {
    let mut image = None;
    let mut refresh = false;
    let mut rows = Vec::new();
    for (name, value) in fields {
        match name.as_ref() {
            "image" if image.is_none() => image = Some(value.parse::<i64>()),
            "action" if !refresh && value == "refresh" => refresh = true,
            "rows[]" if rows.len() < 100 => rows.push(value),
            _ => {
                return Ok(Some(plain(
                    StatusCode::BAD_REQUEST,
                    "Formulaire invalide\n",
                )))
            }
        }
    }
    if refresh {
        refresh_catalog(db)?;
    } else if !rows.is_empty() && image.is_none() {
        let mut matched = false;
        for display in rows {
            let mut fields = display.split(':');
            let (Some(distro), Some(version), Some(arch), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if let Some(id) = db.query_row(
                "SELECT id FROM catalog_entries WHERE distro=?1 AND version_full=?2 AND arch=?3",
                rusqlite::params![distro,version,arch], |row| row.get::<_,i64>(0),
            ).optional()? {
                matched |= queue_image(db,id,false)?.is_some();
            }
        }
        if !matched {
            return Ok(Some(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Images indisponibles\n",
            )));
        }
    } else {
        let available = match image {
            Some(Ok(id)) if id > 0 => queue_image(db, id, false)?.is_some(),
            _ => false,
        };
        if !available {
            return Ok(Some(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Image indisponible\n",
            )));
        }
    }
    Ok(None)
}

fn auto_refresh(db: &Connection, fields: form_urlencoded::Parse<'_>) -> rusqlite::Result<bool> {
    let mut enabled = false;
    let mut interval = None;
    for (name, value) in fields {
        match name.as_ref() {
            "catalog_auto_refresh_enabled" if !enabled && matches!(value.as_ref(), "on" | "1") => {
                enabled = true
            }
            "catalog_auto_refresh_interval_hours"
                if interval.is_none() && matches!(value.as_ref(), "24" | "168" | "720") =>
            {
                interval = Some(value);
            }
            _ => return Ok(false),
        }
    }
    super::onboarding::store(
        db,
        "catalog_auto_refresh_enabled",
        if enabled { "on" } else { "off" },
    )?;
    super::onboarding::store(
        db,
        "catalog_auto_refresh_interval_hours",
        interval.as_deref().unwrap_or("168"),
    )?;
    Ok(true)
}

pub(super) fn refresh_catalog(db: &Connection) -> rusqlite::Result<()> {
    let running = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM init_jobs
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2','bootstrap:auto_refresh_catalog_v2')
         AND status IN ('pending','running'))",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !running {
        let id = db.query_row(
            "INSERT INTO init_jobs(job_type,status,message)
             VALUES('bootstrap:refresh_catalog_v2','pending','Actualisation du catalogue demandée')
             RETURNING id",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        db.execute(
            "INSERT INTO settings(key,value) VALUES('catalog_job_ids', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [format!("[{id}]")],
        )?;
    }
    Ok(())
}

fn list(db: &Connection, number: u32, can_edit: bool) -> Result<Reply, ErrorBox> {
    let mut html = String::from(r#"<div class="panel-stack">"#);
    html.push_str(&managed_images(db, number, can_edit)?);
    html.push_str(&catalog(db, can_edit)?);
    if can_edit {
        html.push_str(&refresh_settings(db)?);
    }
    html.push_str("</div>");
    Ok(page(ConsoleSection::Images, "Images PXE", &html))
}

fn refresh_settings(db: &Connection) -> Result<String, ErrorBox> {
    let mut html = String::from(
        r#"<details class="panel catalog-settings"><summary>Actualisation automatique du catalogue</summary>"#,
    );
    let enabled = if setting(db, "catalog_auto_refresh_enabled")? == "on" {
        " checked"
    } else {
        ""
    };
    let interval = setting(db, "catalog_auto_refresh_interval_hours")?;
    let interval = if matches!(interval.as_str(), "24" | "168" | "720") {
        interval.as_str()
    } else {
        "168"
    };
    write!(
        html,
        r#"<form class="form-stack" method="post" action="{ROUTE}/auto-refresh"><label class="check-label">
<input type="checkbox" name="catalog_auto_refresh_enabled" value="on"{enabled}> Actualiser automatiquement le catalogue</label>
<div class="field"><label for="catalog-frequency">Fréquence</label><select id="catalog-frequency" name="catalog_auto_refresh_interval_hours">"#
    )?;
    for (hours, label) in [
        ("24", "Chaque jour"),
        ("168", "Chaque semaine"),
        ("720", "Tous les 30 jours"),
    ] {
        let selected = if interval == hours { " selected" } else { "" };
        write!(
            html,
            r#"<option value="{hours}"{selected}>{label}</option>"#
        )?;
    }
    html.push_str(r#"</select></div><div class="form-actions"><button>Enregistrer la fréquence</button></div></form></details>"#);
    Ok(html)
}

fn refresh_button(db: &Connection) -> Result<String, ErrorBox> {
    let mut html = String::new();
    if let Some(status) = db
        .query_row(
            "SELECT status FROM init_jobs
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2','bootstrap:auto_refresh_catalog_v2')
         ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        html.push_str(r#"<p class="record-meta">Dernière actualisation du catalogue&nbsp; "#);
        status_badge(&mut html, &status, super::activity::status_label(&status));
        html.push_str("</p>");
    }
    Ok(html)
}

fn distro_icon(code: &str) -> String {
    match code {
        "almalinux" | "centos" | "debian" | "fedora" | "proxmox" | "rocky" | "ubuntu" => format!(
            r#"<img class="distro-icon" src="/console-assets/{code}.svg" width="28" height="28" alt="">"#
        ),
        "windows" => icon("M3 3h8v8H3zm10 0h8v8h-8zM3 13h8v8H3zm10 0h8v8h-8z"),
        _ => icon("M4 4h16v16H4zM8 8h8m-8 4h8m-8 4h4"),
    }
}

fn heading(distro: &str, label: &str) -> String {
    let mut html = format!(r#"<h3 class="image-name">{}<span>"#, distro_icon(distro));
    escape(&mut html, label);
    html.push_str("</span></h3>");
    html
}

fn managed_images(db: &Connection, number: u32, can_edit: bool) -> Result<String, ErrorBox> {
    let mut html = String::from(
        r#"<section data-image-progress aria-labelledby="managed-images"><header class="section-heading"><h2 id="managed-images">Images sur ce serveur</h2><a class="button button--quiet" href="/settings/images#catalogue">Parcourir le catalogue</a></header><div class="image-list">"#,
    );
    let mut query = db.prepare(
        "SELECT distro, COALESCE(NULLIF(version_full,''),version), arch, status, progress_percent,
                enabled, id, error_msg,
                EXISTS(SELECT 1 FROM init_jobs WHERE job_type='image:delete:' || os_images.id
                       AND status IN ('pending','running'))
         FROM os_images ORDER BY distro,major DESC,version_full DESC,arch,id LIMIT ? OFFSET ?",
    )?;
    let mut rows = query.query([PAGE_SIZE + 1, u64::from(number - 1) * PAGE_SIZE])?;
    let mut found = false;
    for _ in 0..PAGE_SIZE {
        let Some(row) = rows.next()? else { break };
        found = true;
        let distro: String = row.get(0)?;
        let version: String = row.get(1)?;
        let arch: String = row.get(2)?;
        let status: String = row.get(3)?;
        let enabled: bool = row.get(5)?;
        let id: i64 = row.get(6)?;
        let deleting: bool = row.get(8)?;
        let (state, tone, status_label) = match (status.as_str(), enabled, deleting) {
            (_, _, true) => ("deleting", "running", "Suppression en cours"),
            ("pending", true, _) => ("pending", "pending", "Téléchargement en attente"),
            ("downloading", _, _) => ("downloading", "downloading", "Téléchargement en cours"),
            ("downloaded", true, _) => ("downloaded", "downloaded", "Téléchargée"),
            ("downloaded", false, _) => ("disabled", "neutral", "Téléchargée · désactivée"),
            ("pending", false, _) => ("disabled", "neutral", "Téléchargement désactivé"),
            ("failed" | "error", _, _) => ("failed", "failed", "Échec du téléchargement"),
            _ => ("unavailable", "neutral", "Indisponible"),
        };
        let title = match distro.as_str() {
            "debian" => "Debian",
            "ubuntu" => "Ubuntu Server",
            _ => &distro,
        };
        let title = format!("{title} {version}");
        write!(
            html,
            r#"<article class="panel image-card" data-image-id="{id}" data-state="{state}"><header><div>{}<span class="record-meta">"#,
            heading(&distro, &title)
        )?;
        escape(&mut html, architecture(&arch));
        html.push_str("</span></div><div data-download-status>");
        status_badge(&mut html, tone, status_label);
        html.push_str("</div></header>");
        html.push_str(r#"<div data-image-details>"#);
        if state == "downloading" {
            let percent = row.get::<_, i64>(4)?.clamp(0, 100);
            write!(
                html,
                r#"<div class="image-progress"><progress value="{percent}" max="100" aria-label="Téléchargement"></progress><span class="record-meta">{percent} %</span></div>"#
            )?;
        }
        if state == "failed" {
            if let Some(error) = row
                .get::<_, Option<String>>(7)?
                .filter(|text| !text.trim().is_empty())
            {
                html.push_str(r#"<p class="image-error">"#);
                escape(&mut html, &error);
                html.push_str("</p>");
            }
        }
        html.push_str("</div>");
        if can_edit {
            let (next, label) = if enabled {
                (0, "Désactiver")
            } else {
                (1, "Activer")
            };
            let busy = matches!(state, "pending" | "downloading" | "deleting");
            let disabled = if busy { " disabled" } else { "" };
            let download = if matches!(status.as_str(), "failed" | "error" | "downloaded") {
                "Relancer le téléchargement"
            } else {
                "Télécharger"
            };
            write!(
                html,
                r#"<div class="image-actions" data-image-actions><div class="form-actions">
<form method="post" action="{ROUTE}/{id}/toggle"><button class="button--quiet" name="enabled" value="{next}"{disabled}>{label}</button></form>
<form method="post" action="{ROUTE}/{id}/download"><button class="button--quiet"{disabled}>{download}</button></form>
</div>"#
            )?;
            if !busy {
                write!(
                    html,
                    r#"<details class="image-delete"><summary>Supprimer…</summary><form method="post" action="{ROUTE}/{id}"><p>Supprimer cette image et ses fichiers locaux&nbsp;?</p><button class="button--danger" name="_method" value="DELETE">Confirmer la suppression</button></form></details>"#
                )?;
            }
            html.push_str("</div>");
        }
        html.push_str("</article>");
    }
    if !found {
        html.push_str(r#"<div class="panel table-empty"><strong>Aucune image téléchargée ou demandée</strong>Choisissez une version dans le catalogue ci-dessous.</div>"#);
    }
    html.push_str("</div>");
    let has_next = rows.next()?.is_some() && number < u32::MAX;
    if number > 1 || has_next {
        html.push_str(r#"<nav class="form-actions pagination" aria-label="Pages des images">"#);
        if number > 1 {
            write!(
                html,
                r#"<a class="button button--quiet" rel="prev" href="{ROUTE}?page={}">Précédente</a>"#,
                number - 1
            )?;
        }
        if has_next {
            write!(
                html,
                r#"<a class="button button--quiet" rel="next" href="{ROUTE}?page={}">Suivante</a>"#,
                number + 1
            )?;
        }
        html.push_str("</nav>");
    }
    html.push_str("</section>");
    Ok(html)
}

fn architecture(arch: &str) -> &str {
    match arch {
        "amd64" => "Intel / AMD 64 bits",
        "arm64" => "ARM 64 bits",
        _ => arch,
    }
}

pub(super) fn queue_image(db: &Connection, id: i64, resume: bool) -> rusqlite::Result<Option<i64>> {
    db.execute(
        "INSERT INTO os_images(distro,version,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,enabled,status)
                SELECT distro,version_full,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,1,'pending'
                FROM catalog_entries WHERE id=?1 AND arch IN ('amd64','arm64')
                    AND ((distro='debian' AND extract_method='direct')
                      OR (distro='ubuntu' AND extract_method='iso_extract'))
                ON CONFLICT(distro,version_full,arch) WHERE version_full IS NOT NULL
                DO UPDATE SET enabled=1,
                    status=CASE WHEN os_images.status IN ('downloaded','downloading')
                                THEN os_images.status ELSE 'pending' END,
                    error_msg=CASE WHEN os_images.status IN ('downloaded','downloading')
                                   THEN os_images.error_msg ELSE NULL END
                WHERE os_images.extract_method=excluded.extract_method AND ?2",
        rusqlite::params![id, resume],
    )?;
    db.query_row(
        "SELECT i.id FROM os_images i JOIN catalog_entries c
                     ON i.distro=c.distro AND i.version_full=c.version_full AND i.arch=c.arch
                  WHERE c.id=?1 AND c.arch IN ('amd64','arm64')
                    AND i.extract_method=c.extract_method
                    AND ((c.distro='debian' AND c.extract_method='direct')
                      OR (c.distro='ubuntu' AND c.extract_method='iso_extract'))",
        [id],
        |row| row.get(0),
    )
    .optional()
}

fn catalog(db: &Connection, can_edit: bool) -> Result<String, ErrorBox> {
    let mut html = String::from(
        r#"<section id="catalogue" aria-labelledby="catalog-title"><header class="section-heading">
<div><h2 id="catalog-title">Catalogue des systèmes</h2><p class="record-meta">Téléchargez les images disponibles depuis leurs éditeurs ou importez vos propres médias.</p></div>"#,
    );
    if can_edit {
        write!(
            html,
            r#"<form method="post" action="{ROUTE}/refresh"><button class="button--quiet">Actualiser le catalogue</button></form>"#
        )?;
    }
    html.push_str("</header>");
    html.push_str(&refresh_button(db)?);
    html.push_str(r#"<div class="panel-grid image-catalog">"#);
    let mut query = db.prepare(
        "SELECT c.id,c.version_full,c.arch, EXISTS(
            SELECT 1 FROM os_images i WHERE i.distro=c.distro AND i.arch=c.arch
                AND COALESCE(NULLIF(i.version_full,''),i.version)=c.version_full
         ) AS managed FROM catalog_entries c
         WHERE c.distro=?1 AND c.arch IN ('amd64','arm64')
           AND ((c.distro='debian' AND c.extract_method='direct')
             OR (c.distro='ubuntu' AND c.extract_method='iso_extract'))
         ORDER BY c.major DESC,c.version_full DESC,c.arch,c.id LIMIT 50",
    )?;
    for (code, title, description) in [
        (
            "debian",
            "Debian",
            "Fichiers de démarrage et d’installation réseau.",
        ),
        (
            "ubuntu",
            "Ubuntu Server",
            "ISO officielle et fichiers de démarrage extraits sur le serveur.",
        ),
    ] {
        write!(
            html,
            r#"<article class="panel image-card">{}<p>{description}</p>"#,
            heading(code, title)
        )?;
        let mut rows = query.query([code])?;
        let mut options = String::new();
        let mut count = 0;
        let mut available = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            let id: i64 = row.get(0)?;
            let version: String = row.get(1)?;
            let arch: String = row.get(2)?;
            let managed: bool = row.get(3)?;
            available += usize::from(!managed);
            let disabled = if managed { " disabled" } else { "" };
            write!(options, r#"<option value="{id}"{disabled}>{title} "#)?;
            escape(&mut options, &version);
            options.push_str(" · ");
            escape(&mut options, architecture(&arch));
            if managed {
                options.push_str(" · Sur ce serveur");
            }
            options.push_str("</option>");
        }
        if count == 0 {
            html.push_str(r#"<p class="record-meta">Aucune version dans le catalogue. Actualisez-le pour rechercher les images.</p>"#);
        } else if can_edit {
            let disabled = if available == 0 { " disabled" } else { "" };
            write!(
                html,
                r#"<form class="form-stack" method="post" action="{ROUTE}">
<div class="field"><label for="image-{code}">Version et architecture</label><select id="image-{code}" name="image" required{disabled}>
<option value="" selected disabled>Choisir une version de {title}</option>{options}</select></div>
<div class="form-actions"><button{disabled}>Télécharger</button></div></form>"#
            )?;
        } else {
            write!(
                html,
                r#"<p class="record-meta">Versions et architectures au catalogue&nbsp; {count}</p>"#
            )?;
        }
        html.push_str("</article>");
    }
    if can_edit {
        write!(
            html,
            r#"<article class="panel image-card">{}<p>Préparez un DVD officiel de RHEL 9 pour le démarrage réseau.</p>
<div class="form-actions"><a class="button" href="{REDHAT_ROUTE}">Télécharger depuis Red Hat</a>
<a class="button button--quiet" href="{ROUTE}/media?kind=rhel9">Importer le DVD</a></div></article>
<article class="panel image-card">{}<p>Importez le média d’installation et un environnement de démarrage WinPE.</p>
<div class="form-actions"><a class="button button--quiet" href="{ROUTE}/media?kind=windows-iso">Importer les fichiers</a>
<a class="button button--quiet" href="/settings/windows">Gérer les éditions</a></div></article>"#,
            heading("rhel9", "Red Hat Enterprise Linux"),
            heading("windows", "Windows")
        )?;
    }
    html.push_str("</div></section>");
    Ok(html)
}
