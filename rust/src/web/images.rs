// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    plain,
    setup::redirect,
    ui::{page, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{
    connect,
    images::{Change, Changed},
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
    Media,
    Refresh,
    RefreshStatus,
    AutoRefresh,
    Status,
    Toggle(i64),
    Download(i64),
    Delete(i64),
}

impl Route {
    pub(super) fn for_path(path: &str) -> Option<Self> {
        Some(match path {
            ROUTE => Self::List,
            "/settings/images/add" => Self::Add,
            "/settings/images/media" => Self::Media,
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
                Self::List | Self::Add | Self::Media | Self::RefreshStatus | Self::Status
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
) -> Reply {
    let result = match (route, form) {
        (Route::List, None) => list(db, number),
        (Route::Media, None) => media_form(db),
        (Route::Media, Some(form)) => queue_media(path, form),
        (Route::Add, None) => catalog_form(db, ROUTE)
            .map(|form| {
                page(
                    ConsoleSection::Images,
                    "Ajouter une image",
                    &format!("{form}<p><a href=\"{ROUTE}\">Images PXE</a></p>"),
                )
            })
            .map_err(Into::into),
        (Route::Status, None) => {
            table(db, number).map(|html| page(ConsoleSection::Images, "Images PXE", &html))
        }
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

fn media_form(db: &Connection) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<nav><a href="/settings/images">Catalogue des images</a> · <a href="/settings/windows">Éditions Windows</a></nav>
<form method="post" action="/settings/images/media">
<label>Type de média <select name="kind" required>
<option value="rhel9">DVD RHEL 9</option>
<option value="windows-iso">ISO Windows</option>
<option value="windows-wim">Fichier install.wim</option>
<option value="windows-esd">Fichier install.esd</option>
<option value="winpe">Archive WinPE préparée</option>
</select></label>
<label>Nom du fichier sur le serveur ou URL HTTPS autorisée <input name="source" maxlength="4096" required></label>
<label>Empreinte SHA-256 de la source <input name="sha256" pattern="[A-Fa-f0-9]{64}" required></label>
<label>Identifiant de l’édition pour une archive WinPE <input name="profile" pattern="[a-z0-9-]{1,40}"></label>
<button>Préparer le média</button>
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
        "SELECT id,status,message FROM init_jobs WHERE job_type=?1 ORDER BY id DESC LIMIT 10",
    )?;
    let mut rows = jobs.query([crate::media::JOB])?;
    html.push_str("<h2>Préparations récentes</h2><ul>");
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        write!(html, "<li><a href=\"/jobs/{id}\">Tâche {id}</a> · ")?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str(" · ");
        escape(
            &mut html,
            &row.get::<_, Option<String>>(2)?.unwrap_or_default(),
        );
        html.push_str("</li>");
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
    };
    if !request.valid() {
        return Ok(plain(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Type de média, source ou empreinte invalide\n",
        ));
    }
    let mut db = connect(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let id = crate::media::enqueue(&mut db, request)?;
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
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2')
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

fn list(db: &Connection, number: u32) -> Result<Reply, ErrorBox> {
    let mut html = String::from(
        r#"<nav><a href="/admin/devices">Console</a> · <a href="/settings/images/media">Préparer un média RHEL ou Windows</a> · <a href="/settings/windows">Éditions Windows</a></nav>"#,
    );
    html.push_str(&catalog_form(db, ROUTE)?);
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
        r#"<form method="post" action="{ROUTE}/auto-refresh"><label>
<input type="checkbox" name="catalog_auto_refresh_enabled" value="on"{enabled}> Actualiser automatiquement le catalogue</label>
<label>Fréquence <select name="catalog_auto_refresh_interval_hours">"#
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
    html.push_str("</select></label><button>Enregistrer</button></form>");
    html.push_str(&refresh_button(db)?);
    html.push_str(&table(db, number)?);
    Ok(page(ConsoleSection::Images, "Images PXE", &html))
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
        html.push_str("<p>Actualisation du catalogue · ");
        escape(&mut html, &status);
        html.push_str("</p>");
    }
    Ok(html)
}

fn table(db: &Connection, number: u32) -> Result<String, ErrorBox> {
    let mut html = String::from("<table><thead><tr><th>Distribution</th><th>Version</th><th>Architecture</th><th>État</th><th>Progression</th><th>Activée</th><th>Actions</th></tr></thead><tbody>");
    let mut query = db.prepare(
        "SELECT distro, COALESCE(version_full,version), arch, status, progress_percent, enabled,id
         FROM os_images ORDER BY distro,major DESC,version_full DESC,arch,id LIMIT ? OFFSET ?",
    )?;
    let mut rows = query.query([PAGE_SIZE + 1, u64::from(number - 1) * PAGE_SIZE])?;
    for _ in 0..PAGE_SIZE {
        let Some(row) = rows.next()? else { break };
        html.push_str("<tr>");
        for col in 0..4 {
            html.push_str("<td>");
            escape(&mut html, &row.get::<_, String>(col)?);
            html.push_str("</td>");
        }
        let percent = row.get::<_, i64>(4)?.clamp(0, 100);
        let id: i64 = row.get(6)?;
        let (active, next, label) = if row.get::<_, bool>(5)? {
            ("Oui", 0, "Désactiver")
        } else {
            ("Non", 1, "Activer")
        };
        write!(
            html,
            r#"<td>{percent} %</td><td>{active}</td><td>
<form method="post" action="{ROUTE}/{id}/toggle"><button name="enabled" value="{next}">{label}</button></form>
<form method="post" action="{ROUTE}/{id}/download"><button>Relancer le téléchargement</button></form>
<details><summary>Suppression</summary><form method="post" action="{ROUTE}/{id}"><button name="_method" value="DELETE">Supprimer cette image</button></form></details>
</td></tr>"#
        )?;
    }
    html.push_str("</tbody></table><nav aria-label=\"Pagination\">");
    if number > 1 {
        write!(
            html,
            r#"<a rel="prev" href="{ROUTE}?page={}">Précédente</a> "#,
            number - 1
        )?;
    }
    if rows.next()?.is_some() && number < u32::MAX {
        write!(
            html,
            r#"<a rel="next" href="{ROUTE}?page={}">Suivante</a>"#,
            number + 1
        )?;
    }
    html.push_str("</nav>");
    Ok(html)
}

pub(super) fn queue_image(db: &Connection, id: i64, resume: bool) -> rusqlite::Result<Option<i64>> {
    db.execute(
        "INSERT INTO os_images(distro,version,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,enabled,status)
                SELECT distro,version_full,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,1,'pending'
                FROM catalog_entries WHERE id=?1 AND arch IN ('amd64','arm64')
                    AND ((distro='debian' AND extract_method='direct')
                      OR (NOT ?2 AND distro='ubuntu' AND extract_method='iso_extract'))
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
                      OR (NOT ?2 AND c.distro='ubuntu' AND c.extract_method='iso_extract'))",
        rusqlite::params![id, resume],
        |row| row.get(0),
    )
    .optional()
}

pub(super) fn catalog_form(db: &Connection, action: &'static str) -> rusqlite::Result<String> {
    let include_ubuntu = action == ROUTE;
    let mut html = format!(
        r#"<form method="post" action="{action}">
<label>Image PXE <select name="image">"#,
    );
    let mut query = db.prepare(
        "SELECT id,version_full,arch,distro FROM catalog_entries
        WHERE arch IN ('amd64','arm64') AND ((distro='debian' AND extract_method='direct')
          OR (?1 AND distro='ubuntu' AND extract_method='iso_extract'))
        ORDER BY distro,major DESC,version_full DESC,arch,id LIMIT 50",
    )?;
    let mut rows = query.query([include_ubuntu])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        let id: i64 = row.get(0)?;
        let distro = if row.get::<_, String>(3)? == "ubuntu" {
            "Ubuntu Server"
        } else {
            "Debian"
        };
        html.push_str(&format!(r#"<option value="{id}">{distro} "#));
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str(" · ");
        escape(&mut html, &row.get::<_, String>(2)?);
        html.push_str("</option>");
    }
    html.push_str("</select></label>");
    if count != 0 {
        html.push_str("<button>Télécharger cette image</button>");
    }
    html.push_str(
        r#"<button name="action" value="refresh">Actualiser le catalogue</button></form>"#,
    );
    Ok(html)
}
