// SPDX-License-Identifier: LGPL-3.0-only

use super::{field, store};
use crate::{
    alpine, setting,
    web::{admin::escape, images, jobs::json_reply, setup::redirect, ui, ErrorBox, Reply},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write};

const PAGE: &str = "/init/images";
pub(super) const EXTRAS_DRAFT: &str = "rust_wizard_additional_images";
const AVAILABLE: &str = "arch IN ('amd64','arm64') AND
    ((distro='debian' AND (extract_method='direct' OR
         (extract_method='iso_extract' AND channel='testing' AND NULLIF(iso_url,'') IS NOT NULL)))
      OR (distro='ubuntu' AND extract_method='iso_extract')
      OR (distro IN ('fedora','centos','almalinux','rocky') AND extract_method='direct'))";

pub(super) struct Image {
    pub id: i64,
    distro: String,
    version: String,
    arch: String,
    pub status: String,
    percent: i64,
}

impl Image {
    pub fn label(&self) -> String {
        format!(
            "{} {} · {}",
            distro(&self.distro),
            self.version,
            architecture(&self.arch)
        )
    }

    fn waiting(&self) -> bool {
        matches!(self.status.as_str(), "pending" | "downloading")
    }

    fn failed(&self) -> bool {
        matches!(self.status.as_str(), "failed" | "error")
    }
}

fn distro(value: &str) -> &str {
    match value {
        "ubuntu" => "Ubuntu Server",
        "debian" => "Debian",
        _ => crate::catalog::rpm_label(value).unwrap_or(value),
    }
}

fn architecture(value: &str) -> &str {
    if value == "arm64" {
        "ARM 64 bits"
    } else {
        "Intel / AMD 64 bits"
    }
}

fn image(db: &Connection, id: i64) -> rusqlite::Result<Option<Image>> {
    db.query_row(
        &format!(
            "SELECT id,distro,COALESCE(version_full,version),arch,status,progress_percent
                  FROM os_images WHERE id=?1 AND enabled=1 AND {AVAILABLE}"
        ),
        [id],
        |row| {
            Ok(Image {
                id: row.get(0)?,
                distro: row.get(1)?,
                version: row.get(2)?,
                arch: row.get(3)?,
                status: row.get(4)?,
                percent: row.get::<_, i64>(5)?.clamp(0, 100),
            })
        },
    )
    .optional()
}

fn service_status(db: &Connection) -> rusqlite::Result<Option<(String, i64)>> {
    db.query_row(
        "SELECT status,progress_percent FROM init_jobs WHERE job_type=?1 ORDER BY id DESC LIMIT 1",
        [alpine::JOB],
        |row| Ok((row.get(0)?, row.get::<_, i64>(1)?.clamp(0, 100))),
    )
    .optional()
}

fn extras(db: &Connection) -> Result<Vec<Image>, ErrorBox> {
    let saved = setting(db, EXTRAS_DRAFT)?;
    let mut result = Vec::new();
    if !saved.is_empty() {
        for id in serde_json::from_str::<Vec<i64>>(&saved)? {
            if let Some(image) = image(db, id)? {
                result.push(image);
            }
        }
    }
    Ok(result)
}

pub(super) fn needs_catalog(db: &Connection) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM catalog_entries)",
        [],
        |row| row.get(0),
    )
}

pub(super) fn submit(db: &Connection, fields: &HashMap<String, String>) -> Result<Reply, ErrorBox> {
    match field(fields, "action") {
        "refresh" if fields.len() == 1 => images::refresh_catalog(db)?,
        "retry" if fields.len() == 1 => {
            alpine::queue(db, true)?;
            for image in extras(db)?.iter().filter(|image| image.failed()) {
                db.execute(
                    "UPDATE os_images SET status='pending',progress_percent=0,message=NULL,error_msg=NULL,
                         updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status IN ('failed','error')",
                    [image.id],
                )?;
            }
        }
        "continue" if fields.len() == 1 => {
            if alpine::all_ready() {
                return Ok(redirect(StatusCode::SEE_OTHER, "/init/done"));
            }
            return Ok(redirect(StatusCode::SEE_OTHER, PAGE));
        }
        "prepare" => {
            let mut selected = Vec::new();
            for (key, value) in fields {
                if key == "action" {
                    continue;
                }
                let pieces: Vec<_> = key.split(':').collect();
                let ["image", distro, version, arch] = pieces.as_slice() else {
                    return Ok(invalid());
                };
                if value != "on" || selected.len() >= 50 {
                    return Ok(invalid());
                }
                let choice = db
                    .query_row(
                        &format!(
                            "SELECT id FROM catalog_entries WHERE distro=?1 AND version_full=?2
                              AND arch=?3 AND {AVAILABLE}"
                        ),
                        params![distro, version, arch],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?;
                let Some(choice) = choice else {
                    return Ok(invalid());
                };
                selected.push(choice);
            }
            alpine::queue(db, false)?;
            selected.sort_unstable();
            let mut saved: Vec<_> = extras(db)?.into_iter().map(|image| image.id).collect();
            for choice in selected {
                if let Some(id) = images::queue_image(db, choice, true)? {
                    if !saved.contains(&id) {
                        saved.push(id);
                    }
                }
            }
            store(db, EXTRAS_DRAFT, &serde_json::to_string(&saved)?)?;
        }
        _ => return Ok(invalid()),
    }
    Ok(redirect(StatusCode::SEE_OTHER, PAGE))
}

fn invalid() -> Reply {
    ui::wizard_error(
        ui::WizardStep::Images,
        StatusCode::UNPROCESSABLE_ENTITY,
        "La sélection ne correspond plus au catalogue. Rouvrez la liste des systèmes.",
        PAGE,
    )
}

#[derive(Serialize)]
struct Snapshot {
    catalog: String,
    catalog_version: String,
    downloads: String,
    active: bool,
    ready: bool,
    retry: bool,
}

fn snapshot(db: &Connection) -> Result<Snapshot, ErrorBox> {
    let db = db.unchecked_transaction()?;
    let extras = extras(&db)?;
    let ready = alpine::all_ready();
    let service = service_status(&db)?;
    let job = db.query_row(
        "SELECT status FROM init_jobs
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2','bootstrap:auto_refresh_catalog_v2')
         ORDER BY status IN ('pending','running') DESC,id DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    ).optional()?;
    let loading = matches!(job.as_deref(), Some("pending" | "running"));
    let catalog = choices(&db, &extras, loading)?;
    let catalog_version = URL_SAFE_NO_PAD.encode(&Sha256::digest(catalog.as_bytes())[..9]);
    let retry = (!ready && service.as_ref().is_some_and(|(state, _)| state == "failed"))
        || extras.iter().any(Image::failed);
    let mut downloads = String::new();
    if ready || service.is_some() || !extras.is_empty() {
        downloads.push_str("<h2>Préparation des images</h2><ul class=\"wizard-downloads\">");
        write!(
            downloads,
            "<li><strong>Image de service · Alpine {} · amd64 et ARM64</strong>",
            alpine::version()
        )?;
        match (ready, service.as_ref()) {
            (true, _) => downloads.push_str("<span>Prête</span>"),
            (_, Some((state, _))) if state == "failed" => {
                downloads.push_str("<span>La préparation d’Alpine a échoué.</span>")
            }
            (_, Some((state, _))) if state == "running" => {
                downloads.push_str("<span>Téléchargement et vérification en cours…</span>")
            }
            _ => downloads.push_str("<span>En attente</span>"),
        }
        downloads.push_str("</li>");
        for image in &extras {
            downloads.push_str("<li><strong>");
            escape(&mut downloads, &image.label());
            downloads.push_str("</strong>");
            match image.status.as_str() {
                "downloaded" => downloads.push_str("<span>Prête</span>"),
                "pending" => downloads.push_str("<span>En attente</span>"),
                "downloading" => write!(
                    downloads,
                    r#"<span>Téléchargement · {} %</span><progress aria-label="Progression du téléchargement" max="100" value="{}"></progress>"#,
                    image.percent, image.percent
                )?,
                "error" | "failed" => {
                    downloads.push_str("<span>Le téléchargement a échoué.</span>")
                }
                _ => downloads.push_str("<span>Image indisponible.</span>"),
            }
            downloads.push_str("</li>");
        }
        downloads.push_str("</ul>");
        if !ready {
            downloads.push_str(r#"<p class="muted">Vous pourrez activer PXE dès que l’image de service sera prête.</p>"#);
        }
    }
    Ok(Snapshot {
        catalog,
        catalog_version,
        downloads,
        active: loading
            || (!ready
                && service
                    .as_ref()
                    .is_some_and(|(state, _)| matches!(state.as_str(), "pending" | "running")))
            || extras.iter().any(Image::waiting),
        ready,
        retry,
    })
}

fn choices(db: &Connection, extras: &[Image], loading: bool) -> Result<String, ErrorBox> {
    let mut html = String::new();
    if loading {
        html.push_str(r#"<p class="wizard-catalog-loading"><span aria-hidden="true"></span>Chargement du catalogue des systèmes…</p>"#);
    } else if needs_catalog(db)? {
        html.push_str(r#"<p>Le catalogue des systèmes à installer est indisponible.</p><form method="post" action="/init/images"><button class="button--quiet" name="action" value="refresh">Recharger le catalogue</button></form>"#);
    }
    html.push_str(
        r#"<form method="post" action="/init/images" class="form-stack">
<details><summary>Choisir des systèmes à installer (facultatif)</summary>
<div class="form-stack network-details"><p class="muted">Cochez les versions à préparer dès maintenant. Vous pourrez ajouter d’autres médias, dont Windows, dans Images PXE après l’assistant.</p>"#,
    );
    let mut statement = db.prepare(&format!(
        "WITH ranked AS (
             SELECT distro,version_full,arch,channel,ROW_NUMBER() OVER (
                 PARTITION BY distro ORDER BY major DESC,id DESC
             ) AS position
             FROM catalog_entries WHERE {AVAILABLE}
         ), selected AS (SELECT * FROM ranked ORDER BY position,distro LIMIT 50)
         SELECT distro,version_full,arch,COALESCE(channel,'') FROM selected ORDER BY distro,position"
    ))?;
    let mut rows = statement.query([])?;
    let mut group = String::new();
    while let Some(row) = rows.next()? {
        let (family, version, arch): (String, String, String) =
            (row.get(0)?, row.get(1)?, row.get(2)?);
        if family != group {
            if !group.is_empty() {
                html.push_str("</fieldset>");
            }
            write!(
                html,
                r#"<fieldset class="permission-fields"><legend>{}</legend>"#,
                distro(&family)
            )?;
            group.clone_from(&family);
        }
        let queued = extras
            .iter()
            .any(|image| image.distro == family && image.version == version && image.arch == arch);
        html.push_str(r#"<label class="check-label"><input type="checkbox" name=""#);
        escape(&mut html, &format!("image:{family}:{version}:{arch}"));
        html.push_str(if queued {
            r#"" checked disabled><span>"#
        } else {
            r#""><span>"#
        });
        escape(&mut html, &format!("{version} · {}", architecture(&arch)));
        let channel: String = row.get(3)?;
        if let Some((tone, label)) = images::catalog_channel(&channel) {
            html.push_str(r#"<span class="wizard-image-channel">"#);
            ui::status_badge(&mut html, tone, label);
            html.push_str("</span>");
        }
        html.push_str("</span></label>");
    }
    if !group.is_empty() {
        html.push_str("</fieldset>");
    }
    html.push_str("</div>");
    if alpine::all_ready() {
        html.push_str(r#"<div class="form-actions"><button class="button--quiet" name="action" value="prepare">Ajouter les systèmes cochés</button></div></details>"#);
    } else {
        html.push_str(r#"</details><div class="form-actions"><button name="action" value="prepare">Préparer les images</button></div>"#);
    }
    html.push_str("</form>");
    Ok(html)
}

pub(super) fn page(db: &Connection) -> Result<Reply, ErrorBox> {
    let state = snapshot(db)?;
    let running = if state.active { "yes" } else { "no" };
    let retry = if state.retry { "" } else { " hidden" };
    let ready = if state.ready { "" } else { " hidden" };
    let html = format!(
        r#"<p class="wizard-intro">PXE Tools utilise Alpine pour la découverte, le secours et les opérations disque. Choisissez aussi les systèmes que vous souhaitez installer.</p>
<section data-image-downloads aria-live="polite" data-active="{running}">{downloads}</section>
<form data-image-retry method="post" action="/init/images"{retry}><button class="button--quiet" name="action" value="retry">Relancer les téléchargements en échec</button></form>
<form data-image-ready method="post" action="/init/images"{ready}><button name="action" value="continue">Continuer vers la validation</button></form>
<div data-image-catalog="{catalog_version}">{catalog}</div>
<p data-image-feedback class="muted" role="status"></p>
<noscript><p><a href="/init/images">Actualiser l’état des téléchargements</a></p></noscript>
<p class="wizard-back"><a href="/init/network">Modifier le réseau</a></p>"#,
        downloads = state.downloads,
        catalog_version = state.catalog_version,
        catalog = state.catalog,
    );
    Ok(ui::wizard_images(&html))
}

pub(super) fn status(db: &Connection) -> Result<Reply, ErrorBox> {
    json_reply(StatusCode::OK, snapshot(db)?)
}
