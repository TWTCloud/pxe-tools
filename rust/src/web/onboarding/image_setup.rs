// SPDX-License-Identifier: LGPL-3.0-only

use super::{field, store};
use crate::{
    setting,
    web::{admin::escape, images, jobs::json_reply, setup::redirect, ui, ErrorBox, Reply},
};
use hyper::StatusCode;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt::Write};

const PAGE: &str = "/init/images";
pub(super) const BASE_DRAFT: &str = "rust_wizard_image";
pub(super) const EXTRAS_DRAFT: &str = "rust_wizard_additional_images";
const AVAILABLE: &str = "arch IN ('amd64','arm64') AND
    ((distro='debian' AND extract_method='direct') OR (distro='ubuntu' AND extract_method='iso_extract'))";

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
    if value == "ubuntu" {
        "Ubuntu Server"
    } else {
        "Debian"
    }
}

fn architecture(value: &str) -> &str {
    if value == "arm64" {
        "ARM 64 bits"
    } else {
        "Intel / AMD 64 bits"
    }
}

fn base_entry(db: &Connection) -> rusqlite::Result<Option<i64>> {
    db.query_row(
        "SELECT id FROM catalog_entries
         WHERE distro='debian' AND channel='stable' AND arch IN ('amd64','arm64')
           AND extract_method='direct'
         ORDER BY arch='amd64' DESC,major DESC,id DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .optional()
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

pub(super) fn base(db: &Connection) -> rusqlite::Result<Option<Image>> {
    let id = setting(db, BASE_DRAFT)?.parse().unwrap_or_default();
    Ok(image(db, id)?.filter(|image| image.distro == "debian"))
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
    Ok(base_entry(db)?.is_none())
}

pub(super) fn submit(db: &Connection, fields: &HashMap<String, String>) -> Result<Reply, ErrorBox> {
    let current = base(db)?;
    match field(fields, "action") {
        "refresh" if fields.len() == 1 => images::refresh_catalog(db)?,
        "retry" if fields.len() == 1 => {
            let additional = extras(db)?;
            for image in current
                .iter()
                .chain(&additional)
                .filter(|image| image.failed())
            {
                db.execute(
                    "UPDATE os_images SET status='pending',progress_percent=0,message=NULL,error_msg=NULL,
                         updated_at=CURRENT_TIMESTAMP WHERE id=?1 AND status IN ('failed','error')",
                    [image.id],
                )?;
            }
        }
        "continue" if fields.len() == 1 => {
            if current.is_some_and(|image| image.status == "downloaded") {
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
            let service_id = if let Some(current) = current {
                current.id
            } else {
                let Some(choice) = base_entry(db)? else {
                    images::refresh_catalog(db)?;
                    return Ok(redirect(StatusCode::SEE_OTHER, PAGE));
                };
                let Some(id) = images::queue_image(db, choice, true)? else {
                    return Ok(invalid());
                };
                store(db, BASE_DRAFT, &id.to_string())?;
                id
            };
            selected.sort_unstable();
            let mut saved: Vec<_> = extras(db)?.into_iter().map(|image| image.id).collect();
            for choice in selected {
                if let Some(id) = images::queue_image(db, choice, false)? {
                    if id != service_id && !saved.contains(&id) {
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
    let base = base(&db)?;
    let extras = extras(&db)?;
    let recommended = base_entry(&db)?;
    let job = db.query_row(
        "SELECT status FROM init_jobs
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2','bootstrap:auto_refresh_catalog_v2')
         ORDER BY status IN ('pending','running') DESC,id DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    ).optional()?;
    let loading = matches!(job.as_deref(), Some("pending" | "running"));
    let catalog = choices(&db, recommended, &extras, loading, base.is_some())?;
    let catalog_version = format!("{:x}", Sha256::digest(catalog.as_bytes()));
    let ready = base
        .as_ref()
        .is_some_and(|image| image.status == "downloaded");
    let retry = base.iter().chain(&extras).any(Image::failed);
    let mut downloads = String::new();
    if base.is_some() || !extras.is_empty() {
        downloads.push_str("<h2>Préparation des images</h2><ul class=\"wizard-downloads\">");
        for image in base.iter().chain(&extras) {
            downloads.push_str("<li><strong>");
            if Some(image.id) == base.as_ref().map(|base| base.id) {
                downloads.push_str("Image de service · ");
            }
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
        active: loading || base.iter().chain(&extras).any(Image::waiting),
        ready,
        retry,
    })
}

fn choices(
    db: &Connection,
    recommended: Option<i64>,
    extras: &[Image],
    loading: bool,
    started: bool,
) -> Result<String, ErrorBox> {
    if recommended.is_none() {
        return Ok(if loading {
            r#"<p class="wizard-catalog-loading"><span aria-hidden="true"></span>Chargement du catalogue des systèmes…</p>"#.into()
        } else {
            r#"<p>Le catalogue est indisponible. Vérifiez la connexion Internet du serveur PXE, puis réessayez.</p><form method="post" action="/init/images"><button name="action" value="refresh">Recharger le catalogue</button></form>"#.into()
        });
    }
    let mut html = String::new();
    if !started {
        let (version, arch): (String, String) = db.query_row(
            "SELECT version_full,arch FROM catalog_entries WHERE id=?1",
            [recommended],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        html.push_str("<p><strong>Image de service</strong><br>");
        escape(
            &mut html,
            &format!("Debian {version} · {}", architecture(&arch)),
        );
        html.push_str("</p>");
    }
    html.push_str(
        r#"<form method="post" action="/init/images" class="form-stack">
<details><summary>Choisir des systèmes à installer (facultatif)</summary>
<div class="form-stack network-details"><p class="muted">Cochez les versions à préparer dès maintenant. Vous pourrez ajouter d’autres médias, dont Windows, dans Images PXE après l’assistant.</p>"#,
    );
    let mut statement = db.prepare(&format!(
        "SELECT distro,version_full,arch FROM catalog_entries WHERE id<>?1 AND {AVAILABLE}
         ORDER BY distro, major DESC, discovered_at DESC, id LIMIT 50"
    ))?;
    let mut rows = statement.query([recommended])?;
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
        html.push_str("</span></label>");
    }
    if !group.is_empty() {
        html.push_str("</fieldset>");
    }
    html.push_str("</div>");
    if started {
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
        r#"<p class="wizard-intro">PXE Tools prépare automatiquement Debian stable pour découvrir et dépanner les appareils. Vous pourrez installer les systèmes de votre choix sur ces appareils.</p>
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
