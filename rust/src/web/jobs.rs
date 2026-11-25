// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    bytes, plain,
    setup::redirect,
    ui::{page, status_badge, ConsoleSection},
    ErrorBox, Reply,
};
use crate::{connect, media};
use hyper::{Method, Response, StatusCode};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};
use serde::Serialize;
use serde_json::json;
use std::{fmt::Write, path::Path};

const PAGE_SIZE: u32 = 50;

pub(super) enum View {
    List,
    Detail(i64),
    Poll(i64),
    Status(i64),
    Latest(String),
    Retry(i64),
}

impl View {
    pub(super) fn for_route(path: &str, query: &str) -> Option<Self> {
        if path == "/jobs" {
            return Some(Self::List);
        }
        if path == "/api/init-job-status" {
            let kind = form_urlencoded::parse(query.as_bytes())
                .find(|(name, _)| name == "job_type")
                .map(|(_, value)| value.trim().to_owned())
                .unwrap_or_default();
            return Some(Self::Latest(kind));
        }
        if let Some(id) = path.strip_prefix("/api/init-retry-job/") {
            return Some(Self::Retry(id.parse().unwrap_or(0)));
        }
        let rest = path.strip_prefix("/jobs/")?;
        let (id, view) = rest.split_once('/').unwrap_or((rest, ""));
        let id = id.parse::<i64>().ok().filter(|id| *id > 0)?;
        match view {
            "" => Some(Self::Detail(id)),
            "poll" => Some(Self::Poll(id)),
            "status" => Some(Self::Status(id)),
            _ => None,
        }
    }

    pub(super) fn allows(&self, method: &Method) -> bool {
        match self {
            Self::Retry(_) => *method == Method::POST,
            _ => matches!(*method, Method::GET | Method::HEAD),
        }
    }

    pub(super) fn is_redhat_media(&self, db: &Connection) -> rusqlite::Result<bool> {
        let (Self::Detail(id) | Self::Poll(id) | Self::Status(id)) = self else {
            return Ok(false);
        };
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM init_jobs WHERE id=?1 AND job_type=?2)",
            rusqlite::params![id, media::REDHAT_JOB],
            |row| row.get(0),
        )
    }

    pub(super) fn serve(
        &self,
        db: &Connection,
        db_path: &Path,
        number: u32,
    ) -> Result<Reply, ErrorBox> {
        const STATUS: &str =
            "SELECT id,job_type,status,progress_percent,message,started_at,ended_at,updated_at FROM init_jobs";
        match self {
            Self::List => list(db, number),
            Self::Detail(id) | Self::Poll(id) => detail(db, *id, matches!(self, Self::Poll(_))),
            Self::Status(id) => {
                let job = db
                    .query_row(&format!("{STATUS} WHERE id=?1"), [id], Job::read)
                    .optional()?;
                status(job, StatusCode::NOT_FOUND)
            }
            Self::Latest(kind) if kind.is_empty() || kind.len() > 128 => json_reply(
                StatusCode::BAD_REQUEST,
                json!({"error":"job_type requis (1-128 chars)"}),
            ),
            Self::Latest(kind) => {
                let job = db
                    .query_row(
                        &format!("{STATUS} WHERE job_type=?1 ORDER BY id DESC LIMIT 1"),
                        [kind],
                        Job::read,
                    )
                    .optional()?;
                status(job, StatusCode::OK)
            }
            Self::Retry(id) => retry(db_path, *id),
        }
    }
}

#[derive(Serialize)]
struct Job {
    id: i64,
    job_type: String,
    status: String,
    progress_percent: i64,
    message: Option<String>,
    started_at: Option<String>,
    ended_at: Option<String>,
    updated_at: Option<String>,
}

impl Job {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            job_type: row.get(1)?,
            status: row.get(2)?,
            progress_percent: row.get(3)?,
            message: row.get(4)?,
            started_at: row.get(5)?,
            ended_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }
}

fn status(job: Option<Job>, absent: StatusCode) -> Result<Reply, ErrorBox> {
    let Some(job) = job else {
        return json_reply(absent, json!({"found":false}));
    };
    #[derive(Serialize)]
    struct Found {
        found: bool,
        #[serde(flatten)]
        job: Job,
    }
    json_reply(StatusCode::OK, Found { found: true, job })
}

fn retry(db_path: &Path, id: i64) -> Result<Reply, ErrorBox> {
    if id <= 0 {
        return json_reply(StatusCode::BAD_REQUEST, json!({"error":"id invalide"}));
    }
    let db = connect(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.execute(
        "UPDATE init_jobs SET status='pending', started_at=NULL, ended_at=NULL,
           updated_at=NULL, progress_percent=0, message=NULL,
           log=CASE WHEN job_type LIKE 'image:delete:%' THEN log ELSE '' END
         WHERE id=?1 AND status='failed' AND job_type<>?2
           AND NOT EXISTS (
             SELECT 1 FROM init_jobs AS active
             WHERE active.job_type=init_jobs.job_type AND active.status IN ('pending','running')
           )",
        rusqlite::params![id, media::REDHAT_JOB],
    )?;
    Ok(redirect(StatusCode::SEE_OTHER, format!("/jobs/{id}")))
}

pub(super) fn json_reply(code: StatusCode, value: impl Serialize) -> Result<Reply, ErrorBox> {
    Ok(Response::builder()
        .status(code)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(bytes(serde_json::to_vec(&value)?))?)
}

pub(super) fn title(kind: &str) -> &str {
    match kind {
        "bootstrap:install_pxe_bins" => "Préparation du démarrage par le réseau",
        "bootstrap:generate_mok" => "Mise en place du démarrage sécurisé",
        "bootstrap:download_images" => "Téléchargement des systèmes d’exploitation",
        "bootstrap:build_grub" => "Préparation du chargeur de démarrage",
        "bootstrap:render_templates" => "Création des menus de démarrage",
        "bootstrap:regen_mok" => "Renouvellement du démarrage sécurisé",
        "bootstrap:rebuild_grub" => "Reconstruction du chargeur de démarrage",
        "bootstrap:restart_dnsmasq" => "Activation du réseau",
        "bootstrap:refresh_catalog"
        | "bootstrap:refresh_catalog_v2"
        | "bootstrap:auto_refresh_catalog_v2" => "Mise à jour de la liste des systèmes",
        "bootstrap:cleanup_per_mac_files" => "Nettoyage des fichiers temporaires",
        "system:factory_reset_wipe" => "Remise à zéro du serveur",
        "system:nginx_reload" => "Mise à jour de l’interface",
        media::JOB => "Préparation d’un média",
        media::REDHAT_JOB => "Téléchargement et préparation de RHEL",
        kind if kind.starts_with("image:delete:") => "Suppression d’une image",
        kind if kind.starts_with("preset:push_github:") => "Sauvegarde du modèle sur GitHub",
        kind if kind.starts_with("preset:delete_github:") => "Suppression du modèle sur GitHub",
        kind if kind.starts_with("preset:pull_github") => "Récupération des modèles depuis GitHub",
        kind if kind.starts_with("action:render_postboot:") => "Préparation du premier démarrage",
        kind if kind.starts_with("machine:ansible_redeploy:")
            || kind.starts_with("action:ansible_retry:") =>
        {
            "Exécution d’Ansible"
        }
        kind if kind.starts_with("machine:reboot:") || kind.starts_with("action:reboot:") => {
            "Redémarrage à distance"
        }
        kind if kind.starts_with("machine:shutdown:") => "Arrêt à distance",
        _ => "Tâche de l’appliance",
    }
}

fn list(db: &Connection, number: u32) -> Result<Reply, ErrorBox> {
    let mut statement = db.prepare(
        "SELECT id,job_type,status,message,COALESCE(updated_at,ended_at,created_at)
         FROM init_jobs ORDER BY id DESC LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = statement.query([
        u64::from(PAGE_SIZE) + 1,
        u64::from(number - 1) * u64::from(PAGE_SIZE),
    ])?;
    let mut html = String::from(
        r#"<div class="table-region jobs-table" role="region" aria-label="Liste des tâches" tabindex="0"><table role="table"><thead role="rowgroup"><tr role="row"><th scope="col" role="columnheader">Tâche</th><th scope="col" role="columnheader">État</th><th scope="col" role="columnheader">Dernière activité (UTC)</th></tr></thead><tbody role="rowgroup">"#,
    );
    let mut found = false;
    for _ in 0..PAGE_SIZE {
        let Some(row) = rows.next()? else { break };
        found = true;
        let id: i64 = row.get(0)?;
        let kind: String = row.get(1)?;
        let state: String = row.get(2)?;
        let message: Option<String> = row.get(3)?;
        let date: Option<String> = row.get(4)?;
        write!(
            html,
            r#"<tr role="row" class="job-row"><td role="cell" class="job-name"><a class="operation-name" href="/jobs/{id}">"#
        )?;
        escape(&mut html, title(&kind));
        write!(html, r#" <span class="operation-id">#{id}</span></a>"#)?;
        if let Some(message) = message.filter(|text| !text.trim().is_empty()) {
            html.push_str(r#"<span class="record-meta">"#);
            escape(&mut html, &message);
            html.push_str("</span>");
        }
        html.push_str(r#"</td><td role="cell" class="job-state">"#);
        status_badge(&mut html, &state, super::activity::status_label(&state));
        html.push_str(r#"</td><td role="cell" class="job-date">"#);
        escape(&mut html, date.as_deref().unwrap_or("—"));
        html.push_str("</td></tr>");
    }
    if !found {
        html.push_str(r#"<tr role="row"><td role="cell" class="table-empty" colspan="3"><strong>Aucune tâche enregistrée</strong>Les tâches du serveur apparaîtront ici.</td></tr>"#);
    }
    html.push_str("</tbody></table></div>");
    let has_next = rows.next()?.is_some() && number < u32::MAX;
    if number > 1 || has_next {
        html.push_str(r#"<nav aria-label="Pages des tâches">"#);
        if number > 1 {
            write!(
                html,
                r#"<a rel="prev" href="/jobs?page={}">Précédente</a>"#,
                number - 1
            )?;
        }
        if has_next {
            write!(
                html,
                r#"<a rel="next" href="/jobs?page={}">Suivante</a>"#,
                number + 1
            )?;
        }
        html.push_str("</nav>");
    }
    Ok(page(ConsoleSection::Jobs, "Tâches", &html))
}

fn detail(db: &Connection, id: i64, fragment: bool) -> Result<Reply, ErrorBox> {
    let row: Option<(Job, String)> = db
        .query_row(
            "SELECT id,job_type,status,progress_percent,message,started_at,ended_at,updated_at,
                COALESCE(substr(log,-65536),'') FROM init_jobs WHERE id=?1",
            [id],
            |row| Ok((Job::read(row)?, row.get(8)?)),
        )
        .optional()?;
    let Some((job, log)) = row else {
        return Ok(plain(StatusCode::NOT_FOUND, "Tâche introuvable\n"));
    };
    let mut html = String::from("<dl><dt>Type</dt><dd>");
    let redhat = job.job_type == media::REDHAT_JOB;
    escape(&mut html, if redhat { "DVD RHEL" } else { &job.job_type });
    html.push_str("</dd><dt>État</dt><dd>");
    status_badge(
        &mut html,
        &job.status,
        super::activity::status_label(&job.status),
    );
    if redhat {
        let active = matches!(job.status.as_str(), "pending" | "running");
        let poll = if active {
            format!(
                r#" data-rhel-job="/jobs/{id}/status" data-rhel-state="{}""#,
                job.status
            )
        } else {
            String::new()
        };
        write!(html, r#"</dd></dl><div{poll}><p role="status">"#)?;
        escape(&mut html, job.message.as_deref().unwrap_or_default());
        write!(
            html,
            r#"</p><div class="image-progress"><progress aria-label="Progression de la préparation" max="100" value="{0}"></progress><span>{0} %</span></div></div>"#,
            job.progress_percent
        )?;
        if job.status == "failed" {
            write!(
                html,
                r#"<p><a href="{}">Relancer avec un jeton Red Hat</a></p>"#,
                media::REDHAT_ROUTE
            )?;
        }
    } else {
        write!(
            html,
            "</dd><dt>Progression</dt><dd>{} %</dd></dl><p>",
            job.progress_percent
        )?;
        escape(&mut html, job.message.as_deref().unwrap_or_default());
        html.push_str("</p>");
    }
    if !redhat || !log.is_empty() {
        html.push_str("<pre>");
        escape(&mut html, &log);
        html.push_str("</pre>");
    }
    if job.status == "failed" && !redhat {
        write!(
            html,
            r#"<form method="post" action="/api/init-retry-job/{id}"><button>Relancer la tâche</button></form>"#
        )?;
    }
    if fragment {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-store")
            .header(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'",
            )
            .body(bytes(html))?);
    }
    let (back, label) = if redhat {
        (media::REDHAT_ROUTE, "Télécharger RHEL")
    } else {
        ("/jobs", "Tâches")
    };
    write!(
        html,
        r#"<nav><a href="/jobs/{id}">Actualiser</a> · <a href="{back}">{label}</a></nav>"#
    )?;
    Ok(page(
        ConsoleSection::Jobs,
        &format!("{} #{id}", title(&job.job_type)),
        &html,
    ))
}
