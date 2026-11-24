// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    bytes, plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::connect;
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
         WHERE id=?1 AND status='failed'
           AND NOT EXISTS (
             SELECT 1 FROM init_jobs AS active
             WHERE active.job_type=init_jobs.job_type AND active.status IN ('pending','running')
           )",
        [id],
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

fn list(db: &Connection, number: u32) -> Result<Reply, ErrorBox> {
    let mut statement =
        db.prepare("SELECT id,job_type,status FROM init_jobs ORDER BY id DESC LIMIT ?1 OFFSET ?2")?;
    let mut rows = statement.query([
        u64::from(PAGE_SIZE) + 1,
        u64::from(number - 1) * u64::from(PAGE_SIZE),
    ])?;
    let mut html =
        String::from("<table><thead><tr><th>Tâche</th><th>État</th></tr></thead><tbody>");
    for _ in 0..PAGE_SIZE {
        let Some(row) = rows.next()? else { break };
        let id: i64 = row.get(0)?;
        write!(html, "<tr><td><a href=\"/jobs/{id}\">")?;
        escape(&mut html, &row.get::<_, String>(1)?);
        html.push_str("</a></td><td>");
        escape(&mut html, &row.get::<_, String>(2)?);
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table><nav aria-label=\"Pagination\">");
    if number > 1 {
        write!(
            html,
            "<a href=\"/jobs?page={}\">Précédente</a> ",
            number - 1
        )?;
    }
    if rows.next()?.is_some() && number < u32::MAX {
        write!(html, "<a href=\"/jobs?page={}\">Suivante</a> ", number + 1)?;
    }
    html.push_str(r#"<a href="/admin/devices">Console</a></nav>"#);
    Ok(page("Tâches", &html))
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
    escape(&mut html, &job.job_type);
    html.push_str("</dd><dt>État</dt><dd>");
    escape(&mut html, &job.status);
    write!(
        html,
        "</dd><dt>Progression</dt><dd>{} %</dd></dl><p>",
        job.progress_percent
    )?;
    escape(&mut html, job.message.as_deref().unwrap_or_default());
    html.push_str("</p><pre>");
    escape(&mut html, &log);
    html.push_str("</pre>");
    if job.status == "failed" {
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
    write!(
        html,
        r#"<nav><a href="/jobs/{id}">Actualiser</a> · <a href="/jobs">Tâches</a></nav>"#
    )?;
    Ok(page(&format!("Tâche {id}"), &html))
}
