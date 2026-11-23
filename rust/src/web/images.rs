// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    admin::escape,
    plain,
    setup::{page, redirect},
    ErrorBox, Reply,
};
use crate::connect;
use hyper::StatusCode;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{fmt::Write, path::Path};

pub(super) const ROUTE: &str = "/settings/images";
const PAGE_SIZE: u64 = 100;

pub(super) fn serve(db: &Connection, path: &Path, number: u32, form: Option<&[u8]>) -> Reply {
    let result = match form {
        Some(form) => update(path, form),
        None => list(db, number),
    };
    result.unwrap_or_else(|error| {
        eprintln!("Rust images: {error}");
        plain(StatusCode::SERVICE_UNAVAILABLE, "Images indisponibles\n")
    })
}

fn update(path: &Path, form: &[u8]) -> Result<Reply, ErrorBox> {
    let mut image = None;
    let mut refresh = false;
    for (name, value) in form_urlencoded::parse(form) {
        match name.as_ref() {
            "image" if image.is_none() => image = Some(value.parse::<i64>()),
            "action" if !refresh && value == "refresh" => refresh = true,
            _ => return Ok(plain(StatusCode::BAD_REQUEST, "Formulaire invalide\n")),
        }
    }
    let mut db = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if refresh {
        refresh_catalog(&tx)?;
    } else {
        let available = match image {
            Some(Ok(id)) if id > 0 => queue_image(&tx, id, false)?.is_some(),
            _ => false,
        };
        if !available {
            return Ok(plain(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Image Debian indisponible\n",
            ));
        }
    }
    tx.commit()?;
    Ok(redirect(StatusCode::SEE_OTHER, ROUTE))
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
    let mut html = String::from(r#"<p><a href="/admin/devices">Retour à la console</a></p>"#);
    html.push_str(&catalog_form(db, ROUTE)?);
    if let Some(status) = db
        .query_row(
            "SELECT status FROM init_jobs
         WHERE job_type IN ('bootstrap:refresh_catalog','bootstrap:refresh_catalog_v2')
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
    html.push_str("<table><thead><tr><th>Distribution</th><th>Version</th><th>Architecture</th><th>État</th><th>Progression</th><th>Activée</th></tr></thead><tbody>");
    let mut query = db.prepare(
        "SELECT distro, COALESCE(version_full,version), arch, status, progress_percent, enabled
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
        let active = if row.get::<_, bool>(5)? { "Oui" } else { "Non" };
        write!(html, "<td>{percent} %</td><td>{active}</td></tr>")?;
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
    Ok(page("Images PXE", &html))
}

pub(super) fn queue_image(db: &Connection, id: i64, resume: bool) -> rusqlite::Result<Option<i64>> {
    db.execute(
        "INSERT INTO os_images(distro,version,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,enabled,status)
                SELECT distro,version_full,version_full,arch,codename,major,channel,
                    kernel_url,initrd_url,firmware_url,iso_url,extract_method,1,'pending'
                FROM catalog_entries WHERE id=?1 AND distro='debian'
                    AND extract_method='direct' AND arch IN ('amd64','arm64')
                ON CONFLICT(distro,version_full,arch) WHERE version_full IS NOT NULL
                DO UPDATE SET enabled=1,
                    status=CASE WHEN os_images.status IN ('downloaded','downloading')
                                THEN os_images.status ELSE 'pending' END,
                    error_msg=CASE WHEN os_images.status IN ('downloaded','downloading')
                                   THEN os_images.error_msg ELSE NULL END
                WHERE os_images.extract_method='direct' AND ?2",
        rusqlite::params![id, resume],
    )?;
    db.query_row(
        "SELECT i.id FROM os_images i JOIN catalog_entries c
                     ON i.distro=c.distro AND i.version_full=c.version_full AND i.arch=c.arch
                  WHERE c.id=?1 AND c.distro='debian' AND c.extract_method='direct'
                    AND c.arch IN ('amd64','arm64') AND i.extract_method='direct'",
        [id],
        |row| row.get(0),
    )
    .optional()
}

pub(super) fn catalog_form(db: &Connection, action: &'static str) -> rusqlite::Result<String> {
    let mut html = format!(
        r#"<form method="post" action="{action}">
<label>Image Debian <select name="image">"#,
    );
    let mut query = db.prepare(
        "SELECT id,version_full,arch FROM catalog_entries
        WHERE distro='debian' AND extract_method='direct' AND arch IN ('amd64','arm64')
        ORDER BY major DESC,version_full DESC,arch,id LIMIT 50",
    )?;
    let mut rows = query.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        let id: i64 = row.get(0)?;
        html.push_str(&format!(r#"<option value="{id}">Debian "#));
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
