// SPDX-License-Identifier: LGPL-3.0-only

use super::{admin::escape, bytes, plain, setup::page, ErrorBox, Reply};
use hyper::{Response, StatusCode};
use rusqlite::{params, Connection, OptionalExtension};
use std::{
    fmt::Write,
    hash::{DefaultHasher, Hash, Hasher},
};

const PAGE_SIZE: i64 = 30;
const TYPES: &[(&str, &str)] = &[
    ("", "Tous les types"),
    ("install", "Installation"),
    ("discovery", "Inventaire"),
    ("wipe", "Effacement"),
    ("disktest", "Test disque"),
    ("job", "Tâche de l’appliance"),
];
const STATUSES: &[(&str, &str)] = &[
    ("", "Tous les états"),
    ("pending", "En attente"),
    ("running", "En cours"),
    ("success", "Réussie"),
    ("failed", "Échec"),
    ("cancelled", "Annulée"),
    ("skipped", "Ignorée"),
    ("aborted", "Interrompue"),
];

const ACTIVITY: &str = "
WITH activity(id,source,kind,status,machine_id,target,author,updated_at,message) AS (
 SELECT a.id,'action',a.type,a.status,a.machine_id,COALESCE(m.hostname,m.mac),a.created_by,
        COALESCE(a.ended_at,(SELECT MAX(e.created_at) FROM machine_events e WHERE e.action_id=a.id),a.created_at),
        (SELECT e.message FROM machine_events e WHERE e.action_id=a.id ORDER BY e.id DESC LIMIT 1)
 FROM actions a JOIN machines m ON m.id=a.machine_id
 UNION ALL
 SELECT id,'job',job_type,status,NULL,'Appliance',NULL,
        COALESCE(updated_at,ended_at,created_at),message FROM init_jobs
 UNION ALL
 SELECT i.id,'installation','install',CASE i.install_status WHEN 'in_progress' THEN 'running'
        ELSE COALESCE(i.install_status,'pending') END,i.machine_id,COALESCE(m.hostname,m.mac),NULL,
        COALESCE(i.ended_at,i.started_at,i.created_at),NULL
 FROM installations i JOIN machines m ON m.id=i.machine_id WHERE i.action_id IS NULL
 UNION ALL
 SELECT w.id,'wipe','wipe',w.wipe_status,w.machine_id,COALESCE(m.hostname,m.mac),NULL,
        COALESCE(w.ended_at,w.started_at,w.created_at),NULL
 FROM wipes w JOIN machines m ON m.id=w.machine_id WHERE w.action_id IS NULL
 UNION ALL
 SELECT d.id,'disktest','disktest',d.job_status,d.machine_id,COALESCE(m.hostname,m.mac),NULL,
        COALESCE(d.ended_at,d.started_at,d.created_at),NULL
 FROM disk_tests d JOIN machines m ON m.id=d.machine_id WHERE d.action_id IS NULL
)
SELECT * FROM activity
WHERE (?1='' OR status=?1)
  AND (?2='' OR (?2='job' AND source='job') OR (?2='install' AND kind IN ('install','install_only','reinstall'))
       OR (?2='wipe' AND kind IN ('wipe','wipe_only')) OR kind=?2)
  AND (?3=0 OR machine_id=?3)
  AND (?4='' OR target LIKE ?4 ESCAPE '!' OR author LIKE ?4 ESCAPE '!' OR message LIKE ?4 ESCAPE '!')
ORDER BY updated_at DESC,source,id DESC LIMIT ?5 OFFSET ?6";

pub(super) enum View {
    List,
    Fragment,
    Task(i64),
    Installation(i64),
    Wipe(i64),
    DiskTest(i64),
}

impl View {
    pub(super) fn for_route(path: &str) -> Option<Self> {
        match path {
            "/activity" | "/installations" => return Some(Self::List),
            "/activity/list" => return Some(Self::Fragment),
            _ => {}
        }
        let (section, id) = path.strip_prefix('/')?.split_once('/')?;
        let id = id.parse().ok().filter(|id| *id > 0)?;
        match section {
            "tasks" => Some(Self::Task(id)),
            "installations" => Some(Self::Installation(id)),
            "wipes" => Some(Self::Wipe(id)),
            "disktests" => Some(Self::DiskTest(id)),
            _ => None,
        }
    }

    pub(super) fn serve(
        &self,
        db: &Connection,
        path: &str,
        query: &str,
        number: u32,
    ) -> Result<Reply, ErrorBox> {
        match self {
            Self::List | Self::Fragment => {
                let mut filter = Filter::parse(query);
                if path == "/installations" {
                    filter.kind = "install".to_owned();
                }
                list(db, &filter, number, matches!(self, Self::Fragment))
            }
            Self::Task(id) => task(db, *id),
            Self::Installation(id) => operation(
                db,
                *id,
                "installations",
                "install_status",
                "install_log",
                "Installation",
            ),
            Self::Wipe(id) => operation(db, *id, "wipes", "wipe_status", "log", "Effacement"),
            Self::DiskTest(id) => {
                operation(db, *id, "disk_tests", "job_status", "log", "Test disque")
            }
        }
    }
}

#[derive(Default)]
struct Filter {
    search: String,
    status: String,
    kind: String,
    machine: i64,
    signature: String,
}

impl Filter {
    fn parse(query: &str) -> Self {
        let mut filter = Self::default();
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            match name.as_ref() {
                "q" => filter.search = value.trim().chars().take(120).collect(),
                "status" if STATUSES.iter().any(|(key, _)| *key == value) => {
                    filter.status = value.into_owned()
                }
                "type" if TYPES.iter().any(|(key, _)| *key == value) => {
                    filter.kind = value.into_owned()
                }
                "machine" => filter.machine = value.parse::<i64>().unwrap_or_default().max(0),
                "sig" if value.len() == 16 => filter.signature = value.into_owned(),
                _ => {}
            }
        }
        filter
    }

    fn link(&self, number: u32) -> String {
        let machine = self.machine.to_string();
        let number = number.to_string();
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("q", self.search.as_str()),
                ("status", &self.status),
                ("type", &self.kind),
                ("machine", &machine),
                ("page", &number),
            ])
            .finish()
    }
}

fn label<'a>(values: &[(&str, &'a str)], key: &'a str) -> &'a str {
    values
        .iter()
        .find(|(value, _)| *value == key)
        .map_or(key, |(_, label)| *label)
}

fn list(db: &Connection, filter: &Filter, number: u32, fragment: bool) -> Result<Reply, ErrorBox> {
    let term = if filter.search.is_empty() {
        String::new()
    } else {
        format!(
            "%{}%",
            filter
                .search
                .replace('!', "!!")
                .replace('%', "!%")
                .replace('_', "!_")
        )
    };
    let mut stmt = db.prepare(ACTIVITY)?;
    let mut rows = stmt.query(params![
        filter.status,
        filter.kind,
        filter.machine,
        term,
        PAGE_SIZE + 1,
        i64::from(number - 1) * PAGE_SIZE
    ])?;
    let mut output = String::from("<table><thead><tr><th>Opération</th><th>Cible et auteur</th><th>État</th><th>Dernière activité (UTC)</th></tr></thead><tbody>");
    for _ in 0..PAGE_SIZE {
        let Some(row) = rows.next()? else { break };
        let id: i64 = row.get(0)?;
        let source: String = row.get(1)?;
        let kind: String = row.get(2)?;
        let state: String = row.get(3)?;
        let target: String = row.get(5)?;
        let author: Option<String> = row.get(6)?;
        let updated: Option<String> = row.get(7)?;
        let message: Option<String> = row.get(8)?;
        let route = match source.as_str() {
            "action" => "/tasks",
            "job" => "/jobs",
            "installation" => "/installations",
            "wipe" => "/wipes",
            _ => "/disktests",
        };
        write!(output, "<tr><td><a href=\"{route}/{id}\">")?;
        escape(
            &mut output,
            match kind.as_str() {
                "install_only" | "reinstall" => "Installation",
                "wipe_only" => "Effacement",
                _ => label(TYPES, &kind),
            },
        );
        write!(output, " #{id}</a></td><td>")?;
        escape(&mut output, &target);
        if let Some(author) = author.filter(|value| !value.is_empty()) {
            output.push_str(" · ");
            escape(&mut output, &author);
        }
        output.push_str("</td><td>");
        escape(&mut output, label(STATUSES, &state));
        if let Some(message) = message.filter(|value| !value.is_empty()) {
            output.push_str("<br>");
            escape(&mut output, &message);
        }
        output.push_str("</td><td>");
        escape(&mut output, updated.as_deref().unwrap_or_default());
        output.push_str("</td></tr>");
    }
    let has_next = rows.next()?.is_some() && number < u32::MAX;
    output.push_str("</tbody></table><nav aria-label=\"Pages de l’activité\">");
    for (allowed, target, caption) in [
        (number > 1, number.saturating_sub(1), "Précédente"),
        (has_next, number.saturating_add(1), "Suivante"),
    ] {
        if allowed {
            output.push_str("<a href=\"/activity?");
            escape(&mut output, &filter.link(target));
            write!(output, "\">{caption}</a> ")?;
        }
    }
    output.push_str("</nav>");
    let mut hash = DefaultHasher::new();
    output.hash(&mut hash);
    let signature = format!("{:016x}", hash.finish());
    let section =
        format!("<section id=\"activity-list\" data-sig=\"{signature}\">{output}</section>");
    if fragment {
        if filter.signature == signature {
            return Ok(plain(StatusCode::NO_CONTENT, ""));
        }
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Cache-Control", "no-store")
            .body(bytes(section))?);
    }
    let mut form = String::from("<nav><a href=\"/admin/devices\">Appareils</a> · <a href=\"/installations\">Installations</a></nav><form method=\"get\" action=\"/activity\"><label>Rechercher <input name=\"q\" type=\"search\" maxlength=\"120\" value=\"");
    escape(&mut form, &filter.search);
    form.push_str("\"></label> ");
    for (name, title, values, selection) in [
        ("type", "Type", TYPES, &filter.kind),
        ("status", "État", STATUSES, &filter.status),
    ] {
        write!(form, "<label>{title} <select name=\"{name}\">")?;
        for (value, caption) in values {
            let selected = if selection == value { " selected" } else { "" };
            write!(
                form,
                "<option value=\"{value}\"{selected}>{caption}</option>"
            )?;
        }
        form.push_str("</select></label> ");
    }
    write!(form, "<input type=\"hidden\" name=\"machine\" value=\"{}\"><button>Filtrer</button> <a href=\"/activity\">Réinitialiser</a></form>{section}", filter.machine)?;
    Ok(page("Activité", &form))
}

fn task(db: &Connection, id: i64) -> Result<Reply, ErrorBox> {
    let Some((target, kind, state)) = db.query_row(
        "SELECT COALESCE(m.hostname,m.mac),a.type,a.status FROM actions a JOIN machines m ON m.id=a.machine_id WHERE a.id=?",
        [id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
    ).optional()? else {
        return Ok(plain(StatusCode::NOT_FOUND, "Tâche introuvable\n"));
    };
    let mut output = String::from("<p>");
    escape(&mut output, &target);
    output.push_str(" · ");
    escape(&mut output, &kind);
    output.push_str(" · ");
    escape(&mut output, label(STATUSES, &state));
    output.push_str("</p><ul>");
    let mut statement = db.prepare("SELECT created_at,message FROM machine_events WHERE action_id=? ORDER BY id DESC LIMIT 100")?;
    let mut rows = statement.query([id])?;
    while let Some(row) = rows.next()? {
        output.push_str("<li><time>");
        escape(&mut output, &row.get::<_, String>(0)?);
        output.push_str("</time> ");
        escape(&mut output, &row.get::<_, String>(1)?);
        output.push_str("</li>");
    }
    output.push_str("</ul><a href=\"/activity\">Activité</a>");
    Ok(page("Suivi de la tâche", &output))
}

fn operation(
    db: &Connection,
    id: i64,
    table: &str,
    state: &str,
    log: &str,
    title: &str,
) -> Result<Reply, ErrorBox> {
    // The route controls the three identifiers, and only the row ID is user input.
    let Some((target, state, log)) = db
        .query_row(
            &format!(
                "SELECT COALESCE(m.hostname,m.mac),COALESCE(o.{state},'pending'),
                         COALESCE(substr(o.{log},-65536),'')
                  FROM {table} o JOIN machines m ON m.id=o.machine_id WHERE o.id=?"
            ),
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(plain(StatusCode::NOT_FOUND, "Opération introuvable\n"));
    };
    let mut output = String::from("<p>");
    escape(&mut output, &target);
    output.push_str(" · ");
    escape(&mut output, label(STATUSES, &state));
    output.push_str("</p><pre>");
    escape(&mut output, &log);
    output.push_str("</pre><a href=\"/activity\">Activité</a>");
    Ok(page(title, &output))
}
