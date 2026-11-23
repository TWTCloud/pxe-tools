// SPDX-License-Identifier: LGPL-3.0-only

use rusqlite::{Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const WINDOW_SECONDS: i64 = 86_400;
const LATEST: &str = "SELECT a.id, a.machine_id, a.type, a.status,
        unixepoch(a.created_at), unixepoch(a.ended_at),
        unixepoch((SELECT MAX(e.created_at) FROM machine_events e WHERE e.action_id = a.id)),
        m.hostname, m.inventory_json
    FROM actions a JOIN machines m ON m.id = a.machine_id
    WHERE a.type IN ('reinstall', 'install_only', 'wipe_only', 'disktest')
      AND a.id = (SELECT MAX(b.id) FROM actions b
                  WHERE b.machine_id = a.machine_id
                  AND b.type IN ('reinstall', 'install_only', 'wipe_only', 'disktest'))
    ORDER BY a.machine_id";

#[derive(Deserialize)]
pub struct Checkpoint {
    code: String,
    label: String,
}

impl Checkpoint {
    pub fn has_code(&self, code: &str) -> bool {
        self.code == code
    }
}

pub type Catalog = HashMap<String, Vec<Checkpoint>>;

#[derive(Serialize)]
pub struct Snapshot {
    generated_at: i64,
    installs: Vec<Install>,
}

#[derive(Serialize)]
struct Install {
    machine_id: i64,
    label: String,
    action_id: i64,
    #[serde(rename = "type")]
    kind: String,
    status: String,
    phase: String,
    steps_done: usize,
    steps_total: usize,
    pct: usize,
    started_at: i64,
    last_event_at: i64,
    ended_at: i64,
}

pub fn snapshot(db: &mut Connection, catalog: &Catalog, now: i64) -> rusqlite::Result<Snapshot> {
    let transaction = db.transaction()?;
    let mut latest = transaction.prepare(LATEST)?;
    let mut rows = latest.query([])?;
    let mut checkpoints = transaction.prepare(
        "SELECT DISTINCT checkpoint FROM machine_events WHERE action_id = ? AND checkpoint IS NOT NULL",
    )?;
    let mut installs = Vec::new();
    while let Some(row) = rows.next()? {
        let action_id = row.get(0)?;
        let machine_id = row.get(1)?;
        let kind: String = row.get(2)?;
        let status = text(row, 3)?;
        let started_at = epoch(row, 4)?;
        let ended_at = epoch(row, 5)?;
        let mut last_event_at = epoch(row, 6)?.max(0);
        let mut disk_pct = None;
        if kind == "disktest" {
            let (last_update, pct) = disk_progress(&transaction, action_id)?;
            last_event_at = last_event_at.max(last_update);
            if matches!(status.as_str(), "pending" | "running") {
                disk_pct = pct;
            }
        }
        let reference = [ended_at, last_event_at, started_at]
            .into_iter()
            .find(|time| *time != 0)
            .unwrap_or(0);
        if now - reference > WINDOW_SECONDS {
            continue;
        }

        let seen = checkpoints
            .query_map([action_id], |row| text(row, 0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        let steps = catalog.get(&kind).map(Vec::as_slice).unwrap_or_default();
        let mut steps_done: usize = 0;
        let mut phase = String::new();
        for step in steps {
            if seen.contains(&step.code) {
                steps_done += 1;
                phase.clone_from(&step.label);
            }
        }
        let steps_total = steps.len();
        let pct = if status == "success" {
            100
        } else {
            disk_pct.unwrap_or_else(|| (100 * steps_done).checked_div(steps_total).unwrap_or(0))
        };
        installs.push(Install {
            machine_id,
            label: machine_label(machine_id, &text(row, 7)?, &text(row, 8)?),
            action_id,
            kind,
            status,
            phase,
            steps_done,
            steps_total,
            pct,
            started_at,
            last_event_at,
            ended_at,
        });
    }
    Ok(Snapshot {
        generated_at: now,
        installs,
    })
}

fn epoch(row: &Row<'_>, index: usize) -> rusqlite::Result<i64> {
    Ok(row.get::<_, Option<i64>>(index)?.unwrap_or_default())
}

fn text(row: &Row<'_>, index: usize) -> rusqlite::Result<String> {
    use rusqlite::types::ValueRef;
    Ok(match row.get_ref(index)? {
        ValueRef::Null => String::new(),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            String::from_utf8_lossy(bytes).into_owned()
        }
        ValueRef::Integer(number) => number.to_string(),
        ValueRef::Real(number) => number.to_string(),
    })
}

fn machine_label(machine_id: i64, hostname: &str, inventory: &str) -> String {
    let hostname = super::php_trim(hostname);
    if !hostname.is_empty() {
        return hostname.to_owned();
    }
    let inventory: Value = serde_json::from_str(inventory).unwrap_or_default();
    let hardware = &inventory["inventory"];
    let parts: Vec<_> = [&hardware["vendor"], &hardware["product"]]
        .into_iter()
        .map(super::php_string)
        .map(|value| super::php_trim(&value).to_owned())
        .filter(|value| !value.is_empty() && value != "n/a")
        .collect();
    if parts.is_empty() {
        format!("machine-{machine_id}")
    } else {
        parts.join(" ")
    }
}

fn disk_progress(db: &Connection, action_id: i64) -> rusqlite::Result<(i64, Option<usize>)> {
    let raw = db
        .query_row(
            "SELECT progress_json FROM disk_tests WHERE action_id = ? ORDER BY id DESC LIMIT 1",
            [action_id],
            |row| text(row, 0),
        )
        .optional()?
        .unwrap_or_default();
    let progress: Value = serde_json::from_str(&raw).unwrap_or_default();
    let disks: Vec<_> = match &progress {
        Value::Object(disks) => disks.values().collect(),
        Value::Array(disks) => disks.iter().collect(),
        _ => Vec::new(),
    };
    let mut last_update = 0;
    let mut total = 0.0;
    let mut count = 0;
    let mut timestamp = db.prepare_cached("SELECT unixepoch(?)")?;
    for disk in disks {
        if let Some(updated_at) = disk["updated_at"].as_str() {
            // The agent stores date('c'), including the offset.
            let updated = timestamp.query_row([updated_at], |row| epoch(row, 0))?;
            last_update = last_update.max(updated);
        }
        let pct = &disk["pct"];
        let numeric = pct.as_f64().or_else(|| pct.as_str()?.trim().parse().ok());
        if let Some(pct) = numeric.filter(|value| value.is_finite()) {
            total += pct;
            count += 1;
        }
    }
    let pct = (count > 0).then(|| (total / f64::from(count)).round().clamp(0.0, 100.0) as usize);
    Ok((last_update, pct))
}
