// SPDX-License-Identifier: LGPL-3.0-only

use crate::{disk_identity::serial, pxe::is_php_array};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

#[derive(PartialEq, Eq)]
pub(super) enum Qualification {
    Accepted,
    Rejected,
    Incomplete,
}

pub(super) fn check(
    db: &Connection,
    test: i64,
    id: &str,
    mode: &str,
) -> rusqlite::Result<Qualification> {
    let mut query = db.prepare_cached(
        "SELECT smart_json FROM disk_smart_snapshots WHERE test_id=?1 AND serial=?2 AND phase=?3
         ORDER BY created_at DESC,id DESC LIMIT 1",
    )?;
    let mut snapshot = |phase| -> rusqlite::Result<Value> {
        let raw: Option<String> = query
            .query_row(params![test, id, phase], |row| row.get(0))
            .optional()?;
        Ok(raw
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default())
    };
    Ok(assess(id, mode, &snapshot("before")?, &snapshot("after")?)
        .unwrap_or(Qualification::Incomplete))
}

fn assess(id: &str, mode: &str, before: &Value, after: &Value) -> Option<Qualification> {
    if serial(&before["serial_number"]).as_deref() != Some(id)
        || serial(&after["serial_number"]).as_deref() != Some(id)
        || !is_php_array(&after["nvme_smart_health_information_log"])
            && after["rotation_rate"].as_u64().is_none()
    {
        return None;
    }
    let before = Summary::read(before)?;
    let after = Summary::read(after)?;
    let recent_unreadable_sector = after.hours > 0.0
        && after
            .last_unreadable_sector
            .is_some_and(|reported| after.hours - reported <= 1_000.0);
    let low_spare = after
        .spare
        .zip(after.spare_threshold)
        .is_some_and(|(spare, threshold)| spare <= threshold);
    // The installation policy accepts grades A through C, and blocks grade D
    // and unreadable evidence. Test completion has already been verified.
    if !after.passed
        || !mode.starts_with("smart_") && after.last_selftest_passed == Some(false)
        || after.reallocated > before.reallocated
        || after.reallocated > 100.0
        || after.pending > 0.0
        || after.uncorrectable > 0.0
        || after.reported_uncorrectable > before.reported_uncorrectable
        || after.ata_error_count > before.ata_error_count
        || recent_unreadable_sector
        || after.critical_warning > 0.0
        || after.media_errors > before.media_errors
        || low_spare
    {
        Some(Qualification::Rejected)
    } else {
        Some(Qualification::Accepted)
    }
}

struct Summary {
    passed: bool,
    hours: f64,
    reallocated: f64,
    pending: f64,
    uncorrectable: f64,
    reported_uncorrectable: f64,
    ata_error_count: f64,
    last_unreadable_sector: Option<f64>,
    last_selftest_passed: Option<bool>,
    critical_warning: f64,
    spare: Option<f64>,
    spare_threshold: Option<f64>,
    media_errors: f64,
}

impl Summary {
    fn read(data: &Value) -> Option<Self> {
        let mut summary = Self {
            passed: data["smart_status"]["passed"].as_bool()?,
            hours: counter(&section(data, "power_on_time")?["hours"])?.unwrap_or_default(),
            reallocated: 0.0,
            pending: 0.0,
            uncorrectable: 0.0,
            reported_uncorrectable: 0.0,
            ata_error_count: 0.0,
            last_unreadable_sector: None,
            last_selftest_passed: None,
            critical_warning: 0.0,
            spare: None,
            spare_threshold: None,
            media_errors: 0.0,
        };
        number(&section(data, "temperature")?["current"])?;
        let attributes = rows(section(data, "ata_smart_attributes")?)?;
        for row in attributes {
            let id = row["id"].as_i64()?;
            if matches!(id, 5 | 10 | 187 | 188 | 194 | 196 | 197 | 198 | 199) {
                let raw = &section(row, "raw")?["value"];
                let count = if id == 194 {
                    number(raw)?
                } else {
                    counter(raw)?
                };
                let count = count.unwrap_or_default();
                match id {
                    5 => summary.reallocated = count,
                    187 => summary.reported_uncorrectable = count,
                    197 => summary.pending = count,
                    198 => summary.uncorrectable = count,
                    _ => {}
                }
            }
        }
        for id in [231, 233, 202, 169, 177] {
            if let Some(attribute) = attributes.iter().find(|row| row["id"] == id) {
                counter(&attribute["value"])?;
                break;
            }
        }
        let errors = section(data, "ata_smart_error_log")?;
        let primary = section(errors, "summary")?;
        let extended = section(errors, "extended")?;
        let counts = if has_entries(primary) {
            primary
        } else {
            extended
        };
        summary.ata_error_count = counter(&counts["count"])?.unwrap_or_default();
        for entry in rows(extended)? {
            let description = optional_string(&entry["error_description"])?.unwrap_or_default();
            let hours = counter(&entry["lifetime_hours"])?.unwrap_or_default();
            if let Some((_, kind)) = description.split_once("Error: ") {
                let kind = kind
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next();
                if matches!(kind, Some("UNC" | "WP")) {
                    summary.last_unreadable_sector = Some(
                        summary
                            .last_unreadable_sector
                            .unwrap_or_default()
                            .max(hours),
                    );
                }
            }
        }
        let tests = section(data, "ata_smart_self_test_log")?;
        let extended = section(tests, "extended")?;
        let log = if has_entries(extended) {
            extended
        } else {
            section(tests, "standard")?
        };
        counter(&log["count"])?;
        let tests = rows(log)?;
        for entry in tests.iter().take(3) {
            optional_string(&section(entry, "type")?["string"])?;
            optional_string(&section(entry, "status")?["string"])?;
            counter(&entry["lifetime_hours"])?;
        }
        if let Some(entry) = tests.first() {
            let passed = &section(entry, "status")?["passed"];
            if !passed.is_null() {
                summary.last_selftest_passed = Some(passed.as_bool()?);
            }
        }
        let health = section(data, "nvme_smart_health_information_log")?;
        if has_entries(health) {
            summary.critical_warning = counter(&health["critical_warning"])?.unwrap_or_default();
            summary.media_errors = counter(&health["media_errors"])?.unwrap_or_default();
            summary.spare = counter(&health["available_spare"])?;
            summary.spare_threshold = counter(&health["available_spare_threshold"])?;
            for field in [
                "percentage_used",
                "num_err_log_entries",
                "unsafe_shutdowns",
                "data_units_written",
            ] {
                counter(&health[field])?;
            }
            if let Some(hours) = health.get("power_on_hours") {
                summary.hours = counter(hours)?.unwrap_or_default();
            }
            number(&health["temperature"])?;
            let tests = rows(section(data, "nvme_self_test_log")?)?;
            for entry in tests.iter().take(3) {
                optional_string(&section(entry, "self_test_code")?["string"])?;
                optional_string(&section(entry, "self_test_result")?["string"])?;
                counter(&entry["power_on_hours"])?;
            }
            if let Some(entry) = tests.first() {
                summary.last_selftest_passed =
                    Some(counter(&section(entry, "self_test_result")?["value"])? == Some(0.0));
            }
        }
        Some(summary)
    }
}

fn section<'a>(data: &'a Value, name: &str) -> Option<&'a Value> {
    let value = &data[name];
    (value.is_null() || is_php_array(value)).then_some(value)
}

fn rows(log: &Value) -> Option<&[Value]> {
    let table = section(log, "table")?;
    if !has_entries(table) {
        return Some(&[]);
    }
    let values = table.as_array()?;
    values.iter().all(is_php_array).then_some(values)
}

fn has_entries(value: &Value) -> bool {
    value.as_array().is_some_and(|items| !items.is_empty())
        || value.as_object().is_some_and(|items| !items.is_empty())
}

fn optional_string(value: &Value) -> Option<Option<&str>> {
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(value.as_str()?))
    }
}

fn number(value: &Value) -> Option<Option<f64>> {
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(value.as_f64()?))
    }
}

fn counter(value: &Value) -> Option<Option<f64>> {
    let count = number(value)?;
    if count.is_some_and(|n| n < 0.0) {
        None
    } else {
        Some(count)
    }
}
