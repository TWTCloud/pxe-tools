// SPDX-License-Identifier: LGPL-3.0-only

use crate::pxe::{array_values, is_php_array};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

pub fn serial(value: &Value) -> Option<String> {
    let value = crate::php_trim(value.as_str()?).to_ascii_uppercase();
    (!matches!(
        value.as_str(),
        "" | "0" | "UNKNOWN" | "N/A" | "NA" | "NONE" | "NULL" | "NOT AVAILABLE" | "DEFAULT"
    ))
    .then_some(value)
}

pub fn valid_wwid(value: &str) -> bool {
    value.strip_prefix("NAA.").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            && suffix != "00000000000000000000000000000000"
    })
}

fn identity(disk: &Value) -> Option<(&'static str, String, String)> {
    let identity = &disk["identity"];
    let kind = identity
        .get("kind")
        .filter(|v| !v.is_null())
        .map(crate::php_string);
    match kind.as_deref().unwrap_or("serial") {
        "serial" => {
            let observed = &disk["serial"];
            let value = serial(
                identity
                    .get("value")
                    .filter(|v| !v.is_null())
                    .unwrap_or(observed),
            )?;
            let default_source = if crate::php_truthy(observed) {
                "legacy"
            } else {
                "unknown"
            };
            let source = identity
                .get("source")
                .filter(|v| !v.is_null())
                .map(crate::php_string)
                .unwrap_or_else(|| default_source.to_owned());
            Some(("serial", value, source))
        }
        "wwid"
            if identity["source"] == "sysfs-wwid"
                && crate::php_trim(&crate::php_string(&disk["vendor"])) == "Msft"
                && crate::php_trim(&crate::php_string(&disk["model"])) == "Virtual Disk" =>
        {
            let value = serial(&identity["value"])?;
            valid_wwid(&value).then_some(("wwid", value, "sysfs-wwid".to_owned()))
        }
        _ => None,
    }
}

pub fn normalize_inventory(disks: &Value) -> Vec<Value> {
    let disks: Vec<_> = array_values(disks)
        .filter(|disk| is_php_array(disk))
        .map(|disk| (disk, identity(disk)))
        .collect();
    let mut counts = HashMap::new();
    for (_, identity) in &disks {
        if let Some((_, value, _)) = identity {
            *counts.entry(value.clone()).or_insert(0) += 1;
        }
    }
    disks
        .into_iter()
        .map(|(disk, identity)| {
            let (kind, value, source, status) = match identity {
                Some((kind, value, source)) => {
                    let status = if counts[&value] > 1 {
                        "ambiguous"
                    } else {
                        "valid"
                    };
                    (kind, value, source, status)
                }
                None => ("serial", String::new(), "none".to_owned(), "missing"),
            };
            let mut data = match disk {
                Value::Object(map) => map.clone(),
                Value::Array(items) => items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index.to_string(), item.clone()))
                    .collect(),
                _ => unreachable!(),
            };
            data.remove("_normalized_identity");
            data.insert(
                "identity".to_owned(),
                json!({"kind":kind, "value":value, "source":source, "status":status}),
            );
            data.extend(storage_metadata(disk));
            Value::Object(data)
        })
        .collect()
}

fn storage_metadata(disk: &Value) -> Map<String, Value> {
    let partitions: Vec<_> = array_values(&disk["partitions"])
        .filter(|partition| is_php_array(partition))
        .map(|partition| {
            let mut values = filesystem(partition);
            values.extend([
                ("name".into(), json!(metadata_text(&partition["name"]))),
                ("path".into(), json!(metadata_text(&partition["path"]))),
                (
                    "number".into(),
                    json!(nonnegative(&partition["number"]).filter(|n| *n > 0)),
                ),
                (
                    "size_bytes".into(),
                    json!(nonnegative(&partition["size_bytes"])),
                ),
            ]);
            values
        })
        .collect();
    let name = disk["name"].as_str().unwrap_or_default();
    let name = name.strip_prefix("/dev/").unwrap_or(name);
    let native_mmc = numbered(name, "mmcblk");
    let mmc = if native_mmc && is_php_array(&disk["mmc"]) {
        Some(mmc_metadata(name, &disk["mmc"]))
    } else {
        None
    };
    let collection = is_php_array(&disk["metadata_collection"]).then(|| {
        let raw = &disk["metadata_collection"];
        let fs_status = match raw["filesystem_status"].as_str() {
            Some("available")
                if is_php_array(&disk["partitions"]) && is_php_array(&disk["filesystem"]) =>
            {
                "available"
            }
            Some("error") => "error",
            _ => "unavailable",
        };
        let mmc_status = match (native_mmc, mmc.is_some(), raw["mmc_status"].as_str()) {
            (false, _, _) => "not_applicable",
            (true, true, Some("available")) => "available",
            _ => "unavailable",
        };
        json!({"filesystem_status": fs_status, "mmc_status": mmc_status})
    });
    Map::from_iter([
        ("mmc".into(), json!(mmc)),
        ("partitions".into(), json!(partitions)),
        (
            "filesystem".into(),
            Value::Object(filesystem(&disk["filesystem"])),
        ),
        ("metadata_collection".into(), json!(collection)),
    ])
}

fn mmc_metadata(base: &str, raw: &Value) -> Map<String, Value> {
    let mut info: Map<_, _> = [
        "type",
        "name",
        "cid",
        "csd",
        "manfid",
        "oemid",
        "date",
        "fwrev",
        "life_time",
        "pre_eol_info",
    ]
    .into_iter()
    .map(|key| {
        let text = metadata_text(&raw[key]).filter(|s| {
            !matches!(key, "cid" | "csd")
                || (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        });
        (key.to_owned(), json!(text))
    })
    .collect();
    let expected_parent = format!("/dev/{base}");
    let regions: Vec<_> = array_values(&raw["hardware_regions"])
        .filter_map(|region| {
            let name = metadata_text(&region["name"])?;
            let path = metadata_text(&region["path"])?;
            let parent = metadata_text(&region["parent_path"]);
            if path != format!("/dev/{name}")
                || region.get("parent_path").is_some_and(|v| !v.is_null())
                    && parent != Some(&expected_parent)
            {
                return None;
            }
            let associated = name.strip_prefix(base).is_some_and(|suffix| {
                matches!(suffix, "boot0" | "boot1" | "rpmb") || numbered(suffix, "gp")
            });
            let independent = numbered(name, "rpmb")
                || name
                    .strip_suffix("rpmb")
                    .is_some_and(|name| numbered(name, "mmcblk"));
            if !(associated || independent && parent == Some(&expected_parent)) {
                return None;
            }
            Some(json!({
                "name": name, "path": path, "parent_path": parent,
                "size_bytes": nonnegative(&region["size_bytes"]),
                "force_ro": nonnegative(&region["force_ro"]).filter(|n| *n <= 1),
                "protected": true
            }))
        })
        .collect();
    info.insert("hardware_regions".into(), json!(regions));
    info
}

fn numbered(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

fn metadata_text(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| !crate::php_trim(s).is_empty())
}

fn nonnegative(value: &Value) -> Option<i64> {
    value.as_i64().filter(|n| *n >= 0).or_else(|| {
        let raw = value.as_str()?;
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits = raw.trim_start_matches('0');
        if digits.is_empty() {
            Some(0)
        } else {
            digits.parse().ok()
        }
    })
}

fn filesystem(value: &Value) -> Map<String, Value> {
    ["fstype", "uuid", "partuuid", "label"]
        .into_iter()
        .map(|name| (name.to_owned(), json!(metadata_text(&value[name]))))
        .collect()
}
