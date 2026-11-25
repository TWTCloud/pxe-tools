// SPDX-License-Identifier: LGPL-3.0-only

use super::{bytes, ErrorBox, Reply};
use crate::{
    disk_identity::normalize_inventory,
    php_string, php_trim,
    pxe::{array_values, is_php_array, normalize_mac},
};
use hyper::{Response, StatusCode};
use serde_json::{json, Map, Value};

pub(super) fn serve(machine: Option<(&str, &Value)>) -> Result<Reply, ErrorBox> {
    let (status, value) = match machine {
        None => (StatusCode::NOT_FOUND, json!({"error":"machine not found"})),
        Some((mac, inventory)) => (StatusCode::OK, context(mac, inventory)),
    };
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(bytes(serde_json::to_vec(&value)?))?)
}

fn context(machine_mac: &str, inventory: &Value) -> Value {
    let hardware = &inventory["inventory"];
    let mut capacities = Map::new();
    let reported: Vec<_> = array_values(&inventory["disks"])
        .filter(|disk| is_php_array(disk))
        .collect();
    for disk in &reported {
        let name = php_string(&disk["name"]);
        if let Some(size) = crate::migrations::integer(&disk["size_bytes"]).filter(|size| *size > 0)
        {
            if !name.is_empty() {
                let path = if name.starts_with("/dev/") {
                    name
                } else {
                    format!("/dev/{}", name.trim_start_matches('/'))
                };
                capacities.insert(path, json!(size / 1_000_000));
            }
        }
    }
    let disks: Vec<_> = reported
        .into_iter()
        .zip(normalize_inventory(&inventory["disks"]))
        .filter_map(|(raw, normalized)| {
            let name = php_string(&raw["name"]);
            if name.is_empty() {
                return None;
            }
            let mut identity = normalized["identity"].clone();
            let identity_status = match identity["status"].as_str() {
                Some("missing") | None => {
                    identity = Value::Null;
                    "missing"
                }
                Some("ambiguous") => "ambiguous",
                _ if is_php_array(&raw["identity"]) => "valid",
                _ => "legacy",
            };
            if !identity.is_null() {
                identity["status"] = json!(raw["identity"]["status"].as_str().unwrap_or("valid"));
            }
            let source = raw["identity"]["source"].as_str().unwrap_or_else(|| {
                if crate::php_truthy(&raw["serial"]) {
                    "legacy"
                } else {
                    "unknown"
                }
            });
            let size = capacities.get(&name);
            Some(json!({
                "name":name,"size_bytes":integer_field(raw,"size_bytes"),"size_mb":size,
                "is_ssd":(!raw["rota"].is_null()).then(|| raw["rota"] == false),
                "vendor":php_string(&raw["vendor"]),"model":php_string(&raw["model"]),
                "serial":php_string(&raw["serial"]),"identity":identity,
                "identity_status":identity_status,"identity_source":source,
                "transport":php_string(&raw["transport"]),
            }))
        })
        .collect();
    let nics: Vec<_> = array_values(&inventory["interfaces"])
        .filter_map(|nic| {
            let mac = php_string(&nic["mac"]);
            if mac.is_empty() {
                return None;
            }
            let address = &nic["ipv4"];
            let ip = if is_php_array(address) {
                array_values(address)
                    .map(php_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                php_string(address)
            };
            Some(
                json!({"mac":mac,"name":php_string(&nic["name"]),"type":php_string(&nic["type"]),
                    "speed_mbps":integer_field(nic,"speed_mbps"),"ipv4":ip}),
            )
        })
        .collect();
    let boot_mac = is_php_array(inventory)
        .then(|| inventory["boot_mac"].as_str().unwrap_or(machine_mac))
        .and_then(normalize_mac)
        .unwrap_or_default();
    json!({
        "disks":disks,"nics":nics,"boot_mac":boot_mac,
        "ram_kb":crate::migrations::integer(&hardware["memory_kb"]).filter(|ram| *ram > 0),
        "is_uefi":hardware["boot_mode"]=="UEFI",
        "cpu":{"model":php_trim(&php_string(&hardware["cpu_model"])),
                "cores":integer_field(hardware,"cpu_cores"),"max_mhz":integer_field(hardware,"cpu_max_mhz"),
                "current_mhz":integer_field(hardware,"cpu_current_mhz")},
        "disk_capacities_mb":if capacities.is_empty() { json!([]) } else { Value::Object(capacities) },
    })
}

fn integer_field(row: &Value, field: &str) -> Option<i64> {
    (!row[field].is_null()).then(|| crate::migrations::integer(&row[field]).unwrap_or_default())
}
