// SPDX-License-Identifier: LGPL-3.0-only

mod validation;

use crate::{configured_database, connect, migrations::integer, php_string, php_trim, php_truthy};
use rusqlite::{
    params_from_iter,
    types::{Value as SqlValue, ValueRef},
    Connection, OpenFlags, OptionalExtension, TransactionBehavior,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{
    error::Error,
    fmt::Write,
    io::{self, Read},
    net::Ipv4Addr,
    path::Path,
};

type ErrorBox = Box<dyn Error + Send + Sync>;
const LIMIT: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    preset: Map<String, Value>,
    repository_profile: String,
    allowed_roles: Option<Vec<String>>,
}

pub(crate) fn run(config: &Path) -> Result<(), ErrorBox> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > LIMIT {
        return Err("Modèle JSON trop volumineux".into());
    }
    let request: Request = serde_json::from_slice(&input).map_err(|_| "Modèle JSON invalide")?;
    let path = configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if request.repository_profile != php_trim(&crate::setting(&tx, "ansible_repo_profile")?) {
        return Err("Le profil du dépôt Ansible a changé pendant l’importation".into());
    }
    let incoming = Value::Object(request.preset);
    let name = php_string(&incoming["name"]);
    let name = php_trim(&name);
    let existing: Option<(i64, String, String)> = tx
        .query_row(
            "SELECT id,root_login_mode,variant FROM presets WHERE name=?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if existing
        .as_ref()
        .is_some_and(|(_, _, variant)| variant == "proxmox-ve")
    {
        return Err("Ce modèle Proxmox VE historique est conservé en lecture seule.".into());
    }
    let payload = normalize(
        &incoming,
        existing.as_ref().map(|(_, mode, _)| mode.as_str()),
    )?;
    validation::preset(&tx, &payload, request.allowed_roles.as_deref())?;
    let (id, action) = persist(&tx, &payload, existing.map(|(id, _, _)| id))?;
    tx.commit()?;
    println!("{}", json!({"action":action,"id":id,"name":name}));
    Ok(())
}

fn normalize(incoming: &Value, current_root: Option<&str>) -> Result<Map<String, Value>, ErrorBox> {
    let mut model = Map::new();
    for key in [
        "description",
        "codename",
        "version_full",
        "static_ip",
        "static_gateway",
        "admin_user_pwhash",
        "admin_user_password_cipher",
        "admin_user_pubkeys",
        "admin_user_fullname",
        "ansible_role",
        "ansible_extra_vars",
        "domain",
    ] {
        model.insert(key.to_owned(), json!(nonempty(&incoming[key])));
    }
    for key in ["name", "distro", "admin_user_login"] {
        model.insert(key.to_owned(), json!(php_trim(&php_string(&incoming[key]))));
    }
    for key in [
        "partition_custom_json",
        "advanced_config_json",
        "pre_wipe_mode_json",
    ] {
        let value = match &incoming[key] {
            raw @ (Value::Array(_) | Value::Object(_)) => json!(encode_php(raw)?),
            Value::String(raw) if !php_trim(raw).is_empty() => json!(raw),
            _ => Value::Null,
        };
        model.insert(key.to_owned(), value);
    }
    let cidr = integer(&incoming["static_cidr"]);
    model.insert("static_cidr".to_owned(), json!(cidr));
    model.insert(
        "static_netmask".to_owned(),
        json!(cidr.map(|size| Ipv4Addr::from(u32::MAX << (32 - size.clamp(1, 32))).to_string())),
    );
    let dns = match &incoming["static_dns"] {
        raw @ (Value::Array(_) | Value::Object(_)) => {
            encode_php(&json!(crate::migrations::dns_list(raw)))?
        }
        Value::String(raw) if !php_trim(raw).is_empty() => raw.to_owned(),
        _ => "[]".to_owned(),
    };
    model.insert("static_dns".to_owned(), json!(dns));
    let network = if incoming["network_mode"] == "static" {
        "static"
    } else {
        "dhcp"
    };
    model.insert("network_mode".to_owned(), json!(network));
    let partition = if incoming["partition_mode"] == "custom" {
        "custom"
    } else {
        "default"
    };
    model.insert("partition_mode".to_owned(), json!(partition));
    let root = incoming
        .get("root_login_mode")
        .map(|value| value.as_str().unwrap_or_default())
        .or(current_root)
        .filter(|value| matches!(*value, "enabled" | "disabled"))
        .unwrap_or("disabled");
    model.insert("root_login_mode".to_owned(), json!(root));
    let groups = php_string(&incoming["admin_user_groups"]);
    let groups = php_trim(&groups);
    model.insert(
        "admin_user_groups".to_owned(),
        json!(if matches!(groups, "" | "0") {
            "sudo"
        } else {
            groups
        }),
    );
    let variant = incoming
        .get("variant")
        .map_or("debian", |value| value.as_str().unwrap_or_default());
    model.insert("variant".to_owned(), json!(variant));
    model.insert(
        "pre_wipe_mode".to_owned(),
        json!(wipe_mode(&incoming["pre_wipe_mode"])?),
    );
    model.insert(
        "based_on_machine_id".to_owned(),
        json!(integer(&incoming["based_on_machine_id"]).filter(|id| *id > 0)),
    );
    let hostname = incoming
        .get("hostname")
        .filter(|value| !value.is_null())
        .unwrap_or(&incoming["hostname_pattern"]);
    model.insert("hostname_pattern".to_owned(), json!(nonempty(hostname)));
    model.insert(
        "hostname_random".to_owned(),
        json!(i64::from(php_truthy(&incoming["hostname_random"]))),
    );
    Ok(model)
}

fn nonempty(value: &Value) -> Option<&str> {
    value
        .as_str()
        .map(php_trim)
        .filter(|value| !value.is_empty())
}

fn disk_path_syntax(path: &str) -> bool {
    path.strip_prefix("/dev/").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/_-".contains(&byte))
    })
}

fn wipe_mode(value: &Value) -> Result<String, ErrorBox> {
    fn supported(value: &str) -> &str {
        if matches!(value, "partial" | "full") {
            value
        } else {
            "aucun"
        }
    }
    match value {
        Value::Object(fields) => {
            let clean: Map<_, _> = fields
                .iter()
                .filter(|(path, _)| path.as_str() == "*" || disk_path_syntax(path))
                .map(|(path, mode)| (path.clone(), json!(supported(&php_string(mode)))))
                .collect();
            if clean.len() == 1 {
                if let Some(mode) = clean.get("*") {
                    return Ok(php_string(mode));
                }
            }
            if clean.is_empty() {
                Ok("[]".to_owned())
            } else {
                encode_php(&Value::Object(clean))
            }
        }
        Value::Array(_) => Ok("[]".to_owned()),
        Value::String(raw) if php_trim(raw).starts_with('{') => {
            match serde_json::from_str::<Value>(raw) {
                Ok(map @ (Value::Object(_) | Value::Array(_))) => encode_php(&map),
                _ => Ok("aucun".to_owned()),
            }
        }
        _ => Ok(supported(php_trim(&php_string(value))).to_owned()),
    }
}

fn encode_php(data: &Value) -> Result<String, ErrorBox> {
    let ascii = serde_json::to_string(&php_arrays(data))?;
    let mut escaped = String::with_capacity(ascii.len());
    for character in ascii.chars() {
        if character.is_ascii() {
            escaped.push(character);
        } else {
            for unit in character.encode_utf16(&mut [0; 2]) {
                write!(escaped, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(escaped)
}

fn php_arrays(data: &Value) -> Value {
    match data {
        Value::Object(fields)
            if fields
                .keys()
                .enumerate()
                .all(|(i, key)| *key == i.to_string()) =>
        {
            Value::Array(fields.values().map(php_arrays).collect())
        }
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), php_arrays(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(php_arrays).collect()),
        _ => data.clone(),
    }
}

fn persist(
    db: &Connection,
    data: &Map<String, Value>,
    existing: Option<i64>,
) -> Result<(i64, &'static str), ErrorBox> {
    let columns = data.keys().map(String::as_str).collect::<Vec<_>>();
    let values = data
        .values()
        .map(|value| match value {
            Value::Number(number) => {
                SqlValue::Integer(number.as_i64().expect("integer preset field"))
            }
            Value::String(value) => SqlValue::Text(value.clone()),
            _ => SqlValue::Null,
        })
        .collect::<Vec<_>>();
    let references = (1..=columns.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>();
    if let Some(id) = existing {
        let mut query = db.prepare(&format!(
            "SELECT {} FROM presets WHERE id=?1",
            columns.join(",")
        ))?;
        let changed = query.query_row([id], |row| {
            for (index, desired) in values.iter().enumerate() {
                let prior = row.get_ref(index)?;
                let equal = match (prior, desired) {
                    (ValueRef::Null, SqlValue::Null) => true,
                    (ValueRef::Integer(old), SqlValue::Integer(new)) => old == *new,
                    (ValueRef::Text(old) | ValueRef::Blob(old), SqlValue::Text(new)) => {
                        old == new.as_bytes()
                    }
                    _ => false,
                };
                if !equal {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if !changed {
            return Ok((id, "unchanged"));
        }
        let assignments = columns
            .iter()
            .zip(&references)
            .map(|(col, binding)| format!("{col}={binding}"))
            .collect::<Vec<_>>()
            .join(",");
        db.execute(
            &format!(
                "UPDATE presets SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?{}",
                columns.len() + 1
            ),
            params_from_iter(values.into_iter().chain([SqlValue::Integer(id)])),
        )?;
        return Ok((id, "updated"));
    }
    db.execute(
        &format!(
            "INSERT INTO presets({}) VALUES({})",
            columns.join(","),
            references.join(",")
        ),
        params_from_iter(values),
    )?;
    Ok((db.last_insert_rowid(), "created"))
}
