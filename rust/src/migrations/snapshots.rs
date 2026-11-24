// SPDX-License-Identifier: LGPL-3.0-only

use crate::{configured_database, connect, php_string, php_trim, php_truthy};
use rusqlite::{params, types::ValueRef, Connection, OpenFlags, Row, TransactionBehavior};
use serde_json::{json, Map, Value};
use std::{collections::HashSet, error::Error, path::Path};

type ErrorBox = Box<dyn Error + Send + Sync>;

pub(crate) fn assigned_presets(config: &Path) -> Result<(), ErrorBox> {
    let path = configured_database(config).ok_or("Existing SQLite database required")?;
    let mut db = connect(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut snapshots = Vec::new();
    {
        let mut statement = tx.prepare(
            "SELECT m.id,p.* FROM machines m JOIN presets p ON m.preset_id=p.id
             WHERE m.preset_id<>0 AND COALESCE(p.name,'') NOT IN ('','0')
                   AND COALESCE(m.install_config_json,'')=''",
        )?;
        let fields: Vec<_> = statement.column_names()[1..]
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let snapshot = snapshot(&read_preset(row, &fields, 1)?)?;
            snapshots.push((row.get::<_, i64>(0)?, serde_json::to_string(&snapshot)?));
        }
    }
    for (id, snapshot) in &snapshots {
        tx.execute(
            "UPDATE machines SET install_config_json=?1 WHERE id=?2",
            params![snapshot, id],
        )?;
    }
    tx.commit()?;
    println!(
        "Rust migrated {} assigned preset snapshot(s)",
        snapshots.len()
    );
    Ok(())
}

pub(crate) fn snapshot_for_preset(db: &Connection, id: i64) -> Result<Option<Value>, ErrorBox> {
    let mut query = db.prepare("SELECT * FROM presets WHERE id=?1")?;
    let fields = query
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut rows = query.query([id])?;
    rows.next()?
        .map(|row| snapshot(&read_preset(row, &fields, 0)?))
        .transpose()
}

fn read_preset(row: &Row<'_>, fields: &[String], offset: usize) -> Result<Value, ErrorBox> {
    let mut preset = Map::new();
    for (index, name) in fields.iter().enumerate() {
        let value = match row.get_ref(index + offset)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(value) => json!(value),
            ValueRef::Real(value) => json!(value),
            ValueRef::Text(value) | ValueRef::Blob(value) => json!(std::str::from_utf8(value)?),
        };
        preset.insert(name.clone(), value);
    }
    Ok(Value::Object(preset))
}

fn snapshot(preset: &Value) -> Result<Value, ErrorBox> {
    let config = decode(&preset["advanced_config_json"]);
    let mut result = Map::new();
    for key in [
        "name",
        "domain",
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
        "hostname_pattern",
        "pre_wipe_mode_json",
    ] {
        result.insert(key.to_owned(), preset[key].clone());
    }
    for (key, default) in [
        ("distro", "debian"),
        ("network_mode", "dhcp"),
        ("partition_mode", "default"),
        ("admin_user_login", ""),
        ("admin_user_groups", "sudo"),
        ("root_login_mode", "enabled"),
        ("variant", "debian"),
        ("pre_wipe_mode", "aucun"),
    ] {
        let value = &preset[key];
        result.insert(
            key.to_owned(),
            if value.is_null() {
                json!(default)
            } else {
                value.clone()
            },
        );
    }
    for key in ["static_cidr", "based_on_machine_id"] {
        let value = &preset[key];
        result.insert(
            key.to_owned(),
            if value.is_null() {
                Value::Null
            } else {
                json!(integer(value).unwrap_or_default())
            },
        );
    }
    result.insert(
        "hostname_random".to_owned(),
        json!(i64::from(php_truthy(&preset["hostname_random"]))),
    );
    result.insert(
        "static_dns".to_owned(),
        json!(dns_list(&preset["static_dns"])),
    );
    result.insert("network".to_owned(), network(preset, &config));
    result.insert("advanced".to_owned(), advanced(&config));
    result.insert(
        "disk_target_constraints".to_owned(),
        config
            .get("disk_target_constraints")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    let partition = if preset["partition_mode"] == "custom" {
        json!(serde_json::to_string(&partition_plan(&decode(
            &preset["partition_custom_json"]
        )))?)
    } else {
        Value::Null
    };
    result.insert("partition_custom_json".to_owned(), partition);
    Ok(Value::Object(result))
}

fn decode(raw: &Value) -> Value {
    raw.as_str()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}

fn entries(value: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    match value {
        Value::Array(values) => Box::new(values.iter()),
        Value::Object(values) => Box::new(values.values()),
        _ => Box::new(std::iter::empty()),
    }
}

fn array_like(value: &Value) -> bool {
    value.is_array() || value.is_object()
}

pub(crate) fn integer(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_f64().map(|number| number as i64))
        .or_else(|| {
            let raw = php_trim(value.as_str()?);
            raw.parse::<i64>().ok().or_else(|| {
                raw.parse::<f64>()
                    .ok()
                    .filter(|n| n.is_finite())
                    .map(|n| n as i64)
            })
        })
}

pub(crate) fn dns_list(value: &Value) -> Vec<String> {
    if let Some(raw) = value.as_str() {
        let decoded = decode(value);
        if array_like(&decoded) {
            return dns_list(&decoded);
        }
        return raw
            .split(|ch: char| matches!(ch, ',' | '\x0b') || ch.is_ascii_whitespace())
            .map(php_trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
    }
    strings(value)
}

fn strings(value: &Value) -> Vec<String> {
    entries(value)
        .map(|item| php_trim(&php_string(item)).to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

fn text(value: &Value) -> Option<&str> {
    value.as_str().map(php_trim).filter(|item| !item.is_empty())
}

fn text_values(value: &Value) -> Vec<&str> {
    entries(value).filter_map(text).collect()
}

fn network(preset: &Value, config: &Value) -> Value {
    let parameters = &config["network"];
    let interfaces: Vec<_> = entries(&parameters["interfaces"])
        .enumerate()
        .filter(|(_, interface)| array_like(interface))
        .map(|(index, interface)| normalized_interface(index as i64, interface))
        .collect();
    if !interfaces.is_empty() {
        let primary = integer(&parameters["primary"])
            .unwrap_or_default()
            .clamp(0, interfaces.len() as i64 - 1);
        return json!({"interfaces": interfaces, "primary": primary});
    }
    let mode = if preset["network_mode"] == "static" {
        "static"
    } else {
        "dhcp"
    };
    let static_config = if mode == "static" {
        static_network(
            &preset["static_ip"],
            &preset["static_cidr"],
            &preset["static_gateway"],
            &preset["static_dns"],
        )
    } else {
        Value::Null
    };
    json!({"interfaces": [{
        "match_by": "primary", "index": 0, "match": null, "mode": mode,
        "static": static_config, "vlan": null, "bond": null
    }], "primary": 0})
}

fn static_network(ip: &Value, cidr: &Value, gateway: &Value, dns: &Value) -> Value {
    json!({"ip": php_string(ip), "cidr": integer(cidr).unwrap_or(24), "gateway": php_string(gateway), "dns": dns_list(dns)})
}

fn normalized_interface(index: i64, interface: &Value) -> Value {
    let mode = interface["mode"]
        .as_str()
        .filter(|mode| matches!(*mode, "dhcp" | "static" | "disabled"))
        .unwrap_or("dhcp");
    let match_by = interface["match_by"]
        .as_str()
        .filter(|kind| matches!(*kind, "index" | "mac"))
        .unwrap_or("primary");
    let mac = &interface["match"]["mac"];
    let matched =
        php_truthy(mac).then(|| json!({"mac": php_trim(&php_string(mac)).to_ascii_lowercase()}));
    let address = &interface["static"];
    let static_config = (mode == "static" && array_like(address)).then(|| {
        static_network(
            &address["ip"],
            &address["cidr"],
            &address["gateway"],
            &address["dns"],
        )
    });
    let vlan = integer(&interface["vlan"]["id"])
        .filter(|id| (1..=4094).contains(id))
        .map(|id| json!({"id": id}));
    let bonding = &interface["bond"];
    let bond_name = php_string(&bonding["name"]);
    let bond_name = php_trim(&bond_name);
    let bond = bonding["role"]
        .as_str()
        .filter(|role| matches!(*role, "master" | "slave") && !bond_name.is_empty())
        .map(|role| {
            let mode = if bonding["mode"].is_null() {
                "active-backup".to_owned()
            } else {
                php_string(&bonding["mode"])
            };
            json!({"role": role, "name": bond_name, "mode": php_trim(&mode)})
        });
    json!({
        "match_by": match_by, "index": integer(&interface["index"]).unwrap_or(index),
        "match": matched, "mode": mode, "static": static_config, "vlan": vlan, "bond": bond
    })
}

fn advanced(config: &Value) -> Value {
    let mut defaults = json!({
        "localization": {"locale":"fr_FR.UTF-8","language":null,"country":null,"supported_locales":[],"keymap":"fr(latin9)","keymap_toggle":null,"console_ask_detect":null},
        "mirror": {"country":"manual","hostname":"deb.debian.org","directory":"/debian","proxy":""},
        "timezone": {"utc":true,"zone":"Europe/Paris","ntp":true,"ntp_server":null},
        "packages": {"tasksel":["ssh-server","standard"],"pkgsel_include":["sudo","openssh-server","python3","ca-certificates","curl"],"install_recommends":false,"upgrade":"full-upgrade","update_policy":null,"popcon":false},
        "apt": {"non_free_firmware":true,"contrib":true,"non_free":false,"services_select":null,"security_host":null,"hw_detect_load_firmware":true},
        "bootloader": {"only_debian":true,"with_other_os":false,"bootdev":"default"},
        "finish": {"reboot":"note","eject_cdrom":null},
        "post_install": {"remote_pubkey_urls":[]},
    });
    for (section, options) in defaults.as_object_mut().expect("default sections") {
        for (key, current) in options.as_object_mut().expect("default options") {
            if let Some(value) = config[section].get(key) {
                *current = value.clone();
            }
        }
    }
    defaults
}

fn partition_fields(data: &Value, fs: &str) -> Map<String, Value> {
    Map::from_iter([
        ("fs".into(), json!(fs)),
        ("mount".into(), json!(text(&data["mount"]))),
        (
            "size_mb".into(),
            json!(integer(&data["size_mb"]).unwrap_or_default()),
        ),
        ("fill".into(), json!(php_truthy(&data["fill"]))),
        (
            "reserved_pct".into(),
            json!(integer(&data["reserved_pct"]).map(|pct| pct.clamp(0, 50))),
        ),
        (
            "mount_options".into(),
            json!(strings(&data["mount_options"])),
        ),
    ])
}

pub(crate) fn partition_plan(plan: &Value) -> Value {
    let mut targets = HashSet::new();
    let target_disks: Vec<_> = text_values(&plan["target_disks"])
        .into_iter()
        .filter(|path| targets.insert(*path))
        .collect();
    let disks: Vec<_> = entries(&plan["disks"])
        .filter_map(|disk| {
            let path = text(&disk["path"])?;
            let partitions: Vec<_> = entries(&disk["partitions"])
                .filter_map(|part| {
                    let mut fields = partition_fields(part, text(&part["fs"])?);
                    fields.insert("id".into(), json!(text(&part["id"])));
                    Some(fields)
                })
                .collect();
            Some(json!({"path": path, "partitions": partitions}))
        })
        .collect();
    let raid_arrays: Vec<_> = entries(&plan["raid_arrays"])
        .filter_map(|raid| {
            let name = text(&raid["name"])?;
            let level =
                integer(&raid["level"]).filter(|level| matches!(level, 0 | 1 | 5 | 6 | 10))?;
            Some(json!({
                "name": name, "level": level,
                "members": text_values(&raid["members"]), "spares": text_values(&raid["spares"]),
                "is_pv": php_truthy(&raid["is_pv"])
            }))
        })
        .collect();
    let vgs: Vec<_> = entries(&plan["vgs"])
        .filter_map(|vg| Some(json!({"name": text(&vg["name"])?, "pvs": text_values(&vg["pvs"])})))
        .collect();
    let logical_volumes: Vec<_> = entries(&plan["logical_volumes"])
        .filter_map(|lv| {
            let (vg, name, fs) = (text(&lv["vg"])?, text(&lv["name"])?, text(&lv["fs"])?);
            let mut fields = partition_fields(lv, fs);
            fields.insert("vg".into(), json!(vg));
            fields.insert("name".into(), json!(name));
            Some(fields)
        })
        .collect();
    json!({"target_disks": target_disks, "disks": disks, "raid_arrays": raid_arrays, "vgs": vgs, "logical_volumes": logical_volumes})
}
