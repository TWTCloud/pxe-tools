// SPDX-License-Identifier: LGPL-3.0-only

mod partition;

use super::{disk_path_syntax, ErrorBox};
use crate::{
    disk_identity,
    migrations::{dns_list, integer, partition_plan},
    php_string, php_trim, php_truthy,
    pxe::{array_values, is_php_array, normalize_mac},
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Map, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr},
};

pub(super) fn preset(
    db: &Connection,
    payload: &Map<String, Value>,
    roles: Option<&[String]>,
) -> Result<(), ErrorBox> {
    let fail = |message: &'static str| -> ErrorBox { message.into() };
    if ["name", "distro", "admin_user_login"]
        .into_iter()
        .any(|key| payload[key] == "")
    {
        return Err(fail("Nom, distribution et compte administrateur requis"));
    }
    let role = payload["ansible_role"].as_str().unwrap_or_default();
    let profile_active = !php_trim(&crate::setting(db, "ansible_repo_profile")?).is_empty();
    if !role.is_empty()
        && (!role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            || (profile_active
                && roles.is_none_or(|roles| !roles.iter().any(|allowed| allowed == role))))
    {
        return Err(fail(
            "Rôle Ansible invalide ou absent du profil de provisionnement",
        ));
    }
    let distro = &payload["distro"];
    let allowed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM catalog_entries WHERE distro=?1)
         OR (?1='debian' AND NOT EXISTS(SELECT 1 FROM catalog_entries))",
        [distro.as_str().unwrap_or_default()],
        |row| row.get(0),
    )?;
    if !allowed || payload["variant"] != "debian" {
        return Err(fail("Distribution ou variante de modèle indisponible"));
    }
    if payload["network_mode"] == "static" {
        let dns = decode(&payload["static_dns"]);
        if !ipv4(&payload["static_ip"])
            || !ipv4(&payload["static_gateway"])
            || !integer(&payload["static_cidr"]).is_some_and(|cidr| (1..=32).contains(&cidr))
            || !array_values(&dns).any(ipv4)
        {
            return Err(fail(
                "Mode statique : IPv4, préfixe, passerelle et DNS IPv4 requis",
            ));
        }
    }
    if payload["root_login_mode"] == "disabled"
        && !php_truthy(&payload["admin_user_pwhash"])
        && !php_truthy(&payload["admin_user_pubkeys"])
    {
        return Err(fail(
            "Compte root désactivé : accès administrateur par mot de passe ou clé SSH requis",
        ));
    }
    let inventory = if let Some(id) = payload["based_on_machine_id"].as_i64() {
        let raw: Option<Option<String>> = db
            .query_row(
                "SELECT inventory_json FROM machines WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        raw.flatten()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    } else {
        Value::Null
    };
    let advanced = decode(&payload["advanced_config_json"]);
    if !payload["advanced_config_json"].is_null()
        && !advanced.as_object().is_some_and(|fields| {
            !fields
                .keys()
                .enumerate()
                .all(|(i, key)| *key == i.to_string())
                || payload["advanced_config_json"]
                    .as_str()
                    .is_some_and(|raw| php_trim(raw) == "{}")
        })
    {
        return Err(fail("Configuration avancée : objet JSON valide requis"));
    }
    if payload["partition_mode"] == "custom" {
        let plan = partition_plan(&decode(&payload["partition_custom_json"]));
        partition::validate(&plan, &inventory)?;
        validate_constraints(&advanced["disk_target_constraints"], &plan)?;
    } else if !advanced["disk_target_constraints"].is_null()
        && advanced["disk_target_constraints"] != serde_json::json!([])
    {
        return Err(fail(
            "Contrainte disque réservée à une recette personnalisée",
        ));
    }
    if !advanced["network"].is_null() {
        network(&advanced["network"], &inventory)?;
    }
    validate_advanced(&advanced)
}

fn decode(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default()
}

fn validate_constraints(constraints: &Value, plan: &Value) -> Result<(), ErrorBox> {
    if constraints.is_null() || constraints.as_array().is_some_and(Vec::is_empty) {
        return Ok(());
    }
    let targets = plan["target_disks"]
        .as_array()
        .expect("normalized target disks");
    let raid = plan["raid_arrays"].as_array().expect("normalized RAID");
    let Some(fields) = constraints.as_object().filter(|fields| fields.len() == 1) else {
        return Err("Une seule contrainte disque est autorisée".into());
    };
    let (path, serial) = fields.iter().next().expect("one constraint");
    if targets.len() != 1
        || targets[0].as_str() != Some(path)
        || !raid.is_empty()
        || disk_identity::serial(serial).is_none()
    {
        return Err(
            "Contrainte disque incompatible avec la recette ou numéro de série invalide".into(),
        );
    }
    Ok(())
}

fn ipv4(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|ip| ip.parse::<Ipv4Addr>().is_ok())
}

fn validated_static_address(data: &Value) -> bool {
    let ip = data["ip"]
        .as_str()
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
    let gateway = data["gateway"]
        .as_str()
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
    let cidr = integer(&data["cidr"]).filter(|cidr| (1..=32).contains(cidr));
    let (Some(ip), Some(gateway), Some(cidr)) = (ip, gateway, cidr) else {
        return false;
    };
    let mask = u32::MAX << (32 - cidr);
    let dns = if is_php_array(&data["dns"]) {
        array_values(&data["dns"]).map(php_string).collect()
    } else {
        dns_list(&data["dns"])
    };
    (u32::from(ip) & mask) == (u32::from(gateway) & mask)
        && !dns.is_empty()
        && dns
            .iter()
            .all(|address| address.parse::<Ipv4Addr>().is_ok())
}

fn network(plan: &Value, inventory: &Value) -> Result<(), ErrorBox> {
    if !is_php_array(plan) {
        return Err("Réseau : objet de configuration requis".into());
    }
    let raw = &plan["interfaces"];
    if !php_truthy(raw) {
        return Ok(());
    }
    let Some(interfaces) = raw.as_array() else {
        return Err("Les interfaces réseau doivent former une liste".into());
    };
    let primary = integer(&plan["primary"]).unwrap_or_default();
    if primary < 0
        || primary as usize >= interfaces.len()
        || interfaces[primary as usize]["mode"] == "disabled"
    {
        return Err("L’interface primaire doit désigner une carte active".into());
    }
    let known: HashSet<_> = array_values(&inventory["interfaces"])
        .filter_map(|nic| nic["mac"].as_str())
        .map(|mac| php_trim(mac).to_ascii_lowercase())
        .filter(|mac| !mac.is_empty())
        .collect();
    let mut seen = HashSet::new();
    let mut bonds: HashMap<String, Vec<&Value>> = HashMap::new();
    for (index, nic) in interfaces.iter().enumerate() {
        if !is_php_array(nic) {
            return Err("Configuration d’interface réseau invalide".into());
        }
        let mode = string_or_default(&nic["mode"], "dhcp");
        let selector = string_or_default(&nic["match_by"], "primary");
        let mac = php_trim(&php_string(&nic["match"]["mac"])).to_ascii_lowercase();
        if !matches!(mode, "dhcp" | "static" | "disabled")
            || !matches!(selector, "primary" | "index" | "mac")
            || (mac.is_empty()
                && (selector == "mac" || (mode != "disabled" && index != primary as usize)))
            || (!mac.is_empty()
                && (normalize_mac(&mac).as_deref() != Some(&mac)
                    || !seen.insert(mac.clone())
                    || (!known.is_empty() && !known.contains(&mac))))
        {
            return Err("Mode, sélecteur ou adresse MAC d’une interface invalide".into());
        }
        if mode == "static" && !validated_static_address(&nic["static"]) {
            return Err("Configuration IPv4 statique d’une interface invalide".into());
        }
        let vlan = &nic["vlan"]["id"];
        if !vlan.is_null()
            && (!integer(vlan).is_some_and(|value| {
                (1..=4094).contains(&value)
                    && php_trim(&php_string(vlan)).parse::<f64>().ok() == Some(value as f64)
            }) || (mode != "disabled" && index == primary as usize))
        {
            return Err("VLAN hors plage ou activé sur le port PXE primaire".into());
        }
        let bond = &nic["bond"];
        if php_truthy(&bond["role"]) || php_truthy(&bond["name"]) {
            let name = php_trim(&php_string(&bond["name"])).to_owned();
            if !valid_bond_name(&name)
                || !matches!(bond["role"].as_str(), Some("master" | "slave"))
                || mac.is_empty()
                || !vlan.is_null()
            {
                return Err("Agrégation réseau invalide".into());
            }
            bonds.entry(name).or_default().push(nic);
        }
    }
    for group in bonds.values() {
        let mut masters = group.iter().filter(|nic| nic["bond"]["role"] == "master");
        let Some(master) = masters.next().filter(|_| group.len() >= 2) else {
            return Err("Une agrégation nécessite au moins deux cartes et un maître".into());
        };
        if masters.next().is_some()
            || master["mode"] == "disabled"
            || !matches!(
                string_or_default(&master["bond"]["mode"], "active-backup"),
                "active-backup"
                    | "balance-rr"
                    | "balance-xor"
                    | "broadcast"
                    | "802.3ad"
                    | "balance-tlb"
                    | "balance-alb"
            )
        {
            return Err("Maître ou mode d’agrégation invalide".into());
        }
    }
    Ok(())
}

fn valid_bond_name(value: &str) -> bool {
    value.len() <= 15
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn string_or_default<'a>(value: &'a Value, default: &'a str) -> &'a str {
    if value.is_null() {
        default
    } else {
        value.as_str().unwrap_or_default()
    }
}

pub(crate) fn validate_advanced(value: &Value) -> Result<(), ErrorBox> {
    let zone = value["timezone"]["zone"].as_str().unwrap_or_default();
    if !zone.is_empty()
        && zone != "UTC"
        && !fs::read_to_string("/usr/share/zoneinfo/zone.tab")
            .ok()
            .is_some_and(|zones| {
                zones
                    .lines()
                    .any(|row| !row.starts_with('#') && row.split('\t').nth(2) == Some(zone))
            })
    {
        return Err("Fuseau horaire IANA invalide".into());
    }
    let bootdev = value["bootloader"]["bootdev"].as_str().unwrap_or_default();
    if !matches!(bootdev, "" | "default") && !disk_path_syntax(bootdev) {
        return Err("Destination GRUB invalide".into());
    }
    let mirror = value["mirror"]["hostname"].as_str().unwrap_or_default();
    if !mirror
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
    {
        return Err("Nom d’hôte du miroir invalide".into());
    }
    let ntp = value["timezone"]["ntp_server"].as_str().unwrap_or_default();
    if !ntp.is_empty() && ntp.parse::<IpAddr>().is_err() && !fqdn(ntp) {
        return Err("Serveur NTP invalide".into());
    }
    let locale = value["localization"]["locale"].as_str().unwrap_or_default();
    if !locale.is_empty() && !locale_valid(locale) {
        return Err("Locale POSIX invalide".into());
    }
    Ok(())
}

fn fqdn(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn locale_valid(locale: &str) -> bool {
    let letters =
        |value: &str| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphabetic());
    let (locale, modifier) = locale
        .split_once('@')
        .map_or((locale, None), |(locale, modif)| (locale, Some(modif)));
    let (locale, encoding) = locale
        .split_once('.')
        .map_or((locale, None), |(locale, charset)| (locale, Some(charset)));
    let (language, country) = locale
        .split_once('_')
        .map_or((locale, None), |(lang, country)| (lang, Some(country)));
    letters(language)
        && country.is_none_or(letters)
        && modifier.is_none_or(letters)
        && encoding.is_none_or(|charset| {
            !charset.is_empty()
                && charset
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
