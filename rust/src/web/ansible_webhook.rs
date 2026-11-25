// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    ansible_settings::workdir,
    bytes,
    device_ansible::{redeploy_eligibility, RedeployEligibility},
    plain, ErrorBox, Reply,
};
use crate::{configured_database, connect, instance_secrets, pxe, setting};
use hyper::{Response, StatusCode};
use ring::hmac;
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(super) const ROUTE: &str = "/api/ansible-repo/webhook";
pub(super) const BODY_LIMIT: usize = 5 * 1024 * 1024;

pub(super) fn receive(
    config: &Path,
    signature: &str,
    event: &str,
    body: &[u8],
) -> Result<Reply, ErrorBox> {
    let Some(path) = configured_database(config) else {
        return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "webhook disabled\n"));
    };
    let db = connect(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    if !enabled(&db)? {
        return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "webhook disabled\n"));
    }
    if body.is_empty() {
        return Ok(plain(StatusCode::BAD_REQUEST, "empty body\n"));
    }
    let Some(signature) = signature.strip_prefix("sha256=") else {
        return Ok(plain(
            StatusCode::UNAUTHORIZED,
            "missing signature header\n",
        ));
    };
    let encrypted = setting(&db, "ansible_repo_webhook_secret")?;
    if encrypted.is_empty() {
        return Ok(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook secret not configured\n",
        ));
    }
    let Ok(secret) = instance_secrets::open(&encrypted) else {
        return Ok(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook secret unreadable\n",
        ));
    };
    if secret.is_empty() {
        return Ok(plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook secret empty after decrypt\n",
        ));
    }
    if !signature_bytes(signature).is_some_and(|tag| {
        hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, &secret), body, &tag).is_ok()
    }) {
        return Ok(plain(StatusCode::UNAUTHORIZED, "invalid signature\n"));
    }
    match event {
        "ping" => return json_reply(StatusCode::OK, json!({"pong":true})),
        "push" => {}
        _ => return json_reply(StatusCode::OK, json!({"ignored":true,"event":event})),
    }
    let Some(payload) = serde_json::from_slice::<Value>(body)
        .ok()
        .filter(pxe::is_php_array)
    else {
        return Ok(plain(StatusCode::BAD_REQUEST, "invalid json\n"));
    };
    let changed: BTreeSet<_> = pxe::array_values(&payload["commits"])
        .flat_map(|commit| {
            ["added", "modified", "removed"]
                .into_iter()
                .flat_map(move |kind| pxe::array_values(&commit[kind]))
        })
        .filter_map(Value::as_str)
        .filter(|name| !name.is_empty())
        .collect();
    let directory = workdir(&setting(&db, "ansible_playbooks_dir")?);
    let impacted = impacted_hosts(&directory, &changed);
    let mut db = connect(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !enabled(&tx)?
        || setting(&tx, "ansible_repo_webhook_secret")? != encrypted
        || workdir(&setting(&tx, "ansible_playbooks_dir")?) != directory
    {
        return Ok(plain(
            StatusCode::CONFLICT,
            "webhook configuration changed\n",
        ));
    }
    let sha = payload["head_commit"]["id"]
        .as_str()
        .and_then(|hash| hash.get(..7))
        .filter(|hash| hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or("?");
    let mut triggered = Vec::new();
    let mut skipped = Vec::new();
    if !impacted.is_empty() {
        let mut machines = tx.prepare(
            "SELECT id,hostname,status,rescue_mode=1,install_config_json
             FROM machines WHERE auto_deploy=1 AND hostname IS NOT NULL ORDER BY id",
        )?;
        let mut rows = machines.query([])?;
        while let Some(row) = rows.next()? {
            let hostname: String = row.get(1)?;
            if !impacted.contains(hostname.as_str()) {
                continue;
            }
            let id: i64 = row.get(0)?;
            let status: String = row.get(2)?;
            let rescue: bool = row.get(3)?;
            let snapshot: Value = row
                .get::<_, Option<String>>(4)?
                .and_then(|raw| serde_json::from_str(&raw).ok())
                .unwrap_or_default();
            let reason = enqueue(&tx, id, &status, rescue, &snapshot, sha)?;
            match reason {
                None => triggered.push(hostname),
                Some(reason) => {
                    pxe::log_event(&tx, id, "warning",
                        &format!("Webhook GitHub : redéploiement non déclenché ({reason}) — commit {sha}"),
                        None, None)?;
                    skipped.push(json!({"hostname":hostname,"reason":reason}));
                }
            }
        }
    }
    tx.commit()?;
    json_reply(
        StatusCode::ACCEPTED,
        json!({
            "commit":sha, "files":changed.len(), "impacted":impacted.len(),
            "triggered":triggered, "skipped":skipped,
        }),
    )
}

fn enabled(db: &Connection) -> rusqlite::Result<bool> {
    Ok(setting(db, "ansible_repo_webhook_enabled")? == "on"
        && setting(db, "ansible_enabled")? == "on")
}

fn enqueue(
    db: &Connection,
    id: i64,
    status: &str,
    rescue: bool,
    snapshot: &Value,
    sha: &str,
) -> rusqlite::Result<Option<&'static str>> {
    match redeploy_eligibility(db, id, status, rescue, snapshot)? {
        RedeployEligibility::Ready => {}
        RedeployEligibility::MissingRole => return Ok(Some("ansible_role_missing")),
        RedeployEligibility::Pending(_) => return Ok(Some("already_pending")),
        RedeployEligibility::Busy => return Ok(Some("machine_busy")),
    }
    let name = format!("machine:ansible_redeploy:{id}");
    let message = format!("Webhook GitHub : commit {sha}");
    db.execute(
        "INSERT INTO init_jobs(job_type,status,message) VALUES(?1,'pending',?2)",
        params![name, message],
    )?;
    pxe::log_event(
        db,
        id,
        "action",
        &format!("Redéploiement Ansible planifié : {message}"),
        None,
        None,
    )?;
    Ok(None)
}

fn signature_bytes(signature: &str) -> Option<[u8; 32]> {
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (i, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&signature[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(decoded)
}

fn impacted_hosts(root: &Path, changed: &BTreeSet<&str>) -> BTreeSet<String> {
    let inventory = fs::canonicalize(root)
        .ok()
        .and_then(|root| read_local(&root, "inventory.ini", 1024 * 1024))
        .unwrap_or_default();
    let mut groups = BTreeMap::<&str, Vec<&str>>::new();
    let mut group = None;
    for line in inventory.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
        {
            group = (!name.is_empty() && !name.contains([':', ']'])).then_some(name);
        } else if let Some((group, name)) = group.zip(line.split_whitespace().next()) {
            groups.entry(group).or_default().push(name);
        }
    }
    let mut impacted = BTreeSet::new();
    for path in changed
        .iter()
        .map(|path| path.trim_start_matches('/'))
        .filter(|path| !path.is_empty())
    {
        if let Some(host) = scoped_name(path, "host_vars/") {
            impacted.insert(host.to_owned());
            continue;
        }
        if let Some(group) = scoped_name(path, "group_vars/").filter(|name| *name != "all") {
            impacted.extend(
                groups
                    .get(group)
                    .into_iter()
                    .flatten()
                    .map(|name| (*name).to_owned()),
            );
            continue;
        }
        if let Some(playbook) = path
            .strip_prefix("playbooks/")
            .filter(|name| !name.contains('/'))
        {
            if yaml_stem(playbook).is_some() {
                let snippet = fs::canonicalize(root)
                    .ok()
                    .and_then(|root| read_local(&root, path, 4096))
                    .unwrap_or_default();
                if let Some(group) = playbook_group(&snippet).filter(|group| *group != "all") {
                    impacted.extend(
                        groups
                            .get(group)
                            .into_iter()
                            .flatten()
                            .map(|name| (*name).to_owned()),
                    );
                    continue;
                }
            }
        }
        return groups
            .values()
            .flatten()
            .map(|name| (*name).to_owned())
            .collect();
    }
    impacted
}

fn yaml_stem(name: &str) -> Option<&str> {
    name.strip_suffix(".yml")
        .or_else(|| name.strip_suffix(".yaml"))
        .filter(|stem| !stem.is_empty())
}

fn scoped_name<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let relative = path.strip_prefix(prefix)?;
    relative
        .split_once('/')
        .map(|(name, _)| name)
        .or_else(|| yaml_stem(relative))
        .filter(|name| !name.is_empty())
}

fn playbook_group(source: &str) -> Option<&str> {
    source.lines().find_map(|line| {
        let raw = line
            .trim_start()
            .strip_prefix('-')?
            .trim_start()
            .strip_prefix("hosts:")?
            .trim_start();
        let end = raw
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(raw.len());
        (end > 0).then(|| &raw[..end])
    })
}

fn read_local(root: &Path, relative: &str, limit: u64) -> Option<String> {
    let path = fs::canonicalize(root.join(relative)).ok()?;
    if !path.starts_with(root) {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut content = String::new();
    file.take(limit).read_to_string(&mut content).ok()?;
    Some(content)
}

fn json_reply(code: StatusCode, payload: Value) -> Result<Reply, ErrorBox> {
    Ok(Response::builder()
        .status(code)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .body(bytes(payload.to_string()))?)
}
