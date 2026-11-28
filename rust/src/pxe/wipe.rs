// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    agent::{Input, Session},
    array_values, client_in_subnet, is_php_array, log_event, machine_for_mac, normalize_mac,
    set_machine_status,
};
use crate::{
    bearer, decimal, disk_identity::serial, failure, header, install, json_response, param,
    parse_query, php_string, preseed, read_body, request_header, response, setting, HttpResponse,
    PxeRequest, TEXT,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
};

const MENU: &str = "wipe";
const SCRIPT: &str = include_str!("../../assets/pxe/wipe.sh");

pub(crate) fn serve(
    db: &mut Connection,
    ip: Option<IpAddr>,
    route: &str,
    query: &str,
    request: &mut PxeRequest<'_>,
) -> rusqlite::Result<HttpResponse> {
    let subnet = request.subnet(db)?;
    let allowed = match ip {
        Some(IpAddr::V4(peer)) if client_in_subnet(peer, &subnet) => Some(peer),
        _ => None,
    };
    if route == "/wipe.sh" {
        let Some(ip) = allowed else {
            return Ok(response(404, TEXT, ""));
        };
        let raw = parse_query(query.as_bytes());
        return script(db, ip, param(&raw, "mac"), request.network);
    }
    let token = bearer(request).to_owned();
    let is_form = request_header(request, "Content-Type").is_some_and(|raw| {
        raw.split(';').next().is_some_and(|kind| {
            kind.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    });
    let body = match read_body(request, 1_048_577) {
        Ok(body) if body.len() <= 1_048_576 => body,
        Ok(_) => return json_response(failure(413, "body too large")),
        Err(_) => return json_response(failure(400, "invalid request body")),
    };
    let input = Input::new(query, &body, is_form);
    let id = decimal(input.get("wipe_id"));
    if id <= 0 {
        return json_response(if route == "/api/wipe-progress" {
            Ok((200, json!({"status":"debug_ack"})))
        } else {
            failure(400, "wipe_id required")
        });
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(job) = Job::get(&tx, id)? else {
        return json_response(failure(404, "wipe not found"));
    };
    let Some((ip, mac)) = allowed.zip(normalize_mac(input.get("mac"))) else {
        return json_response(failure(404, "not found"));
    };
    let Some((action, _, _)) = job.action(&tx)? else {
        return json_response(failure(404, "not found"));
    };
    let session = Session {
        machine: job.machine,
        mac: &mac,
        action,
        menu: MENU,
        ip,
    };
    if !session.authorized(&tx, &token)? {
        return json_response(failure(404, "not found"));
    }
    let result = if route == "/api/wipe-progress" {
        let text = input.log_line();
        if !text.is_empty() {
            tx.execute(
                "UPDATE wipes SET log=COALESCE(log,'') || ?2 WHERE id=?1",
                params![job.id, text],
            )?;
        }
        json!({"status":"ok"})
    } else {
        match end(&tx, &job, &mac, input.get("status"), action)? {
            Some(body) => body,
            None => return json_response(failure(409, "installation plan no longer supported")),
        }
    };
    tx.commit()?;
    json_response(Ok((200, result)))
}

struct Job {
    id: i64,
    machine: i64,
    action_id: Option<i64>,
    status: String,
    disks: Value,
    after: String,
    chain: Value,
}
impl Job {
    fn get(db: &Connection, id: i64) -> rusqlite::Result<Option<Self>> {
        db.query_row(
            "SELECT machine_id,action_id,wipe_status,disks_json,post_action,chain_install_config_json FROM wipes WHERE id=?1",
            [id], |row| Ok(Self{
                id,machine:row.get(0)?,action_id:row.get(1)?,status:row.get(2)?,
                disks:serde_json::from_str(&row.get::<_,String>(3)?).unwrap_or_default(),
                after:row.get::<_,Option<String>>(4)?.unwrap_or_else(||"poweroff".to_owned()),
                chain:row.get::<_,Option<String>>(5)?.and_then(|raw|serde_json::from_str(&raw).ok()).unwrap_or_default(),
            })
        ).optional()
    }
    fn action(&self, db: &Connection) -> rusqlite::Result<Option<(i64, String, String)>> {
        let Some(action) = self
            .action_id
            .filter(|_| matches!(self.status.as_str(), "pending" | "running"))
        else {
            return Ok(None);
        };
        db.query_row("SELECT id,type,token FROM actions WHERE id=?1 AND machine_id=?2 AND type IN ('wipe_only','reinstall')
                      AND status IN ('pending','running')",params![action,self.machine],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional()
    }
    fn chain_accepted(&self, db: &Connection, mac: &str) -> rusqlite::Result<bool> {
        if !is_php_array(&self.chain["install_config"]) {
            return Ok(true);
        }
        let Some(machine) = install::machine(db, mac, true)? else {
            return Ok(false);
        };
        Ok(preseed::validate_plan(db, &machine, &self.chain["install_config"])?.is_ok())
    }
    fn disk_lines(&self) -> Option<String> {
        let mut targets = HashSet::new();
        let mut identities = HashSet::new();
        let mut lines = Vec::new();
        for disk in array_values(&self.disks) {
            let name = disk["name"].as_str()?;
            let normalized = if name.starts_with("/dev/") {
                name.to_owned()
            } else {
                format!("/dev/{name}")
            };
            let mode = disk["mode"]
                .as_str()
                .filter(|mode| matches!(*mode, "full" | "partial"))?;
            if !preseed::whole_disk(&normalized) || !targets.insert(normalized) {
                return None;
            }
            let proof = &disk["identity"];
            let identity = (proof["kind"] == "serial" && proof["status"] == "valid")
                .then(|| serial(&proof["value"]))
                .flatten();
            let encoded = if let Some(identity) = identity {
                if !identities.insert(identity.clone()) {
                    return None;
                }
                STANDARD.encode(identity)
            } else {
                // Older rows are readable. The guest refuses a job without a serial.
                "-".to_owned()
            };
            lines.push(format!("{name}|{mode}|{encoded}"));
        }
        (!lines.is_empty()).then(|| lines.join("\n"))
    }
}

fn script(
    db: &mut Connection,
    ip: Ipv4Addr,
    raw_mac: &str,
    network: Option<&crate::boot_networks::Network>,
) -> rusqlite::Result<HttpResponse> {
    let Some(mac) = normalize_mac(raw_mac) else {
        return Ok(response(400, TEXT, "# ERREUR : mac required (?mac=...)\n"));
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let job = if let Some(machine) = machine_for_mac(&tx, &mac)? {
        let latest = tx
            .query_row(
                "SELECT id FROM wipes WHERE machine_id=?1 AND wipe_status IN ('pending','running')
                                ORDER BY id DESC LIMIT 1",
                [machine],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        latest.map(|id| Job::get(&tx, id)).transpose()?.flatten()
    } else {
        None
    };
    let Some(job) = job else {
        return Ok(response(
            404,
            TEXT,
            format!("# ERREUR : no active wipe job for mac {mac}\n"),
        ));
    };
    let Some((action, kind, action_token)) = job.action(&tx)? else {
        return Ok(response(404, TEXT, ""));
    };
    let Ok(server) = network
        .map_or_else(
            || setting(&tx, "pxe_ip"),
            |item| Ok(item.address.to_string()),
        )?
        .parse::<Ipv4Addr>()
    else {
        return Ok(response(503, TEXT, "# PXE address unavailable\n"));
    };
    let Some(disks) = job.disk_lines() else {
        return Ok(response(422, TEXT, "# Invalid wipe targets\n"));
    };
    if !install::valid_token(&action_token)
        || !matches!(job.after.as_str(), "reboot" | "poweroff")
        || !job.chain_accepted(&tx, &mac)?
    {
        return Ok(response(
            422,
            TEXT,
            "# Invalid wipe action or installation plan\n",
        ));
    }
    let token = Session {
        machine: job.machine,
        action,
        mac: &mac,
        menu: MENU,
        ip,
    }
    .issue(&tx)?;
    let mut rendered = SCRIPT.to_owned();
    for (field, value) in [
        ("__PXE_IP__", server.to_string()),
        ("__MAC__", mac),
        ("__WIPE_ID__", job.id.to_string()),
        ("__ACTION_TOKEN__", action_token),
        ("__BOOT_TOKEN__", token),
        ("__ACTION_ID__", action.to_string()),
        ("__ACTION_TYPE__", kind),
        ("__POST_ACTION__", job.after),
        ("__DISK_LIST__", disks),
    ] {
        rendered = rendered.replace(field, &value);
    }
    tx.execute(
        "UPDATE wipes SET wipe_status='running' WHERE id=?1 AND wipe_status='pending'",
        [job.id],
    )?;
    tx.commit()?;
    Ok(response(200, "text/x-shellscript; charset=utf-8", rendered)
        .with_header(header("Cache-Control", "no-store")))
}

fn end(
    db: &Connection,
    job: &Job,
    mac: &str,
    reported: &str,
    action: i64,
) -> rusqlite::Result<Option<Value>> {
    let success = reported != "failed";
    if success && !job.chain_accepted(db, mac)? {
        return Ok(None);
    }
    let status = if success { "success" } else { "failed" };
    db.execute(
        "UPDATE wipes SET wipe_status=?2,ended_at=CURRENT_TIMESTAMP WHERE id=?1",
        params![job.id, status],
    )?;
    install::recompute(db, action)?;
    let old: String = db.query_row(
        "SELECT status FROM machines WHERE id=?1",
        [job.machine],
        |row| row.get(0),
    )?;
    if success && is_php_array(&job.chain["install_config"]) {
        let name = php_string(&job.chain["hostname"]);
        let domain = job.chain["domain"].as_str();
        db.execute(
            "UPDATE machines SET hostname=COALESCE(NULLIF(?2,''),hostname),domain=?3,
                   install_config_json=?4,next_action='reboot' WHERE id=?1",
            params![
                job.machine,
                name,
                domain,
                job.chain["install_config"].to_string()
            ],
        )?;
        set_machine_status(db, job.machine, &old, "configured")?;
        log_event(
            db,
            job.machine,
            "action",
            "Wipe terminé · installation programmée pour le prochain boot (chain)",
            None,
            None,
        )?;
        return Ok(Some(
            json!({"status":"ok","wipe_id":job.id,"machine_status":"configured","chain":"consumed"}),
        ));
    }
    let state = if success { "wiped" } else { "failed" };
    set_machine_status(db, job.machine, &old, state)?;
    Ok(Some(
        json!({"status":"ok","wipe_id":job.id,"machine_status":state}),
    ))
}
