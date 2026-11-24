// SPDX-License-Identifier: LGPL-3.0-only

use super::{
    agent::{Input, Session},
    array_values, client_in_subnet, is_php_array, log_event, machine_for_mac, normalize_mac,
    set_machine_status,
};
use crate::{
    arg, bearer, decimal, disk_identity::serial, failure, header, install, json_response,
    php_string, read_body, request_header, setting, ApiResult, HttpResponse, PxeRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};

const MENU: &str = "disktest";
const SMART_LIMIT: usize = 1_048_576;

pub(crate) fn serve(
    db: &mut Connection,
    ip: Option<IpAddr>,
    route: &str,
    query: &str,
    request: &mut PxeRequest<'_>,
) -> rusqlite::Result<HttpResponse> {
    let token = bearer(request).to_owned();
    let is_form = request_header(request, "Content-Type").is_some_and(|raw| {
        raw.split(';').next().is_some_and(|kind| {
            kind.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    });
    let body = match read_body(request, SMART_LIMIT + 1) {
        Ok(body) => body,
        Err(_) => return json_response(failure(400, "invalid request body")),
    };
    let values = Input::new(query, &body, is_form);
    let test = decimal(values.get("test_id"));
    let peer = match ip {
        Some(IpAddr::V4(peer)) if client_in_subnet(peer, &setting(db, "pxe_subnet")?) => Some(peer),
        _ => None,
    };
    if route == "/api/disktest-job" {
        let Some(ip) = peer else {
            return json_response(failure(404, "not found"));
        };
        return Ok(json_response(start(db, ip, values.get("mac"))?)?
            .with_header(header("Cache-Control", "no-store")));
    }
    if test <= 0 {
        return json_response(match route {
            "/api/disktest-progress" => ok("debug_ack"),
            "/api/disktest-disk-progress" => ok("ignored"),
            _ => failure(400, "test_id required"),
        });
    }

    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(job) = Job::get(&tx, test)? else {
        return json_response(if route == "/api/disktest-disk-progress" {
            ok("ignored")
        } else {
            failure(404, "test not found")
        });
    };
    if route == "/api/disktest-disk-progress" && !job.active() {
        return json_response(ok("ignored"));
    }
    let Some((ip, mac)) = peer.zip(normalize_mac(values.get("mac"))) else {
        return json_response(failure(404, "not found"));
    };
    let Some(session) = job.session(&tx, ip, &mac)? else {
        return json_response(failure(404, "not found"));
    };
    if !session.authorized(&tx, &token)? {
        return json_response(failure(404, "not found"));
    }
    let result = match route {
        "/api/disktest-progress" => progress(&tx, &job, &values),
        "/api/disktest-disk-progress" => disk_progress(&tx, &job, &values),
        "/api/disktest-result" => result(&tx, &job, &values),
        "/api/disktest-smart" => smart(&tx, &job, &values),
        "/api/disktest-end" => end(&tx, &job, values.get("status")),
        _ => unreachable!(),
    }?;
    tx.commit()?;
    json_response(Ok(result))
}

struct Job {
    id: i64,
    machine: i64,
    action: Option<i64>,
    status: String,
    jobs: Value,
    parallel: bool,
    after: String,
    in_session: bool,
}
impl Job {
    fn get(db: &Connection, id: i64) -> rusqlite::Result<Option<Self>> {
        db.query_row(
            "SELECT machine_id,action_id,job_status,jobs_json,parallel,post_action,in_session FROM disk_tests WHERE id=?1",[id],
            |row|Ok(Self {
                id,machine:row.get(0)?,action:row.get(1)?,status:row.get(2)?,
                jobs:serde_json::from_str(&row.get::<_,String>(3)?).unwrap_or_default(),
                parallel:row.get::<_,i64>(4)?==1,
                after:row.get::<_,Option<String>>(5)?.unwrap_or_else(||"poweroff".to_owned()),
                in_session:row.get::<_,i64>(6)?==1,
            }),
        ).optional()
    }
    fn active(&self) -> bool {
        matches!(self.status.as_str(), "pending" | "running")
    }
    fn session<'a>(
        &self,
        db: &Connection,
        ip: Ipv4Addr,
        mac: &'a str,
    ) -> rusqlite::Result<Option<Session<'a>>> {
        let Some(action) = self.action.filter(|_| self.active()) else {
            return Ok(None);
        };
        let allowed: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM actions WHERE id=?1 AND machine_id=?2
             AND type='disktest' AND status IN ('pending','running'))",
            params![action, self.machine],
            |row| row.get(0),
        )?;
        Ok(allowed.then_some(Session {
            machine: self.machine,
            action,
            mac,
            menu: MENU,
            ip,
        }))
    }
}

fn start(db: &mut Connection, ip: Ipv4Addr, raw_mac: &str) -> rusqlite::Result<ApiResult> {
    let Some(mac) = normalize_mac(raw_mac) else {
        return Ok(failure(400, "mac required"));
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = machine_for_mac(&tx, &mac)? else {
        return Ok(failure(404, "no active disk test job"));
    };
    let active = tx.query_row(
        "SELECT id FROM disk_tests WHERE machine_id=?1 AND job_status IN ('pending','running') ORDER BY id DESC LIMIT 1",
        [machine],|row|row.get::<_,i64>(0),
    ).optional()?;
    let Some(active) = active else {
        return Ok(failure(404, "no active disk test job"));
    };
    let Some(job) = Job::get(&tx, active)? else {
        return Ok(failure(404, "no active disk test job"));
    };
    let Some(session) = job.session(&tx, ip, &mac)? else {
        return Ok(failure(404, "not found"));
    };
    if deferred_installation(&tx, job.machine)? {
        return Ok(failure(
            409,
            "automatic installation after disk qualification unavailable",
        ));
    }
    let token = session.issue(&tx)?;
    if job.status == "pending" {
        tx.execute(
            "UPDATE disk_tests SET job_status='running' WHERE id=?1",
            [job.id],
        )?;
        tx.execute(
            "UPDATE actions SET status='running',ended_at=NULL WHERE id=?1 AND status='pending'",
            [session.action],
        )?;
        log_event(
            &tx,
            machine,
            "action",
            "Tests des disques démarrés",
            Some("disktest_started"),
            Some(session.action),
        )?;
    }
    let jobs: Vec<_> = array_values(&job.jobs)
        .map(|entry| {
            json!({
                "disk":php_string(&entry["disk"]),"mode":php_string(&entry["mode"]),
                "serial_b64":job_serial(entry).map(|id|STANDARD.encode(id)).unwrap_or_default(),
            })
        })
        .collect();
    tx.commit()?;
    Ok(Ok((
        200,
        json!({"test_id":job.id,"action_id":session.action,"boot_token":token,
        "parallel":job.parallel,"jobs":jobs,"post_action":job.after}),
    )))
}

fn progress(db: &Connection, job: &Job, input: &Input<'_>) -> ApiResult {
    let line = input.log_line();
    if !line.is_empty() {
        db.execute(
            "UPDATE disk_tests SET log=COALESCE(log,'') || ?2 WHERE id=?1",
            params![job.id, line],
        )?;
    }
    ok("ok")
}

fn disk_progress(db: &Connection, job: &Job, input: &Input<'_>) -> ApiResult {
    let disk = percent_encoding::percent_decode_str(input.get("disk")).decode_utf8_lossy();
    let Some(entry) = array_values(&job.jobs).find(|entry| entry["disk"].as_str() == Some(&disk))
    else {
        return ok("ignored");
    };
    let phase = input.get("phase");
    let phase = if (1..=24).contains(&phase.len())
        && phase
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        phase
    } else {
        ""
    };
    let pass = arg(&input.query, "pass")
        .or_else(|| arg(&input.form, "pass"))
        .unwrap_or("1");
    let clamp = |value: &str| decimal(value).clamp(0, 2_764_800);
    let eta = input.get("eta");
    let state = stored(
        db,
        job.id,
        "SELECT progress_json FROM disk_tests WHERE id=?1",
    )?;
    let mut state = state.as_object().cloned().unwrap_or_default();
    state.insert(disk.into_owned(),json!({
        "mode":php_string(&entry["mode"]),"phase":phase,"pass":decimal(pass).clamp(0,99),
        "pct":decimal(input.get("pct")).clamp(0,100),"bad":decimal(input.get("bad")).clamp(0,1_000_000_000),
        "elapsed_s":clamp(input.get("elapsed")),"eta_s":(!eta.is_empty()).then(||clamp(eta)),
        "updated_at":timestamp(db)?,
    }));
    db.execute(
        "UPDATE disk_tests SET progress_json=?2 WHERE id=?1",
        params![job.id, Value::Object(state).to_string()],
    )?;
    ok("ok")
}

fn result(db: &Connection, job: &Job, input: &Input<'_>) -> ApiResult {
    let mut payload = serde_json::from_slice::<Value>(input.body)
        .ok()
        .filter(is_php_array);
    let raw = payload.take().unwrap_or_else(|| {
        Value::Object(
            input
                .form
                .iter()
                .chain(input.query.iter())
                .map(|(key, value)| (key.clone(), json!(value)))
                .collect(),
        )
    });
    let disk = php_string(&raw["disk"]);
    let mode = php_string(&raw["mode"]);
    if disk.is_empty() || mode.is_empty() {
        return failure(400, "disk + mode required");
    }
    if !matches!(
        mode.as_str(),
        "smart_short"
            | "smart_long"
            | "badblocks_quick_ro"
            | "badblocks_fixed_rw"
            | "badblocks_quick_rw"
            | "badblocks_long_rw"
    ) {
        return failure(400, "invalid mode");
    }
    let Some(id) = array_values(&job.jobs)
        .find(|entry| entry["disk"] == disk && entry["mode"] == mode)
        .and_then(job_serial)
    else {
        return failure(409, "known disk + mode with serial required");
    };
    let verdict = raw["verdict"]
        .as_str()
        .filter(|value| matches!(*value, "passed" | "failed"))
        .unwrap_or("unknown");
    let path = raw["device"].as_str().filter(|path| {
        path.strip_prefix("/dev/").is_some_and(|name| {
            (1..=16).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    });
    let number = |field: &str| (!raw[field].is_null()).then(|| decimal(&php_string(&raw[field])));
    let mut received = json!({"disk":disk,"mode":mode,"verdict":verdict,
        "bad_blocks":number("bad_blocks"),"duration_s":number("duration_s"),
        "serial":id,"device":path,"completed_at":timestamp(db)?,
    });
    if evidence(&raw["evidence"]) {
        received["evidence"] = raw["evidence"].clone();
    }
    let old = stored(
        db,
        job.id,
        "SELECT results_json FROM disk_tests WHERE id=?1",
    )?;
    let mut results: Vec<_> = array_values(&old).cloned().collect();
    if let Some(entry) = results
        .iter_mut()
        .find(|entry| entry["disk"] == disk && entry["mode"] == mode)
    {
        *entry = received;
    } else {
        results.push(received);
    }
    db.execute(
        "UPDATE disk_tests SET results_json=?2 WHERE id=?1",
        params![job.id, json!(results).to_string()],
    )?;
    Ok((200, json!({"status":"ok","test_id":job.id})))
}

fn smart(db: &Connection, job: &Job, input: &Input<'_>) -> ApiResult {
    let phase = crate::param(&input.query, "phase");
    if !matches!(phase, "before" | "after") {
        return failure(400, "invalid phase");
    }
    if input.body.len() > SMART_LIMIT {
        return failure(413, "body too large");
    }
    let Ok(raw) = std::str::from_utf8(input.body) else {
        return failure(400, "invalid JSON");
    };
    let Some(payload) = serde_json::from_str::<Value>(raw).ok().filter(is_php_array) else {
        return failure(400, "invalid JSON");
    };
    let disk = crate::param(&input.query, "disk");
    let Some(entry) =
        array_values(&job.jobs).find(|entry| !disk.is_empty() && entry["disk"] == disk)
    else {
        return failure(400, "unknown disk");
    };
    let Some(id) = job_serial(entry) else {
        return failure(409, "job serial required");
    };
    let Some(reported) = payload.get("serial_number") else {
        return failure(409, "serial missing in snapshot");
    };
    if serial(reported).as_deref() != Some(&id) {
        return failure(409, "serial mismatch");
    }
    let device = payload["device"]["name"]
        .as_str()
        .filter(|name| !name.is_empty() && name.len() <= 128);
    db.execute(
        "DELETE FROM disk_smart_snapshots WHERE test_id=?1 AND serial=?2 AND phase=?3",
        params![job.id, id, phase],
    )?;
    db.execute(
        "INSERT INTO disk_smart_snapshots(machine_id,test_id,serial,device,phase,smart_json)
                VALUES(?1,?2,?3,?4,?5,?6)",
        params![job.machine, job.id, id, device, phase, raw],
    )?;
    db.execute(
        "DELETE FROM disk_smart_snapshots WHERE id IN (
                SELECT id FROM disk_smart_snapshots WHERE serial=?1 AND phase=?2
                ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET 20)",
        params![id, phase],
    )?;
    ok("ok")
}

fn end(db: &Connection, job: &Job, reported: &str) -> ApiResult {
    if deferred_installation(db, job.machine)? {
        return failure(
            409,
            "automatic installation after disk qualification unavailable",
        );
    }
    let old: String = db.query_row(
        "SELECT status FROM machines WHERE id=?1",
        [job.machine],
        |row| row.get(0),
    )?;
    let results = stored(
        db,
        job.id,
        "SELECT results_json FROM disk_tests WHERE id=?1",
    )?;
    let expected: Vec<_> = array_values(&job.jobs).collect();
    let mut failed = false;
    let mut incomplete = expected.is_empty();
    for entry in expected {
        let mut matching = array_values(&results)
            .filter(|result| result["disk"] == entry["disk"] && result["mode"] == entry["mode"]);
        if let Some(result) = matching.next() {
            let verified = job_serial(entry)
                .is_some_and(|id| serial(&result["serial"]).as_deref() == Some(&id));
            if verified
                && matching.next().is_none()
                && completed(&php_string(&entry["mode"]), result)
            {
                failed |= result["verdict"] == "failed";
                continue;
            }
        }
        incomplete = true;
    }
    let ok_result = !failed && !incomplete && reported != "failed";
    let status = if ok_result { "success" } else { "failed" };
    let state = if ok_result { "tested" } else { "failed" };
    db.execute(
        "UPDATE disk_tests SET job_status=?2,ended_at=CURRENT_TIMESTAMP WHERE id=?1",
        params![job.id, status],
    )?;
    if let Some(action) = job.action {
        install::recompute(db, action)?;
    }
    let message = if !failed && (incomplete || reported == "failed") {
        "Tests des disques incomplets ou indéterminés"
    } else {
        "Tests des disques terminés"
    };
    log_event(
        db,
        job.machine,
        if ok_result { "action" } else { "error" },
        message,
        Some("disktest_finished"),
        job.action,
    )?;
    log_event(
        db,
        job.machine,
        "info",
        "Résultats des tests disponibles",
        Some("disktest_results_posted"),
        job.action,
    )?;
    set_machine_status(db, job.machine, &old, state)?;
    if job.after == "wait" && job.in_session {
        db.execute(
            "UPDATE machines SET awaiting_action_until=datetime('now','+1 hour') WHERE id=?1",
            [job.machine],
        )?;
    }
    Ok((
        200,
        json!({"status":"ok","test_id":job.id,"machine_status":state,"post_action":job.after}),
    ))
}

fn deferred_installation(db: &Connection, machine: i64) -> rusqlite::Result<bool> {
    let config: Option<String> = db.query_row(
        "SELECT install_config_json FROM machines WHERE id=?1",
        [machine],
        |row| row.get(0),
    )?;
    let config: Value = config
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    let deferred = crate::migrations::integer(&config["_pending_action_id"]).unwrap_or_default();
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM actions WHERE id=?1 AND machine_id=?2 AND type='install_only' AND status='pending')",
        params![deferred,machine],|row|row.get(0),
    )
}

fn completed(mode: &str, result: &Value) -> bool {
    let outcome = &result["verdict"];
    let data = &result["evidence"];
    let passed = outcome == "passed";
    if !(passed || outcome == "failed") || !evidence(data) || data["status"] != "completed" {
        return false;
    }
    if matches!(mode, "smart_short" | "smart_long") {
        let direction = if mode == "smart_long" {
            "long"
        } else {
            "short"
        };
        return data["tool"] == "smartctl"
            && data["type"] == direction
            && data["start_exit_code"]
                .as_i64()
                .is_some_and(|rc| rc >= 0 && rc & 7 == 0)
            && (data["new_entry"] == true || data["seen_running"] == true)
            && data["passed"].as_bool() == Some(passed);
    }
    let patterns = match mode {
        "badblocks_fixed_rw" => json!(["0xaa"]),
        "badblocks_quick_rw" => json!(["random"]),
        "badblocks_long_rw" => json!(["0xaa", "0x55"]),
        "badblocks_quick_ro" | "badblocks_long_ro" => json!([]),
        _ => return false,
    };
    let phase_count = patterns.as_array().expect("known patterns").len() as u64;
    let passes = if mode == "badblocks_long_ro" { 4 } else { 1 };
    let errors = data["errors"].as_u64();
    let blocks = data["bad_blocks"].as_u64();
    data["tool"] == "badblocks"
        && data["exit_code"].as_i64() == Some(0)
        && data["pass_completed"] == true
        && data["passes_completed"]
            .as_u64()
            .is_some_and(|count| count >= passes)
        && data["patterns"] == patterns
        && data["write_phases"].as_u64() == Some(phase_count)
        && data["verify_phases"].as_u64() == Some(phase_count)
        && errors.is_some()
        && blocks.is_some()
        && data
            .get("stalls")
            .is_some_and(|stalls| stalls.is_null() || is_php_array(stalls))
        && (errors == Some(0) && blocks == Some(0)) == passed
}

fn evidence(value: &Value) -> bool {
    value["schema"].as_i64() == Some(1)
        && matches!(value["tool"].as_str(), Some("badblocks" | "smartctl"))
        && serde_json::to_vec(value).is_ok_and(|data| data.len() <= 16_384)
}
fn job_serial(value: &Value) -> Option<String> {
    let identity = &value["identity"];
    (identity["kind"] == "serial" && identity["status"].as_str().unwrap_or("valid") == "valid")
        .then(|| serial(&identity["value"]))
        .flatten()
}
fn timestamp(db: &Connection) -> rusqlite::Result<String> {
    db.query_row(
        "SELECT strftime('%Y-%m-%dT%H:%M:%S+00:00','now')",
        [],
        |row| row.get(0),
    )
}
fn stored(db: &Connection, id: i64, statement: &str) -> rusqlite::Result<Value> {
    let raw: Option<String> = db.query_row(statement, [id], |row| row.get(0))?;
    Ok(raw
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default())
}
fn ok(status: &str) -> ApiResult {
    Ok((200, json!({"status":status})))
}
