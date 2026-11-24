// SPDX-License-Identifier: LGPL-3.0-only

use crate::{connect, migrations, preseed, pxe, setting};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use std::{
    env,
    error::Error,
    io::Read,
    net::{Ipv4Addr, UdpSocket},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

type ErrorBox = Box<dyn Error + Send + Sync>;

#[derive(Clone, Copy)]
enum Power {
    Reboot,
    Shutdown,
}

impl Power {
    fn command(self) -> &'static str {
        match self {
            Self::Reboot => "sudo systemctl reboot",
            Self::Shutdown => "sudo systemctl poweroff",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Reboot => "Redémarrage",
            Self::Shutdown => "Arrêt",
        }
    }
}

struct Target {
    mac: String,
    action: Option<i64>,
    peer: Option<Ipv4Addr>,
    subnet: String,
    user: String,
}

pub(crate) fn run(database: &Path, id: i64) -> Result<(), ErrorBox> {
    if id <= 0 || !database.is_absolute() {
        return Err("Expected a positive job ID and absolute worker database".into());
    }
    let mut db = connect(
        database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let kind: Option<String> = tx
        .query_row(
            "SELECT job_type FROM init_jobs WHERE id=?1 AND status='pending'",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(kind) = kind else {
        return Ok(());
    };
    let (power, action, raw) = if let Some(raw) = kind.strip_prefix("action:reboot:") {
        (Power::Reboot, true, raw)
    } else if let Some(raw) = kind.strip_prefix("machine:reboot:") {
        (Power::Reboot, false, raw)
    } else if let Some(raw) = kind.strip_prefix("machine:shutdown:") {
        (Power::Shutdown, false, raw)
    } else {
        return Err("Unsupported power job".into());
    };
    let subject = raw.parse::<i64>().ok().filter(|id| *id > 0);
    let key = if action {
        "SELECT m.id,m.mac,m.install_config_json FROM machines m JOIN actions a ON a.machine_id=m.id
         WHERE a.id=?1 AND a.status IN ('pending','running')"
    } else {
        "SELECT id,mac,install_config_json FROM machines WHERE id=?1"
    };
    let machine = tx
        .query_row(key, [subject], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })
        .optional()?;
    let Some((machine, mac, config)) = machine else {
        tx.execute(
            "UPDATE init_jobs SET status='failed', ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,
             message='Appareil introuvable ou action clôturée' WHERE id=?1", [id],
        )?;
        tx.commit()?;
        return Ok(());
    };
    let target = Target {
        mac,
        action: subject.filter(|_| action),
        peer: last_address(&tx, machine, config.as_deref())?,
        subnet: setting(&tx, "pxe_subnet")?,
        user: setting(&tx, "ansible_target_user")?,
    };
    tx.execute(
        "UPDATE init_jobs SET status='running',started_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?1",
        [id],
    )?;
    tx.commit()?;
    let (success, message, event) = execute(power, &target);
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE init_jobs SET status=?2,message=?3,ended_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP
         WHERE id=?1 AND status='running'",
        params![id,if success { "success" } else { "failed" },message],
    )? > 0 {
        pxe::log_event(&tx,machine,if success { "action" } else { "warning" }, &event,None,target.action)?;
    }
    tx.commit()?;
    Ok(())
}

fn execute(power: Power, target: &Target) -> (bool, String, String) {
    let name = power.description();
    let problem = match target.peer {
        Some(peer) => match ssh(power, peer, &target.user) {
            Ok(()) => {
                let message = format!("{name} SSH déclenché vers {peer}");
                return (true, message.clone(), format!("{message} via worker"));
            }
            Err(error) => error,
        },
        None => "IP inconnue".to_owned(),
    };
    if matches!(power, Power::Shutdown) {
        return (
            false,
            format!("SSH KO ({problem})"),
            format!("Échec arrêt SSH via worker ({problem})"),
        );
    }
    if wake(&target.mac, &target.subnet) {
        return (
            true,
            format!("WoL envoyé à {} ({problem})", target.mac),
            "Magic packet WoL envoyé via worker".into(),
        );
    }
    (
        false,
        format!("SSH KO ({problem}) et WoL échec"),
        "Échec redémarrage SSH + WoL via worker".into(),
    )
}

fn last_address(
    db: &Connection,
    machine: i64,
    config: Option<&str>,
) -> rusqlite::Result<Option<Ipv4Addr>> {
    let event = db.query_row(
        "SELECT message FROM machine_events WHERE machine_id=?1 AND checkpoint IN
         ('dhcp_request_install','dhcp_request_wipe','dhcp_request_disktest') ORDER BY id DESC LIMIT 1",
        [machine],|row|row.get::<_,String>(0),
    ).optional()?;
    let known = event
        .as_deref()
        .and_then(|line| line.find('{').map(|start| &line[start..]))
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let snapshot = config
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    Ok(known
        .as_ref()
        .and_then(|data| ipv4(&data["dhcp_ip"]))
        .or_else(|| static_ip(&snapshot)))
}

fn ipv4(value: &Value) -> Option<Ipv4Addr> {
    let result: Ipv4Addr = value.as_str()?.trim().parse().ok()?;
    (!result.is_unspecified()
        && !result.is_multicast()
        && !result.is_broadcast()
        && !result.is_loopback())
    .then_some(result)
}

fn static_ip(config: &Value) -> Option<Ipv4Addr> {
    let network = &config["network"];
    if let Some(interfaces) = network["interfaces"]
        .as_array()
        .filter(|items| !items.is_empty())
    {
        let index = migrations::integer(&network["primary"]).unwrap_or(0);
        let primary = interfaces.get(usize::try_from(index).ok()?)?;
        let bond = &primary["bond"]["name"];
        let primary = if bond.is_string() {
            interfaces
                .iter()
                .find(|iface| iface["bond"]["name"] == *bond && iface["bond"]["role"] == "master")
                .unwrap_or(primary)
        } else {
            primary
        };
        return (primary["mode"] == "static")
            .then(|| ipv4(&primary["static"]["ip"]))
            .flatten();
    }
    (config["network_mode"] == "static")
        .then(|| ipv4(&config["static_ip"]))
        .flatten()
}

fn ssh(power: Power, peer: Ipv4Addr, raw_user: &str) -> Result<(), String> {
    let user = if raw_user.trim().is_empty() {
        "ansible"
    } else {
        raw_user.trim()
    };
    if !preseed::technical_account(user) {
        return Err("nom du compte technique invalide".into());
    }
    let key = env::var_os("PXE_ANSIBLE_HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/ansible"))
        .join(".ssh/ansible_automation");
    let mut child = Command::new("ssh")
        .arg("-i")
        .arg(&key)
        .args([
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
        ])
        .arg(format!("{user}@{peer}"))
        .arg(power.command())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|_| "ssh indisponible".to_owned())?;
    let stderr = child.stderr.take().expect("configured piped stderr");
    let (sender, reader) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stderr.take(8192).read_to_end(&mut output);
        let _ = sender.send(output);
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            _ => {
                // SSH and its optional local helper share a dedicated process group.
                unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                let _ = child.wait();
                return Err("ssh timeout".into());
            }
        }
    };
    if status.success() {
        return Ok(());
    }
    let output = reader
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_default();
    let output = String::from_utf8_lossy(&output);
    let lowered = output.to_ascii_lowercase();
    if status.code() == Some(255)
        && [
            "closed by remote host",
            "connection reset by peer",
            "broken pipe",
        ]
        .iter()
        .any(|diagnostic| lowered.contains(diagnostic))
    {
        return Err("session SSH interrompue, résultat non confirmé".into());
    }
    let clean = output
        .lines()
        .filter(|line| !line.starts_with("debug"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .replace(key.to_string_lossy().as_ref(), "<key>");
    Err(if clean.is_empty() {
        format!("ssh {status}")
    } else {
        clean
    })
}

fn wake(mac: &str, subnet: &str) -> bool {
    let Some(packet) = packet(mac) else {
        return false;
    };
    let Some((network, mask)) =
        pxe::parse_subnet(subnet.trim()).filter(|(_, mask)| mask.count_ones() < 31)
    else {
        return false;
    };
    let destination = Ipv4Addr::from(network | !mask);
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| {
            socket.set_broadcast(true)?;
            socket.send_to(&packet, (destination, 9))
        })
        .is_ok()
}

fn packet(mac: &str) -> Option<[u8; 102]> {
    let mac = pxe::normalize_mac(mac)?;
    let mut decoded = [0_u8; 6];
    for (index, part) in mac.split(':').enumerate() {
        decoded[index] = u8::from_str_radix(part, 16).ok()?;
    }
    let mut packet = [0xff; 102];
    for part in packet[6..].chunks_exact_mut(6) {
        part.copy_from_slice(&decoded);
    }
    Some(packet)
}
