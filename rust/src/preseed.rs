// SPDX-License-Identifier: LGPL-3.0-only

mod network;
mod partition;
pub(crate) use partition::whole_disk;

use crate::install::{self, Machine};
use crate::pxe::{array_values, is_php_array, log_event, normalize_mac, parse_subnet};
use crate::{header, php_string, php_trim, php_truthy, response, setting, HttpResponse, TEXT};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{Connection, TransactionBehavior};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

const BASE: &str = include_str!("../../docker/worker/templates/preseed-base.cfg.j2");
const DISK_GUARD: &str = include_str!(concat!(env!("OUT_DIR"), "/disk-guard.sh"));
const FIRST_BOOT: &str = include_str!(concat!(env!("OUT_DIR"), "/first-boot.sh"));
const INSTALL_LOG: &str = include_str!(concat!(env!("OUT_DIR"), "/install-log.sh"));
const TARGET_HOSTNAME: &str = include_str!(concat!(env!("OUT_DIR"), "/target-hostname.sh"));
pub fn serve(
    db: &mut Connection,
    source: Option<Ipv4Addr>,
    raw_mac: &str,
) -> rusqlite::Result<HttpResponse> {
    let subnet = setting(db, "pxe_subnet")?;
    let Some((network, mask)) = parse_subnet(&subnet) else {
        return Ok(reply(
            503,
            "# ERREUR : sous-réseau PXE non configuré ou invalide\n",
        ));
    };
    if source.is_none_or(|ip| u32::from(ip) & mask != network) {
        return Ok(reply(
            403,
            "# ERREUR : accès refusé (hôte hors subnet PXE)\n",
        ));
    }
    let Some(mac) = normalize_mac(raw_mac) else {
        return Ok(reply(400, "# ERREUR : MAC manquante (?mac=...)\n"));
    };
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(machine) = install::machine(&tx, raw_mac, false)? else {
        return Ok(reply(
            404,
            format!("# ERREUR : machine introuvable pour MAC {mac}\n"),
        ));
    };
    let Some(raw) = machine
        .config
        .as_deref()
        .filter(|raw| !matches!(*raw, "" | "0"))
    else {
        return Ok(reply(404, format!("# ERREUR : machine {mac} sans config d'install (passer par /machines/{{id}}/install d'abord)\n")));
    };
    let config: Value = match serde_json::from_str(raw) {
        Ok(config) if is_php_array(&config) => config,
        _ => {
            return Ok(reply(
                500,
                format!("# ERREUR : install_config_json corrompu pour MAC {mac}\n"),
            ))
        }
    };
    let action = install::latest_action(&tx, machine.id)?;
    let action_id = action.as_ref().map(|(id, _)| *id);
    if !install::eligible(&tx, &machine, action_id)?
        || install::installation_closed(&tx, machine.id, action_id)?
    {
        return Ok(reply(404, ""));
    }

    let pxe_server = setting(&tx, "pxe_ip")?;
    let Ok(pxe_server) = pxe_server.parse::<Ipv4Addr>() else {
        return Ok(reply(
            503,
            "# ERREUR : adresse PXE du serveur indisponible\n",
        ));
    };
    if action
        .as_ref()
        .is_some_and(|(_, token)| !install::valid_token(token))
    {
        return Ok(reply(503, "# ERREUR : jeton d'action invalide\n"));
    }
    let seed = match Profile::new(&tx, &machine, &config) {
        Ok(profile) => profile,
        Err(ProfileError::Db(error)) => return Err(error),
        Err(ProfileError::Invalid(reason)) => {
            return Ok(reply(422, format!("# ERREUR : {reason}\n")))
        }
    };
    let start_action = install::snapshot_action(&tx, &machine, &config)?;
    // A snapshot can lag behind an action change. A distinct active action must
    // never receive an install ID, installer credentials, or a log callback.
    if start_action != action_id || install::other_active_install(&tx, machine.id, action_id)? {
        return Ok(reply(404, ""));
    }
    let install = install::start_row(&tx, &machine, action_id)?;
    if let Some(action) = action_id {
        log_event(
            &tx,
            machine.id,
            "info",
            "checkpoint:preseed_loaded_install",
            Some("preseed_loaded_install"),
            Some(action),
        )?;
    }
    install::ping_phase(&tx, "install", install, "preseed-loaded", "success", None)?;
    let body = seed.render(&machine.mac, pxe_server, install, action.as_ref());
    tx.commit()?;
    Ok(reply(200, body))
}

fn reply(status: u16, body: impl Into<String>) -> HttpResponse {
    response(status, TEXT, body).with_header(header("Cache-Control", "no-store"))
}

enum ProfileError {
    Invalid(&'static str),
    Db(rusqlite::Error),
}
impl From<rusqlite::Error> for ProfileError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

pub(crate) fn validate_plan(
    db: &Connection,
    machine: &Machine,
    config: &Value,
) -> rusqlite::Result<Result<(), &'static str>> {
    match Profile::new(db, machine, config) {
        Ok(_) => Ok(Ok(())),
        Err(ProfileError::Invalid(message)) => Ok(Err(message)),
        Err(ProfileError::Db(error)) => Err(error),
    }
}

struct Profile {
    hostname: String,
    domain: String,
    distro: String,
    network: network::Network,
    partitions: partition::Layout,
    bootdev: String,
    user: String,
    fullname: String,
    groups: String,
    user_hash: String,
    root_hash: String,
    user_keys: Vec<String>,
    remote_keys: Vec<String>,
    ansible_requested: bool,
    ansible: Option<(String, String)>,
    advanced: Value,
}

impl Profile {
    fn new(db: &Connection, machine: &Machine, config: &Value) -> Result<Self, ProfileError> {
        let invalid = ProfileError::Invalid;
        let distro = distro_codename(config);
        if !matches!(
            distro.as_str(),
            "bullseye" | "bookworm" | "trixie" | "forky"
        ) || !matches!(
            config["distro"].as_str(),
            None | Some("" | "debian" | "bullseye" | "bookworm" | "trixie" | "forky")
        ) || !matches!(config["variant"].as_str(), None | Some("" | "debian"))
        {
            return Err(invalid(
                "distribution non prise en charge par le preseed Rust.",
            ));
        }
        let net = network::Network::new(config)
            .ok_or_else(|| invalid("plan réseau non pris en charge par le preseed Rust."))?;
        let partitions = partition::Layout::new(config).map_err(invalid)?;
        let advanced = if is_php_array(&config["advanced"]) {
            config["advanced"].clone()
        } else {
            config["advanced_config_json"]
                .as_str()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default()
        };
        let bootdev = fallback(&advanced["bootloader"]["bootdev"], "default");
        if bootdev != "default" && !partitions.contains_disk(&bootdev) {
            return Err(invalid(
                "la cible GRUB doit correspondre au disque vérifié.",
            ));
        }
        let hostname = sanitize_name(
            override_text(config, "hostname", machine.hostname.as_deref()),
            false,
        );
        let domain = sanitize_name(
            override_text(config, "domain", machine.domain.as_deref()),
            true,
        );
        let user = filter_user(
            &php_string(&config["admin_user_login"]).to_ascii_lowercase(),
            false,
        );
        let user = if user.is_empty() {
            "admin".into()
        } else {
            user
        };
        let groups = filter_user(&php_string(&config["admin_user_groups"]), true);
        let groups = if groups.is_empty() {
            "sudo".into()
        } else {
            groups
        };
        let fullname = php_trim(config["admin_user_fullname"].as_str().unwrap_or_default());
        let fullname = if fullname.is_empty() {
            user.clone()
        } else {
            fullname.to_string()
        };
        let user_hash = sanitized_hash(config["admin_user_pwhash"].as_str().unwrap_or_default())
            .ok_or_else(|| invalid("hash du compte administrateur invalide."))?;
        let root = if config["root_login_mode"] == "disabled" {
            ""
        } else {
            override_text(config, "root_password_hash", machine.root_hash.as_deref())
        };
        let root_hash =
            sanitized_hash(root).ok_or_else(|| invalid("hash du compte root invalide."))?;
        let user_keys: Vec<String> = config["admin_user_pubkeys"]
            .as_str()
            .unwrap_or_default()
            .lines()
            .map(php_trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        let remote_keys = array_values(&advanced["post_install"]["remote_pubkey_urls"])
            .filter_map(|item| {
                let url = php_trim(
                    item.as_str()
                        .or_else(|| item["url"].as_str())
                        .unwrap_or_default(),
                );
                let path = url.strip_prefix("https://")?;
                (!path.is_empty()
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._~/:?=&@-+%".contains(&b)))
                .then(|| url.to_owned())
            })
            .collect();
        let ansible_requested = config["ansible_role"]
            .as_str()
            .is_some_and(|role| !php_trim(role).is_empty())
            && setting(db, "ansible_enabled")? == "on";
        let ansible = if ansible_requested {
            let key = setting(db, "ansible_ssh_pubkey")?;
            let key = php_trim(&key);
            if !key.is_empty() && !public_key(key) {
                return Err(invalid("clé publique du module Ansible invalide."));
            }
            let technical = setting(db, "ansible_target_user")?;
            let technical = php_trim(&technical);
            let technical = if technical.is_empty() {
                "ansible"
            } else {
                technical
            };
            if !technical_account(technical) {
                return Err(invalid(
                    "nom du compte technique du module Ansible invalide.",
                ));
            }
            (!key.is_empty()).then(|| (technical.to_owned(), key.to_owned()))
        } else {
            None
        };
        Ok(Self {
            hostname,
            domain,
            distro,
            network: net,
            partitions,
            bootdev,
            user,
            fullname,
            groups,
            user_hash,
            root_hash,
            user_keys,
            remote_keys,
            ansible_requested,
            ansible,
            advanced,
        })
    }

    fn render(
        &self,
        mac: &str,
        pxe: Ipv4Addr,
        install: i64,
        action: Option<&(i64, String)>,
    ) -> String {
        let mut early = Vec::new();
        if self.distro == "trixie" {
            early.push(r#"if [ -d /sys/firmware/efi ]; then case "$(uname -m)" in x86_64) pxe_signed=grub-efi-amd64-signed ;; aarch64) pxe_signed=grub-efi-arm64-signed ;; *) pxe_signed= ;; esac; if [ -n "$pxe_signed" ]; then pxe_pkgs="$(debconf-get pkgsel/include)" || exit 1; debconf-set pkgsel/include "$pxe_pkgs $pxe_signed shim-signed" || exit 1; fi; fi"#.into());
        }
        let mut late = Vec::new();
        if !self.hostname.is_empty() {
            let fqdn = if self.domain.is_empty() {
                self.hostname.clone()
            } else {
                format!("{}.{}", self.hostname, self.domain)
            };
            let script = TARGET_HOSTNAME
                .replace("__NODE__", &STANDARD.encode(&self.hostname))
                .replace("__FQDN__", &STANDARD.encode(fqdn));
            late.push(format!(
                "printf '%s' '{}' | base64 -d | /bin/sh || exit 1",
                STANDARD.encode(script)
            ));
        }
        let base_url = format!("http://{pxe}");
        let phase_url = format!("{base_url}/api/task-phase?task=install&mac={mac}");
        let phase = |name: &str, status: &str| {
            format!("/usr/bin/wget -q --timeout=5 -O /dev/null '{phase_url}&phase={name}&status={status}' || true")
        };
        for name in [
            "partman-done",
            "base-install-done",
            "apt-setup",
            "tasksel",
            "bootloader",
        ] {
            late.push(phase(name, "success"));
        }
        late.push(phase("late-command", "running"));
        let log_url = format!("{base_url}/api/internal/install-log?install_id={install}");
        if let Some((_, token)) = action {
            let checkpoint = |code| {
                format!("/usr/bin/wget -q --timeout=5 --post-data='' -O /dev/null --header='Authorization: Bearer {token}' '{base_url}/api/internal/checkpoint?mac={mac}&code={code}' || true")
            };
            early.push(format!("echo {} | base64 -d > /tmp/pxe-dilog.sh ; (/bin/sh /tmp/pxe-dilog.sh run '{log_url}' '{token}' </dev/null >/dev/null 2>&1 &)", STANDARD.encode(INSTALL_LOG)));
            early.push(checkpoint("partitioning_started"));
            late.push(checkpoint("late_command_started"));
        }
        self.append_accounts(&mut late);
        let password_auth = if self.user_hash.is_empty() {
            "no"
        } else {
            "yes"
        };
        late.push(format!("in-target /bin/sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication {password_auth}/' /etc/ssh/sshd_config"));
        late.push("in-target /bin/sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config".into());
        if let Some(command) = self.partitions.reserve_blocks() {
            late.push(command);
        }
        let first_boot = action.is_some() && self.ansible_requested;
        if let Some((_, token)) = action.filter(|_| first_boot) {
            let script = FIRST_BOOT
                .replace("__PXE_IP__", &format!("'{pxe}'"))
                .replace("__MAC__", &format!("'{mac}'"))
                .replace("__TOKEN__", &format!("'{token}'"));
            let generator = "/target/etc/systemd/system-generators/pxe-first-boot";
            late.push(format!(
                "/bin/sh -ec 'umask 077; mkdir -p /target/etc/systemd/system-generators; echo {} | base64 -d > {generator}; chmod 0700 {generator}' || exit 1",
                STANDARD.encode(format!("{script}\n"))
            ));
        }
        if !self.network.secondary.is_empty() {
            late.push("in-target /bin/mkdir -p /etc/network/interfaces.d".into());
            late.extend(self.network.secondary.iter().cloned());
        }
        late.push(phase("late-command", "success"));
        late.push(phase("finished", "success"));
        if let Some((_, token)) = action {
            late.push(format!(
                "/bin/sh /tmp/pxe-dilog.sh flush '{log_url}' '{token}' || true"
            ));
            late.push("kill $(cat /tmp/pxe-dilog.pid 2>/dev/null) 2>/dev/null || true".into());
            late.push("ssh_fingerprint=''".into());
            late.push(r#"if [ -r /target/etc/ssh/ssh_host_ed25519_key.pub ]; then ssh_fingerprint=$(in-target /usr/bin/ssh-keygen -E sha256 -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'); fi"#.into());
            late.push(format!(r#"http_status=$(in-target /usr/bin/curl -fsS --connect-timeout 5 --max-time 15 --retry 3 --retry-connrefused --output /dev/null --write-out '%{{http_code}}' --data-urlencode "ssh_host_fingerprint=$ssh_fingerprint" -H 'Authorization: Bearer {token}' '{base_url}/api/install-end?mac={mac}&status=success') || exit 1"#));
            late.push(r#"[ "$http_status" = 200 ] || exit 1"#.into());
        }
        let mut early = commands("preseed/early_command", &early);
        if !early.is_empty() {
            early.push('\n');
        }
        let guard = STANDARD.encode(DISK_GUARD.replace("__BOOTMODE__", self.partitions.firmware));
        early.push_str(&format!("d-i partman/early_command string \\\n    echo {guard} | base64 -d > /tmp/pxe-disk-guard.sh ; /bin/sh /tmp/pxe-disk-guard.sh {} '{phase_url}' '{}' '{base_url}/static-bin/smartctl' {}",
            self.partitions.guard_mode(), self.bootdev, self.partitions.guard_specs()));
        let blocks = [
            ("EARLY_COMMAND_BLOCK", early),
            ("HOSTNAME_BLOCK", self.hostname_block()),
            ("NETWORK_BLOCK", self.network.installer.clone()),
            ("DISTRO_CODENAME", self.distro.clone()),
            ("MIRROR_BLOCK", self.mirror_block()),
            ("LOCALIZATION_BLOCK", self.localization_block()),
            ("CLOCK_BLOCK", self.clock_block()),
            ("ACCOUNTS_BLOCK", self.accounts_block()),
            (
                "PACKAGES_BLOCK",
                self.packages_block(action.is_some(), first_boot),
            ),
            ("APT_BLOCK", self.apt_block()),
            ("BOOTLOADER_BLOCK", self.bootloader_block()),
            ("PARTITION_BLOCK", self.partitions.directives.clone()),
            ("FINISH_BLOCK", self.finish_block()),
            ("ADMIN_USER_BLOCK", commands("preseed/late_command", &late)),
        ];
        substitute(BASE, HashMap::from(blocks))
    }

    fn append_accounts(&self, late: &mut Vec<String>) {
        if let Some((user, key)) = &self.ansible {
            late.push(format!("in-target /usr/sbin/groupadd -f {user}"));
            late.push(format!("in-target /usr/bin/id -u {user} >/dev/null 2>&1 || in-target /usr/sbin/useradd -m -s /bin/bash -g {user} -G sudo {user}"));
            let file = format!("/home/{user}/.ssh/authorized_keys");
            late.push(format!(
                "in-target /usr/bin/install -d -m 0700 -o {user} -g {user} /home/{user}/.ssh"
            ));
            late.push(write_target(&file, format!("{key}\n")));
            late.push(format!("in-target /bin/chown {user}:{user} {file}"));
            late.push(format!("in-target /bin/chmod 0600 {file}"));
            late.push(write_target(
                &format!("/etc/sudoers.d/{user}"),
                format!("{user} ALL=(ALL) NOPASSWD:ALL\n"),
            ));
            late.push(format!("in-target /bin/chmod 0440 /etc/sudoers.d/{user}"));
            late.push(format!(
                "in-target /usr/sbin/visudo -cf /etc/sudoers.d/{user}"
            ));
        }
        let user = &self.user;
        let groups = &self.groups;
        if self.user_hash.is_empty() && self.user_keys.is_empty() {
            return;
        }
        if !self.root_hash.is_empty() {
            late.push(format!(
                "in-target /usr/sbin/useradd -m -s /bin/bash -G {groups} -- {user}"
            ));
            if !self.user_hash.is_empty() {
                let encoded = STANDARD.encode(format!("{user}:{}\n", self.user_hash));
                late.push(format!(
                    "in-target /bin/sh -c 'echo {encoded} | base64 -d | /usr/sbin/chpasswd -e'"
                ));
            }
        }
        if !self.user_keys.is_empty() || !self.remote_keys.is_empty() {
            let file = format!("/home/{user}/.ssh/authorized_keys");
            late.push(format!(
                "in-target /usr/bin/install -d -m 0700 -o {user} -g {user} /home/{user}/.ssh"
            ));
            late.push(write_target(
                &file,
                format!("{}\n", self.user_keys.join("\n")),
            ));
            for url in &self.remote_keys {
                late.push(format!(
                    "in-target /bin/sh -c 'curl -fsSL \"{url}\" >> {file}'"
                ));
            }
            late.push(format!("in-target /bin/chown {user}:{user} {file}"));
            late.push(format!("in-target /bin/chmod 0600 {file}"));
        }
    }

    fn hostname_block(&self) -> String {
        let mut lines = Vec::new();
        if !self.hostname.is_empty() {
            lines.push(format!("d-i netcfg/get_hostname string {}", self.hostname));
        }
        if !self.domain.is_empty() {
            lines.push(format!("d-i netcfg/get_domain string {}", self.domain));
        }
        if !self.hostname.is_empty() {
            lines.push(format!("d-i netcfg/hostname string {}", self.hostname));
        }
        lines.join("\n")
    }

    fn accounts_block(&self) -> String {
        if self.root_hash.is_empty() {
            let pwd = if self.user_hash.is_empty() {
                "!"
            } else {
                &self.user_hash
            };
            format!("d-i passwd/root-login boolean false\nd-i passwd/make-user boolean true\nd-i passwd/user-fullname string {}\nd-i passwd/username string {}\nd-i passwd/user-password-crypted password {pwd}\nd-i passwd/user-default-groups string {}",
                scalar(&self.fullname), self.user, self.groups)
        } else {
            format!("d-i passwd/root-login boolean true\nd-i passwd/root-password-crypted password {}\nd-i passwd/make-user boolean false", self.root_hash)
        }
    }

    fn localization_block(&self) -> String {
        let loc = &self.advanced["localization"];
        let mut block = vec![format!(
            "d-i debian-installer/locale string {}",
            fallback(&loc["locale"], "fr_FR.UTF-8")
        )];
        optional(
            &mut block,
            "d-i debian-installer/language string ",
            &loc["language"],
        );
        optional(
            &mut block,
            "d-i debian-installer/country string ",
            &loc["country"],
        );
        let supported = list(&loc["supported_locales"], &[]);
        if !supported.is_empty() {
            block.push(format!(
                "d-i localechooser/supported-locales multiselect {}",
                supported.join(", ")
            ));
        }
        block.push(format!(
            "d-i keyboard-configuration/xkb-keymap select {}",
            fallback(&loc["keymap"], "fr(latin9)")
        ));
        optional(
            &mut block,
            "d-i keyboard-configuration/toggle select ",
            &loc["keymap_toggle"],
        );
        if !loc["console_ask_detect"].is_null() {
            block.push(format!(
                "d-i console-setup/ask_detect boolean {}",
                php_truthy(&loc["console_ask_detect"])
            ));
        }
        block.join("\n")
    }

    fn mirror_block(&self) -> String {
        let m = &self.advanced["mirror"];
        format!("d-i mirror/country string {}\nd-i mirror/http/hostname string {}\nd-i mirror/http/directory string {}\nd-i mirror/http/proxy string {}",
                fallback(&m["country"], "manual"), fallback(&m["hostname"], "deb.debian.org"),
                fallback(&m["directory"], "/debian"), scalar(&php_string(&m["proxy"])))
    }

    fn clock_block(&self) -> String {
        let tz = &self.advanced["timezone"];
        let ntp = on(tz, "ntp", true);
        let mut block = vec![format!("d-i clock-setup/utc boolean {}\nd-i time/zone string {}\nd-i clock-setup/ntp boolean {ntp}",
            on(tz,"utc",true), fallback(&tz["zone"], "Europe/Paris"))];
        if ntp {
            optional(
                &mut block,
                "d-i clock-setup/ntp-server string ",
                &tz["ntp_server"],
            );
        }
        block.join("\n")
    }

    fn packages_block(&self, tracked: bool, first_boot: bool) -> String {
        let pkg = &self.advanced["packages"];
        let mut lines = vec![format!(
            "d-i base-installer/install-recommends boolean {}",
            on(pkg, "install_recommends", false)
        )];
        let tasksel = list_field(pkg, "tasksel", &["ssh-server", "standard"]);
        if !tasksel.is_empty() {
            lines.push(format!(
                "tasksel tasksel/first multiselect {}",
                tasksel.join(", ")
            ));
        }
        let mut include = list_field(
            pkg,
            "pkgsel_include",
            &[
                "sudo",
                "openssh-server",
                "python3",
                "ca-certificates",
                "curl",
            ],
        );
        include.extend(self.network.packages.iter().copied().map(String::from));
        if tracked {
            include.push("curl".into());
        }
        if first_boot {
            include.push("iproute2".into());
        }
        if self.ansible.is_some() {
            include.extend(["sudo", "openssh-server", "python3"].map(String::from));
        }
        let mut seen = HashSet::new();
        include.retain(|package| seen.insert(package.clone()));
        if !include.is_empty() || self.distro == "trixie" {
            lines.push(format!("d-i pkgsel/include string {}", include.join(" ")));
        }
        if let Some(upgrade) = pkg.get("upgrade") {
            optional(&mut lines, "d-i pkgsel/upgrade select ", upgrade);
        } else {
            lines.push("d-i pkgsel/upgrade select full-upgrade".into());
        }
        optional(
            &mut lines,
            "d-i pkgsel/update-policy select ",
            &pkg["update_policy"],
        );
        lines.push(format!(
            "popularity-contest popularity-contest/participate boolean {}",
            on(pkg, "popcon", false)
        ));
        lines.join("\n")
    }

    fn apt_block(&self) -> String {
        let apt = &self.advanced["apt"];
        let mut block: Vec<_> = [
            ("apt-setup/non-free-firmware", "non_free_firmware", true),
            ("apt-setup/contrib", "contrib", true),
            ("apt-setup/non-free", "non_free", false),
            ("hw-detect/load_firmware", "hw_detect_load_firmware", true),
        ]
        .into_iter()
        .map(|(path, key, default)| format!("d-i {path} boolean {}", on(apt, key, default)))
        .collect();
        if is_php_array(&apt["services_select"]) {
            block.push(format!(
                "d-i apt-setup/services-select multiselect {}",
                list(&apt["services_select"], &[]).join(", ")
            ));
        }
        optional(
            &mut block,
            "d-i apt-setup/security_host string ",
            &apt["security_host"],
        );
        block.join("\n")
    }

    fn bootloader_block(&self) -> String {
        let b = &self.advanced["bootloader"];
        format!("d-i grub-installer/only_debian boolean {}\nd-i grub-installer/with_other_os boolean {}\nd-i grub-installer/bootdev string {}\nd-i grub-installer/force-efi-extra-removable boolean true",
            on(b,"only_debian",true), on(b,"with_other_os",false), self.bootdev)
    }

    fn finish_block(&self) -> String {
        let f = &self.advanced["finish"];
        let mut block = format!(
            "d-i finish-install/reboot_in_progress {}",
            fallback(&f["reboot"], "note")
        );
        if !f["eject_cdrom"].is_null() {
            block.push_str(&format!(
                "\nd-i cdrom-detect/eject boolean {}",
                php_truthy(&f["eject_cdrom"])
            ));
        }
        block
    }
}

fn distro_codename(config: &Value) -> String {
    let named = config["codename"]
        .as_str()
        .map(php_trim)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !named.is_empty() {
        return named;
    }
    let version = config["version_full"]
        .as_str()
        .unwrap_or("")
        .split('.')
        .next()
        .unwrap_or("");
    match crate::decimal(version) {
        11 => "bullseye",
        12 => "bookworm",
        13 => "trixie",
        14 => "forky",
        _ => config["distro"]
            .as_str()
            .filter(|name| matches!(*name, "bullseye" | "bookworm" | "trixie" | "forky"))
            .unwrap_or("trixie"),
    }
    .to_owned()
}

fn scalar(value: &str) -> String {
    value
        .replace(['\r', '\n', '\0'], "")
        .trim_end_matches('\\')
        .to_owned()
}

fn fallback(value: &Value, default: &str) -> String {
    if php_truthy(value) {
        scalar(&php_string(value))
    } else {
        default.to_owned()
    }
}

fn optional(block: &mut Vec<String>, prefix: &str, value: &Value) {
    if php_truthy(value) {
        block.push(format!("{prefix}{}", scalar(&php_string(value))));
    }
}

fn on(section: &Value, name: &str, default: bool) -> bool {
    section.get(name).map_or(default, php_truthy)
}

fn list(value: &Value, default: &[&str]) -> Vec<String> {
    if is_php_array(value) {
        array_values(value)
            .map(|value| scalar(&php_string(value)))
            .filter(|s| !matches!(s.as_str(), "" | "0"))
            .collect()
    } else {
        default.iter().map(|s| s.to_string()).collect()
    }
}

fn list_field(section: &Value, key: &str, default: &[&str]) -> Vec<String> {
    match section.get(key) {
        Some(value) => list(value, &[]),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

fn override_text<'a>(config: &'a Value, field: &str, stored: Option<&'a str>) -> &'a str {
    match config.get(field) {
        Some(value) => value.as_str().unwrap_or_default(),
        None => stored.unwrap_or_default(),
    }
}

fn sanitize_name(raw: &str, dot: bool) -> String {
    php_trim(raw)
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || dot && *c == '.')
        .collect()
}

fn filter_user(raw: &str, comma: bool) -> String {
    raw.chars()
        .filter(|c| {
            c.is_ascii_lowercase()
                || c.is_ascii_digit()
                || matches!(c, '_' | '-')
                || comma && *c == ','
        })
        .collect()
}

pub(crate) fn technical_account(user: &str) -> bool {
    user != "root"
        && user.len() <= 32
        && user
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
        && filter_user(user, false) == user
}

pub(crate) fn sanitized_hash(hash: &str) -> Option<String> {
    hash.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"$./,!_*+=-".contains(&b))
        .then(|| hash.to_owned())
}

fn valid_disk(path: &str) -> bool {
    path.strip_prefix("/dev/").is_some_and(|name| {
        name.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    })
}

fn public_key(key: &str) -> bool {
    let mut parts = key.split_ascii_whitespace();
    let (Some(kind), Some(bytes)) = (parts.next(), parts.next()) else {
        return false;
    };
    let payload = bytes.trim_end_matches('=');
    !key.contains(['\r', '\n'])
        && !payload.is_empty()
        && bytes.len() - payload.len() <= 2
        && payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        && (matches!(kind, "ssh-rsa" | "ssh-ed25519" | "ssh-dss")
            || kind.strip_prefix("ecdsa-sha2-").is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }))
}

fn write_target(file: &str, text: impl AsRef<[u8]>) -> String {
    format!(
        "in-target /bin/sh -c 'echo {} | base64 -d > {file}'",
        STANDARD.encode(text)
    )
}

fn commands(phase: &str, commands: &[String]) -> String {
    if commands.is_empty() {
        return String::new();
    }
    format!(
        "d-i {phase} string \\\n    {}",
        commands.join(" ; \\\n    ")
    )
}

fn substitute(template: &str, blocks: HashMap<&str, String>) -> String {
    let mut result = String::new();
    let mut rest = template;
    while let Some((before, after)) = rest.split_once("{{ '{{") {
        result.push_str(before);
        let (key, tail) = after
            .split_once("}}' }}")
            .expect("valid preseed placeholder");
        if let Some(block) = blocks.get(key) {
            result.push_str(block);
        } else {
            result.push_str("{{");
            result.push_str(key);
            result.push_str("}}");
        }
        rest = tail;
    }
    result.push_str(rest);
    result
}
