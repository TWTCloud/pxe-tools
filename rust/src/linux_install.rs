// SPDX-License-Identifier: LGPL-3.0-only

use crate::{preseed, pxe::normalize_mac};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::Ipv4Addr;

pub const PREFIX: &str = "/pxe/linux/auto/";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Source {
    Ubuntu(String),
    Rhel9(String),
}

#[derive(Deserialize, Serialize)]
pub struct Plan {
    pub source: Source,
    pub arch: String,
    pub boot_mac: String,
    pub client: Ipv4Addr,
    pub disk: String,
    pub serial: String,
    pub hostname: String,
    pub login: String,
    pub password_hash: String,
}

impl Plan {
    pub fn valid(&self) -> bool {
        matches!(self.arch.as_str(), "amd64" | "arm64")
            && normalize_mac(&self.boot_mac).as_deref() == Some(self.boot_mac.as_str())
            && !self.client.is_loopback()
            && !self.client.is_unspecified()
            && !self.client.is_multicast()
            && !self.client.is_broadcast()
            && preseed::whole_disk(&self.disk)
            && !self.serial.is_empty()
            && self.serial.len() <= 128
            && self
                .serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && valid_hostname(&self.hostname)
            && preseed::technical_account(&self.login)
            && self.password_hash.starts_with("$6$")
            && preseed::sanitized_hash(&self.password_hash).is_some()
    }

    pub fn configuration(
        &self,
        machine_mac: &str,
        token: &str,
        server: Ipv4Addr,
        port: u16,
    ) -> Option<String> {
        if !self.valid() || !crate::install::valid_token(token) {
            return None;
        }
        let boot_mac = &self.boot_mac;
        let machine_mac = normalize_mac(machine_mac)?;
        let guard = self.guard(&boot_mac);
        let authority = authority(server, port);
        let mut launcher = preseed::first_boot_script(server, port, &machine_mac, token);
        if matches!(&self.source, Source::Rhel9(_)) {
            launcher = launcher.replace("ssh.service", "sshd.service");
        }
        let target = "/etc/systemd/system-generators/pxe-first-boot";
        let end = format!(
            "status=$(curl -fsS --connect-timeout 5 --max-time 15 --retry 3 --retry-connrefused \
             --output /dev/null --write-out '%{{http_code}}' --data 'first_boot=1' \
             -H 'Authorization: Bearer {token}' \
             'http://{authority}/api/install-end?mac={machine_mac}&status=success')\n[ \"$status\" = 200 ]"
        );
        let save = format!(
            "umask 077\nmkdir -p /etc/systemd/system-generators\nprintf '%s' '{}' | base64 -d > {target}\nchmod 0700 {target}",
            STANDARD.encode(launcher)
        );
        match &self.source {
            Source::Ubuntu(_) => {
                let late = format!(
                    "set -eu\ncurtin in-target --target=/target -- /bin/sh -ec \
                     \"$(printf '%s' '{}' | base64 -d)\"\n{end}",
                    STANDARD.encode(&save)
                );
                // JSON is valid YAML and safely quotes every value and command.
                let content = json!({"autoinstall": {
                    "version": 1,
                    "refresh-installer": {"update": false},
                    "apt": {"geoip": false, "fallback": "offline-install"},
                    "identity": {
                        "hostname": self.hostname,
                        "username": self.login,
                        "password": self.password_hash
                    },
                    "ssh": {"install-server": true, "allow-pw": true},
                    "storage": {"layout": {"name": "lvm", "match": {"path": self.disk}}},
                    "packages": ["curl"],
                    "early-commands": [["/bin/sh", "-ec", guard]],
                    "late-commands": [["/bin/sh", "-ec", late]],
                    "shutdown": "reboot"
                }});
                Some(format!("#cloud-config\n{content}\n"))
            }
            Source::Rhel9(repo) => {
                let disk = self.disk.strip_prefix("/dev/")?;
                let repo = if repo.starts_with(crate::media::RHEL_PREFIX) {
                    format!("http://{authority}{repo}")
                } else {
                    repo.to_owned()
                };
                Some(format!(
                    "#version=RHEL9\nlang en_US.UTF-8\nkeyboard us\ntimezone Etc/UTC --utc\n\
                     network --bootproto=dhcp --device={boot_mac} --activate --hostname={}\n\
                     url --url={}\nfirstboot --disable\nrootpw --lock\n\
                     user --name={} --groups=wheel --iscrypted --password={}\n\
                     cmdline\nreboot\nignoredisk --only-use={disk}\n\
                     clearpart --all --initlabel --drives={disk}\nautopart --type=lvm --nohome\n\
                     %pre --erroronfail --log=/tmp/pxe-tools-guard.log\n{guard}\n%end\n\
                     %packages\n@^minimal-environment\ncurl\n%end\n\
                     %post --erroronfail\nset -eu\n{save}\nrestorecon {target}\n{end}\n%end\n",
                    self.hostname, repo, self.login, self.password_hash
                ))
            }
        }
    }

    fn guard(&self, boot_mac: &str) -> String {
        let arch = if self.arch == "arm64" {
            "aarch64"
        } else {
            "x86_64"
        };
        format!(
            "set -eu\nexport LC_ALL=C\n\
             test -d /sys/firmware/efi\ntest \"$(uname -m)\" = {arch}\n\
             udevadm settle\n\
             grep -Fiqx -- '{boot_mac}' /sys/class/net/*/address\n\
             disks=$(lsblk -dnpo NAME,TYPE,SERIAL)\n\
             actual=$(printf '%s\\n' \"$disks\" | awk -v serial='{}' '$2 == \"disk\" && toupper($3) == toupper(serial) && NF == 3 {{ print $1 }}')\n\
             test \"$actual\" = '{}'\ntest -b '{}'\n",
            self.serial, self.disk, self.disk
        )
    }
}

pub fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn authority(server: Ipv4Addr, port: u16) -> String {
    if port == 80 {
        server.to_string()
    } else {
        format!("{server}:{port}")
    }
}
