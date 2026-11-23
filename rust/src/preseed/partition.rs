// SPDX-License-Identifier: LGPL-3.0-only

use super::valid_disk;
use crate::disk_identity::{serial, valid_wwid};
use crate::{php_string, php_truthy};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::collections::HashSet;

const ATOMIC: &str = "d-i partman-auto/method string lvm
d-i partman-auto/choose_recipe select atomic
d-i partman-auto-lvm/guided_size string max
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true";

pub(super) struct Layout {
    pub(super) disk: String,
    pub(super) identity: String,
    pub(super) firmware: &'static str,
    pub(super) directives: String,
    reserved: Vec<(String, u8)>,
}

impl Layout {
    pub(super) fn new(config: &Value) -> Result<Self, &'static str> {
        let mode = config["partition_mode"].as_str().unwrap_or_default();
        match mode {
            "" | "default" => {
                let disk = config["system_disk_path"]
                    .as_str()
                    .filter(|path| valid_disk(path))
                    .ok_or("chemin du disque système absent ou invalide.")?;
                Ok(Self {
                    disk: disk.to_owned(),
                    identity: identity(&config["system_disk_identity"])?,
                    firmware: "",
                    directives: ATOMIC.to_owned(),
                    reserved: Vec::new(),
                })
            }
            "custom" => Self::regular(config).ok_or(
                "plan de partition personnalisé non pris en charge ou identité du disque non vérifiée.",
            ),
            _ => Err("mode de partitionnement non pris en charge."),
        }
    }

    fn regular(config: &Value) -> Option<Self> {
        let plan: Value = serde_json::from_str(config["partition_custom_json"].as_str()?).ok()?;
        for field in ["raid_arrays", "vgs", "logical_volumes"] {
            if !empty_collection(&plan[field]) {
                return None;
            }
        }
        let [disk] = plan["target_disks"].as_array()?.as_slice() else {
            return None;
        };
        let disk = disk.as_str().filter(|disk| whole_disk(disk))?;
        let [recipe] = plan["disks"].as_array()?.as_slice() else {
            return None;
        };
        let proof = &plan["target_disk_identities"][disk];
        let identity = identity(proof).ok()?;
        let constraints = &config["disk_target_constraints"];
        if recipe["path"] != disk || !constraint_matches(constraints, disk, proof) {
            return None;
        }

        let mut bios_partition = false;
        let mut efi_partition = false;
        let mut fill = false;
        let mut ids = HashSet::new();
        let mut mounts = HashSet::new();
        let mut reserved = Vec::new();
        let mut segments = Vec::new();

        for (position, entry) in recipe["partitions"].as_array()?.iter().enumerate() {
            let id = entry["id"].as_str().filter(|id| !id.is_empty())?;
            let fs = entry["fs"].as_str()?;
            let uses_fill = php_truthy(&entry["fill"]);
            if !ids.insert(id) || (uses_fill && fill) {
                return None;
            }
            fill |= uses_fill;
            let size = php_string(&entry["size_mb"]).parse::<u32>().ok();
            let size = if uses_fill {
                0
            } else {
                size.filter(|size| *size > 0)?
            };
            if fs == "biosgrub" {
                if position != 0 || uses_fill || size > 4 {
                    return None;
                }
                bios_partition = true;
                segments.push(format!(
                    "{size} {size} {size} free $bios_boot{{ }} method{{ biosgrub }} ."
                ));
                continue;
            }
            let filesystem = match fs {
                "swap" => "linux-swap",
                "efi" if !uses_fill => "fat32",
                "ext2" | "ext3" | "ext4" | "xfs" => fs,
                _ => return None,
            };
            let mut segment = if uses_fill {
                format!("512 1000 -1 {filesystem}")
            } else {
                format!("{size} {size} {size} {filesystem}")
            };
            segment.push_str(" $primary{ }");
            if fs == "swap" {
                segment.push_str(" method{ swap } format{ }");
            } else {
                let mount = entry["mount"].as_str().filter(|mount| safe_mount(mount))?;
                if !mounts.insert(mount) || (fs == "efi") != (mount == "/boot/efi") {
                    return None;
                }
                if fs == "efi" {
                    efi_partition = true;
                    segment.push_str(" $bootable{ } method{ efi } format{ }");
                } else {
                    if mount == "/boot" {
                        segment.push_str(" $bootable{ }");
                    }
                    segment.push_str(&format!(
                        " method{{ format }} format{{ }} use_filesystem{{ }} filesystem{{ {fs} }}"
                    ));
                }
                segment.push_str(&format!(" mountpoint{{ {mount} }}"));
                if matches!(fs, "ext2" | "ext3" | "ext4") && !entry["reserved_pct"].is_null() {
                    let pct = php_string(&entry["reserved_pct"]).parse::<u8>().ok()?;
                    if pct > 100 {
                        return None;
                    }
                    reserved.push((mount.to_owned(), pct));
                }
            }
            if !entry["mount_options"].is_null() {
                for option in entry["mount_options"].as_array()? {
                    let option = option.as_str()?;
                    if !option.is_empty()
                        && option
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_=,.-".contains(&byte))
                    {
                        segment.push_str(&format!(" options/{option}{{ {option} }}"));
                    } else if !option.is_empty() {
                        return None;
                    }
                }
            }
            segment.push_str(" .");
            segments.push(segment);
        }
        if !mounts.contains("/") || (bios_partition && efi_partition) {
            return None;
        }
        let firmware = if efi_partition { "uefi" } else { "bios" };
        if config["review_boot_mode"]
            .as_str()
            .is_some_and(|mode| !mode.is_empty() && !mode.eq_ignore_ascii_case(firmware))
        {
            return None;
        }
        let label = if efi_partition || bios_partition {
            "gpt"
        } else {
            "msdos"
        };
        let recipe = segments.join(" \\\n      ");
        let directives = format!(
            "d-i partman-auto/disk string {disk}
d-i partman/unmount_active boolean true
d-i partman-auto/method string regular
d-i partman-partitioning/default_label string {label}
d-i partman-basicfilesystems/default_label string {label}
d-i partman/default_filesystem string ext4
d-i partman-md/device_remove_md boolean true
d-i partman-auto/expert_recipe string custom_recipe :: \\\n      {recipe}
d-i partman-auto/choose_recipe select custom_recipe
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-basicfilesystems/no_swap boolean false"
        );
        Some(Self {
            disk: disk.to_owned(),
            identity,
            firmware,
            directives,
            reserved,
        })
    }

    pub(super) fn reserve_blocks(&self) -> Option<String> {
        if self.reserved.is_empty() {
            return None;
        }
        let args = self
            .reserved
            .iter()
            .map(|(mount, pct)| format!("{mount}:{pct}"))
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!(
            r#"in-target /bin/bash -c 'for pair in {args}; do mp="${{pair%%:*}}"; pct="${{pair##*:}}"; d=$(findmnt -n -o SOURCE "$mp" 2>/dev/null) || continue; tune2fs -m "$pct" "$d" || true; done'"#
        ))
    }
}

fn identity(proof: &Value) -> Result<String, &'static str> {
    let value = serial(&proof["value"]).ok_or("identité du disque système absente ou invalide.")?;
    if proof["status"]
        .as_str()
        .is_some_and(|status| status != "valid")
    {
        return Err("identité du disque système non vérifiée.");
    }
    match proof["kind"].as_str() {
        Some("serial") => Ok(STANDARD.encode(value)),
        Some("wwid") if proof["source"] == "sysfs-wwid" && valid_wwid(&value) => {
            Ok(format!("wwid={}", STANDARD.encode(value)))
        }
        _ => Err("type d'identité du disque système non pris en charge."),
    }
}

fn empty_collection(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn constraint_matches(constraints: &Value, disk: &str, proof: &Value) -> bool {
    empty_collection(constraints)
        || (proof["kind"] == "serial"
            && constraints
                .as_object()
                .is_some_and(|items| items.len() == 1)
            && serial(&constraints[disk])
                .is_some_and(|intent| serial(&proof["value"]) == Some(intent)))
}

fn whole_disk(path: &str) -> bool {
    let Some(name) = path.strip_prefix("/dev/") else {
        return false;
    };
    for prefix in ["sd", "hd", "vd", "xvd"] {
        if let Some(suffix) = name.strip_prefix(prefix) {
            return !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_lowercase());
        }
    }
    let digits = |run: &str| !run.is_empty() && run.bytes().all(|byte| byte.is_ascii_digit());
    name.strip_prefix("mmcblk").is_some_and(digits)
        || name
            .strip_prefix("nvme")
            .and_then(|tail| tail.split_once('n'))
            .is_some_and(|(controller, namespace)| digits(controller) && digits(namespace))
}

fn safe_mount(mount: &str) -> bool {
    mount.starts_with('/')
        && mount
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.-".contains(&byte))
        && !mount
            .split('/')
            .any(|component| matches!(component, "." | ".."))
}
