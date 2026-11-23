// SPDX-License-Identifier: LGPL-3.0-only

use super::valid_disk;
use crate::disk_identity::{serial, valid_wwid};
use crate::{php_string, php_truthy};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

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
    targets: Vec<(String, String)>,
    strict: bool,
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
                    targets: vec![(disk.to_owned(), identity(&config["system_disk_identity"])? )],
                    strict: false,
                    firmware: "",
                    directives: ATOMIC.to_owned(),
                    reserved: Vec::new(),
                })
            }
            "custom" => Self::custom(config).ok_or(
                "plan de partition personnalisé non pris en charge ou identité du disque non vérifiée.",
            ),
            _ => Err("mode de partitionnement non pris en charge."),
        }
    }

    fn custom(config: &Value) -> Option<Self> {
        let plan: Value = serde_json::from_str(config["partition_custom_json"].as_str()?).ok()?;
        let arrays = collection(&plan["raid_arrays"])?;
        let lvm = Lvm::parse(&plan)?;
        let mut targets = Vec::new();
        let plan_targets = plan["target_disks"].as_array()?;
        let recipes = plan["disks"].as_array()?;
        if plan_targets.is_empty() || recipes.len() != plan_targets.len() {
            return None;
        }
        let multi = plan_targets.len() > 1;
        let raid_layout = !arrays.is_empty();
        if raid_layout {
            // Debian applies the entire physical recipe to each RAID disk.
            // The guided profile supports a symmetric GPT BIOS RAID1 root.
            if arrays.len() != 1
                || php_string(&arrays[0]["level"]) != "1"
                || php_truthy(&arrays[0]["is_pv"])
                || lvm.first_group.is_some()
            {
                return None;
            }
        } else if multi && lvm.first_group.is_none() {
            // D-I regular mode partitions only the first matching device.
            return None;
        }
        let constraints = &config["disk_target_constraints"];
        if multi && !empty_collection(constraints) {
            return None;
        }
        for disk in plan_targets {
            let disk = disk.as_str().filter(|disk| whole_disk(disk))?;
            let proof = &plan["target_disk_identities"][disk];
            let identity = identity(proof).ok()?;
            if !constraint_matches(constraints, disk, proof)
                || targets
                    .iter()
                    .any(|(path, saved)| path == disk || *saved == identity)
            {
                return None;
            }
            targets.push((disk.to_owned(), identity));
        }

        let mut bios_partition = false;
        let mut efi_partition = false;
        let mut ids = HashSet::new();
        let mut assigned = HashSet::new();
        let mut pv_ids = HashSet::new();
        let mut raid_members = HashMap::new();
        let mut mounts = HashSet::new();
        let mut reserved = Vec::new();
        let mut segments = Vec::new();

        for recipe in recipes {
            let disk = recipe["path"].as_str()?;
            if !assigned.insert(disk) || !targets.iter().any(|(path, _)| path == disk) {
                return None;
            }
            let mut fill = false;
            let mut disk_segments = Vec::new();
            let entries = recipe["partitions"]
                .as_array()
                .filter(|entries| !entries.is_empty())?;
            for (position, entry) in entries.iter().enumerate() {
                let id = entry["id"].as_str().filter(|id| !id.is_empty())?;
                let fs = entry["fs"].as_str()?;
                if (raid_layout && !matches!(fs, "biosgrub" | "raid-member"))
                    || (multi && !raid_layout && disk != targets[0].0 && fs != "lvm-pv")
                {
                    return None;
                }
                let uses_fill = php_truthy(&entry["fill"]);
                if !ids.insert(id) || (uses_fill && fill) {
                    return None;
                }
                fill |= uses_fill;
                let size = if uses_fill {
                    0
                } else {
                    php_string(&entry["size_mb"])
                        .parse::<u32>()
                        .ok()
                        .filter(|size| *size > 0)?
                };
                if fs == "biosgrub" {
                    if position != 0 || uses_fill || size > 4 {
                        return None;
                    }
                    bios_partition = true;
                    disk_segments.push(format!(
                        "{size} {size} {size} free $bios_boot{{ }} method{{ biosgrub }} ."
                    ));
                    continue;
                }
                let filesystem = match fs {
                    "swap" => "linux-swap",
                    "efi" if !uses_fill => "fat32",
                    "ext2" | "ext3" | "ext4" | "xfs" => fs,
                    "lvm-pv" | "raid-member" => "ext4",
                    _ => return None,
                };
                let mut segment = sized_segment(uses_fill, size, filesystem);
                segment.push_str(" $primary{ }");
                match fs {
                    "lvm-pv" => {
                        let group = lvm.physical.get(id)?;
                        pv_ids.insert(id);
                        if !entry["mount"].is_null() || !empty_collection(&entry["mount_options"]) {
                            return None;
                        }
                        if multi {
                            segment.push_str(&format!(" device{{ {disk} }}"));
                        }
                        segment.push_str(&format!(
                            " $defaultignore{{ }} method{{ lvm }} vg_name{{ {group} }}"
                        ));
                    }
                    "raid-member" => {
                        if !raid_layout
                            || !entry["mount"].is_null()
                            || !empty_collection(&entry["mount_options"])
                        {
                            return None;
                        }
                        let separator = if disk.as_bytes().last()?.is_ascii_digit() {
                            "p"
                        } else {
                            ""
                        };
                        let path = format!("{disk}{separator}{}", position + 1);
                        raid_members.insert(id, (disk, path));
                        segment.push_str(" method{ raid }");
                    }
                    _ => {
                        filesystem_directives(
                            entry,
                            fs,
                            true,
                            &mut segment,
                            &mut mounts,
                            &mut reserved,
                        )?;
                        efi_partition |= fs == "efi";
                    }
                }
                segment.push_str(" .");
                disk_segments.push(segment);
            }
            if raid_layout && !segments.is_empty() {
                if disk_segments != segments {
                    return None;
                }
            } else {
                segments.extend(disk_segments);
            }
        }
        if lvm.first_group.is_some() && !mounts.contains("/boot") {
            return None;
        }
        let raid = if let Some(array) = arrays.first() {
            mounts.insert("/");
            raid_directives(array, &raid_members)?
        } else {
            String::new()
        };
        if !lvm.physical.keys().all(|id| pv_ids.contains(id)) {
            return None;
        }
        lvm.render_volumes(&mut segments, &mut mounts, &mut reserved)?;
        if !mounts.contains("/") || (bios_partition && efi_partition) {
            return None;
        }
        // The RAID recipe fixes physical partition numbers. GPT keeps those
        // numbers independent of the number of primary partitions.
        if raid_layout && !bios_partition {
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
        let (base_method, lvm_directives) = match lvm.first_group {
            Some(group) => ("lvm", format!(
                "d-i partman-auto-lvm/new_vg_name string {group}\nd-i partman-auto-lvm/guided_size string max\nd-i partman-lvm/device_remove_lvm boolean true\nd-i partman-lvm/confirm boolean true\nd-i partman-lvm/confirm_nooverwrite boolean true\nd-i partman-auto/purge_lvm_from_device boolean true\n"
            )),
            None => ("regular", String::new()),
        };
        let method = if arrays.is_empty() {
            base_method
        } else {
            "raid"
        };
        let disk = targets
            .iter()
            .map(|(disk, _)| disk.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let directives = format!(
            "d-i partman-auto/disk string {disk}
d-i partman/unmount_active boolean true
d-i partman-auto/method string {method}
d-i partman-partitioning/default_label string {label}
d-i partman-basicfilesystems/default_label string {label}
d-i partman/default_filesystem string ext4
{lvm_directives}{raid}d-i partman-md/device_remove_md boolean true
d-i partman-auto/expert_recipe string custom_recipe :: \\\n      {recipe}
d-i partman-auto/choose_recipe select custom_recipe
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-basicfilesystems/no_swap boolean false"
        );
        Some(Self {
            targets,
            strict: multi || !arrays.is_empty(),
            firmware,
            directives,
            reserved,
        })
    }

    pub(super) fn contains_disk(&self, disk: &str) -> bool {
        self.targets.iter().any(|(path, _)| path == disk)
    }

    pub(super) fn guard_mode(&self) -> &'static str {
        if self.strict {
            "strict"
        } else {
            "remap"
        }
    }

    pub(super) fn guard_specs(&self) -> String {
        self.targets
            .iter()
            .map(|(disk, id)| format!("'{disk}:{id}'"))
            .collect::<Vec<_>>()
            .join(" ")
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

fn raid_directives(array: &Value, members: &HashMap<&str, (&str, String)>) -> Option<String> {
    lvm_name(&array["name"])?;
    let active = array["members"].as_array()?;
    let spares = collection(&array["spares"])?;
    if active.len() < 2 {
        return None;
    }
    let mut disks = HashSet::new();
    let mut paths = |values: &[Value]| -> Option<String> {
        let paths = values
            .iter()
            .map(|value| {
                let (disk, path) = members.get(value.as_str()?)?;
                disks.insert(*disk).then_some(path.as_str())
            })
            .collect::<Option<Vec<_>>>()?;
        Some(paths.join("#"))
    };
    let devices = paths(active)?;
    // Debian auto-raidcfg passes the optional seventh field directly to mdadm.
    let spare_field = if spares.is_empty() {
        String::new()
    } else {
        format!(" {}", paths(spares)?)
    };
    if disks.len() != members.len() {
        return None;
    }
    let continued = " \\\n      ";
    Some(format!("d-i partman-auto-raid/recipe string{continued}1 {} {} ext4 / {devices}{spare_field}{continued}.\nd-i partman-md/confirm boolean true\nd-i partman-md/confirm_nooverwrite boolean true\n", active.len(), spares.len()))
}

struct Lvm<'a> {
    physical: HashMap<&'a str, &'a str>,
    groups: HashSet<&'a str>,
    first_group: Option<&'a str>,
    volumes: &'a [Value],
}

impl<'a> Lvm<'a> {
    fn parse(plan: &'a Value) -> Option<Self> {
        let groups = collection(&plan["vgs"])?;
        let volumes = collection(&plan["logical_volumes"])?;
        if groups.is_empty() != volumes.is_empty() {
            return None;
        }
        let mut parsed = Self {
            physical: HashMap::new(),
            groups: HashSet::new(),
            first_group: None,
            volumes,
        };
        for group in groups {
            let name = lvm_name(&group["name"])?;
            let physical = group["pvs"].as_array().filter(|ids| !ids.is_empty())?;
            if !parsed.groups.insert(name) {
                return None;
            }
            parsed.first_group.get_or_insert(name);
            for member in physical {
                let id = member.as_str().filter(|id| !id.is_empty())?;
                if parsed.physical.insert(id, name).is_some() {
                    return None;
                }
            }
        }
        Some(parsed)
    }

    fn render_volumes<'b>(
        &'b self,
        segments: &mut Vec<String>,
        mounts: &mut HashSet<&'b str>,
        reserved: &mut Vec<(String, u8)>,
    ) -> Option<()> {
        let mut ids = HashSet::new();
        let mut fills = HashSet::new();
        for lv in self.volumes {
            let group = lv["vg"].as_str().filter(|vg| self.groups.contains(vg))?;
            let name = lvm_name(&lv["name"])?;
            let fs = lv["fs"].as_str()?;
            let filesystem = match fs {
                "swap" => "linux-swap",
                "ext2" | "ext3" | "ext4" | "xfs" => fs,
                _ => return None,
            };
            let fill = php_truthy(&lv["fill"]);
            if !ids.insert((group, name)) || (fill && !fills.insert(group)) {
                return None;
            }
            let size = if fill {
                0
            } else {
                php_string(&lv["size_mb"])
                    .parse::<u32>()
                    .ok()
                    .filter(|size| *size > 0)?
            };
            let mut segment = sized_segment(fill, size, filesystem);
            segment.push_str(&format!(
                " $defaultignore{{ }} $lvmok{{ }} in_vg{{ {group} }} lv_name{{ {name} }}"
            ));
            filesystem_directives(lv, fs, false, &mut segment, mounts, reserved)?;
            segment.push_str(" .");
            segments.push(segment);
        }
        Some(())
    }
}

fn collection(value: &Value) -> Option<&[Value]> {
    if empty_collection(value) {
        Some(&[])
    } else {
        value.as_array().map(Vec::as_slice)
    }
}

fn lvm_name(value: &Value) -> Option<&str> {
    value.as_str().filter(|name| {
        !name.is_empty()
            && !name.starts_with('-')
            && name.len() <= 127
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    })
}

fn sized_segment(fill: bool, size: u32, filesystem: &str) -> String {
    if fill {
        format!("512 1000 -1 {filesystem}")
    } else {
        format!("{size} {size} {size} {filesystem}")
    }
}

fn filesystem_directives<'a>(
    entry: &'a Value,
    fs: &str,
    physical: bool,
    segment: &mut String,
    mounts: &mut HashSet<&'a str>,
    reserved: &mut Vec<(String, u8)>,
) -> Option<()> {
    if fs == "swap" {
        segment.push_str(" method{ swap } format{ }");
    } else {
        let mount = entry["mount"].as_str().filter(|mount| safe_mount(mount))?;
        if !mounts.insert(mount)
            || (fs == "efi") != (mount == "/boot/efi")
            || (!physical && mount == "/boot")
        {
            return None;
        }
        if fs == "efi" {
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
            if option.is_empty() {
                continue;
            }
            if !option
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_=,.-".contains(&byte))
            {
                return None;
            }
            segment.push_str(&format!(" options/{option}{{ {option} }}"));
        }
    }
    Some(())
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

pub(crate) fn whole_disk(path: &str) -> bool {
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
