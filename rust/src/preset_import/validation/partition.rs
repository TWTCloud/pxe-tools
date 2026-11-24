// SPDX-License-Identifier: LGPL-3.0-only

use super::ErrorBox;
use crate::{migrations::integer, preseed::whole_disk, pxe::array_values};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const STANDARD: &[&str] = &["ext2", "ext3", "ext4", "xfs", "swap"];

pub(super) fn validate(plan: &Value, inventory: &Value) -> Result<(), ErrorBox> {
    let target = strings(&plan["target_disks"]);
    let disks = list(&plan["disks"]);
    let raid = list(&plan["raid_arrays"]);
    let vgs = list(&plan["vgs"]);
    let lvs = list(&plan["logical_volumes"]);
    let declared = disks
        .iter()
        .map(|disk| text(&disk["path"]))
        .collect::<HashSet<_>>();
    if target.is_empty()
        || target
            .iter()
            .any(|path| !whole_disk(path) || !declared.contains(path))
        || declared.len() != disks.len()
        || declared.iter().any(|path| !target.contains(path))
    {
        return Err("Disques cibles absents, répétés ou incompatibles avec la recette".into());
    }
    let capacities: HashMap<_, _> = array_values(&inventory["disks"])
        .filter_map(|disk| {
            let path = disk["name"].as_str().filter(|name| !name.is_empty())?;
            let bytes = integer(&disk["size_bytes"]).filter(|size| *size > 0)?;
            let path = if path.starts_with("/dev/") {
                path.to_owned()
            } else {
                format!("/dev/{}", path.trim_start_matches('/'))
            };
            Some((path, i128::from(bytes / 1_000_000)))
        })
        .collect();
    if !capacities.is_empty() && target.iter().any(|path| !capacities.contains_key(*path)) {
        return Err("Disque cible absent de l’inventaire de référence".into());
    }
    let mut mounts = HashSet::new();
    let mut partition_ids = HashSet::new();
    let mut raid_members = HashSet::new();
    let mut physical_volumes = HashSet::new();
    let mut pv_sizes = HashMap::new();
    for disk in disks {
        let parts = list(&disk["partitions"]);
        if parts.is_empty() {
            return Err("Une recette de disque doit contenir au moins une partition".into());
        }
        let margin = if parts
            .iter()
            .any(|part| matches!(text(&part["fs"]), "efi" | "biosgrub"))
        {
            2
        } else {
            1
        };
        let capacity = capacities
            .get(text(&disk["path"]))
            .map(|capacity| (capacity - margin).max(0));
        let total_fixed: i128 = parts.iter().filter(|part| !fill(part)).map(size).sum();
        let fills = parts.iter().filter(|part| fill(part)).count();
        if fills > 1 || capacity.is_some_and(|capacity| total_fixed > capacity) {
            return Err(
                "Partitions dépassant la capacité utile ou plusieurs tailles extensibles".into(),
            );
        }
        for (index, part) in parts.iter().enumerate() {
            let fs = text(&part["fs"]);
            let id = text(&part["id"]);
            if id.is_empty() || !partition_ids.insert(id) || (!fill(part) && size(part) <= 0) {
                return Err("Identifiant ou taille de partition invalide".into());
            }
            match fs {
                "lvm-pv" => {
                    physical_volumes.insert(id);
                    if let Some(capacity) = capacity {
                        pv_sizes.insert(
                            id,
                            if fill(part) {
                                (capacity - total_fixed).max(0)
                            } else {
                                size(part)
                            },
                        );
                    }
                }
                "raid-member" => {
                    raid_members.insert(id);
                }
                "biosgrub" if index == 0 && !fill(part) && size(part) <= 4 => {}
                "swap" => {}
                "efi" if part["mount"] == "/boot/efi" => mount_once(&mut mounts, &part["mount"])?,
                fs if STANDARD.contains(&fs) && part["mount"] != "/boot/efi" => {
                    mount_once(&mut mounts, &part["mount"])?
                }
                _ => return Err("Type de partition ou montage incompatible avec la recette".into()),
            }
        }
    }
    let physical_boot = mounts.contains("/boot");
    let mut raid_names = HashSet::new();
    let mut used = HashSet::new();
    for array in raid {
        let name = text(&array["name"]);
        let members = strings(&array["members"]);
        let spares = strings(&array["spares"]);
        let minimum = match integer(&array["level"]) {
            Some(0 | 1) => 2,
            Some(5) => 3,
            Some(6 | 10) => 4,
            _ => return Err("Niveau RAID inconnu".into()),
        };
        if !raid_names.insert(name)
            || members.len() < minimum
            || (array["level"] == 0 && !spares.is_empty())
            || members
                .iter()
                .chain(&spares)
                .any(|part| !raid_members.contains(part) || !used.insert(*part))
        {
            return Err("Membres ou disques de secours RAID invalides".into());
        }
        if array["is_pv"] == true {
            physical_volumes.insert(name);
        }
    }
    if used != raid_members {
        return Err("Partition RAID orpheline".into());
    }

    let mut groups = HashMap::new();
    let mut used = HashSet::new();
    for group in vgs {
        let name = text(&group["name"]);
        let pvs = strings(&group["pvs"]);
        if pvs.is_empty()
            || groups.insert(name, pvs.clone()).is_some()
            || pvs
                .iter()
                .any(|pv| !physical_volumes.contains(pv) || !used.insert(*pv))
        {
            return Err("Groupe LVM ou volume physique invalide".into());
        }
    }
    if used != physical_volumes {
        return Err("Volume physique LVM orphelin".into());
    }

    let mut lv_names = HashSet::new();
    let mut lv_by_group = HashMap::<&str, Vec<&Value>>::new();
    for lv in lvs {
        let group = text(&lv["vg"]);
        let name = text(&lv["name"]);
        let fs = text(&lv["fs"]);
        if !groups.contains_key(group)
            || !lv_names.insert((group, name))
            || !STANDARD.contains(&fs)
            || (!fill(lv) && size(lv) <= 0)
        {
            return Err("Volume logique LVM invalide".into());
        }
        if fs != "swap" {
            mount_once(&mut mounts, &lv["mount"])?;
        }
        lv_by_group.entry(group).or_default().push(lv);
    }
    for (name, volumes) in lv_by_group {
        let pvs = groups[name]
            .iter()
            .filter_map(|pv| pv_sizes.get(pv))
            .collect::<Vec<_>>();
        let capacity = pvs.iter().copied().sum::<i128>();
        let fixed = volumes
            .iter()
            .filter(|lv| !fill(lv))
            .map(|lv| size(lv))
            .sum::<i128>();
        let overhead = 4 * pvs.len() as i128 + 4 * volumes.len() as i128 + 16;
        if volumes.iter().filter(|lv| fill(lv)).count() > 1
            || (capacity > 0 && fixed > (capacity - overhead).max(0))
        {
            return Err(
                "Volumes logiques dépassant la capacité LVM ou plusieurs tailles extensibles"
                    .into(),
            );
        }
    }
    if !physical_boot || !mounts.contains("/") {
        return Err("La recette doit contenir une partition physique /boot et une racine /".into());
    }
    Ok(())
}

fn list(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn strings(value: &Value) -> Vec<&str> {
    list(value).iter().filter_map(Value::as_str).collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

fn size(value: &Value) -> i128 {
    i128::from(integer(&value["size_mb"]).unwrap_or_default())
}

fn fill(value: &Value) -> bool {
    value["fill"] == true
}

fn mount_once<'a>(mounts: &mut HashSet<&'a str>, value: &'a Value) -> Result<(), ErrorBox> {
    let mount = text(value);
    if mount.is_empty() || !mounts.insert(mount) {
        return Err("Point de montage manquant ou réutilisé".into());
    }
    Ok(())
}
