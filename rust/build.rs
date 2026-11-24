// SPDX-License-Identifier: LGPL-3.0-only

use std::{env, fs, path::PathBuf};

fn main() {
    let path = "../docker/worker/templates/preseed.php.j2";
    println!("cargo:rerun-if-changed={path}");
    let source = fs::read_to_string(path).expect("read the PHP preseed template");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    // Reuse the scripts that the PHP renderer already delivers to Debian Installer.
    for (name, file) in [
        ("disk_guard_tpl", "disk-guard.sh"),
        ("dilog_tpl", "install-log.sh"),
        ("firstBoot", "first-boot.sh"),
        ("host_script", "target-hostname.sh"),
        ("bond_script_tpl", "target-bond.sh"),
    ] {
        let marker = format!("${name} = <<<'SH'\n");
        let (_, rest) = source
            .split_once(&marker)
            .expect("find shared installer script");
        let (script, _) = rest
            .split_once("\nSH;")
            .expect("find end of installer script");
        fs::write(output.join(file), script).expect("write shared installer script");
    }
    let path = "../docker/worker/templates/grub.php.j2";
    println!("cargo:rerun-if-changed={path}");
    let source = fs::read_to_string(path).expect("read the PHP GRUB template");
    for menu in [
        "discovery",
        "install",
        "local",
        "rescue",
        "disktest",
        "wipe",
    ] {
        let (_, function) = source
            .split_once(&format!("function menuentry_{menu}("))
            .expect("find shared GRUB menu");
        let (_, body) = function
            .split_once("return <<<")
            .expect("find GRUB menu heredoc");
        let (delimiter, text) = body.split_once('\n').expect("read GRUB delimiter");
        let (menuentry, _) = text
            .split_once(&format!("\n{delimiter};"))
            .expect("read GRUB menu");
        fs::write(output.join(format!("grub-{menu}.cfg")), menuentry)
            .expect("write shared GRUB menu");
    }

    let path = "../app/src/Views/pxe/wipe.sh.php";
    println!("cargo:rerun-if-changed={path}");
    let mut wipe = fs::read_to_string(path).expect("read the shared wipe script");
    for (field, marker) in [
        ("$pxe_ip", "__PXE_IP__"),
        ("$mac", "__MAC__"),
        ("$wipe_id", "__WIPE_ID__"),
        ("$action_token ?? ''", "__ACTION_TOKEN__"),
        ("$boot_token", "__BOOT_TOKEN__"),
        ("$action_id ?? ''", "__ACTION_ID__"),
        ("$action_type ?? ''", "__ACTION_TYPE__"),
        ("$post_action", "__POST_ACTION__"),
        ("$disks_parsed", "__DISK_LIST__"),
    ] {
        let pattern = format!("<?= {field} ?>");
        assert_eq!(
            wipe.matches(&pattern).count(),
            1,
            "expected each wipe field once"
        );
        wipe = wipe.replace(&pattern, marker);
    }
    assert!(
        !wipe.contains("<?"),
        "unexpected PHP block in the shared wipe script"
    );
    fs::write(output.join("wipe.sh"), wipe).expect("write shared wipe script");
}
