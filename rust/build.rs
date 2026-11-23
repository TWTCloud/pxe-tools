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
        ("host_script", "target-hostname.sh"),
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
    for menu in ["discovery", "install", "local", "rescue"] {
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
}
