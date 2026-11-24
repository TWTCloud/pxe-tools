#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""PXE discovery, Debian installation and first boot through nginx and Rust.

The BIOS guest uses restricted QEMU user networking, signed Debian lpxelinux,
and one HTTP forward to a private Unix socket. QEMU supplies DHCP/TFTP in this
fixture. The native dnsmasq/packaging chain is exercised by a different bench.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing, ExitStack
import json
import os
from pathlib import Path
import secrets
import selectors
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
PROTOTYPE = ROOT / "tests/support/prototype"
SCRIPTS = ROOT / "docker/worker/templates"
sys.path[:0] = [str(PROTOTYPE / "tests/integration"), str(PROTOTYPE / "app"),
                str(ROOT / "tests/benchmarks/rust-monitor")]
from artifacts.debian_netboot import verify_debian_netboot
from benchmark import process
from full_install_mirror import FullInstallMirror
from run_qemu_dnsmasq_from_debian import prepare_inputs
from test_qemu_project_menu import package_checks

PXE_IP = "10.0.2.100"
CLIENT = "10.0.2.15"
MAC = "02:00:00:00:00:01"
SERIAL = "PXE-TEST-ONE"
# SHA-512 crypt of the public, synthetic password pxe-fixture-password.
FIXTURE_HASH = '$6$pxe-rust-fixture$3qZUDjjE3OJvYO8pbsw4RHkkfm57OLObfMO6T70WK4.i0jn8CsDqRh0JbCwExpu06CX/aCgUOCVkdcsJ6QAzk/'


def write_nginx(root):
    conf = root / "nginx.conf"
    source = "&phase=finished&status=success' || true"
    serial = base64.b64encode(
        b'GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 net.ifnames=0"\n'
    ).decode("ascii")
    settings = (
        f" ; in-target /bin/sh -c 'echo {serial} | base64 -d "
        ">> /etc/default/grub; update-grub'"
    )
    conf.write_text(f"""
        daemon off;
        master_process off;
        error_log stderr warn;
        pid "{root}/nginx.pid";
        events {{ worker_connections 1024; }}
        http {{
            access_log "{root}/access.log";
            client_body_temp_path "{root}/client";
            proxy_temp_path "{root}/proxy";
            fastcgi_temp_path "{root}/fastcgi";
            uwsgi_temp_path "{root}/uwsgi";
            scgi_temp_path "{root}/scgi";
            upstream rust_pxe {{ server unix:{root}/rust.sock; }}
            upstream fixture_mirror {{ server unix:{root}/mirror.sock; }}
            server {{
                listen unix:{root}/http.sock;
                root "{root}/http";
                # Only QEMU's guestfwd helper can reach this private socket.
                proxy_set_header X-Pxe-Client-Ip {CLIENT};
                location /api/ {{ proxy_pass http://rust_pxe; }}
                location /pxe/postboot/ {{ proxy_pass http://rust_pxe; }}
                location = /preseed.php {{
                    proxy_pass http://rust_pxe;
                    sub_filter_types text/plain;
                    sub_filter 'd-i mirror/suite string trixie' 'd-i mirror/suite string trixie\nd-i mirror/udeb/suite string trixie';
                    sub_filter "{source}" "{source}{settings}";
                }}
                location /debian/ {{ proxy_pass http://fixture_mirror; proxy_read_timeout 90s; }}
                location / {{ try_files $uri =404; }}
            }}
        }}
    """)
    return conf


def render_fixture(source, **values):
    template = (SCRIPTS / source).read_text()
    for field, value in values.items():
        template = template.replace("{{ " + field + " }}", value)
    return template


def setup(root, inputs, keyring):
    verify_debian_netboot(inputs / "linux", inputs / "initrd.gz", inputs / "SHA256SUMS",
                          inputs / "InRelease", keyring)
    packages = ("pxelinux", "syslinux-common")
    package_checks((inputs / "InRelease").read_bytes(), (inputs / "Packages.xz").read_bytes(),
                   {name: inputs / f"{name}.deb" for name in packages})
    tftp = root / "tftp"
    (tftp / "pxelinux.cfg").mkdir(parents=True)
    extract = root / "loader"
    extract.mkdir()
    for name in packages:
        subprocess.run(["dpkg-deb", "-x", str(inputs / f"{name}.deb"), str(extract)], check=True)
    shutil.copyfile(extract / "usr/lib/PXELINUX/lpxelinux.0", tftp / "lpxelinux.0")
    shutil.copyfile(extract / "usr/lib/syslinux/modules/bios/ldlinux.c32", tftp / "ldlinux.c32")

    http = root / "http"
    http.mkdir()
    for item in ("linux", "initrd.gz"):
        (http / item).symlink_to(inputs / item)
    (http / "static-bin").symlink_to(ROOT / "docker/pxe-tools/static-bin", target_is_directory=True)
    (http / "discover.sh").write_text(render_fixture("discover.sh.j2", pxe_ip=PXE_IP))
    discovery = render_fixture("discovery-preseed.cfg.j2", pxe_ip=PXE_IP, ansible_managed="Disposable fixture")
    # Debian Installer's serial frontend only offers English and C.
    discovery = discovery.replace("deb.debian.org", PXE_IP).replace("fr_FR.UTF-8", "en_US.UTF-8")
    discovery = discovery.replace("xkb-keymap select fr", "xkb-keymap select us")
    discovery = discovery.replace("debian-installer/language string fr", "debian-installer/language string en")
    discovery = discovery.replace("debian-installer/country string FR", "debian-installer/country string US")
    discovery = discovery.replace("clock-setup/ntp boolean true", "clock-setup/ntp boolean false")
    (http / "discovery.cfg").write_text(discovery + "\nd-i mirror/udeb/suite string trixie\n")
    with closing(sqlite3.connect(root / "fixture.sqlite")) as db, db:
        db.executescript((ROOT / "app/db/schema.sqlite.sql").read_text())
        db.execute("PRAGMA journal_mode=WAL")
        db.executemany("INSERT INTO settings(key,value) VALUES(?,?)",
                       [("pxe_ip", PXE_IP), ("pxe_subnet", "10.0.2.0/24"), ("ansible_enabled", "off")])
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(root / "client.qcow2"), "12G"],
                   check=True, stdout=subprocess.DEVNULL)


def menu(root, discovery):
    name = "discovery" if discovery else "install"
    seed = "discovery.cfg" if discovery else f"preseed.php?mac={MAC}"
    (root / "tftp/pxelinux.cfg/default").write_text(f"""SERIAL 0 115200
NOESCAPE 1
PROMPT 0
TIMEOUT 10
DEFAULT {name}
LABEL {name}
    KERNEL http://{PXE_IP}/linux
    APPEND initrd=http://{PXE_IP}/initrd.gz console=ttyS0,115200n8 net.ifnames=0 ipv6.disable=1 auto=true priority=critical language=en country=US locale=en_US.UTF-8 keymap=us interface=auto netcfg/get_nameservers=10.0.2.3 netcfg/no_default_route=true url=http://{PXE_IP}/{seed}
    IPAPPEND 2
""")


def schedule(root):
    with closing(sqlite3.connect(root / "fixture.sqlite")) as db, db:
        row = db.execute("SELECT id, inventory_json FROM machines WHERE mac=? AND status='discovered'", (MAC,)).fetchone()
        if not row:
            return False
        machine, inventory = row
        target = next((item for item in json.loads(inventory)["disks"]
                       if item["identity"]["value"] == SERIAL and item["identity"]["status"] == "valid"), None)
        if target is None:
            raise RuntimeError("Discovery did not identify the disposable disk")
        path = "/dev/" + target["name"].removeprefix("/dev/")
        token = secrets.token_hex(32)
        action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(?,'install_only','pending',?)",
                            (machine, token)).lastrowid
        config = {"distro": "debian", "codename": "trixie", "network_mode": "dhcp", "partition_mode": "default",
                  "root_login_mode": "disabled", "admin_user_login": "fixture", "admin_user_pwhash": FIXTURE_HASH,
                  "_pending_action_id": action, "system_disk_path": path, "system_disk_identity": target["identity"],
                  "advanced": {"localization": {"locale": "en_US.UTF-8", "keymap": "us"},
                               "mirror": {"hostname": PXE_IP}, "timezone": {"zone": "UTC", "ntp": False},
                               "packages": {"tasksel": ["ssh-server"], "pkgsel_include": ["sudo", "openssh-server", "curl"],
                                            "upgrade": "none"}, "apt": {"services_select": [],
                                  "contrib": False, "non_free_firmware": False, "hw_detect_load_firmware": False},
                               "finish": {"reboot": "quiet"}}}
        db.execute("UPDATE machines SET status='configured',hostname='pxe-fixture',domain='example.test',"
                   "install_config_json=?,next_action='reboot' WHERE id=?", (json.dumps(config), machine))
    return True


def run_guest(root, name, timeout, *, ready, first_boot=False, discovery=False):
    # Restrict the guest to the approved HTTP fixture and QEMU's built-in PXE LAN.
    forward = shlex.join((sys.executable, "-u", str(PROTOTYPE / "tests/integration/qemu_unix_http_forward.py"),
                          str(root / "http.sock")))
    network = "user,id=lan,restrict=on,tftp=" + str(root / "tftp") + ",bootfile=lpxelinux.0,"
    network += f"guestfwd=tcp:{PXE_IP}:80-cmd:" + forward.replace(",", ",,")
    readonly = "on" if discovery else "off"
    argv = ["qemu-system-x86_64", "-machine", "pc,accel=tcg", "-m", "1024", "-smp", "2",
            "-display", "none", "-monitor", "none", "-no-reboot", "-serial", "stdio", "-netdev", network,
            "-boot", "c" if first_boot else "n", "-device", f"e1000,netdev=lan,mac={MAC}",
            "-drive", f"if=none,id=fixture,format=qcow2,readonly={readonly},file={root / 'client.qcow2'}",
            "-device", f"virtio-blk-pci,drive=fixture,serial={SERIAL}"]
    log_path = root / f"{name}.serial"
    with log_path.open("wb", buffering=0) as log, selectors.DefaultSelector() as selector:
        guest = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        selector.register(guest.stdout, selectors.EVENT_READ)
        output = bytearray()
        signaled = False
        wakeup = False
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if shutil.disk_usage(root).free < 512 * 1024 * 1024:
                    raise RuntimeError("free space for the disposable guest fell below 512 MiB")
                if selector.select(timeout=1):
                    chunk = os.read(guest.stdout.fileno(), 65536)
                    if chunk:
                        output.extend(chunk)
                        log.write(chunk)
                    else:
                        selector.unregister(guest.stdout)
                if discovery and not signaled:
                    signaled = ready()
                    if signaled:
                        print("Discovery posted a verified disk identity and the fixture scheduled installation", flush=True)
                if first_boot and not wakeup and b"Debian GNU/Linux 13 pxe-fixture ttyS0" in output:
                    guest.stdin.write(b"\n")
                    guest.stdin.flush()
                    wakeup = True
                if first_boot and b"pxe-fixture login:" in output and ready():
                    return
                if guest.poll() is not None:
                    if (not first_boot and guest.returncode == 0 and
                        (signaled if discovery else ready()) and b"PXELINUX" in output and b"Linux version" in output):
                        return
                    raise RuntimeError(f"{name} guest exited before the expected evidence")
            raise RuntimeError(f"{name} guest timed out")
        finally:
            if guest.poll() is None:
                guest.terminate()
                try:
                    guest.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    guest.kill()
                    guest.wait()


def installed(root):
    with closing(sqlite3.connect(root / "fixture.sqlite")) as db:
        return db.execute("""SELECT i.install_status, m.status, m.local_boot_source
            FROM installations i JOIN machines m ON m.id=i.machine_id WHERE m.mac=?""", (MAC,)).fetchone() == (
            "success", "installed", "pxe"
        )


def first_boot_recorded(root):
    with closing(sqlite3.connect(root / "fixture.sqlite")) as db:
        receipt = db.execute("""SELECT 1 FROM machine_events e JOIN installations i ON i.action_id=e.action_id
            WHERE e.message LIKE 'Empreinte SSH déclarée par Debian Installer : SHA256:%'
            AND i.install_status='success'""").fetchone()
        boot = db.execute("""SELECT 1 FROM machine_events e JOIN installations i ON i.action_id=e.action_id
                             WHERE e.checkpoint='os_first_boot' AND i.install_status='success'""").fetchone()
        old_callback = db.execute("SELECT 1 FROM machine_events WHERE message LIKE 'Machine signalée online%'").fetchone()
        guard = db.execute("SELECT 1 FROM task_phases WHERE phase_key='disk-guard' AND status='success'").fetchone()
    return receipt is not None and guard is not None and boot is not None and old_callback is None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs_group = parser.add_mutually_exclusive_group(required=True)
    inputs_group.add_argument("--inputs", type=Path, help="directory of downloaded Debian inputs")
    inputs_group.add_argument("--fetch-inputs", action="store_true", help="download and verify Debian inputs in the fixture")
    parser.add_argument("--rust", type=Path, default=ROOT / "rust/target/release/pxe-tools-rust")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--keep-fixture", action="store_true")
    parser.add_argument("--mirror-cache", type=Path, help="copy a mirror cache from a previous fixture")
    args = parser.parse_args()
    if os.geteuid() == 0 or os.environ.get("PXE_RUST_QEMU_TEST") != "1":
        parser.error("Set PXE_RUST_QEMU_TEST=1 and run as an unprivileged user")
    if os.path.lexists("/etc/pxe-tools/db.conf"):
        parser.error("Use a test host without appliance configuration")
    root = Path(tempfile.mkdtemp(prefix="pxe-qemu-rust-", dir="/tmp"))
    print(f"Disposable fixture: {root}", flush=True)
    keyring = ROOT / "packaging/native/keyrings/debian-archive-2025.1.gpg"
    try:
        if shutil.disk_usage(root).free < 1536 * 1024 * 1024:
            raise RuntimeError("the guest and Debian mirror require at least 1.5 GiB free")
        if args.fetch_inputs:
            inputs = root / "inputs"
            (inputs / "debs").mkdir(parents=True)
            prepare_inputs(SimpleNamespace(
                keyring=keyring, runtime_manager=False, disk_guard=True,
                proxy_boot=True, uefi=False, partman_uefi=False,
            ), inputs)
        else:
            inputs = args.inputs.resolve()
        setup(root, inputs, keyring)
        cache = root / "mirror-cache"
        cache.mkdir()
        if args.mirror_cache:
            # The mirror verifies each reused index/package before serving it.
            for item in args.mirror_cache.iterdir():
                if len(item.name) == 64 and all(ch in "0123456789abcdef" for ch in item.name):
                    if item.is_file() and not item.is_symlink():
                        shutil.copyfile(item, cache / item.name)
        mirror = FullInstallMirror(root / "mirror-cache", inputs / "InRelease", keyring,
                                   b"", inputs / "Packages.xz")
        with ExitStack() as stack:
            mirror.start(root / "mirror.sock")
            stack.callback(mirror.close)
            env = dict(os.environ, POSTBOOT_OUTPUT_DIR=str(root / "postboot"))
            stack.enter_context(process([str(args.rust.resolve()), str(root / "fixture.sqlite"),
                                         str(root / "rust.sock")], root, "rust", env))
            stack.enter_context(process(["nginx", "-p", str(root), "-c", str(write_nginx(root))], root, "nginx"))
            for _ in range(200):
                if (root / "rust.sock").is_socket() and (root / "http.sock").is_socket():
                    break
                time.sleep(0.025)
            else:
                raise RuntimeError("the private HTTP sockets did not start")
            menu(root, discovery=True)
            run_guest(root, "discovery", args.timeout, ready=lambda: schedule(root), discovery=True)
            menu(root, discovery=False)
            print("Starting the PXE installation on the same disposable disk", flush=True)
            run_guest(root, "install", args.timeout, ready=lambda: installed(root))
            print("Debian installer finished and Rust recorded its callback", flush=True)
            run_guest(root, "first-boot", args.timeout, ready=lambda: first_boot_recorded(root), first_boot=True)
            print("Debian 13 login and action-bound installer receipt verified with Rust and nginx", flush=True)
    finally:
        if not args.keep_fixture:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
