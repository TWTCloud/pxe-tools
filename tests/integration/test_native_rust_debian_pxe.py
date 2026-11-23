#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Run the native Debian package with dnsmasq and a Rust PXE backend in a disposable VM."""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT / "tests/support/native-rust-pxe"
PROTOTYPE = ROOT / "tests/support/prototype"
sys.path[:0] = [str(PROTOTYPE / "tests/integration"), str(PROTOTYPE / "app"),
                str(ROOT / "tests/benchmarks/rust-monitor")]
from artifacts.debian_netboot import verify_debian_netboot
from benchmark import process
from full_install_mirror import FullInstallMirror
from test_qemu_proxy_boot import PrivateSwitch

SERVER = "192.0.2.1"
READY = b"PXE_NATIVE_READY"
DISCOVERED = b"PXE_NATIVE_DISCOVERY_OK"
INSTALLED = b"PXE_NATIVE_INSTALL_OK"
BOOTED = b"PXE_NATIVE_FIRST_BOOT_OK"
MAC = "02:00:00:00:00:01"
SERIAL = "PXE-TEST-ONE"
KEYRING = ROOT / "packaging/native/keyrings/debian-archive-2025.1.gpg"


def native_vhost(mirror_upstream="http://10.0.2.100"):
    serial = base64.b64encode(b'GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 net.ifnames=0"\n').decode()
    hook = "in-target /bin/systemctl enable pxe-machine-ready.service"
    instrument = f"{hook} ; in-target /bin/sh -c 'echo {serial} | base64 -d >> /etc/default/grub; update-grub'"
    return f"""server {{
    listen @@PXE_IPV4@@:80 default_server;
    root @@HTTP_ROOT@@;
    autoindex off;
    proxy_set_header X-Pxe-Client-Ip $remote_addr;
    location = /healthz {{ return 200 "ok\\n"; }}
    location = /preseed.php {{
        proxy_pass http://unix:/run/pxe-tools-rust-lab/http.sock:;
        sub_filter_types text/plain;
        sub_filter 'd-i mirror/suite string trixie' 'd-i mirror/suite string trixie\\nd-i mirror/udeb/suite string trixie';
        sub_filter "{hook}" "{instrument}";
    }}
    location /api/ {{ proxy_pass http://unix:/run/pxe-tools-rust-lab/http.sock:; }}
    location /pxe/postboot/ {{ proxy_pass http://unix:/run/pxe-tools-rust-lab/http.sock:; }}
    location /debian/ {{ proxy_pass {mirror_upstream}; proxy_read_timeout 120s; }}
    location ~ \\.php$ {{ return 404; }}
    location / {{ try_files $uri =404; }}
}}
"""


def cloud_seed(root, args):
    seed = root / "seed"
    seed.mkdir()
    for source, target in [
        (SUPPORT / "server.sh", "user-data"), (SUPPORT / "server.py", "server.py"),
        (args.package, "pxe-tools-local.deb"), (args.rust, "pxe-tools-rust"),
        (ROOT / "app/db/schema.sqlite.sql", "schema.sqlite.sql"),
        (args.inputs / "linux", "linux"), (args.inputs / "initrd.gz", "initrd.gz"),
    ]:
        shutil.copyfile(source, seed / target)
    (seed / "native-rust-lab").touch()
    (seed / "pxe-rust.conf").write_text(native_vhost())
    (seed / "meta-data").write_text("instance-id: pxe-native-rust-fixture\nlocal-hostname: pxe-native-lab\n")
    (seed / "network-config").write_text("""version: 2
ethernets:
  fixture-mirror:
    match:
      macaddress: "52:54:00:44:00:01"
    addresses: [10.0.2.15/24]
    dhcp4: false
    dhcp6: false
    link-local: []
""")
    iso = root / "seed.iso"
    subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata", "-joliet",
                    "-rock", "-o", str(iso), str(seed)], check=True)
    return iso


def check_server(root, child):
    if shutil.disk_usage(root).free < 512 * 1024 * 1024:
        raise RuntimeError("The disposable fixture has less than 512 MiB free")
    output = (root / "native-status.log").read_bytes()
    if b"PXE_NATIVE_FAILED" in output or child.poll() is not None:
        raise RuntimeError(f"Native guest failed. Inspect {root / 'native-status.log'}")
    return output


def wait_server(root, child, marker, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in check_server(root, child):
            return
        time.sleep(1)
    raise RuntimeError(f"Native server did not produce {marker.decode()}")


def isolated_lan(root):
    path = str(root / "switch.sock")
    return f"stream,id=pxe,server=off,addr.type=unix,addr.path={path},reconnect-ms=1000"


def start_server(root, args, stack):
    with args.cloud_image.open("rb") as stream:
        if hashlib.file_digest(stream, "sha512").hexdigest() != args.cloud_sha512:
            raise ValueError("Debian cloud image SHA-512 mismatch")
    iso = cloud_seed(root, args)
    disk = root / "native.qcow2"
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(args.cloud_image.resolve()), str(disk), "8G"], check=True)
    forward = shlex.join((sys.executable, "-u",
                          str(PROTOTYPE / "tests/integration/qemu_unix_http_forward.py"),
                          str(root / "mirror.sock")))
    net = "user,id=mirror,restrict=on,guestfwd=tcp:10.0.2.100:80-cmd:" + forward.replace(",", ",,")
    (root / "native-status.log").touch()
    return stack.enter_context(process([
        "qemu-system-x86_64", "-machine", "pc,accel=tcg", "-m", "1280", "-smp", "2",
        "-display", "none", "-monitor", "none", "-no-reboot", "-boot", "c",
        "-serial", f"file:{root / 'native-kernel.log'}", "-serial", f"file:{root / 'native-status.log'}",
        "-drive", f"file={disk},if=virtio,format=qcow2",
        "-drive", f"file={iso},format=raw,media=cdrom,readonly=on",
        "-netdev", net, "-device", "virtio-net-pci,netdev=mirror,mac=52:54:00:44:00:01",
        "-netdev", isolated_lan(root), "-device", "virtio-net-pci,netdev=pxe,mac=52:54:00:44:00:02",
    ], root, "native-qemu"))


def client(root, server, stage, marker, timeout, *, readonly=False, local=False):
    serial = root / f"{stage}.serial"
    drive = f"file={root / 'client.qcow2'},if=none,id=disk,format=qcow2"
    drive += ",readonly=on" if readonly else ",discard=unmap,detect-zeroes=unmap"
    with serial.open("wb", buffering=0) as stream:
        guest = subprocess.Popen([
            "qemu-system-x86_64", "-machine", "pc,accel=tcg", "-m", "1024", "-smp", "2",
            "-display", "none", "-monitor", "none", "-no-reboot", "-serial", "stdio",
            "-boot", "c" if local else "n", "-netdev", isolated_lan(root),
            "-device", f"e1000,netdev=pxe,mac={MAC}",
            "-drive", drive,
            "-device", f"virtio-blk-pci,drive=disk,serial={SERIAL}",
        ], stdout=stream, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        try:
            wakeup = False
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                ready = marker in check_server(root, server)
                report = serial.read_bytes()
                if local:
                    if not wakeup and b"Debian GNU/Linux 13 pxe-fixture ttyS0" in report:
                        guest.stdin.write(b"\n")
                        guest.stdin.flush()
                        wakeup = True
                    if ready and b"pxe-fixture login:" in report:
                        return
                elif guest.poll() == 0 and ready and b"Linux version" in report:
                    return
                if guest.poll() not in (None, 0) or local and guest.poll() is not None:
                    raise RuntimeError(f"The {stage} client exited before the expected proof")
                time.sleep(1)
            raise RuntimeError(f"The {stage} client timed out")
        finally:
            if guest.poll() is None:
                guest.terminate()
                try:
                    guest.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    guest.kill()
                    guest.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("cloud-image", "inputs", "package", "rust"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    parser.add_argument("--cloud-sha512", type=str.lower, required=True)
    parser.add_argument("--mirror-cache", type=Path)
    parser.add_argument("--keep-fixture", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0 or os.environ.get("PXE_NATIVE_RUST_QEMU_TEST") != "1":
        parser.error("Set PXE_NATIVE_RUST_QEMU_TEST=1 as an unprivileged user on a test host")
    if not re.fullmatch(r"[0-9a-f]{128}", args.cloud_sha512):
        parser.error("Provide the SHA-512 checksum for the Debian 13 amd64 cloud image")
    root = Path(tempfile.mkdtemp(prefix="pxe-native-qemu-", dir="/tmp"))
    print(f"Disposable native fixture: {root}", flush=True)
    try:
        verify_debian_netboot(args.inputs / "linux", args.inputs / "initrd.gz",
                              args.inputs / "SHA256SUMS", args.inputs / "InRelease", KEYRING)
        cache = root / "mirror"
        cache.mkdir()
        if args.mirror_cache:
            for entry in args.mirror_cache.iterdir():
                if re.fullmatch(r"[0-9a-f]{64}", entry.name) and entry.is_file() and not entry.is_symlink():
                    # FullInstallMirror treats existing files as read-only and verifies their digests.
                    try:
                        os.link(entry, cache / entry.name)
                    except OSError:
                        shutil.copyfile(entry, cache / entry.name)
        mirror = FullInstallMirror(cache, args.inputs / "InRelease", KEYRING, b"", args.inputs / "Packages.xz")
        with ExitStack() as stack:
            mirror.start(root / "mirror.sock")
            stack.callback(mirror.close)
            switch = PrivateSwitch(root / "switch.sock", tftp_address=SERVER)
            stack.callback(switch.close)
            server = start_server(root, args, stack)
            wait_server(root, server, READY, 1500)
            print("Native Debian package, Rust, nginx and proxy dnsmasq ready with PHP-FPM masked", flush=True)
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(root / "client.qcow2"), "12G"], check=True)
            client(root, server, "discovery", DISCOVERED, 1200, readonly=True)
            assert any(name.startswith(b"lpxelinux.0") for name in switch.tftp_requests), switch.tftp_requests
            assert b"pxelinux.cfg/default" in switch.tftp_requests, switch.tftp_requests
            print("Real DHCP proxy and TFTP boot led to the native discovery and install menu", flush=True)
            with switch.lock:
                switch.tftp_requests.clear()
            client(root, server, "install", INSTALLED, 2400)
            install_menu = ("pxelinux.cfg/01-" + MAC.replace(":", "-")).encode()
            assert install_menu in switch.tftp_requests, switch.tftp_requests
            print("Native install callback recorded", flush=True)
            client(root, server, "first-boot", BOOTED, 900, local=True)
            for line in check_server(root, server).decode(errors="replace").splitlines():
                if line.startswith(("PXE_NATIVE_PLATFORM ", "PXE_NATIVE_PACKAGE ", "PXE_NATIVE_BINARY ",
                                    "PXE_NATIVE_DNSMASQ ", "PXE_NATIVE_FIRST_BOOT_OK ")):
                    print(line, flush=True)
            print("PASS: Debian 13 native dnsmasq/PXE to installed Debian login and authenticated first-boot receipt", flush=True)
    finally:
        if not args.keep_fixture:
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
