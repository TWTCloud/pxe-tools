#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Boot the official Proxmox VE ISO with KVM on a disposable, disconnected LAN."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlencode

REPO = Path(__file__).resolve().parents[2]
SERVER, CLIENT, MAC = "192.0.2.1", "192.0.2.10", "52:54:00:73:92:01"
HOSTNAME, SERIAL = "pve-pxe.example.test", "PXE-PVE-TEST"
ADMIN = "fixture-admin:fixture-login-password"


def run(*args, **options):
    return subprocess.run(list(map(str, args)), check=True, **options)


def wait_for(check, description, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(3)
    raise RuntimeError(f"Délai dépassé pour {description}")


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main(binary, logs):
    if os.geteuid() != 0 or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SystemExit("Le banc exige root et KVM. Aucun repli vers TCG.")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[os.uname().machine]
    qemu, grub_target, firmware, firmware_vars, machine = {
        "amd64": ("qemu-system-x86_64", "x86_64-efi", "/usr/share/OVMF/OVMF_CODE_4M.fd",
                  "/usr/share/OVMF/OVMF_VARS_4M.fd", "q35"),
        "arm64": ("qemu-system-aarch64", "arm64-efi", "/usr/share/AAVMF/AAVMF_CODE.fd",
                  "/usr/share/AAVMF/AAVMF_VARS.fd", "virt"),
    }[arch]
    sha = {
        "amd64": "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
        "arm64": "b1619dcd1f5b1a6d67d77b59e7e2fa2033174551d1e1b9dc22b2171ec093abbd",
    }[arch]
    logs.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="pxe-proxmox-") as directory, ExitStack() as cleanup:
        root = Path(directory)
        public, tftp = root/"http", root/"tftp"
        public.mkdir()
        tftp.mkdir()
        cert, key = root/"cert.pem", root/"key.pem"
        run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", f"/CN={SERVER}", "-addext", f"subjectAltName=IP:{SERVER}",
            "-days", 1, "-keyout", key, "-out", cert,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        dbfile, config = root/"fixture.sqlite", root/"db.json"
        config.write_text(json.dumps({"driver": "sqlite", "path": str(dbfile)}))
        with sqlite3.connect(dbfile) as db:
            db.executescript((REPO/"app/db/schema.sqlite.sql").read_text())
            db.executemany("INSERT INTO settings(key,value) VALUES(?,?)", [
                ("pxe_enabled", "on"), ("pxe_ip", SERVER), ("pxe_subnet", "192.0.2.0/24"),
                ("pxe_interface", "pxetap"), ("wizard_completed", "1"),
                ("media_import_request_1", json.dumps({"kind": "proxmox", "source": arch,
                 "sha256": sha, "profile": f"{SERVER}:443:{pin}", "remote": False})),
            ])
            db.execute("INSERT INTO init_jobs(id,job_type,status) VALUES(1,'media:prepare','pending')")
            db.execute("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)", (
                "fixture-admin", "$2y$12$zGZhsSwt3AHDHVbliUPl5eMV46SsqfpLUsIOAcZiq1frkQPqxaEcK",
            ))
            inventory = {"boot_mac": MAC, "discovery_ip": CLIENT, "inventory": {"boot_mode": "UEFI"},
                         "disks": [{"name": "sda", "serial": SERIAL}]}
            device, = db.execute("""INSERT INTO machines(mac,status,boot_arch,inventory_json)
                VALUES(?,'discovered',?,?) RETURNING id""", (MAC, arch, json.dumps(inventory))).fetchone()
        environment = {**os.environ, "HTTP_ROOT": str(public), "TLS_DIR": str(root),
                       "PXE_HTTP_PORT": "80", "PXE_HTTPS_PORT": "443", "AUTH_MODE": "local",
                       "PXE_TLS_IMPORT_DIR": str(root/"tls-import")}
        print(f"Préparation du vrai ISO Proxmox VE 9.2-1 {arch} avec le worker", flush=True)
        run(binary, "--run-media-import", dbfile, 1, REPO/"docker/worker/scripts", env=environment)
        with sqlite3.connect(dbfile) as db:
            state, message = db.execute("SELECT status,message FROM init_jobs WHERE id=1").fetchone()
        print(message, flush=True)
        if state != "success":
            raise RuntimeError("La préparation du média Proxmox a échoué")
        stage = public/"netboot/proxmox/9.2-1"/arch
        for name in ["linux", "initrd.gz", "source.iso"]:
            assert (stage/name).stat().st_size > 0

        namespace = f"pxe-pve-{os.getpid()}"
        run("ip", "netns", "add", namespace)
        cleanup.callback(run, "ip", "netns", "del", namespace)
        ns = ("ip", "netns", "exec", namespace)
        run(*ns, "ip", "link", "set", "lo", "up")
        run(*ns, "ip", "tuntap", "add", "dev", "pxetap", "mode", "tap")
        run(*ns, "ip", "addr", "add", f"{SERVER}/24", "dev", "pxetap")
        run(*ns, "ip", "link", "set", "pxetap", "up")
        assert not run(*ns, "ip", "route", "list", "default", capture_output=True).stdout

        def launch(label, *command, **options):
            log = cleanup.enter_context((logs/f"{label}.log").open("wb"))
            process = subprocess.Popen([*ns, *map(str, command)], stdout=log, stderr=subprocess.STDOUT, **options)
            cleanup.callback(stop, process)
            return process

        seed = "/grub.php?" + urlencode({"mac": MAC, "arch": arch})
        # Only the first-stage EFI loader is a fixture. The menu and all installation
        # responses are supplied by the product.
        grub = root/"grub.cfg"
        grub.write_text(f"""insmod efinet
insmod net
insmod http
net_bootp
configfile (http,{SERVER}){seed}
""")
        run("grub-mkstandalone", "-O", grub_target, "--modules=efinet net http configfile normal linux",
            "-o", tftp/"grub.efi", f"boot/grub/grub.cfg={grub}")
        launch("dhcp", "dnsmasq", "--no-daemon", "--log-dhcp", "--user=root", "--port=0",
               "--interface=pxetap", "--bind-interfaces", "--dhcp-authoritative",
               f"--dhcp-range={CLIENT},{CLIENT},255.255.255.0,1h",
               f"--dhcp-host={MAC},{CLIENT}", f"--dhcp-option=option:router,{SERVER}",
               f"--dhcp-option=option:dns-server,{SERVER}", "--enable-tftp", f"--tftp-root={tftp}",
               f"--dhcp-boot=grub.efi,,{SERVER}", f"--dhcp-leasefile={root/'leases'}")
        service = launch("pxe-tools", binary, "--serve-guided", config, env=environment)

        def curl(*args):
            return subprocess.run([*ns, "curl", "-fsS", "--connect-timeout", "2", "--max-time", "12",
                                   *map(str, args)], capture_output=True)

        def ready():
            if service.poll() is not None:
                raise RuntimeError("Le serveur PXE s’est arrêté avant les essais")
            return curl("--cacert", cert, f"https://{SERVER}/healthz").returncode == 0

        wait_for(ready, "la console HTTPS Rust", 45)
        form = urlencode({"image": "proxmox-9.2-1", "disk": f"/dev/sda:{SERIAL}", "hostname": HOSTNAME,
                          "login": "", "proxmox_email": "admin@example.test", "password": "fixture-pve-password",
                          "password_confirm": "fixture-pve-password", "confirm": "yes"})
        schedule = curl("--cacert", cert, "-u", ADMIN, "-H", f"Origin: https://{SERVER}", "-D", "-",
                        "-d", form, f"https://{SERVER}/machines/{device}/install/linux")
        if schedule.returncode != 0 or b"303" not in schedule.stdout.splitlines()[0]:
            raise RuntimeError(f"La planification Proxmox a échoué (curl={schedule.returncode})")
        drive = root/"disk.qcow2"
        run("qemu-img", "create", "-f", "qcow2", drive, "32G")
        vars_file = root/"uefi-vars.fd"
        shutil.copyfile(firmware_vars, vars_file)
        guest = launch("guest", qemu, "-machine", f"{machine},accel=kvm", "-cpu", "host", "-smp", "2",
                       "-m", "8192", "-display", "none", "-serial", "stdio",
                       "-monitor", f"unix:{root / 'monitor.sock'},server=on,wait=off",
                       "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
                       "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
                       "-netdev", "tap,id=lan,ifname=pxetap,script=no,downscript=no",
                       "-device", f"virtio-net-pci,netdev=lan,mac={MAC},bootindex=2",
                       "-device", "virtio-scsi-pci,id=scsi",
                       "-drive", f"if=none,id=target,format=qcow2,file={drive}",
                       "-device", f"scsi-hd,drive=target,serial={SERIAL},bootindex=1")
        print("Client UEFI démarré avec KVM sur le LAN isolé", flush=True)

        def installed():
            if guest.poll() is not None:
                raise RuntimeError("Le client KVM s’est arrêté avant la confirmation du premier démarrage")
            with sqlite3.connect(dbfile) as db:
                return db.execute("""SELECT EXISTS(
                    SELECT 1 FROM machine_events e JOIN installations i ON i.action_id=e.action_id
                    WHERE e.machine_id=? AND e.checkpoint='os_first_boot' AND i.install_status='success')""",
                                  (device,)).fetchone()[0]

        try:
            wait_for(installed, "le premier démarrage de Proxmox VE", 1200)
            version = wait_for(lambda: curl("-k", f"https://{CLIENT}:8006/").stdout,
                               "l’interface Proxmox sur le port 8006", 90)
            if not re.search(rb"Proxmox (Virtual Environment|VE)", version, re.I):
                raise RuntimeError("Le port 8006 ne présente pas la console Proxmox")
        finally:
            with sqlite3.connect(dbfile) as db:
                diagnostics = db.execute("SELECT status,local_boot_source FROM machines").fetchall(), \
                    db.execute("SELECT level,message,checkpoint FROM machine_events ORDER BY id").fetchall()
            (logs/"state.json").write_text(json.dumps(diagnostics, indent=2, ensure_ascii=False))
        print(f"Proxmox VE 9.2-1 {arch} installé depuis PXE. Premier démarrage et HTTPS 8006 confirmés.", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2]).resolve())
