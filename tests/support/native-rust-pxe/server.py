# SPDX-License-Identifier: LGPL-3.0-only
"""Native guest side of the isolated Rust PXE fixture."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time

DATA = Path("/var/lib/pxe-tools")
CONF = Path("/etc/pxe-tools")
APP = Path(os.environ.get("PXE_APP_DIR", "/usr/lib/pxe-tools/app"))
HTTP = Path("/var/lib/pxe-tools-http")
TFTP = Path(os.environ.get("TFTP_ROOT", "/var/lib/pxe-tools-tftp"))
UNIT = Path("/etc/systemd/system")
DATABASE = DATA / "chosen.sqlite"
STALE = DATA / "stale.sqlite"
PXE_IP = "192.0.2.1"
MIRROR_IP = os.environ.get("PXE_FIXTURE_MIRROR_IP", PXE_IP)
CLIENT = "192.0.2.100"
NGINX_LOG = Path(os.environ.get("PXE_FIXTURE_NGINX_LOG", "/var/lib/pxe-tools-native/log/nginx-access.log"))
MAC = "02:00:00:00:00:01"
SERIAL = "PXE-TEST-ONE"
INSTALL_MENU = TFTP / "pxelinux.cfg" / ("01-" + MAC.replace(":", "-"))
DIRECT_HTTP = os.environ.get("PXE_RUST_DIRECT_HTTP") == "1"
SECURE_BOOT = os.environ.get("PXE_FIXTURE_SECURE_BOOT") == "1"
CUSTOM_PARTITIONS = os.environ.get("PXE_FIXTURE_CUSTOM_PARTITIONS") == "1"
USE_WORKER_QUEUE = os.environ.get("PXE_FIXTURE_USE_WORKER") == "1"


def create_db(path, schema, settings):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(schema)
        db.execute("PRAGMA journal_mode=WAL")
        db.executemany("INSERT INTO settings(key,value) VALUES(?,?)", settings.items())
    path.chmod(0o660)


def seed(root):
    if DATA.exists() or CONF.exists():
        raise RuntimeError("The native fixture requires a fresh system")
    DATA.mkdir(mode=0o755)
    CONF.mkdir(mode=0o750)
    (CONF / "db.conf").write_text(json.dumps({"driver": "sqlite", "path": str(DATABASE)}))
    (CONF / "db.conf").chmod(0o640)
    with (CONF / "master.key").open("xb") as key:
        key.write(os.urandom(32))
    (CONF / "master.key").chmod(0o600)
    schema = (root / "schema.sqlite.sql").read_text()
    create_db(DATABASE, schema, {
        "pxe_ip": PXE_IP, "pxe_subnet": "192.0.2.0/24", "pxe_interface": "br-pxetest",
        "pxe_enabled": "on", "dhcp_proxy_enabled": "on", "dhcp_proxy_network": "192.0.2.0",
        "dhcp_proxy_netmask": "255.255.255.0", "https_enabled": "off",
        "wizard_completed": "1", "db_init_done": "1", "admin_created": "1",
        "init_completed": "1", "ansible_enabled": "off", "catalog_auto_refresh_enabled": "off",
    })
    with closing(sqlite3.connect(DATABASE)) as db, db:
        db.execute("""INSERT INTO os_images (distro,version,arch,codename,version_full,enabled,status)
                      VALUES ('debian','13.0','amd64','trixie','13.0',1,'downloaded')""")
    create_db(STALE, schema, {"pxe_ip": "198.51.100.1", "pxe_subnet": "198.51.100.0/24",
                              "pxe_interface": "fixture-stale", "fixture_marker": "preserved"})
    with closing(sqlite3.connect(STALE)) as db, db:
        db.execute("INSERT INTO machines(mac,status) VALUES(?,'wiping')", (MAC,))


def wire(root):
    binary = "/usr/local/libexec/pxe-tools-rust-lab"
    (UNIT / "pxe-tools-rust-lab.service").write_text(f"""[Unit]
Description=PXE Tools Rust backend for the native disposable fixture
Requires=pxe-tools-init.service
After=pxe-tools-init.service
[Service]
User=www-data
Group=www-data
RuntimeDirectory=pxe-tools-rust-lab
RuntimeDirectoryMode=0700
Environment=PXE_DB_PATH={STALE}
ExecStart=/bin/sh -ec 'exec {binary} "$(/usr/bin/python3 {APP}/database_selection.py)" /run/pxe-tools-rust-lab/http.sock'
""")
    original = Path("/usr/lib/systemd/system/pxe-tools-pxe-http.service")
    native = original.read_text()
    for key in ("Requires=", "After="):
        old = f"{key}pxe-tools-php.service pxe-tools-init.service"
        if native.count(old) != 1:
            raise RuntimeError("PXE HTTP unit no longer matches the expected dependency graph")
        native = native.replace(old, f"{key}pxe-tools-rust-lab.service pxe-tools-init.service")
    (UNIT / original.name).write_text(native)
    boot_dir = HTTP / "netboot/debian/13.0/amd64"
    boot_dir.mkdir(parents=True, exist_ok=True)
    for item in ("linux", "initrd.gz"):
        subprocess.run(["install", "-m", "0644", str(root / item), str(boot_dir / item)], check=True)
    env = Path("/usr/lib/pxe-tools/native/default.env")
    opts = ('language=en country=US locale=en_US.UTF-8 keymap=us console=ttyS0,115200n8 '
            'net.ifnames=0 ipv6.disable=1 netcfg/no_default_route=true netcfg/get_nameservers=192.0.2.2')
    env.write_text(env.read_text().replace(f"PXE_DB_PATH={DATA}/pxe-tools.sqlite", f"PXE_DB_PATH={STALE}")
                   + f'\nKERNEL_OPTS="{opts}"\n')
    template = Path("/opt/pxe-tools/templates/discovery-preseed.cfg.j2")
    text = template.read_text()
    for before, after in [
        ("fr_FR.UTF-8", "en_US.UTF-8"), ("xkb-keymap select fr", "xkb-keymap select us"),
        ("debian-installer/language string fr", "debian-installer/language string en"),
        ("debian-installer/country string FR", "debian-installer/country string US"),
        ("mirror/http/hostname string deb.debian.org", f"mirror/http/hostname string {PXE_IP}"),
        ("clock-setup/ntp boolean true", "clock-setup/ntp boolean false"),
    ]:
        if text.count(before) != 1:
            raise RuntimeError("Unexpected discovery fixture template")
        text = text.replace(before, after)
    template.write_text(text + "\nd-i mirror/udeb/suite string trixie\n")


def assert_php_stopped():
    for proc in Path("/proc").iterdir():
        if proc.name.isdecimal():
            try:
                name = (proc / "comm").read_text().strip()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if name.startswith("php-fpm"):
                raise RuntimeError("PHP-FPM started in the native PXE fixture")
    if os.environ.get("PXE_SERVICE_MANAGER") == "s6":
        return
    for name in ("php8.4-fpm.service", "pxe-tools-php.service"):
        state = subprocess.check_output(
            ["systemctl", "show", "--property=UnitFileState,ActiveState", name], text=True
        ).splitlines()
        if set(state) != {"UnitFileState=masked", "ActiveState=inactive"}:
            raise RuntimeError(f"PHP-FPM unit not masked and inactive: {state}")


def wait_for(query, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        assert_php_stopped()
        result = query()
        if result:
            return result
        time.sleep(1)
    raise RuntimeError("Timed out: " + description)


def inventory():
    with closing(sqlite3.connect(DATABASE)) as db:
        return db.execute("SELECT id,inventory_json FROM machines WHERE mac=? AND status='discovered'", (MAC,)).fetchone()


def schedule(machine, report):
    observed = json.loads(report)
    if SECURE_BOOT and (observed["inventory"]["boot_mode"] != "UEFI"
                        or observed["inventory"]["secure_boot"] is not True):
        firmware = observed["inventory"]
        raise RuntimeError(f"Expected Secure Boot inventory, got {firmware['boot_mode']} "
                           f"with secure_boot={firmware['secure_boot']!r}")
    target = next((item for item in observed["disks"]
                   if item["identity"]["value"] == SERIAL and item["identity"]["status"] == "valid"), None)
    if target is None:
        raise RuntimeError("Discovery failed to identify the disposable disk")
    token = secrets.token_hex(32)
    fixture_hash = subprocess.check_output(
        ["openssl", "passwd", "-6", "-salt", "pxe-native-lab", "fixture-password"], text=True
    ).strip()
    with closing(sqlite3.connect(DATABASE)) as db, db:
        action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(?,'install_only','pending',?)",
                            (machine, token)).lastrowid
        config = {
            "distro": "debian", "codename": "trixie", "version_full": "13.0",
            "_pending_action_id": action, "network_mode": "dhcp", "partition_mode": "default",
            "root_login_mode": "disabled", "admin_user_login": "fixture", "admin_user_pwhash": fixture_hash,
            "system_disk_path": "/dev/" + target["name"].removeprefix("/dev/"),
            "system_disk_identity": target["identity"],
            "advanced": {"localization": {"locale": "en_US.UTF-8", "keymap": "us"},
                         "mirror": {"hostname": MIRROR_IP}, "timezone": {"zone": "UTC", "ntp": False},
                         "packages": {"tasksel": ["ssh-server"], "pkgsel_include": ["sudo", "openssh-server", "curl"],
                                      "upgrade": "none"},
                         "apt": {"services_select": [], "contrib": False, "non_free_firmware": False,
                                 "hw_detect_load_firmware": False}, "finish": {"reboot": "quiet"}},
        }
        if CUSTOM_PARTITIONS:
            disk = config["system_disk_path"]
            if disk != "/dev/vda":
                raise RuntimeError("Unexpected disk for the disposable partition recipe")
            second = next((item for item in observed["disks"]
                           if item["identity"]["value"] == "PXE-TEST-TWO"
                           and item["identity"]["status"] == "valid"), None)
            if not second or second["name"].removeprefix("/dev/") != "vdb":
                raise RuntimeError("Discovery failed to identify the second disposable disk")
            config["partition_mode"] = "custom"
            config["review_boot_mode"] = "bios"
            config["advanced"]["bootloader"] = {"bootdev": disk}
            config["partition_custom_json"] = json.dumps({
                "target_disks": [disk, "/dev/vdb"],
                "target_disk_identities": {disk: target["identity"], "/dev/vdb": second["identity"]},
                "disks": [
                    {"path": disk, "partitions": [
                        {"id": "vda1", "fs": "biosgrub", "size_mb": 1},
                        {"id": "vda2", "fs": "ext4", "mount": "/boot", "size_mb": 768},
                        {"id": "vda3", "fs": "swap", "size_mb": 512},
                        {"id": "vda4", "fs": "raid-member", "fill": True},
                    ]},
                    {"path": "/dev/vdb", "partitions": [
                        {"id": "vdb1", "fs": "biosgrub", "size_mb": 1},
                        {"id": "vdb2", "fs": "raid-member", "fill": True},
                    ]},
                ],
                "raid_arrays": [{"name": "md0", "level": 1, "members": ["vda4", "vdb2"]}],
            })
        db.execute("UPDATE machines SET status='configured',hostname='pxe-fixture',domain='example.test',"
                   " install_config_json=? WHERE id=?", (json.dumps(config), machine))
        if USE_WORKER_QUEUE:
            jobs = [
                db.execute("INSERT INTO init_jobs(job_type,status) VALUES(?,'pending')", (kind,)).lastrowid
                for kind in (f"action:render_postboot:{action}", "bootstrap:render_templates")
            ]
    if USE_WORKER_QUEUE:
        def rendered():
            with closing(sqlite3.connect(DATABASE)) as db:
                statuses = [status for status, in db.execute(
                    "SELECT status FROM init_jobs WHERE id IN (?,?) ORDER BY id", jobs,
                )]
            if "failed" in statuses:
                raise RuntimeError("The packaged worker failed to render its boot artifacts")
            return statuses == ["success", "success"]
        wait_for(rendered, 120, "packaged worker rendered menu and postboot artifacts")
    else:
        sys.path.insert(0, str(APP))
        from worker import render_postboot_for_action
        if render_postboot_for_action(action, token, MAC, PXE_IP) is None:
            raise RuntimeError("The native worker could not render its postboot artifacts")
        subprocess.run(["bash", "/opt/pxe-tools/scripts/render-per-mac-pxelinux.sh"], check=True)
    if "DEFAULT install\n" not in INSTALL_MENU.read_text():
        raise RuntimeError("The native renderer did not publish the install menu")
    with closing(sqlite3.connect(DATABASE)) as db, db:
        db.execute("UPDATE machines SET next_action='reboot' WHERE id=?", (machine,))
    return action


def successful_install(action):
    with closing(sqlite3.connect(DATABASE)) as db:
        return db.execute("""SELECT i.install_status,m.status,m.local_boot_source
                             FROM installations i JOIN machines m ON m.id=i.machine_id
                             WHERE i.action_id=?""", (action,)).fetchone() == ("success", "installed", "pxe")


def first_boot(action):
    with closing(sqlite3.connect(DATABASE)) as db:
        receipt = db.execute("SELECT message FROM machine_events WHERE action_id=? AND checkpoint='os_first_boot'",
                             (action,)).fetchone()
        ready = db.execute("SELECT 1 FROM machine_events WHERE message LIKE 'Machine signalée online%'").fetchone()
        guard = db.execute("SELECT 1 FROM task_phases WHERE phase_key='disk-guard' AND status='success'").fetchone()
    if not (receipt and ready and guard):
        return None
    payload = json.loads(receipt[0].removeprefix("checkpoint:os_first_boot "))
    if payload["ip"] != CLIENT or payload["_observed_remote_ip"] != CLIENT or not payload["kernel"]:
        raise RuntimeError("The first-boot receipt lacks the original native client address or kernel")
    if SECURE_BOOT and payload.get("fixture_secure_boot") != 1:
        raise RuntimeError("The installed guest did not boot with Secure Boot enabled")
    if CUSTOM_PARTITIONS and payload.get("fixture_layout") != "gpt-raid1-two-disks":
        raise RuntimeError("The installed system did not boot from the requested GPT/RAID1 recipe")
    # The postboot client asked for an acknowledgement. "accepted\n" is nine bytes.
    if not DIRECT_HTTP and not any(line.startswith(f"{CLIENT} ") and "code=os_first_boot&ack=1" in line and '" 200 9 ' in line
               for line in NGINX_LOG.read_text().splitlines()):
        return None
    return payload["kernel"]


def follow(_root):
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    original_stale = digest(STALE)
    original_key = digest(CONF / "master.key")
    if INSTALL_MENU.exists():
        raise RuntimeError("The new client already has a specific PXE menu")
    assert_php_stopped()
    print("PXE_NATIVE_READY", flush=True)
    machine, report = wait_for(inventory, 1200, "native inventory")
    action = schedule(machine, report)
    print("PXE_NATIVE_DISCOVERY_OK", flush=True)
    wait_for(lambda: successful_install(action), 2400, "native install callback")
    print("PXE_NATIVE_INSTALL_OK", flush=True)
    try:
        kernel = wait_for(lambda: first_boot(action), 900, "native first-boot checkpoint and HTTP acknowledgement")
    except RuntimeError:
        with closing(sqlite3.connect(DATABASE)) as db:
            action_state = db.execute(
                "SELECT a.status,i.install_status,i.ansible_status FROM actions a "
                "JOIN installations i ON i.action_id=a.id WHERE a.id=?", (action,),
            ).fetchone()
        print(f"First-boot fixture action and installation states: {action_state}", flush=True)
        if not DIRECT_HTTP:
            for entry in NGINX_LOG.read_text().splitlines():
                if "code=os_first_boot&ack=1" in entry:
                    print("First-boot HTTP status and bytes:", entry.split('"')[2].strip(), flush=True)
        raise
    if USE_WORKER_QUEUE:
        def worker_finalized():
            with closing(sqlite3.connect(DATABASE)) as db:
                return db.execute(
                    "SELECT a.status,i.ansible_status FROM actions a "
                    "JOIN installations i ON i.action_id=a.id WHERE a.id=?", (action,),
                ).fetchone() == ("success", "no_role")
        wait_for(worker_finalized, 30, "packaged worker finalized the action after first boot")
    if digest(STALE) != original_stale or digest(CONF / "master.key") != original_key:
        raise RuntimeError("The stale database or existing fixture master key was modified")
    assert_php_stopped()
    if not DIRECT_HTTP:
        log = NGINX_LOG.read_text().splitlines()
        for path in ("/api/discovery", "/preseed.php?mac=", "/pxe/postboot/", "/api/install-end?",
                     "/api/machine-ready?", "code=os_first_boot"):
            if not any(line.startswith(f"{CLIENT} ") and path in line and '" 200 ' in line for line in log):
                raise RuntimeError("Missing native HTTP evidence for " + path)
    if CUSTOM_PARTITIONS:
        print("Custom GPT/RAID1 partition recipe verified from the installed guest", flush=True)
    if SECURE_BOOT:
        print("UEFI Secure Boot verified in discovery and the installed guest", flush=True)
    print(f"PXE_NATIVE_FIRST_BOOT_OK kernel={kernel} peer={CLIENT} action={action} ack=accepted", flush=True)
    while True:
        assert_php_stopped()
        time.sleep(1)


if __name__ == "__main__":
    phase, directory = sys.argv[1:]
    {"seed": seed, "wire": wire, "follow": follow}[phase](Path(directory))
