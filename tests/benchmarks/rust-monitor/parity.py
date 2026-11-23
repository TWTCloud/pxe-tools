#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Compare opted-in Rust handlers with the real PHP routes and their SQLite effects."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
import datetime
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlencode

from benchmark import HERE, ROUTE, SOURCE, backend, connect, process, seed, timestamp, write_nginx

BOOT = "/api/boot-selected"
DISCOVERY = "/api/discovery"
POLL = "/api/discovery-action"
START = "/api/install-start"
END = "/api/install-end"
READY = "/api/machine-ready"
CHECKPOINT = "/api/internal/checkpoint"
LOG = "/api/internal/install-log"
PHASE = "/api/task-phase"
PRESEED = "/preseed.php"
GRUB = "/grub.php"
ARTIFACT = "/pxe/postboot/162/postboot.sh"
ROUTES = (ROUTE, BOOT, DISCOVERY, POLL, START, END, READY, CHECKPOINT, LOG, PHASE, PRESEED, GRUB, ARTIFACT)
LAN = "192.0.2.24"


def add_parity_cases(path, catalog):
    now = time.time()
    with closing(sqlite3.connect(path)) as db, db:
        for host, kind in enumerate(("reinstall", "wipe_only", "disktest", "disktest", "disktest"), 81):
            inventory = {"inventory": {"vendor": "  Matériel ", "product": "Échantillon "},
                         "interfaces": [{"mac": f"02:00:00:00:02:{host:02x}"}]}
            db.execute("""INSERT INTO machines(id,mac,hostname,inventory_json,awaiting_action_until)
                          VALUES (?,?,?,?,?)""", (
                host, f"02:00:00:00:01:{host:02x}", None, json.dumps(inventory), timestamp(now, -3600),
            ))
            # The running disk test stays visible through progress, even when its action and
            # last checkpoint are older than the window.
            started = timestamp(now, 100_000 if host == 83 else 600)
            db.execute("INSERT INTO actions(id,machine_id,type,status,token,created_at) VALUES (?,?,?,?,?,?)",
                       (host * 2, host, kind, "running" if host != 85 else "success", f"fixture-{host * 2}", started))
            db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES (?,'reboot','pending',?)",
                       (host, f"untracked-{host}"))
            for step in reversed(catalog[kind][:-1]):
                db.execute("""INSERT INTO machine_events(machine_id,action_id,checkpoint,created_at,message)
                              VALUES (?,?,?,?,'fixture')""", (host, host * 2, step["code"], started))
        # An unknown or stale checkpoint doesn't increase the counters.
        db.execute("""INSERT INTO machine_events(machine_id,action_id,checkpoint,message)
                      VALUES (81,162,'unknown-checkpoint','fixture')""")
        updated = datetime.datetime.fromtimestamp(now - 50, datetime.timezone(datetime.timedelta(hours=2))).isoformat(
            timespec="seconds"
        )
        progress = {"/dev/a": {"pct": "25.5", "updated_at": updated}, "/dev/b": {"pct": 75.5},
                    "/dev/c": {"pct": "n/a"}, "/dev/d": "invalid"}
        db.executemany("INSERT INTO disk_tests(machine_id,action_id,jobs_json,progress_json) VALUES (?,?, '[]',?)",
                       [(83, 166, '{"stale":{"pct":0}}'), (83, 166, json.dumps(progress)),
                        (84, 168, '{malformed'), (85, 170, '[{"pct":-20}]')])
        for boot_id, action_id, token in ((1, 162, "a" * 32), (2, 164, "b" * 32), (3, 162, "c" * 32)):
            db.execute("""INSERT INTO boot_sessions(id,machine_id,action_id,mac,default_menu,token,client_ip)
                          SELECT ?,machine_id,actions.id,mac,'install',?,? FROM actions
                          JOIN machines ON machines.id=actions.machine_id WHERE actions.id=?""",
                       (boot_id, token, LAN, action_id))
        db.execute("UPDATE machines SET inventory_json='{malformed' WHERE id=13")


def response(port, route, method="GET", peer=None, spoof=False, body=None, content_type=None, token=None):
    headers = {"X-Fixture-Peer": peer} if peer else {}
    if spoof:
        headers.update({"X-Pxe-Client-Ip": LAN, "X-Forwarded-For": LAN, "X-Real-IP": LAN})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    with connect(port) as connection:
        connection.request(method, route, body=body, headers=headers)
        result = connection.getresponse()
        body = result.read()
        content_type = result.getheader("Content-Type", "").lower()
        if "application/json" in content_type:
            body = json.loads(body)
        return result.status, content_type, result.getheader("Cache-Control"), body


def compare(ports, route, expected, **kwargs):
    php, rust = (response(port, route, **kwargs) for port in ports)
    assert php[0] == expected, (route.split("?")[0], php[:3], expected)
    if route == ROUTE and expected == 200:
        for result in (php, rust):
            assert isinstance(result[3].pop("generated_at"), int)
    if route == ARTIFACT:
        assert (php[0], php[1].split(";")[0], php[3]) == (rust[0], rust[1].split(";")[0], rust[3]), (php, rust)
        if expected == 200:
            assert php[2] == rust[2] == "no-store"
    else:
        assert php == rust, (route.split("?")[0], php, rust)
    return rust[3]


def compare_states(paths, selectors):
    results = []
    for path in paths:
        with closing(sqlite3.connect(path)) as db:
            results.append([db.execute(sql).fetchall() for sql in selectors])
    assert results[0] == results[1], results
    return results[0]


def php_preseed(root, port):
    templates = SOURCE / "docker/worker/templates"
    renderer = (templates / "preseed.php.j2").read_text()
    renderer = re.sub(r"\{\{ '(\{\{[A-Z_]+\}\})' \}\}", r"\1", renderer)
    renderer = renderer.replace("{{ pxe_data_dir }}", str(root)).replace("{{ pxe_ip }}", "192.0.2.1")
    renderer = renderer.replace("http://127.0.0.1/api/", f"http://127.0.0.1:{port}/api/")
    (root / "preseed.php").write_text(renderer)
    template = (templates / "preseed-base.cfg.j2").read_text()
    template = re.sub(r"\{\{ '(\{\{[A-Z_]+\}\})' \}\}", r"\1", template)
    (root / "preseed-base.cfg").write_text(template)
    grub = (templates / "grub.php.j2").read_text().replace("{{ pxe_data_dir }}", str(root))
    (root / "grub.php").write_text(grub)
    (root / "data.json").write_text(json.dumps({
        "pxe_ip": "192.0.2.1", "default_distro": "trixie",
        "default_arch": "amd64", "kernel_opts": "ipv6.disable=1",
    }))


def compare_grub(ports, paths):
    mac = "02:00:00:00:04:00"
    route = GRUB + "?" + urlencode({"mac": mac, "arch": "aarch64"})
    for port, database in zip(ports, paths):
        assert response(port, route, peer="outside", spoof=True)[0] == 403
        status, _, _, menu = response(port, route, peer="lan")
        assert status == 200 and b"/netboot/trixie/arm64/linux" in menu
        assert b"/discovery-preseed.cfg" in menu and b"${net_default_mac}" in menu
        boot, token = re.search(rb"boot_id=(\d+)&token=([a-f0-9]{32})&menu=discovery", menu).groups()
        assert response(port, BOOT + f"?boot_id={boot.decode()}&token={token.decode()}&menu=discovery",
                        peer="lan")[0] == 200
        with closing(sqlite3.connect(database)) as db, db:
            machine = db.execute("SELECT id,status,boot_arch FROM machines WHERE mac=?", (mac,)).fetchone()
            assert machine[1:] == ("inventorying", "arm64")
            assert db.execute("SELECT selected_menu,client_ip FROM boot_sessions WHERE id=?", (int(boot),)).fetchone() == (
                "discovery", LAN,
            )
            db.execute("UPDATE machines SET status='configured',hostname='PXE-UEFI',install_config_json=? WHERE mac=?",
                       (json.dumps({"codename": "bookworm"}), mac))
            action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(?,'install_only','pending',?)",
                                (machine[0], "grub-fixture")).lastrowid
        status, _, _, menu = response(port, route, peer="lan")
        assert status == 200 and b"/netboot/bookworm/arm64/linux" in menu
        assert b"/preseed.php?mac=" + mac.encode() in menu
        with closing(sqlite3.connect(database)) as db:
            assert db.execute("SELECT checkpoint FROM machine_events WHERE action_id=? AND checkpoint IS NOT NULL",
                              (action,)).fetchall() == [("grub_config_served_install",)]


def compare_inventory(ports, paths):
    mac = "02:00:00:00:03:01"
    second = "02:00:00:00:03:02"
    data = {
        "mac": mac, "inventory": {"cpu_arch": "x86_64"},
        "interfaces": [{"mac": mac}, {"mac": second}],
        "disks": [
            {"name": "/dev/vda", "serial": " serial-01 ", "filesystem": {"uuid": "informative"},
             "partitions": [{"number": "0001", "size_bytes": "18446744073709551616"}],
             "metadata_collection": {"filesystem_status": "available", "mmc_status": "available"}},
            {"name": "vdb", "serial": "Serial-01"},
            {"name": "sda", "vendor": "Msft", "model": "Virtual Disk", "identity":
                {"kind": "wwid", "value": "naa." + "a" * 32, "source": "sysfs-wwid"}},
            {"name": "/dev/mmcblk0", "filesystem": {}, "partitions": [], "mmc": {
                "cid": "a" * 32, "csd": "invalid",
                "hardware_regions": [
                    {"name": "mmcblk0boot0", "path": "/dev/mmcblk0boot0", "force_ro": "1"},
                    {"name": "rpmb8", "path": "/dev/rpmb8", "parent_path": "/dev/mmcblk0"},
                    {"name": "rpmb9", "path": "/dev/rpmb9", "parent_path": "/dev/mmcblk1"},
                ],
            }, "metadata_collection": {"filesystem_status": "available", "mmc_status": "available"}},
        ],
    }
    def post(payload, code=200):
        return compare(ports, DISCOVERY, code, method="POST", peer="lan",
                       content_type="application/json", body=json.dumps(payload).encode())
    compare(ports, DISCOVERY, 422)
    compare(ports, DISCOVERY + "?b64=bad%24", 400)
    compare(ports, DISCOVERY + "?b64%5B%5D=bad", 400)
    compare(ports, DISCOVERY, 400, method="POST", content_type="application/json", body=b"{")
    post({"mac": mac}, 422)
    post({**data, "mac": "incorrect"}, 400)
    post({**data, "padding": "x" * 1_048_576}, 413)
    machine = post(data)["machine_id"]
    data["mac"] = second
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    result = compare(ports, DISCOVERY + "?" + urlencode({"b64": payload}), 200, peer="lan")
    assert result == {"status": "updated", "machine_id": machine, "matched_via": "secondary_nic", "merged_ids": []}
    result = compare(ports, DISCOVERY, 200, peer="lan", method="POST",
                     content_type="application/x-www-form-urlencoded", body=urlencode({"b64": payload}))
    assert result["machine_id"] == machine
    for database in paths:
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE machines SET next_action='reboot', status='configured' WHERE id=?", (machine,))
    result = compare(ports, POLL + "?" + urlencode({"mac": second}), 200)
    assert result == {"action": "reboot", "remaining_seconds": 0}
    assert compare(ports, POLL + "?" + urlencode({"mac": second}), 200)["action"] == "wait"
    inventories = []
    for database in paths:
        with closing(sqlite3.connect(database)) as db, db:
            status, arch, snapshot = db.execute(
                "SELECT status,boot_arch,inventory_json FROM machines WHERE id=?", (machine,)
            ).fetchone()
            assert (status, arch) == ("configured", "amd64")
            assert db.execute("SELECT count(*) FROM discoveries WHERE machine_id=? AND discovery_status='success'",
                              (machine,)).fetchone() == (3,)
            inventory = json.loads(snapshot)
            inventory.pop("discovered_at")
            inventories.append(inventory)
            db.execute("INSERT INTO machines(mac,status) VALUES(?,'inventorying')", (second,))
    assert inventories[0] == inventories[1]
    assert [disk["identity"]["status"] for disk in inventories[1]["disks"]] == ["ambiguous", "ambiguous", "valid", "missing"]
    post(data, 409)
    logs, = compare_states(paths, ["SELECT machine_id,level,message FROM machine_events WHERE message LIKE 'Conflit de découverte%' ORDER BY id"])
    assert len(logs) == 2


def compare_install(ports, paths):
    mac = "02:00:00:00:01:51"
    token = "e" * 64
    config = {"distro": "debian", "codename": "trixie", "_pending_action_id": 162,
              "system_disk_path": "/dev/vda", "system_disk_identity": {"kind": "serial", "value": " PXE-TEST-ONE ", "status": "valid"},
              "root_login_mode": "disabled", "root_password_hash": "$6$hidden",
              "admin_user_login": "fixture", "admin_user_pwhash": "$6$fixture$hash",
              "admin_user_pubkeys": "ssh-ed25519 AAAA fixture",
              "network": {"interfaces": [{"mode": "dhcp", "match_by": "primary"}], "primary": 0},
              "advanced": {"apt": {"services_select": []},
                           "packages": {"tasksel": ["ssh-server"], "pkgsel_include": ["openssh-server"],
                                        "upgrade": "none"}}}
    for database in paths:
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE actions SET token=?,status='pending' WHERE id=162", (token,))
            db.execute("DELETE FROM machine_events WHERE action_id=162 AND checkpoint='os_first_boot'")
            db.execute("UPDATE machines SET status='configured', local_boot_source='manual', hostname='Host', domain='example.test',"
                       " install_config_json=? WHERE id=81", (json.dumps(config),))
    query = "?" + urlencode({"mac": mac})
    compare(ports, START + query, 404, peer="lan")
    compare(ports, PRESEED + query, 403, peer="outside", spoof=True)
    compare(ports, PRESEED, 400, peer="lan")
    compare(ports, ARTIFACT, 404, peer="lan")
    seeds = [response(port, PRESEED + query, peer="lan") for port in ports]
    assert [item[:3] for item in seeds] == [(200, "text/plain; charset=utf-8", "no-store")] * 2
    decoded = [item[3].decode() for item in seeds]
    def directives(seed):
        return [line.rstrip() for line in seed.splitlines() if line.startswith(("d-i ", "tasksel ", "popularity-contest "))
                and not re.match(r"d-i (preseed|partman)/.*_command ", line)]
    assert directives(decoded[0]) == directives(decoded[1]), (directives(decoded[0]), directives(decoded[1]))
    guard = r"echo ([A-Za-z0-9+/=]+) \| base64 -d > /tmp/pxe-disk-guard.sh"
    assert re.search(guard, decoded[0]).group(1) == re.search(guard, decoded[1]).group(1)
    for seed in decoded:
        assert "d-i pkgsel/include string openssh-server curl iproute2" in seed
        assert "in-target /usr/bin/curl -fsS --connect-timeout 5 --max-time 20 --retry 3" in seed
        assert "systemctl enable pxe-postboot.service || exit 1" in seed
    dependency = re.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d > /etc/systemd/system/pxe-postboot.service.d/ready.conf", decoded[1])
    assert base64.b64decode(dependency.group(1)) == (
        b"[Unit]\nRequires=pxe-machine-ready.service\nAfter=pxe-machine-ready.service\n"
    )
    for seed in decoded:
        assert "Bearer " + token in seed and "$6$hidden" not in seed
        assert "services-select multiselect" in seed
        assert "/dev/vda:" + base64.b64encode(b"PXE-TEST-ONE").decode() in seed
    def set_config(snapshot):
        for database in paths:
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("UPDATE machines SET install_config_json=? WHERE id=81", (json.dumps(snapshot),))

    vlan = {"mode": "static", "match_by": "mac", "match": {"mac": "02:00:00:00:51:02"},
            "vlan": {"id": 77}, "static": {"ip": "198.51.100.4", "cidr": 24,
                                           "gateway": "198.51.100.1", "dns": ["198.51.100.53"]}}
    primary = {"mode": "dhcp", "match_by": "mac", "match": {"mac": mac}}
    secondary = {"mode": "dhcp", "match_by": "mac", "match": {"mac": "02:00:00:00:51:03"}}
    disabled = {"mode": "disabled", "match_by": "index"}
    multi = {**config, "network": {"interfaces": [vlan, primary, secondary, disabled], "primary": 1}}
    set_config(multi)
    seeds = [response(port, PRESEED + query, peer="lan") for port in ports]
    assert [item[0] for item in seeds] == [200, 200]
    decoded = [item[3].decode() for item in seeds]
    assert directives(decoded[0]) == directives(decoded[1]), (directives(decoded[0]), directives(decoded[1]))
    for seed in decoded:
        assert f"d-i netcfg/choose_interface select {mac}" in seed
        assert "d-i pkgsel/include string openssh-server vlan curl iproute2" in seed
        assert "/etc/network/interfaces.d/pxe-nic-03" not in seed
    stanza = r"echo ([A-Za-z0-9+/=]+) \| base64 -d \| sed .*?/etc/network/interfaces.d/pxe-nic-(\d{2})"
    generated = [{index: base64.b64decode(data).decode() for data, index in re.findall(stanza, seed)} for seed in decoded]
    assert generated[0] == generated[1]
    assert "iface __IFNAME__.77 inet static" in generated[1]["00"]
    assert "vlan-raw-device __IFNAME__" in generated[1]["00"]
    assert "iface __IFNAME__ inet dhcp" in generated[1]["02"]
    master_mac = "02:00:00:00:51:04"
    master = {**vlan, "match": {"mac": master_mac}, "vlan": None,
              "bond": {"name": "bond0", "role": "master", "mode": "active-backup"}}
    member = {**primary, "bond": {"name": "bond0", "role": "slave"}}
    bonded = {**multi, "network": {"interfaces": [master, member, secondary], "primary": 1}}
    set_config(bonded)
    seeds = [response(port, PRESEED + query, peer="lan") for port in ports]
    assert [item[0] for item in seeds] == [200, 200]
    decoded = [item[3].decode() for item in seeds]
    assert directives(decoded[0]) == directives(decoded[1]), (directives(decoded[0]), directives(decoded[1]))
    for seed in decoded:
        assert f"d-i netcfg/choose_interface select {mac}" in seed
        assert "d-i netcfg/get_ipaddress string 198.51.100.4" in seed
        assert "d-i pkgsel/include string openssh-server ifenslave curl iproute2" in seed
    shell = [base64.b64decode(re.search(pattern, seed).group(1)) for pattern, seed in zip((
        r"echo ([A-Za-z0-9+/=]+) \| base64 -d > /tmp/pxe-bond.sh",
        r"echo ([A-Za-z0-9+/=]+) \| base64 -d \| /bin/bash'",
    ), decoded, strict=True)]
    assert shell[0] == shell[1]
    assert f"for mac in {mac} {master_mac}; do".encode() in shell[1]
    assert b"bond-primary-reselect always" in shell[1]
    subprocess.run(["bash", "-n"], input=shell[1], check=True)
    set_config({**bonded, "network": {"interfaces": [master], "primary": 0}})
    assert response(ports[1], PRESEED + query, peer="lan")[0] == 422
    invalid_vlan = {**multi, "network": {"interfaces": [vlan, primary], "primary": 0}}
    set_config(invalid_vlan)
    assert response(ports[1], PRESEED + query, peer="lan")[0] == 422
    target = "/dev/vda"
    proof = {"kind": "serial", "value": "PXE-TEST-ONE", "status": "valid"}
    root = {"id": "vda2", "fs": "ext4", "mount": "/", "fill": True, "reserved_pct": 2,
            "mount_options": ["noatime"]}
    for firmware, first in (
        ("bios", {"id": "vda1", "fs": "biosgrub", "size_mb": 1}),
        ("uefi", {"id": "vda1", "fs": "efi", "mount": "/boot/efi", "size_mb": 512}),
    ):
        plan = {"target_disks": [target], "target_disk_identities": {target: proof},
                "disks": [{"path": target, "partitions": [first, root]}]}
        recipe = {**config, "partition_mode": "custom", "partition_custom_json": json.dumps(plan),
                  "review_boot_mode": firmware, "disk_target_constraints": {target: "PXE-TEST-ONE"}}
        set_config(recipe)
        seeds = [response(port, PRESEED + query, peer="lan") for port in ports]
        assert [item[0] for item in seeds] == [200, 200]
        rendered = [item[3].decode() for item in seeds]
        assert directives(rendered[0]) == directives(rendered[1])
        def partman_block(seed):
            return re.search(r"custom_recipe ::.*?\nd-i partman-auto/choose_recipe", seed, re.S).group(0)
        assert partman_block(rendered[0]) == partman_block(rendered[1])
        for seed in rendered:
            assert "for pair in /:2;" in seed
            assert target + ":" + base64.b64encode(proof["value"].encode()).decode() in seed
            embedded = base64.b64decode(re.search(guard, seed).group(1))
            assert f"EXPECTED_BOOT_MODE='{firmware}'".encode() in embedded
        set_config({**recipe, "review_boot_mode": "bios" if firmware == "uefi" else "uefi"})
        assert response(ports[1], PRESEED + query, peer="lan")[0] == 422
        set_config({**recipe, "disk_target_constraints": {target: "OTHER-DISK"}})
        assert response(ports[1], PRESEED + query, peer="lan")[0] == 422
    set_config(config)
    assert compare(ports, START + query, 200)["installation_id"] == 1
    assert compare(ports, ARTIFACT, 200, peer="lan") == b"#!/bin/sh\ntrue\n"
    compare(ports, ARTIFACT, 404, peer="outside", spoof=True)
    compare(ports, END + query, 404, peer="lan")
    compare(ports, END + query, 404, peer="outside", token=token, spoof=True)
    compare(ports, END + query, 404, peer="lan", token="b" * 64)
    compare(ports, LOG + "?install_id=1", 401, method="POST", peer="outside", token=token)
    compare(ports, LOG + "?install_id=2", 401, method="POST", peer="lan", token=token)
    compare(ports, LOG + "?install_id=1", 413, method="POST", peer="lan", token=token, body=b"x" * 262145)
    chunk = "journal système\n".encode()
    result = compare(ports, LOG + "?install_id=1&seq=42", 200, method="POST", peer="lan",
                     token=token, content_type="text/plain", body=chunk)
    assert result == {"status": "ok", "bytes": len(chunk), "appended": len(chunk), "seq": 42}
    assert compare(ports, CHECKPOINT + query + "&code=late_command_started&ack=1", 200,
                   method="POST", peer="lan", token=token) == b""
    assert compare(ports, END, 200, method="POST", peer="lan", token=token,
                   content_type="application/x-www-form-urlencoded", body=urlencode({"mac": mac}))["machine_status"] == "installed"
    compare(ports, END + query, 200, peer="lan", token=token)  # Replay is idempotent.
    compare(ports, PRESEED + query, 404, peer="lan")
    compare(ports, START + query, 409)
    compare(ports, ARTIFACT, 404, peer="lan")
    compare(ports, READY + query, 200, peer="lan")
    first_boot = CHECKPOINT + query + "&code=os_first_boot"
    ack = first_boot + "&ack=1"
    assert compare(ports, ack, 200, method="POST", peer="outside", token=token, spoof=True) == b""
    assert compare(ports, ack, 200, method="POST", peer="lan", token="b" * 64) == b""
    other_mac = urlencode({"mac": "02:00:00:00:01:52"})
    assert compare(ports, f"{CHECKPOINT}?{other_mac}&code=os_first_boot&ack=1", 200,
                   method="POST", peer="lan", token=token) == b""
    assert compare(ports, ack, 200, method="POST", peer="lan", token=token, spoof=True,
                   body=b'{"_observed_remote_ip":"fake","kernel":"fixture"}') == b"accepted\n"
    assert compare(ports, ack, 200, method="POST", peer="lan", token=token) == b"accepted\n"
    states = compare_states(paths, [
        "SELECT status,local_boot_source FROM machines WHERE id=81",
        "SELECT action_id,install_status,ansible_status,install_log FROM installations",
        "SELECT status FROM actions WHERE id=162",
    ])
    assert states == [[("installed", "pxe")], [(162, "success", "pending", chunk.decode())], [("running",)]]
    closed_token = "c" * 64
    for database in paths:
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE actions SET status='success' WHERE id=162")
            db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES (81,'install_only','success',?)",
                       (closed_token,))
    assert compare(ports, ack, 200, method="POST", peer="lan", token=closed_token) == b"closed\n"
    assert compare(ports, ack, 200, method="POST", peer="lan", token=token) == b"accepted\n"
    assert compare(ports, first_boot, 200, method="POST", peer="lan", token=token) == b""
    for database in paths:
        with closing(sqlite3.connect(database)) as db:
            events = db.execute("SELECT message FROM machine_events WHERE action_id=162 AND checkpoint='os_first_boot'").fetchall()
            assert len(events) == 1
            receipt = json.loads(events[0][0].removeprefix("checkpoint:os_first_boot "))
            assert receipt["_observed_remote_ip"] == LAN and receipt["_proxy_headers_seen"] is True



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", default=shutil.which("nginx") or "/usr/sbin/nginx")
    parser.add_argument("--fpm", default=shutil.which("php-fpm") or "/usr/sbin/php-fpm8.4")
    parser.add_argument("--rust", default=str(SOURCE / "rust/target/release/pxe-tools-rust"))
    args = parser.parse_args()
    if os.geteuid() == 0 or os.path.lexists("/etc/pxe-tools/db.conf"):
        parser.error("Run as an unprivileged user on a test host without appliance configuration.")
    environment = {**os.environ, "PXE_BENCH_APP": str(SOURCE / "app"), "PXE_DB_DRIVER": "sqlite"}
    catalog = json.loads(subprocess.check_output(["php", str(HERE / "monitor.php"), "--catalog"], env=environment))
    assert catalog == json.loads((SOURCE / "rust/src/checkpoints.json").read_text())
    with tempfile.TemporaryDirectory(prefix="pxe-parity-", dir="/tmp") as temporary, ExitStack() as stack:
        base = Path(temporary)
        php, rust = base / "php", base / "rust"
        php.mkdir(mode=0o700)
        rust.mkdir(mode=0o700)
        paths = (php / "fixture.sqlite", rust / "fixture.sqlite")
        php_db, rust_db = paths
        seed(php, environment, SOURCE)
        add_parity_cases(php_db, catalog)
        with closing(sqlite3.connect(php_db)) as src, closing(sqlite3.connect(rust_db)) as dst:
            src.backup(dst)

        ports = []
        for variant, root, db in (("php-ondemand-3", php, php_db), ("rust-3", rust, rust_db)):
            _, upstream, handler = stack.enter_context(
                backend(variant, root, args, {**environment, "PXE_DB_PATH": str(db),
                        "PXE_APP_DIR": str(SOURCE / "app"), "POSTBOOT_OUTPUT_DIR": str(root / "postboot"),
                        "PXE_SESSION_DIR": str(root / "sessions"), "KERNEL_OPTS": "ipv6.disable=1"})
            )
            config, port = write_nginx(root, variant, upstream, handler, routes=ROUTES)
            if variant.startswith("php"):
                php_preseed(root, port)
            artifact = root / "postboot/162/postboot.sh"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("#!/bin/sh\ntrue\n")
            with closing(sqlite3.connect(db)) as connection, connection:
                connection.execute("INSERT INTO settings(key,value) VALUES('pxe_ip','192.0.2.1')")
            stack.enter_context(process([args.nginx, "-p", str(root), "-c", str(config)], root, "nginx"))
            for _ in range(100):
                try:
                    response(port, ROUTE)
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(f"nginx failed to start for {variant}")
            ports.append(port)

        result = compare(ports, ROUTE, 200)["installs"]
        assert len(result) == 69
        latest = {item["machine_id"]: item for item in result}
        assert latest[13]["label"] == "machine-13"
        assert latest[81]["label"] == "Matériel Échantillon"
        assert latest[83]["pct"] == 51
        assert latest[84]["pct"] == 80
        assert latest[85]["pct"] == 100
        compare(ports, ROUTE, 200, peer="alternate_loopback")
        compare(ports, ROUTE, 200, peer="lan")
        compare(ports, ROUTE, 403, peer="outside", spoof=True)
        compare(ports, ROUTE, 403, peer="ipv6")
        for database in paths:
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("UPDATE settings SET value='192.0.2.0/024' WHERE key='pxe_subnet'")
        compare(ports, ROUTE, 403, peer="lan")
        compare(ports, ROUTE, 200)
        for database in paths:
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("UPDATE settings SET value='192.0.2.0/24' WHERE key='pxe_subnet'")

        def selection(token="a" * 32, menu="local", boot_id="1"):
            return BOOT + "?" + urlencode(dict(token=token, menu=menu, boot_id=boot_id))

        compare(ports, selection(), 404, peer="outside", spoof=True)
        compare(ports, selection(), 404)
        compare(ports, selection(token="b" * 32), 404, peer="lan")
        compare(ports, selection(menu="missing"), 404, peer="lan")
        compare(ports, selection(boot_id="-1"), 404, peer="lan")
        assert compare_states(paths, ["SELECT selected_menu FROM boot_sessions"]) == [[(None,)] * 3]
        # Concurrent initial requests and retries share one selection and checkpoint.
        for port in ports:
            with ThreadPoolExecutor(max_workers=4) as pool:
                assert list(pool.map(lambda _: response(port, selection(), peer="lan")[0], range(8))) == [200] * 8
        compare(ports, selection(menu="install"), 404, peer="lan")
        compare(ports, selection(boot_id="2", token="b" * 32), 200, peer="lan")
        compare(ports, selection(boot_id="3", token="c" * 32), 200, peer="lan")
        boots, events = compare_states(paths, [
            "SELECT selected_menu, length(selected_at) FROM boot_sessions ORDER BY id",
            "SELECT machine_id, level, message, checkpoint, action_id FROM machine_events WHERE action_id IN (162,164) ORDER BY id",
        ])
        assert boots == [("local", 19)] * 3
        assert sum(event[3] == "install_reboot_done" for event in events) == 1

        primary = "02:00:00:00:01:51"
        secondary = "01-02-00-00-00-02-51"
        for phase, mac, method in (("scan_start", primary, "GET"), ("post_0_failure", secondary, "POST"),
                                   ("action_poweroff", secondary, "GET"), ("scan_start", "invalid", "GET")):
            route = DISCOVERY + "?" + urlencode(dict(phase=phase, mac=mac))
            assert compare(ports, route, 200, method=method) == {"status": "phase_ack", "phase": phase}
        logs, inventory = compare_states(paths, [
            "SELECT machine_id, level, message FROM machine_events WHERE action_id IS NULL ORDER BY id",
            "SELECT inventory_json, status, next_action FROM machines WHERE id=81",
        ])
        assert logs == [(81, "info", "discover.sh phase: scan_start"),
                        (81, "warning", "discover.sh phase: post_0_failure"),
                        (81, "info", "discover.sh phase: action_poweroff")]
        assert inventory[0][1:] == ("unknown", None)
        # Compare both stored UTC deadlines without requiring the requests to land on the same second.
        for database in paths:
            with closing(sqlite3.connect(database)) as db:
                deadline, = db.execute("SELECT unixepoch(awaiting_action_until) FROM machines WHERE id=81").fetchone()
                assert abs(time.time() - deadline) < 10
        compare_inventory(ports, paths)
        compare_install(ports, paths)

        # A failed event insert must leave the Rust boot selection available for retry.
        with closing(sqlite3.connect(rust_db)) as db, db:
            db.execute("""INSERT INTO boot_sessions(id,machine_id,mac,default_menu,token)
                          VALUES (4,81,?,'install',?)""", (primary, "d" * 32))
            db.execute("""CREATE TRIGGER fail_event BEFORE INSERT ON machine_events
                          BEGIN SELECT RAISE(ABORT, 'fixture write failure'); END""")
        retry = selection(boot_id="4", token="d" * 32)
        assert response(ports[1], retry, peer="lan")[0] == 500
        with closing(sqlite3.connect(rust_db)) as db, db:
            assert db.execute("SELECT selected_menu, selected_at FROM boot_sessions WHERE id=4").fetchone() == (None, None)
            db.execute("DROP TRIGGER fail_event")
        assert response(ports[1], retry, peer="lan")[0] == 200
        compare_grub(ports, paths)
    print("Parity OK: 69 summaries, GRUB menus and selection, discovery inventory, preseed with advanced networking and single-disk recipes, and installation callbacks")


if __name__ == "__main__":
    main()
