#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Compare opted-in Rust handlers with the real PHP routes and their SQLite effects."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
import datetime
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlencode

from benchmark import HERE, ROUTE, SOURCE, backend, connect, process, seed, timestamp, write_nginx

BOOT = "/api/boot-selected"
DISCOVERY = "/api/discovery"
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


def response(port, route, method="GET", peer=None, spoof=False):
    headers = {"X-Fixture-Peer": peer} if peer else {}
    if spoof:
        headers.update({"X-Pxe-Client-Ip": LAN, "X-Forwarded-For": LAN, "X-Real-IP": LAN})
    with connect(port) as connection:
        connection.request(method, route, headers=headers)
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
    assert php == rust, (route.split("?")[0], php, rust)
    return rust[3]


def compare_states(paths, selectors):
    results = []
    for path in paths:
        with closing(sqlite3.connect(path)) as db:
            results.append([db.execute(sql).fetchall() for sql in selectors])
    assert results[0] == results[1], results
    return results[0]


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
                backend(variant, root, args, {**environment, "PXE_DB_PATH": str(db)})
            )
            config, port = write_nginx(root, variant, upstream, handler, routes=(ROUTE, BOOT, DISCOVERY))
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
        assert response(ports[1], DISCOVERY)[0] == 501  # Inventory still belongs to the PHP handler.

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
    print("Parity OK: 69 installation summaries, PXE source checks, GRUB selection and discovery phase events")


if __name__ == "__main__":
    main()
