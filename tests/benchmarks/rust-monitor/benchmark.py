#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Compare trois serveurs du même endpoint sur une base SQLite synthétique."""

import argparse
import concurrent.futures
import contextlib
import datetime
import http.client
import json
import math
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
ROUTE = "/api/monitoring/installs"
VARIANTS = ("php-dynamic-8", "php-ondemand-3", "rust-3")
IDLE_TIMEOUT = 3


def seed(root, environment, source):
    catalog_json = subprocess.check_output(
        ["php", str(HERE / "monitor.php"), "--catalog"], env=environment, text=True
    )
    catalog = json.loads(catalog_json)["install_only"]
    assert len(catalog) >= 3
    now = time.time()
    with contextlib.closing(sqlite3.connect(root / "fixture.sqlite")) as db, db:
        db.executescript((source / "app/db/schema.sqlite.sql").read_text())
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("INSERT INTO settings(key,value) VALUES ('pxe_subnet','192.0.2.0/24')")
        for host in range(1, 81):
            db.execute("INSERT INTO machines(id,mac,hostname) VALUES (?, ?, ?)", (
                host, f"02:00:00:00:01:{host:02x}", "" if host % 13 == 0 else f"poste-{host:02d}",
            ))
            action = host * 2
            status = ("running", "success", "failed")[host % 3]
            expired = host % 5 == 0
            start = timestamp(now, 180_000 if expired else 900)
            updated = timestamp(now, 179_900 if expired else 100)
            db.executemany("""INSERT INTO actions(id,machine_id,type,status,token,created_at,ended_at)
                              VALUES (?,?,'install_only',?,?,?,?)""", [
                (action - 1, host, "failed", f"fixture-{action - 1}",
                 timestamp(now, 190_000), timestamp(now, 189_000)),
                (action, host, status, f"fixture-{action}", start,
                 None if status == "running" else updated),
            ])
            for step in catalog[:1 + host % (len(catalog) - 1)]:
                db.executemany("""INSERT INTO machine_events(machine_id,action_id,checkpoint,created_at,message)
                                  VALUES (?,?,?,?,'fixture')""",
                               [(host, action, step["code"], updated)] * 2)


def timestamp(now, seconds):
    return datetime.datetime.fromtimestamp(now - seconds, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def nginx_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def process(command, root, name, env=None):
    log = root / f"{name}.log"
    with log.open("w+") as stream:
        child = subprocess.Popen(command, env=env, stdout=stream, stderr=stream)
        try:
            yield child
        except Exception:
            stream.seek(0)
            print(stream.read()[-2500:], file=sys.stderr)
            raise
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def fetch(connection):
    connection.request("GET", ROUTE)
    response = connection.getresponse()
    content = response.read()
    if response.status != 200 or response.getheader("Cache-Control") != "no-store":
        raise RuntimeError(f"HTTP {response.status}: {content[:160]!r}")
    return content


@contextlib.contextmanager
def connect(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        yield connection
    finally:
        connection.close()


def wait_ready(port, child):
    deadline = time.monotonic() + 8
    while child.poll() is None and time.monotonic() < deadline:
        try:
            with connect(port) as connection:
                return json.loads(fetch(connection))
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Le serveur ne répond pas.")


def tree_usage(parent):
    rows = [line.split() for line in subprocess.check_output(
        ["ps", "-x", "-o", "pid=,ppid=,rss=,time="], text=True
    ).splitlines()]
    pids = {parent}
    while True:
        children = {int(pid) for pid, ppid, _, _ in rows if int(ppid) in pids}
        if children <= pids:
            break
        pids |= children
    rss = 0
    linux = platform.system() == "Linux"
    pss = 0 if linux else None
    cpu = 0.0
    for pid, _, resident, cpu_time in rows:
        if int(pid) not in pids:
            continue
        rss += int(resident)
        if pss is not None:
            try:
                rollup = Path(f"/proc/{pid}/smaps_rollup").read_text()
                pss += int(next(line.split()[1] for line in rollup.splitlines()
                                if line.startswith("Pss:")))
            except (OSError, StopIteration):
                pss = None
        if linux:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                cpu += (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
                continue
            except (OSError, ValueError, IndexError):
                pass
        days, _, clock = cpu_time.rpartition("-")
        seconds = sum(float(v) * 60 ** i for i, v in enumerate(reversed(clock.split(":"))))
        cpu += seconds + (int(days) * 86400 if days else 0)
    return rss, cpu, pss, len(pids)


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(values) * fraction) - 1)]


def memory_pressure_total():
    # PSI covers the entire kernel, so use a dedicated VM when comparing runs.
    try:
        rows = Path("/proc/pressure/memory").read_text().splitlines()
    except OSError:
        return None
    return {row.split()[0]: int(row.rsplit("total=", 1)[1]) for row in rows}


def measure(port, root_pid, seconds, clients):
    idle_rss, _, idle_pss, idle_processes = tree_usage(root_pid)
    with connect(port) as connection:
        began = time.perf_counter()
        fetch(connection)
        first_ms = 1000 * (time.perf_counter() - began)
    samples = [tree_usage(root_pid)]
    stop = threading.Event()

    def sample():
        while not stop.wait(0.2):
            samples.append(tree_usage(root_pid))

    def load():
        latency = []
        with connect(port) as connection:
            while time.monotonic() < deadline:
                began = time.perf_counter()
                fetch(connection)
                latency.append(1000 * (time.perf_counter() - began))
        return latency

    sampler = threading.Thread(target=sample)
    sampler.start()
    psi_before = memory_pressure_total()
    began = time.monotonic()
    deadline = began + seconds
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
            latencies = [ms for batch in pool.map(lambda _: load(), range(clients)) for ms in batch]
    finally:
        elapsed = time.monotonic() - began
        psi_after = memory_pressure_total()
        stop.set()
        sampler.join()
    samples.append(tree_usage(root_pid))
    cpu_used = max(0, samples[-1][1] - samples[0][1])
    pss_samples = [pss for _, _, pss, _ in samples]
    peak_pss = max(pss_samples) if all(pss is not None for pss in pss_samples) else None
    return {
        "rss_repos_mio": round(idle_rss / 1024, 2),
        "rss_charge_max_mio": round(max(rss for rss, _, _, _ in samples) / 1024, 2),
        "pss_repos_mio": round(idle_pss / 1024, 2) if idle_pss is not None else None,
        "pss_charge_max_mio": round(peak_pss / 1024, 2) if peak_pss is not None else None,
        "pression_memoire_hote_usec": (
            {kind: total - psi_before[kind] for kind, total in psi_after.items()}
            if psi_before is not None and psi_after is not None else None
        ),
        "processus_repos": idle_processes,
        "premiere_requete_ms": round(first_ms, 3),
        "p50_ms": round(percentile(latencies, 0.5), 3),
        "p95_ms": round(percentile(latencies, 0.95), 3),
        "requetes": len(latencies),
        "requetes_par_seconde": round(len(latencies) / elapsed, 1),
        "cpu_serveur_ms_par_requete": round(1000 * cpu_used / len(latencies), 3),
    }


def write_nginx(root, name, upstream, backend, routes=(ROUTE,)):
    config = root / f"{name}.nginx"
    port = nginx_port()
    locations = "\n".join(f"location = {route} {{ {backend} }}" for route in routes)
    config.write_text(f"""
        daemon off;
        master_process off;
        pid "{root}/{name}.pid";
        error_log stderr warn;
        events {{ worker_connections 128; }}
        http {{
            access_log off;
            keepalive_requests 10000;
            client_max_body_size 5m;
            client_body_temp_path "{root}/client";
            proxy_temp_path "{root}/proxy";
            fastcgi_temp_path "{root}/fastcgi";
            uwsgi_temp_path "{root}/uwsgi";
            scgi_temp_path "{root}/scgi";
            {upstream}
            # Only this loopback fixture can select simulated addresses.
            map $http_x_fixture_peer $fixture_peer {{
                default $remote_addr;
                lan 192.0.2.24;
                outside 198.51.100.24;
                ipv6 ::1;
                alternate_loopback 127.1.2.3;
                other_lan 192.0.2.25;
            }}
            server {{
                listen 127.0.0.1:{port};
                {locations}
                location / {{ return 404; }}
            }}
        }}
    """)
    return config, port


@contextlib.contextmanager
def backend(variant, root, args, environment):
    if variant == "rust-3":
        sock = root / "rust.sock"
        with process([args.rust, str(root / "fixture.sqlite"), str(sock)], root, variant, environment) as child:
            deadline = time.monotonic() + 5
            while child.poll() is None and not sock.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not sock.exists():
                raise RuntimeError("Socket Rust absent.")
            upstream = f"upstream rust_backend {{ server unix:{sock}; keepalive 16; }}"
            yield child, upstream, """
                proxy_http_version 1.1;
                proxy_set_header Connection "";
                proxy_set_header X-Pxe-Client-Ip $fixture_peer;
                proxy_pass http://rust_backend;
            """
        sock.unlink(missing_ok=True)
    else:
        pool = ("pm = dynamic\npm.max_children = 8\npm.start_servers = 2\n"
                "pm.min_spare_servers = 1\npm.max_spare_servers = 3"
                if variant == "php-dynamic-8" else
                f"pm = ondemand\npm.max_children = 3\npm.process_idle_timeout = {IDLE_TIMEOUT}s")
        sock = root / "php.sock"
        conf = root / f"{variant}.fpm"
        conf.write_text(f"""[global]
daemonize = no
error_log = {root}/fpm-errors.log
[bench]
listen = {sock}
clear_env = no
{pool}
""")
        with process([args.fpm, "-y", str(conf), "-F"], root, variant, environment) as child:
            deadline = time.monotonic() + 5
            while child.poll() is None and not sock.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not sock.exists():
                raise RuntimeError(f"Socket PHP-FPM absent: {(root / 'fpm-errors.log').read_text()}")
            yield child, "", f"""
                fastcgi_pass unix:{sock};
                fastcgi_param SCRIPT_FILENAME "{HERE}/monitor.php";
                fastcgi_param REQUEST_METHOD $request_method;
                fastcgi_param REQUEST_URI $request_uri;
                fastcgi_param QUERY_STRING $query_string;
                fastcgi_param CONTENT_TYPE $content_type;
                fastcgi_param CONTENT_LENGTH $content_length;
                fastcgi_param REMOTE_ADDR $fixture_peer;
                fastcgi_param HTTP_AUTHORIZATION $http_authorization;
            """
        sock.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?", default=SOURCE, help="checkout de PXE Tools")
    parser.add_argument("--nginx", default=shutil.which("nginx") or "/opt/homebrew/opt/nginx/bin/nginx")
    parser.add_argument("--fpm", default=shutil.which("php-fpm") or "/usr/sbin/php-fpm8.4")
    parser.add_argument("--rust", default=str(SOURCE / "rust/target/release/pxe-tools-rust"))
    parser.add_argument("--seconds", type=float, default=4)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if os.geteuid() == 0 or os.path.lexists("/etc/pxe-tools/db.conf"):
        parser.error("Utiliser un compte sans privilèges sur un hôte de test sans db.conf PXE Tools.")
    if args.seconds < 1 or not 1 <= args.clients <= 16 or not 1 <= args.rounds <= 9:
        parser.error("Durée d’au moins 1 s, 1 à 16 clients et 1 à 9 passages.")
    source = args.source.resolve()
    if not (source / "app/src/Controllers/MonitoringController.php").is_file():
        parser.error("Checkout PXE Tools introuvable.")
    if subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"]).strip():
        parser.error("Utiliser un checkout PXE Tools propre pour rendre le résultat reproductible.")
    fixture_result = None
    results = []
    with tempfile.TemporaryDirectory(prefix="pxe-bench-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {**os.environ, "PXE_BENCH_APP": str(source / "app"),
                       "PXE_DB_DRIVER": "sqlite", "PXE_DB_PATH": str(root / "fixture.sqlite")}
        seed(root, environment, source)
        for round_no in range(args.rounds):
            order = VARIANTS[round_no % len(VARIANTS):] + VARIANTS[:round_no % len(VARIANTS)]
            for variant in order:
                with backend(variant, root, args, environment) as (child, upstream, route):
                    conf, port = write_nginx(root, variant, upstream, route)
                    with process([args.nginx, "-p", temporary, "-c", str(conf)], root, "nginx") as nginx:
                        current = wait_ready(port, nginx)["installs"]
                        if len(current) != 64:
                            raise RuntimeError(f"64 lignes de recette attendues, reçu {len(current)}.")
                        if fixture_result is None:
                            fixture_result = current
                        elif current != fixture_result:
                            raise RuntimeError(f"Réponse différente du contrôleur PHP: {variant}")
                        if variant == "php-ondemand-3":
                            idle_deadline = time.monotonic() + IDLE_TIMEOUT + 5
                            while tree_usage(child.pid)[3] != 1:
                                if time.monotonic() > idle_deadline:
                                    raise RuntimeError("Le pool PHP à la demande n’est pas revenu au repos.")
                                time.sleep(0.25)
                        else:
                            time.sleep(0.3)
                        metrics = measure(port, child.pid, args.seconds, args.clients)
                        results.append({"passage": round_no + 1, "variante": variant, **metrics})
    metadata = {
        "source": subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"],
                                          text=True).strip(),
        "hote": platform.platform(),
        "profil": "monitoring-install-only-unix-socket",
        "clients": args.clients, "duree_secondes": args.seconds,
        "reponses_identiques": len(fixture_result), "mesures": results,
    }
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
