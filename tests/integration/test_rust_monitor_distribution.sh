#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Run on a disposable native Linux Docker host. No ports are published.
set -euo pipefail

architecture="${1:?amd64 or arm64}"
case "$architecture" in
    amd64) test "$(uname -m)" = x86_64 ;;
    arm64) test "$(uname -m)" = aarch64 ;;
    *) exit 2 ;;
esac

name="pxe-tools-rust-monitor-$$"
work=$(mktemp -d)
cleanup() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        docker logs --tail 50 "$name-apt" 2>/dev/null || true
        docker exec "$name-apt" journalctl --no-pager -n 45 \
            -u pxe-tools-pxe-http -u pxe-tools-init -u pxe-tools-rust-monitor || true
        docker logs --tail 60 "$name-docker" || true
    fi
    docker rm -f "$name-apt" "$name-docker" "$name-binary" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    docker volume rm "$name-docker-data" "$name-docker-conf" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT
chmod 0755 "$work"

build=(docker build --platform "linux/$architecture" -f docker/pxe-tools/Dockerfile)
"${build[@]}" --target rust-experimental -t "$name-experimental" .
"${build[@]}" -t "$name-standard" .
docker create --name "$name-binary" "$name-experimental" >/dev/null
docker cp "$name-binary:/usr/lib/pxe-tools/pxe-tools-rust" "$work/pxe-tools-rust"
docker rm "$name-binary" >/dev/null
docker image inspect -f 'Docker {{.Os}}/{{.Architecture}} {{.Size}} bytes {{index .RepoTags 0}}' \
    "$name-standard" "$name-experimental"
docker run --rm --network none --entrypoint /bin/sh "$name-standard" -ec \
    'test ! -e /usr/lib/pxe-tools/pxe-tools-rust'

python3 packaging/native/build-local-package.py "$work/standard.deb" --architecture "$architecture" --version '0.1.0~rust1'
python3 packaging/native/build-local-package.py "$work/experimental.deb" --architecture "$architecture" \
    --version '0.1.0~rust2' --rust-binary "$work/pxe-tools-rust"
test "$(dpkg-deb -f "$work/experimental.deb" Architecture)" = "$architecture"
test "$(stat -c %s "$work/experimental.deb")" -le 26214400
stat -c 'Debian package: %s bytes %n' "$work/standard.deb" "$work/experimental.deb"

docker network create --internal --subnet 192.0.2.0/24 "$name" >/dev/null
docker build -t "$name-systemd" - <<'DOCKERFILE'
FROM debian:13-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates systemd systemd-sysv && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker run -d --name "$name-apt" --privileged --cgroupns private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    --mount "type=bind,src=$work,dst=/fixture,readonly" \
    "$name-systemd" /lib/systemd/systemd --unit=basic.target >/dev/null
for attempt in {1..60}; do
    if docker exec "$name-apt" systemctl list-units --no-legend >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$name-apt" bash -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends /fixture/standard.deb
    systemctl is-active --quiet pxe-tools-admin.target
'

seed() {
    docker exec -i "$1" bash -eus -- "$2" <<'SEED'
app="$1"
db=/var/lib/pxe-tools/orchestrator.sqlite
config=/etc/pxe-tools/db.conf
test -s /etc/pxe-tools/master.key
test ! -e "$config"
sqlite3 -bail "$db" < "$app/db/schema.sqlite.sql"
secret=$(php -r 'require $argv[1] . "/src/Util/Crypto.php"; echo Admin\Util\Crypto::encrypt("fixture-secret");' "$app")
sqlite3 -bail "$db" <<SQL
PRAGMA journal_mode=WAL;
INSERT INTO settings(key,value) VALUES
    ('pxe_enabled','on'),('pxe_ip','192.0.2.10'),('pxe_subnet','192.0.2.0/25'),('pxe_interface','eth0'),
    ('https_enabled','off'),('catalog_auto_refresh_enabled','off'),('ansible_enabled','off'),
    ('fixture_encrypted','$secret');
INSERT INTO machines(id,mac,hostname) VALUES(1,'02:00:00:00:00:01','fixture-legacy');
INSERT INTO actions(id,machine_id,type,status,token,ended_at)
    VALUES(2,1,'install_only','success','fixture-token',datetime('now'));
SQL
chown www-data:www-data "$db"
sha256sum /etc/pxe-tools/master.key | cut -d' ' -f1 > /var/lib/pxe-tools/.fixture-key
SEED
}

check_key() {
    docker exec -i "$1" bash -eus -- "$2" <<'CHECK_KEY'
test "$(sha256sum /etc/pxe-tools/master.key | cut -d' ' -f1)" = "$(cat /var/lib/pxe-tools/.fixture-key)"
php -r '
    require $argv[1] . "/src/Db.php";
    require $argv[1] . "/src/Util/Crypto.php";
    $db = Admin\Db::get(false);
    $ciphertext = $db->query("SELECT value FROM settings WHERE key = '\''fixture_encrypted'\''")->fetchColumn();
    if (Admin\Db::sqliteRuntimePath() !== "/var/lib/pxe-tools/orchestrator.sqlite"
        || Admin\Util\Crypto::decrypt($ciphertext) !== "fixture-secret") exit(1);
' "$1"
CHECK_KEY
}

check_monitor() {
    local container="$1" backend="$2" socket='/run/pxe-tools-rust-monitor/http.sock'
    docker exec -i "$container" python3 - "$backend" <<'CHECK_MONITOR'
import http.client
import json
import sys
import time

expected = sys.argv[1] == "rust"
for attempt in range(45):
    conn = http.client.HTTPConnection("127.0.0.1", timeout=2)
    try:
        conn.request("GET", "/api/monitoring/installs?fixture=1")
        response = conn.getresponse()
        body = response.read()
        if response.status == 200 and (response.getheader("X-PXE-Monitor-Backend") == "rust") == expected:
            assert response.getheader("Cache-Control") == "no-store"
            payload = json.loads(body)
            assert isinstance(payload.pop("generated_at"), int)
            assert [(item["label"], item["status"]) for item in payload["installs"]] == [("fixture-legacy", "success")]
            print(json.dumps(payload, sort_keys=True))
            break
    except OSError:
        pass
    finally:
        conn.close()
    time.sleep(1)
else:
    raise RuntimeError(f"{sys.argv[1]} monitor did not serve the fixture")
CHECK_MONITOR
    if [ "$backend" = rust ]; then
        docker exec "$container" bash -ec '
            test "$(stat -c %a "$1")" = 600
            test "$(stat -c %a "${1%/*}")" = 700
            test "$(curl -sS -o /dev/null -w "%{http_code}" --unix-socket "$1" \
                -X POST http://localhost/api/install-start)" = 404
        ' bash "$socket"
        # The peer is outside the configured /25, even with a forged loopback header.
        docker run --rm --network "$name" --ip 192.0.2.200 --entrypoint curl "$name-standard" \
            --silent --show-error --max-time 5 --dump-header - --header 'X-Pxe-Client-Ip: 127.0.0.1' \
            'http://192.0.2.10/api/monitoring/installs' > "$work/denied"
        grep -Eq '^HTTP/[0-9.]+ 403 ' "$work/denied"
        grep -Eiq '^X-PXE-Monitor-Backend: rust' "$work/denied"
        grep -Fq '{"error":"forbidden"}' "$work/denied"
    fi
}

seed "$name-apt" /usr/lib/pxe-tools/app
docker exec "$name-apt" systemctl restart pxe-tools-init.service
check_key "$name-apt" /usr/lib/pxe-tools/app
# The Docker fixture cannot freeze systemd service cgroups. Exercise a
# quiescent upgrade through the same maintainer scripts.
docker exec "$name-apt" systemctl stop pxe-tools-worker.service
docker exec "$name-apt" bash -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq --no-install-recommends /fixture/experimental.deb
'
docker network disconnect bridge "$name-apt"
docker network connect --ip 192.0.2.10 "$name" "$name-apt"
docker exec "$name-apt" systemctl start pxe-tools-pxe-http.service
check_key "$name-apt" /usr/lib/pxe-tools/app
check_monitor "$name-apt" rust > "$work/apt-rust.json"
docker exec "$name-apt" systemctl stop pxe-tools-rust-monitor.service
check_monitor "$name-apt" php > "$work/apt-php.json"
diff -u "$work/apt-php.json" "$work/apt-rust.json"
docker rm -f "$name-apt" >/dev/null
echo "APT $architecture: preserved PHP SQLite and master key, Rust monitoring, deny and fallback passed"

docker_app=(docker run -d --name "$name-docker" --network "$name" --ip 192.0.2.10
    --volume "$name-docker-data:/var/lib/pxe-tools" --volume "$name-docker-conf:/etc/pxe-tools")
"${docker_app[@]}" "$name-standard" >/dev/null
for attempt in {1..60}; do
    if docker exec "$name-docker" curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
    sleep 1
done
seed "$name-docker" /app
docker rm -f "$name-docker" >/dev/null
"${docker_app[@]}" "$name-experimental" >/dev/null
check_monitor "$name-docker" rust > "$work/docker-rust.json"
check_key "$name-docker" /app
docker exec "$name-docker" /command/s6-svc -d /run/service/rust-monitor
check_monitor "$name-docker" php > "$work/docker-php.json"
diff -u "$work/docker-php.json" "$work/docker-rust.json"
echo "Docker $architecture: preserved PHP SQLite and master key, Rust monitoring, deny and fallback passed"
