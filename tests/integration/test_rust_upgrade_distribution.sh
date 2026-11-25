#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Exercise the published beta 12 in a disposable Docker namespace.
set -euo pipefail

variant="${1:?apt or docker}"
registry=ghcr.io/williamboglietti/pxe-tools-appliance
release=https://github.com/williamboglietti/pxe-tools/releases/download/v0.1.0-beta12
name="pxe-rust-upgrade-$variant-$$"
work=$(mktemp -d)
volumes=()
cleanup() {
    if docker inspect "$name" >/dev/null 2>&1; then
        if [ "$variant" = apt ]; then
            docker exec "$name" journalctl -u pxe-tools-init.service -u pxe-tools-pxe-http.service \
                -u pxe-tools-worker.service -n 45 --no-pager || true
        else
            docker logs --tail 45 "$name" || true
        fi
        docker rm -fv "$name" >/dev/null
    fi
    if [ "${#volumes[@]}" -gt 0 ]; then docker volume rm "${volumes[@]}" >/dev/null; fi
    rm -rf -- "$work"
}
trap cleanup EXIT

wait_https() {
    local port=$1
    for _ in {1..60}; do
        if docker exec "$name" curl -kfsS --max-time 2 "https://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

download() {
    curl -fsSL --retry 3 --max-time 90 "$release/$1" -o "$work/$1"
    printf '%s  %s\n' "$2" "$work/$1" | sha256sum --check
}

case "$variant" in
    apt)
        arch=$(dpkg-deb -f "${PXE_GUIDED_DEB:?}" Architecture)
        case "$arch" in
            amd64) digest=36189e6b327ae47451e7e4d63376e3f090e0b6e534d4cdfed4fdc7bd01c0174c ;;
            arm64) digest=30b0fe7dd4cd789be83f38bb15f67818e249e62d4c6d88119504402da07ef992 ;;
            *) exit 2 ;;
        esac
        download "pxe-tools_0.1.0-beta12_$arch.deb" "$digest"
        download pxe-tools-ansible_0.1.0-beta12_all.deb d1bfb0f7eb8d46e15977f7e892321054e6eb66bc9c34dfe7e433729beb388576
        cp -- "$PXE_GUIDED_DEB" "$work/rust.deb"
        cp -- "${PXE_GUIDED_ANSIBLE_DEB:?}" "$work/rust-ansible.deb"
        chmod 0755 "$work"
        docker run -d --name "$name" --privileged --cgroupns private \
            --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
            --mount "type=bind,src=$work,dst=/mnt/pxe-fixture,readonly" \
            "${PXE_FRESH_APT_IMAGE:?}" /lib/systemd/systemd --unit=basic.target >/dev/null
        for _ in {1..45}; do
            if docker exec "$name" systemctl list-units --no-legend >/dev/null 2>&1; then break; fi
            sleep 1
        done
        docker exec -i -e DEBIAN_FRONTEND=noninteractive "$name" bash -es -- "$arch" <<'APT_LEGACY'
            apt-get update -qq
            apt-get install -y --no-install-recommends "/mnt/pxe-fixture/pxe-tools_0.1.0-beta12_$1.deb" \
                /mnt/pxe-fixture/pxe-tools-ansible_0.1.0-beta12_all.deb
            test "$(dpkg-query -W -f='${Version}' pxe-tools)" = '0.1.0~beta12'
            systemctl stop pxe-tools-worker.service
APT_LEGACY
        schema=/usr/lib/pxe-tools/app/db/schema.sqlite.sql
        cert=/var/lib/pxe-tools-native/tls/cert.pem
        ;;
    docker)
        prior="$registry:v0.1.0-beta12"
        docker pull "$prior"
        test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$prior")" = 1e425e788ca9a3a6db2ab9143b6617172a099177
        mounts=()
        for location in /var/lib/pxe-tools /etc/pxe-tools /srv/http /srv/tftp; do
            volume="$name-${#volumes[@]}"
            docker volume create "$volume" >/dev/null
            volumes+=("$volume")
            mounts+=(--mount "type=volume,src=$volume,dst=$location")
        done
        docker run -d --name "$name" --network none "${mounts[@]}" "$prior" >/dev/null
        for _ in {1..60}; do
            if docker exec "$name" curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
            sleep 1
        done
        docker exec "$name" curl -fsS --max-time 5 http://127.0.0.1:8080/healthz >/dev/null
        schema=/app/db/schema.sqlite.sql
        cert=/var/lib/pxe-tools/tls/cert.pem
        ;;
    *) exit 2 ;;
esac

# A known local account and a console-only SQLite instance are enough to
# detect lost configuration without enabling DHCP in the fixture.
docker exec -i "$name" bash -es -- "$schema" <<'PREVIOUS_INSTANCE'
    db=/var/lib/pxe-tools/pxe-tools.sqlite
    if [ ! -f "$db" ]; then
        umask 077
        runuser -u www-data -- sqlite3 "$db" < "$1"
    fi
    if [ ! -f /etc/pxe-tools/db.conf ]; then
        printf '{"driver":"sqlite","path":"%s"}\n' "$db" > /etc/pxe-tools/db.conf
        chown root:www-data /etc/pxe-tools/db.conf
        chmod 0640 /etc/pxe-tools/db.conf
    fi
    runuser -u www-data -- sqlite3 "$db" <<'SQL'
BEGIN;
INSERT OR REPLACE INTO settings(key,value) VALUES
('db_init_done','1'),('admin_created','1'),('wizard_completed','1'),
('pxe_enabled','off'),('dhcp_proxy_enabled','off'),('ui_device_term','ordinateur');
INSERT INTO users(username,password_hash)
VALUES('fixture-admin','$2y$12$zGZhsSwt3AHDHVbliUPl5eMV46SsqfpLUsIOAcZiq1frkQPqxaEcK');
COMMIT;
SQL
PREVIOUS_INSTANCE
key=$(docker exec "$name" sha256sum /etc/pxe-tools/master.key | cut -d ' ' -f 1)
fingerprint=$(docker exec "$name" openssl x509 -in "$cert" -noout -fingerprint -sha256)

if [ "$variant" = apt ]; then
    docker exec -i -e DEBIAN_FRONTEND=noninteractive "$name" bash -es -- "${PXE_TEST_APT_VERSION:?}" <<'APT_UPGRADE'
        apt-get install -y --no-install-recommends /mnt/pxe-fixture/rust.deb /mnt/pxe-fixture/rust-ansible.deb
        for package in pxe-tools pxe-tools-ansible; do
            test "$(dpkg-query -W -f='${Version}' "$package")" = "$1"
        done
        systemctl start pxe-tools-admin.target
        systemctl is-active --quiet pxe-tools-worker.service
        for unit in pxe-tools-php.service pxe-tools-nginx.service pxe-tools-dnsmasq.service; do
            if systemctl is-active --quiet "$unit"; then exit 1; fi
        done
        ansible --version
APT_UPGRADE
else
    docker rm -fv "$name" >/dev/null
    docker run -d --name "$name" --network none "${mounts[@]}" "${PXE_RUST_GUIDED_DOCKER_IMAGE:?}" >/dev/null
fi

wait_https 443
docker exec "$name" curl -kfsS -u fixture-admin:fixture-login-password https://127.0.0.1/admin/devices > "$work/admin.html"
rg -q '<h1>Ordinateurs</h1>' "$work/admin.html"
test "$(docker exec "$name" sha256sum /etc/pxe-tools/master.key | cut -d ' ' -f 1)" = "$key"
served=$(docker exec "$name" bash -o pipefail -c 'openssl s_client -connect 127.0.0.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256')
test "$served" = "$fingerprint"
test -z "$(docker exec "$name" ss -Hlun '( sport = :67 or sport = :4011 )')"
printf 'Rust %s upgrade from beta 12 preserved SQLite, the account, the master key and TLS.\n' "$variant"
