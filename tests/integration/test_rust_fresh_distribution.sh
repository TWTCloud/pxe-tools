#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Run on a disposable Linux runner with Docker and no host PXE network.
set -euo pipefail

variant="${1:?apt or docker}"
container="pxe-rust-fresh-$variant-$$"
cleanup() {
    if docker inspect "$container" >/dev/null 2>&1; then
        if [ "$variant" = apt ]; then
            docker exec "$container" journalctl -u pxe-tools-pxe-http.service \
                -u pxe-tools-worker.service --no-pager -n 30 || true
        else
            docker logs --tail 40 "$container" || true
        fi
        docker rm -fv "$container" >/dev/null
    fi
}
trap cleanup EXIT

case "$variant" in
    apt)
        docker run -d --name "$container" --privileged --cgroupns private \
            --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
            --mount "type=bind,src=${PXE_GUIDED_DEB:?},dst=/var/tmp/pxe-tools.deb,readonly" \
            "${PXE_FRESH_APT_IMAGE:?}" /lib/systemd/systemd --unit=basic.target >/dev/null
        for _ in {1..45}; do
            if docker exec "$container" systemctl list-units --no-legend >/dev/null 2>&1; then break; fi
            sleep 1
        done
        docker exec -i -e DEBIAN_FRONTEND=noninteractive "$container" bash -es <<'APT_GUEST'
            apt-get update -qq
            apt-get install -y --no-install-recommends /var/tmp/pxe-tools.deb
            test "$(dpkg-query -W -f='${Version}' pxe-tools)" = "0.1.0~guided1"
            systemctl is-active --quiet pxe-tools-admin.target
            systemctl is-active --quiet pxe-tools-worker.service
            if systemctl is-active --quiet pxe-tools-dnsmasq.service; then exit 1; fi
APT_GUEST
        ;;
    docker)
        docker run -d --name "$container" --network none "${PXE_RUST_GUIDED_DOCKER_IMAGE:?}" >/dev/null
        ;;
    *) exit 2 ;;
esac

for _ in {1..60}; do
    if docker exec "$container" curl -kfsS --max-time 2 https://127.0.0.1/healthz >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$container" bash -ec '
    test "$(curl -fsS --max-time 5 -o /dev/null -w "%{redirect_url}" http://127.0.0.1/)" = "https://127.0.0.1/admin/"
    test "$(curl -kfsS --max-time 5 -o /dev/null -w "%{redirect_url}" https://127.0.0.1/admin/)" = "https://127.0.0.1/init/welcome"
    curl -kfsS --max-time 5 https://127.0.0.1/init/welcome >/dev/null
    test -s /run/pxe-tools-rust-guided/setup-code
    for executable in php php-fpm8.4 nginx ansible; do
        if command -v "$executable"; then exit 1; fi
    done
    test -z "$(ss -Hlun "( sport = :67 or sport = :4011 )")"
'
printf 'Fresh Rust distribution ready for setup over HTTPS (%s)\n' "$variant"
