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
                -u pxe-tools-worker.service -u pxe-tools-apt-update.service --no-pager -n 60 || true
        else
            docker logs --tail 40 "$container" || true
        fi
        docker rm -fv "$container" >/dev/null
    fi
    if [ "$variant" = docker ] && docker network inspect "$container" >/dev/null 2>&1; then
        docker network rm "$container" >/dev/null
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
        docker exec -i -e DEBIAN_FRONTEND=noninteractive "$container" bash -es -- "${PXE_TEST_APT_VERSION:-0.1.0~guided1}" <<'APT_GUEST'
            apt-get update -qq
            apt-get install -y --no-install-recommends /var/tmp/pxe-tools.deb
            test "$(dpkg-query -W -f='${Version}' pxe-tools)" = "$1"
            systemctl is-active --quiet pxe-tools-admin.target
            systemctl is-active --quiet pxe-tools-worker.service
            if systemctl is-active --quiet pxe-tools-dnsmasq.service; then exit 1; fi
APT_GUEST
        ;;
    docker)
        docker network create --internal "$container" >/dev/null
        docker run -d --name "$container" --network "$container" "${PXE_RUST_GUIDED_DOCKER_IMAGE:?}" >/dev/null
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
address=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")
test -n "$address"
docker exec "$container" curl -fsS --max-time 5 --cacert /run/pxe-tools-rust-guided/cert.pem \
    "https://$address/init/welcome" >/dev/null
docker exec "$container" bash -ec '
    variant="$1"
    address="$2"
    origin=https://127.0.0.1
    code=$(</run/pxe-tools-rust-guided/setup-code)
    [[ "$code" =~ ^[0-9a-f]{4}(-[0-9a-f]{4}){2}$ ]]
    page=$(curl -kfsS --max-time 5 "$origin/init/admin")
    [[ "$page" == *"/console-assets/style.css"* && "$page" == *"id=\"copy-setup-command\""* ]]
    test "$(grep -o "name=\"code\"" <<< "$page" | wc -l)" -eq 1
    css=$(curl -kfsS --max-time 5 "$origin/console-assets/style.css")
    [[ "$css" == *".setup-command-row"* ]]
    if [[ "$variant" == apt ]]; then
        test "$(dpkg-query -S /usr/bin/pxe-tools)" = "pxe-tools: /usr/bin/pxe-tools"
        [[ "$page" == *"value=\"sudo pxe-tools setup\" readonly"* ]]
        output=$(pxe-tools setup)
        [[ "$output" == *"https://$address/init/welcome"* && "$output" == *"$code"* ]]
        if runuser -u nobody -- pxe-tools setup; then exit 1; fi
    else
        [[ "$page" == *"value=\"cat /run/pxe-tools-rust-guided/setup-code\" readonly"* ]]
    fi
    request=(curl -ksS --max-time 5 -o /dev/null -w "%{http_code} %{redirect_url}" -H "Origin: $origin"
             --data-urlencode "username=setup-fixture" --data-urlencode "password=fixture-only-password"
             --data-urlencode "password_confirm=fixture-only-password")
    wrong_code="0${code:1}"
    [[ "$wrong_code" != "$code" ]] || wrong_code="1${code:1}"
    test "$("${request[@]}" "$origin/init/admin" --data-urlencode "code=$wrong_code")" = "403 "
    test ! -e /etc/pxe-tools/db.conf
    submitted="${code^^}"
    test "$("${request[@]}" "$origin/init/admin" --data-urlencode "code=${submitted//-/ }")" = "303 $origin/admin/devices"
    test "$("${request[@]}" "$origin/init/admin" --data-urlencode "code=$code")" = "409 "
    curl -kfsS --max-time 5 --user setup-fixture:fixture-only-password "$origin/admin/devices" >/dev/null
    if [[ "$variant" == apt ]]; then
        output=$(pxe-tools setup)
        [[ "$output" == *"https://$address/admin/"* && "$output" != *"$code"* ]]
    fi
' _ "$variant" "$address"
if [[ "$variant" == apt ]] && docker exec "$container" test -f /usr/lib/pxe-tools/native/apt-console-update.py; then
    docker exec -e DEBIAN_FRONTEND=noninteractive "$container" \
        apt-get install -y --no-install-recommends apt-utils gnupg
    docker cp tests/integration/test_apt_console_update.py "$container:/var/tmp/test_apt_console_update.py"
    docker exec "$container" python3 /var/tmp/test_apt_console_update.py "${PXE_TEST_APT_VERSION:-0.1.0~guided1}"
fi
printf 'Fresh Rust distribution ready for setup over HTTPS (%s)\n' "$variant"
