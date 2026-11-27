#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Exercise the previous approved release in a disposable Docker namespace.
set -euo pipefail

variant="${1:?apt or docker}"
manifest=packaging/ci/release-manifest.json
tag=$(jq -er .release_tag "$manifest")
previous=$(jq -er .version "$manifest")
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta[0-9]+$ ]]
[[ "$tag" == "v${previous//\~/-}" ]]
release="https://github.com/TWTCloud/pxe-tools/releases/download/$tag"
name="pxe-rust-upgrade-$variant-$$"
server_name=pxe-upgrade-fixture
search_domain=lan.example.test
hostname_args=(--hostname "$server_name" --dns-search "$search_domain")
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
    if [ "$variant" = docker ] && docker network inspect "$name" >/dev/null 2>&1; then
        docker network rm "$name" >/dev/null
    fi
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
    [[ "$1" =~ ^pxe-tools(-ansible)?_[A-Za-z0-9._-]+_(amd64|arm64|all)\.deb$ && "$2" =~ ^[0-9a-f]{64}$ ]]
    curl -fsSL --retry 3 --max-time 90 "$release/$1" -o "$work/$1"
    printf '%s  %s\n' "$2" "$work/$1" | sha256sum --check
}

case "$variant" in
    apt)
        arch=$(dpkg-deb -f "${PXE_GUIDED_DEB:?}" Architecture)
        case "$arch" in
            amd64) prefix=package ;;
            arm64) prefix=arm64_package ;;
            *) exit 2 ;;
        esac
        old_core=$(jq -er ".${prefix}_asset" "$manifest")
        old_module=$(jq -er .ansible_package_asset "$manifest")
        download "$old_core" "$(jq -er ".${prefix}_sha256" "$manifest")"
        download "$old_module" "$(jq -er .ansible_package_sha256 "$manifest")"
        cp -- "$PXE_GUIDED_DEB" "$work/rust.deb"
        cp -- "${PXE_GUIDED_ANSIBLE_DEB:?}" "$work/rust-ansible.deb"
        chmod 0755 "$work"
        docker run -d --name "$name" --privileged --cgroupns private "${hostname_args[@]}" \
            --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
            --mount "type=bind,src=$work,dst=/mnt/pxe-fixture,readonly" \
            "${PXE_FRESH_APT_IMAGE:?}" /lib/systemd/systemd --unit=basic.target >/dev/null
        for _ in {1..45}; do
            if docker exec "$name" systemctl list-units --no-legend >/dev/null 2>&1; then break; fi
            sleep 1
        done
        docker exec -i -e DEBIAN_FRONTEND=noninteractive "$name" bash -es -- "$old_core" "$old_module" "$previous" <<'APT_LEGACY'
            apt-get update -qq
            apt-get install -y --no-install-recommends "/mnt/pxe-fixture/$1" "/mnt/pxe-fixture/$2"
            test "$(dpkg-query -W -f='${Version}' pxe-tools)" = "$3"
            systemctl stop pxe-tools-worker.service
APT_LEGACY
        schema=/usr/lib/pxe-tools/app/db/schema.sqlite.sql
        cert=/var/lib/pxe-tools-native/tls/cert.pem
        ;;
    docker)
        docker_baseline=packaging/ci/docker-upgrade-from.json
        prior=$(jq -er .image "$docker_baseline")
        previous=$(jq -er .version "$docker_baseline")
        [[ "$prior" =~ ^ghcr[.]io/[a-z0-9-]+/[a-z0-9-]+@sha256:[0-9a-f]{64}$ ]]
        docker pull "$prior"
        test "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$prior")" = "$(jq -er .source_commit "$docker_baseline")"
        mounts=()
        for location in /var/lib/pxe-tools /etc/pxe-tools /srv/http /srv/tftp /var/lib/pxe-tools-tls; do
            volume="$name-${#volumes[@]}"
            docker volume create "$volume" >/dev/null
            volumes+=("$volume")
            mounts+=(--mount "type=volume,src=$volume,dst=$location")
        done
        docker network create --internal "$name" >/dev/null
        docker run -d --name "$name" --network "$name" "${hostname_args[@]}" "${mounts[@]}" "$prior" >/dev/null
        if [ "$(docker image inspect --format '{{json .Config.Env}}' "$prior" | jq -r 'index("PXE_RUST_DIRECT_HTTP=1") != null')" = true ]; then
            wait_https 443
        else
            for _ in {1..60}; do
                if docker exec "$name" curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
                sleep 1
            done
            docker exec "$name" curl -fsS --max-time 5 http://127.0.0.1:8080/healthz >/dev/null
        fi
        schema=/app/db/schema.sqlite.sql
        cert="$(docker exec "$name" printenv TLS_DIR)/cert.pem"
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
    admin_column=$(runuser -u www-data -- sqlite3 "$db" "SELECT name FROM pragma_table_info('users') WHERE name='is_admin'")
    if [ "$admin_column" = is_admin ]; then
        runuser -u www-data -- sqlite3 "$db" "UPDATE users SET is_admin=1 WHERE username='fixture-admin'"
    fi
PREVIOUS_INSTANCE
key=$(docker exec "$name" sha256sum /etc/pxe-tools/master.key | cut -d ' ' -f 1)
fingerprint=$(docker exec "$name" openssl x509 -in "$cert" -noout -fingerprint -sha256)

if [ "$variant" = apt ]; then
    docker exec -i -e DEBIAN_FRONTEND=noninteractive "$name" bash -es -- "${PXE_TEST_APT_VERSION:?}" <<'APT_UPGRADE'
        set -o pipefail
        # Pull requests can build the same version string as the released package.
        # Reinstall so this fixture always runs the candidate binary.
        apt-get install -y --reinstall --no-install-recommends /mnt/pxe-fixture/rust.deb /mnt/pxe-fixture/rust-ansible.deb
        for package in pxe-tools pxe-tools-ansible; do
            test "$(dpkg-query -W -f='${Version}' "$package")" = "$1"
        done
        candidate_sha=$(dpkg-deb --fsys-tarfile /mnt/pxe-fixture/rust.deb \
            | tar -xOf - ./usr/lib/pxe-tools/pxe-tools-rust | sha256sum)
        installed_sha=$(sha256sum /usr/lib/pxe-tools/pxe-tools-rust)
        test "${candidate_sha%% *}" = "${installed_sha%% *}"
        systemctl start pxe-tools-admin.target
        systemctl is-active --quiet pxe-tools-worker.service
        for unit in pxe-tools-php.service pxe-tools-nginx.service pxe-tools-dnsmasq.service; do
            if systemctl is-active --quiet "$unit"; then exit 1; fi
        done
        ansible --version
APT_UPGRADE
else
    docker rm -fv "$name" >/dev/null
    docker run -d --name "$name" --network "$name" "${hostname_args[@]}" \
        "${mounts[@]}" "${PXE_RUST_GUIDED_DOCKER_IMAGE:?}" >/dev/null
fi

wait_https 443
address=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
test -n "$address"
docker exec "$name" curl -kfsS -u fixture-admin:fixture-login-password "https://$address/admin/inventaire" > "$work/admin.html"
grep -Fq '<h1>Inventaire</h1>' "$work/admin.html"
test "$(docker exec "$name" sha256sum /etc/pxe-tools/master.key | cut -d ' ' -f 1)" = "$key"
served=$(docker exec "$name" bash -o pipefail -c 'openssl s_client -connect 127.0.0.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256')
test "$served" = "$fingerprint"
dns_name="$server_name.$search_domain"
test "$(docker exec "$name" curl -ksS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' \
    --resolve "$dns_name:443:$address" -H "Origin: https://$dns_name" \
    --data 'username=fixture-admin&password=fixture-login-password' "https://$dns_name/login")" = 303
test -z "$(docker exec "$name" ss -Hlun '( sport = :67 or sport = :4011 )')"
printf 'Rust %s upgrade from %s preserved SQLite, the account, the master key and TLS. DNS login works.\n' "$variant" "$previous"

if [[ "$variant" == apt ]]; then
    # Use the candidate public script against the upgraded official APT instance.
    docker cp packaging/native/uninstall-apt.py "$name:/var/tmp/pxe-uninstall-test.py"
    docker exec -i "$name" bash -es <<'APT_PURGE'
        set -euo pipefail
        cd /var/tmp
        # The guest was started in basic.target. The native freeze command
        # needs the system D-Bus socket that a normal Debian boot provides.
        systemctl start dbus.socket
        systemctl is-active --quiet dbus.socket
        printf 'keep outside the PXE instance\n' > /var/tmp/unrelated-data
        args=(--allow-legacy --purge-residuals)
        python3 ./pxe-uninstall-test.py --dry-run "${args[@]}" > pxe-removal-plan
        residual=$(awk '/^Residual plan SHA256: / { print $4 }' pxe-removal-plan)
        legacy=$(awk '/^Legacy plan SHA256: / { print $4 }' pxe-removal-plan)
        [[ "$residual" =~ ^[a-f0-9]{64}$ ]]
        args+=(--yes --residual-plan-sha256 "$residual")
        if [[ -n "$legacy" ]]; then args+=(--legacy-plan-sha256 "$legacy"); fi

        dropin=/etc/systemd/system/pxe-tools.target.d
        mkdir "$dropin"
        printf '[Unit]\nDescription=local PXE setting\n' > "$dropin/90-local.conf"
        if python3 ./pxe-uninstall-test.py "${args[@]}" > pxe-guard.log 2>&1; then
            exit 1
        fi
        cat pxe-guard.log
        grep -Fq 'local unit drop-in; preserved: pxe-tools.target' pxe-guard.log
        systemctl is-active --quiet pxe-tools-worker.service
        test -s /var/lib/pxe-tools/pxe-tools.sqlite
        rm "$dropin/90-local.conf"
        rmdir "$dropin"

        # Upgrade starts bootstrap jobs. Exercise a normal purge once the worker
        # has finished them and the guard can identify just its main process.
        worker=pxe-tools-worker.service
        ready=false
        for _ in {1..90}; do
            pid=$(systemctl show --property=MainPID --value "$worker")
            group=$(systemctl show --property=ControlGroup --value "$worker")
            busy=$(sqlite3 -readonly /var/lib/pxe-tools/pxe-tools.sqlite \
                "SELECT EXISTS (SELECT 1 FROM init_jobs WHERE status IN ('pending','running'));")
            if [[ "$pid" =~ ^[1-9][0-9]*$ && "$group" == /* && "$busy" == 0 ]] &&
                [[ "$(cat "/sys/fs/cgroup$group/cgroup.procs" 2>/dev/null)" == "$pid" ]]; then
                ready=true
                break
            fi
            sleep 1
        done
        test "$ready" = true
        # In CI, retain the exception chain behind the public CLI's concise error.
        python3 -c 'import runpy, sys; sys.exit(runpy.run_path(sys.argv[1])["main"](sys.argv[2:]))' \
            ./pxe-uninstall-test.py "${args[@]}"
        for package in pxe-tools pxe-tools-ansible; do
            if dpkg-query -W "$package" >/dev/null 2>&1; then exit 1; fi
        done
        for path in /etc/pxe-tools /var/lib/pxe-tools /var/lib/pxe-tools-native /opt/pxe-tools; do
            test ! -e "$path"
        done
        test ! -L /etc/systemd/system/pxe-tools-apt-update.service
        test "$(cat /var/tmp/unrelated-data)" = 'keep outside the PXE instance'
APT_PURGE
    printf 'Rust APT uninstall completed with real systemd and dpkg.\n'
fi
