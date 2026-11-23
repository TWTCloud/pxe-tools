#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Run on a disposable native Linux Docker host with outbound HTTPS to Debian.
set -euo pipefail

mode="${1:?apt or docker}"
architecture="${2:?amd64 or arm64}"
case "$mode" in apt|docker) ;; *) exit 2 ;; esac
case "$architecture" in
    amd64) test "$(uname -m)" = x86_64 ;;
    arm64) test "$(uname -m)" = aarch64 ;;
    *) exit 2 ;;
esac

name="pxe-architecture-$mode-$$"
work=$(mktemp -d)
cleanup() {
    if docker inspect "$name" >/dev/null 2>&1; then
        docker logs --tail 80 "$name" || true
        if [ "$mode" = apt ]; then
            docker exec "$name" journalctl -u pxe-tools-init.service -u pxe-tools-nginx.service \
                -u pxe-tools-php.service --no-pager -n 50 || true
        fi
        docker rm -f "$name" >/dev/null
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
chmod 0755 "$work"

if [ "$mode" = apt ]; then
    version="${PXE_TEST_APT_VERSION:-0.1.0~lab1}"
    for arch in amd64 arm64; do
        python3 packaging/native/build-apt-package-candidate.py "$work/candidate-$arch.deb" \
            --architecture "$arch" --version "$version" --maintainer 'Fixture <fixture@example.invalid>'
        test "$(dpkg-deb -f "$work/candidate-$arch.deb" Architecture)" = "$arch"
        test "$(stat -c %s "$work/candidate-$arch.deb")" -le 26214400
        stat -c '%s %n' "$work/candidate-$arch.deb"
    done
    python3 packaging/native/build-local-ansible-package.py "$work/ansible.deb" --release --version "$version"
    install -d -m 0700 "$work/gnupg"
    gpg --homedir "$work/gnupg" --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key 'PXE fixture <fixture@example.invalid>' rsa2048 sign 1d
    fingerprint=$(gpg --homedir "$work/gnupg" --batch --with-colons --list-keys | awk -F: '$1=="fpr" {print $10}')
    gpg --homedir "$work/gnupg" --batch --export > "$work/keyring.gpg"
    python3 packaging/native/build-apt-release-candidate.py "$work/candidate-amd64.deb" "$work/apt" \
        --gnupg-home "$work/gnupg" --fingerprint "$fingerprint" \
        --source-commit "$(git rev-parse HEAD)" --build-run-id "${GITHUB_RUN_ID:-1}" \
        --approved-package-sha256 "$(sha256sum "$work/candidate-amd64.deb" | cut -d' ' -f1)" \
        --arm64-package "$work/candidate-arm64.deb" \
        --approved-arm64-sha256 "$(sha256sum "$work/candidate-arm64.deb" | cut -d' ' -f1)" \
        --ansible-package "$work/ansible.deb" \
        --approved-ansible-sha256 "$(sha256sum "$work/ansible.deb" | cut -d' ' -f1)"
    python3 packaging/native/prepare-static-apt.py "$work/apt" "$work/assets" \
        --keyring "$work/keyring.gpg" --primary-fingerprint "$fingerprint" --signing-fingerprint "$fingerprint"
    for arch in amd64 arm64; do
        diff -u <(printf 'all\n%s\n' "$arch" | sort) \
            <(sed -n 's/^Architecture: //p' "$work/apt/dists/stable/main/binary-$arch/Packages" | sort)
    done

    # No published ports or host networking. Run systemd so APT exercises postinst.
    docker build --platform "linux/$architecture" -t "$name" - <<'DOCKERFILE'
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates systemd systemd-sysv && rm -rf /var/lib/apt/lists/*
DOCKERFILE
    docker run -d --name "$name" --privileged --cgroupns private \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        --mount "type=bind,src=$work/assets/apt,dst=/mnt/pxe-apt,readonly" \
        --mount "type=bind,src=$work/keyring.gpg,dst=/usr/share/keyrings/pxe-lab.gpg,readonly" \
        "$name" /lib/systemd/systemd --unit=basic.target >/dev/null
    for attempt in {1..60}; do
        if docker exec "$name" systemctl list-units --no-legend >/dev/null 2>&1; then break; fi
        sleep 1
    done
    docker exec -i "$name" bash -eus -- "$architecture" "$version" <<'APT_GUEST'
export DEBIAN_FRONTEND=noninteractive
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/pxe-lab.gpg] file:/mnt/pxe-apt stable main' \
    > /etc/apt/sources.list.d/pxe-lab.list
apt-get update
apt-get install -y --no-install-recommends pxe-tools
test "$(dpkg-query -W -f='${Architecture}' pxe-tools)" = "$1"
test "$(dpkg-query -W -f='${Version}' pxe-tools)" = "$2"
test -z "$(dpkg --print-foreign-architectures)"
systemctl is-active --quiet pxe-tools-admin.target
systemctl is-active --quiet pxe-tools-worker.service
if systemctl is-active --quiet pxe-tools-dnsmasq.service || command -v ansible; then
    echo 'The fresh core started DHCP or included Ansible.' >&2
    exit 1
fi
APT_GUEST
else
    image="${PXE_DOCKER_TEST_IMAGE:-$name}"
    labels=(--label "org.opencontainers.image.revision=$(git rev-parse HEAD)"
            --label 'org.opencontainers.image.source=https://github.com/williamboglietti/pxe-tools')
    if [ -n "${PXE_DOCKER_DOCUMENTATION:-}" ]; then
        labels+=(--label "org.opencontainers.image.documentation=$PXE_DOCKER_DOCUMENTATION")
    fi
    docker build --platform "linux/$architecture" --build-arg "APP_VERSION=${PXE_TEST_APT_VERSION:-0.1.0~lab1}" \
        "${labels[@]}" -f docker/pxe-tools/Dockerfile -t "$image" .
    docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Size}} bytes {{.Id}}' "$image"
    docker run -d --name "$name" "$image" >/dev/null
    docker exec "$name" dpkg-query -W -f='Debian source: ${source:Package} ${source:Version}\n' | sort -u
    if [ -n "${PXE_DOCKER_SOURCE_OFFER:-}" ]; then
        python3 packaging/ci/docker-source-offer.py "$image" > "$PXE_DOCKER_SOURCE_OFFER"
    fi
fi

for attempt in {1..90}; do
    if docker exec "$name" curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$name" curl -fsS --max-time 5 http://127.0.0.1:8080/healthz
docker exec "$name" curl -fsSL --max-time 10 http://127.0.0.1:8080/init >/dev/null

docker exec -i "$name" bash -eus -- "$mode" "$architecture" <<'GUEST'
if [ "$1" = apt ]; then
    set -a
    source /usr/lib/pxe-tools/native/default.env
    source /var/lib/pxe-tools-native/runtime.env
    set +a
fi
export PXE_IP=192.0.2.1
test "$(dpkg --print-architecture)" = "$2"
bash /opt/pxe-tools/scripts/bootstrap-generate-mok.sh
bash /opt/pxe-tools/scripts/bootstrap-install-pxe-bins.sh
bash /opt/pxe-tools/scripts/bootstrap-build-grub.sh
sbverify --cert "$MOK_DIR/MOK.pem" "$TFTP_ROOT/grubx64.efi"
test -s "$TFTP_ROOT/lpxelinux.0"
test -s "$TFTP_ROOT/grub/x86_64-efi/http.mod"
python3 - "$TFTP_ROOT" "$2" <<'PY'
from pathlib import Path
import struct
import sys

tftp = Path(sys.argv[1])
expected = {"grubnetx64.efi": 0x8664, "grubx64.efi": 0x8664, "mmx64.efi": 0x8664}
if sys.argv[2] == "arm64":
    expected["grubnetaa64.efi"] = 0xaa64
    assert (tftp / "grub/arm64-efi/http.mod").is_file()
for name, machine in expected.items():
    data = (tftp / name).read_bytes()
    assert data[:2] == b"MZ", name
    offset, = struct.unpack_from("<I", data, 0x3c)
    assert data[offset:offset + 4] == b"PE\0\0", name
    assert struct.unpack_from("<H", data, offset + 4)[0] == machine, name
    print(f"{name}: PE machine 0x{machine:04x}")
PY
test -z "$(dpkg --print-foreign-architectures)"
GUEST

if [ "$mode" = apt ]; then
    docker exec -e DEBIAN_FRONTEND=noninteractive "$name" apt-get install -y --no-install-recommends \
        pxe-tools-ansible
    docker exec "$name" ansible --version
    test "$(docker exec "$name" dpkg-query -W -f='${Architecture}' pxe-tools-ansible)" = all
fi
printf 'PXE_SERVER_ARCH_PASS=%s/%s\n' "$mode" "$architecture"
