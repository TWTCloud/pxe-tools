#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Exercise real DHCP/TFTP and Rust HTTP in two disposable Docker LANs.
set -euo pipefail

server="${1:?PXE server container}"
variant="${2:?apt or docker}"
name="$server-multi"
image=$(docker inspect --format '{{.Config.Image}}' "$server")
cleanup() {
    for id in a b; do
        if docker inspect "$name-client-$id" >/dev/null 2>&1; then
            docker rm -f "$name-client-$id" >/dev/null
        fi
        if docker network inspect "$name-$id" >/dev/null 2>&1; then
            docker network disconnect -f "$name-$id" "$server" 2>/dev/null || true
            docker network rm "$name-$id" >/dev/null
        fi
    done
    if [[ "$variant" == docker ]]; then
        docker network disconnect -f bridge "$server" 2>/dev/null || true
    fi
}
trap cleanup EXIT

create_lan() {
    local id=$1 prefix=$2
    docker network create --internal --subnet "$prefix.0/24" "$name-$id" >/dev/null
    docker network connect --ip "$prefix.2" "$name-$id" "$server"
    docker run --detach --name "$name-client-$id" --network "$name-$id" --ip "$prefix.20" \
        --entrypoint /bin/sleep "$image" infinity >/dev/null
}
create_lan a 203.0.113
create_lan b 198.19.77
if [[ "$variant" == docker ]]; then
    # The ARM64 server may retrieve signed x86 bootloader packages from Debian.
    docker network connect bridge "$server"
fi

docker exec -i "$server" bash -es -- "$variant" <<'GUEST'
set -euo pipefail
if [[ "$1" == apt ]]; then
    systemctl stop pxe-tools-worker.service
    set -a
    source /usr/lib/pxe-tools/native/default.env
    source /var/lib/pxe-tools-native/runtime.env
    set +a
else
    s6-svc -d /run/service/worker
fi
interface() {
    ip -o -4 addr show | awk -v address="$1/24" '$4 == address { print $2 }'
}
a=$(interface 203.0.113.2)
b=$(interface 198.19.77.2)
test -n "$a"
test -n "$b"
test "$a" != "$b"
port=$(/usr/lib/pxe-tools/pxe-tools-rust --console-https-port /etc/pxe-tools/db.conf)
origin="https://127.0.0.1:$port"
auth=(curl -ksS --max-time 8 --user setup-fixture:fixture-only-password)
page=$("${auth[@]}" -f "$origin/settings/network")
[[ "$page" == *'type="checkbox" name="network_address_'* && "$page" == *"$a|203.0.113.2"* && "$page" == *"$b|198.19.77.2"* ]]
form=(-o /dev/null -w '%{http_code}' -H "Origin: $origin" --data-urlencode role=proxy)
test "$("${auth[@]}" "${form[@]}" --data-urlencode "network_address_0=$a|203.0.113.2" \
    --data-urlencode "network_address_1=$a|203.0.113.2" "$origin/settings/network")" = 422
test "$("${auth[@]}" "${form[@]}" --data-urlencode "network_address_0=$a|203.0.113.2" \
    --data-urlencode "network_address_1=$b|198.19.77.2" "$origin/settings/network")" = 303

bash /opt/pxe-tools/scripts/bootstrap-render-templates.sh
bash /opt/pxe-tools/scripts/bootstrap-restart-dnsmasq.sh
test "$(curl -fsS --retry 6 --retry-connrefused --max-time 4 http://127.0.0.1/healthz)" = ok
test "$(curl --interface 203.0.113.2 -sS --max-time 4 -o /dev/null -w '%{http_code}' \
    http://198.19.77.2/discovery-preseed.cfg)" = 404
GUEST

probe_lan() {
    local id=$1 server_ip=$2 other=$3 pid
    pid=$(docker inspect --format '{{.State.Pid}}' "$name-client-$id")
    sudo nsenter -t "$pid" -n python3 - "$server_ip" <<'PYTHON'
import json
import os
import socket
import struct
import subprocess
import sys
import time

server = socket.inet_aton(sys.argv[1])
link, = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'dev', 'eth0']))
mac = bytes.fromhex(link['address'].replace(':', ''))
xid = os.urandom(4)
packet = bytearray(240)
packet[:4] = bytes((1, 1, 6, 0))
packet[4:8] = xid
packet[10:12] = struct.pack('!H', 0x8000)
packet[28:34] = mac
packet[236:240] = bytes.fromhex('63825363')
vendor = b'PXEClient:Arch:00007:UNDI:003016'
packet += bytes((53, 1, 1, 93, 2, 0, 7, 60, len(vendor))) + vendor + b'\xff'
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.bind(('', 68))
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        client.sendto(packet, ('255.255.255.255', 67))
        client.settimeout(1)
        try:
            reply, peer = client.recvfrom(2048)
        except TimeoutError:
            continue
        if reply[4:8] != xid:
            continue
        assert reply[16:20] == b'\0' * 4, 'proxy DHCP offered an IP lease'
        assert reply[20:24] == server, (sys.argv[1], peer, socket.inet_ntoa(reply[20:24]))
        assert reply[108:236].split(b'\0', 1)[0] == b'grubnetx64.efi'
        break
    else:
        raise SystemExit(f'No UEFI ProxyDHCP offer received from {sys.argv[1]}')
PYTHON
    local tftp menu seed
    tftp=$(sudo nsenter -t "$pid" -n curl --noproxy '*' -fsS --max-time 8 "tftp://$server_ip/pxelinux.cfg/default")
    menu=$(sudo nsenter -t "$pid" -n curl --noproxy '*' -fsS --max-time 8 "http://$server_ip/pxe/grub.cfg?mac=02:00:00:00:ae:0$id")
    seed=$(sudo nsenter -t "$pid" -n curl --noproxy '*' -fsS --max-time 8 "http://$server_ip/discovery-preseed.cfg")
    [[ "$tftp" == *"http://$server_ip/"* && "$tftp" != *"$other"* ]]
    [[ "$menu" == *"http://$server_ip/"* && "$menu" != *"$other"* ]]
    [[ "$seed" == *"http://$server_ip/"* && "$seed" != *"$other"* ]]
    printf 'ProxyDHCP, TFTP BIOS, GRUB et preseed de découverte passent par %s.\n' "$server_ip"
}
probe_lan a 203.0.113.2 198.19.77.2
probe_lan b 198.19.77.2 203.0.113.2
