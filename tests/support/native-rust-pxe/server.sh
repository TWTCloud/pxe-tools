#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
exec </dev/null >/dev/ttyS1 2>&1

fail() {
    printf 'PXE_NATIVE_FAILED line=%s status=%s\n' "$1" "$2"
    if [ -f /run/pxe-lab-apt.log ]; then tail -n 24 /run/pxe-lab-apt.log; fi
    if [ -f /run/pxe-lab-dhcp.log ]; then tail -n 24 /run/pxe-lab-dhcp.log; fi
    journalctl -b --no-pager -n 35 -u pxe-tools-rust-lab -u pxe-tools-init -u pxe-tools-pxe-http -u pxe-tools-dnsmasq || true
}
trap 'fail "$LINENO" "$?"' ERR

. /etc/os-release
[ "$ID" = debian ] && [ "$VERSION_ID" = 13 ] && [ "$(uname -m)" = x86_64 ]
seed=/mnt/pxe-native-fixture
mkdir -p "$seed"
mount -o ro /dev/sr0 "$seed"
[ -f "$seed/native-rust-lab" ]
printf '%s\n' "PXE_NATIVE_PLATFORM $PRETTY_NAME $(uname -m)"

# The first NIC has only a QEMU guestfwd to the fixture mirror. The second
# NIC is on the private Ethernet switch and cannot see the host network.
interface() {
    ip -j link show | python3 -c 'import json,sys; matches=[i["ifname"] for i in json.load(sys.stdin) if i.get("address")==sys.argv[1]]; assert len(matches)==1; print(matches[0])' "$1"
}
mirror_if=$(interface 52:54:00:44:00:01)
pxe_if=$(interface 52:54:00:44:00:02)
[ "$mirror_if" != "$pxe_if" ]
ip link set "$mirror_if" up
ip addr replace 10.0.2.15/24 dev "$mirror_if"
[ -z "$(ip -4 route show default)" ]
[ -z "$(ip -6 route show default)" ]

install -d -m 0750 /run/pxe-lab-apt-sources
for path in /etc/apt/sources.list.d/*; do
    [ -e "$path" ] || continue
    mv "$path" /run/pxe-lab-apt-sources/
done
printf '%s\n' 'deb [arch=amd64] http://10.0.2.100/debian trixie main' > /etc/apt/sources.list
printf '%s\n' 'Acquire::By-Hash "false";' 'Acquire::Languages "none";' > /etc/apt/apt.conf.d/99-pxe-lab
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
systemctl mask --now php8.4-fpm.service pxe-tools-php.service nginx.service
apt-get -qq update >/run/pxe-lab-apt.log 2>&1

# Seed before dpkg so first-install provisioning cannot start the PHP admin vhost.
python3 "$seed/server.py" seed "$seed"
apt-get -y --no-install-recommends install "$seed/pxe-tools-local.deb" >>/run/pxe-lab-apt.log 2>&1
apt-get clean
[ "$(dpkg-query -W -f='${Status}|${Version}|${Architecture}' pxe-tools-local-test)" = 'install ok installed|0.0.1~local1|amd64' ]
printf 'PXE_NATIVE_PACKAGE %s\n' "$(dpkg-query -W -f='${Package}=${Version}' pxe-tools-local-test)"
printf 'PXE_NATIVE_DNSMASQ %s\n' "$(dpkg-query -W -f='${Package}=${Version}' dnsmasq-base)"

ip link add br-pxetest type bridge
ip link set "$pxe_if" master br-pxetest
ip link set "$pxe_if" up
ip addr add 192.0.2.1/24 dev br-pxetest
ip link set br-pxetest up
ip netns add pxe-lease
ip link add veth-pxe type veth peer name veth-lease
ip link set veth-pxe master br-pxetest
ip link set veth-pxe up
ip link set veth-lease netns pxe-lease
ip netns exec pxe-lease ip link set lo up
ip netns exec pxe-lease ip addr add 192.0.2.2/24 dev veth-lease
ip netns exec pxe-lease ip link set veth-lease up
[ -z "$(ip -4 route show default)" ]
[ -z "$(ip netns exec pxe-lease ip -4 route show default)" ]
# The PXE ROM, installer and installed OS can send different DHCP client IDs.
ip netns exec pxe-lease dnsmasq -k --interface=veth-lease --bind-interfaces --dhcp-authoritative \
    --no-resolv --no-hosts --address=/pxe-native-lab.example.test/192.0.2.1 \
    --dhcp-range=192.0.2.0,static,255.255.255.0,1h \
    --dhcp-host='02:00:00:00:00:01,id:*,192.0.2.100' \
    --dhcp-option=3 --dhcp-option-force=6,192.0.2.2 \
    --dhcp-leasefile=/run/pxe-lab-leases --log-dhcp --log-facility=/run/pxe-lab-dhcp.log &
lease_pid=$!
trap 'kill "$lease_pid" 2>/dev/null || true' EXIT

install -D -m 0755 "$seed/pxe-tools-rust" /usr/local/libexec/pxe-tools-rust-lab
sha256sum /usr/local/libexec/pxe-tools-rust-lab | awk '{print "PXE_NATIVE_BINARY "$1}'
install -m 0644 "$seed/pxe-rust.conf" /usr/lib/pxe-tools/native/pxe.conf
python3 /usr/lib/pxe-tools/native/configure-secure-tftp.py
python3 "$seed/server.py" wire "$seed"
systemctl daemon-reload
systemctl start pxe-tools-init.service
set -a
. /usr/lib/pxe-tools/native/default.env
. /var/lib/pxe-tools-native/runtime.env
set +a
bash /opt/pxe-tools/scripts/bootstrap-install-pxe-bins.sh
systemctl start pxe-tools-dnsmasq.service

grep -qx 'dhcp-range=192.0.2.0,proxy,255.255.255.0' "$PXE_DNSMASQ_CONFIG"
for service in pxe-tools-dnsmasq.service pxe-tools-pxe-http.service pxe-tools-rust-lab.service; do
    systemctl is-active --quiet "$service"
done
test "$(curl -fsS --max-time 5 http://192.0.2.1/healthz)" = 'ok'
if curl -fsS --max-time 1 http://127.0.0.1/healthz >/dev/null 2>&1; then
    printf '%s\n' 'Unexpected loopback boot listener'
    exit 1
fi
test "$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://192.0.2.1/preseed.php?mac=02:00:00:00:00:ff)" = 404
grep -qx 'DEFAULT discovery' "$TFTP_ROOT/pxelinux.cfg/default"
python3 "$seed/server.py" follow "$seed"
