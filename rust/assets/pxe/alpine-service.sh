#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# Run from Alpine's local service, after the network and modloop are available.
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
server=
mode=
bootif=
read -r cmdline </proc/cmdline
set -f
for option in $cmdline; do
    case "$option" in
        pxe_server=*) server=${option#pxe_server=} ;;
        pxe_service=*) mode=${option#pxe_service=} ;;
        BOOTIF=*) bootif=${option#BOOTIF=} ;;
    esac
done
set +f
if ! printf '%s\n' "$server" | grep -Eq '^([0-9]{1,3}[.]){3}[0-9]{1,3}$'; then
    echo "PXE Tools: adresse du serveur absente ou invalide." >/dev/console
    exit 1
fi
mac=$(printf '%s' "${bootif#01-}" | tr 'A-Z-' 'a-z:')
if ! printf '%s\n' "$mac" | grep -Eq '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; then
    echo "PXE Tools: adresse MAC de démarrage absente ou invalide." >/dev/console
    exit 1
fi
case "$mode" in
    discovery) route=discover.sh ;;
    disktest) route=disktest.sh ;;
    wipe) route="wipe.sh?mac=$mac" ;;
    rescue) route= ;;
    *) echo "PXE Tools: mode de service inconnu." >/dev/console; exit 1 ;;
esac
for tool in wget smartctl badblocks blkdiscard blkid; do
    if ! command -v "$tool" >/dev/null; then
        printf 'PXE Tools: outil Alpine indisponible (%s).\n' "$tool" >/dev/console
        exit 1
    fi
done
mem=$(awk '$1=="MemAvailable:" {print $2}' /proc/meminfo)
printf 'PXE_ALPINE_SERVICE_READY mode=%s available_kib=%s\n' "$mode" "$mem" >/dev/console
if [ "$mode" = rescue ]; then
    echo 'PXE Tools · Secours Alpine · shell local · disques non montés' >/dev/console
    exec /bin/busybox setsid /bin/busybox cttyhack /bin/sh -i </dev/console >/dev/console 2>&1
fi

script=$(mktemp /run/pxe-service.XXXXXXXX)
trap 'unlink "$script"' EXIT
ORCH_IP="$server"
PXE_BOOT_MAC="$mac"
export ORCH_IP PXE_BOOT_MAC
if [ "$mode" = discovery ]; then
    wget -q -T 10 -O /dev/null "http://$server/api/discovery?phase=alpine_ready&mac=$mac" || true
fi
if wget -q -T 30 -O "$script" "http://$server/$route" && [ -s "$script" ]; then
    /bin/sh "$script" || echo "PXE Tools: l’opération $mode a échoué." >/dev/console
else
    echo "PXE Tools: le serveur n’a pas fourni l’opération $mode." >/dev/console
fi
sync
poweroff -f
