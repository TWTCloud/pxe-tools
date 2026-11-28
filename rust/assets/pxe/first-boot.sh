#!/bin/sh
set -eu

if [ "$1" != --notify ]; then
    mkdir -p "$1/multi-user.target.wants"
    cat > "$1/pxe-first-boot.service" <<'UNIT'
[Unit]
Description=Signaler le premier démarrage à PXE Tools
After=network-online.target ssh.service
Wants=network-online.target ssh.service
ConditionPathExists=/etc/systemd/system-generators/pxe-first-boot

[Service]
Type=oneshot
ExecStart=/etc/systemd/system-generators/pxe-first-boot --notify
TimeoutStartSec=190
UNIT
    ln -sf ../pxe-first-boot.service "$1/multi-user.target.wants/pxe-first-boot.service"
    exit 0
fi

trap 'unlink "$0"' EXIT
trap 'exit 1' HUP INT TERM
pxe_ip=__PXE_IP__
mac=__MAC__
token=__TOKEN__
attempt=1
while [ "$attempt" -le 12 ]; do
    route=$(ip -4 route get "$pxe_ip" 2>/dev/null || true)
    source=$(printf '%s\n' "$route" | awk '{for (i=1; i<NF; i++) if ($i=="src") {print $(i+1); exit}}')
    if [ -n "$source" ]; then
        payload=$(printf '{"ip":"%s","kernel":"%s"}' "$source" "$(uname -r)")
        if receipt=$(curl -fsS --connect-timeout 5 --max-time 10 -X POST \
            "http://${pxe_ip}/api/internal/checkpoint?mac=${mac}&code=os_first_boot&ack=1" \
            -H "Authorization: Bearer ${token}" -H 'Content-Type: application/json' \
            --data-raw "$payload"); then
            case "$receipt" in
                accepted|closed) exit 0 ;;
            esac
        fi
    fi
    [ "$attempt" -eq 12 ] || sleep 5
    attempt=$((attempt + 1))
done
printf '%s\n' 'PXE Tools : signal de premier démarrage sans accusé de réception.' >&2
exit 1
