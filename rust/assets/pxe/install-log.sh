#!/bin/sh
# usage : pxe-dilog.sh <run|flush> <url> <jeton>
SRC="${PXE_DILOG_SRC:-/var/log/syslog}"; STATE="${PXE_DILOG_STATE:-/tmp/pxe-dilog}"
WGET="${PXE_DILOG_WGET:-/usr/bin/wget}"; PAUSE="${PXE_DILOG_PAUSE:-2}"
MODE="$1"; URL="$2"; TOKEN="$3"
send() {
    [ -r "$SRC" ] || return 0
    OFF=$(( $(cat "$STATE.off" 2>/dev/null || echo 0) ))
    SIZE=$(( $(wc -c < "$SRC") ))
    [ "$SIZE" -gt "$OFF" ] || return 0
    tail -c +$((OFF + 1)) "$SRC" 2>/dev/null | dd bs=4096 count=48 2>/dev/null > "$STATE.chunk"
    N=$(( $(wc -c < "$STATE.chunk") ))
    [ "$N" -gt 0 ] || return 0
    SEQ=$(( $(cat "$STATE.seq" 2>/dev/null || echo 0) + 1 ))
    if "$WGET" -q --timeout=5 --tries=1 --header="Authorization: Bearer $TOKEN" --header='Content-Type: text/plain' \
        --post-file="$STATE.chunk" -O /dev/null "$URL&seq=$SEQ" 2>/dev/null; then
        echo $((OFF + N)) > "$STATE.off"; echo "$SEQ" > "$STATE.seq"
    fi
}
if [ "$MODE" = run ]; then
    echo $$ > "$STATE.pid"
    while :; do send; sleep "$PAUSE"; done
fi
for i in 1 2 3 4 5 6 7 8; do
    send
    [ $(( $(cat "$STATE.off" 2>/dev/null || echo 0) )) -ge $(( $(wc -c < "$SRC") )) ] && break
done
exit 0
