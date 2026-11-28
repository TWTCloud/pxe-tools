#!/bin/sh
set -eu
node=$(printf '%s' '__NODE__' | base64 -d)
fqdn=$(printf '%s' '__FQDN__' | base64 -d)
printf '%s\n' "$node" > /target/etc/hostname
hosts=/target/etc/hosts
tmp="$hosts.pxe-tools.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
[ -f "$hosts" ] || : > "$hosts"
awk -v node="$node" -v fqdn="$fqdn" '
    $1 == "127.0.1.1" && !done {
        printf "127.0.1.1\t%s", fqdn
        if (node != fqdn) printf " %s", node
        for (i = 2; i <= NF; i++) {
            if ($i != node && $i != fqdn) printf " %s", $i
        }
        printf "\n"
        done = 1
        next
    }
    { print }
    END {
        if (!done) {
            printf "127.0.1.1\t%s", fqdn
            if (node != fqdn) printf " %s", node
            printf "\n"
        }
    }
' "$hosts" > "$tmp"
mv "$tmp" "$hosts"
