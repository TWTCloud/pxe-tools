#!/bin/sh
# usage : pxe-disk-guard.sh <remap|strict> <url-ping> <bootdev> <smartctl-url> <chemin:base64(serial)|->...
SYS="${PXE_GUARD_SYSFS:-/sys/block}"
SYSROOT="${PXE_GUARD_SYSROOT:-/sys}"
EXPECTED_BOOT_MODE='__BOOTMODE__'
MODE="$1"; PING="$2"; BOOTDEV="$3"; SMARTCTL_URL="$4"; shift 4
SMARTCTL=""; SMARTCTL_TRIED=0
ensure_smartctl() {
    [ "$SMARTCTL_TRIED" = 1 ] && return 0
    SMARTCTL_TRIED=1
    [ -n "$SMARTCTL_URL" ] || return 0
    if "${PXE_GUARD_WGET:-/usr/bin/wget}" -q --timeout=8 -O /tmp/pxe-guard-smartctl "$SMARTCTL_URL" 2>/dev/null \
        && chmod +x /tmp/pxe-guard-smartctl 2>/dev/null && /tmp/pxe-guard-smartctl --version >/dev/null 2>&1; then
        SMARTCTL=/tmp/pxe-guard-smartctl
    else rm -f /tmp/pxe-guard-smartctl; fi
}
norm() { printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; }
valid_serial() {
    case "$1" in ''|0|UNKNOWN|N/A|NA|NONE|NULL|DEFAULT|"NOT AVAILABLE") return 1 ;; esac
    return 0
}
serial_for() {
    d="$1"; b="${d##*/}"
    s=""
    # Les contrôleurs n'exposent pas tous la série au même niveau de sysfs.
    for serial_path in "$d/device/serial" "$d/serial" "$d/device/device/serial"; do
        candidate=$(norm "$(cat "$serial_path" 2>/dev/null)")
        if valid_serial "$candidate"; then s="$candidate"; break; fi
    done
    if [ -z "$s" ]; then
        c=$(printf '%s' "$b" | sed -n 's/^\(nvme[0-9][0-9]*\)n[0-9][0-9]*$/\1/p')
        [ -n "$c" ] && s=$(norm "$(cat "$SYSROOT/class/nvme/$c/serial" 2>/dev/null)")
        valid_serial "$s" || s=""
    fi
    if [ -z "$s" ]; then
        ensure_smartctl
        [ -n "$SMARTCTL" ] && s=$("$SMARTCTL" -i "/dev/$b" 2>/dev/null | sed -n 's/^[Ss]erial [Nn]umber:[[:space:]]*//p' | head -1)
    fi
    norm "$s"
}
wwid_for() {
    d="$1"
    # Only the Hyper-V synthetic SCSI device class validated by the collector.
    [ "$(norm "$(cat "$d/device/vendor" 2>/dev/null)")" = 'MSFT' ] || return 0
    [ "$(norm "$(cat "$d/device/model" 2>/dev/null)")" = 'VIRTUAL DISK' ] || return 0
    norm "$(cat "$d/device/wwid" 2>/dev/null)"
}
valid_wwid() {
    [ "$1" != 'NAA.00000000000000000000000000000000' ] && printf '%s\n' "$1" | grep -Eq '^NAA\.[0-9A-F]{32}$'
}
report() {
    [ -n "$PING" ] || return 0
    "${PXE_GUARD_WGET:-/usr/bin/wget}" -q --timeout=5 -O /dev/null "$PING&phase=disk-guard&status=$1&message=$(printf '%s' "$2" | tr ' /' '+_')" 2>/dev/null || true
}
if [ -n "$EXPECTED_BOOT_MODE" ]; then
    actual_boot_mode=bios
    [ -d "$SYSROOT/firmware/efi" ] && actual_boot_mode=uefi
    if [ "$actual_boot_mode" != "$EXPECTED_BOOT_MODE" ]; then
        debconf-set partman-auto/disk /dev/pxe-disque-introuvable
        logger -t pxe-disk-guard "firmware-refuse-attendu-$EXPECTED_BOOT_MODE-observe-$actual_boot_mode"
        report failed "firmware-refuse-attendu-$EXPECTED_BOOT_MODE-observe-$actual_boot_mode"
        exit 1
    fi
fi
final_list=""; new_boot="$BOOTDEV"; bad=""; changes=""; target_count=0; diagnostic=""
for spec in "$@"; do
    path="${spec%%:*}"; encoded="${spec#*:}"; target_count=$((target_count + 1))
    case "$path" in /dev/[A-Za-z0-9]*) ;; *) bad="$bad $path"; diagnostic="chemin-cible-invalide"; continue ;; esac
    if [ "$encoded" = "-" ] || [ -z "$encoded" ]; then bad="$bad $path"; diagnostic="numero-serie-absent-du-snapshot"; continue; fi
    kind=serial
    case "$encoded" in wwid=*) kind=wwid; encoded="${encoded#wwid=}" ;; esac
    decoded=$(printf '%s' "$encoded" | base64 -d 2>/dev/null || printf '%s' "$encoded" | base64 -D 2>/dev/null)
    want=$(norm "$decoded")
    if [ "$kind" = wwid ]; then
        if ! valid_wwid "$want"; then bad="$bad $path"; diagnostic="wwid-cible-invalide"; continue; fi
    elif ! valid_serial "$want"; then bad="$bad $path"; diagnostic="numero-serie-cible-invalide"; continue; fi
    found=""; count=0
    for d in "$SYS"/*; do
        b="${d##*/}"
        case "$b" in loop*|ram*|dm-*|md*|sr*|fd*|zram*|nbd*|mmcblk*boot*|mmcblk*gp*|mmcblk*rpmb) continue ;; esac
        [ -e "$d/size" ] || continue
        if [ "$kind" = wwid ]; then
            got=$(wwid_for "$d")
            valid_wwid "$got" || continue
        else
            got=$(serial_for "$d")
            valid_serial "$got" || continue
        fi
        [ "$got" = "$want" ] || continue
        found="$b"; count=$((count + 1))
    done
    if [ "$count" -ne 1 ]; then
        bad="$bad $path"
        if [ "$count" -eq 0 ]; then diagnostic="numero-absent-illisible-ou-different"; else diagnostic="numero-serie-ambigu"; fi
    elif [ "$MODE" = strict ] && [ "/dev/$found" != "$path" ]; then
        bad="$bad $path"; diagnostic="remappage-interdit-en-raid-strict"
    else
        final_list="$final_list /dev/$found"
        [ "/dev/$found" != "$path" ] && changes="$changes $path=/dev/$found"
        [ "$BOOTDEV" = "$path" ] && new_boot="/dev/$found"
    fi
done
if [ -n "$bad" ]; then
    debconf-set partman-auto/disk /dev/pxe-disque-introuvable
    logger -t pxe-disk-guard "identite-refusee-$diagnostic:$bad"
    report failed "identite-refusee-$diagnostic:$bad"
    exit 1
elif [ "$target_count" -eq 0 ]; then
    debconf-set partman-auto/disk /dev/pxe-disque-introuvable
    logger -t pxe-disk-guard "aucun-disque-cible-avec-identite"
    report failed "aucun-disque-cible-avec-identite"
    exit 1
else
    debconf-set partman-auto/disk "${final_list# }"
    [ "$new_boot" != "$BOOTDEV" ] && debconf-set grub-installer/bootdev "$new_boot"
    if [ "$BOOTDEV" = default ] && [ "$target_count" -eq 1 ]; then debconf-set grub-installer/bootdev "${final_list# }"; fi
    logger -t pxe-disk-guard "identite confirmee :$final_list remappes:$changes"
    report success "identite confirmee:$final_list remappes:$changes"
fi
exit 0
