#!/bin/sh
set -eu

if [ "${PXE_RUST_DIRECT_HTTP:-}" = 1 ] && [ -e /etc/pxe-tools/db.conf ]; then
    binary=/usr/lib/pxe-tools/pxe-tools-rust
    config=/etc/pxe-tools/db.conf
    if ! address=$(runuser -u www-data -- "$binary" --refresh-pxe-address "$config"); then
        echo '[bootstrap] Impossible de vérifier l’adresse PXE.' >&2
        exit 0
    fi
    case "$address" in
        unchanged) ;;
        suspended)
            echo '[bootstrap] Aucune IPv4 unique utilisable sur l’interface PXE. La console reste accessible.'
            exit 0
            ;;
        *)
            # A rebinding changes the IP embedded in signed GRUB. Gate the
            # network until both GRUB and the boot scripts use the new address.
            if timeout 30s /bin/bash /opt/pxe-tools/scripts/bootstrap-build-grub.sh &&
                /bin/bash /opt/pxe-tools/scripts/bootstrap-render-templates.sh &&
                runuser -u www-data -- "$binary" --finish-pxe-address "$config" "$address"; then
                echo "[bootstrap] Nouvelle adresse PXE appliquée : $address"
            else
                echo '[bootstrap] Préparation de la nouvelle adresse échouée. Démarrage PXE suspendu.' >&2
            fi
            exit 0
            ;;
    esac
fi

if [ "${1:-}" = --refresh-only ]; then exit 0; fi
exec /bin/bash /opt/pxe-tools/scripts/bootstrap-render-templates.sh
