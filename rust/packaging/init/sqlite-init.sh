#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only

adopt_database() {
    /usr/lib/pxe-tools/pxe-tools-rust --adopt-existing-sqlite "$DB_CONF" "$DETECTED_DB"
}

migrate_database() {
    echo '[database-init] Migrations SQLite'
    run_as_web /usr/lib/pxe-tools/pxe-tools-rust --migrate-sqlite "$DB_CONF" "${HTTP_ROOT:-/srv/http}" || {
        echo '[database-init] ERREUR : migration refusée ou échouée ; démarrage arrêté.' >&2
        exit 1
    }
}

prepare_web_runtime() { :; }

. "${0%/*}/database-init.sh"
