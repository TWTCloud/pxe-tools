#!/bin/sh
# Compatibility launcher for the historical appliance and upgrade fixtures.

adopt_database() {
    php -r 'require $argv[1]; \Admin\Db::writeInitialConfig(["driver" => "sqlite", "path" => $argv[2]]);' "$PXE_APP_DIR/src/Db.php" "$DETECTED_DB"
}

migrate_database() {
    migration="$PXE_APP_DIR/db/migrate.php"
    if [ -f "$migration" ]; then
        echo "[database-init] Migrations SQLite : $migration"
        run_as_web php "$migration" || {
            echo '[database-init] ERREUR : migration refusée ou échouée ; démarrage arrêté.' >&2
            exit 1
        }
    fi
}

prepare_web_runtime() {
    mkdir -p /run/php
    chown www-data:www-data /run/php
}

. "${0%/*}/database-init.sh"
