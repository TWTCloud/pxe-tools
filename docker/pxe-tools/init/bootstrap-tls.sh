#!/bin/sh
# Génère un cert TLS self-signed pour le port admin 8443.
# Idempotent : skip si cert.pem + key.pem déjà présents et valides (>30j).
# Storage : volume nommé pxe_tls monté sur /var/lib/pxe-tools/tls
#
# Le certificat reste prêt si HTTPS est réactivé depuis l'interface. Sa
# présence n'ouvre aucun port lorsque https_enabled='off'.
set -eu

TLS_DIR="${TLS_DIR:-/var/lib/pxe-tools/tls}"
CERT="$TLS_DIR/cert.pem"
KEY="$TLS_DIR/key.pem"
CN="${TLS_CN:-pxe-tools.local}"
DAYS="${TLS_DAYS:-3650}"

if [ "${PXE_RUST_DIRECT_HTTP:-}" = 1 ]; then
    python3 /opt/pxe-tools/scripts/validate-native-runtime.py tls "$TLS_DIR"
else
    mkdir -p "$TLS_DIR"
fi

# Never replace existing certificate material automatically. An expired or
# unreadable certificate can be diagnosed and replaced explicitly by its owner.
if [ -e "$CERT" ] || [ -L "$CERT" ] || [ -e "$KEY" ] || [ -L "$KEY" ]; then
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        echo "[bootstrap-tls] ERREUR : certificat ou clé manquante ; fichiers existants conservés." >&2
        exit 1
    fi
    if ! openssl x509 -in "$CERT" -noout -checkend 2592000 >/dev/null 2>&1; then
        echo "[bootstrap-tls] WARN : certificat expiré, bientôt expiré ou illisible ; fichiers conservés." >&2
    fi
    echo "[bootstrap-tls] certificat et clé existants conservés"
    exit 0
fi

echo "[bootstrap-tls] Génération cert self-signed CN=$CN ($DAYS jours)"
SAN="DNS:localhost,DNS:$CN,IP:127.0.0.1"
if [ "${PXE_RUST_DIRECT_HTTP:-}" = 1 ]; then
    ADDITIONAL_SAN=$(PYTHONPATH="${PXE_APP_DIR:-/app}" python3 - <<'PYTHON'
import ipaddress
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path

from database_selection import select_database

names = []
host = os.environ.get('PXE_PUBLIC_HOST', '')
if host:
    try:
        names.append('IP:' + str(ipaddress.ip_address(host)))
    except ValueError:
        if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host):
            names.append('DNS:' + host)
try:
    path = Path(select_database()[0])
    if path.is_file():
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            row = db.execute("SELECT value FROM settings WHERE key='pxe_ip'").fetchone()
            if row and row[0]:
                names.append('IP:' + str(ipaddress.IPv4Address(row[0])))
except (RuntimeError, sqlite3.Error, ValueError):
    pass
print(''.join(',' + name for name in dict.fromkeys(names)), end='')
PYTHON
)
    SAN="$SAN$ADDITIONAL_SAN"
fi
if [ "${PXE_RUST_DIRECT_HTTP:-}" = 1 ]; then
    umask 077
    ISSUE_DIR=$(mktemp -d "$TLS_DIR/.issue.XXXXXX")
    trap 'rm -rf -- "$ISSUE_DIR"' EXIT
    CERT="$ISSUE_DIR/cert.pem"
    KEY="$ISSUE_DIR/key.pem"
fi
openssl req -x509 -nodes \
    -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -days "$DAYS" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=$SAN"

chmod 0600 "$KEY"
chmod 0644 "$CERT"
if [ "${PXE_RUST_DIRECT_HTTP:-}" = 1 ]; then
    mv -- "$KEY" "$TLS_DIR/key.pem"
    mv -- "$CERT" "$TLS_DIR/cert.pem"
    python3 /opt/pxe-tools/scripts/validate-native-runtime.py tls "$TLS_DIR"
fi

echo "[bootstrap-tls] cert généré dans $TLS_DIR"
