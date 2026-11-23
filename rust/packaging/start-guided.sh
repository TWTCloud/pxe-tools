#!/bin/sh
set -eu
python3 /opt/pxe-tools/scripts/validate-native-runtime.py tls "$TLS_DIR"
export CREDENTIALS_DIRECTORY=/run/pxe-tools-rust-guided
install -d -o root -g www-data -m 0750 "$CREDENTIALS_DIRECTORY"
install -o root -g www-data -m 0440 "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem" "$CREDENTIALS_DIRECTORY/"
exec /usr/bin/setpriv --reuid=www-data --regid=www-data --init-groups \
    --inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
    --bounding-set=-all,+net_bind_service --no-new-privs \
    /usr/lib/pxe-tools/pxe-tools-rust --serve-guided /etc/pxe-tools/db.conf
