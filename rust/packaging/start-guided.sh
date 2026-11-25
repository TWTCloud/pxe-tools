#!/bin/sh
set -eu
python3 /opt/pxe-tools/scripts/validate-native-runtime.py tls "$TLS_DIR"
export CREDENTIALS_DIRECTORY=/run/pxe-tools-rust-guided
install -d -o root -g www-data -m 0750 "$CREDENTIALS_DIRECTORY"
install -o root -g www-data -m 0440 "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem" "$CREDENTIALS_DIRECTORY/"
setup_code=$(mktemp "$CREDENTIALS_DIRECTORY/.setup-code.XXXXXX")
trap 'rm -f -- "$setup_code"' EXIT
short_code=$(openssl rand -hex 6)
printf '%s\n' "$short_code" | sed -E 's/^([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})$/\1-\2-\3/' > "$setup_code"
install -o root -g www-data -m 0440 "$setup_code" "$CREDENTIALS_DIRECTORY/setup-code"
rm -f -- "$setup_code"
trap - EXIT
exec /usr/bin/setpriv --reuid=www-data --regid=www-data --init-groups \
    --inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
    --bounding-set=-all,+net_bind_service --no-new-privs \
    /usr/lib/pxe-tools/pxe-tools-rust --serve-guided /etc/pxe-tools/db.conf
