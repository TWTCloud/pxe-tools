#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
set -eu

console_port=$(/usr/lib/pxe-tools/pxe-tools-rust --console-https-port /etc/pxe-tools/db.conf)
curl -fsS "http://127.0.0.1:${PXE_HTTP_PORT:-80}/healthz" >/dev/null
curl -fsSk "https://127.0.0.1:${console_port}/healthz" >/dev/null
