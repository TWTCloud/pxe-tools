#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
set -eu
case "$1" in
    activate)
        s6-svc -u /run/service/rust-guided
        exec s6-svc -r /run/service/rust-guided
        ;;
    deactivate) exec s6-svc -d /run/service/rust-guided ;;
    *) exit 2 ;;
esac
