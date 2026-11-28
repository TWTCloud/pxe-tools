#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
directory="$(dirname "${BASH_SOURCE[0]}")"
exec python3 "$directory/prepare-alpine-service.py"
