#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
exec /usr/lib/pxe-tools/pxe-tools-rust --refresh-catalog /etc/pxe-tools/db.conf
