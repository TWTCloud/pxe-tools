#!/bin/sh
set -eu
/opt/pxe-tools/init/render-nginx-conf.sh
nginx -t
nginx -s reload
