#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Paths to complete Alpine client media for the static boot renderers."""
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

MANIFEST = Path(__file__).with_name('alpine-release.json')


def media(root, arch):
    if arch not in ('amd64', 'arm64') or not MANIFEST.is_file():
        return '', ''
    release = json.loads(MANIFEST.read_text())
    path = f"alpine-service/{release['version']}/{arch}"
    directory = Path(root) / 'netboot' / path
    files = (directory / name for name in (
        '.alpine-ready', 'linux', 'initrd.gz', 'modloop', 'service.apkovl.tar.gz',
    ))
    if not all(item.is_file() and not item.is_symlink() and item.stat().st_size > 0 for item in files):
        return '', ''
    mirror = os.environ.get('PXE_ALPINE_REPOSITORY', '')
    if re.fullmatch(r'[A-Za-z0-9:/._-]+', mirror):
        parsed = urlsplit(mirror)
        if parsed.scheme in ('http', 'https') and parsed.hostname:
            return path, mirror
    return path, f"https://dl-cdn.alpinelinux.org/alpine/{release['branch']}/main"


if __name__ == '__main__':
    path, repository = media(*sys.argv[1:])
    if path:
        print(path, repository)
