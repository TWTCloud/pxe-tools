#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Serve deterministic vendor catalog metadata to the Rust refresh command."""

from hashlib import sha256
import sys


def indexes():
    digest = sha256(b'verified replacement').hexdigest()
    url = sys.argv[-1]
    roots = {
        'https://dl.fedoraproject.org/pub/fedora/linux/releases/': ('43', '44', '46', 'test'),
        'https://mirror.stream.centos.org/': ('9-stream', '10-stream', 'SIGs'),
        'https://repo.almalinux.org/almalinux/': ('8', '9', '10', '10.1'),
        'https://download.rockylinux.org/pub/rocky/': ('8', '9', '10', '10.1'),
        'https://cdimage.debian.org/cdimage/archive/': ('13.8.0', '13.7.0', '13.5.0', '13.7.0-live'),
    }
    if url in roots:
        return '\n'.join(f'<a href="{name}/">{name}/</a>' for name in roots[url])
    if url.endswith('/bookworm/Release'):
        return 'Version: 12.15'
    if url.endswith('/trixie/Release'):
        return 'Version: 13.8'
    if url.endswith('/weekly-builds/amd64/iso-cd/SHA256SUMS'):
        return f'{digest}  debian-testing-amd64-netinst.iso'
    if url == 'https://releases.ubuntu.com/24.04/SHA256SUMS':
        return f'{digest} *ubuntu-24.04.6-live-server-amd64.iso'
    if url == 'https://cdimage.ubuntu.com/releases/24.04/release/SHA256SUMS':
        return f'{digest} *ubuntu-24.04.7-live-server-arm64.iso'
    if url == 'https://old-releases.ubuntu.com/releases/24.04/':
        return '<a href="ubuntu-24.04.10-live-server-amd64.iso">ISO</a>'
    if url.endswith('/.treeinfo') and url.startswith(tuple(roots)):
        if '/46/Server/aarch64/' in url:
            return '[checksums]\nimages/boot.iso = sha256:' + digest
        return f'''[checksums]
images/pxeboot/vmlinuz=sha256:{digest}
images/pxeboot/initrd.img = sha256:{digest}

[images]
'''
    if url.endswith('/current/images/SHA256SUMS'):
        return f'{digest}  ./netboot/debian-installer/amd64/initrd.gz'
    sys.exit(22)


print(indexes())
