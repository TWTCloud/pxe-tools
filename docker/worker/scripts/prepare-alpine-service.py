#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Prepare the verified Alpine netboot files and service overlay."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from atomic_publish import publish as publish_small
import importlib.util


DIRECTORY = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    'publish_verified', DIRECTORY / 'publish-verified-image.py'
)
verified = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verified)
RELEASE = json.loads((DIRECTORY / 'alpine-release.json').read_text())
MAX_ARCHIVE = 640 * 1024**2
MEMBERS = {
    'boot/vmlinuz-lts': ('linux', 40 * 1024**2),
    'boot/initramfs-lts': ('initrd.gz', 96 * 1024**2),
    'boot/modloop-lts': ('modloop', 448 * 1024**2),
}
PACKAGES = (
    'smartmontools e2fsprogs-extra util-linux-misc blkid pciutils dmidecode parted '
    'mdadm lvm2 cryptsetup dosfstools xfsprogs curl'
)


def fetch(url, destination, maximum):
    subprocess.run([
        'curl', '--disable', '--fail', '--silent', '--show-error', '--location',
        '--proto', '=https', '--proto-redir', '=https', '--max-time', '900',
        '--max-filesize', str(maximum), '--retry', '2', '--output', str(destination), url,
    ], check=True)


def verify(archive, signature, expected):
    with archive.open('rb') as content:
        if hashlib.file_digest(content, 'sha256').hexdigest() != expected:
            raise ValueError('La somme SHA256 de l’archive Alpine est inattendue.')
    result = subprocess.run([
        'gpgv', '--status-fd', '1', '--keyring', str(DIRECTORY / 'alpine-release.gpg'),
        str(signature), str(archive),
    ], check=True, capture_output=True, text=True)
    rows = [line.split() for line in result.stdout.splitlines()
            if line.startswith('[GNUPG:] VALIDSIG ')]
    if len(rows) != 1 or rows[0][-1] != RELEASE['fingerprint']:
        raise ValueError('L’archive Alpine n’est pas signée par la clé de publication attendue.')


def unpack(archive, stage):
    found = set()
    with tarfile.open(archive, mode='r|gz') as tar:
        for entry in tar:
            name = entry.name.removeprefix('./')
            if name not in MEMBERS:
                continue
            target, maximum = MEMBERS[name]
            if name in found or not entry.isreg() or not 0 < entry.size <= maximum:
                raise ValueError(f'Entrée de démarrage Alpine invalide ({name}).')
            with tar.extractfile(entry) as source, (stage / target).open('xb') as dest:
                shutil.copyfileobj(source, dest, 1024**2)
            found.add(name)
    if found != MEMBERS.keys():
        raise ValueError('L’archive Alpine ne contient pas tous les fichiers LTS.')


def overlay():
    """Configure OpenRC in the transient root and install only the required tools."""
    files = {
        'etc/.default_boot_services': (b'', 0o644),
        'etc/apk/world': (('alpine-base\n' + PACKAGES.replace(' ', '\n') + '\n').encode(), 0o644),
        'etc/local.d/pxe-service.start': ((DIRECTORY / 'alpine-service.sh').read_bytes(), 0o755),
        # The rescue shell is started on the local console only for rescue-mode boots.
        'etc/inittab': (b'::sysinit:/sbin/openrc sysinit\n::sysinit:/sbin/openrc boot\n'
                        b'::wait:/sbin/openrc default\n::shutdown:/sbin/openrc shutdown\n', 0o644),
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for path, (content, mode) in files.items():
            member = tarfile.TarInfo(path)
            member.mode = mode
            member.size = len(content)
            tar.addfile(member, io.BytesIO(content))
        member = tarfile.TarInfo('etc/runlevels/default/local')
        member.type = tarfile.SYMTYPE
        member.linkname = '/etc/init.d/local'
        tar.addfile(member)
    return gzip.compress(archive.getvalue(), mtime=0)


def prepared(destination):
    return all(p.is_file() and not p.is_symlink() and p.stat().st_size > 0 for p in (
        destination / '.alpine-ready', destination / 'linux', destination / 'initrd.gz',
        destination / 'modloop', destination / 'service.apkovl.tar.gz',
    ))


def prepare(http, arch, source):
    version = RELEASE['version']
    destination = http / 'netboot/alpine-service' / version / arch
    if prepared(destination):
        return
    if os.environ.get('PXE_SERVICE_MANAGER') == 'systemd':
        subprocess.run([
            'python3', str(DIRECTORY / 'validate-native-runtime.py'), 'http-tree',
            str(http), f'netboot/alpine-service/{version}/{arch}',
        ], check=True)
    upstream = source['upstream_arch']
    artifact = f'alpine-netboot-{version}-{upstream}.tar.gz'
    url = f'https://dl-cdn.alpinelinux.org/alpine/{RELEASE["branch"]}/releases/{upstream}/{artifact}'
    print(f'Préparation d’Alpine {version} pour {arch}…', flush=True)
    with tempfile.TemporaryDirectory(prefix='pxe-image.', dir='/var/tmp') as private:
        stage = Path(private)
        archive = stage / artifact
        signature = stage / 'release.asc'
        fetch(url, archive, MAX_ARCHIVE)
        fetch(url + '.asc', signature, 16 * 1024)
        verify(archive, signature, source['sha256'])
        unpack(archive, stage)
        sign_kernel(stage)
        # The publication marker is written only after all files are complete.
        for name, _ in MEMBERS.values():
            verified.publish(stage / name, destination / name)
        publish_small(destination / 'service.apkovl.tar.gz', overlay(), mode=0o644)
        publish_small(destination / '.alpine-ready', (version + '\n').encode(), mode=0o644)
        print(f'Image Alpine vérifiée et prête ({arch}).', flush=True)


def sign_kernel(stage):
    mok = Path(os.environ.get('MOK_DIR', '/etc/pxe-tools/mok'))
    if os.environ.get('PXE_SERVICE_MANAGER') == 'systemd':
        subprocess.run([
            'python3', str(DIRECTORY / 'validate-native-runtime.py'), 'mok', str(mok),
        ], check=True)
    kernel = stage / 'linux'
    signed = stage / 'linux.signed'
    subprocess.run(['sbsign', '--key', str(mok / 'MOK.key'), '--cert', str(mok / 'MOK.pem'),
                    '--output', str(signed), str(kernel)], check=True)
    subprocess.run(['sbverify', '--cert', str(mok / 'MOK.pem'), str(signed)], check=True)
    signed.replace(kernel)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=RELEASE['images'])
    args = parser.parse_args()
    http = Path(os.environ.get('HTTP_ROOT', '/srv/http'))
    if os.geteuid() != 0 or not http.is_absolute() or not http.is_dir():
        raise ValueError('Racine HTTP PXE absolue et accès worker requis.')
    for arch, source in RELEASE['images'].items():
        if args.arch is None or args.arch == arch:
            prepare(http, arch, source)


if __name__ == '__main__':
    main()
