#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Record corresponding sources identified from a built PXE Tools image."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import lzma
from pathlib import Path
import re
import subprocess
import sys
import tempfile

DEBIAN = 'https://deb.debian.org'
SUITES = (
    f'{DEBIAN}/debian/dists/trixie',
    f'{DEBIAN}/debian/dists/trixie-updates',
    f'{DEBIAN}/debian-security/dists/trixie-security',
)
ARCHIVED = {
    ('base-files', '13.8+deb13u7'): [
        {'url': 'https://snapshot.debian.org/file/09c6e9bef6e1c0234e4cd91d2a7ac5d52f6dc8b3',
         'name': 'base-files_13.8+deb13u7.dsc',
         'sha256': '6240b5a02fc32bd6d925bb7776e00c467e80d930f8cf3c4a20c299ce692dc7e4'},
        {'url': 'https://snapshot.debian.org/file/967e7c01534a5ffee64590239c8c22371619c1aa',
         'name': 'base-files_13.8+deb13u7.tar.xz',
         'sha256': 'be32803b9408ac9aa46b96f68c83ee45e88d04d89854a87999986efc4cb34c69'},
    ],
}
S6 = {
    'overlay': 'https://github.com/just-containers/s6-overlay/tree/e2738d136bbdedbe3553b947f3c18183fc70e56c',
    'helpers': 'https://github.com/just-containers/s6-overlay-helpers/tree/v0.1.1.0',
    'BearSSL': 'https://www.bearssl.org/gitweb/?p=BearSSL;a=commit;h=79c060eea3eea1257797f15ea1608a9a9923aa6f',
    'musl': 'https://git.musl-libc.org/cgit/musl/commit/?id=007997299248b8682dcbb73595c53dfe86071c83',
    'musl-archive': 'https://codeload.github.com/ifduyue/musl/tar.gz/007997299248b8682dcbb73595c53dfe86071c83',
    'GCC': 'https://ftp.gnu.org/gnu/gcc/gcc-14.1.0/',
    **{name: f'https://skarnet.org/software/{name}/{name}-{version}.tar.gz' for name, version in (
        ('skalibs', '2.14.2.0'), ('execline', '2.9.6.0'), ('s6', '2.13.0.0'),
        ('s6-rc', '0.5.4.3'), ('s6-linux-init', '1.1.2.0'), ('s6-portable-utils', '2.3.0.3'),
        ('s6-linux-utils', '2.6.2.0'), ('s6-dns', '2.3.7.2'), ('s6-networking', '2.7.0.3'),
    )},
}


def fetch(url, limit):
    return subprocess.check_output([
        'curl', '--proto', '=https', '--proto-redir', '=https', '--fail', '--silent',
        '--show-error', '--location', '--retry', '2', '--max-time', '60', '--max-filesize', str(limit), url,
    ], timeout=190)


def sources(suite, keyring, needed):
    with tempfile.TemporaryDirectory(prefix='pxe-debian-sources-') as temporary:
        signed = Path(temporary) / 'InRelease'
        signed.write_bytes(fetch(f'{suite}/InRelease', 1024 * 1024))
        release = subprocess.check_output(
            ['gpgv', '--keyring', str(keyring), '--output', '-', str(signed)], text=True, timeout=15)
    sha256 = release.split('\nSHA256:\n', 1)[1].split('\nSHA512:\n', 1)[0]
    checksum, length = re.fullmatch(
        r' ([a-f0-9]{64})\s+([0-9]+) main/source/Sources\.xz',
        next(line for line in sha256.splitlines() if line.endswith(' main/source/Sources.xz')),
    ).groups()
    raw = fetch(f'{suite}/main/source/by-hash/SHA256/{checksum}', 32 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != checksum or len(raw) != int(length):
        raise ValueError('Debian source index differs from its signed digest')
    limit = 192 * 1024 * 1024
    decoder = lzma.LZMADecompressor(memlimit=limit)
    text = decoder.decompress(raw, max_length=limit + 1)
    if len(text) > limit or not decoder.eof or decoder.unused_data:
        raise ValueError('invalid Debian source index size')
    found = {}
    for paragraph in text.decode().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in paragraph.splitlines()
                      if not line.startswith(' ') and ': ' in line)
        package = (fields.get('Package'), fields.get('Version'))
        if package not in needed:
            continue
        directory = fields['Directory']
        if not re.fullmatch(r'pool/[A-Za-z0-9._+/-]+', directory) or '..' in directory.split('/'):
            raise ValueError('invalid Debian source directory')
        checksums = re.search(r'(?m)^Checksums-Sha256:\n((?: [^\n]+\n)+)', paragraph + '\n')
        if not checksums:
            raise ValueError('missing Debian source checksums')
        files = []
        for line in checksums[1].splitlines():
            digest, size, name = line.split()
            if not re.fullmatch(r'[a-f0-9]{64}', digest) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+._~-]+', name):
                raise ValueError('invalid source artifact metadata')
            files.append({'url': f"{suite.split('/dists/', 1)[0]}/{directory}/{name}",
                          'name': name, 'sha256': digest, 'bytes': int(size)})
        found[package] = files
    return found


def inspect_image(image):
    details = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image]))[0]
    run = ['docker', 'run', '--rm', '--network', 'none', '--entrypoint']
    overlay = subprocess.check_output([*run, 'readlink', image, '/package/admin/s6-overlay'], text=True).strip()
    if overlay != 's6-overlay-3.2.0.0':
        raise ValueError(f'unreviewed s6-overlay source version: {overlay}')
    inventory = subprocess.check_output([
        *run, 'dpkg-query', image, '-W', '-f=${source:Package}\t${source:Version}\n',
    ], text=True)
    needed = set(tuple(line.split('\t')) for line in inventory.splitlines())
    if any(len(package) != 2 or not all(package) for package in needed) or not needed:
        raise ValueError('incomplete Debian binary inventory')
    key = subprocess.check_output([*run, 'cat', image, '/usr/share/keyrings/debian-archive-keyring.gpg'])
    with tempfile.TemporaryDirectory(prefix='pxe-debian-keyring-') as temporary:
        keyring = Path(temporary) / 'debian.gpg'
        keyring.write_bytes(key)
        with ThreadPoolExecutor(max_workers=len(SUITES)) as pool:
            available = {}
            for result in pool.map(lambda suite: sources(suite, keyring, needed), SUITES):
                available.update(result)

    missing = needed - available.keys()
    if missing - ARCHIVED.keys():
        raise ValueError(f'Debian sources missing: {sorted(missing - ARCHIVED.keys())}')
    for package in missing:
        files = []
        for record in ARCHIVED[package]:
            data = fetch(record['url'], 1024 * 1024)
            digest = hashlib.sha256(data).hexdigest()
            if digest != record['sha256']:
                raise ValueError('archived Debian source checksum mismatch')
            files.append({**record, 'sha256': digest, 'bytes': len(data)})
        available[package] = files
    return {
        'image_id': details['Id'], 'architecture': details['Architecture'],
        'debian_sources': [{'name': name, 'version': version, 'files': available[name, version]}
                           for name, version in sorted(needed)],
        's6_overlay_3.2.0.0': S6,
        'static_helpers': 'https://github.com/williamboglietti/pxe-tools/releases/tag/sources-2026-11-12',
        'pxe_tools_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    }


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('pass one locally built image')
        print(json.dumps(inspect_image(sys.argv[1]), indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
