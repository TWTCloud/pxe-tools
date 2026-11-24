#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Extract the installation image once from a verified local Windows ISO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


IMAGE_PATHS = {'sources/install.wim', 'sources/install.esd'}
SHA256 = re.compile(r'[0-9a-f]{64}')


def fingerprint(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected a regular media file')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def extract(iso, expected, cache):
    if not SHA256.fullmatch(expected):
        raise ValueError('Invalid approved ISO digest')
    record = cache/f'iso-{expected}.json'
    if record.exists():
        metadata = json.loads(record.read_text())
        image = metadata['install_image']
        digest = metadata['install_sha256']
        if f'sources/{image}' not in IMAGE_PATHS or not SHA256.fullmatch(digest):
            raise ValueError('Invalid installation image cache entry')
        destination = cache/digest/image
        if fingerprint(destination) != digest or destination.stat().st_size != metadata['size']:
            raise ValueError('Cached image digest differs')
        return {'install_image': image, 'install_sha256': digest,
                'size': metadata['size'], 'path': str(destination), 'iso_sha256': expected}

    if iso is None:
        raise ValueError('Provide the approved ISO for the first import')
    if fingerprint(iso) != expected:
        raise ValueError('ISO differs from the approved digest')
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    listing = subprocess.check_output(['7z', 'l', '-slt', iso], text=True)
    matches = [
        line.removeprefix('Path = ') for line in listing.splitlines()
        if line.startswith('Path = ') and line.removeprefix('Path = ').lower() in IMAGE_PATHS
    ]
    if len(matches) != 1:
        raise ValueError('Expected exactly one install.wim or install.esd in the ISO')
    entry = matches[0]
    name = Path(entry).name.lower()
    with tempfile.TemporaryDirectory(prefix='.import-', dir=cache) as staging:
        staged = Path(staging)/name
        with staged.open('xb') as destination:
            subprocess.run(['7z', 'x', '-so', iso, entry], stdout=destination, check=True)
        size = staged.stat().st_size
        if size == 0:
            raise ValueError('The extracted installation image is empty')
        digest = fingerprint(staged)
        final = cache/digest/name
        final.parent.mkdir(mode=0o700, exist_ok=True)
        staged.chmod(0o444)
        try:
            os.link(staged, final)
        except FileExistsError:
            if fingerprint(final) != digest:
                raise ValueError('Existing image at the content address has a different digest')
        metadata = {'install_image': name, 'install_sha256': digest, 'size': size,
                    'path': str(final), 'iso_sha256': expected}
        pointer = Path(staging)/'record.json'
        pointer.write_text(json.dumps(metadata)+'\n')
        pointer.replace(record)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, help='Local Windows ISO for the first import')
    parser.add_argument('--iso-sha256', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    try:
        iso = args.iso.absolute() if args.iso else None
        print(json.dumps(extract(iso, args.iso_sha256.lower(), args.cache.absolute())))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Windows media import failed. {error}\n')


if __name__ == '__main__':
    main()
