#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Verify Windows PXE fixture inputs and evidence from both guest boots."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid


PREFIX = 'PXE_TOOLS_WINDOWS '
WINPE_RAMDISK = {'Remote', 'Ramdisk:SourceIdentified', 'Ramdisk:SourceUnidentified'}
BOOT_FILES = {'wimboot': 'wimboot_sha256', 'BCD': 'bcd_sha256',
              'boot.sdi': 'boot_sdi_sha256', 'boot.wim': 'winpe_sha256'}


def load_json(path):
    with path.open(encoding='utf-8') as stream:
        return json.load(stream)


def check_fingerprint(expected, media):
    if not isinstance(expected, str) or re.fullmatch(r'[0-9a-f]{64}', expected) is None:
        raise ValueError(f'Invalid manifest fingerprint for {media.name}')
    if not media.is_file() or media.stat().st_size == 0:
        raise ValueError(f'Missing fixture media: {media.name}')
    with media.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise ValueError(f'Unexpected fingerprint for {media.name}')


def check_media(case, iso, winpe):
    check_fingerprint(case['iso_sha256'], iso)
    check_fingerprint(case['winpe_sha256'], winpe)


def check_boot_assets(case, directory):
    for filename, field in BOOT_FILES.items():
        asset = directory / filename
        if asset.is_symlink():
            raise ValueError(f'Boot asset must be a regular media file: {filename}')
        check_fingerprint(case[field], asset)


def verify(case, network, transcript):
    guest = str(uuid.UUID(case['guest_id']))
    disk = case['disk_serial']
    if re.fullmatch(r'[A-Za-z0-9-]{1,40}', disk) is None:
        raise ValueError('Invalid disposable disk serial')
    if (network['guest_id'] != guest or network['architecture'] != 'uefi-amd64'
            or network['efi_boot_manager_transferred'] is not True
            or network['winpe_sha256'] != case['winpe_sha256']):
        raise ValueError('Missing matching network evidence for the EFI loader and WinPE')

    receipts = []
    with transcript.open(encoding='utf-8', errors='replace') as log:
        for line in log:
            if line.startswith(PREFIX):
                payload = line.removeprefix(PREFIX)
                if len(payload) > 4096:
                    raise ValueError('Oversized Windows guest receipt')
                receipts.append(json.loads(payload))
    if [receipt.get('phase') for receipt in receipts] != ['winpe', 'windows']:
        raise ValueError('Expected one WinPE boot followed by one installed Windows boot')
    for receipt in receipts:
        if (receipt['guest_id'] != guest or receipt['disk_serial'] != disk
                or receipt['secure_boot'] is not True or receipt['tpm_spec'] != '2.0'):
            raise ValueError('Guest identity, disk serial, Secure Boot or TPM evidence differs')
    winpe, windows = receipts
    if winpe['pe_boot_type'] not in WINPE_RAMDISK or winpe['partition_style'] != 'RAW':
        raise ValueError('WinPE did not boot with the blank fixture disk')
    if (windows['partition_style'] != 'GPT' or windows['system_disk_matches'] is not True
            or windows['product_type'] != 1 or type(windows['build']) is not int
            or windows['build'] < 22000 or windows['edition'] != case['edition']):
        raise ValueError('Windows 11 did not boot on the intended GPT disk and edition')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--winpe', type=Path, required=True)
    parser.add_argument('--boot-root', type=Path, help='check the four approved assets served by Rust')
    parser.add_argument('--network-proof', type=Path)
    parser.add_argument('--serial', type=Path)
    args = parser.parse_args()
    if (args.network_proof is None) != (args.serial is None):
        parser.error('--network-proof and --serial must be provided together')
    try:
        case = load_json(args.case)
        check_media(case, args.iso, args.winpe)
        if args.boot_root is not None:
            check_boot_assets(case, args.boot_root)
        if args.serial is not None:
            verify(case, load_json(args.network_proof), args.serial)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        parser.exit(1, f'Fixture refused: {error}\n')
    print('Windows PXE deployment evidence verified' if args.serial is not None else 'Media fingerprints verified')


if __name__ == '__main__':
    main()
