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
WINPE_TFTP_FILES = {'BCD': 'boot/bcd', 'boot.sdi': 'boot/boot.sdi', 'boot.wim': 'sources/boot.wim'}
NATIVE_BOOT_FILES = {'bootmgfw.efi': 'boot_manager_sha256'} | {
    file: BOOT_FILES[original] for original, file in WINPE_TFTP_FILES.items()
}
WINDOWS_10_FIRST_BUILD = 10240
WINDOWS_11_FIRST_BUILD = 22000


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


def check_media(case, source, winpe, *, cached=False):
    if cached and (source.name not in {'install.wim', 'install.esd'} or
                   source.name != case['install_image']):
        raise ValueError('The cached installation file does not match the case manifest')
    check_fingerprint(case['install_sha256' if cached else 'iso_sha256'], source)
    check_fingerprint(case['winpe_sha256'], winpe)


def check_boot_assets(case, directory):
    chain = case.get('boot_chain', 'ipxe-wimboot')
    files = {'ipxe-wimboot': BOOT_FILES, 'native-uefi': NATIVE_BOOT_FILES}[chain]
    for filename, field in files.items():
        asset = directory / filename
        if asset.is_symlink():
            raise ValueError(f'Boot asset must be a regular media file: {filename}')
        check_fingerprint(case[field], asset)


def verify(case, network, transcript):
    guest = str(uuid.UUID(case['guest_id']))
    disk = case['disk_serial']
    identity = case.get('disk_identity', 'serial')
    patterns = {'serial': r'[A-Za-z0-9-]{1,40}', 'unique_id': r'[A-F0-9]{32}'}
    if identity not in patterns or re.fullmatch(patterns[identity], disk) is None:
        raise ValueError('Invalid disposable disk identifier')
    chain = case.get('boot_chain', 'ipxe-wimboot')
    if (chain not in {'ipxe-wimboot', 'native-uefi'} or
            network.get('boot_chain', 'ipxe-wimboot') != chain or
            network['guest_id'] != guest or network['architecture'] != 'uefi-amd64'
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
                or receipt.get('disk_identity', 'serial') != identity
                or receipt['secure_boot'] is not True or receipt['tpm_spec'] != '2.0'):
            raise ValueError('Guest identity, disk identifier, Secure Boot or TPM evidence differs')
    winpe, windows = receipts
    if winpe['pe_boot_type'] not in WINPE_RAMDISK or winpe['partition_style'] != 'RAW':
        raise ValueError('WinPE did not boot with the blank fixture disk')
    version = case.get('windows_version', 11)
    build = windows['build']
    if type(version) is not int or version not in {10, 11}:
        raise ValueError('Unsupported Windows version in the case manifest')
    if (type(build) is not int or build < WINDOWS_10_FIRST_BUILD or
            (build >= WINDOWS_11_FIRST_BUILD) != (version == 11)):
        raise ValueError(f'The installed build does not match Windows {version}')
    if (windows['partition_style'] != 'GPT' or windows['system_disk_matches'] is not True
            or windows['product_type'] != 1 or windows['edition'] != case['edition']):
        raise ValueError('Windows did not boot on the intended GPT disk and edition')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--iso', type=Path, help='approved Windows ISO')
    source.add_argument('--install-image', type=Path, help='approved install.wim or install.esd from the cache')
    parser.add_argument('--winpe', type=Path, required=True)
    parser.add_argument('--boot-root', type=Path, help='check the approved HTTP or native TFTP boot assets')
    parser.add_argument('--network-proof', type=Path)
    parser.add_argument('--serial', type=Path)
    args = parser.parse_args()
    if (args.network_proof is None) != (args.serial is None):
        parser.error('--network-proof and --serial must be provided together')
    try:
        case = load_json(args.case)
        check_media(case, args.iso or args.install_image, args.winpe, cached=args.install_image is not None)
        if args.boot_root is not None:
            check_boot_assets(case, args.boot_root)
        if args.serial is not None:
            verify(case, load_json(args.network_proof), args.serial)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        parser.exit(1, f'Fixture refused: {error}\n')
    print('Windows PXE deployment evidence verified' if args.serial is not None else 'Media fingerprints verified')


if __name__ == '__main__':
    main()
