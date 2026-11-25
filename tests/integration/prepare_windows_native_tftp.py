#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Stage the approved Windows UEFI network loader and WinPE files for a disposable client."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from verify_windows_pxe_deployment import BOOT_FILES, WINPE_TFTP_FILES, check_fingerprint, load_json


def prepare(case, boot_root, output, mac, boot_manager_sha256):
    if output.exists() or output.is_symlink():
        raise ValueError('The TFTP bundle destination must be new')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
        raise ValueError('A colon-separated MAC address is required')
    if mac == '00:00:00:00:00:00' or int(mac[:2], 16) & 1:
        raise ValueError('A unicast client MAC address is required')

    with tempfile.TemporaryDirectory(prefix='.winpe-tftp-', dir=output.parent) as directory:
        bundle = Path(directory) / 'bundle'
        client = bundle / 'tftp' / mac.replace(':', '-')
        (client / 'boot').mkdir(parents=True)
        (client / 'sources').mkdir()
        for filename, relative in WINPE_TFTP_FILES.items():
            source = boot_root / filename
            if source.is_symlink() or not source.is_file():
                raise ValueError(f'Boot asset must be a regular media file: {filename}')
            target = client / relative
            shutil.copyfile(source, target)
            check_fingerprint(case[BOOT_FILES[filename]], target)

        loader = client / 'bootmgfw.efi'
        with loader.open('xb') as stream:
            subprocess.run([
                'wimlib-imagex', 'extract', client / 'sources/boot.wim', '1',
                '/Windows/Boot/EFI/bootmgfw.efi', '--no-globs', '--to-stdout',
            ], stdout=stream, check=True)
        check_fingerprint(boot_manager_sha256, loader)

        manifest = {**case, 'boot_chain': 'native-uefi', 'boot_manager_sha256': boot_manager_sha256}
        (bundle / 'case.json').write_text(json.dumps(manifest) + '\n', encoding='utf-8')
        bundle.rename(output)
    return output / 'tftp' / mac.replace(':', '-')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--boot-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mac', required=True)
    parser.add_argument('--boot-manager-sha256', required=True)
    args = parser.parse_args()
    try:
        case = load_json(args.case)
        client = prepare(case, args.boot_root, args.output, args.mac.lower(), args.boot_manager_sha256.lower())
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Windows TFTP bundle refused. {error}\n')
    print(client)


if __name__ == '__main__':
    main()
