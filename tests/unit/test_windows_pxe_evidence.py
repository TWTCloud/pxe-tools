#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1] / 'integration' / 'verify_windows_pxe_deployment.py'
spec = importlib.util.spec_from_file_location('windows_pxe_evidence', MODULE)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class WindowsEvidenceTest(unittest.TestCase):
    def test_media_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            iso = Path(directory) / 'fixture.iso'
            winpe = Path(directory) / 'boot.wim'
            image = Path(directory) / 'install.wim'
            iso.write_bytes(b'iso fixture')
            winpe.write_bytes(b'winpe fixture')
            image.write_bytes(b'install fixture')
            case = {'iso_sha256': hashlib.sha256(iso.read_bytes()).hexdigest(),
                    'winpe_sha256': hashlib.sha256(winpe.read_bytes()).hexdigest()}
            evidence.check_media(case, iso, winpe)
            cached = {**case, 'install_image': image.name,
                      'install_sha256': hashlib.sha256(image.read_bytes()).hexdigest()}
            evidence.check_media(cached, image, winpe, cached=True)
            with self.assertRaisesRegex(ValueError, 'case manifest'):
                evidence.check_media(cached, iso, winpe, cached=True)
            winpe.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                evidence.check_media(case, iso, winpe)

    def test_approved_boot_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {}
            for name, checksum in evidence.BOOT_FILES.items():
                content = name.encode()
                (root/name).write_bytes(content)
                manifest[checksum] = hashlib.sha256(content).hexdigest()
            evidence.check_boot_assets(manifest, root)
            (root/'boot.sdi').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'Unexpected fingerprint'):
                evidence.check_boot_assets(manifest, root)
            (root/'boot.sdi').unlink()
            (root/'boot.sdi').symlink_to('BCD')
            with self.assertRaisesRegex(ValueError, 'regular media file'):
                evidence.check_boot_assets(manifest, root)

            native = root / 'native'
            manifest = {'boot_chain': 'native-uefi'}
            for name, checksum in evidence.NATIVE_BOOT_FILES.items():
                content = name.encode()
                asset = native / name
                asset.parent.mkdir(parents=True, exist_ok=True)
                asset.write_bytes(content)
                manifest[checksum] = hashlib.sha256(content).hexdigest()
            evidence.check_boot_assets(manifest, native)
            (native/'bootmgfw.efi').write_bytes(b'wrong loader')
            with self.assertRaisesRegex(ValueError, 'bootmgfw.efi'):
                evidence.check_boot_assets(manifest, native)

    def test_guest_contract(self):
        guest = 'b9c4c7c8-c599-446b-b540-69915fbb9a39'
        disk = 'PXE-WIN-TEST-01'
        case = {'guest_id': guest, 'disk_serial': disk, 'edition': 'Professional', 'winpe_sha256': 'a'*64}
        network = {'guest_id': guest, 'architecture': 'uefi-amd64', 'efi_boot_manager_transferred': True,
                   'winpe_sha256': case['winpe_sha256']}
        common = {'guest_id': guest, 'disk_serial': disk, 'secure_boot': True, 'tpm_spec': '2.0'}
        winpe = {**common, 'phase': 'winpe', 'partition_style': 'RAW', 'pe_boot_type': 'Remote'}
        windows = {**common, 'phase': 'windows', 'partition_style': 'GPT', 'product_type': 1, 'build': 26100,
                   'system_disk_matches': True, 'edition': 'Professional'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'serial.log'

            def transcript(*receipts):
                path.write_text(''.join(evidence.PREFIX + json.dumps(receipt) + '\n' for receipt in receipts))

            transcript(winpe, windows)
            evidence.verify(case, network, path)
            with self.assertRaisesRegex(ValueError, 'network evidence'):
                evidence.verify(case, {**network, 'winpe_sha256': 'b'*64}, path)
            for change in ({'secure_boot': False}, {'tpm_spec': '1.2'}, {'disk_serial': 'WRONG'},
                           {'partition_style': 'MBR'}, {'system_disk_matches': False}, {'product_type': 3}):
                with self.subTest(change=change):
                    transcript(winpe, {**windows, **change})
                    with self.assertRaises(ValueError):
                        evidence.verify(case, network, path)
            transcript({**winpe, 'pe_boot_type': 'Ramdisk:OpticalDrive'}, windows)
            with self.assertRaisesRegex(ValueError, 'WinPE'):
                evidence.verify(case, network, path)
            transcript(windows, winpe)
            with self.assertRaisesRegex(ValueError, 'followed'):
                evidence.verify(case, network, path)

            windows10 = {**windows, 'build': 19045}
            transcript(winpe, windows10)
            evidence.verify({**case, 'windows_version': 10}, network, path)
            native = {**case, 'windows_version': 10, 'boot_chain': 'native-uefi'}
            evidence.verify(native, {**network, 'boot_chain': 'native-uefi'}, path)
            with self.assertRaisesRegex(ValueError, 'network evidence'):
                evidence.verify(native, network, path)
            with self.assertRaisesRegex(ValueError, 'Windows 11'):
                evidence.verify(case, network, path)

            identifier = {'disk_serial': '60022480' + 'A' * 24, 'disk_identity': 'unique_id'}
            hyperv = {**case, **identifier}
            transcript({**winpe, **identifier}, {**windows, **identifier})
            evidence.verify(hyperv, network, path)
            transcript({**winpe, **identifier},
                       {**windows, 'disk_serial': identifier['disk_serial']})
            with self.assertRaisesRegex(ValueError, 'identifier'):
                evidence.verify(hyperv, network, path)


if __name__ == '__main__':
    unittest.main()
