# SPDX-License-Identifier: LGPL-3.0-only
import importlib.util
import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

path = Path(__file__).resolve().parents[2] / 'docker/worker/scripts/extract-grub-sbat.py'
spec = importlib.util.spec_from_file_location('extract_grub_sbat', path)
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)


class SbatDistributionTests(unittest.TestCase):
    def test_distribution_uses_the_supported_bootstrap_base(self):
        cases = [
            ({'ID': 'debian', 'VERSION_ID': '12', 'VERSION_CODENAME': 'bookworm'}, 'debian'),
            ({'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'trixie'}, 'debian'),
            ({'ID': 'ubuntu', 'VERSION_ID': '24.04', 'VERSION_CODENAME': 'noble'}, 'ubuntu'),
            ({'ID': 'ubuntu', 'VERSION_ID': '26.04', 'VERSION_CODENAME': 'resolute'}, 'ubuntu'),
            ({'ID': 'zorin', 'VERSION_ID': '18', 'VERSION': '18.1', 'ID_LIKE': 'ubuntu debian',
              'UBUNTU_CODENAME': 'noble'}, 'ubuntu'),
            ({'ID': 'example', 'ID_LIKE': 'ubuntu'}, ''),
            ({'ID': 'example', 'ID_LIKE': 'notubuntu', 'UBUNTU_CODENAME': 'noble'}, ''),
            ({'ID': 'example', 'ID_LIKE': 'ubuntu', 'UBUNTU_CODENAME': 'unknown'}, ''),
            ({'ID': 'ubuntu', 'VERSION_ID': '24.04', 'VERSION_CODENAME': 'resolute'}, ''),
            ({'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'unknown',
              'ID_LIKE': 'ubuntu', 'UBUNTU_CODENAME': 'noble'}, ''),
        ]
        for release, expected in cases:
            with self.subTest(release=release):
                self.assertEqual(extract.grub_distribution(release), expected)

    def test_signed_image_vendor_and_module_version_must_both_match(self):
        debian = [['grub.debian', '4', 'Debian', 'grub2', '2.12-9']]
        ubuntu = [['grub.ubuntu', '2', 'Ubuntu', 'grub2', '2.12-1ubuntu7.3']]
        self.assertTrue(extract.matching_sbat(debian, 'debian', '2.12-9'))
        self.assertTrue(extract.matching_sbat(ubuntu, 'ubuntu', '2.12-1ubuntu7.3'))
        self.assertFalse(extract.matching_sbat(ubuntu, 'debian', '2.12-1ubuntu7.3'))
        self.assertFalse(extract.matching_sbat(debian, 'ubuntu', '2.12-9'))
        self.assertFalse(extract.matching_sbat(ubuntu, 'ubuntu', '2.12-1ubuntu7.2'))
        self.assertFalse(extract.matching_sbat(ubuntu, 'unknown', '2.12-1ubuntu7.3'))
        self.assertFalse(extract.matching_sbat([['grub.ubuntu']], 'ubuntu', '2.12'))

    def test_main_preserves_sbat_and_still_rejects_vendor_or_version_mismatch(self):
        # The Ubuntu row is from the official noble-updates signed image
        # grub-efi-amd64-signed 1.202.5+2.12-1ubuntu7.3, not its package version.
        fixtures = [
            ('grub.ubuntu', '2.12-1ubuntu7.3',
             {'ID': 'zorin', 'ID_LIKE': 'ubuntu debian', 'UBUNTU_CODENAME': 'noble'}),
            ('grub.debian', '2.12-9',
             {'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'trixie'}),
        ]
        original_query = extract.subprocess.check_output
        for vendor, version, release in fixtures:
            sbat = ('sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n'
                    f'{vendor},2,Distribution,grub2,{version},https://example.invalid/\n')
            # A PE section fixture exercises main's actual section extraction.
            image = bytearray(512)
            image[:2] = b'MZ'
            struct.pack_into('<I', image, 0x3c, 128)
            image[128:132] = b'PE\0\0'
            struct.pack_into('<H', image, 134, 1)
            image[152:160] = b'.sbat\0\0\0'
            struct.pack_into('<II', image, 168, len(sbat.encode()) + 1, 256)
            image[256:256 + len(sbat.encode()) + 1] = sbat.encode() + b'\0'

            def query(command, **kwargs):
                if command[0] == 'dpkg-query':
                    self.assertEqual(command, ['dpkg-query', '-W', '-f=${Version}', 'grub-efi-amd64-bin'])
                    return installed_version
                return original_query(command, **kwargs)

            with tempfile.TemporaryDirectory() as directory:
                signed = Path(directory) / 'grubnetx64.efi.signed'
                signed.write_bytes(image)
                with patch.object(extract, 'SIGNED_GRUB', signed), \
                        patch.object(extract.platform, 'freedesktop_os_release', return_value=release), \
                        patch.object(extract.subprocess, 'check_output', side_effect=query):
                    installed_version = version
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        extract.main()
                    self.assertEqual(output.getvalue(), sbat)

                    installed_version = version + '.different'
                    with self.assertRaisesRegex(ValueError, 'does not match'):
                        extract.main()

                    installed_version = version
                    other = {'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'trixie'} \
                        if vendor == 'grub.ubuntu' else \
                        {'ID': 'zorin', 'ID_LIKE': 'ubuntu debian', 'UBUNTU_CODENAME': 'noble'}
                    with patch.object(extract.platform, 'freedesktop_os_release', return_value=other):
                        with self.assertRaisesRegex(ValueError, 'does not match'):
                            extract.main()


if __name__ == '__main__':
    unittest.main()
