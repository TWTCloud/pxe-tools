#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "pxe_media", ROOT / "docker/worker/scripts/prepare-pxe-media.py",
)
MEDIA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MEDIA)


class OfficialWindowsMediaTest(unittest.TestCase):
    def test_indexes_come_from_x64_edition_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            xml = stage / "wim.xml"
            xml.write_bytes("""<WIM>
                <IMAGE INDEX="2"><WINDOWS><ARCH>9</ARCH><EDITIONID>Core</EDITIONID></WINDOWS></IMAGE>
                <IMAGE INDEX="5"><WINDOWS><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID></WINDOWS></IMAGE>
                <IMAGE INDEX="6"><WINDOWS><ARCH>9</ARCH><EDITIONID>Education</EDITIONID></WINDOWS></IMAGE>
                </WIM>""".encode("utf-16"))
            with patch.object(MEDIA.subprocess, "run") as run:
                expected = [{"edition": "Core", "index": 2}, {"edition": "Professional", "index": 5}]
                self.assertEqual(MEDIA.windows_editions(stage / "install.wim", stage), expected)
                self.assertIn(f"--extract-xml={xml}", run.call_args.args[0])
                xml.write_text("<WIM><IMAGE INDEX='2'><FLAGS>Core</FLAGS></IMAGE></WIM>")
                with self.assertRaisesRegex(MEDIA.MediaError, "ambiguës"):
                    MEDIA.windows_editions(stage / "install.wim", stage)

    def test_publishes_one_boot_image_without_copying_the_install_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            library = root / "media" / "windows"
            library.mkdir(parents=True)
            stage = root / "stage"
            stage.mkdir()
            cache = root / "cache"
            cache.mkdir()
            source = root / "windows.iso"
            source.write_bytes(b"fixture iso")
            digest = MEDIA.windows.fingerprint(source)
            image = cache / "install.wim"
            image.write_bytes(b"MSWIM\0\0\0install")
            boot_loader = root / "verified-loader"
            boot_loader.write_bytes(b"fixture loader")
            metadata = {
                "path": str(image),
                "install_sha256": MEDIA.windows.fingerprint(image),
                "size": image.stat().st_size,
            }
            request = {"sha256": digest, "profile": "fr-fr", "source": "windows.iso"}

            def download(url, target, *_args, **_kwargs):
                self.assertEqual(url, MEDIA.WIMBOOT_URL)
                target.write_bytes(boot_loader.read_bytes())
                return target

            def extract_boot(_args, *, stdout, check):
                stdout.write(b"MSWIM\0\0\0boot")

            progress = []
            with (
                patch.object(MEDIA, "directory", return_value=library),
                patch.object(MEDIA, "download", side_effect=download) as fetch,
                patch.object(MEDIA.windows, "extract", return_value=metadata),
                patch.object(MEDIA, "windows_editions", return_value=[{"edition": "Core", "index": 2}]),
                patch.object(MEDIA.subprocess, "check_output", return_value="Path = sources/boot.wim\n"),
                patch.object(MEDIA.subprocess, "run", side_effect=extract_boot),
                patch.object(MEDIA, "WIMBOOT_SHA", MEDIA.windows.fingerprint(boot_loader)),
            ):
                with self.assertRaisesRegex(MEDIA.MediaError, "empreinte Microsoft"):
                    MEDIA.prepare_official_windows(
                        {**request, "sha256": "0" * 64}, root, stage, cache, progress.append, source,
                    )
                progress.clear()
                MEDIA.prepare_official_windows(request, root, stage, cache, progress.append, source)
                result = library / digest
                self.assertEqual(progress, [85, 95])
                self.assertTrue(image.samefile(result / "install.wim"))
                self.assertEqual((result / "boot.wim").read_bytes(), b"MSWIM\0\0\0boot")
                manifest = json.loads((result / "media.json").read_text())
                self.assertEqual(manifest["editions"], [{"edition": "Core", "index": 2}])
                self.assertEqual(manifest["iso_sha256"], digest)
                self.assertIn("déjà préparé", MEDIA.prepare_official_windows(request, root, stage, cache, progress.append))
                self.assertEqual(fetch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
