#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Check removal of known bytecode without touching other package files."""
import importlib.util
import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('uninstall', ROOT/'packaging/native/uninstall-apt.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture_open(parent, name):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)


class PackageCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.owner = os.geteuid()
        self.app = self.root/'usr/lib/pxe-tools/app/__pycache__'
        self.native = self.root/'usr/lib/pxe-tools/native/__pycache__'
        self.scripts = self.root/'opt/pxe-tools/scripts/__pycache__'
        for path in (self.app, self.native, self.scripts): path.mkdir(parents=True)
        for path in self.root.rglob('*'):
            if path.is_dir(): path.chmod(0o755)
        for path in (self.app/'image_delete.cpython-312.pyc',
                     self.native/'uninstall-apt.cpython-312.pyc',
                     self.native/'upgrade-lifecycle.cpython-312.pyc',
                     self.scripts/'atomic_publish.cpython-312.pyc'):
            path.write_bytes(b'bytecode')
            path.chmod(0o644)
        self.payload = self.root/'usr/lib/pxe-tools/native/upgrade-lifecycle.py'
        self.payload.write_text('package payload')

    def clean(self):
        return module.clean_package_caches(self.root, owner=self.owner, opener=fixture_open)

    def test_known_caches_are_removed_but_package_payload_remains(self):
        self.assertEqual(self.clean(), 4)
        for path in (self.app, self.native, self.scripts): self.assertFalse(path.exists())
        self.assertEqual(self.payload.read_text(), 'package payload')

    @unittest.skipUnless(sys.platform == 'linux', 'openat2 requires Linux')
    def test_linux_openat2_cleans_actual_cache_directories(self):
        self.assertEqual(module.clean_package_caches(self.root, owner=self.owner), 4)
        self.assertTrue(self.payload.exists())

    def test_unknown_file_preserves_all_caches(self):
        unknown = self.native/'custom.cpython-312.pyc'
        unknown.write_text('keep')
        with self.assertRaises(ValueError): self.clean()
        self.assertEqual(unknown.read_text(), 'keep')
        self.assertTrue((self.app/'image_delete.cpython-312.pyc').exists())

    def test_symlink_and_writable_cache_are_refused(self):
        (self.scripts/'atomic_publish.cpython-312.pyc').unlink()
        (self.scripts/'atomic_publish.cpython-312.pyc').symlink_to(self.payload)
        with self.assertRaises(ValueError): self.clean()
        self.assertEqual(self.payload.read_text(), 'package payload')
        (self.scripts/'atomic_publish.cpython-312.pyc').unlink()
        self.scripts.chmod(0o777)
        with self.assertRaises(ValueError): self.clean()

    def test_mount_boundary_failure_preserves_all_caches(self):
        def refuses_mount(parent, name):
            if name == 'scripts': raise OSError(errno.EXDEV, 'mount boundary')
            return fixture_open(parent, name)
        with self.assertRaises(OSError):
            module.clean_package_caches(self.root, owner=self.owner, opener=refuses_mount)
        self.assertTrue((self.native/'uninstall-apt.cpython-312.pyc').exists())
        self.assertTrue((self.app/'image_delete.cpython-312.pyc').exists())

    def test_package_installer_and_uninstaller_recognise_same_modules(self):
        other_spec = importlib.util.spec_from_file_location('package_cleanup', ROOT/'packaging/native/prune-package-cache.py')
        other = importlib.util.module_from_spec(other_spec)
        other_spec.loader.exec_module(other)
        installer = {'usr/lib/pxe-tools/' + key: value for key, value in other.MODULES.items()}
        installer.update({'opt/pxe-tools/' + key: value for key, value in other.OPT_MODULES.items()})
        self.assertEqual(module.PACKAGE_CACHE_MODULES, installer)


if __name__ == '__main__': unittest.main()
