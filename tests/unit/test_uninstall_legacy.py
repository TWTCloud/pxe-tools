#!/usr/bin/env python3
"""Legacy identity snapshots are explicit consent, never creation provenance."""
import importlib.util
import os
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest

script = Path(__file__).resolve().parents[2] / 'packaging/native/uninstall-apt.py'
spec = importlib.util.spec_from_file_location('uninstall_legacy', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LegacySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-legacy-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / 'var/lib/pxe-tools'
        self.data.mkdir(parents=True)
        (self.data / 'data').write_text('must survive preview')
        (self.root / 'etc/pxe-tools').mkdir(parents=True)
        self.outside = self.root / 'var/lib/other'
        self.outside.mkdir()
        (self.outside / 'data').write_text('external')

    @staticmethod
    def opener(parent, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)

    @staticmethod
    def identity(fd):
        st = os.fstat(fd)
        return {'dev': st.st_dev, 'ino': st.st_ino, 'btime_sec': 123, 'btime_nsec': 456}

    def test_preview_snapshots_only_allowlisted_paths_without_mutating_data(self):
        plan = module.snapshot_legacy_paths(self.root, mounts=(), owner=None,
                                            opener=self.opener, identity=self.identity)
        self.assertEqual(plan['source'], 'explicit-legacy-consent')
        self.assertEqual(set(plan['directories']), {'/etc/pxe-tools', '/var/lib/pxe-tools'})
        self.assertEqual((self.data / 'data').read_text(), 'must survive preview')
        self.assertEqual((self.outside / 'data').read_text(), 'external')

    def test_legacy_account_is_preserved_and_shared_or_active_account_is_refused(self):
        account = SimpleNamespace(pw_name='pxe-tools-ansible', pw_uid=997, pw_gid=997,
                                  pw_dir='/var/lib/pxe-tools-ansible/home', pw_shell='/usr/sbin/nologin')
        group = SimpleNamespace(gr_name='pxe-tools-ansible', gr_gid=997, gr_mem=[])
        module.validate_legacy_account([account], [group], set())
        with self.assertRaisesRegex(ValueError, 'in use'):
            module.validate_legacy_account([account], [group], {997})
        group.gr_mem.append('other-user')
        with self.assertRaisesRegex(ValueError, 'shared'):
            module.validate_legacy_account([account], [group], set())

    def test_group_writable_log_parent_is_preserved_and_reported(self):
        parent = self.root / 'var/log'
        parent.mkdir(parents=True)
        parent.chmod(0o775)
        log = parent / 'pxe-tools'
        log.mkdir()
        (log / 'keep').write_text('do not touch')
        plan = module.snapshot_legacy_paths(self.root, mounts=(), owner=os.getuid(),
                                            opener=self.opener, identity=self.identity)
        self.assertEqual(plan['preserved'], ['/var/log/pxe-tools'])
        self.assertNotIn('/var/log/pxe-tools', plan['directories'])
        self.assertEqual((log / 'keep').read_text(), 'do not touch')

    def test_mount_and_symlink_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'mount'):
            module.snapshot_legacy_paths(self.root, mounts=('/var/lib/pxe-tools/mounted',), owner=None,
                                         opener=self.opener, identity=self.identity)
        self.data.rename(self.root / 'var/lib/moved')
        self.data.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            module.snapshot_legacy_paths(self.root, mounts=(), owner=None,
                                         opener=self.opener, identity=self.identity)
        self.assertEqual((self.outside / 'data').read_text(), 'external')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux statx and openat2 required')
    def test_real_kernel_identity_changes_when_directory_is_replaced(self):
        plan = module.snapshot_legacy_paths(self.root, mounts=(), owner=os.getuid())
        proof = plan['directories']['/var/lib/pxe-tools']
        fd = os.open(self.data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.assertTrue(module.legacy_identity_matches(fd, proof))
        finally:
            os.close(fd)
        self.data.rename(self.root / 'var/lib/original-data')
        self.data.mkdir()
        fd = os.open(self.data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.assertFalse(module.legacy_identity_matches(fd, proof))
        finally:
            os.close(fd)

    def test_explicit_preview_digest_cannot_be_used_with_resume_or_without_confirmation(self):
        digest = 'a' * 64
        for args in (['--allow-legacy', '--legacy-plan-sha256', digest],
                     ['--yes', '--legacy-plan-sha256', digest],
                     ['--resume', '--allow-legacy'],
                     ['--yes', '--allow-legacy', '--legacy-plan-sha256', 'bad']):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                module.parse_arguments(args)
        args = module.parse_arguments(['--yes', '--allow-legacy', '--legacy-plan-sha256', digest])
        self.assertEqual(args.legacy_plan_sha256, digest)


if __name__ == '__main__':
    unittest.main()
