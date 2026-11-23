#!/usr/bin/env python3
"""Exercise confirmed legacy cleanup only inside disposable directories."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('residual_purge', ROOT / 'packaging/native/uninstall-apt.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ResidualPurge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-residual-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for p in ('var/lib', 'var/log/pxe-tools', 'etc/apt/keyrings', 'etc/apt/sources.list.d'):
            (self.root / p).mkdir(parents=True, exist_ok=True)
        for p in ('var', 'var/lib', 'var/log/pxe-tools', 'etc', 'etc/apt', 'etc/apt/keyrings', 'etc/apt/sources.list.d'):
            (self.root / p).chmod(0o755)
        (self.root / 'var/log').chmod(0o775)
        (self.root / 'var/log/pxe-tools/service.log').write_text('old logs')
        self.source = self.root / m.RESIDUAL_SOURCE.lstrip('/')
        self.key = self.root / m.RESIDUAL_KEY.lstrip('/')
        self.source.write_bytes(b'Types: deb\nURIs: https://packages.pxetools.com/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/pxe-tools-archive-keyring.gpg\n')
        shutil.copyfile(ROOT / 'packaging/ci/pxe-tools-public.gpg', self.key)
        self.source.chmod(0o644)
        self.key.chmod(0o644)
        self.config = {'SOURCE': '/etc/apt/sources.list', 'PARTS': '/etc/apt/sources.list.d/', 'TRUSTED': '/etc/apt/trusted.gpg', 'TRUSTEDPARTS': '/etc/apt/trusted.gpg.d/', 'ROOT': ''}
        self.preview = {'source': False, 'key': False, 'preserved': (m.RESIDUAL_LOG,)}

    @staticmethod
    def identity(fd):
        s = os.fstat(fd)
        return {'dev': s.st_dev, 'ino': s.st_ino, 'btime_sec': 1, 'btime_nsec': 2}

    @staticmethod
    def matches(fd, proof):
        return ResidualPurge.identity(fd) == proof

    @staticmethod
    def opener(fd, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)

    def plan(self):
        return m.residual_plan(self.root, self.preview, (), owner=os.getuid(), apt_config=self.config, opener=self.opener, identity=self.identity)

    def journal(self, plan):
        j = m.ResidualJournal(self.root, owner=os.getuid(), opener=self.opener)
        j.create(plan)
        return j

    def complete(self, journal):
        return m.complete_residual_purge(journal, (), apt_config=self.config, opener=self.opener, identity_matches=self.matches)

    def test_confirmed_exact_resources_removed(self):
        plan = self.plan()
        self.assertTrue(all(plan[k] is not None for k in ('source', 'key', 'log')))
        self.complete(self.journal(plan))
        for p in (self.source, self.key, self.root / m.RESIDUAL_LOG.lstrip('/'), self.root / 'var/lib' / m.RESIDUAL_JOURNAL):
            self.assertFalse(p.exists(), p)

    def test_shared_key_is_never_included(self):
        (self.source.parent / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://example.invalid stable main\n')
        plan = self.plan()
        self.assertIsNotNone(plan['source'])
        self.assertIsNone(plan['key'])
        self.complete(self.journal(plan))
        self.assertTrue(self.key.exists())

    def test_shared_key_after_preview_is_preserved(self):
        j = self.journal(self.plan())
        (self.source.parent / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://example.invalid stable main\n')
        with self.assertRaisesRegex(ValueError, 'shared'):
            self.complete(j)
        self.assertTrue(self.key.exists())
        self.assertTrue((self.root / 'var/log/pxe-tools/service.log').exists())

    def test_changed_file_is_preserved(self):
        j = self.journal(self.plan())
        self.source.write_text('changed')
        with self.assertRaises(ValueError):
            self.complete(j)
        self.assertTrue(self.source.exists())

    def test_replaced_log_is_preserved(self):
        j = self.journal(self.plan())
        log = self.root / 'var/log/pxe-tools'
        log.rename(log.parent / 'original')
        log.mkdir()
        (log / 'someone-else').write_text('keep')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.complete(j)
        self.assertTrue((log / 'someone-else').exists())
        self.assertTrue((log.parent / 'original/service.log').exists())

    def test_resume_after_interrupted_log_clear(self):
        j = self.journal(self.plan())
        with patch.object(m, '_clear_residual_directory', side_effect=OSError('interrupted')):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                self.complete(j)
        j = m.ResidualJournal(self.root, owner=os.getuid(), opener=self.opener)
        self.complete(j)
        self.assertFalse((self.root / 'var/log/pxe-tools').exists())
        self.assertFalse((self.root / 'var/lib' / m.RESIDUAL_JOURNAL).exists())

    def test_unrecognized_key_bytes_are_removable_after_review(self):
        self.key.write_bytes(b'not the trusted key')
        plan = self.plan()
        self.assertIsNotNone(plan['key'])
        self.complete(self.journal(plan))
        self.assertFalse(self.key.exists())

    def test_key_changed_after_confirmation_is_preserved(self):
        journal = self.journal(self.plan())
        self.key.write_bytes(b'changed after confirmation')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.complete(journal)
        self.assertTrue(self.key.exists())

    def test_mounted_key_and_log_are_preserved_in_preview(self):
        plan = m.residual_plan(self.root, self.preview, (m.RESIDUAL_LOG, m.RESIDUAL_KEY), owner=os.getuid(), apt_config=self.config, opener=self.opener, identity=self.identity)
        self.assertIsNone(plan['key'])
        self.assertIsNone(plan['log'])

    @unittest.skipUnless(sys.platform == 'linux', 'Linux openat2/statx required')
    def test_real_linux_generation_and_quarantine(self):
        plan = m.residual_plan(self.root, self.preview, (), owner=os.getuid(), apt_config=self.config)
        j = m.ResidualJournal(self.root, owner=os.getuid())
        j.create(plan)
        m.complete_residual_purge(j, (), apt_config=self.config)
        self.assertFalse(self.source.exists())
        self.assertFalse(self.key.exists())
        self.assertFalse((self.root / 'var/log/pxe-tools').exists())

    def test_writable_root_group_reference_is_not_trusted_if_group_shared(self):
        from types import SimpleNamespace
        reference = self.root / 'etc/apt/sources.list'
        reference.write_text('deb https://example.invalid stable main\n')
        reference.chmod(0o664)
        # Simulate root-owned fixture metadata without touching host account databases.
        with patch.object(m.os, 'stat', wraps=m.os.stat) as mocked:
            def fake_stat(path, *args, **kwargs):
                info = mocked._mock_wraps(path, *args, **kwargs)
                values = list(info); values[4] = 0; values[5] = 0
                return os.stat_result(values)
            mocked.side_effect = fake_stat
            with patch('grp.getgrgid', return_value=SimpleNamespace(gr_name='root', gr_mem=['someone'])):
                source, key = m.apt_cleanup_plan(self.root, owner=0, apt_config=self.config, allow_reviewed=True)
        self.assertFalse(key)

if __name__ == '__main__':
    unittest.main()
