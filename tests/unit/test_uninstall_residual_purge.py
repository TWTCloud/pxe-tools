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

    def old_instance(self):
        self.docker_state = 'inactive'
        (self.root / 'proc').mkdir()
        for path in m.ORPHAN_TREES:
            (self.root / path.lstrip('/')).mkdir(parents=True)
        compose = self.root / 'opt/pxe-tools/compose'
        compose.mkdir()
        manifest = compose / 'docker-compose.yml'
        manifest.write_text('services:\n  pxe-tools:\n    container_name: pxe-tools\n'
                            '    volumes:\n      - /etc/pxe-tools:/etc/pxe-tools\n')
        (self.root / 'var/lib/pxe-tools').chmod(0o775)
        (self.root / 'etc/pxe-tools').chmod(0o770)
        return manifest

    def orphan_preview(self, mounts=()):
        from types import SimpleNamespace

        def runner(command, **kwargs):
            if command[0] == 'dpkg-query':
                return SimpleNamespace(returncode=0, stdout='dpkg\tinstalled\tok\n')
            state = self.docker_state if command[-1] == 'docker.service' else 'inactive'
            return SimpleNamespace(returncode=0, stdout=state)

        return m.orphan_plan(self.root, runner, mounts, owner=os.getuid(),
                             opener=self.opener, identity=self.identity)

    def test_orphan_purge_covers_old_config_payload_and_data(self):
        self.old_instance()
        outside = self.root / 'outside'
        outside.write_text('keep')
        (self.root / 'var/lib/pxe-tools/linked').symlink_to(outside)
        proofs = self.orphan_preview(('/var',))
        self.assertEqual(set(proofs), set(m.ORPHAN_TREES))
        plan = m.residual_plan(self.root, self.preview, ('/var',), owner=os.getuid(),
                               apt_config=self.config, opener=self.opener, identity=self.identity,
                               orphan=proofs)
        self.complete(self.journal(plan))
        for path in m.ORPHAN_TREES:
            self.assertFalse((self.root / path.lstrip('/')).exists())
            self.assertFalse((self.root / m.orphan_stage(path).lstrip('/')).exists())
        self.assertEqual(outside.read_text(), 'keep')

    def test_orphan_detects_unrelated_manifest_and_active_runtime(self):
        manifest = self.old_instance()
        initial = manifest.read_text()
        manifest.write_text('services:\n  other-service:\n    container_name: unrelated\n')
        self.assertEqual(self.orphan_preview(), {})
        manifest.write_text(initial)
        self.docker_state = 'active'
        with self.assertRaisesRegex(RuntimeError, 'docker.service'):
            self.orphan_preview()
        self.docker_state = 'inactive'
        process = self.root / 'proc/123'
        (process / 'fd').mkdir(parents=True)
        (process / 'comm').write_text('unrelated\n')
        (process / 'fd/4').symlink_to('/var/lib/pxe-tools/data.sqlite')
        with self.assertRaisesRegex(RuntimeError, 'PID 123'):
            self.orphan_preview()

    def test_orphan_preserves_nested_mount_and_replaced_directory(self):
        self.old_instance()
        with self.assertRaisesRegex(ValueError, 'mount within'):
            self.orphan_preview(('/var/lib/pxe-tools/data',))
        plan = {'format': 1, 'source': None, 'key': None, 'log': None,
                'orphan': self.orphan_preview()}
        journal = self.journal(plan)
        config = self.root / 'etc/pxe-tools'
        config.rename(config.with_name('original'))
        config.mkdir()
        with self.assertRaisesRegex(ValueError, 'directory changed'):
            self.complete(journal)
        self.assertTrue(config.is_dir())

    def test_orphan_resumes_after_quarantine(self):
        self.old_instance()
        plan = {'format': 1, 'source': None, 'key': None, 'log': None,
                'orphan': self.orphan_preview()}
        journal = self.journal(plan)
        with patch.object(m, '_clear_residual_directory', side_effect=OSError('interrupted')):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                self.complete(journal)
        staged = self.root / m.orphan_stage(m.ORPHAN_TREES[0]).lstrip('/') / 'tree'
        self.assertTrue(staged.is_dir())
        self.complete(m.ResidualJournal(self.root, owner=os.getuid(), opener=self.opener))
        self.assertFalse(staged.exists())
        self.assertFalse((self.root / 'opt/pxe-tools').exists())

if __name__ == '__main__':
    unittest.main()
