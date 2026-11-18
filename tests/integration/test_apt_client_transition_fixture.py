#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Test the client-certificate transition solely on disposable fixture trees."""
import hashlib
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if os.environ.get('PXE_APT_ROTATION_FIXTURE') != '1':
    raise SystemExit('Run only in the disposable APT rotation fixture')
ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(os.environ['PXE_ROTATION_FIXTURE_DIR'])
PRIMARY = os.environ['PXE_ROTATION_PRIMARY']
OLD_SIGNER = os.environ['PXE_ROTATION_OLD_SIGNER']
NEW_SIGNER = os.environ['PXE_ROTATION_NEW_SIGNER']
spec = importlib.util.spec_from_file_location('pxe_client_transition_fixture', ROOT / 'packaging/native/prepare-client-key-transition.py')
transition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transition)


class ClientTransitionFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pxe-rotation-client-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / '.pxe-rotation-fixture').write_text('PXE_TOOLS_ROTATION_DISPOSABLE\n')
        keys = self.root / 'etc/apt/keyrings'
        sources = self.root / 'etc/apt/sources.list.d'
        keys.mkdir(parents=True)
        sources.mkdir(parents=True)
        self.key = keys / 'pxe-tools-archive-keyring.gpg'
        self.old = (FIXTURE / 'old-public.gpg').read_bytes()
        self.new = FIXTURE / 'new-public.gpg'
        self.key.write_bytes(self.old)
        self.anchor = keys / ('.pxe-tools-archive-keyring.' + hashlib.sha256(self.old).hexdigest() + '.created')
        os.link(self.key, self.anchor)
        self.source = sources / 'pxe-tools.sources'
        self.source.write_text('Types: deb\nURIs: https://packages.pxetools.com/apt\nSuites: stable\n'
                               'Components: main\nArchitectures: amd64\n'
                               'Signed-By: /etc/apt/keyrings/pxe-tools-archive-keyring.gpg\n')
        os.link(self.source, sources / ('.pxe-tools-sources.' + hashlib.sha256(self.source.read_bytes()).hexdigest() + '.created'))

    def run_transition(self, *, apply=False, new=None, signer=NEW_SIGNER):
        return transition.rehearse(self.root, new or self.new, PRIMARY, OLD_SIGNER, signer, apply=apply)

    def test_preview_and_atomic_apply_preserve_original_witness(self):
        before = self.key.stat()
        report = self.run_transition()
        self.assertFalse(report['applied'])
        self.assertEqual(self.key.read_bytes(), self.old)
        self.assertEqual(self.key.stat().st_ino, before.st_ino)
        report = self.run_transition(apply=True)
        self.assertTrue(report['applied'])
        self.assertEqual(self.key.read_bytes(), self.new.read_bytes())
        self.assertEqual(self.anchor.read_bytes(), self.old)
        self.assertFalse(os.path.samefile(self.key, self.anchor))
        self.assertEqual(transition.uninstall.apt_cleanup_plan(self.root, owner=None, apt_config=transition.CONFIG), (True, False))
        with self.assertRaises(ValueError):
            self.run_transition(apply=True)
        self.assertFalse(list(self.key.parent.glob('.pxe-key-transition-*')))

    def test_shared_key_and_bad_fingerprint_refuse_without_writes(self):
        (self.source.parent / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://example.invalid stable main\n')
        with self.assertRaises(ValueError):
            self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), self.old)
        (self.source.parent / 'other.list').unlink()
        with self.assertRaises(ValueError):
            self.run_transition(apply=True, signer='0' * 40)
        self.assertEqual(self.key.read_bytes(), self.old)

    @unittest.skipUnless(shutil.which('apt-get'), 'requires a disposable Linux APT client')
    def test_updated_fixture_keyring_accepts_new_signed_repository(self):
        client = self.root / 'client'
        (client / 'parts').mkdir(parents=True)
        (client / 'status').write_text('')
        def update(label, repo):
            lists = client / ('lists-' + label)
            (lists / 'partial').mkdir(parents=True)
            source = client / (label + '.list')
            source.write_text(f'deb [signed-by={self.key}] file:{FIXTURE / repo} stable main\n')
            user = subprocess.check_output(['id', '-un'], text=True).strip()
            options = ['-o', f'APT::Sandbox::User={user}', '-o', f'Dir::Etc::sourcelist={source}',
                       '-o', f'Dir::Etc::sourceparts={client / "parts"}',
                       '-o', f'Dir::State::lists={lists}', '-o', f'Dir::State::status={client / "status"}',
                       '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
                       '-o', 'APT::Update::Error-Mode=any']
            return subprocess.run(['apt-get', *options, 'update'], capture_output=True, text=True)
        old = update('old', 'old')
        self.assertEqual(old.returncode, 0, old.stdout + old.stderr)
        stale = update('stale', 'new')
        self.assertNotEqual(stale.returncode, 0, stale.stdout + stale.stderr)
        self.run_transition(apply=True)
        updated = update('updated', 'new')
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertEqual(self.anchor.read_bytes(), self.old)

    def test_interrupted_replace_cleans_staging_and_preserves_key_and_anchor(self):
        with patch.object(transition.os, 'replace', side_effect=OSError('fixture interruption')):
            with self.assertRaisesRegex(OSError, 'fixture interruption'):
                self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), self.old)
        self.assertTrue(os.path.samefile(self.key, self.anchor))
        self.assertFalse(list(self.key.parent.glob('.pxe-key-transition-*')))

    def test_failure_after_replace_reports_uncertain_state_and_keeps_witness(self):
        real_fsync = os.fsync
        calls = 0
        def fail_on_directory(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('fixture directory flush failed')
            return real_fsync(descriptor)
        with patch.object(transition.os, 'fsync', side_effect=fail_on_directory):
            with self.assertRaisesRegex(RuntimeError, 'replaced.*durability is uncertain'):
                self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), self.new.read_bytes())
        self.assertEqual(self.anchor.read_bytes(), self.old)
        self.assertFalse(list(self.key.parent.glob('.pxe-key-transition-*')))

    def test_source_symlink_and_changed_witness_are_refused(self):
        source_content = self.source.read_bytes()
        self.source.unlink()
        outside = self.root / 'other-source'
        outside.write_bytes(source_content)
        self.source.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), self.old)
        self.source.unlink()
        self.source.write_bytes(source_content)
        self.anchor.write_bytes(b'changed witness')
        with self.assertRaises(ValueError):
            self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), b'changed witness')

    def test_only_explicitly_marked_fixture_in_tmp_is_allowed(self):
        with self.assertRaises(ValueError):
            transition.rehearse(Path('/'), self.new, PRIMARY, OLD_SIGNER, NEW_SIGNER, apply=True)
        (self.root / '.pxe-rotation-fixture').unlink()
        with self.assertRaises(ValueError):
            self.run_transition(apply=True)
        self.assertEqual(self.key.read_bytes(), self.old)


if __name__ == '__main__':
    unittest.main()
