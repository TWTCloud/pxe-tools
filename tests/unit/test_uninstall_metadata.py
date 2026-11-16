#!/usr/bin/env python3
"""Ownership and nginx journals, isolated from the real host."""
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('uninstall_for_metadata', ROOT / 'packaging/native/uninstall-apt.py')
uninstall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstall)


class MetadataFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-metadata-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.parent = self.root / 'var/lib'
        self.parent.mkdir(parents=True)
        self.journal_dir = self.parent / 'pxe-tools-nginx-ownership'
        self.journal_dir.mkdir(mode=0o700)
        self.state = self.journal_dir / 'state.json'
        self.lock = self.journal_dir / 'lock'
        self.lock.touch(mode=0o600)
        self.record = {'format': 1, 'service': 'nginx.service', 'phase': 'complete',
                       'before': {'active': 'active', 'enabled': 'enabled'},
                       'after': {'active': 'inactive', 'enabled': 'disabled'},
                       'resources': {'fixture': 'unchanged'}, 'identity': {'pid': '1'},
                       'provenance': {'source': 'apt-and-dpkg', 'nginx_previously_absent': True, 'start': 'fixture', 'end': None, 'core': 'pxe-tools', 'initial_packages': {'nginx': '1', 'nginx-common': '1', 'pxe-tools': '1'}}}
        self.write_record()
        self.external = self.root / 'external'
        self.external.write_text('keep')
        class Reconciler:
            def stock(self): return {'fixture': 'unchanged'}
            def state(self): return {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
        self.reconciler = Reconciler()

    def write_record(self):
        self.state.write_text(json.dumps(self.record))
        self.state.chmod(0o600)

    def guard(self, mounts=()):
        return uninstall.nginx_journal_guard(self.root, self.reconciler,
                                              owner=os.getuid(), mounts=mounts)

    def test_valid_journal_is_guarded_without_mutating_nginx_or_files(self):
        with self.guard() as journal:
            self.assertEqual(journal.record, self.record)
            self.assertTrue(self.state.exists())
        self.assertTrue(self.state.exists())
        self.assertEqual(self.external.read_text(), 'keep')

    def test_explicit_consent_does_not_authorise_automatic_restoration(self):
        self.record['provenance'] = {'source': 'explicit-stock-consent'}
        self.write_record()
        with self.assertRaises(ValueError):
            with self.guard(): pass
        self.assertTrue(self.state.exists())

    def test_incomplete_or_unproven_journal_refuses(self):
        for record in ({**self.record, 'phase': 'prepared'},
                       {**self.record, 'provenance': {'source': 'apt-and-dpkg'}},
                       {**self.record, 'format': 2}):
            with self.subTest(record=record):
                self.record = record
                self.write_record()
                with self.assertRaises(ValueError):
                    with self.guard(): pass
                self.assertTrue(self.state.exists())

    def test_changed_nginx_configuration_or_state_is_preserved(self):
        self.reconciler.stock = lambda: {'fixture': 'changed'}
        with self.assertRaises(ValueError):
            with self.guard(): pass
        self.assertTrue(self.state.exists())

    def test_unknown_files_or_mount_prevent_metadata_cleanup(self):
        (self.journal_dir / 'third-party').write_text('keep')
        with self.assertRaises(ValueError):
            with self.guard(): pass
        self.assertTrue(self.state.exists())
        self.assertTrue((self.journal_dir / 'third-party').exists())
        with self.assertRaises(ValueError):
            with self.guard(mounts=('/var/lib/pxe-tools-nginx-ownership',)): pass

    def test_changed_journal_contents_are_not_deleted(self):
        with self.guard() as journal:
            self.state.write_text('changed in place')
            self.state.chmod(0o600)
            with self.assertRaises(ValueError):
                uninstall.remove_private_journal(self.root, '/var/lib/pxe-tools-nginx-ownership',
                                                  journal.fd, owner=os.getuid(), mounts=(),
                                                  identities=journal.identities, expected_bytes=journal.contents)
        self.assertEqual(self.state.read_text(), 'changed in place')

    def test_valid_metadata_directory_can_be_removed_under_held_lock(self):
        with self.guard() as journal:
            uninstall.remove_private_journal(self.root, '/var/lib/pxe-tools-nginx-ownership',
                                              journal.fd, owner=os.getuid(), mounts=(), identities=journal.identities, expected_bytes=journal.contents)
        self.assertFalse(self.journal_dir.exists())
        self.assertEqual(self.external.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
