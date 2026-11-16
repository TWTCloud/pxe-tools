#!/usr/bin/env python3
"""Ownership and nginx journals, isolated from the real host."""
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def receipt(self):
        fd = uninstall._open_private_journal(self.root, '/var/lib/pxe-tools-nginx-ownership', os.getuid(), ())
        try:
            identities = uninstall._journal_identities(fd, os.getuid())
            digest = hashlib.sha256(uninstall._journal_bytes(fd)).hexdigest()
            # A JSON round trip changes identity tuples to lists.
            return json.loads(json.dumps(identities)), digest
        finally:
            os.close(fd)

    def resume_cleanup(self, identities, digest, *, authorized=True, dry_run=False, mounts=()):
        return uninstall.remove_private_journal_resumable(
            self.root, '/var/lib/pxe-tools-nginx-ownership', owner=os.getuid(),
            mounts=mounts, identities=identities, expected_sha256=digest,
            authorized=authorized, dry_run=dry_run)

    def test_resumable_preflight_and_idempotent_cleanup(self):
        identities, digest = self.receipt()
        self.resume_cleanup(identities, digest, dry_run=True)
        self.assertTrue(self.state.exists())
        self.assertTrue(self.lock.exists())
        self.resume_cleanup(identities, digest)
        self.assertFalse(self.journal_dir.exists())
        self.resume_cleanup(identities, digest)
        self.assertEqual(self.external.read_text(), 'keep')

    def test_resumable_interruption_accepts_only_authorized_missing_files(self):
        identities, digest = self.receipt()
        self.state.unlink()
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest, authorized=False)
        self.assertTrue(self.lock.exists())
        self.resume_cleanup(identities, digest)
        self.assertFalse(self.journal_dir.exists())
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest, authorized=False)

    def test_resumable_after_failure_between_state_and_lock_unlink(self):
        identities, digest = self.receipt()
        unlink = os.unlink
        def interrupted(path, *args, **kwargs):
            if path == 'lock':
                raise OSError('simulated interruption')
            return unlink(path, *args, **kwargs)
        with patch.object(uninstall.os, 'unlink', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.resume_cleanup(identities, digest)
        self.assertFalse(self.state.exists())
        self.assertTrue(self.lock.exists())
        self.resume_cleanup(identities, digest, dry_run=True)
        self.assertTrue(self.lock.exists())
        self.resume_cleanup(identities, digest)
        self.assertFalse(self.journal_dir.exists())

    def test_resumable_after_failure_before_directory_rmdir(self):
        identities, digest = self.receipt()
        with patch.object(uninstall.os, 'rmdir', side_effect=OSError('simulated interruption')):
            with self.assertRaises(OSError):
                self.resume_cleanup(identities, digest)
        self.assertEqual(list(self.journal_dir.iterdir()), [])
        self.resume_cleanup(identities, digest)
        self.assertFalse(self.journal_dir.exists())

    def test_resumable_rejects_changed_state_before_removing_any_file(self):
        identities, digest = self.receipt()
        self.state.write_text('modified in place')
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertEqual(self.state.read_text(), 'modified in place')
        self.assertTrue(self.lock.exists())

    def test_resumable_rejects_replaced_lock_before_removing_state(self):
        identities, digest = self.receipt()
        self.lock.rename(self.root / 'old-lock')
        self.lock.touch(mode=0o600)
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertTrue(self.state.exists())
        self.assertTrue((self.root / 'old-lock').exists())

    def test_resumable_rejects_nonempty_lock_before_removing_state(self):
        identities, digest = self.receipt()
        self.lock.write_text('unexpected')
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertTrue(self.state.exists())
        self.assertEqual(self.lock.read_text(), 'unexpected')

    def test_resumable_rejects_foreign_file_and_mount(self):
        identities, digest = self.receipt()
        (self.journal_dir / 'foreign').write_text('keep')
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertTrue(self.state.exists())
        self.assertTrue((self.journal_dir / 'foreign').exists())
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest, mounts=('/var/lib/pxe-tools-nginx-ownership',))

    def test_resumable_preserves_replaced_directory(self):
        identities, digest = self.receipt()
        self.journal_dir.rename(self.parent / 'original-journal')
        self.journal_dir.mkdir(mode=0o700)
        (self.journal_dir / 'foreign').write_text('keep')
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertEqual((self.journal_dir / 'foreign').read_text(), 'keep')
        self.assertTrue((self.parent / 'original-journal/state.json').exists())

    def test_resumable_refuses_linked_ancestor(self):
        identities, digest = self.receipt()
        (self.root / 'var').rename(self.root / 'old-var')
        (self.root / 'var').symlink_to(self.root / 'old-var', target_is_directory=True)
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.resume_cleanup(identities, digest)
        self.assertTrue((self.root / 'old-var/lib/pxe-tools-nginx-ownership/state.json').exists())

    def test_resumable_validates_receipt_even_when_directory_is_absent(self):
        identities, digest = self.receipt()
        self.resume_cleanup(identities, digest)
        for broken, wrong_digest in (({}, digest), (identities, 'not-sha256')):
            with self.subTest(broken=broken, digest=wrong_digest):
                with self.assertRaises(ValueError):
                    self.resume_cleanup(broken, wrong_digest)

    def test_resumable_rejects_hardlinked_or_symlinked_files(self):
        identities, digest = self.receipt()
        os.link(self.state, self.root / 'outside-link')
        with self.assertRaises((ValueError, RuntimeError)):
            self.resume_cleanup(identities, digest)
        self.assertTrue(self.lock.exists())
        (self.root / 'outside-link').unlink()
        self.state.unlink()
        self.state.symlink_to(self.external)
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.resume_cleanup(identities, digest)
        self.assertEqual(self.external.read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
