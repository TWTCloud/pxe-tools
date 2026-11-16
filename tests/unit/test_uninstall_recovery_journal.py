"""Fixture-only tests for an explicitly non-integrable journal prototype."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name('uninstall_recovery_journal_prototype.py')
spec = importlib.util.spec_from_file_location('journal_prototype', MODULE)
journal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run/lock').mkdir(parents=True)
        (self.root / 'var/lib').mkdir(parents=True)
        self.store = journal.Journal(self.root)
        self.folder = self.root / 'var/lib/pxe-tools-uninstall'
        self.state = self.folder / 'state.json'
        self.lock = self.root / 'run/lock/pxe-tools-uninstall.lock'
        self.plan = {'trees': ['/var/lib/pxe-tools']}

    def create(self):
        with self.store.hold_lock() as lock:
            return self.store.create(self.plan, lock)

    def test_roundtrip_modes_and_strict_transitions(self):
        with self.store.hold_lock() as lock:
            result = self.store.create(self.plan, lock)
            self.assertEqual(result['phase'], 'planned')
            self.assertEqual(self.store.read(lock), result)
            self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.lock.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                self.store.advance('planned', 'finished', lock)
            self.assertEqual(self.store.advance('planned', 'quiesced', lock)['phase'], 'quiesced')
            with self.assertRaises(ValueError):
                self.store.advance('planned', 'quiesced', lock)
        self.assertTrue(self.lock.is_file())

    def test_prototype_cannot_use_host_root(self):
        with self.assertRaises(ValueError):
            journal.Journal('/')

    def test_plan_is_closed_and_no_secret_is_written(self):
        for plan in ({'trees': ['/etc/shadow']}, {'trees': ['/var/lib/pxe-tools'], 'secret': 'password'},
                     {'trees': ['/var/lib/pxe-tools'] * 2}, {'trees': 'bad'}):
            with self.subTest(plan=plan), self.store.hold_lock() as lock:
                with self.assertRaises(ValueError):
                    self.store.create(plan, lock)
                self.assertFalse(self.folder.exists())

    def test_unlocked_operations_are_rejected(self):
        with tempfile.TemporaryFile() as other:
            with self.assertRaises(ValueError):
                self.store.create(self.plan, other.fileno())
        self.assertFalse(self.folder.exists())

    def test_foreign_and_corrupt_files_fail_closed(self):
        self.create()
        original = self.state.read_bytes()
        with self.store.hold_lock() as lock:
            for payload in (b'{', b'{"version":1,"version":1}', b'NaN', b'\xff', b'{}', b'x' * 65537):
                with self.subTest(payload=payload[:20]):
                    self.state.write_bytes(payload)
                    with self.assertRaises((ValueError, OSError)):
                        self.store.read(lock)
            self.state.write_bytes(original)
            foreign = self.folder / 'unexpected'
            foreign.write_text('keep')
            with self.assertRaises(ValueError):
                self.store.read(lock)
            self.assertEqual(foreign.read_text(), 'keep')

    def test_symlinks_hardlinks_and_unsafe_permissions_rejected(self):
        target = self.root / 'target'
        target.write_text('keep')
        self.lock.symlink_to(target)
        with self.assertRaises(OSError):
            with self.store.hold_lock():
                pass
        self.lock.unlink()
        self.create()
        self.state.unlink()
        self.state.symlink_to(target)
        with self.store.hold_lock() as lock:
            with self.assertRaises((ValueError, OSError)):
                self.store.read(lock)
        self.assertEqual(target.read_text(), 'keep')
        self.state.unlink()
        self.state.write_text('{}')
        os.link(self.state, self.folder / 'hardlink')
        with self.store.hold_lock() as lock:
            with self.assertRaises(ValueError):
                self.store.read(lock)
        (self.folder / 'hardlink').unlink()
        self.folder.chmod(0o755)
        with self.store.hold_lock() as lock:
            with self.assertRaises(ValueError):
                self.store.read(lock)

    def test_crash_before_replace_preserves_old_state_and_temporary(self):
        self.create()
        with self.store.hold_lock() as lock:
            previous = self.state.read_bytes()
            with patch.object(journal.os, 'replace', side_effect=OSError('crash')):
                with self.assertRaises(OSError):
                    self.store.advance('planned', 'quiesced', lock)
            self.assertEqual(self.state.read_bytes(), previous)
            self.assertTrue(any(p.name.startswith('.state-') for p in self.folder.iterdir()))
            with self.assertRaises(ValueError):
                self.store.read(lock)

    def test_crash_after_replace_exposes_only_the_new_valid_state(self):
        self.create()
        replace = os.replace
        def interrupted(*args, **kwargs):
            replace(*args, **kwargs)
            raise OSError('interrupted after rename')
        with self.store.hold_lock() as lock:
            with patch.object(journal.os, 'replace', side_effect=interrupted):
                with self.assertRaises(OSError):
                    self.store.advance('planned', 'quiesced', lock)
            self.assertEqual(self.store.read(lock)['phase'], 'quiesced')

    def test_symlink_and_unsafe_parent_are_refused(self):
        (self.root / 'var/lib').rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'var/lib').symlink_to(outside, target_is_directory=True)
        with self.store.hold_lock() as lock:
            with self.assertRaises(OSError):
                self.store.create(self.plan, lock)
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'var/lib').unlink()
        (self.root / 'var/lib').mkdir(mode=0o777)
        (self.root / 'var/lib').chmod(0o777)
        with self.store.hold_lock() as lock:
            with self.assertRaises(ValueError):
                self.store.create(self.plan, lock)

    def test_competing_process_cannot_acquire_stable_lock(self):
        command = [sys.executable, '-c', '''
import importlib.util, sys
s=importlib.util.spec_from_file_location('p', sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
try:
    with m.Journal(sys.argv[2]).hold_lock(): pass
except BlockingIOError:
    sys.exit(23)
''', str(MODULE), str(self.root)]
        with self.store.hold_lock():
            self.assertEqual(subprocess.run(command, check=False).returncode, 23)
        self.assertEqual(subprocess.run(command, check=False).returncode, 0)


if __name__ == '__main__':
    unittest.main()
