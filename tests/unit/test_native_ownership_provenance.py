#!/usr/bin/env python3
"""Ownership proofs are created and checked exclusively in temporary trees."""
import importlib.util
import json
import shutil
import subprocess
import sys
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'packaging/native/ownership-provenance.py'
if PATH.exists():
    spec = importlib.util.spec_from_file_location('native_ownership_provenance', PATH)
    ownership = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ownership)
else:
    ownership = None


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pxe-generation-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'owned'
        self.directory.mkdir()
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.birth = (1700000000, 123456789)
        self.xattrs = {}
        def statx(fd):
            item = os.fstat(fd)
            return {'dev': item.st_dev, 'ino': item.st_ino,
                    'btime_sec': self.birth[0], 'btime_nsec': self.birth[1]}
        def setxattr(fd, name, value, flags):
            if (fd, name) in self.xattrs:
                raise OSError('already exists')
            self.xattrs[(fd, name)] = value
        def getxattr(fd, name):
            return self.xattrs[(fd, name)]
        self.generation = ownership.Generation(statx=statx, setxattr=setxattr, getxattr=getxattr)

    def test_linux_statx_requires_birthtime_mask_and_reads_fd(self):
        import ctypes
        import struct
        raw = bytearray(256)
        struct.pack_into('=I', raw, 0, 0x100)  # inode available; btime unavailable
        struct.pack_into('=Q', raw, 32, 42)
        struct.pack_into('=qI', raw, 80, 1700000000, 123456789)
        struct.pack_into('=II', raw, 136, 8, 1)
        class Call:
            def __call__(self, fd, path, flags, mask, output):
                self.args = fd, path, flags, mask
                ctypes.memmove(output, bytes(raw), 256)
                return 0
        call = Call()
        with patch('sys.platform', 'linux'), patch('ctypes.CDLL', return_value=SimpleNamespace(statx=call)):
            self.assertIsNone(ownership._linux_statx(self.fd))
            struct.pack_into('=I', raw, 0, 0x900)
            observed = ownership._linux_statx(self.fd)
        self.assertEqual(call.args, (self.fd, b'', 0x1000, 0x900))
        self.assertEqual(observed, {'dev': os.makedev(8, 1), 'ino': 42,
                                    'btime_sec': 1700000000, 'btime_nsec': 123456789})

    def test_strong_proof_requires_matching_birthtime_and_private_xattr(self):
        proof = self.generation.capture(self.fd)
        self.assertEqual(proof['btime_sec'], self.birth[0])
        self.assertEqual(proof['btime_nsec'], self.birth[1])
        self.assertRegex(proof['nonce'], r'^[0-9a-f]{64}$')
        self.assertTrue(self.generation.matches(self.fd, proof))
        # Simulate inode reuse with identical dev/ino but a different btime.
        self.birth = (self.birth[0], self.birth[1] + 1)
        self.assertFalse(self.generation.matches(self.fd, proof))

    def test_nonce_replacement_refuses_even_when_inode_and_birthtime_match(self):
        proof = self.generation.capture(self.fd)
        self.xattrs[(self.fd, ownership.XATTR_NAME)] = b'other'
        self.assertFalse(self.generation.matches(self.fd, proof))

    def test_unavailable_statx_never_makes_a_strong_proof(self):
        unavailable = ownership.Generation(statx=lambda fd: None,
                                           setxattr=lambda *args, **kwargs: self.fail('no xattr needed'),
                                           getxattr=lambda *args, **kwargs: None)
        proof = unavailable.capture(self.fd)
        self.assertIsNone(proof['btime_sec'])
        self.assertIsNone(proof['btime_nsec'])
        self.assertIsNone(proof['nonce'])
        self.assertFalse(unavailable.matches(self.fd, proof))

    def test_unavailable_xattr_never_makes_a_strong_proof(self):
        def no_xattr(*args, **kwargs):
            raise OSError('not supported')
        unavailable = ownership.Generation(statx=self.generation.statx, setxattr=no_xattr,
                                           getxattr=no_xattr)
        proof = unavailable.capture(self.fd)
        self.assertIsNone(proof['btime_sec'])
        self.assertIsNone(proof['btime_nsec'])
        self.assertIsNone(proof['nonce'])
        self.assertFalse(unavailable.matches(self.fd, proof))

    def test_statx_mismatched_inode_never_makes_a_strong_proof(self):
        item = os.fstat(self.fd)
        generation = ownership.Generation(statx=lambda fd: {'dev': item.st_dev, 'ino': item.st_ino + 1,
                                   'btime_sec': 1, 'btime_nsec': 2},
                                   setxattr=lambda *args, **kwargs: self.fail('no xattr needed'),
                                   getxattr=lambda *args, **kwargs: None)
        self.assertIsNone(generation.capture(self.fd)['nonce'])



class FixtureGeneration(ownership.Generation):
    def __init__(self):
        self.xattrs = {}
        self.birth = {}
        def key(fd):
            info = os.fstat(fd)
            return info.st_dev, info.st_ino
        def statx(fd):
            dev, ino = key(fd)
            sec, nsec = self.birth.setdefault((dev, ino), (1700000000, 123456789))
            return {'dev': dev, 'ino': ino, 'btime_sec': sec, 'btime_nsec': nsec}
        def setxattr(fd, name, value, flags):
            item = (*key(fd), name)
            if item in self.xattrs:
                raise OSError('already exists')
            self.xattrs[item] = value
        def getxattr(fd, name):
            return self.xattrs[(*key(fd), name)]
        super().__init__(statx=statx, setxattr=setxattr, getxattr=getxattr)


class OwnershipFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pxe-ownership-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.generation = FixtureGeneration()
        for path in ('etc', 'var/lib', 'var/log', 'run/lock'):
            (self.root / path).mkdir(parents=True, exist_ok=True)

    def store(self):
        self.assertIsNotNone(ownership, 'ownership helper missing')
        return ownership.Store(self.root, owner=os.geteuid(), generation=self.generation)

    def test_stable_lock_is_not_followed_if_symlinked(self):
        lock = self.root / 'run/lock/pxe-tools-ownership.lock'
        outside = self.root / 'outside-lock'
        outside.write_text('preserve')
        lock.symlink_to(outside)
        with self.assertRaises((OSError, ValueError)):
            with self.store().hold_lock():
                pass
        self.assertEqual(outside.read_text(), 'preserve')

    def test_stable_lock_serializes_two_processes(self):
        store = self.store()
        child = ('import importlib.util,sys; from pathlib import Path; '
                 's=importlib.util.spec_from_file_location("owner_child", sys.argv[1]); '
                 'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
                 'm.Store(Path(sys.argv[2]), owner=int(sys.argv[3])).hold_lock().__enter__()')
        with store.hold_lock():
            result = subprocess.run([sys.executable, '-c', child, str(PATH), str(self.root), str(os.geteuid())],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('BlockingIOError', result.stderr)
        with store.hold_lock():
            self.assertTrue((self.root / 'run/lock/pxe-tools-ownership.lock').is_file())

    def test_external_lock_fd_is_verified_before_accessing_journal(self):
        store = self.store()
        store.create_base()
        with store.hold_lock() as locked:
            with store._locked(create=False, stable_fd=locked) as journal:
                self.assertEqual(store._read(journal)['format'], 2)
            other = os.open(self.root / 'outside', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with self.assertRaises((ValueError, OSError)):
                    with store._locked(create=False, stable_fd=other):
                        pass
            finally:
                os.close(other)

    def test_reading_absent_journal_creates_nothing(self):
        with self.assertRaises(FileNotFoundError):
            self.store().read()
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())

    def test_fresh_directories_have_pinned_inodes(self):
        store = self.store()
        store.create_base()
        record = store.read()
        self.assertEqual(record['format'], 2)
        self.assertEqual(record['base_phase'], 'prepared')
        for path in ('/etc/pxe-tools', '/var/lib/pxe-tools'):
            info = (self.root / path.lstrip('/')).stat()
            self.assertEqual((record['directories'][path]['dev'], record['directories'][path]['ino']),
                             (info.st_dev, info.st_ino))
            self.assertRegex(record['directories'][path]['nonce'], r'^[0-9a-f]{64}$')
        self.assertNotIn('account', record)
        self.assertNotIn('/var/log/pxe-tools', record['directories'])
        self.assertEqual((self.root / 'var/lib/pxe-tools-ownership').stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / 'var/lib/pxe-tools-ownership/state.json').stat().st_mode & 0o777, 0o600)

    def test_legacy_v1_journal_is_read_but_not_promoted(self):
        store = self.store()
        with store._locked() as fd:
            store._write(fd, {'format': 1, 'directories': {}})
        record = store.read()
        self.assertEqual(record['format'], 1)
        self.assertEqual(record['directories'], {})

    def test_v2_missing_generation_is_explicitly_weak(self):
        def unavailable(fd): return None
        generation = ownership.Generation(statx=unavailable)
        store = ownership.Store(self.root, owner=os.geteuid(), generation=generation)
        store.create_base()
        proof = store.read()['directories']['/etc/pxe-tools']
        self.assertIsNone(proof['btime_sec'])
        self.assertIsNone(proof['btime_nsec'])
        self.assertIsNone(proof['nonce'])

    def test_weak_proof_finishes_only_with_creation_fds_held(self):
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        store.create_base(activate=lambda: None)
        self.assertEqual(store.read()['base_phase'], 'complete')
        self.assertIsNone(store.read()['directories']['/etc/pxe-tools']['nonce'])

    def test_enable_failure_still_finishes_provenance_with_pinned_fds(self):
        import io
        from contextlib import redirect_stderr
        runtime_spec = importlib.util.spec_from_file_location('secure_runtime_failed_enable',
                                                              ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(runtime_spec)
        runtime_spec.loader.exec_module(runtime)
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=1)
        with redirect_stderr(io.StringIO()):
            store.create_base(activate=lambda: runtime.activate_admin(runner))
        self.assertEqual(store.read()['base_phase'], 'complete')
        self.assertEqual(len(calls), 1)
        self.assertIsNone(store.read()['directories']['/etc/pxe-tools']['nonce'])

    def test_weak_proof_cannot_complete_after_creation_fds_are_closed(self):
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        store.create_base()
        with self.assertRaises(ValueError):
            store.finish_base()
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_weak_directory_replacement_during_activation_is_refused(self):
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        def replace_etc():
            path = self.root / 'etc/pxe-tools'
            path.rename(self.root / 'etc/original')
            path.mkdir()
        with self.assertRaises(ValueError):
            store.create_base(activate=replace_etc)
        self.assertEqual(store.read()['base_phase'], 'prepared')
        self.assertTrue((self.root / 'etc/original').is_dir())

    def test_same_inode_different_birthtime_is_not_same_proof(self):
        store = self.store()
        store.create_base()
        original = store.read()['directories']['/etc/pxe-tools']
        path = self.root / 'etc/pxe-tools'
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.assertTrue(self.generation.matches(fd, original))
            self.generation.birth[(original['dev'], original['ino'])] = (original['btime_sec'], original['btime_nsec'] + 1)
            self.assertFalse(self.generation.matches(fd, original))
        finally:
            os.close(fd)

    def test_check_base_does_not_follow_linked_ancestor_even_without_marker(self):
        lib = self.root / 'var/lib'
        lib.rename(self.root / 'var/lib-original')
        external = self.root / 'external'
        external.mkdir()
        lib.symlink_to(external, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            self.store().check_base()
        self.assertFalse((external / 'pxe-tools-ownership').exists())

    def test_incomplete_first_start_refuses_retry_until_explicit_recovery(self):
        store = self.store()
        store.check_base()
        store.create_base()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            store.check_base()
        store.finish_base()
        self.assertEqual(store.read()['base_phase'], 'complete')
        store.check_base()

    def test_replaced_directory_cannot_complete_the_base_proof(self):
        store = self.store()
        store.create_base()
        original = self.root / 'etc/pxe-tools'
        original.rename(self.root / 'etc/pxe-tools-old')
        original.mkdir()
        with self.assertRaises(ValueError):
            store.finish_base()
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_real_runtime_helper_journals_in_fixture_without_privileges(self):
        spec = importlib.util.spec_from_file_location('secure_runtime_unprivileged_fixture',
                                                     ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root / 'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        self.assertEqual(store.read()['base_phase'], 'runtime-prepared')
        self.assertEqual(set(store.read()['directories']), ownership.NATIVE_DIRECTORIES)
        store.create_base(require_runtime=True)
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_weak_runtime_and_base_proofs_allow_setup_while_all_fds_are_pinned(self):
        spec = importlib.util.spec_from_file_location('secure_runtime_weak_fixture',
                                                     ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        def initialize(held):
            store.create_base(require_runtime=True, native_fds=held, activate=lambda: None)
        runtime.prepare(base=self.root / 'var/lib', root=self.root, owner=os.geteuid(),
                        journal=store, after_create=initialize)
        record = store.read()
        self.assertEqual(record['base_phase'], 'complete')
        self.assertTrue(all(item['nonce'] is None for item in record['directories'].values()))

    def test_runtime_replacement_during_activation_is_refused_even_with_weak_proof(self):
        spec = importlib.util.spec_from_file_location('secure_runtime_replaced_fixture',
                                                     ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        store = ownership.Store(self.root, owner=os.geteuid(),
                                generation=ownership.Generation(statx=lambda fd: None))
        def replace_tftp():
            target = self.root / 'var/lib/pxe-tools-tftp'
            target.rename(self.root / 'var/lib/old-tftp')
            target.mkdir()
        def initialize(held):
            store.create_base(require_runtime=True, native_fds=held, activate=replace_tftp)
        with self.assertRaises(ValueError):
            runtime.prepare(base=self.root / 'var/lib', root=self.root, owner=os.geteuid(),
                            journal=store, after_create=initialize)
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_real_runtime_interruption_leaves_incomplete_proof(self):
        spec = importlib.util.spec_from_file_location('secure_runtime_unprivileged_failure',
                                                     ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        store = self.store()
        original = store.record_runtime_created
        def fail_second(path, fd):
            if path.endswith('-tftp'):
                raise OSError('fixture failure')
            original(path, fd)
        store.record_runtime_created = fail_second
        with self.assertRaises(OSError):
            runtime.prepare(base=self.root / 'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        self.assertEqual(store.read()['base_phase'], 'runtime-preparing')
        self.assertNotIn('/var/lib/pxe-tools-tftp', store.read()['directories'])
        with self.assertRaises(ValueError):
            store.check_base()

    def test_runtime_proof_records_the_exact_opened_directories(self):
        store = self.store()
        store.begin_runtime()
        base = self.root / 'var/lib'
        for name in ('pxe-tools-native', 'pxe-tools-tftp', 'pxe-tools-http'):
            path = base / name
            path.mkdir()
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                store.record_runtime_created('/var/lib/' + name, fd)
            finally:
                os.close(fd)
        (base / 'pxe-tools-native/runtime.env').write_bytes(ownership.RUNTIME_MARKER)
        store.finish_runtime()
        record = store.read()
        self.assertEqual(record['base_phase'], 'runtime-prepared')
        self.assertEqual(set(record['directories']), {'/var/lib/pxe-tools-native',
                                                      '/var/lib/pxe-tools-tftp', '/var/lib/pxe-tools-http'})
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            store.check_base()
        store.create_base(require_runtime=True)
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_runtime_phase_cannot_claim_instance_or_account_paths(self):
        invalid = {'format': 1, 'base_phase': 'runtime-preparing',
                   'directories': {'/etc/pxe-tools': {'dev': 1, 'ino': 2}}}
        with self.assertRaises(ValueError):
            ownership.validate(invalid)

    def test_runtime_record_refuses_replaced_path_and_retry_cannot_adopt(self):
        store = self.store()
        store.begin_runtime()
        path = self.root / 'var/lib/pxe-tools-tftp'
        path.mkdir()
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            path.rename(self.root / 'var/lib/other')
            path.mkdir()
            with self.assertRaises(ValueError):
                store.record_runtime_created('/var/lib/pxe-tools-tftp', fd)
        finally:
            os.close(fd)
        self.assertEqual(store.read()['directories'], {})
        with self.assertRaises((ValueError, FileExistsError)):
            store.begin_runtime()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            store.check_base()

    def test_base_production_action_refuses_absent_runtime_proof(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.store().create_base(require_runtime=True)
        self.assertFalse((self.root / 'etc/pxe-tools').exists())

    def test_existing_logs_never_acquire_ownership(self):
        logs = self.root / 'var/log/pxe-tools'
        logs.mkdir()
        (logs / 'outside').write_text('keep')
        store = self.store()
        store.create_base()
        self.assertNotIn('/var/log/pxe-tools', store.read()['directories'])
        self.assertEqual((logs / 'outside').read_text(), 'keep')

    def test_group_writable_system_log_parent_is_not_used_for_creation(self):
        log_parent = self.root / 'var/log'
        log_parent.chmod(0o775)
        logs = log_parent / 'pxe-tools'; logs.mkdir()
        witness = logs / 'outside'; witness.write_text('keep')
        store = self.store()
        store.create_base()
        self.assertNotIn('/var/log/pxe-tools', store.read()['directories'])
        self.assertEqual(witness.read_text(), 'keep')
        self.assertEqual(log_parent.stat().st_mode & 0o777, 0o775)

    def test_first_native_install_with_group_writable_system_log_parent(self):
        spec = importlib.util.spec_from_file_location('secure_runtime_group_writable_log',
                                                     ROOT / 'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        log_parent = self.root/'var/log'; log_parent.chmod(0o775)
        existing = log_parent/'pxe-tools'; existing.mkdir()
        witness = existing/'old.log'; witness.write_text('keep')
        store = self.store()
        def initialize(held):
            store.create_base(require_runtime=True, native_fds=held, activate=lambda: None)
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(),
                        journal=store, after_create=initialize)
        self.assertEqual(store.read()['base_phase'], 'complete')
        self.assertEqual(witness.read_text(), 'keep')
        self.assertEqual(log_parent.stat().st_mode & 0o777, 0o775)

    def test_resume_missing_runtime_creates_new_proofs_without_adopting_data(self):
        spec = importlib.util.spec_from_file_location('resume_runtime_fixture', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        for name in ('pxe-tools-http', 'pxe-tools-tftp'):
            directory = self.root/'var/lib'/name
            info = directory.stat(); directory.rmdir()
            # The fake xattr store must discard attributes when an inode dies.
            self.generation.xattrs.pop((info.st_dev, info.st_ino, ownership.XATTR_NAME), None)
            self.generation.birth.pop((info.st_dev, info.st_ino), None)
        self.assertEqual(set(store.resume_missing_runtime(mounts=[])), {'/var/lib/pxe-tools-http', '/var/lib/pxe-tools-tftp'})
        store.create_base(require_runtime=True, activate=lambda: None)
        self.assertEqual(store.read()['base_phase'], 'complete')

    def test_recover_initialization_retries_until_base_is_finalized(self):
        spec = importlib.util.spec_from_file_location('automatic_runtime_recovery', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        self.assertFalse(store.recover_initialization())
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        for name in ('pxe-tools-http', 'pxe-tools-tftp'):
            directory = self.root/'var/lib'/name
            info = directory.stat(); directory.rmdir()
            self.generation.xattrs.pop((info.st_dev, info.st_ino, ownership.XATTR_NAME), None)
            self.generation.birth.pop((info.st_dev, info.st_ino), None)
        with patch.object(store, 'resume_missing_runtime', wraps=lambda: ownership.Store.resume_missing_runtime(store, mounts=[])):
            self.assertTrue(store.recover_initialization())
        self.assertEqual(store.read()['base_phase'], 'prepared')
        self.assertTrue(store.recover_initialization())
        self.assertEqual(store.read()['base_phase'], 'prepared')
        store.finish_base()
        self.assertFalse(store.recover_initialization())
        self.assertEqual(store.read()['base_phase'], 'complete')

    def test_recovery_refuses_replaced_prepared_base(self):
        spec = importlib.util.spec_from_file_location('prepared_runtime_recovery', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        store.create_base(require_runtime=True)
        target = self.root/'etc/pxe-tools'
        target.rename(self.root/'etc/pxe-tools-old'); target.mkdir()
        with self.assertRaises(ValueError): store.recover_initialization()
        self.assertEqual(store.read()['base_phase'], 'prepared')

    def test_resume_missing_runtime_rejects_changed_native_content(self):
        spec = importlib.util.spec_from_file_location('resume_runtime_changed', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        missing = self.root/'var/lib/pxe-tools-http'; missing.rmdir()
        witness = self.root/'var/lib/pxe-tools-native/unknown'; witness.write_text('keep')
        with self.assertRaises(ValueError): store.resume_missing_runtime(mounts=[])
        self.assertEqual(witness.read_text(), 'keep')
        self.assertFalse(missing.exists())
        self.assertEqual(store.read()['base_phase'], 'runtime-prepared')

    def test_resume_missing_runtime_rejects_mount_and_replaced_directory(self):
        spec = importlib.util.spec_from_file_location('resume_runtime_replaced', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        http = self.root/'var/lib/pxe-tools-http'; http.rmdir()
        tftp = self.root/'var/lib/pxe-tools-tftp'
        with self.assertRaisesRegex(ValueError, 'mount'):
            store.resume_missing_runtime(mounts=[str(tftp/'nested')])
        self.assertFalse(http.exists())
        tftp.rename(self.root/'var/lib/old-tftp'); tftp.mkdir()
        with self.assertRaisesRegex(ValueError, 'generation'):
            store.resume_missing_runtime(mounts=[])
        self.assertFalse(http.exists())

    def test_resume_does_not_adopt_unrecorded_directory_after_write_failure(self):
        spec = importlib.util.spec_from_file_location('resume_runtime_failed_write', ROOT/'packaging/native/configure-secure-tftp.py')
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        store = self.store()
        runtime.prepare(base=self.root/'var/lib', root=self.root, owner=os.geteuid(), journal=store)
        missing = self.root/'var/lib/pxe-tools-http'
        info = missing.stat(); missing.rmdir()
        self.generation.xattrs.pop((info.st_dev, info.st_ino, ownership.XATTR_NAME), None)
        self.generation.birth.pop((info.st_dev, info.st_ino), None)
        with patch.object(store, '_write', side_effect=OSError('fixture sync failure')):
            with self.assertRaises(OSError): store.resume_missing_runtime(mounts=[])
        self.assertTrue(missing.is_dir())
        with self.assertRaisesRegex(ValueError, 'generation'):
            store.resume_missing_runtime(mounts=[])
        self.assertEqual(store.read()['base_phase'], 'runtime-prepared')

    def test_existing_data_refuses_without_claiming_or_changing_it(self):
        data = self.root / 'var/lib/pxe-tools'
        data.mkdir()
        (data / 'outside').write_text('keep')
        with self.assertRaises((ValueError, FileExistsError)):
            self.store().create_base()
        self.assertEqual((data / 'outside').read_text(), 'keep')
        self.assertFalse((self.root / 'etc/pxe-tools').exists())

    def test_repeat_or_crash_does_not_adopt_existing_paths(self):
        store = self.store()
        store.create_base()
        before = store.read()
        with self.assertRaises((ValueError, FileExistsError)):
            store.create_base()
        self.assertEqual(store.read(), before)

    def test_failed_write_after_mkdir_never_adopts_directory_on_retry(self):
        store = self.store()
        original = store._write
        calls = 0
        def failed_write(directory, record):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('fixture failure after mkdir')
            return original(directory, record)
        store._write = failed_write
        with self.assertRaises(OSError):
            store.create_base()
        self.assertTrue((self.root / 'etc/pxe-tools').exists())
        store._write = original
        self.assertEqual(store.read()['directories'], {})
        with self.assertRaises((ValueError, FileExistsError)):
            store.create_base()
        self.assertEqual(store.read()['directories'], {})

    def test_preexisting_unproven_metadata_directory_is_not_adopted(self):
        meta = self.root / 'var/lib/pxe-tools-ownership'
        meta.mkdir(mode=0o700)
        (meta / 'witness').write_text('keep')
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.store().create_base()
        self.assertEqual((meta / 'witness').read_text(), 'keep')
        self.assertFalse((meta / 'state.json').exists())
        self.assertFalse((meta / 'lock').exists())
        self.assertFalse((self.root / 'etc/pxe-tools').exists())

    def test_existing_or_linked_metadata_is_not_replaced(self):
        outside = self.root / 'external'
        outside.mkdir()
        (outside / 'witness').write_text('keep')
        (self.root / 'var/lib/pxe-tools-ownership').symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.store().create_base()
        self.assertEqual((outside / 'witness').read_text(), 'keep')
        self.assertFalse((self.root / 'etc/pxe-tools').exists())

    def test_marker_must_be_private_regular_file_with_known_schema(self):
        store = self.store()
        store.create_base()
        state = self.root / 'var/lib/pxe-tools-ownership/state.json'
        original = json.loads(state.read_text())
        state.chmod(0o644)
        with self.assertRaises(ValueError):
            store.read()
        state.chmod(0o600)
        original['surprise'] = True
        state.write_text(json.dumps(original))
        with self.assertRaises(ValueError):
            store.read()

    def test_account_schema_rejects_non_dedicated_names(self):
        self.assertIsNotNone(ownership)
        valid = {'format': 1, 'directories': {},
                 'account': {'name': 'pxe-tools-ansible', 'uid': 501, 'gid': 502,
                             'gecos': 'pxe-tools-' + 'a' * 32,
                             'home': '/var/lib/pxe-tools-ansible/home', 'shell': '/usr/sbin/nologin'}}
        self.assertEqual(ownership.validate(valid)['account']['uid'], 501)
        valid['account']['name'] = 'automation'
        with self.assertRaises(ValueError):
            ownership.validate(valid)


class BuilderHooksTests(unittest.TestCase):
    def builder(self, name):
        spec = importlib.util.spec_from_file_location('fixture_' + name.replace('-', '_'),
                                                       ROOT / 'packaging/native' / name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_failed_service_enable_warns_but_keeps_install_success(self):
        import io
        from contextlib import redirect_stderr
        runtime = self.builder('configure-secure-tftp.py')
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=1)
        with redirect_stderr(io.StringIO()) as error:
            runtime.activate_admin(runner)
        self.assertEqual(calls, [['systemctl', 'enable', 'pxe-tools-admin.target']])
        self.assertIn('enable', error.getvalue())

    def test_failed_service_start_warns_but_keeps_install_success(self):
        import io
        from contextlib import redirect_stderr
        runtime = self.builder('configure-secure-tftp.py')
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=int(command[1] == 'start'))
        with redirect_stderr(io.StringIO()) as error:
            runtime.activate_admin(runner)
        self.assertEqual([call[1] for call in calls], ['enable', 'start'])
        self.assertIn('start', error.getvalue())

    def test_secure_runtime_accepts_transaction_journal_injection(self):
        import inspect
        runtime = self.builder('configure-secure-tftp.py')
        self.assertIn('journal', inspect.signature(runtime.prepare).parameters)

    def test_base_hook_checks_removal_before_nginx_and_records_around_first_start(self):
        postinst = self.builder('build-local-package.py').POSTINST
        self.assertLess(postinst.index('check-removal'), postinst.index('reconcile-nginx.py'))
        self.assertLess(postinst.index('check-base'), postinst.index('reconcile-nginx.py'))
        self.assertLess(postinst.index('recover-initialization'), postinst.index('reconcile-nginx.py'))
        self.assertLess(postinst.index('reconcile-nginx.py'), postinst.index('finish-base'))
        self.assertIn('configure-secure-tftp.py --initialize-instance', postinst)
        self.assertLess(postinst.index('reconcile-nginx.py'), postinst.index('configure-secure-tftp.py --initialize-instance'))

    def test_postinst_finishes_recovered_setup_after_service_start(self):
        postinst = self.builder('build-local-package.py').POSTINST
        with tempfile.TemporaryDirectory(prefix='pxe-postinst-recovery-') as temp:
            root = Path(temp); binaries = root/'bin'; binaries.mkdir()
            systemd = root/'systemd'; systemd.mkdir()
            trace = root/'trace'
            python = binaries/'python3'
            python.write_text('#!/bin/sh\nprintf "python %s\\n" "$*" >> "$TRACE"\n'
                              'if [ "$2" = recover-initialization ]; then echo recovered; fi\n')
            python.chmod(0o755)
            systemctl = binaries/'systemctl'
            systemctl.write_text('#!/bin/sh\nprintf "systemctl %s\\n" "$*" >> "$TRACE"\n')
            systemctl.chmod(0o755)
            postinst = postinst.replace('[ -d /run/systemd/system ]', '[ -d "$FIXTURE_SYSTEMD" ]')
            script = root/'postinst'; script.write_text(postinst)
            environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.defpath,
                               TRACE=str(trace), FIXTURE_SYSTEMD=str(systemd))
            subprocess.run(['/bin/sh', str(script), 'configure'], env=environment,
                           check=True, capture_output=True, text=True)
            lines = trace.read_text().splitlines()
            find = lambda text: next(index for index, line in enumerate(lines) if text in line)
            self.assertLess(find('check-removal'), find('recover-initialization'))
            self.assertLess(find('recover-initialization'), find('reconcile-nginx.py'))
            self.assertLess(find('reconcile-nginx.py'), find('systemctl start pxe-tools-admin.target'))
            self.assertLess(find('systemctl start pxe-tools-admin.target'), find('finish-base'))
            self.assertFalse(any(' check-base' in line for line in lines))

    def test_preinst_checks_removal_before_unpack_for_both_packages(self):
        for name in ('build-local-package.py', 'build-local-ansible-package.py'):
            with self.subTest(builder=name):
                preinst = self.builder(name).PREINST
                self.assertIn('check-removal', preinst)
                self.assertIn('@@PXE_UPGRADE_LIFECYCLE@@', preinst)
                self.assertLess(preinst.index('check-removal'),
                                preinst.index('getent passwd') if 'getent passwd' in preinst
                                else preinst.index('PXE_CACHE_CLEANUP'))

    def test_both_package_staging_trees_carry_exact_helper_bytes(self):
        expected_helper = (ROOT / 'packaging/native/ownership-provenance.py').read_bytes()
        expected_uninstall = (ROOT / 'packaging/native/uninstall-apt.py').read_bytes()
        for name in ('build-local-package.py', 'build-local-ansible-package.py'):
            with self.subTest(builder=name), tempfile.TemporaryDirectory(prefix='pxe-pkg-fixture-') as tmp:
                builder = self.builder(name)
                captured = {}
                def fake_dpkg(command, **kwargs):
                    staged = Path(command[-2])
                    helper = ('usr/lib/pxe-tools/native/ownership-provenance.py' if name == 'build-local-package.py'
                              else 'usr/lib/pxe-tools-ansible/ownership-provenance.py')
                    captured['helper'] = (staged / helper).read_bytes()
                    if name == 'build-local-package.py':
                        captured['uninstall'] = (staged / 'usr/lib/pxe-tools/native/uninstall-apt.py').read_bytes()
                    captured['postinst'] = (staged / 'DEBIAN/postinst').read_text()
                    Path(command[-1]).write_bytes(b'deb fixture')
                with patch.object(builder.source_inventory, 'tracked_files', return_value=set()), \
                     patch.object(builder.source_inventory, 'checked_file', side_effect=lambda root, path, tracked: path), \
                     patch.object(builder.subprocess, 'run', side_effect=fake_dpkg):
                    builder.build(Path(tmp) / 'fixture.deb', '0.1.0~fixture')
                self.assertEqual(captured['helper'], expected_helper)
                if name == 'build-local-package.py':
                    self.assertEqual(captured['uninstall'], expected_uninstall)
                    self.assertIn('configure-secure-tftp.py --initialize-instance', captured['postinst'])
                else:
                    self.assertIn('ownership-provenance.py configure-ansible', captured['postinst'])

    def test_module_hook_uses_its_own_installed_helper(self):
        postinst = self.builder('build-local-ansible-package.py').POSTINST
        self.assertIn('/usr/lib/pxe-tools-ansible/ownership-provenance.py configure-ansible', postinst)
        self.assertNotIn('useradd --system', postinst)



@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0 and Path('/.dockerenv').exists(),
                     'requires an isolated root Linux container')
class NativeFirstBootCompatibility(unittest.TestCase):
    def test_real_runtime_creation_journals_all_three_roots_before_base(self):
        with tempfile.TemporaryDirectory(prefix='pxe-runtime-proof-', dir='/root') as temporary:
            root = Path(temporary)
            for part in ('etc', 'var/lib', 'var/log', 'run/lock'):
                (root / part).mkdir(parents=True, exist_ok=True)
            spec = importlib.util.spec_from_file_location('secure_runtime_for_ownership',
                                                         ROOT / 'packaging/native/configure-secure-tftp.py')
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
            store = ownership.Store(root, owner=0)
            def initialize(held):
                record = store.read()
                self.assertEqual(record['base_phase'], 'runtime-prepared')
                self.assertEqual(set(record['directories']), ownership.NATIVE_DIRECTORIES)
                store.create_base(require_runtime=True, native_fds=held, activate=lambda: None)
            runtime.prepare(base=root / 'var/lib', journal=store, after_create=initialize)
            self.assertEqual(store.read()['base_phase'], 'complete')

    def test_real_runtime_interruption_does_not_adopt_any_uncreated_path(self):
        with tempfile.TemporaryDirectory(prefix='pxe-runtime-proof-', dir='/root') as temporary:
            root = Path(temporary)
            for part in ('etc', 'var/lib', 'var/log', 'run/lock'):
                (root / part).mkdir(parents=True, exist_ok=True)
            spec = importlib.util.spec_from_file_location('secure_runtime_for_ownership_failure',
                                                         ROOT / 'packaging/native/configure-secure-tftp.py')
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
            store = ownership.Store(root, owner=0)
            original = store.record_runtime_created
            def fail_second(path, fd):
                if path.endswith('-tftp'):
                    raise OSError('fixture failure')
                original(path, fd)
            store.record_runtime_created = fail_second
            with self.assertRaises(OSError):
                runtime.prepare(base=root / 'var/lib', journal=store)
            record = store.read()
            self.assertEqual(record['base_phase'], 'runtime-preparing')
            self.assertNotIn('/var/lib/pxe-tools-tftp', record['directories'])
            with self.assertRaises(ValueError):
                store.check_base()

    def test_real_php_init_accepts_precreated_base_roots(self):
        with tempfile.TemporaryDirectory(prefix='pxe-init-ownership-') as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            for part in ('etc', 'var/lib', 'var/log', 'run/lock'):
                (root / part).mkdir(parents=True, exist_ok=True)
            store = ownership.Store(root, owner=0)
            script = (ROOT / 'docker/pxe-tools/init/php-init.sh').read_text()
            for path in ('/etc/pxe-tools', '/var/lib/pxe-tools', '/run/php'):
                script = script.replace(path, str(root / path.lstrip('/')))
            fixture = root / 'php-init.sh'
            fixture.write_text(script)
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PXE_APP_DIR': str(ROOT / 'app'),
                   'PXE_SERVICE_MANAGER': 'systemd'}
            identities = {}
            def initialize():
                # Production keeps these FDs pinned across service startup;
                # direct finish_base after closing them must refuse weak proof.
                for path in ('etc/pxe-tools', 'var/lib/pxe-tools'):
                    info = (root / path).stat()
                    identities[path] = (info.st_dev, info.st_ino)
                result = subprocess.run(['/bin/sh', str(fixture)], env=env, text=True,
                                        capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((root / 'etc/pxe-tools/master.key').is_file())
                self.assertTrue((root / 'var/lib/pxe-tools/sessions').is_dir())
                for path, expected in identities.items():
                    info = (root / path).stat()
                    self.assertEqual((info.st_dev, info.st_ino), expected)
            store.create_base(activate=initialize)
            record = store.read()
            self.assertEqual(record['base_phase'], 'complete')
            for path, expected in identities.items():
                proof = record['directories']['/' + path]
                self.assertEqual((proof['dev'], proof['ino']), expected)

    @unittest.skipUnless(shutil.which('dpkg-deb') and shutil.which('git'), 'dpkg-deb and git required')
    def test_actual_debs_contain_identical_canonical_helpers(self):
        with tempfile.TemporaryDirectory(prefix='pxe-deb-ownership-') as temporary:
            work = Path(temporary)
            source = work / 'source'
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc', '.DS_Store'))
            subprocess.run(['git', 'init', '-q', str(source)], check=True)
            subprocess.run(['git', '-C', str(source), 'add', '-A'], check=True)
            for name, builder in (('base', 'build-local-package.py'), ('ansible', 'build-local-ansible-package.py')):
                package = work / (name + '.deb')
                subprocess.run([sys.executable, str(source / 'packaging/native' / builder), str(package),
                                '--version', '0.1.0~fixture'], check=True, stdout=subprocess.DEVNULL)
                extracted = work / (name + '-tree')
                subprocess.run(['dpkg-deb', '-x', str(package), str(extracted)], check=True)
                helper = ('usr/lib/pxe-tools/native/ownership-provenance.py' if name == 'base' else
                          'usr/lib/pxe-tools-ansible/ownership-provenance.py')
                self.assertEqual((extracted / helper).read_bytes(),
                                 (source / 'packaging/native/ownership-provenance.py').read_bytes())
                if name == 'base':
                    self.assertEqual((extracted / 'usr/lib/pxe-tools/native/uninstall-apt.py').read_bytes(),
                                     (source / 'packaging/native/uninstall-apt.py').read_bytes())



class FakeAccounts:
    def __init__(self, *, preexisting=False):
        from types import SimpleNamespace
        self.SimpleNamespace = SimpleNamespace
        self.uid = os.geteuid() or 1234
        self.gid = os.getegid() or 1234
        self.account = self.entry('existing') if preexisting else None
        self.calls = []
    def entry(self, gecos):
        return self.SimpleNamespace(pw_name='pxe-tools-ansible', pw_uid=self.uid,
                                    pw_gid=self.gid, pw_gecos=gecos,
                                    pw_dir='/var/lib/pxe-tools-ansible/home',
                                    pw_shell='/usr/sbin/nologin')
    def getpwnam(self, name):
        if self.account is None or name != 'pxe-tools-ansible':
            raise KeyError(name)
        return self.account
    def getgrnam(self, name):
        return self.SimpleNamespace(gr_gid=self.gid, gr_mem=[])
    def getgrouplist(self, name, gid):
        return [gid]
    def run(self, command, **kwargs):
        self.calls.append(command)
        self.account = self.entry(command[command.index('--comment') + 1])
        return self.SimpleNamespace(returncode=0)
    def chown(self, fd, uid, gid):
        # Synthetic accounts use the fixture owner; never call host useradd.
        assert (uid, gid) == (self.uid, self.gid)
        os.fchown(fd, uid, gid)


class AccountCreationTests(unittest.TestCase):
    setUp = OwnershipFixture.setUp
    store = OwnershipFixture.store
    def test_incomplete_base_setup_blocks_module_before_account_changes(self):
        store = self.store()
        store.create_base()
        accounts = FakeAccounts()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            store.configure_ansible(accounts=accounts, groups=accounts,
                    group_list=accounts.getgrouplist, runner=accounts.run, chown=accounts.chown)
        self.assertEqual(accounts.calls, [])
        self.assertNotIn('account', store.read())

    def test_unfinished_removal_journal_blocks_module_before_useradd(self):
        marker = self.root / 'var/lib/pxe-tools-native/upgrade/uninstall-state.json'
        marker.parent.mkdir(parents=True)
        marker.write_text('{}')
        accounts = FakeAccounts()
        with self.assertRaisesRegex(ValueError, 'uninstall'):
            self.store().configure_ansible(accounts=accounts, groups=accounts,
                    group_list=accounts.getgrouplist, runner=accounts.run, chown=accounts.chown)
        self.assertEqual(accounts.calls, [])
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())

    def test_separate_uninstall_marker_blocks_module_before_useradd(self):
        marker = self.root / 'var/lib/pxe-tools-uninstall'
        marker.mkdir()
        accounts = FakeAccounts()
        store = ownership.Store(self.root, owner=os.geteuid())
        with self.assertRaisesRegex(ValueError, 'uninstall'):
            store.configure_ansible(accounts=accounts, groups=accounts,
                                    group_list=accounts.getgrouplist,
                                    runner=accounts.run, chown=accounts.chown)
        self.assertEqual(accounts.calls, [])
        self.assertTrue(marker.is_dir())
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())

    def test_linked_removal_runtime_refuses_module_before_useradd(self):
        (self.root / 'var/lib/pxe-tools-native').symlink_to(self.root / 'elsewhere', target_is_directory=True)
        accounts = FakeAccounts()
        with self.assertRaises((OSError, ValueError)):
            self.store().configure_ansible(accounts=accounts, groups=accounts,
                    group_list=accounts.getgrouplist, runner=accounts.run, chown=accounts.chown)
        self.assertEqual(accounts.calls, [])

    def test_mode_is_set_before_transferring_each_new_directory(self):
        # Model root with CAP_CHOWN and DAC_OVERRIDE but without CAP_FOWNER:
        # fchmod becomes forbidden as soon as ownership has been transferred.
        accounts = FakeAccounts()
        store = self.store()
        transferred = set()
        real_chmod = os.fchmod
        def identity(fd):
            info = os.fstat(fd)
            return info.st_dev, info.st_ino
        def tracked_chown(fd, uid, gid):
            accounts.chown(fd, uid, gid)
            transferred.add(identity(fd))
        def limited_chmod(fd, mode):
            if identity(fd) in transferred:
                raise PermissionError('fixture: CAP_FOWNER unavailable after chown')
            return real_chmod(fd, mode)
        with patch.object(ownership.os, 'fchmod', side_effect=limited_chmod):
            store.configure_ansible(accounts=accounts, groups=accounts,
                                    group_list=accounts.getgrouplist,
                                    runner=accounts.run, chown=tracked_chown)
        for path in ('var/lib/pxe-tools-ansible', 'var/lib/pxe-tools-ansible/home',
                     'var/lib/pxe-tools-ansible/workspace'):
            self.assertEqual((self.root / path).stat().st_mode & 0o777, 0o700)

    def test_new_account_and_new_workspace_are_proven(self):
        accounts = FakeAccounts()
        store = self.store()
        store.configure_ansible(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                                runner=accounts.run, chown=accounts.chown)
        record = store.read()
        self.assertRegex(record['account']['gecos'], r'^pxe-tools-[0-9a-f]{32}$')
        self.assertEqual(record['account']['uid'], accounts.uid)
        self.assertIn('/var/lib/pxe-tools-ansible', record['directories'])
        self.assertTrue((self.root / 'var/lib/pxe-tools-ansible/home').is_dir())
        self.assertTrue((self.root / 'var/lib/pxe-tools-ansible/workspace').is_dir())
        self.assertEqual(len(accounts.calls), 1)

    def test_existing_account_is_never_claimed(self):
        accounts = FakeAccounts(preexisting=True)
        store = self.store()
        store.configure_ansible(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                                runner=accounts.run, chown=accounts.chown)
        self.assertNotIn('account', store.read())
        self.assertEqual(accounts.calls, [])

    def test_existing_workspace_is_not_claimed(self):
        accounts = FakeAccounts(preexisting=True)
        base = self.root / 'var/lib/pxe-tools-ansible'
        base.mkdir(mode=0o700)
        os.chown(base, accounts.uid, accounts.gid)
        store = self.store()
        store.configure_ansible(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                                runner=accounts.run, chown=accounts.chown)
        self.assertNotIn('/var/lib/pxe-tools-ansible', store.read()['directories'])

    def test_interrupted_account_record_is_never_adopted_on_retry(self):
        accounts = FakeAccounts()
        store = self.store()
        original = store._write
        calls = 0
        def fail_after_useradd(directory, record):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('fixture failure after useradd')
            return original(directory, record)
        store._write = fail_after_useradd
        kwargs = dict(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                      runner=accounts.run, chown=accounts.chown)
        with self.assertRaises(OSError):
            store.configure_ansible(**kwargs)
        self.assertIsNotNone(accounts.account)
        store._write = original
        store.configure_ansible(**kwargs)
        self.assertEqual(len(accounts.calls), 1)
        self.assertNotIn('account', store.read())

    def test_missing_recorded_account_is_not_silently_recreated(self):
        accounts = FakeAccounts()
        store = self.store()
        kwargs = dict(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                      runner=accounts.run, chown=accounts.chown)
        store.configure_ansible(**kwargs)
        before = store.read()
        accounts.account = None
        with self.assertRaises(ValueError):
            store.configure_ansible(**kwargs)
        self.assertEqual(store.read(), before)
        self.assertEqual(len(accounts.calls), 1)

    def test_legacy_v1_journal_does_not_gain_account_or_workspace_proof(self):
        accounts = FakeAccounts()
        store = self.store()
        with store._locked() as fd:
            store._write(fd, {'format': 1, 'directories': {}})
        original = store.read()
        store.configure_ansible(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                                runner=accounts.run, chown=accounts.chown)
        self.assertEqual(store.read(), original)
        self.assertEqual(len(accounts.calls), 1)
        self.assertTrue((self.root / 'var/lib/pxe-tools-ansible').is_dir())

    def test_same_workspace_inode_with_changed_birthtime_refuses_reconfigure(self):
        accounts = FakeAccounts()
        store = self.store()
        kwargs = dict(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                      runner=accounts.run, chown=accounts.chown)
        store.configure_ansible(**kwargs)
        proof = store.read()['directories']['/var/lib/pxe-tools-ansible']
        self.generation.birth[(proof['dev'], proof['ino'])] = (proof['btime_sec'], proof['btime_nsec'] + 1)
        with self.assertRaises(ValueError):
            store.configure_ansible(**kwargs)

    def test_replacement_account_does_not_inherit_marker(self):
        accounts = FakeAccounts()
        store = self.store()
        kwargs = dict(accounts=accounts, groups=accounts, group_list=accounts.getgrouplist,
                      runner=accounts.run, chown=accounts.chown)
        store.configure_ansible(**kwargs)
        before = store.read()
        accounts.account = accounts.entry('new human account')
        with self.assertRaises(ValueError):
            store.configure_ansible(**kwargs)
        self.assertEqual(store.read(), before)



if __name__ == '__main__':
    unittest.main()
