#!/usr/bin/env python3
"""The removal helpers operate only on isolated fixture trees."""
import importlib.util
import sqlite3
import json
import os
import subprocess
import sys
from contextlib import closing, redirect_stderr
from io import StringIO
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/native/uninstall-apt.py'
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location('uninstall_apt', SCRIPT)
    uninstall = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(uninstall)
else:
    uninstall = None


def fixture_proof(path):
    info = path.lstat()
    return {'dev': info.st_dev, 'ino': info.st_ino, 'btime_sec': 1,
            'btime_nsec': 1, 'nonce': 'a' * 64}


def fixture_matches(fd, proof):
    info = os.fstat(fd)
    return (info.st_dev, info.st_ino) == (proof['dev'], proof['ino'])


class ScopedRemovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-uninstall-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'var/lib').mkdir(parents=True)
        self.target = self.root / 'var/lib/pxe-tools'
        self.target.mkdir()
        (self.target / 'data').write_text('instance')
        self.outside = self.root / 'external'
        self.outside.mkdir()
        (self.outside / 'keep').write_text('outside')

    def remove(self, mounts=()):
        self.assertIsNotNone(uninstall, 'uninstaller is not implemented')
        return uninstall.remove_tree(self.root, '/var/lib/pxe-tools', mounts=mounts, owner=None)

    def test_removes_owned_tree_without_following_a_nested_symlink(self):
        (self.target / 'external-link').symlink_to(self.outside, target_is_directory=True)
        self.remove()
        self.assertFalse(self.target.exists())
        self.assertEqual((self.outside / 'keep').read_text(), 'outside')

    def test_mount_inside_target_refuses_before_any_deletion(self):
        nested = self.target / 'mounted'
        nested.mkdir()
        with self.assertRaises(ValueError):
            self.remove(mounts=('/var/lib/pxe-tools/mounted',))
        self.assertTrue((self.target / 'data').exists())

    def test_new_mount_during_descent_is_not_followed(self):
        import errno
        mounted = self.target / 'mounted'
        mounted.mkdir()
        (mounted / 'keep').write_text('mounted-sentinel')
        def opener(parent, name):
            if name == 'mounted':
                raise OSError(errno.EXDEV, 'mount boundary')
            return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        with self.assertRaises(OSError):
            uninstall.remove_tree(self.root, '/var/lib/pxe-tools', mounts=(), owner=None, opener=opener)
        self.assertEqual((mounted / 'keep').read_text(), 'mounted-sentinel')

    def test_root_symlink_is_refused(self):
        (self.target / 'data').unlink()
        self.target.rmdir()
        self.target.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.remove()
        self.assertTrue((self.outside / 'keep').exists())

    def test_preflight_checks_tree_without_deleting_it(self):
        uninstall.remove_tree(self.root, '/var/lib/pxe-tools', mounts=(), owner=None, dry_run=True)
        self.assertTrue((self.target / 'data').exists())

    def test_missing_tree_is_idempotent(self):
        self.remove()
        self.remove()
        self.assertTrue((self.outside / 'keep').exists())

    def test_symlinked_ancestor_is_refused(self):
        link = self.root / 'var/link'
        link.symlink_to(self.root / 'var/lib', target_is_directory=True)
        # Simulate a hostile ancestor by moving the fixture target out of the way.
        (self.target / 'data').unlink()
        self.target.rmdir()
        (self.root / 'var/lib').rmdir()
        (self.root / 'var/lib').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.remove()
        self.assertTrue((self.outside / 'keep').exists())

    def test_mount_exactly_on_target_refuses_before_deletion(self):
        with self.assertRaises(ValueError):
            self.remove(mounts=('/var/lib/pxe-tools',))
        self.assertTrue((self.target / 'data').exists())

    def test_unexpected_and_root_paths_are_refused(self):
        self.assertIsNotNone(uninstall, 'uninstaller is not implemented')
        for name in ('/', '/var/lib', '', '/var/lib/../external'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                uninstall.remove_tree(self.root, name, mounts=(), owner=None)
        self.assertTrue((self.outside / 'keep').exists())


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-origin-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime = self.root / 'var/lib/pxe-tools-native'
        self.runtime.mkdir(parents=True)
        self.data = self.root / 'var/lib/pxe-tools'
        self.data.mkdir()
        (self.root / 'etc/pxe-tools').mkdir(parents=True)
        self.marker = self.runtime / 'runtime.env'
        self.marker.write_text('TFTP_ROOT=/var/lib/pxe-tools-tftp\nHTTP_ROOT=/var/lib/pxe-tools-http\nPXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\nMOK_DIR=/var/lib/pxe-tools-native/mok\n')
        paths = ('/var/lib/pxe-tools-native', '/var/lib/pxe-tools', '/etc/pxe-tools')
        self.record = {'format': 2, 'base_phase': 'complete', 'directories': {}}
        for path in paths:
            self.record['directories'][path] = fixture_proof(self.root / path.lstrip('/'))

    def test_runtime_environment_alone_is_not_creation_proof(self):
        self.assertEqual(uninstall.proven_tree_paths(self.root, owner=None), ())

    def test_journalled_directory_identity_is_required(self):
        found = uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)
        self.assertIn('/var/lib/pxe-tools', found)
        self.assertIn('/etc/pxe-tools', found)
        self.data.rename(self.root / 'var/lib/original-data')
        self.data.mkdir()
        with self.assertRaises(ValueError):
            uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)
        self.assertTrue((self.root / 'var/lib/original-data').exists())

    def test_ansible_workspace_not_claimed_without_account_proof(self):
        workspace = self.root / 'var/lib/pxe-tools-ansible'
        workspace.mkdir()
        self.record['directories']['/var/lib/pxe-tools-ansible'] = fixture_proof(workspace)
        found = uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)
        self.assertNotIn('/var/lib/pxe-tools-ansible', found)
        self.assertTrue(workspace.exists())

    def test_incomplete_creation_journal_is_refused(self):
        self.record['base_phase'] = 'runtime-preparing'
        with self.assertRaises(ValueError):
            uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)

    def test_legacy_or_weak_proof_is_not_authority_to_delete(self):
        self.record['format'] = 1
        with self.assertRaises(ValueError):
            uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)
        self.record['format'] = 2
        self.record['directories']['/etc/pxe-tools'].update(btime_sec=None, btime_nsec=None, nonce=None)
        with self.assertRaises(ValueError):
            uninstall.proven_tree_paths(self.root, owner=None, record=self.record, generation_matches=fixture_matches)



class DatabaseQuiescenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-db-fixture-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        (root / 'var/lib/pxe-tools').mkdir(parents=True)
        (root / 'etc/pxe-tools').mkdir(parents=True)
        self.db = root / 'var/lib/pxe-tools/pxe-tools.sqlite'
        with closing(sqlite3.connect(self.db)) as conn:
            conn.executescript((SCRIPT.parents[2] / 'app/db/schema.sqlite.sql').read_text())
        (root / 'etc/pxe-tools/db.conf').write_text(json.dumps({'driver': 'sqlite', 'path': '/var/lib/pxe-tools/pxe-tools.sqlite'}))
        lifecycle_path = SCRIPT.parent / 'upgrade-lifecycle.py'
        spec = importlib.util.spec_from_file_location('test_lifecycle_for_uninstall', lifecycle_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.lifecycle = module.Lifecycle(root)

    def test_idle_database_is_accepted(self):
        uninstall.assert_idle_database(self.lifecycle)

    def test_running_or_pending_boot_action_is_refused(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("INSERT INTO machines(id,mac) VALUES(1,'02:00:00:00:00:01')")
            conn.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(1,'install','pending','fixture-token')")
            conn.commit()
        with self.assertRaises(RuntimeError):
            uninstall.assert_idle_database(self.lifecycle)

    def test_unknown_database_schema_is_refused(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('DROP TABLE actions')
        with self.assertRaises(RuntimeError):
            uninstall.assert_idle_database(self.lifecycle)



class ActiveServiceQuiescenceTests(unittest.TestCase):
    def setUp(self):
        helper = SCRIPT.parents[2] / 'tests/unit/test_native_upgrade_lifecycle.py'
        spec = importlib.util.spec_from_file_location('upgrade_fixtures_uninstall', helper)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.fixture = module.NativeUpgrade(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.life = self.fixture.subject
        self.systemd = self.fixture.systemd
        self.original = set(self.systemd.active)

    def test_idle_active_services_are_stopped_under_database_barrier(self):
        with uninstall.quiesced_lifecycle(self.life):
            self.assertFalse(self.systemd.active)
            self.assertEqual(self.life.load()['phase'], 'prepared')
            self.assertTrue((self.life.home / 'uninstall-state.json').exists())
            self.assertFalse((self.life.home / 'state.json').exists())
        # Successful callers own the next transaction; no automatic restart.
        self.assertFalse(self.systemd.active)
        self.assertTrue((self.life.home / 'uninstall-state.json').exists())
        self.assertIsNone(self.life.load())

    def test_running_job_refuses_without_stopping_services(self):
        self.fixture.row("INSERT INTO init_jobs(job_type,status) VALUES('fixture','running')")
        with self.assertRaisesRegex(RuntimeError, 'operations are still active'):
            with uninstall.quiesced_lifecycle(self.life):
                self.fail('must not enter')
        self.assertEqual(self.systemd.active, self.original)
        self.assertIsNone(self.life.load())
        self.assertFalse(any(call[0] in ('stop', 'start') for call in self.systemd.calls))
        self.assertFalse((self.life.home / 'uninstall-state.json').exists())

    def test_legacy_pending_installation_ansible_and_discovery_refuse(self):
        cases = [
            ("INSERT INTO installations(machine_id,install_status) VALUES(1,'pending')", 'installations'),
            ("INSERT INTO installations(machine_id,ansible_status) VALUES(1,'pending')", 'installations'),
            ("INSERT INTO discoveries(machine_id,discovery_status) VALUES(1,'pending')", 'discoveries'),
            ("INSERT INTO init_jobs(job_type,status) VALUES('machine:ansible_redeploy:1','pending')", 'init_jobs'),
        ]
        self.fixture.row("INSERT INTO machines(id,mac) VALUES(1,'02:00:00:00:00:01')")
        for sql, table in cases:
            with self.subTest(sql=sql):
                self.fixture.row(sql)
                with self.assertRaisesRegex(RuntimeError, table):
                    with uninstall.quiesced_lifecycle(self.life):
                        self.fail('must not stop while work is pending')
                self.assertEqual(self.systemd.active, self.original)
                self.fixture.row('DELETE FROM ' + table)

    def test_upgrade_and_configure_refuse_interrupted_uninstall(self):
        journal = self.life.home / 'uninstall-state.json'
        journal.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'uninstall'):
            self.life.prepare('2')
        with self.assertRaisesRegex(RuntimeError, 'uninstall'):
            self.life.configure()
        self.assertFalse(any(call[0] in ('stop', 'start') for call in self.systemd.calls))

    def test_check_removal_entrypoint_is_nonmutating_and_refuses_journal(self):
        # Simulate a running systemd host without touching the real host.
        namespace = self.life.prepare.__func__.__globals__
        fake_path = lambda value: type('RunPath', (), {'is_dir': lambda self: True})()
        with patch.dict(namespace, {'Lifecycle': lambda: self.life, 'Path': fake_path}), patch('sys.argv', ['lifecycle', 'check-removal']):
            namespace['main']()
            (self.life.home / 'uninstall-state.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'uninstall'):
                namespace['main']()
        self.assertFalse(any(call[0] in ('stop', 'start') for call in self.systemd.calls))

    def test_persistent_barrier_is_installed_before_database_barrier_releases(self):
        from contextlib import contextmanager
        observed = []
        @contextmanager
        def barrier(transaction):
            self.assertFalse(self.systemd.active)
            with closing(sqlite3.connect(self.fixture.db, timeout=0)) as conn:
                with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                    conn.execute("UPDATE settings SET value='race' WHERE key='fixture'")
            observed.append('entered')
            yield
            observed.append('exited')
        with uninstall.quiesced_lifecycle(self.life, after_stop=barrier):
            self.assertEqual(observed, ['entered'])
        self.assertEqual(observed, ['entered', 'exited'])

    def test_write_barrier_is_held_during_worker_freeze(self):
        def contender():
            with closing(sqlite3.connect(self.fixture.db, timeout=0)) as conn:
                with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                    conn.execute("UPDATE settings SET value='race' WHERE key='fixture'")
        self.systemd.on_freeze = contender
        with uninstall.quiesced_lifecycle(self.life):
            pass

    def test_uncertain_mask_cleanup_keeps_services_stopped_and_journal(self):
        from contextlib import contextmanager
        @contextmanager
        def barrier(transaction):
            yield
            raise uninstall.BarrierRecoveryRequired('mask cleanup uncertain')
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, after_stop=barrier):
                pass
        self.assertFalse(self.systemd.active)
        self.assertTrue((self.life.home / 'uninstall-state.json').exists())
        self.assertFalse(any(call[0] == 'start' for call in self.systemd.calls))

    def test_failure_before_purge_restores_original_services(self):
        with self.assertRaisesRegex(RuntimeError, 'preflight'):
            with uninstall.quiesced_lifecycle(self.life):
                raise RuntimeError('preflight')
        self.assertEqual(self.systemd.active, self.original)
        self.assertIsNone(self.life.load())

    def test_failure_after_purge_begins_retains_recovery_journal(self):
        with self.assertRaisesRegex(RuntimeError, 'dpkg'):
            with uninstall.quiesced_lifecycle(self.life) as transaction:
                transaction.begin_purge()
                raise RuntimeError('dpkg')
        self.assertFalse(self.systemd.active)
        self.assertIsNone(self.life.load())
        journal = json.loads((self.life.home / 'uninstall-state.json').read_text())
        self.assertEqual(journal['phase'], 'purge_started')



class PackageRemovalTests(unittest.TestCase):
    def test_only_the_two_product_packages_are_requested(self):
        commands = []
        def runner(command, **kwargs):
            commands.append((command, kwargs))
            return type('Result', (), {'returncode': 0})()
        uninstall.purge_packages(runner, frontend_locked=True)
        self.assertEqual(commands[0][0], ['dpkg', '--purge', 'pxe-tools-ansible', 'pxe-tools'])
        env = commands[0][1]['env']
        self.assertEqual(env['DPKG_FRONTEND_LOCKED'], '1')
        self.assertNotIn('DPKG_ROOT', env)
        self.assertNotIn('DPKG_ADMINDIR', env)
        self.assertNotIn('DPKG_FORCE', env)

    def test_purge_without_frontend_lock_is_refused(self):
        with self.assertRaises(RuntimeError):
            uninstall.purge_packages(lambda *a, **kw: self.fail('must not run'), frontend_locked=False)

    def test_absent_package_status_is_verified_from_complete_database(self):
        def absent(command, **kwargs):
            return type('Result', (), {'returncode': 0, 'stdout': 'bash\tinstalled\tok\n', 'stderr': ''})()
        self.assertTrue(uninstall.packages_absent(absent))

    def test_partial_or_config_files_are_not_absent(self):
        for status in ('installed', 'half-installed', 'config-files'):
            def found(command, **kwargs):
                return type('Result', (), {'returncode': 0, 'stdout': f'bash\tinstalled\tok\npxe-tools\t{status}\tok\n', 'stderr': ''})()
            with self.subTest(status=status):
                self.assertFalse(uninstall.packages_absent(found))

    def test_unknown_package_query_fails_closed(self):
        def failed(command, **kwargs):
            return type('Result', (), {'returncode': 1, 'stdout': '', 'stderr': 'database inaccessible'})()
        with self.assertRaises(RuntimeError):
            uninstall.packages_absent(failed)

    def test_purge_failure_is_propagated(self):
        def runner(command, **kwargs):
            return type('Result', (), {'returncode': 1})()
        with self.assertRaises(RuntimeError):
            uninstall.purge_packages(runner, frontend_locked=True)


class ServiceBarrierTests(unittest.TestCase):
    class Systemd:
        def __init__(self):
            self.active = {'pxe-tools-worker.service': 'inactive', 'pxe-tools-php.service': 'inactive'}
            self.masked = {'pxe-tools-php.service'}
            self.calls = []
        def __call__(self, command, **kwargs):
            self.calls.append(command)
            action = command[1]
            unit = command[-1]
            code, output = 0, ''
            if action == 'show':
                output = self.active[unit] + '\n'
            elif action == 'is-enabled':
                output = ('masked-runtime' if unit in self.masked else 'enabled') + '\n'
            elif action == 'mask':
                self.masked.add(unit)
            elif action == 'unmask':
                self.masked.discard(unit)
            return type('Result', (), {'returncode': code, 'stdout': output})()

    def test_running_service_refuses_without_masking_anything(self):
        systemd = self.Systemd()
        systemd.active['pxe-tools-worker.service'] = 'active'
        with self.assertRaises(RuntimeError):
            with uninstall.service_barrier(systemd, tuple(systemd.active)):
                self.fail('must not enter')
        self.assertFalse(any(c[1] == 'mask' for c in systemd.calls))

    def test_temporary_masks_are_reverted_and_existing_masks_preserved(self):
        systemd = self.Systemd()
        with uninstall.service_barrier(systemd, tuple(systemd.active)):
            self.assertEqual(systemd.masked, set(systemd.active))
        self.assertEqual(systemd.masked, {'pxe-tools-php.service'})

    def test_masks_are_reverted_if_inner_operation_fails(self):
        systemd = self.Systemd()
        with self.assertRaisesRegex(RuntimeError, 'fixture'):
            with uninstall.service_barrier(systemd, tuple(systemd.active)):
                raise RuntimeError('fixture')
        self.assertEqual(systemd.masked, {'pxe-tools-php.service'})



class PackagedUnitHashTests(unittest.TestCase):
    def test_embedded_unit_hashes_match_packaged_sources(self):
        import hashlib
        for name in uninstall.UNITS:
            with self.subTest(unit=name):
                content = (SCRIPT.parent / name).read_bytes()
                self.assertEqual(uninstall.UNIT_HASHES[name], hashlib.sha256(content).hexdigest())
        self.assertEqual(uninstall.ANSIBLE_DROPIN_HASH,
                         hashlib.sha256((SCRIPT.parent / 'ansible-worker.conf').read_bytes()).hexdigest())



class LifecycleLoaderTests(unittest.TestCase):
    def test_installed_helper_loads_from_regular_trusted_fixture(self):
        with tempfile.TemporaryDirectory(prefix='pxe-helper-fixture-') as tmp:
            root = Path(tmp)
            helper = root / 'usr/lib/pxe-tools/native/upgrade-lifecycle.py'
            helper.parent.mkdir(parents=True)
            helper.write_bytes((SCRIPT.parent / 'upgrade-lifecycle.py').read_bytes())
            subject = uninstall.load_lifecycle(root, owner=None)
            self.assertIsNotNone(subject)
            self.assertEqual(subject.root, root)

    def test_ownership_helper_loads_without_following_links(self):
        with tempfile.TemporaryDirectory(prefix='pxe-helper-fixture-') as tmp:
            root = Path(tmp)
            helper = root / 'usr/lib/pxe-tools/native/ownership-provenance.py'
            helper.parent.mkdir(parents=True)
            helper.write_bytes((SCRIPT.parent / 'ownership-provenance.py').read_bytes())
            subject = uninstall.load_ownership(root, owner=os.getuid())
            self.assertEqual(subject.root, root)

    def test_symlinked_helper_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='pxe-helper-fixture-') as tmp:
            root = Path(tmp)
            helper = root / 'usr/lib/pxe-tools/native/upgrade-lifecycle.py'
            helper.parent.mkdir(parents=True)
            helper.symlink_to(SCRIPT.parent / 'upgrade-lifecycle.py')
            with self.assertRaises((OSError, ValueError)):
                uninstall.load_lifecycle(root, owner=None)



class ExternalPathsTests(unittest.TestCase):
    def test_custom_database_and_secret_paths_are_reported_without_deletion(self):
        class Lifecycle:
            root = Path('/')
            def environments(self):
                return {'HTTP_ROOT': '/srv/shared/http', 'PXE_MASTER_KEY_PATH': '/secrets/master.key',
                        'MOK_DIR': '/etc/pxe-tools/mok', 'OTHER_SECRET': 'never-print-this'}
            def database(self): return Path('/srv/shared/instance.sqlite')
        found = uninstall.external_paths(Lifecycle(), ('/etc/pxe-tools', '/var/lib/pxe-tools'))
        self.assertEqual(found, ('/secrets/master.key', '/srv/shared/http', '/srv/shared/instance.sqlite'))



class ConsentTests(unittest.TestCase):
    def test_preview_is_default_and_requires_no_stdin(self):
        options = uninstall.parse_arguments([])
        self.assertFalse(options.yes)

    def test_only_explicit_yes_requests_removal(self):
        self.assertTrue(uninstall.parse_arguments(['--yes']).yes)
        self.assertFalse(uninstall.parse_arguments(['--dry-run']).yes)

    def test_unvalidated_candidate_cannot_run_a_real_removal(self):
        with self.assertRaisesRegex(RuntimeError, 'not yet validated'):
            uninstall.require_release_ready(True)
        uninstall.require_release_ready(False)

    def test_yes_and_preview_are_mutually_exclusive(self):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            uninstall.parse_arguments(['--yes', '--dry-run'])



class InstallerLockTests(unittest.TestCase):
    def test_parallel_invocation_refuses_and_releases_lock(self):
        with tempfile.TemporaryDirectory(prefix='pxe-lock-fixture-') as tmp:
            path = Path(tmp) / 'installer.lock'
            with uninstall.installer_lock(path, owner=None):
                with self.assertRaises((BlockingIOError, RuntimeError)):
                    with uninstall.installer_lock(path, owner=None):
                        pass
            with uninstall.installer_lock(path, owner=None):
                self.assertTrue(path.exists())

    def test_untrusted_lock_owner_is_refused(self):
        with tempfile.TemporaryDirectory(prefix='pxe-lock-fixture-') as tmp:
            path = Path(tmp) / 'installer.lock'
            path.touch()
            with self.assertRaises(ValueError):
                with uninstall.installer_lock(path, owner=-1):
                    pass

    def test_symlink_parent_is_not_followed(self):
        with tempfile.TemporaryDirectory(prefix='pxe-lock-fixture-') as tmp:
            base = Path(tmp)
            (base / 'real').mkdir()
            (base / 'link').symlink_to(base / 'real', target_is_directory=True)
            with self.assertRaises(OSError):
                with uninstall.installer_lock(base / 'link/lock', owner=None):
                    pass
            self.assertFalse((base / 'real/lock').exists())

    def test_symlink_lock_is_never_followed(self):
        with tempfile.TemporaryDirectory(prefix='pxe-lock-fixture-') as tmp:
            path = Path(tmp) / 'installer.lock'
            target = Path(tmp) / 'external'
            target.write_text('keep')
            path.symlink_to(target)
            with self.assertRaises(OSError):
                with uninstall.installer_lock(path, owner=None):
                    pass
            self.assertEqual(target.read_text(), 'keep')



class DpkgFrontendLockTests(unittest.TestCase):
    def test_frontend_lock_excludes_another_process(self):
        with tempfile.TemporaryDirectory(prefix='pxe-dpkg-lock-') as tmp:
            path = Path(tmp) / 'lock-frontend'
            program = "import fcntl,os,sys; f=os.open(sys.argv[1],os.O_RDWR); fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)"
            with uninstall.dpkg_frontend_lock(path, owner=None):
                result = subprocess.run([sys.executable, '-c', program, str(path)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
            result = subprocess.run([sys.executable, '-c', program, str(path)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(path.exists())

    def test_frontend_lock_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pxe-dpkg-lock-') as tmp:
            target = Path(tmp) / 'keep'
            target.write_text('sentinel')
            path = Path(tmp) / 'lock-frontend'
            path.symlink_to(target)
            with self.assertRaises(OSError):
                with uninstall.dpkg_frontend_lock(path, owner=None): pass
            self.assertEqual(target.read_text(), 'sentinel')



class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-transaction-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        runtime = self.root / 'var/lib/pxe-tools-native'
        runtime.mkdir(parents=True)
        (self.root / 'var/lib/dpkg').mkdir(parents=True)
        (runtime / 'runtime.env').write_text('TFTP_ROOT=/var/lib/pxe-tools-tftp\nHTTP_ROOT=/var/lib/pxe-tools-http\nPXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\nMOK_DIR=/var/lib/pxe-tools-native/mok\n')
        self.data = self.root / 'var/lib/pxe-tools-http'
        self.data.mkdir()
        (self.data / 'db').write_text('instance')
        (self.root / 'etc/pxe-tools').mkdir(parents=True)
        (self.root / 'var/lib/pxe-tools').mkdir()
        (self.root / 'var/log').mkdir()
        self.unproven = self.root / 'var/log/pxe-tools'
        self.record = {'format': 2, 'base_phase': 'complete', 'directories': {}}
        for path in ('/etc/pxe-tools', '/var/lib/pxe-tools', '/var/lib/pxe-tools-native', '/var/lib/pxe-tools-http'):
            self.record['directories'][path] = fixture_proof(self.root / path.lstrip('/'))
        unit_dir = self.root / 'etc/systemd/system'
        unit_dir.mkdir(parents=True)
        (self.root / 'run/systemd/system').mkdir(parents=True)
        (self.root / 'run/lock').mkdir()
        packaged = self.root / 'usr/lib/systemd/system'
        packaged.mkdir(parents=True)
        for name in ('pxe-tools-worker.service', 'pxe-tools-php.service'):
            (packaged / name).write_bytes((SCRIPT.parent / name).read_bytes())
        fixture_file = SCRIPT.parents[2] / 'tests/unit/test_uninstall_persistent_masks.py'
        fixture_spec = importlib.util.spec_from_file_location('mask_fixtures_for_transaction', fixture_file)
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        fixture_spec.loader.exec_module(fixture_module)
        self.systemd = fixture_module.FakeSystemd(unit_dir, ('pxe-tools-worker.service', 'pxe-tools-php.service'))
        (unit_dir / 'pxe-tools-php.service').symlink_to('/dev/null')
        self.systemd.preexisting.add('pxe-tools-php.service')
        self.events = []
        self.fail_purge = False
        ownership_file = SCRIPT.parent / 'ownership-provenance.py'
        ownership_spec = importlib.util.spec_from_file_location('ownership_fixture', ownership_file)
        ownership_module = importlib.util.module_from_spec(ownership_spec)
        ownership_spec.loader.exec_module(ownership_module)
        self.ownership = ownership_module.Store(self.root, owner=os.getuid())
        self.ownership.generation.matches = fixture_matches
        with self.ownership._locked() as fd:
            self.ownership._write(fd, self.record)
        systemd = self.systemd
        events = self.events
        class Lifecycle:
            def __init__(self, root):
                self.root = root
                self.home = root / 'var/lib/pxe-tools-native/upgrade'
                self.state_file = self.home / 'state.json'
            def private_home(self): self.home.mkdir(parents=True, exist_ok=True)
            def database(self): return None
            def environments(self): return getattr(self, 'storage_environment', {})
            def load(self): return None
            def check_effective_configuration(self): pass
            def freeze_worker(self, state): return False
            def busy(self, connection): return []
            def capture(self, version):
                self.check_effective_configuration()
                state = {'phase': 'captured', 'active': dict(systemd.active)}
                self.save(state)
                return state
            def save(self, state): self.state_file.write_text(json.dumps(state))
            def stop(self, state, frozen):
                events.append(['fixture-stop'])
                for unit in systemd.active: systemd.active[unit] = 'inactive'
            def quiesce(self, state, snapshot=False):
                self.check_effective_configuration()
                self.stop(state, False)
                state['phase'] = 'prepared'
                self.save(state)
            def restore(self, state, old=False): systemd.active.update(state['active'])
            def release_worker(self): pass
            def sync_directory(self, directory): pass
        self.lifecycle = Lifecycle(self.root)

    def runner(self, command, **kwargs):
        self.events.append(command)
        if command[0] == 'dpkg':
            if self.lifecycle is not None:
                with self.assertRaises(BlockingIOError):
                    with self.ownership._locked(create=False): pass
            return type('Result', (), {'returncode': int(self.fail_purge)})()
        if command[0] == 'dpkg-query':
            return type('Result', (), {'returncode': 0, 'stdout': 'bash\tinstalled\tok\n', 'stderr': ''})()
        return self.systemd(command, **kwargs)

    def execute(self, **kwargs):
        return uninstall.run_uninstall(self.root, self.runner, self.lifecycle,
                                       tuple(self.systemd.active), lambda: (), owner=None, record=self.record, ownership=self.ownership, **kwargs)

    def test_preview_does_not_mutate_or_invoke_system_commands(self):
        self.execute(apply=False)
        self.assertTrue((self.data / 'db').exists())
        self.assertEqual(self.events, [])

    def test_unfinished_upgrade_journal_refuses_before_purge(self):
        self.lifecycle.load = lambda: {'phase': 'prepared'}
        with self.assertRaisesRegex(RuntimeError, 'upgrade'):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_cleanup_failure_after_purge_reports_partial_completion(self):
        calls = 0
        def mount_provider():
            nonlocal calls
            calls += 1
            if calls >= 5:
                return ('/var/lib/pxe-tools-http',)
            return ()
        with self.assertRaisesRegex(RuntimeError, 'purge succeeded'):
            uninstall.run_uninstall(self.root, self.runner, self.lifecycle,
                                    tuple(self.systemd.active), mount_provider, owner=None, record=self.record, ownership=self.ownership, apply=True)
        self.assertTrue(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue((self.data / 'db').exists())

    def test_changed_ownership_journal_refuses_before_purge(self):
        self.ownership._read = lambda fd: {'format': 1, 'base_phase': 'preparing', 'directories': {}}
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.execute(apply=True)
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue((self.data / 'db').exists())

    def test_frontend_lock_is_required_before_service_or_package_changes(self):
        from contextlib import contextmanager
        @contextmanager
        def busy(*args, **kwargs):
            raise BlockingIOError('frontend lock held')
            yield
        with patch.object(uninstall, 'dpkg_frontend_lock', busy), self.assertRaises(BlockingIOError):
            self.execute(apply=True)
        self.assertEqual(self.events, [])
        self.assertTrue((self.data / 'db').exists())

    def test_custom_active_unit_refuses_before_any_service_stop(self):
        override = self.root / 'etc/systemd/system/pxe-tools-worker.service'
        override.write_text('administrator unit')
        self.systemd.active['pxe-tools-worker.service'] = 'active'
        with self.assertRaises((ValueError, RuntimeError)):
            self.execute(apply=True)
        self.assertEqual(override.read_text(), 'administrator unit')
        self.assertEqual(self.systemd.active['pxe-tools-worker.service'], 'active')
        self.assertFalse(any(command[0] in ('dpkg', 'fixture-stop') for command in self.events))

    def test_storage_configuration_changed_during_stop_refuses_purge(self):
        original = self.lifecycle.stop
        def changed(state, frozen):
            original(state, frozen)
            self.lifecycle.storage_environment = {'HTTP_ROOT': '/srv/external-pxe'}
        self.lifecycle.stop = changed
        with self.assertRaisesRegex(RuntimeError, 'storage configuration'):
            self.execute(apply=True)
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue((self.data / 'db').exists())

    def test_unsupported_service_override_refuses_before_purge(self):
        def unsupported():
            raise RuntimeError('unsupported override')
        self.lifecycle.check_effective_configuration = unsupported
        with self.assertRaisesRegex(RuntimeError, 'unsupported override'):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_idle_active_services_are_quiesced_before_purge(self):
        self.systemd.active['pxe-tools-worker.service'] = 'active'
        self.systemd.active['pxe-tools-php.service'] = 'active'
        self.execute(apply=True)
        self.assertTrue(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue(all(state == 'inactive' for state in self.systemd.active.values()))

    def test_failed_package_purge_leaves_data_untouched(self):
        self.fail_purge = True
        with self.assertRaises(RuntimeError):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertTrue((self.root / 'etc/systemd/system/pxe-tools-php.service').is_symlink())
        self.assertTrue((self.root / 'etc/systemd/system/pxe-tools-worker.service').is_symlink())
        journal = json.loads((self.root / 'var/lib/pxe-tools-native/upgrade/uninstall-state.json').read_text())
        self.assertEqual(journal['phase'], 'purge_started')

    def test_cleanup_after_success_preserves_external_link_target(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'keep').write_text('shared')
        (self.data / 'link').symlink_to(external, target_is_directory=True)
        self.execute(apply=True)
        self.assertFalse(self.data.exists())
        self.assertEqual((external / 'keep').read_text(), 'shared')
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())
        self.assertTrue((self.root / 'etc/systemd/system/pxe-tools-php.service').is_symlink())

    def test_reexecution_after_success_does_not_touch_external_data(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'keep').write_text('shared')
        self.execute(apply=True)
        self.lifecycle = None
        self.record = None
        self.ownership = None
        self.execute(apply=True)
        self.assertEqual((external / 'keep').read_text(), 'shared')

    def test_nginx_ownership_journal_requires_reconciliation_before_removal(self):
        journal = self.root / 'var/lib/pxe-tools-nginx-ownership'
        journal.mkdir(parents=True)
        (journal / 'state.json').write_text('{"format": 1, "phase": "complete"}')
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.execute(apply=True)
        self.assertTrue((journal / 'state.json').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_verified_nginx_journal_is_removed_without_changing_nginx(self):
        journal = self.root / 'var/lib/pxe-tools-nginx-ownership'
        journal.mkdir(mode=0o700)
        (journal / 'lock').touch(mode=0o600)
        state = {'format': 1, 'service': 'nginx.service', 'phase': 'complete',
                 'before': {'active': 'active', 'enabled': 'enabled'},
                 'after': {'active': 'inactive', 'enabled': 'disabled'},
                 'resources': {'fixture': 'unchanged'}, 'identity': {'pid': '1'},
                 'provenance': {'source': 'apt-and-dpkg', 'nginx_previously_absent': True,
                                'start': 'fixture', 'end': None, 'core': 'pxe-tools',
                                'initial_packages': {'nginx': '1', 'nginx-common': '1', 'pxe-tools': '1'}}}
        (journal / 'state.json').write_text(json.dumps(state))
        (journal / 'state.json').chmod(0o600)
        class Reconciler:
            def stock(self): return {'fixture': 'unchanged'}
            def state(self): return {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
            def stable_lock(self):
                from contextlib import nullcontext
                return nullcontext()
        uninstall.run_uninstall(self.root, self.runner, self.lifecycle, tuple(self.systemd.active),
                                lambda: (), owner=None, record=self.record, ownership=self.ownership,
                                reconciler=Reconciler(), apply=True)
        self.assertFalse(journal.exists())
        self.assertFalse(any(command[0] == 'systemctl' and command[-1] == 'nginx.service' for command in self.events))

    def test_unproven_instance_data_aborts_before_package_removal(self):
        self.unproven.mkdir()
        (self.unproven / 'preserve').write_text('unproven')
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.execute(apply=True)
        self.assertEqual((self.unproven / 'preserve').read_text(), 'unproven')
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_partial_install_with_unverifiable_jobs_keeps_all_data(self):
        self.lifecycle = None
        with self.assertRaises(RuntimeError):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_missing_native_runtime_is_not_created_for_partial_install(self):
        import shutil
        shutil.rmtree(self.root / 'var/lib/pxe-tools-native')
        with self.assertRaises(RuntimeError):
            self.execute(apply=True)
        self.assertFalse((self.root / 'var/lib/pxe-tools-native').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_unknown_legacy_instance_without_lifecycle_is_not_purged(self):
        self.unproven.mkdir()
        (self.root / 'var/lib/pxe-tools-native/runtime.env').unlink()
        self.lifecycle = None
        with self.assertRaises(RuntimeError):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_mount_is_refused_before_purge(self):
        with self.assertRaises(ValueError):
            uninstall.run_uninstall(self.root, self.runner, self.lifecycle, tuple(self.systemd.active),
                                    lambda: ('/var/lib/pxe-tools-http',), owner=None, record=self.record, ownership=self.ownership, apply=True)
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue((self.data / 'db').exists())



class MountInfoTests(unittest.TestCase):
    def test_bind_mount_and_escaped_names_are_detected(self):
        data = '41 23 8:1 / /var/lib/pxe-tools/http\\040external rw - ext4 /dev/x rw\n'
        self.assertEqual(uninstall.parse_mountinfo(data), ('/var/lib/pxe-tools/http external',))

    def test_malformed_mountinfo_is_not_treated_as_empty(self):
        with self.assertRaises(ValueError):
            uninstall.parse_mountinfo('malformed line\n')



class AptSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-apt-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'etc/apt/sources.list.d').mkdir(parents=True)
        (self.root / 'etc/apt/keyrings').mkdir(parents=True)
        self.source = self.root / 'etc/apt/sources.list.d/pxe-tools.sources'
        self.key = self.root / 'etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
        self.source.write_text('Types: deb\nURIs: https://packages.pxetools.com/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/pxe-tools-archive-keyring.gpg\n')
        self.key.write_bytes(b'fixture')

    def test_untrusted_ownership_prevents_source_removal(self):
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=-1), (False, False))

    def test_dedicated_source_is_removed_but_key_is_preserved(self):
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (True, False))
        self.assertEqual(uninstall.remove_apt_config(self.root, mounts=(), owner=None), (True, False))
        self.assertFalse(self.source.exists())
        self.assertTrue(self.key.exists())

    def test_unrelated_url_in_product_named_source_is_never_removed(self):
        other = self.source.read_text().replace('https://packages.pxetools.com/apt',
                                                'https://third-party.example/apt')
        self.source.write_text(other)
        self.assertEqual(uninstall.remove_apt_config(self.root, mounts=(), owner=None), (False, False))
        self.assertEqual(self.source.read_text(), other)
        self.assertTrue(self.key.exists())

    def test_nonstandard_apt_sources_do_not_cause_key_deletion(self):
        custom = self.root / 'custom-apt-sources'
        custom.mkdir()
        (custom / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://other.invalid stable main\n')
        (self.root / 'etc/apt/apt.conf').write_text('Dir::Etc::sourceparts "/custom-apt-sources";\n')
        self.assertEqual(uninstall.remove_apt_config(self.root, mounts=(), owner=None), (True, False))
        self.assertTrue(self.key.exists())
        self.assertTrue((custom / 'other.list').exists())

    def test_other_source_uses_key_so_key_is_preserved(self):
        (self.source.parent / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://other.invalid stable main\n')
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (True, False))

    def test_key_alias_outside_keyrings_is_preserved(self):
        alias = self.root / 'alias.gpg'
        alias.symlink_to(self.key)
        (self.source.parent / 'other.list').write_text('deb [signed-by=/alias.gpg] https://other.invalid stable main\n')
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (True, False))

    def test_modified_source_is_preserved_along_with_key(self):
        with self.source.open('a') as stream:
            stream.write('Enabled: no\n')
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (False, False))

    def test_symlinked_other_source_preserves_key(self):
        (self.source.parent / 'other.list').symlink_to(self.root / 'other')
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (True, False))

    def test_symlinked_apt_parent_preserves_everything(self):
        external = self.root / 'outside-apt'
        (self.root / 'etc/apt').rename(external)
        (self.root / 'etc/apt').symlink_to(external, target_is_directory=True)
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (False, False))
        self.assertTrue((external / 'sources.list.d/pxe-tools.sources').exists())

    def test_cleanup_removes_only_the_dedicated_files(self):
        (self.source.parent / 'other.list').write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://other.invalid stable main\n')
        self.assertEqual(uninstall.remove_apt_config(self.root, mounts=(), owner=None), (True, False))
        self.assertFalse(self.source.exists())
        self.assertTrue(self.key.exists())
        self.assertTrue((self.source.parent / 'other.list').exists())

    def test_mounted_key_is_preserved(self):
        self.assertEqual(uninstall.remove_apt_config(self.root, mounts=('/etc/apt/keyrings/pxe-tools-archive-keyring.gpg',), owner=None), (True, False))
        self.assertTrue(self.key.exists())

    def test_missing_files_are_idempotent(self):
        self.source.unlink()
        self.key.unlink()
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (False, False))


if __name__ == '__main__':
    unittest.main()
