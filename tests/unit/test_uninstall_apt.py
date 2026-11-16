#!/usr/bin/env python3
"""The removal helpers operate only on isolated fixture trees."""
import importlib.util
import sqlite3
import json
from contextlib import closing, redirect_stderr
from io import StringIO
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/native/uninstall-apt.py'
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location('uninstall_apt', SCRIPT)
    uninstall = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(uninstall)
else:
    uninstall = None


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
        self.marker = self.runtime / 'runtime.env'
        self.marker.write_text('TFTP_ROOT=/var/lib/pxe-tools-tftp\nHTTP_ROOT=/var/lib/pxe-tools-http\nPXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\nMOK_DIR=/var/lib/pxe-tools-native/mok\n')

    def test_known_fresh_marker_identifies_standard_roots_only(self):
        found = uninstall.proven_tree_paths(self.root, owner=None)
        self.assertNotIn('/var/lib/pxe-tools', found)
        self.assertNotIn('/etc/pxe-tools', found)
        self.assertIn('/var/lib/pxe-tools-native', found)
        self.assertNotIn('/var/lib/pxe-tools-ansible', found)
        self.assertNotIn('/var/log/pxe-tools', found)

    def test_custom_or_symlinked_marker_does_not_prove_ownership(self):
        self.marker.write_text('TFTP_ROOT=/external/share\n')
        self.assertEqual(uninstall.proven_tree_paths(self.root, owner=None), ())
        self.marker.unlink()
        self.marker.symlink_to(self.root / 'external')
        self.assertEqual(uninstall.proven_tree_paths(self.root, owner=None), ())



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



class PackageRemovalTests(unittest.TestCase):
    def test_only_the_two_product_packages_are_requested(self):
        commands = []
        def runner(command, **kwargs):
            commands.append(command)
            return type('Result', (), {'returncode': 0})()
        uninstall.purge_packages(runner)
        self.assertEqual(commands, [['dpkg', '--purge', 'pxe-tools-ansible', 'pxe-tools']])

    def test_purge_failure_is_propagated(self):
        def runner(command, **kwargs):
            return type('Result', (), {'returncode': 1})()
        with self.assertRaises(RuntimeError):
            uninstall.purge_packages(runner)



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



class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-transaction-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        runtime = self.root / 'var/lib/pxe-tools-native'
        runtime.mkdir(parents=True)
        (runtime / 'runtime.env').write_text('TFTP_ROOT=/var/lib/pxe-tools-tftp\nHTTP_ROOT=/var/lib/pxe-tools-http\nPXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\nMOK_DIR=/var/lib/pxe-tools-native/mok\n')
        self.data = self.root / 'var/lib/pxe-tools-http'
        self.data.mkdir()
        (self.data / 'db').write_text('instance')
        self.unproven = self.root / 'var/lib/pxe-tools'
        self.systemd = ServiceBarrierTests.Systemd()
        self.events = []
        self.fail_purge = False
        class Lifecycle:
            def __init__(self, root):
                self.home = root / 'var/lib/pxe-tools-native/upgrade'
                self.state_file = self.home / 'state.json'
            def private_home(self): self.home.mkdir(parents=True, exist_ok=True)
            def database(self): return None
            def load(self): return None
            def check_effective_configuration(self): pass
            def freeze_worker(self, state): return False
            def release_worker(self): pass
        self.lifecycle = Lifecycle(self.root)

    def runner(self, command, **kwargs):
        self.events.append(command)
        if command[0] == 'dpkg':
            return type('Result', (), {'returncode': int(self.fail_purge)})()
        return self.systemd(command, **kwargs)

    def execute(self, **kwargs):
        return uninstall.run_uninstall(self.root, self.runner, self.lifecycle,
                                       tuple(self.systemd.active), lambda: (), owner=None, **kwargs)

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
            if calls >= 3:
                return ('/var/lib/pxe-tools-http',)
            return ()
        with self.assertRaisesRegex(RuntimeError, 'purge succeeded'):
            uninstall.run_uninstall(self.root, self.runner, self.lifecycle,
                                    tuple(self.systemd.active), mount_provider, owner=None, apply=True)
        self.assertTrue(any(command[0] == 'dpkg' for command in self.events))
        self.assertTrue((self.data / 'db').exists())

    def test_unsupported_service_override_refuses_before_purge(self):
        def unsupported():
            raise RuntimeError('unsupported override')
        self.lifecycle.check_effective_configuration = unsupported
        with self.assertRaisesRegex(RuntimeError, 'unsupported override'):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertFalse(any(command[0] == 'dpkg' for command in self.events))

    def test_failed_package_purge_leaves_data_untouched(self):
        self.fail_purge = True
        with self.assertRaises(RuntimeError):
            self.execute(apply=True)
        self.assertTrue((self.data / 'db').exists())
        self.assertEqual(self.systemd.masked, {'pxe-tools-php.service'})

    def test_cleanup_after_success_preserves_external_link_target(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'keep').write_text('shared')
        (self.data / 'link').symlink_to(external, target_is_directory=True)
        self.execute(apply=True)
        self.assertFalse(self.data.exists())
        self.assertEqual((external / 'keep').read_text(), 'shared')
        self.assertEqual(self.systemd.masked, {'pxe-tools-php.service'})

    def test_reexecution_after_success_does_not_touch_external_data(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'keep').write_text('shared')
        self.execute(apply=True)
        self.lifecycle = None
        self.execute(apply=True)
        self.assertEqual((external / 'keep').read_text(), 'shared')

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
                                    lambda: ('/var/lib/pxe-tools-http',), owner=None, apply=True)
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

    def test_dedicated_source_and_key_can_be_removed(self):
        self.assertEqual(uninstall.apt_cleanup_plan(self.root, owner=None), (True, True))

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
