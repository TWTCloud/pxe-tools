# SPDX-License-Identifier: LGPL-3.0-only
"""Real SQLite/filesystem lifecycle tests with a deterministic systemd boundary.

Kernel freezer and dpkg integration require the separate disposable Linux lab.
"""
import hashlib
from contextlib import closing, contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('native_upgrade', ROOT / 'packaging/native/upgrade-lifecycle.py')
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


@contextmanager
def database_connection(*args, **kwargs):
    with closing(sqlite3.connect(*args, **kwargs)) as connection:
        with connection:
            yield connection


class Systemd:
    def __init__(self, root, active):
        self.root = root
        self.active = set(active)
        self.enabled = {unit: 'enabled' if unit.endswith('.target') else 'static' for unit in lifecycle.UNITS}
        self.calls = []
        self.fail_start = set()
        self.fail_stop = False
        self.on_freeze = None
        self.on_start = None
        self.environment = ''
        self.beta5_php = False
        self.restart = 'on-failure'
        group = root / 'sys/fs/cgroup/system.slice/pxe-tools-worker.service'
        group.mkdir(parents=True)
        (group / 'cgroup.events').write_text('frozen 0\n')
        (group / 'cgroup.procs').write_text('123\n')
        self.group = group
        process = root / 'proc/123'
        process.mkdir(parents=True)
        (process / 'stat').write_text('123 (python3) ' + ' '.join(['0'] * 20))
        (process / 'environ').write_bytes(b'')

    def __call__(self, argv, **kwargs):
        args = argv[1:]
        self.calls.append(args)
        action = args[0]
        output = ''
        status = 0
        unit = args[-1]
        if action == 'show':
            prop = args[1].split('=', 1)[1]
            if prop == 'ActiveState':
                output = 'active' if unit in self.active else 'inactive'
            elif prop == 'MainPID':
                output = '123'
            elif prop == 'ControlGroup':
                output = '/system.slice/pxe-tools-worker.service' if unit in self.active else ''
            elif prop == 'EnvironmentFiles':
                names = ['/usr/lib/pxe-tools/native/default.env']
                if unit != 'pxe-tools-init.service' and not (self.beta5_php and unit == 'pxe-tools-php.service'):
                    names.append('/var/lib/pxe-tools-native/network.env')
                names.append('/var/lib/pxe-tools-native/runtime.env')
                output = ' '.join(name + ' (ignore_errors=yes)' for name in names)
            elif prop == 'Environment':
                output = self.environment
            elif prop == 'ExecStart':
                output = '{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/lib/pxe-tools/native/start-worker.py ; ignore_errors=no ; }'
            elif prop == 'Restart':
                output = self.restart
        elif action == 'is-active':
            status = 0 if unit in self.active else 3
        elif action == 'is-enabled':
            output = self.enabled[unit]
        elif action == 'freeze':
            if unit not in self.active:
                status = 1
            else:
                (self.group / 'cgroup.events').write_text('frozen 1\n')
                environment = []
                for name in ('usr/lib/pxe-tools/native/default.env', 'var/lib/pxe-tools-native/network.env', 'var/lib/pxe-tools-native/runtime.env'):
                    if (self.root / name).exists():
                        environment.extend(line for line in (self.root / name).read_text().splitlines() if '=' in line)
                (self.root / 'proc/123/environ').write_bytes(('\0'.join(environment) + '\0').encode())
                if self.on_freeze:
                    self.on_freeze()
        elif action == 'thaw':
            (self.group / 'cgroup.events').write_text('frozen 0\n')
        elif action == 'kill':
            assert (self.group / 'cgroup.events').read_text() == 'frozen 1\n'
        elif action == 'stop':
            self.active.difference_update(args[1:])
            if self.fail_stop and len(args) > 2:
                self.fail_stop = False
                status = 1
        elif action == 'start':
            assert args[1] == '--job-mode=ignore-dependencies'
            if unit in self.fail_start:
                status = 1
            else:
                self.active.add(unit)
                if self.on_start:
                    self.on_start(unit)
        else:
            raise AssertionError(args)
        return subprocess.CompletedProcess(argv, status, stdout=output + '\n', stderr='')


class NativeUpgrade(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pxe-native-upgrade-')
        self.root = Path(self.temporary.name)
        (self.root / 'var/lib/pxe-tools').mkdir(parents=True)
        (self.root / 'etc/pxe-tools').mkdir(parents=True)
        self.db = self.root / 'var/lib/pxe-tools/pxe-tools.sqlite'
        with database_connection(self.db) as connection:
            connection.executescript((ROOT / 'app/db/schema.sqlite.sql').read_text())
            connection.execute("INSERT INTO settings(key,value) VALUES('fixture','unchanged')")
        (self.root / 'etc/pxe-tools/db.conf').write_text(json.dumps({'driver': 'sqlite', 'path': '/var/lib/pxe-tools/pxe-tools.sqlite'}))
        (self.root / 'etc/pxe-tools/master.key').write_bytes(b'k' * 32)
        self.systemd = Systemd(self.root, lifecycle.UNITS)
        self.subject = lifecycle.Lifecycle(self.root, runner=self.systemd, owner=os.geteuid())
        self.subject.private_home()

    def tearDown(self):
        self.temporary.cleanup()

    def row(self, sql):
        with database_connection(self.db) as connection:
            connection.execute(sql)

    def snapshot(self):
        return self.subject.home / self.subject.load()['id']

    def test_idle_active_upgrade_snapshots_key_and_database_then_restores_exact_roles(self):
        self.systemd.active -= {'pxe-tools.target', 'pxe-tools-dnsmasq.service',
                                'pxe-tools-dnsmasq-tail.service', 'pxe-tools-pxe-http.service'}
        original = set(self.systemd.active)
        enabled = dict(self.systemd.enabled)
        self.subject.prepare('1.2.3')
        self.assertEqual(self.systemd.active, set())
        snapshot = self.snapshot()
        manifest = json.loads((snapshot / 'manifest.json').read_text())
        self.assertEqual((snapshot / 'files/etc/pxe-tools/master.key').read_bytes(), b'k' * 32)
        for entry in manifest['files']:
            path = snapshot / entry['snapshot']
            if path.is_file():
                self.assertEqual(entry['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o700)
        with database_connection(snapshot / 'database.sqlite') as connection:
            self.assertEqual(connection.execute("SELECT value FROM settings WHERE key='fixture'").fetchone(), ('unchanged',))
        self.subject.configure()
        self.assertEqual(self.systemd.active, original)
        self.assertEqual(self.systemd.enabled, enabled)
        self.assertIsNone(self.subject.load())
        self.assertTrue((snapshot / 'result.json').exists())
        self.assertFalse(any(call[0] in ('enable', 'disable', 'reset-failed') for call in self.systemd.calls))

    def test_db_write_barrier_is_held_before_worker_freeze(self):
        def contender():
            with database_connection(self.db, timeout=0) as connection:
                with self.assertRaisesRegex(sqlite3.OperationalError, 'locked'):
                    connection.execute("UPDATE settings SET value='race' WHERE key='fixture'")
        self.systemd.on_freeze = contender
        self.subject.prepare('1')

    def test_pending_local_queue_survives_while_real_running_job_refuses_before_stop(self):
        self.row("INSERT INTO init_jobs(job_type,status) VALUES('catalog_refresh','pending')")
        self.subject.prepare('1')
        self.subject.configure()
        self.row("UPDATE init_jobs SET status='running'")
        self.systemd.calls.clear()
        original = set(self.systemd.active)
        with self.assertRaisesRegex(RuntimeError, 'operations are still active'):
            self.subject.prepare('2')
        self.assertEqual(self.systemd.active, original)
        self.assertFalse(any(call[0] in ('kill', 'stop') for call in self.systemd.calls))
        self.assertIsNone(self.subject.load())
        self.assertEqual((self.systemd.group / 'cgroup.events').read_text(), 'frozen 0\n')

    def test_external_client_pending_refuses(self):
        self.row("INSERT INTO machines(id,mac) VALUES(1,'02:00:00:00:00:01')")
        self.row("INSERT INTO actions(machine_id,type,status,token) VALUES(1,'install','pending','fixture-token')")
        with self.assertRaisesRegex(RuntimeError, 'actions'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] == 'stop' for call in self.systemd.calls))

    def test_running_task_phase_requires_reconciliation_even_with_idle_parent_tables(self):
        self.row("INSERT INTO task_phases(task_type,task_id,phase_key,status) VALUES('install',1,'preseed-loaded','running')")
        with self.assertRaisesRegex(RuntimeError, 'task_phases id=1'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] == 'stop' for call in self.systemd.calls))

    def test_beta5_php_environment_list_is_supported(self):
        self.systemd.beta5_php = True
        self.subject.prepare('1')
        self.systemd.beta5_php = False  # Incoming beta 7 carries the newer unit.
        self.subject.configure()
        self.assertEqual(self.systemd.active, set(lifecycle.UNITS))

    def test_untracked_worker_child_refuses_and_thaws_without_stopping(self):
        subgroup = self.systemd.group / 'child'
        subgroup.mkdir()
        (subgroup / 'cgroup.procs').write_text('456\n')
        with self.assertRaisesRegex(RuntimeError, 'active subprocess'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] == 'kill' for call in self.systemd.calls))
        self.assertEqual((self.systemd.group / 'cgroup.events').read_text(), 'frozen 0\n')

    def test_snapshot_failure_compensates_without_modifying_database(self):
        (self.root / 'etc/pxe-tools/unsupported-link').symlink_to('master.key')
        original = set(self.systemd.active)
        with self.assertRaisesRegex(RuntimeError, 'configuration links'):
            self.subject.prepare('1')
        self.assertEqual(self.systemd.active, original)
        self.assertIsNone(self.subject.load())
        with database_connection(self.db) as connection:
            self.assertEqual(connection.execute("SELECT value FROM settings WHERE key='fixture'").fetchone(), ('unchanged',))

    def test_configure_failure_and_retry_keep_original_snapshot_and_do_not_rollback_database(self):
        self.subject.prepare('1')
        snapshot = self.snapshot()
        self.row("UPDATE settings SET value='migration-committed' WHERE key='fixture'")
        self.systemd.fail_start.add('pxe-tools-init.service')
        with self.assertRaisesRegex(RuntimeError, 'did not resume'):
            self.subject.configure()
        self.assertIn(self.subject.load()['phase'], ('prepared', 'configuring'))
        self.assertEqual(self.systemd.active, set())
        self.systemd.fail_start.clear()
        self.subject.configure()
        with database_connection(snapshot / 'database.sqlite') as connection:
            self.assertEqual(connection.execute("SELECT value FROM settings WHERE key='fixture'").fetchone(), ('unchanged',))
        with database_connection(self.db) as connection:
            self.assertEqual(connection.execute("SELECT value FROM settings WHERE key='fixture'").fetchone(), ('migration-committed',))

    def test_network_failure_keeps_administration_and_retry_journal(self):
        self.subject.prepare('1')
        snapshot = self.snapshot()
        self.systemd.fail_start.add('pxe-tools-pxe-http.service')
        with self.assertRaisesRegex(RuntimeError, 'boot network could not resume'):
            self.subject.configure()
        self.assertIn('pxe-tools-nginx.service', self.systemd.active)
        self.assertIn('pxe-tools-worker.service', self.systemd.active)
        self.assertFalse(self.systemd.active & lifecycle.NETWORK)
        self.assertTrue(self.subject.state_file.exists())
        self.systemd.fail_start.clear()
        self.subject.configure()
        self.assertEqual(self.systemd.active, set(lifecycle.UNITS))
        self.assertTrue((snapshot / 'result.json').exists())

    def test_repeated_preinst_after_unpack_failure_preserves_snapshot(self):
        self.subject.prepare('1')
        original = self.subject.load()
        self.subject.prepare('1')
        self.assertEqual(self.subject.load()['id'], original['id'])
        self.assertEqual(self.subject.load()['units'], original['units'])
        self.subject.configure()
        self.assertEqual(self.systemd.active, set(lifecycle.UNITS))

    def test_retry_preinst_busy_does_not_leave_previous_worker_frozen(self):
        self.subject.prepare('1')
        original = self.subject.load()
        self.systemd.fail_start.add('pxe-tools-pxe-http.service')
        with self.assertRaises(RuntimeError):
            self.subject.configure()
        self.row("INSERT INTO init_jobs(job_type,status) VALUES('fixture','running')")
        with self.assertRaisesRegex(RuntimeError, 'operations are still active'):
            self.subject.prepare('1')
        self.assertEqual((self.systemd.group / 'cgroup.events').read_text(), 'frozen 0\n')
        self.assertEqual(self.subject.load()['id'], original['id'])
        self.assertEqual(self.subject.load()['units'], original['units'])

    def test_retry_partial_stop_failure_keeps_original_snapshot_and_retryable_journal(self):
        self.subject.prepare('1')
        original = self.subject.load()
        self.systemd.fail_start.add('pxe-tools-pxe-http.service')
        with self.assertRaises(RuntimeError):
            self.subject.configure()
        self.systemd.fail_start.clear()
        self.systemd.fail_stop = True
        with self.assertRaisesRegex(RuntimeError, 'stop failed'):
            self.subject.prepare('1')
        self.assertEqual(self.subject.load()['id'], original['id'])
        self.assertEqual(self.subject.load()['units'], original['units'])
        self.assertIn(self.subject.load()['phase'], ('prepared', 'configuring'))
        self.assertEqual((self.systemd.group / 'cgroup.events').read_text(), 'frozen 0\n')
        self.subject.prepare('1')
        self.subject.configure()
        self.assertEqual(self.systemd.active, set(lifecycle.UNITS))

    def test_ambiguous_running_job_without_worker_still_refuses(self):
        self.systemd.active.clear()
        self.row("INSERT INTO init_jobs(job_type,status) VALUES('fixture','running')")
        with self.assertRaisesRegex(RuntimeError, 'operations are still active'):
            self.subject.prepare('1')

    def test_all_inactive_stay_inactive(self):
        self.systemd.active.clear()
        self.subject.prepare('1')
        self.subject.configure()
        self.assertEqual(self.systemd.active, set())
        self.assertFalse(any(call[0] == 'start' for call in self.systemd.calls))

    def test_fresh_configure_does_not_create_runtime_before_first_install_guard(self):
        fresh = self.root / 'fresh'
        fresh.mkdir()
        subject = lifecycle.Lifecycle(fresh, runner=self.systemd, owner=os.geteuid())
        with patch.object(lifecycle, 'Lifecycle', return_value=subject), patch.object(lifecycle, 'Path') as path, patch.object(lifecycle.sys, 'argv', ['helper', 'configure']):
            path.return_value.is_dir.return_value = True
            lifecycle.main()
        self.assertFalse((fresh / 'var/lib/pxe-tools-native').exists())

    def test_dangerous_effective_environment_override_refuses_before_stop(self):
        self.systemd.environment = 'PXE_DB_PATH=/alternate/instance.sqlite'
        with self.assertRaisesRegex(RuntimeError, 'Environment override'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] in ('freeze', 'stop') for call in self.systemd.calls))

    def test_restart_always_override_refuses_before_freeze_or_stop(self):
        self.systemd.restart = 'always'
        with self.assertRaisesRegex(RuntimeError, 'unsupported worker Restart policy'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] in ('freeze', 'stop', 'kill') for call in self.systemd.calls))
        self.assertIsNone(self.subject.load())

    def test_override_added_during_retry_refuses_before_freeze(self):
        self.subject.prepare('1')
        self.systemd.environment = 'PXE_MASTER_KEY_PATH=/wrong/key'
        self.systemd.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Environment override'):
            self.subject.prepare('1')
        self.assertFalse(any(call[0] in ('freeze', 'stop') for call in self.systemd.calls))

    def test_stop_failure_compensates_on_original_code(self):
        self.systemd.fail_stop = True
        original = set(self.systemd.active)
        with self.assertRaisesRegex(RuntimeError, 'stop failed'):
            self.subject.prepare('1')
        self.assertEqual(self.systemd.active, original)
        self.assertIsNone(self.subject.load())

    def test_failed_compensation_preserves_journal(self):
        self.systemd.fail_stop = True
        self.systemd.fail_start.add('pxe-tools-init.service')
        with self.assertRaisesRegex(RuntimeError, 'stop failed'):
            self.subject.prepare('1')
        self.assertIsNotNone(self.subject.load())

    def test_target_failure_happens_before_worker_can_take_new_job(self):
        self.subject.prepare('1')
        self.systemd.fail_start.add('pxe-tools-admin.target')
        self.systemd.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'did not resume'):
            self.subject.configure()
        starts = [call[-1] for call in self.systemd.calls if call[0] == 'start']
        self.assertNotIn('pxe-tools-worker.service', starts)
        self.assertIsNotNone(self.subject.load())

    def test_interrupted_capture_is_not_treated_as_prepared_snapshot(self):
        self.subject.capture('1')
        with self.assertRaisesRegex(RuntimeError, 'interrupted.*preparation'):
            self.subject.prepare('1')

    def test_snapshot_uses_effective_key_outside_etc_and_records_original_metadata(self):
        native = self.root / 'var/lib/pxe-tools-native'
        (native / 'runtime.env').write_text('PXE_MASTER_KEY_PATH=/private/key\n')
        (self.root / 'private').mkdir()
        key = self.root / 'private/key'
        key.write_bytes(b'z' * 32)
        key.chmod(0o440)
        self.subject.prepare('1')
        snapshot = self.snapshot()
        self.assertEqual((snapshot / 'files/private/key').read_bytes(), b'z' * 32)
        entries = json.loads((snapshot / 'manifest.json').read_text())['files']
        recorded = next(entry for entry in entries if entry['path'] == 'private/key')
        self.assertEqual(recorded['mode'], 0o440)

    def test_retention_only_removes_older_completed_automatic_snapshots(self):
        manual = self.subject.home / 'manual'
        manual.mkdir()
        failed = self.subject.home / ('a' * 32)
        failed.mkdir(mode=0o700)
        identifiers = []
        for version in ('1', '2', '3', '4'):
            self.subject.prepare(version)
            identifiers.append(self.subject.load()['id'])
            self.subject.configure()
        self.assertFalse((self.subject.home / identifiers[0]).exists())
        self.assertTrue(all((self.subject.home / item).is_dir() for item in identifiers[1:]))
        self.assertTrue(manual.is_dir())
        self.assertTrue(failed.is_dir())


if __name__ == '__main__':
    unittest.main()
