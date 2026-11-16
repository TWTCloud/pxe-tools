#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Persistent removal barriers, exercised exclusively in temporary trees.

The fake runner never invokes systemd or dpkg. Actual reboot and package
interaction require the separately authorised native Linux receipt.
"""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / 'packaging/native/uninstall-apt.py'
spec = importlib.util.spec_from_file_location('uninstall_for_masks', SCRIPT)
uninstall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstall)


class FakeSystemd:
    def __init__(self, unit_dir, units):
        self.unit_dir = unit_dir
        self.active = {unit: 'inactive' for unit in units}
        self.preexisting = set()
        self.runtime_masked = set()
        self.calls = []
        self.fail_reload = False

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if command[0] not in ('systemctl', '/usr/bin/systemctl'):
            raise AssertionError('unexpected executable in isolated test')
        action = command[1]
        unit = command[-1]
        status = 0
        output = ''
        if action == 'daemon-reload':
            status = int(self.fail_reload)
        elif action == 'is-enabled':
            path = self.unit_dir / unit
            output = ('masked' if unit in self.preexisting or (path.is_symlink() and os.readlink(path) == '/dev/null')
                      else 'masked-runtime' if unit in self.runtime_masked else 'static')
        elif action == 'show':
            prop = next((value.split('=', 1)[1] for value in command if value.startswith('--property=')), '')
            if prop == 'ActiveState':
                output = self.active[unit]
            elif prop == 'LoadState':
                path = self.unit_dir / unit
                output = 'masked' if unit in self.runtime_masked or (path.is_symlink() and os.readlink(path) == '/dev/null') else 'loaded'
            elif prop == 'ControlGroup':
                output = ''
            elif prop == 'FragmentPath':
                output = '/usr/lib/systemd/system/' + unit
            elif prop == 'DropInPaths':
                output = ''
            else:
                raise AssertionError('unexpected systemd property: ' + repr(command))
        else:
            raise AssertionError('unexpected systemd action: ' + repr(command))
        return subprocess.CompletedProcess(command, status, stdout=output + '\n', stderr='fixture failure' if status else '')


class FakeTransaction:
    def __init__(self, unit_dir):
        self.unit_dir = unit_dir
        self.purge_started = False
        self.events = []
        self.on_record = None

    def record_mask(self, unit, temporary, dev, ino, phase):
        temp = self.unit_dir / temporary
        dest = self.unit_dir / unit
        self.events.append({
            'unit': unit, 'temporary': temporary, 'dev': dev, 'ino': ino,
            'phase': phase, 'temp_exists': temp.is_symlink(),
            'dest_exists': dest.exists() or dest.is_symlink(),
        })
        if self.on_record:
            self.on_record(unit, temporary, phase)


class PersistentMaskFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-removal-mask-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.units = ('pxe-tools-worker.service', 'pxe-tools-php.service')
        self.unit_dir = self.root / 'etc/systemd/system'
        self.unit_dir.mkdir(parents=True)
        self.systemd = FakeSystemd(self.unit_dir, self.units)
        self.transaction = FakeTransaction(self.unit_dir)
        self.sentinel = self.unit_dir / 'nginx.service'
        self.sentinel.write_text('third-party unit; keep')
        self.external = self.root / 'external-sentinel'
        self.external.write_text('outside; keep')

    def barrier(self, units=None, mounts=()):
        return uninstall.persistent_masks(self.root, self.systemd,
            self.units if units is None else units, self.transaction, owner=None, mounts=mounts)

    def assert_third_party_intact(self):
        self.assertEqual(self.sentinel.read_text(), 'third-party unit; keep')
        self.assertEqual(self.external.read_text(), 'outside; keep')
        self.assertFalse(any(call[1] in ('stop', 'start', 'disable', 'enable', 'mask', 'unmask')
                             for call in self.systemd.calls))

    def test_each_mask_has_journalled_temporary_inode_before_publication(self):
        with self.barrier():
            for unit in self.units:
                link = self.unit_dir / unit
                self.assertTrue(link.is_symlink())
                self.assertEqual(os.readlink(link), '/dev/null')
                before = [event for event in self.transaction.events
                          if event['unit'] == unit and event['temp_exists'] and not event['dest_exists']]
                self.assertTrue(before, 'temporary identity must be recorded before the final link')
                event = before[0]
                temp = self.unit_dir / event['temporary']
                self.assertTrue(temp.name.startswith('.'))
                temp_info = temp.lstat()
                final_info = link.lstat()
                self.assertTrue(stat.S_ISLNK(temp_info.st_mode))
                self.assertEqual(os.readlink(temp), '/dev/null')
                self.assertEqual((temp_info.st_dev, temp_info.st_ino), (event['dev'], event['ino']))
                self.assertEqual((final_info.st_dev, final_info.st_ino), (event['dev'], event['ino']))
                self.assertGreaterEqual(final_info.st_nlink, 2)
        self.assertEqual(sorted(path.name for path in self.unit_dir.iterdir()), ['nginx.service'])
        for unit in self.units:
            phases = [event['phase'] for event in self.transaction.events if event['unit'] == unit]
            self.assertEqual(phases, ['prepared', 'published', 'removed'])
        self.assertTrue(any(call[1] == 'daemon-reload' for call in self.systemd.calls))
        self.assert_third_party_intact()

    def test_preexisting_permanent_mask_is_never_claimed_or_deleted(self):
        existing = self.unit_dir / self.units[0]
        existing.symlink_to('/dev/null')
        original = existing.lstat()
        self.systemd.preexisting.add(self.units[0])
        with self.barrier():
            self.assertEqual(existing.lstat().st_ino, original.st_ino)
        self.assertTrue(existing.is_symlink())
        self.assertEqual(existing.lstat().st_ino, original.st_ino)
        self.assertFalse(any(event['unit'] == self.units[0] for event in self.transaction.events))
        self.assert_third_party_intact()

    def test_existing_runtime_mask_gets_persistent_guard_without_losing_original(self):
        unit = self.units[0]
        self.systemd.runtime_masked.add(unit)
        with self.barrier():
            permanent = self.unit_dir / unit
            self.assertTrue(permanent.is_symlink())
            self.assertEqual(os.readlink(permanent), '/dev/null')
            self.assertTrue(any(event['unit'] == unit and event['phase'] == 'prepared'
                                for event in self.transaction.events))
        self.assertIn(unit, self.systemd.runtime_masked)
        self.assertFalse((self.unit_dir / unit).is_symlink())
        self.assert_third_party_intact()

    def test_runtime_mask_remains_protected_across_reboot_after_purge_failure(self):
        unit = self.units[0]
        self.systemd.runtime_masked.add(unit)
        with self.assertRaisesRegex(RuntimeError, 'dpkg'):
            with self.barrier():
                self.transaction.purge_started = True
                raise RuntimeError('dpkg')
        # Simulate runtime state disappearing on reboot; persistent guard stays.
        self.systemd.runtime_masked.clear()
        permanent = self.unit_dir / unit
        self.assertTrue(permanent.is_symlink())
        self.assertEqual(os.readlink(permanent), '/dev/null')
        self.assert_third_party_intact()

    def test_local_override_refuses_without_overwriting_or_removing_it(self):
        override = self.unit_dir / self.units[1]
        override.write_text('administrator override')
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('an administrator unit must not be masked')
        self.assertEqual(override.read_text(), 'administrator override')
        self.assertFalse((self.unit_dir / self.units[0]).exists())
        self.assert_third_party_intact()

    def test_third_party_alias_is_never_followed_or_removed(self):
        override = self.unit_dir / self.units[1]
        override.symlink_to(self.external)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('an administrator alias must not be masked')
        self.assertTrue(override.is_symlink())
        self.assertEqual(os.readlink(override), str(self.external))
        self.assert_third_party_intact()

    def test_collision_after_recording_does_not_overwrite_new_file(self):
        target = self.unit_dir / self.units[0]
        def collide(unit, temporary, phase):
            if unit == self.units[0] and not (target.exists() or target.is_symlink()):
                target.write_text('concurrent administrator change')
                self.transaction.on_record = None
        self.transaction.on_record = collide
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('publishing over a concurrent file must fail')
        self.assertEqual(target.read_text(), 'concurrent administrator change')
        self.assert_third_party_intact()

    def test_replaced_mask_is_preserved_and_reported_on_cleanup(self):
        victim = self.unit_dir / self.units[0]
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                victim.unlink()
                victim.write_text('replacement by administrator')
        self.assertEqual(victim.read_text(), 'replacement by administrator')
        self.assert_third_party_intact()

    def test_failure_before_purge_compensates_our_masks_only(self):
        with self.assertRaisesRegex(RuntimeError, 'preflight'):
            with self.barrier():
                raise RuntimeError('preflight')
        for unit in self.units:
            self.assertFalse((self.unit_dir / unit).exists())
            self.assertFalse((self.unit_dir / unit).is_symlink())
        self.assert_third_party_intact()

    def test_failure_after_purge_started_retains_masks_for_recovery(self):
        with self.assertRaisesRegex(RuntimeError, 'dpkg'):
            with self.barrier():
                self.transaction.purge_started = True
                raise RuntimeError('dpkg')
        for unit in self.units:
            path = self.unit_dir / unit
            self.assertTrue(path.is_symlink())
            self.assertEqual(os.readlink(path), '/dev/null')
            self.assertTrue(any(event['unit'] == unit for event in self.transaction.events))
        self.assert_third_party_intact()

    def test_daemon_reload_failure_refuses_and_preserves_other_units(self):
        self.systemd.fail_reload = True
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('reload failed')
        self.assert_third_party_intact()

    def test_non_product_unit_is_rejected(self):
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier(('nginx.service',)):
                self.fail('shared nginx must not be masked')
        self.assert_third_party_intact()

    def test_inactive_unit_with_surviving_cgroup_process_is_refused(self):
        group = self.root / 'sys/fs/cgroup/system.slice/pxe-tools-worker.service'
        group.mkdir(parents=True)
        (group / 'cgroup.procs').write_text('123\n')
        original = self.systemd
        def runner(command, **kwargs):
            if command[1] == 'show' and '--property=ControlGroup' in command and command[-1] == self.units[0]:
                return subprocess.CompletedProcess(command, 0, stdout='/system.slice/pxe-tools-worker.service\n', stderr='')
            return original(command, **kwargs)
        self.systemd = runner
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('surviving child must block removal')
        self.assertEqual((group / 'cgroup.procs').read_text(), '123\n')

    def test_linked_cgroup_ancestor_is_never_followed(self):
        cgroups = self.root / 'sys/fs/cgroup'
        cgroups.mkdir(parents=True)
        elsewhere = self.root / 'other-cgroup'
        (elsewhere / 'pxe-tools-worker.service').mkdir(parents=True)
        (elsewhere / 'pxe-tools-worker.service/cgroup.procs').write_text('')
        (cgroups / 'system.slice').symlink_to(elsewhere, target_is_directory=True)
        original = self.systemd
        def runner(command, **kwargs):
            if command[1] == 'show' and '--property=ControlGroup' in command and command[-1] == self.units[0]:
                return subprocess.CompletedProcess(command, 0, stdout='/system.slice/pxe-tools-worker.service\n', stderr='')
            return original(command, **kwargs)
        self.systemd = runner
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier(): self.fail('linked cgroup ancestor must be rejected')
        self.assertEqual((elsewhere / 'pxe-tools-worker.service/cgroup.procs').read_text(), '')

    def test_active_unit_refuses_without_touching_unit_files(self):
        self.systemd.active[self.units[0]] = 'active'
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('active units must not be masked blindly')
        self.assertEqual(sorted(path.name for path in self.unit_dir.iterdir()), ['nginx.service'])
        self.assert_third_party_intact()

    def test_mount_on_systemd_directory_or_parent_is_refused_before_mutation(self):
        for mount in ('/etc/systemd', '/etc/systemd/system'):
            with self.subTest(mount=mount):
                with self.assertRaises((OSError, ValueError, RuntimeError)):
                    with self.barrier(mounts=(mount,)):
                        self.fail('mount boundaries must be preserved')
                self.assertEqual(sorted(path.name for path in self.unit_dir.iterdir()), ['nginx.service'])
                self.assertEqual(self.transaction.events, [])
                self.assert_third_party_intact()

    def test_failed_preparation_journal_never_publishes_the_mask(self):
        def fail_record(unit, temporary, phase):
            if phase == 'prepared':
                raise RuntimeError('journal fsync failed')
        self.transaction.on_record = fail_record
        with self.assertRaisesRegex(RuntimeError, 'journal'):
            with self.barrier():
                self.fail('unrecorded mask must not be published')
        for unit in self.units:
            self.assertFalse((self.unit_dir / unit).is_symlink())
            self.assertFalse((self.unit_dir / unit).exists())
        self.assert_third_party_intact()

    def test_symlinked_systemd_ancestor_refuses_without_following_it(self):
        etc = self.root / 'etc'
        elsewhere = self.root / 'elsewhere'
        etc.rename(elsewhere)
        etc.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.barrier():
                self.fail('linked ancestors must not be followed')
        self.assertEqual((elsewhere / 'systemd/system/nginx.service').read_text(), 'third-party unit; keep')
        self.assertEqual(self.external.read_text(), 'outside; keep')

    def test_journal_failure_after_publication_does_not_touch_other_files(self):
        def fail_record(unit, temporary, phase):
            if phase == 'published':
                raise RuntimeError('journal write failed')
        self.transaction.on_record = fail_record
        with self.assertRaisesRegex(RuntimeError, 'journal'):
            with self.barrier():
                self.fail('cannot proceed if publication is unrecorded')
        self.assert_third_party_intact()

    def test_repeated_success_does_not_change_preexisting_mask(self):
        existing = self.unit_dir / self.units[0]
        existing.symlink_to('/dev/null')
        original = existing.lstat()
        self.systemd.preexisting.add(self.units[0])
        for _ in range(2):
            with self.barrier():
                pass
        self.assertEqual(existing.lstat().st_ino, original.st_ino)
        self.assertEqual(os.readlink(existing), '/dev/null')
        self.assert_third_party_intact()


if __name__ == '__main__':
    unittest.main()
