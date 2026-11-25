#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise interruption and explicit restart exclusively in temporary roots.

No installed package, real account, systemd service, signal, or dpkg command is
used here.  A separate Linux/systemd/dpkg qualification remains necessary.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'uninstall_roundtrip_recovery_fixtures', ROOT / 'tests/unit/test_uninstall_roundtrip.py')
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
uninstall = fixtures.uninstall
UNITS = fixtures.UNITS


class InterruptedRemoval(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SyntheticRoundTrip(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.store = self.fixture.install_fixture(with_module=True)
        self.receipt = self.root / 'var/lib/pxe-tools-uninstall/state.json'
        self.data = self.root / 'var/lib/pxe-tools/instance.sqlite'

    def resume(self):
        # generation_matches is fixture injection only: real use must validate
        # strong generation evidence with the code in the standalone script.
        return uninstall.resume_uninstall(
            self.root, self.fixture.runner, UNITS, lambda: (),
            owner=os.geteuid(), account_lookup=self.fixture.accounts.snapshot,
            generation_matches=self.store.generation.matches, lifecycle=self.fixture.life)

    def resume_pre_purge(self):
        return uninstall.resume_uninstall(
            self.root, self.fixture.runner, UNITS, lambda: (), owner=os.geteuid(),
            lifecycle=self.fixture.life, ownership=self.store,
            account_lookup=self.fixture.accounts.snapshot,
            generation_matches=self.store.generation.matches)

    def prepare_legacy(self):
        with self.store._locked(create=False) as directory:
            self.store._write(directory, {'format': 2, 'directories': {}})
        def identity(fd):
            st = os.fstat(fd)
            return {'dev': st.st_dev, 'ino': st.st_ino, 'btime_sec': 1, 'btime_nsec': 1}
        def matches(fd, proof):
            st = os.fstat(fd)
            return (st.st_dev, st.st_ino) == (proof['dev'], proof['ino'])
        def opener(fd, name):
            return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        def snapshot(root, *, mounts, owner):
            return uninstall.snapshot_legacy_paths(root, mounts=mounts, owner=owner,
                                                   opener=opener, identity=identity)
        common = {'owner': os.geteuid(), 'record': self.store.read(), 'ownership': self.store,
                  'account_lookup': self.fixture.accounts.snapshot, 'allow_legacy': True,
                  'legacy_snapshotter': snapshot, 'legacy_matcher': matches}
        preview = uninstall.run_uninstall(self.root, self.fixture.runner, self.fixture.life,
                                         UNITS, lambda: (), apply=False, **common)
        return common, preview, matches

    def test_legacy_interruption_after_purge_can_resume_without_claiming_account(self):
        common, preview, matches = self.prepare_legacy()
        original = uninstall.remove_tree
        def interrupt(root, path, **kwargs):
            if path == '/etc/pxe-tools' and not kwargs.get('dry_run', False):
                raise OSError('simulated interruption')
            return original(root, path, **kwargs)
        with patch.object(uninstall, 'remove_tree', side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, 'purge succeeded'):
                uninstall.run_uninstall(self.root, self.fixture.runner, self.fixture.life, UNITS, lambda: (),
                                        apply=True, legacy_expected=preview['legacy_plan_sha256'], **common)
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertIsNotNone(self.fixture.accounts.account)
        state = json.loads(self.receipt.read_text())
        self.assertEqual(state['record']['source'], 'explicit-legacy-consent')
        uninstall.resume_uninstall(self.root, self.fixture.runner, UNITS, lambda: (),
                                   owner=os.geteuid(), account_lookup=self.fixture.accounts.snapshot,
                                   generation_matches=matches, lifecycle=self.fixture.life)
        self.assertFalse(self.data.exists())
        self.assertIsNotNone(self.fixture.accounts.account)
        self.fixture.assert_external_survives()

    def test_legacy_interruption_before_purge_requires_fresh_preview(self):
        common, preview, matches = self.prepare_legacy()
        original = os.symlink
        def interrupt(source, destination, *args, **kwargs):
            if os.fspath(destination).startswith('.pxe-uninstall-'):
                raise uninstall.BarrierRecoveryRequired('simulated interruption')
            return original(source, destination, *args, **kwargs)
        with patch.object(os, 'symlink', side_effect=interrupt):
            with self.assertRaises(uninstall.BarrierRecoveryRequired):
                uninstall.run_uninstall(self.root, self.fixture.runner, self.fixture.life, UNITS, lambda: (),
                                        apply=True, legacy_expected=preview['legacy_plan_sha256'], **common)
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertEqual(uninstall.resume_uninstall(
            self.root, self.fixture.runner, UNITS, lambda: (), owner=os.geteuid(),
            lifecycle=self.fixture.life, ownership=self.store,
            account_lookup=self.fixture.accounts.snapshot, generation_matches=matches), 'retry-legacy')
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.data.is_file())
        self.assertIn('pxe-tools', self.fixture.package_states)

    def assert_barrier_held(self):
        for unit in UNITS:
            path = self.root / 'etc/systemd/system' / unit
            self.assertTrue(path.is_symlink(), unit)
            self.assertEqual(os.readlink(path), '/dev/null')

    def interrupt_after_purge(self):
        # The synthetic dpkg runner removes the package payload inside self.root.
        # Interrupt before userdel or any instance data deletion.
        with patch.object(uninstall, 'remove_account', side_effect=RuntimeError('simulated power loss')):
            with self.assertRaises(RuntimeError):
                self.fixture.uninstall_fixture(self.store)
        self.assertNotIn('pxe-tools', self.fixture.package_states)
        self.assertNotIn('pxe-tools-ansible', self.fixture.package_states)
        self.assertFalse((self.root / 'usr/lib/pxe-tools').exists())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def install_synthetic_nginx_verifier(self):
        """Model a private verifier and nginx receipt without touching nginx."""
        control = self.root / 'nginx-fixture'
        control.mkdir()
        (control / 'status.json').write_text(json.dumps(
            {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}))
        (control / 'resources.json').write_text(json.dumps({'fixture': 'unchanged'}))
        helper = self.root / 'usr/lib/pxe-tools/native/reconcile-nginx.py'
        helper.parent.mkdir(parents=True)
        helper.write_text('''\
import json
from pathlib import Path
from contextlib import nullcontext
class Reconciler:
    def __init__(self, root=Path('/'), run=None):
        self.root = Path(root)
    def state(self):
        return json.loads((self.root / 'nginx-fixture/status.json').read_text())
    def stock(self):
        return json.loads((self.root / 'nginx-fixture/resources.json').read_text())
def stable_nginx_lock(root=Path('/'), *, owner=0):
    return nullcontext()
''')
        helper.chmod(0o600)
        folder = self.root / 'var/lib/pxe-tools-nginx-ownership'
        folder.mkdir(mode=0o700)
        (folder / 'lock').touch(mode=0o600)
        state = {'format': 1, 'service': 'nginx.service', 'phase': 'complete',
                 'before': {'active': 'active', 'enabled': 'enabled'},
                 'after': {'active': 'inactive', 'enabled': 'disabled'},
                 'resources': {'fixture': 'unchanged'}, 'identity': {'pid': '1'},
                 'provenance': {'source': 'apt-and-dpkg', 'nginx_previously_absent': True,
                                'start': 'fixture', 'end': None, 'core': 'pxe-tools',
                                'initial_packages': {'nginx': '1', 'nginx-common': '1', 'pxe-tools': '1'}}}
        (folder / 'state.json').write_text(json.dumps(state))
        (folder / 'state.json').chmod(0o600)
        return uninstall.load_reconciler(self.root, self.fixture.runner, owner=os.getuid())

    def interrupt_with_nginx_after_purge(self):
        reconciler = self.install_synthetic_nginx_verifier()
        with patch.object(uninstall, 'remove_account', side_effect=RuntimeError('simulated power loss')):
            with self.assertRaises(RuntimeError):
                uninstall.run_uninstall(self.root, self.fixture.runner, self.fixture.life,
                    UNITS, lambda: (), owner=os.getuid(), apply=True, record=self.store.read(),
                    ownership=self.store, reconciler=reconciler,
                    account_lookup=self.fixture.accounts.snapshot)
        self.assertFalse((self.root / 'usr/lib/pxe-tools').exists())
        self.assertTrue((self.root / 'var/lib/pxe-tools-nginx-ownership/state.json').is_file())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()

    def interrupt_mask_publication(self, *, after_link):
        """Model a crash at linkat without actually killing a test process."""
        original_link, original_unlink = os.link, os.unlink
        def interrupted_link(source, destination, *args, **kwargs):
            if os.fspath(source).startswith('.pxe-uninstall-'):
                if after_link:
                    original_link(source, destination, *args, **kwargs)
                raise OSError('simulated interruption at mask publication')
            return original_link(source, destination, *args, **kwargs)
        def interrupted_unlink(path, *args, **kwargs):
            # For the temporary-only case, preserve the on-disk state as a
            # power loss would, instead of allowing in-process compensation.
            if os.fspath(path).startswith('.pxe-uninstall-'):
                raise OSError('simulated interruption before mask cleanup')
            return original_unlink(path, *args, **kwargs)
        with patch.object(os, 'link', side_effect=interrupted_link), \
             patch.object(os, 'unlink', side_effect=interrupted_unlink):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.assertTrue(self.receipt.is_file())
        temporaries = list((self.root / 'etc/systemd/system').glob('.pxe-uninstall-*'))
        self.assertEqual(len(temporaries), 1)
        self.assertTrue(temporaries[0].is_symlink())
        self.assertEqual(os.readlink(temporaries[0]), '/dev/null')
        return temporaries[0], self.root / 'etc/systemd/system' / UNITS[0]

    def interrupt_mask_creation(self, *, after_symlink):
        """Model process loss before or immediately after creating the link."""
        original = os.symlink
        interrupted = []
        def interrupt(source, destination, *args, **kwargs):
            if os.fspath(destination).startswith('.pxe-uninstall-'):
                if after_symlink:
                    original(source, destination, *args, **kwargs)
                interrupted.append(os.fspath(destination))
                # Preserve exactly the on-disk state at the injected boundary.
                raise uninstall.BarrierRecoveryRequired('simulated abrupt process loss')
            return original(source, destination, *args, **kwargs)
        with patch.object(os, 'symlink', side_effect=interrupt):
            with self.assertRaises(uninstall.BarrierRecoveryRequired):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(len(interrupted), 1)
        self.assertTrue(self.receipt.is_file())
        state = json.loads(self.receipt.read_bytes())
        proof = state['masks'][UNITS[0]]
        self.assertEqual(proof['phase'], 'creating')
        self.assertEqual((proof['dev'], proof['ino']), (0, 0))
        self.assertEqual(proof['temporary'], interrupted[0])
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        return self.root / 'etc/systemd/system' / interrupted[0]

    def interrupt_receipt_replacement(self):
        """Keep the old receipt plus its fully written unpublished successor."""
        self.interrupt_after_purge()
        original_replace = os.replace
        old = self.receipt.read_bytes()
        interrupted = []
        def stop_before_replace(source, destination, *args, **kwargs):
            if (os.fspath(source).startswith('.state-') and
                    os.fspath(destination) == 'state.json' and not interrupted):
                interrupted.append(os.fspath(source))
                raise OSError('simulated power loss before receipt replacement')
            return original_replace(source, destination, *args, **kwargs)
        with patch.object(os, 'replace', side_effect=stop_before_replace):
            with self.assertRaises((RuntimeError, OSError)):
                self.resume()
        self.assertEqual(len(interrupted), 1)
        self.assertEqual(self.receipt.read_bytes(), old)
        self.assertIsInstance(json.loads(old), dict)
        temporary = self.receipt.parent / interrupted[0]
        self.assertTrue(temporary.is_file())
        self.assertFalse(temporary.is_symlink())
        self.assertIsInstance(json.loads(temporary.read_bytes()), dict)
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        return temporary

    def interrupt_initial_receipt(self):
        """Stop after writing the first receipt, before its first replace."""
        original_replace = os.replace
        interrupted = []
        def stop_before_initial_replace(source, destination, *args, **kwargs):
            if (os.fspath(source).startswith('.state-') and
                    os.fspath(destination) == 'state.json' and not interrupted):
                interrupted.append(os.fspath(source))
                raise OSError('simulated power loss before first receipt replacement')
            return original_replace(source, destination, *args, **kwargs)
        before_active = dict(self.fixture.systemd.active)
        with patch.object(os, 'replace', side_effect=stop_before_initial_replace):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(len(interrupted), 1)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.receipt.is_symlink())
        temporary = self.receipt.parent / interrupted[0]
        self.assertTrue(temporary.is_file())
        self.assertFalse(temporary.is_symlink())
        state = json.loads(temporary.read_bytes())
        self.assertEqual(state['phase'], 'preparing')
        self.assertIsNone(state['worker'])
        self.assertEqual(state['masks'], {})
        self.assertEqual(state['initial_units'], {})
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls))
        return temporary, before_active

    def test_failed_and_partial_dpkg_are_not_retried_or_cleaned_automatically(self):
        self.fixture.fail_purge = True
        with self.assertRaises(RuntimeError):
            self.fixture.uninstall_fixture(self.store)
        self.fixture.package_states['pxe-tools'] = 'half-installed'
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        before = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        with self.assertRaises((RuntimeError, ValueError)):
            self.resume()
        after = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        self.assertEqual(after, before, 'resume must not silently retry a partial purge')
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assertIsNotNone(self.fixture.accounts.account)
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_resume_after_successful_purge_does_not_need_installed_helpers_and_is_idempotent(self):
        self.interrupt_after_purge()
        before = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        # Installed Python helpers were removed by the fake dpkg operation.
        # A restart must use only the standalone code and durable journal.
        with patch.object(uninstall, 'load_package_helper', side_effect=AssertionError('installed helper used')):
            self.resume()
            self.resume()
        self.assertEqual(len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg']), before)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.assertIsNone(self.fixture.accounts.account)
        self.assertIsNone(self.fixture.accounts.group)
        for unit in UNITS:
            self.assertFalse((self.root / 'etc/systemd/system' / unit).exists())
            self.assertFalse((self.root / 'etc/systemd/system' / unit).is_symlink())
        self.fixture.assert_external_survives()

    def test_incomplete_install_resumes_after_package_purge(self):
        import shutil
        original = self.store.read()
        record = {'format': 2, 'base_phase': 'runtime-prepared', 'directories': {
            path: original['directories'][path] for path in uninstall.INITIAL_RUNTIME_TREES}}
        for relative in ('etc/pxe-tools', 'var/lib/pxe-tools', 'var/lib/pxe-tools-ansible',
                         'var/lib/pxe-tools-tftp'):
            shutil.rmtree(self.root / relative)
        with self.store._locked(create=False) as directory:
            self.store._write(directory, record)
        old_log = self.root / 'var/log/pxe-tools/service.log'
        old_log.parent.mkdir(parents=True, exist_ok=True)
        old_log.write_text('synthetic-log')
        original_remove = uninstall.remove_tree
        def interrupt(root, path, **kwargs):
            if path == '/var/lib/pxe-tools-http' and not kwargs.get('dry_run', False):
                raise OSError('simulated interruption after package purge')
            return original_remove(root, path, **kwargs)
        with patch.object(uninstall, 'remove_tree', side_effect=interrupt):
            with self.assertRaises(RuntimeError): self.fixture.uninstall_fixture(self.store)
        self.assertNotIn('pxe-tools', self.fixture.package_states)
        self.assertTrue(self.receipt.is_file())
        self.resume()
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.root / 'var/lib/pxe-tools-native').exists())
        self.assertFalse((self.root / 'var/lib/pxe-tools-http').exists())
        self.assertEqual(old_log.read_text(), 'synthetic-log')
        self.assertIsNotNone(self.fixture.accounts.account)

    def test_resume_revalidates_nginx_using_saved_verifier_after_payload_removal(self):
        self.interrupt_with_nginx_after_purge()
        with patch.object(uninstall, 'load_package_helper', side_effect=AssertionError('installed helper used')):
            self.resume()
        self.assertFalse((self.root / 'var/lib/pxe-tools-nginx-ownership').exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.assertFalse(any(command[0] == 'systemctl' and command[-1] == 'nginx.service'
                             for command in self.fixture.calls))
        self.assertEqual(json.loads((self.root / 'nginx-fixture/status.json').read_text()),
                         {'ActiveState': 'inactive', 'UnitFileState': 'disabled'})
        self.fixture.assert_external_survives()

    def test_changed_nginx_after_purge_blocks_all_cleanup_and_preserves_journal(self):
        self.interrupt_with_nginx_after_purge()
        status = self.root / 'nginx-fixture/status.json'
        status.write_text(json.dumps({'ActiveState': 'active', 'UnitFileState': 'enabled'}))
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertTrue((self.root / 'var/lib/pxe-tools-nginx-ownership/state.json').is_file())
        self.assert_barrier_held()
        self.assertFalse(any(command[0] == 'systemctl' and command[-1] == 'nginx.service'
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_changed_nginx_configuration_blocks_recovery_before_data_cleanup(self):
        self.interrupt_with_nginx_after_purge()
        resources = self.root / 'nginx-fixture/resources.json'
        resources.write_text(json.dumps({'fixture': 'administrator changed configuration'}))
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(json.loads(resources.read_text()),
                         {'fixture': 'administrator changed configuration'})
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertTrue((self.root / 'var/lib/pxe-tools-nginx-ownership/state.json').is_file())
        self.assert_barrier_held()
        self.assertFalse(any(command[0] == 'systemctl' and command[-1] == 'nginx.service'
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_recreated_path_is_preserved_and_blocks_recovery(self):
        self.interrupt_after_purge()
        tree = self.root / 'var/lib/pxe-tools'
        saved = self.root / 'var/lib/previous-instance'
        tree.rename(saved)
        tree.mkdir()
        (tree / 'foreign').write_text('do not remove')
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual((tree / 'foreign').read_text(), 'do not remove')
        self.assertTrue((saved / 'instance.sqlite').is_file())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_changed_ansible_account_is_not_deleted_on_recovery(self):
        self.interrupt_after_purge()
        account = self.fixture.accounts.account
        account.pw_gecos = 'operator replaced identity'
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertIs(self.fixture.accounts.account, account)
        self.assertEqual(account.pw_gecos, 'operator replaced identity')
        self.assertFalse(any(Path(command[0]).name == 'userdel' for command in self.fixture.calls))
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_active_service_blocks_recovery_without_stop_or_cleanup(self):
        self.interrupt_after_purge()
        self.fixture.systemd.active[UNITS[0]] = 'active'
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(self.fixture.systemd.active[UNITS[0]], 'active')
        self.assertFalse(any(command[:2] == ['systemctl', 'stop'] for command in self.fixture.calls))
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_optional_update_mask_is_recovered_and_blocks_if_active(self):
        unit = uninstall.APT_UPDATE_UNIT
        packaged = self.root / 'usr/lib/systemd/system' / unit
        packaged.write_bytes((ROOT / 'rust/packaging' / unit).read_bytes())
        self.fixture.systemd.active[unit] = 'inactive'
        original_capture = self.fixture.life.capture

        def capture(version):
            # The installed upgrade helper records the core units only.
            state = original_capture(version)
            del state['units'][unit]
            del state['active'][unit]
            self.fixture.life.save(state)
            return state

        with patch.object(self.fixture.life, 'capture', side_effect=capture):
            self.interrupt_after_purge()
        packaged.unlink()  # Model removal of this additional package unit.
        mask = self.root / 'etc/systemd/system' / unit
        self.assertTrue(mask.is_symlink())
        self.assertIn(unit, json.loads(self.receipt.read_text())['masks'])

        self.fixture.systemd.active[unit] = 'active'
        with self.assertRaisesRegex(RuntimeError, 'service is active during recovery: ' + unit):
            self.resume()
        self.assertTrue(self.data.is_file())
        self.assertTrue(mask.is_symlink())

        self.fixture.systemd.active[unit] = 'inactive'
        self.resume()
        self.assertFalse(os.path.lexists(mask))
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.fixture.assert_external_survives()

    def test_inactive_service_with_residual_cgroup_process_blocks_recovery(self):
        self.interrupt_after_purge()
        unit = UNITS[0]
        self.assertEqual(self.fixture.systemd.active[unit], 'inactive')
        (self.fixture.life.group / 'cgroup.procs').write_text('456\n')
        original_runner = self.fixture.runner
        def runner(command, **kwargs):
            if (command[0] == 'systemctl' and command[-1] == unit and
                    '--property=ControlGroup' in command):
                self.fixture.calls.append(list(command))
                return subprocess.CompletedProcess(command, 0, stdout=self.fixture.life.CGROUP + '\n', stderr='')
            return original_runner(command, **kwargs)
        self.fixture.runner = runner
        before = len(self.fixture.calls)
        with self.assertRaisesRegex((RuntimeError, ValueError, OSError), 'process'):
            self.resume()
        self.assertEqual(self.fixture.systemd.active[unit], 'inactive')
        self.assertEqual((self.fixture.life.group / 'cgroup.procs').read_text(), '456\n')
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls[before:]))
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_changed_generation_proof_blocks_recovery_even_when_inode_is_unchanged(self):
        self.interrupt_after_purge()
        before = self.data.parent.stat()
        self.store.generation.getxattr = lambda fd, name: b'changed synthetic nonce'
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        after = self.data.parent.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_interruption_after_one_tree_was_removed_can_resume(self):
        original = uninstall.remove_tree
        removed = []
        def interrupt_after_tree(root, name, **kwargs):
            result = original(root, name, **kwargs)
            if not kwargs.get('dry_run') and not removed:
                removed.append(name)
                raise RuntimeError('simulated interruption after tree removal')
            return result
        with patch.object(uninstall, 'remove_tree', side_effect=interrupt_after_tree):
            with self.assertRaises(RuntimeError):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(len(removed), 1)
        self.assertFalse((self.root / removed[0].lstrip('/')).exists())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.resume()
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.fixture.assert_external_survives()

    def test_interruption_inside_tree_can_resume_without_following_external_link(self):
        original = uninstall.remove_tree
        interrupted = []
        def interrupt_during_tree(root, name, **kwargs):
            if name == '/var/lib/pxe-tools' and not kwargs.get('dry_run') and not interrupted:
                target = self.root / 'var/lib/pxe-tools/instance.sqlite'
                self.assertTrue(target.is_file())
                self.assertFalse(target.is_symlink())
                target.unlink()
                interrupted.append(name)
                raise RuntimeError('simulated interruption within tree')
            return original(root, name, **kwargs)
        with patch.object(uninstall, 'remove_tree', side_effect=interrupt_during_tree):
            with self.assertRaises(RuntimeError):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(interrupted, ['/var/lib/pxe-tools'])
        self.assertTrue((self.root / 'var/lib/pxe-tools').is_dir())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        self.resume()
        self.assertFalse((self.root / 'var/lib/pxe-tools').exists())
        self.fixture.assert_external_survives()

    def test_interruption_after_completion_journal_rename_can_be_resumed(self):
        original = os.rename
        interrupted = []
        def interrupt_after_rename(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if source == 'pxe-tools-uninstall' and destination == 'pxe-tools-uninstall-complete':
                interrupted.append(True)
                raise OSError('simulated interruption after completion rename')
            return result
        with patch.object(os, 'rename', side_effect=interrupt_after_rename):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(interrupted, [True])
        completed = self.root / 'var/lib/pxe-tools-uninstall-complete'
        self.assertTrue((completed / 'state.json').is_file())
        self.assertFalse(self.data.exists())
        before = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        self.resume()
        self.assertEqual(len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg']), before)
        self.assertFalse(completed.exists())
        self.assertFalse(self.receipt.exists())
        self.fixture.assert_external_survives()

    def test_completed_receipt_is_preserved_if_package_was_reinstalled(self):
        original = os.rename
        def interrupt_after_rename(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if source == 'pxe-tools-uninstall' and destination == 'pxe-tools-uninstall-complete':
                raise OSError('simulated interruption after completion rename')
            return result
        with patch.object(os, 'rename', side_effect=interrupt_after_rename):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        completed = self.root / 'var/lib/pxe-tools-uninstall-complete/state.json'
        self.assertEqual(json.loads(completed.read_bytes())['phase'], 'complete')
        before = completed.read_bytes()
        self.fixture.package_states['pxe-tools'] = 'installed'
        purge_count = sum(Path(c[0]).name == 'dpkg' for c in self.fixture.calls)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(completed.read_bytes(), before)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(sum(Path(c[0]).name == 'dpkg' for c in self.fixture.calls), purge_count)
        self.fixture.assert_external_survives()

    def test_completed_active_receipt_is_preserved_if_package_was_reinstalled(self):
        original = os.rename
        def interrupt_before_rename(source, destination, *args, **kwargs):
            if source == 'pxe-tools-uninstall' and destination == 'pxe-tools-uninstall-complete':
                raise OSError('simulated interruption before completion rename')
            return original(source, destination, *args, **kwargs)
        with patch.object(os, 'rename', side_effect=interrupt_before_rename):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(json.loads(self.receipt.read_bytes())['phase'], 'complete')
        before = self.receipt.read_bytes()
        self.fixture.package_states['pxe-tools-ansible'] = 'installed'
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.fixture.assert_external_survives()

    def test_aborted_receipt_can_be_finalized_when_packages_remain_installed(self):
        original = os.rename
        def interrupt_before_rename(source, destination, *args, **kwargs):
            if source == 'pxe-tools-uninstall' and destination == 'pxe-tools-uninstall-aborted':
                raise OSError('simulated interruption before aborted receipt rename')
            return original(source, destination, *args, **kwargs)
        def fail_preflight():
            raise RuntimeError('simulated pre-purge preflight refusal')
        self.fixture.life.environments = fail_preflight
        before_active = dict(self.fixture.systemd.active)
        with patch.object(os, 'rename', side_effect=interrupt_before_rename):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(json.loads(self.receipt.read_bytes())['phase'], 'aborted')
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertTrue(self.data.is_file())
        self.resume()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.assertFalse(any(command[:2] in (['systemctl', 'start'], ['systemctl', 'stop'])
                             for command in self.fixture.calls))
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_renamed_aborted_receipt_can_be_finalized_with_packages_installed(self):
        original = os.rename
        def interrupt_after_rename(source, destination, *args, **kwargs):
            result = original(source, destination, *args, **kwargs)
            if source == 'pxe-tools-uninstall' and destination == 'pxe-tools-uninstall-aborted':
                raise OSError('simulated interruption after aborted receipt rename')
            return result
        def fail_preflight():
            raise RuntimeError('simulated pre-purge preflight refusal')
        self.fixture.life.environments = fail_preflight
        before_active = dict(self.fixture.systemd.active)
        with patch.object(os, 'rename', side_effect=interrupt_after_rename):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        completed = self.root / 'var/lib/pxe-tools-uninstall-aborted/state.json'
        self.assertEqual(json.loads(completed.read_bytes())['phase'], 'aborted')
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.resume()
        self.assertFalse(completed.exists())
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_empty_aborted_receipt_can_be_finalized_after_interruption(self):
        original = os.rmdir
        def interrupt(name, *args, **kwargs):
            if os.fspath(name) == 'pxe-tools-uninstall-aborted':
                raise OSError('simulated interruption after receipt unlink')
            return original(name, *args, **kwargs)
        self.fixture.life.environments = lambda: (_ for _ in ()).throw(RuntimeError('preflight refusal'))
        with patch.object(os, 'rmdir', side_effect=interrupt):
            with self.assertRaises((RuntimeError, OSError)):
                self.fixture.uninstall_fixture(self.store)
        completed = self.root / 'var/lib/pxe-tools-uninstall-aborted'
        self.assertTrue(completed.is_dir())
        self.assertEqual(list(completed.iterdir()), [])
        self.resume()
        self.assertFalse(completed.exists())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_interruption_after_ownership_metadata_deletion_can_resume(self):
        original = uninstall.remove_private_journal
        interrupted = []
        def interrupt_after_metadata(root, name, *args, **kwargs):
            result = original(root, name, *args, **kwargs)
            if name == '/var/lib/pxe-tools-ownership':
                interrupted.append(name)
                raise RuntimeError('simulated interruption after ownership metadata removal')
            return result
        with patch.object(uninstall, 'remove_private_journal', side_effect=interrupt_after_metadata):
            with self.assertRaises(RuntimeError):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(interrupted, ['/var/lib/pxe-tools-ownership'])
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())
        self.assertTrue(self.receipt.is_file())
        before = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        self.resume()
        self.assertEqual(len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg']), before)
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.fixture.assert_external_survives()

    def test_native_runtime_removal_holds_masks_and_can_resume_after_interruption(self):
        original = uninstall.remove_tree
        interrupted = []
        def interrupt_after_runtime(root, name, **kwargs):
            if name == '/var/lib/pxe-tools-native' and not kwargs.get('dry_run'):
                self.assert_barrier_held()
                result = original(root, name, **kwargs)
                self.assert_barrier_held()
                interrupted.append(name)
                raise RuntimeError('simulated interruption after native runtime removal')
            return original(root, name, **kwargs)
        with patch.object(uninstall, 'remove_tree', side_effect=interrupt_after_runtime):
            with self.assertRaisesRegex(RuntimeError, 'native journal cleanup is incomplete'):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(interrupted, ['/var/lib/pxe-tools-native'])
        self.assertFalse((self.root / 'var/lib/pxe-tools-native').exists())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        before = sum(Path(command[0]).name == 'dpkg' for command in self.fixture.calls)
        self.resume()
        self.assertEqual(sum(Path(command[0]).name == 'dpkg' for command in self.fixture.calls), before)
        self.assertFalse(self.receipt.exists())
        for unit in UNITS:
            self.assertFalse((self.root / 'etc/systemd/system' / unit).is_symlink())
        self.fixture.assert_external_survives()

    def test_nginx_and_ownership_metadata_removal_hold_masks_and_resume(self):
        reconciler = self.install_synthetic_nginx_verifier()
        original = uninstall.remove_private_journal
        removed = []
        def remove_with_barrier(root, name, *args, **kwargs):
            self.assert_barrier_held()
            result = original(root, name, *args, **kwargs)
            self.assert_barrier_held()
            removed.append(name)
            if name == '/var/lib/pxe-tools-ownership':
                raise RuntimeError('simulated interruption after metadata removal')
            return result
        with patch.object(uninstall, 'remove_private_journal', side_effect=remove_with_barrier):
            with self.assertRaisesRegex(RuntimeError, 'ownership cleanup is incomplete'):
                uninstall.run_uninstall(
                    self.root, self.fixture.runner, self.fixture.life, UNITS, lambda: (),
                    owner=os.getuid(), apply=True, record=self.store.read(), ownership=self.store,
                    reconciler=reconciler, account_lookup=self.fixture.accounts.snapshot)
        self.assertEqual(removed, ['/var/lib/pxe-tools-nginx-ownership', '/var/lib/pxe-tools-ownership'])
        self.assertFalse((self.root / 'var/lib/pxe-tools-nginx-ownership').exists())
        self.assertFalse((self.root / 'var/lib/pxe-tools-ownership').exists())
        self.assertTrue(self.receipt.is_file())
        self.assert_barrier_held()
        before = sum(Path(command[0]).name == 'dpkg' for command in self.fixture.calls)
        self.resume()
        self.assertEqual(sum(Path(command[0]).name == 'dpkg' for command in self.fixture.calls), before)
        self.assertFalse(self.receipt.exists())
        for unit in UNITS:
            self.assertFalse((self.root / 'etc/systemd/system' / unit).is_symlink())
        self.assertFalse(any(command[0] == 'systemctl' and command[-1] == 'nginx.service'
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_interruption_after_unlinking_mask_can_resume_with_inode_proof(self):
        self.interrupt_after_purge()
        original = os.unlink
        interrupted = []
        def unlink_then_interrupt(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if os.fspath(path) in UNITS and not interrupted:
                interrupted.append(os.fspath(path))
                raise OSError('simulated interruption after unlinking final mask')
            return result
        with patch.object(os, 'unlink', side_effect=unlink_then_interrupt):
            with self.assertRaises((RuntimeError, OSError)):
                self.resume()
        self.assertEqual(len(interrupted), 1)
        self.assertTrue(self.receipt.is_file())
        self.assertFalse((self.root / 'etc/systemd/system' / interrupted[0]).is_symlink())
        before = len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg'])
        self.resume()
        self.assertEqual(len([c for c in self.fixture.calls if Path(c[0]).name == 'dpkg']), before)
        self.assertFalse(self.receipt.exists())
        for unit in UNITS:
            self.assertFalse((self.root / 'etc/systemd/system' / unit).is_symlink())
        self.fixture.assert_external_survives()

    def test_replaced_mask_is_preserved_and_blocks_recovery(self):
        self.interrupt_after_purge()
        path = self.root / 'etc/systemd/system' / UNITS[0]
        path.unlink()
        path.write_text('administrator replacement')
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(path.read_text(), 'administrator replacement')
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_corrupt_journal_is_preserved_without_any_cleanup(self):
        self.interrupt_after_purge()
        self.receipt.write_bytes(b'{"format": 1, "format": 2}')
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(self.receipt.read_bytes(), b'{"format": 1, "format": 2}')
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_linked_journal_is_never_followed(self):
        self.interrupt_after_purge()
        target = self.fixture.external / 'unrelated-journal'
        target.write_bytes(self.receipt.read_bytes())
        self.receipt.unlink()
        self.receipt.symlink_to(target)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertTrue(self.receipt.is_symlink())
        self.assertEqual(os.readlink(self.receipt), str(target))
        self.assertTrue(target.is_file())
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_unpublished_receipt_temporary_is_reconciled_after_interruption(self):
        temporary = self.interrupt_receipt_replacement()
        self.resume()
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary.is_symlink())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(self.data.exists())
        self.fixture.assert_external_survives()

    def test_first_valid_receipt_temporary_can_be_resumed_and_retried(self):
        temporary, before_active = self.interrupt_initial_receipt()
        self.assertEqual(self.resume_pre_purge(), 'retry')
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary.is_symlink())
        self.assertFalse(self.receipt.parent.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             or command[:2] in (['systemctl', 'start'], ['systemctl', 'stop'])
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_first_malformed_receipt_temporary_is_preserved_and_blocks_recovery(self):
        temporary, before_active = self.interrupt_initial_receipt()
        corrupt = b'{"format":1,"format":2}'
        temporary.write_bytes(corrupt)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), corrupt)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             or command[:2] in (['systemctl', 'start'], ['systemctl', 'stop'])
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_first_linked_receipt_temporary_is_preserved_without_following(self):
        temporary, before_active = self.interrupt_initial_receipt()
        target = self.fixture.external / 'backup'
        temporary.unlink()
        temporary.symlink_to(target)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), str(target))
        self.assertEqual(target.read_text(), 'external-backup')
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             or command[:2] in (['systemctl', 'start'], ['systemctl', 'stop'])
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_first_receipt_temporary_with_worker_is_not_treated_as_initial(self):
        temporary, before_active = self.interrupt_initial_receipt()
        state = json.loads(temporary.read_bytes())
        state['worker'] = {'boot_id': '9f622097-cd4d-44df-9f29-8ad323ef9405', 'pid': '123',
                           'starttime': '4242', 'cgroup': '/system.slice/pxe-tools-worker.service',
                           'phase': 'freeze_intent'}
        changed = json.dumps(state, sort_keys=True).encode()
        temporary.write_bytes(changed)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), changed)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_first_receipt_temporary_with_mask_is_not_treated_as_initial(self):
        temporary, before_active = self.interrupt_initial_receipt()
        state = json.loads(temporary.read_bytes())
        state['masks'] = {UNITS[0]: {'temporary': '.pxe-uninstall-' + '0' * 32 + '-' + UNITS[0],
                                   'dev': 0, 'ino': 0, 'phase': 'creating'}}
        changed = json.dumps(state, sort_keys=True).encode()
        temporary.write_bytes(changed)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), changed)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_first_receipt_with_captured_service_state_is_not_treated_as_initial(self):
        temporary, before_active = self.interrupt_initial_receipt()
        state = json.loads(temporary.read_bytes())
        state['initial_units'] = {UNITS[0]: {'active': True, 'enabled': 'disabled'}}
        changed = json.dumps(state, sort_keys=True).encode()
        temporary.write_bytes(changed)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), changed)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_first_receipt_with_cleanup_intent_is_not_treated_as_initial(self):
        temporary, before_active = self.interrupt_initial_receipt()
        state = json.loads(temporary.read_bytes())
        state['steps']['account'] = 'intent'
        changed = json.dumps(state, sort_keys=True).encode()
        temporary.write_bytes(changed)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), changed)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_multiple_first_receipt_temporaries_are_preserved_as_ambiguous(self):
        temporary, before_active = self.interrupt_initial_receipt()
        original = temporary.read_bytes()
        alternate = temporary.parent / ('.state-' + ('f' * 32 if temporary.name != '.state-' + 'f' * 32 else 'e' * 32))
        alternate.write_bytes(original)
        alternate.chmod(0o600)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(temporary.read_bytes(), original)
        self.assertEqual(alternate.read_bytes(), original)
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.fixture.systemd.active, before_active)
        self.assertTrue(self.data.is_file())
        self.fixture.assert_external_survives()

    def test_linked_receipt_temporary_is_preserved_without_following_it(self):
        temporary = self.interrupt_receipt_replacement()
        target = self.fixture.external / 'backup'
        temporary.unlink()
        temporary.symlink_to(target)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), str(target))
        self.assertEqual(target.read_text(), 'external-backup')
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_foreign_receipt_file_blocks_recovery_and_is_preserved(self):
        temporary = self.interrupt_receipt_replacement()
        foreign = self.receipt.parent / 'operator-file'
        foreign.write_text('do not delete')
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume()
        self.assertEqual(foreign.read_text(), 'do not delete')
        self.assertTrue(temporary.is_file())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assert_barrier_held()
        self.fixture.assert_external_survives()

    def test_prepared_temporary_mask_replaced_before_publication_is_preserved(self):
        temporary, final = self.interrupt_mask_publication(after_link=False)
        self.assertFalse(final.exists())
        self.assertFalse(final.is_symlink())
        temporary.unlink()
        temporary.symlink_to(self.fixture.external)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), str(self.fixture.external))
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.assertFalse(any(command[:2] == ['systemctl', 'start'] for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_explicit_pre_purge_resume_cleans_only_proven_masks_and_allows_retry(self):
        temporary, final = self.interrupt_mask_publication(after_link=False)
        self.assertFalse(final.exists())
        self.assertFalse(final.is_symlink())
        self.assertEqual(json.loads(self.receipt.read_bytes())['phase'], 'preparing')
        self.assertEqual(self.fixture.systemd.active[UNITS[0]], 'inactive')
        result = self.resume_pre_purge()
        self.assertEqual(result, 'retry')
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary.is_symlink())
        self.assertFalse(final.exists())
        self.assertFalse(final.is_symlink())
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.fixture.life.home / 'uninstall-state.json').exists())
        self.assertEqual(self.fixture.systemd.active[UNITS[0]], 'active')
        self.assertTrue(self.data.is_file())
        self.assertTrue(self.fixture.source.is_file())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertIsNotNone(self.fixture.accounts.account)
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_pre_purge_resume_preserves_unproven_old_logs(self):
        with self.store._locked(create=False) as directory:
            record = self.store._read(directory)
            record['directories'].pop('/var/log/pxe-tools', None)
            self.store._write(directory, record)
        logs = self.root / 'var/log/pxe-tools/service.log'
        logs.parent.mkdir(parents=True, exist_ok=True)
        if not logs.exists(): logs.write_text('synthetic-log')
        self.assertEqual(logs.read_text(), 'synthetic-log')
        self.interrupt_mask_publication(after_link=False)
        self.assertEqual(self.resume_pre_purge(), 'retry')
        self.assertEqual(logs.read_text(), 'synthetic-log')
        self.assertTrue(self.data.exists())
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))

    def test_resume_before_temporary_symlink_creation_allows_safe_retry(self):
        temporary = self.interrupt_mask_creation(after_symlink=False)
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary.is_symlink())
        result = self.resume_pre_purge()
        self.assertEqual(result, 'retry')
        self.assertFalse(temporary.exists())
        self.assertFalse(temporary.is_symlink())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.data.is_file())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertEqual(self.fixture.package_states['pxe-tools-ansible'], 'installed')
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_resume_preserves_unproven_symlink_created_before_inode_capture(self):
        temporary = self.interrupt_mask_creation(after_symlink=True)
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), '/dev/null')
        identity = os.lstat(temporary)
        with self.assertRaisesRegex((RuntimeError, ValueError, OSError), 'mask|proof|identity|inspect'):
            self.resume_pre_purge()
        self.assertTrue(temporary.is_symlink())
        current = os.lstat(temporary)
        self.assertEqual((current.st_dev, current.st_ino), (identity.st_dev, identity.st_ino))
        self.assertEqual(os.readlink(temporary), '/dev/null')
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_os_error_after_temporary_symlink_creation_preserves_uncertain_receipt(self):
        original = os.symlink
        created = []
        def create_then_fail(source, destination, *args, **kwargs):
            if os.fspath(destination).startswith('.pxe-uninstall-'):
                original(source, destination, *args, **kwargs)
                created.append(os.fspath(destination))
                raise OSError('simulated error after symlink creation')
            return original(source, destination, *args, **kwargs)
        with patch.object(os, 'symlink', side_effect=create_then_fail):
            with self.assertRaisesRegex(uninstall.BarrierRecoveryRequired, 'uncertain'):
                self.fixture.uninstall_fixture(self.store)
        self.assertEqual(len(created), 1)
        temporary = self.root / 'etc/systemd/system' / created[0]
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), '/dev/null')
        identity = os.lstat(temporary)
        self.assertTrue(self.receipt.is_file())
        state = json.loads(self.receipt.read_bytes())
        self.assertEqual(state['phase'], 'preparing')
        proof = state['masks'][UNITS[0]]
        self.assertEqual(proof['phase'], 'creating')
        self.assertEqual((proof['dev'], proof['ino']), (0, 0))
        self.assertEqual(proof['temporary'], created[0])
        self.assertTrue(all(status == 'inactive' for status in self.fixture.systemd.active.values()))
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             or command[:2] == ['systemctl', 'start'] for command in self.fixture.calls))
        with self.assertRaisesRegex((RuntimeError, ValueError, OSError), 'mask|identity|inspect'):
            self.resume_pre_purge()
        current = os.lstat(temporary)
        self.assertEqual((current.st_dev, current.st_ino), (identity.st_dev, identity.st_ino))
        self.assertTrue(temporary.is_symlink())
        self.assertEqual(os.readlink(temporary), '/dev/null')
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertTrue(all(status == 'inactive' for status in self.fixture.systemd.active.values()))
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             or command[:2] == ['systemctl', 'start'] for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_pre_purge_resume_accepts_published_mask_before_phase_was_saved(self):
        temporary, final = self.interrupt_mask_publication(after_link=True)
        self.assertTrue(final.is_symlink())
        self.assertEqual((os.lstat(temporary).st_dev, os.lstat(temporary).st_ino),
                         (os.lstat(final).st_dev, os.lstat(final).st_ino))
        self.assertEqual(os.lstat(final).st_nlink, 2)
        result = self.resume_pre_purge()
        self.assertEqual(result, 'retry')
        self.assertFalse(temporary.is_symlink())
        self.assertFalse(final.is_symlink())
        self.assertFalse(self.receipt.exists())
        self.assertTrue(self.data.is_file())
        self.assertEqual(self.fixture.package_states['pxe-tools'], 'installed')
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_pre_purge_resume_refuses_ambiguous_frozen_worker_without_thaw(self):
        temporary, final = self.interrupt_mask_publication(after_link=False)
        life = self.fixture.life
        life.systemd.active[UNITS[0]] = 'active'
        life.freezer = 'frozen'
        life._write_cgroup(frozen=True, active=True)
        release_calls = life.release_calls
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertEqual(life.release_calls, release_calls)
        self.assertEqual(life.freezer, 'frozen')
        self.assertTrue(temporary.is_symlink())
        self.assertFalse(final.exists())
        self.assertFalse(final.is_symlink())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name in ('dpkg', 'userdel', 'groupdel')
                             for command in self.fixture.calls))
        self.fixture.assert_external_survives()

    def test_prepared_mask_published_before_journal_write_refuses_replacement(self):
        temporary, final = self.interrupt_mask_publication(after_link=True)
        self.assertTrue(final.is_symlink())
        self.assertEqual(os.lstat(temporary).st_ino, os.lstat(final).st_ino)
        self.assertEqual(os.lstat(final).st_nlink, 2)
        final.unlink()
        final.symlink_to('/dev/null')  # Same target, different ownership identity.
        self.assertNotEqual(os.lstat(temporary).st_ino, os.lstat(final).st_ino)
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.resume_pre_purge()
        self.assertTrue(final.is_symlink())
        self.assertEqual(os.readlink(final), '/dev/null')
        self.assertTrue(temporary.is_symlink())
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.data.is_file())
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.fixture.calls))
        self.assertFalse(any(command[:2] == ['systemctl', 'start'] for command in self.fixture.calls))
        self.fixture.assert_external_survives()


class ExplicitResumeOption(unittest.TestCase):
    def test_resume_requires_explicit_command_line_option(self):
        self.assertTrue(uninstall.parse_arguments(['--resume']).resume)
        self.assertFalse(uninstall.parse_arguments([]).resume)


if __name__ == '__main__':
    unittest.main()
