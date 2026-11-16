#!/usr/bin/env python3
"""Worker recovery tests use temporary proc/cgroup fixtures and fake signals."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('uninstall_worker_recovery', ROOT / 'packaging/native/uninstall-apt.py')
uninstall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstall)

BOOT = '9f622097-cd4d-44df-9f29-8ad323ef9405'
GROUP = '/system.slice/pxe-tools-worker.service'
PID = '123'


class FakeLifecycle:
    def __init__(self, root):
        self.root = root
        self.home = root / 'var/lib/pxe-tools-native/upgrade'
        self.home.mkdir(parents=True)
        self.state_file = self.home / 'state.json'
        self.group = root / 'sys/fs/cgroup' / GROUP.lstrip('/')
        self.group.mkdir(parents=True)
        for directory in (self.group.parent, self.group):
            (directory / 'cgroup.freeze').write_text('0\n')
            (directory / 'cgroup.events').write_text('frozen 0\n')
        (self.group / 'cgroup.procs').write_text(PID + '\n')
        boot = root / 'proc/sys/kernel/random/boot_id'
        boot.parent.mkdir(parents=True)
        boot.write_text(BOOT + '\n')
        proc = root / 'proc' / PID
        thread = proc / 'task' / PID
        thread.mkdir(parents=True)
        (proc / 'cgroup').write_text('0::' + GROUP + '\n')
        self.process_state('S')
        self.current = {'ActiveState': 'active', 'FreezerState': 'running',
                        'ControlGroup': GROUP, 'MainPID': PID}
        self.actions = []
        self.before_signal = None

    def process_state(self, state, start='4242'):
        text = PID + ' (fixture) ' + state + ' ' + ' '.join(['0'] * 18 + [start]) + '\n'
        (self.root / 'proc' / PID / 'stat').write_text(text)
        (self.root / 'proc' / PID / 'task' / PID / 'stat').write_text(text)

    def freeze(self):
        self.current['FreezerState'] = 'frozen'
        (self.group / 'cgroup.freeze').write_text('1\n')
        (self.group / 'cgroup.events').write_text('frozen 1\n')

    def worker_status(self):
        return dict(self.current)

    def thaw_worker(self):
        self.actions.append(('thaw',))
        self.current['FreezerState'] = 'running'
        (self.group / 'cgroup.freeze').write_text('0\n')
        (self.group / 'cgroup.events').write_text('frozen 0\n')
        if self.before_signal:
            self.before_signal()

    def signaler(self, pid, sig):
        self.actions.append(('signal', pid, sig))
        self.process_state('S')


class RecoveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-worker-recovery-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.life = FakeLifecycle(self.root)
        self.worker = {'boot_id': BOOT, 'pid': PID, 'starttime': '4242',
                       'cgroup': GROUP, 'phase': 'freeze_intent'}

    def test_same_recorded_worker_frozen_by_our_attempt_is_thawed_without_signal(self):
        self.life.freeze()
        self.worker['phase'] = 'frozen'
        uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [('thaw',)])

    def test_confirmed_sigstop_can_resume_the_same_stopped_worker_after_thaw(self):
        self.life.freeze()
        self.life.process_state('T')
        self.worker['phase'] = 'sigstop_confirmed'
        uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [('thaw',), ('signal', int(PID), signal.SIGCONT)])

    def test_freeze_intent_alone_cannot_thaw_a_frozen_worker(self):
        self.life.freeze()
        with self.assertRaisesRegex(RuntimeError, 'inspect'):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_stop_intent_alone_cannot_resume_a_stopped_worker(self):
        self.life.freeze()
        self.life.process_state('T')
        self.worker['phase'] = 'stop_intent'
        with self.assertRaisesRegex(RuntimeError, 'inspect'):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_stop_intent_cannot_assume_an_unstopped_worker_has_no_pending_sigstop(self):
        self.worker['phase'] = 'stop_intent'
        with self.assertRaisesRegex(RuntimeError, 'inspect'):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_confirmed_sigstop_can_clear_a_pending_signal_on_the_same_worker(self):
        self.life.freeze()
        self.worker['phase'] = 'sigstop_confirmed'
        uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [('thaw',), ('signal', int(PID), signal.SIGCONT)])

    def test_freeze_intent_never_signals_previously_stopped_process(self):
        self.life.freeze()
        self.life.process_state('T')
        with self.assertRaises((ValueError, RuntimeError)):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_changed_pid_or_starttime_while_frozen_is_never_touched(self):
        for change in ('pid', 'starttime'):
            with self.subTest(change=change):
                self.life.freeze()
                if change == 'pid':
                    self.life.current['MainPID'] = '456'
                else:
                    self.life.process_state('S', start='4243')
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    uninstall.recover_recorded_worker(self.life, self.worker)
                self.assertEqual(self.life.actions, [])
                self.life.current['MainPID'] = PID
                self.life.process_state('S')

    def test_changed_cgroup_or_boot_with_ambiguous_worker_is_never_touched(self):
        self.life.freeze()
        self.life.current['ControlGroup'] = '/system.slice/other.service'
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])
        self.life.current['ControlGroup'] = GROUP
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('8f622097-cd4d-44df-9f29-8ad323ef9405\n')
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_new_boot_with_healthy_worker_never_signals_old_pid(self):
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('8f622097-cd4d-44df-9f29-8ad323ef9405\n')
        uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_new_boot_with_inactive_worker_never_signals_old_pid(self):
        (self.root / 'proc/sys/kernel/random/boot_id').write_text('8f622097-cd4d-44df-9f29-8ad323ef9405\n')
        self.life.current.update(ActiveState='inactive', FreezerState='running', ControlGroup='', MainPID='0')
        uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_no_record_cannot_thaw_an_unexplained_freeze(self):
        self.life.freeze()
        with self.assertRaises((ValueError, RuntimeError)):
            uninstall.recover_recorded_worker(self.life, None)
        self.assertEqual(self.life.actions, [])

    def test_identity_changed_during_thaw_is_not_signalled(self):
        self.life.freeze()
        self.life.process_state('T')
        self.worker['phase'] = 'sigstop_confirmed'
        self.life.before_signal = lambda: self.life.process_state('T', start='4243')
        with self.assertRaises((ValueError, RuntimeError)):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [('thaw',)])

    def test_identity_changed_just_before_signal_is_not_signalled(self):
        self.life.process_state('T')
        self.worker['phase'] = 'sigstop_confirmed'
        original = uninstall._worker_process
        calls = 0
        def changed(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.life.process_state('T', start='4243')
            return original(*args)
        with patch.object(uninstall, '_worker_process', side_effect=changed):
            with self.assertRaises((ValueError, RuntimeError)):
                uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])

    def test_unexpected_stopped_process_after_completed_stop_is_not_signalled(self):
        self.life.process_state('T')
        self.worker['phase'] = 'stopped'
        with self.assertRaises((ValueError, RuntimeError)):
            uninstall.recover_recorded_worker(self.life, self.worker)
        self.assertEqual(self.life.actions, [])


class RecordedTransitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pxe-worker-transitions-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.life = FakeLifecycle(self.root)
        self.life.load = lambda: None
        self.life.busy = lambda connection: []
        self.life.save = lambda state: self.life.state_file.write_text(json.dumps(state))
        self.life.sync_directory = lambda path: None
        self.life.capture = lambda version: self._capture(version)
        self.snapshots = []
        outer = self
        class Receipt:
            state = {'worker': None, 'masks': {}}
            def save(self):
                worker = self.state['worker']
                if worker is not None:
                    outer.snapshots.append(copy.deepcopy(worker))
        self.journal = Receipt()

    def _capture(self, version):
        self.assertEqual(version, 'uninstall')
        state = {'phase': 'captured'}
        self.life.save(state)
        return state

    def _freeze_with_release(self, state, snapshot):
        try:
            self.life.freeze_worker(state)
        finally:
            self.life.release_worker()

    def test_identity_and_freeze_intent_are_durable_before_freeze_and_stop(self):
        def freeze(state):
            self.assertEqual(self.snapshots[-1]['phase'], 'freeze_intent')
            self.assertEqual(self.snapshots[-1]['pid'], PID)
            self.assertEqual(self.snapshots[-1]['starttime'], '4242')
            self.life.freeze()
            return True
        def stop(state, frozen):
            self.assertTrue(frozen)
            self.assertEqual(self.snapshots[-1]['phase'], 'stop_intent')
            self.life.current.update(ActiveState='inactive', FreezerState='running', ControlGroup='', MainPID='0')
        self.life.freeze_worker = freeze
        self.life.stop = stop
        self.life.release_worker = lambda: None
        self.life.quiesce = lambda state, snapshot: self.life.stop(state, self.life.freeze_worker(state))
        with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
            self.assertEqual(self.journal.state['worker']['phase'], 'stopped')
        self.assertEqual([record['phase'] for record in self.snapshots],
                         ['freeze_intent', 'frozen', 'stop_intent', 'stopped'])

    def test_failed_durable_freeze_intent_never_calls_freeze(self):
        self.life.freeze_worker = lambda state: self.fail('freeze called without durable intent')
        self.life.stop = lambda state, frozen: self.fail('stop called')
        self.life.release_worker = lambda: self.fail('release called')
        self.life.quiesce = self._freeze_with_release
        save = self.journal.save
        failed = False
        def failing_save():
            nonlocal failed
            worker = self.journal.state['worker']
            if worker is not None and worker['phase'] == 'freeze_intent' and not failed:
                failed = True
                raise OSError('fixture write failure')
            save()
        self.journal.save = failing_save
        with self.assertRaises(OSError):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertTrue(failed)
        self.assertEqual(self.life.actions, [])

    def test_ambiguous_failed_freeze_keeps_receipt_and_never_thaws(self):
        def uncertain(state):
            self.life.freeze()
            raise OSError('fixture failure after freeze')
        self.life.freeze_worker = uncertain
        self.life.stop = lambda state, frozen: self.fail('stop called')
        self.life.release_worker = lambda: self.fail('release called after ambiguous freeze')
        self.life.quiesce = self._freeze_with_release
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertEqual(self.journal.state['worker']['phase'], 'freeze_intent')
        self.assertTrue((self.life.home / 'uninstall-state.json').is_file())
        self.assertEqual(self.life.actions, [])

    def test_failure_to_persist_frozen_state_keeps_pre_freeze_intent(self):
        def freeze(state):
            self.life.freeze()
            return True
        self.life.freeze_worker = freeze
        self.life.stop = lambda state, frozen: self.fail('stop called')
        self.life.release_worker = lambda: self.fail('release called after ambiguous receipt')
        self.life.quiesce = self._freeze_with_release
        save = self.journal.save
        def failing_save():
            if self.journal.state['worker'] is not None and self.journal.state['worker']['phase'] == 'frozen':
                raise OSError('fixture interruption before journal update')
            save()
        self.journal.save = failing_save
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertEqual(self.snapshots[-1]['phase'], 'freeze_intent')
        self.assertEqual(self.life.worker_status()['FreezerState'], 'frozen')
        self.assertTrue((self.life.home / 'uninstall-state.json').is_file())
        self.assertEqual(self.life.actions, [])

    def test_successful_sigstop_is_recorded_before_control_returns_to_stop(self):
        self.life.freeze_worker = lambda state: (self.life.freeze() or True)
        def signaler(pid, sig):
            self.assertEqual(self.snapshots[-1]['phase'], 'stop_intent')
            self.life.actions.append(('signal', pid, sig))
            self.life.process_state('T')
        self.life.signaler = signaler
        def stop(state, frozen):
            self.life.signaler(int(PID), signal.SIGSTOP)
            self.assertEqual(self.snapshots[-1]['phase'], 'sigstop_confirmed')
            self.life.current.update(ActiveState='inactive', FreezerState='running', ControlGroup='', MainPID='0')
        self.life.stop = stop
        self.life.release_worker = lambda: None
        self.life.quiesce = lambda state, snapshot: self.life.stop(state, self.life.freeze_worker(state))
        with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
            self.assertEqual(self.journal.state['worker']['phase'], 'stopped')
        self.assertEqual([record['phase'] for record in self.snapshots],
                         ['freeze_intent', 'frozen', 'stop_intent', 'sigstop_confirmed', 'stopped'])

    def test_failure_to_record_successful_sigstop_never_thaws_or_resumes(self):
        self.life.freeze_worker = lambda state: (self.life.freeze() or True)
        def signaler(pid, sig):
            self.life.actions.append(('signal', pid, sig))
            self.life.process_state('T')
        self.life.signaler = signaler
        self.life.stop = lambda state, frozen: self.life.signaler(int(PID), signal.SIGSTOP)
        self.life.release_worker = lambda: self.fail('release called after uncertain SIGSTOP receipt')
        def quiesce(state, snapshot):
            try:
                self.life.stop(state, self.life.freeze_worker(state))
            finally:
                self.life.release_worker()
        self.life.quiesce = quiesce
        save = self.journal.save
        def failing_save():
            if self.journal.state['worker'] is not None and self.journal.state['worker']['phase'] == 'sigstop_confirmed':
                raise OSError('fixture interruption before signal receipt')
            save()
        self.journal.save = failing_save
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertEqual(self.snapshots[-1]['phase'], 'stop_intent')
        self.assertEqual(self.life.actions, [('signal', int(PID), signal.SIGSTOP)])
        self.assertTrue((self.life.home / 'uninstall-state.json').is_file())

    def test_uncertain_sigstop_error_never_thaws_or_resumes(self):
        self.life.freeze_worker = lambda state: (self.life.freeze() or True)
        def signaler(pid, sig):
            self.life.actions.append(('signal', pid, sig))
            self.life.process_state('T')
            raise OSError('fixture signal result uncertain')
        self.life.signaler = signaler
        self.life.stop = lambda state, frozen: self.life.signaler(int(PID), signal.SIGSTOP)
        self.life.release_worker = lambda: self.fail('release called after uncertain SIGSTOP')
        def quiesce(state, snapshot):
            try:
                self.life.stop(state, self.life.freeze_worker(state))
            finally:
                self.life.release_worker()
        self.life.quiesce = quiesce
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertEqual(self.snapshots[-1]['phase'], 'stop_intent')
        self.assertEqual(self.life.actions, [('signal', int(PID), signal.SIGSTOP)])
        self.assertTrue((self.life.home / 'uninstall-state.json').is_file())

    def test_changed_identity_after_sigstop_preserves_confirmed_receipt(self):
        self.life.freeze_worker = lambda state: (self.life.freeze() or True)
        def signaler(pid, sig):
            self.life.actions.append(('signal', pid, sig))
            self.life.process_state('T', start='4243')
        self.life.signaler = signaler
        self.life.stop = lambda state, frozen: self.life.signaler(int(PID), signal.SIGSTOP)
        self.life.release_worker = lambda: self.fail('release called after identity changed')
        def quiesce(state, snapshot):
            try:
                self.life.stop(state, self.life.freeze_worker(state))
            finally:
                self.life.release_worker()
        self.life.quiesce = quiesce
        with self.assertRaises(uninstall.BarrierRecoveryRequired):
            with uninstall.quiesced_lifecycle(self.life, journal=self.journal):
                pass
        self.assertEqual(self.snapshots[-1]['phase'], 'sigstop_confirmed')
        self.assertEqual(self.life.actions, [('signal', int(PID), signal.SIGSTOP)])
        self.assertTrue((self.life.home / 'uninstall-state.json').is_file())


if __name__ == '__main__':
    unittest.main()
