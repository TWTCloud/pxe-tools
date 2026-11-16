#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Synthetic native setup/removal/re-setup using only temporary fixture paths.

This is not a Debian package installation, real systemd/dpkg/useradd execution,
PXE boot, HTTP onboarding test, or evidence of distribution compatibility.
The shared native Linux receipt must establish those separately.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


uninstall = load('uninstall_roundtrip_fixture', ROOT / 'packaging/native/uninstall-apt.py')
authority = load('ownership_roundtrip_fixture', ROOT / 'packaging/native/ownership-provenance.py')
runtime = load('runtime_roundtrip_fixture', ROOT / 'packaging/native/configure-secure-tftp.py')
mask_fixtures = load('systemd_roundtrip_fixture', ROOT / 'tests/unit/test_uninstall_persistent_masks.py')

NAME = 'pxe-tools-ansible'
HOME = '/var/lib/pxe-tools-ansible/home'
SHELL = '/usr/sbin/nologin'
UNITS = ('pxe-tools-worker.service', 'pxe-tools-php.service')


class FakeAccounts:
    """Synthetic NSS database and deletion runner; never invokes host NSS."""
    def __init__(self):
        self.uid = os.geteuid() or 1234
        self.gid = os.getegid() or 1234
        self.account = None
        self.group = None
        self.human = SimpleNamespace(pw_name='automation', pw_uid=98761, pw_gid=98762,
                                     pw_gecos='fixture', pw_dir='/home/automation', pw_shell='/bin/bash')
        self.human_group = SimpleNamespace(gr_name='automation', gr_gid=98762, gr_mem=[])
        self.calls = []
        self._fstat = os.fstat
        self._owners = {}

    def fstat(self, fd):
        info = self._fstat(fd)
        identity = (info.st_dev, info.st_ino)
        if identity not in self._owners:
            return info
        # Simulate only the uid/gid of fixture directories, leaving the real
        # directory owned by the runner so it can fchmod without CAP_FOWNER.
        fields = list(info)
        fields[stat.ST_UID], fields[stat.ST_GID] = self._owners[identity]
        return os.stat_result(fields)

    def getpwnam(self, name):
        if name != NAME or self.account is None:
            raise KeyError(name)
        return self.account

    def getgrnam(self, name):
        if name != NAME or self.group is None:
            raise KeyError(name)
        return self.group

    def getgrouplist(self, name, gid):
        return [gid]

    def create(self, command, **kwargs):
        self.calls.append(list(command))
        if Path(command[0]).name != 'useradd' or command[-1] != NAME:
            raise AssertionError('unexpected creation command')
        gecos = command[command.index('--comment') + 1]
        self.account = SimpleNamespace(pw_name=NAME, pw_uid=self.uid, pw_gid=self.gid,
                                       pw_gecos=gecos, pw_dir=HOME, pw_shell=SHELL)
        self.group = SimpleNamespace(gr_name=NAME, gr_gid=self.gid, gr_mem=[])
        return SimpleNamespace(returncode=0)

    def chown(self, fd, uid, gid):
        if (uid, gid) != (self.uid, self.gid):
            raise AssertionError('unexpected synthetic account')
        info = self._fstat(fd)
        self._owners[(info.st_dev, info.st_ino)] = (uid, gid)

    def snapshot(self):
        return {'accounts': copy.deepcopy(([self.account] if self.account else []) + [self.human]),
                'groups': copy.deepcopy(([self.group] if self.group else []) + [self.human_group]),
                'process_uids': set(), 'login_defs': 'USERGROUPS_ENAB no\n', 'userdel_hooks': []}

    def remove(self, command):
        self.calls.append(list(command))
        kind = Path(command[0]).name
        if kind not in ('userdel', 'groupdel') or command != ['/usr/sbin/' + kind, NAME]:
            raise AssertionError('unexpected account deletion command')
        if kind == 'userdel':
            self.account = None
        else:
            self.group = None
        return SimpleNamespace(returncode=0, stdout='', stderr='')


class FakeLifecycle:
    """Model quiescence with fixture cgroup/proc files and no real signals."""
    PID = '123'
    CGROUP = '/system.slice/pxe-tools-worker.service'

    def __init__(self, root, systemd):
        self.root = root
        self.systemd = systemd
        self.home = root / 'var/lib/pxe-tools-native/upgrade'
        self.state_file = self.home / 'state.json'
        self.group = root / 'sys/fs/cgroup' / self.CGROUP.lstrip('/')
        self.group.mkdir(parents=True, exist_ok=True)
        # system.slice is an actual non-root ancestor in cgroup v2. The
        # hierarchy root itself deliberately has no cgroup.freeze fixture.
        self.parent_group = self.group.parent
        (self.parent_group / 'cgroup.events').write_text('frozen 0\n')
        (self.parent_group / 'cgroup.freeze').write_text('0\n')
        self.process = root / 'proc' / self.PID
        thread = self.process / 'task' / self.PID
        thread.mkdir(parents=True, exist_ok=True)
        (self.process / 'cgroup').write_text('0::' + self.CGROUP + '\n')
        self.freezer = 'running'
        self.freeze_calls = 0
        self.release_calls = 0
        self.signaler = lambda pid, number: None
        self._write_cgroup(frozen=False, active=True)
        self.write_process_state('S')

    def _write_cgroup(self, *, frozen, active):
        (self.group / 'cgroup.events').write_text('frozen ' + ('1' if frozen else '0') + '\n')
        (self.group / 'cgroup.freeze').write_text('1\n' if frozen else '0\n')
        (self.group / 'cgroup.procs').write_text(self.PID + '\n' if active else '')

    def write_process_state(self, state):
        # /proc/PID/stat and /proc/PID/task/TID/stat expose the same starttime.
        value = self.PID + ' (python3) ' + state + ' ' + ' '.join(['0'] * 18 + ['4242']) + '\n'
        (self.process / 'stat').write_text(value)
        (self.process / 'task' / self.PID / 'stat').write_text(value)

    def worker_status(self):
        active = self.systemd.active['pxe-tools-worker.service'] == 'active'
        return {'ActiveState': 'active' if active else 'inactive',
                'FreezerState': self.freezer,
                'ControlGroup': self.CGROUP if active else '',
                'MainPID': self.PID if active else '0'}

    def private_home(self):
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)

    def database(self): return None
    def environments(self): return {}
    def load(self): return None
    def check_effective_configuration(self): pass
    def sync_directory(self, path): pass
    def busy(self, conn): return []
    def save(self, state):
        self.state_file.write_text(json.dumps(state))
        self.state_file.chmod(0o600)

    def capture(self, version):
        state = {'format': 1, 'id': 'a' * 32, 'version': version, 'phase': 'captured',
                 'units': {unit: {'active': active == 'active', 'enabled': 'static'}
                           for unit, active in self.systemd.active.items()},
                 'active': dict(self.systemd.active)}
        self.save(state)
        return state

    def freeze_worker(self, state):
        if self.worker_status()['ActiveState'] != 'active':
            raise AssertionError('fixture expected active worker before freeze')
        self.freeze_calls += 1
        self.freezer = 'frozen'
        self._write_cgroup(frozen=True, active=True)
        return True

    def release_worker(self):
        self.release_calls += 1
        active = self.systemd.active['pxe-tools-worker.service'] == 'active'
        self.freezer = 'running'
        self._write_cgroup(frozen=False, active=active)

    def stop(self, state, frozen):
        if not frozen or self.freezer != 'frozen':
            raise AssertionError('fixture worker must be frozen before safe stop')
        self.signaler(int(self.PID), signal.SIGSTOP)
        # Only update the fake systemd state; no process or signal is touched.
        for unit in self.systemd.active:
            self.systemd.active[unit] = 'inactive'
        self.freezer = 'running'
        self._write_cgroup(frozen=False, active=False)

    def quiesce(self, state, snapshot=False):
        frozen = self.freeze_worker(state)
        try:
            self.stop(state, frozen)
        finally:
            self.release_worker()
        state['phase'] = 'prepared'
        self.save(state)

    def restore(self, state, old=False):
        self.systemd.active.update(state['active'])
        active = self.systemd.active['pxe-tools-worker.service'] == 'active'
        self.freezer = 'running'
        self._write_cgroup(frozen=False, active=active)


class SyntheticRoundTrip(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pxe-uninstall-roundtrip-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('etc/systemd/system', 'etc/apt/sources.list.d', 'etc/apt/keyrings',
                     'var/lib/dpkg', 'var/log', 'usr/lib', 'usr/lib/systemd/system',
                     'run/lock', 'opt'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        (self.root / 'run/systemd/system').mkdir(parents=True)
        self.external = self.root / 'external'
        self.external.mkdir()
        (self.external / 'backup').write_text('external-backup')
        self.human_keys = self.root / 'home/automation/.ssh/authorized_keys'
        self.human_keys.parent.mkdir(parents=True)
        self.human_keys.write_text('human-key')
        self.nginx = self.root / 'etc/systemd/system/nginx.service'
        self.nginx.write_text('pre-existing nginx override')
        self.key = self.root / 'etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
        self.source = self.root / 'etc/apt/sources.list.d/pxe-tools.sources'
        self.third_party = self.source.parent / 'third-party.list'
        self.third_party.write_text('deb [signed-by=/etc/apt/keyrings/pxe-tools-archive-keyring.gpg] https://example.invalid stable main\n')
        self.accounts = FakeAccounts()
        self.package_states = {}
        self.fail_purge = False
        self.calls = []
        self.systemd = None
        self.life = None

    @staticmethod
    def fixture_generation():
        # Deliberately simulated statx/xattrs keyed by fixture inode. This does
        # not establish the real filesystem, Linux trusted xattr, or kernel proof.
        values = {}
        def key(fd, name):
            info = os.fstat(fd)
            return info.st_dev, info.st_ino, name
        def statx(fd):
            info = os.fstat(fd)
            return {'dev': info.st_dev, 'ino': info.st_ino,
                    'btime_sec': 1700000000, 'btime_nsec': 123456789}
        def setxattr(fd, name, value, flags):
            identity = key(fd, name)
            if identity in values:
                raise OSError('fixture xattr already exists')
            values[identity] = value
        def getxattr(fd, name):
            try:
                return values[key(fd, name)]
            except KeyError as exc:
                raise OSError('fixture xattr missing') from exc
        return authority.Generation(statx=statx, setxattr=setxattr, getxattr=getxattr)

    def install_fixture(self, with_module):
        """Exercise real directory creation/provenance and fake the DEB payload."""
        if self.accounts.account is None:
            # The previous fixture account was removed; do not model stale
            # ownership if the filesystem reuses one of its former inodes.
            self.accounts._owners.clear()
        self.generation = self.fixture_generation()
        store = authority.Store(self.root, owner=os.geteuid(), generation=self.generation)
        runtime.prepare(base=self.root / 'var/lib', root=self.root,
                        owner=os.geteuid(), journal=store)
        store.create_base(require_runtime=True)
        store.finish_base()
        if with_module:
            # The test must never rely on CAP_CHOWN/FOWNER in the CI container.
            with patch('os.fstat', side_effect=self.accounts.fstat), \
                 patch('os.fchown', side_effect=AssertionError('fixture must not call fchown')):
                store.configure_ansible(accounts=self.accounts, groups=self.accounts,
                                        group_list=self.accounts.getgrouplist,
                                        runner=self.accounts.create, chown=self.accounts.chown)
        data = self.root / 'var/lib/pxe-tools'
        (data / 'instance.sqlite').write_text('synthetic-database')
        (data / 'external-link').symlink_to(self.external, target_is_directory=True)
        (self.root / 'etc/pxe-tools/master.key').write_text('synthetic-secret')
        (self.root / 'var/log/pxe-tools/service.log').write_text('synthetic-log')
        (self.root / 'var/lib/pxe-tools-http/boot').write_text('synthetic-boot')
        (self.root / 'var/lib/pxe-tools-native/local-snapshot').write_text('synthetic-local-backup')
        package_units = self.root / 'usr/lib/systemd/system'
        for unit in UNITS:
            shutil.copyfile(ROOT / 'packaging/native' / unit, package_units / unit)
        if with_module:
            dropin = package_units / 'pxe-tools-worker.service.d'
            dropin.mkdir()
            shutil.copyfile(ROOT / 'packaging/native/ansible-worker.conf', dropin / '50-ansible.conf')
        for payload in (self.root / 'usr/lib/pxe-tools', self.root / 'opt/pxe-tools'):
            payload.mkdir()
            (payload / 'package-file').write_text('synthetic-package-payload')
        self.source.write_text('Types: deb\nURIs: https://packages.pxetools.com/apt\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/pxe-tools-archive-keyring.gpg\n')
        source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        os.link(self.source, self.source.parent / ('.pxe-tools-sources.' + source_hash + '.created'))
        boot_id = self.root / 'proc/sys/kernel/random/boot_id'
        boot_id.parent.mkdir(parents=True, exist_ok=True)
        boot_id.write_text('12345678-1234-1234-1234-123456789abc\n')
        if not self.key.exists():
            self.key.write_text('synthetic-shared-key')
        self.package_states = {'pxe-tools': 'installed', 'nginx': 'installed',
                               'php-fpm': 'installed', 'ansible-core': 'installed'}
        if with_module:
            self.package_states['pxe-tools-ansible'] = 'installed'
        self.systemd = mask_fixtures.FakeSystemd(self.root / 'etc/systemd/system', UNITS)
        self.systemd.active = {unit: 'active' for unit in UNITS}
        self.life = FakeLifecycle(self.root, self.systemd)
        return store

    def runner(self, command, **kwargs):
        self.calls.append(list(command))
        executable = Path(command[0]).name
        if executable == 'dpkg':
            self.assertEqual(command, ['dpkg', '--purge', 'pxe-tools-ansible', 'pxe-tools'])
            self.assertEqual(kwargs.get('env', {}).get('DPKG_FRONTEND_LOCKED'), '1')
            if self.fail_purge:
                return SimpleNamespace(returncode=1, stdout='', stderr='fixture purge failure')
            self.package_states.pop('pxe-tools', None)
            self.package_states.pop('pxe-tools-ansible', None)
            # Model dpkg-owned payload removal strictly beneath this temp root.
            for relative in ('usr/lib/pxe-tools', 'opt/pxe-tools',
                             'usr/lib/systemd/system/pxe-tools-worker.service.d'):
                target = self.root / relative
                self.assertTrue(target.is_relative_to(self.root))
                if target.exists():
                    shutil.rmtree(target)
            for unit in UNITS:
                (self.root / 'usr/lib/systemd/system' / unit).unlink(missing_ok=True)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if executable == 'dpkg-query':
            lines = ['bash\tinstalled\tok'] + [name + '\t' + state + '\tok'
                                             for name, state in self.package_states.items()]
            return SimpleNamespace(returncode=0, stdout='\n'.join(lines) + '\n', stderr='')
        if executable in ('userdel', 'groupdel'):
            return self.accounts.remove(command)
        if executable == 'systemctl':
            property_arg = next((arg for arg in command if arg.startswith('--property=')), '')
            unit = command[-1]
            if property_arg == '--property=FragmentPath':
                return SimpleNamespace(returncode=0, stdout='/usr/lib/systemd/system/' + unit + '\n', stderr='')
            if property_arg == '--property=DropInPaths':
                dropin = ('/usr/lib/systemd/system/pxe-tools-worker.service.d/50-ansible.conf'
                          if unit == 'pxe-tools-worker.service' and 'pxe-tools-ansible' in self.package_states else '')
                return SimpleNamespace(returncode=0, stdout=dropin + '\n', stderr='')
            return self.systemd(command, **kwargs)
        raise AssertionError('real executable would have been called: ' + repr(command))

    def uninstall_fixture(self, store):
        kwargs = dict(owner=os.geteuid(), apply=True, record=store.read(), ownership=store,
                      account_lookup=self.accounts.snapshot)
        return uninstall.run_uninstall(self.root, self.runner, self.life, UNITS,
                                      lambda: (), **kwargs)

    def assert_external_survives(self):
        self.assertEqual((self.external / 'backup').read_text(), 'external-backup')
        self.assertEqual(self.human_keys.read_text(), 'human-key')
        self.assertEqual(self.nginx.read_text(), 'pre-existing nginx override')
        self.assertTrue(self.key.exists(), 'shared third-party APT key must survive')
        self.assertTrue(self.third_party.exists(), 'third-party source must survive')
        self.assertIsNotNone(self.accounts.human)
        self.assertEqual(self.accounts.human.pw_name, 'automation')

    def exercise(self, with_module):
        store = self.install_fixture(with_module)
        first = store.read()
        self.assertEqual(first['format'], 2)
        self.assertEqual(first['base_phase'], 'complete')
        if with_module:
            self.assertIn('account', first)
            self.assertIn('/var/lib/pxe-tools-ansible', first['directories'])
        self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 1, 'the fake active worker must pass the real pre-freeze check')
        self.assertGreaterEqual(self.life.release_calls, 1)
        for relative in ('etc/pxe-tools', 'var/lib/pxe-tools', 'var/lib/pxe-tools-native',
                         'var/lib/pxe-tools-tftp', 'var/lib/pxe-tools-http',
                         'var/lib/pxe-tools-ownership', 'var/log/pxe-tools',
                         'usr/lib/pxe-tools', 'opt/pxe-tools'):
            self.assertFalse((self.root / relative).exists(), relative)
        self.assertFalse(self.source.exists())
        self.assertEqual({name: self.package_states[name] for name in ('nginx', 'php-fpm', 'ansible-core')},
                         {'nginx': 'installed', 'php-fpm': 'installed', 'ansible-core': 'installed'})
        self.assertFalse(any(path.name.startswith('.pxe-uninstall-') for path in
                             (self.root / 'etc/systemd/system').iterdir()))
        self.assert_external_survives()
        if with_module:
            self.assertIsNone(self.accounts.account)
            self.assertIsNone(self.accounts.group)
            self.assertFalse((self.root / 'var/lib/pxe-tools-ansible').exists())
            operations = [Path(command[0]).name for command in self.calls]
            self.assertLess(operations.index('dpkg'), operations.index('userdel'))
            self.assertLess(operations.index('userdel'), operations.index('groupdel'))
        else:
            operations = [Path(command[0]).name for command in self.calls]
            self.assertNotIn('userdel', operations)
            self.assertNotIn('groupdel', operations)
        # A second invocation against the absent packages is harmless.
        uninstall.run_uninstall(self.root, self.runner, None, UNITS, lambda: (),
                                owner=os.geteuid(), apply=True, record=None,
                                ownership=None, account_lookup=self.accounts.snapshot)
        self.assert_external_survives()
        # The new install starts from clean product paths but the third party stays.
        second_store = self.install_fixture(with_module)
        second = second_store.read()
        self.assertEqual(second['base_phase'], 'complete')
        self.assertEqual((self.root / 'var/lib/pxe-tools/instance.sqlite').read_text(), 'synthetic-database')
        for path, identity in second['directories'].items():
            info = (self.root / path.lstrip('/')).lstat()
            self.assertEqual((identity['dev'], identity['ino']), (info.st_dev, info.st_ino))
            fd = os.open(self.root / path.lstrip('/'), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                self.assertTrue(second_store.generation.matches(fd, identity))
            finally:
                os.close(fd)
        self.assert_external_survives()

    def test_preexisting_stopped_worker_is_not_signalled_or_purged(self):
        store = self.install_fixture(with_module=False)
        self.life.write_process_state('T')
        with self.assertRaisesRegex(RuntimeError, 'stopped'):
            self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 0)
        self.assertEqual(self.life.release_calls, 0)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_preexisting_stopped_thread_is_not_signalled_or_purged(self):
        store = self.install_fixture(with_module=False)
        thread = self.life.process / 'task' / self.life.PID / 'stat'
        thread.write_text(thread.read_text().replace(' (python3) S ', ' (python3) T '))
        with self.assertRaisesRegex(RuntimeError, 'stopped'):
            self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 0)
        self.assertEqual(self.life.release_calls, 0)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_unexpected_cgroup_child_is_not_interrupted_or_purged(self):
        store = self.install_fixture(with_module=False)
        (self.life.group / 'cgroup.procs').write_text(self.life.PID + '\n124\n')
        with self.assertRaisesRegex(RuntimeError, 'unexpected processes'):
            self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 0)
        self.assertEqual(self.life.release_calls, 0)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assert_external_survives()

    def test_requested_ancestor_freeze_refuses_without_thaw_or_purge(self):
        store = self.install_fixture(with_module=False)
        # The ancestor has a freeze requested even before frozen=1 is observed.
        (self.life.parent_group / 'cgroup.freeze').write_text('1\n')
        with self.assertRaisesRegex(RuntimeError, 'ancestor'):
            self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 0)
        self.assertEqual(self.life.release_calls, 0)
        self.assertEqual((self.life.parent_group / 'cgroup.freeze').read_text(), '1\n')
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_preexisting_frozen_worker_is_not_thawed_or_purged(self):
        store = self.install_fixture(with_module=False)
        self.life.freezer = 'frozen'
        self.life._write_cgroup(frozen=True, active=True)
        with self.assertRaisesRegex(RuntimeError, 'freezer'):
            self.uninstall_fixture(store)
        self.assertEqual(self.life.freeze_calls, 0)
        self.assertEqual(self.life.release_calls, 0)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_weak_generation_proof_refuses_before_any_purge(self):
        store = self.install_fixture(with_module=False)
        with store._locked(create=False) as directory:
            record = store._read(directory)
            proof = record['directories']['/var/lib/pxe-tools']
            proof.update(btime_sec=None, btime_nsec=None, nonce=None)
            store._write(directory, record)
        with self.assertRaisesRegex(ValueError, 'recorded directory'):
            self.uninstall_fixture(store)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_changed_generation_nonce_refuses_before_any_purge(self):
        store = self.install_fixture(with_module=False)
        store.generation.getxattr = lambda fd, name: b'changed synthetic nonce'
        with self.assertRaisesRegex(ValueError, 'generation'):
            self.uninstall_fixture(store)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assert_external_survives()

    def test_mounted_product_path_refuses_before_any_purge(self):
        store = self.install_fixture(with_module=True)
        with self.assertRaisesRegex(ValueError, 'mount'):
            uninstall.run_uninstall(self.root, self.runner, self.life, UNITS,
                                    lambda: ('/var/lib/pxe-tools-http',), owner=os.geteuid(),
                                    apply=True, record=store.read(), ownership=store,
                                    account_lookup=self.accounts.snapshot)
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assertTrue(self.source.exists())
        self.assertIsNotNone(self.accounts.account)
        self.assertFalse(any(Path(command[0]).name == 'dpkg' for command in self.calls))
        self.assert_external_survives()

    def test_failed_purge_preserves_product_data_source_and_account(self):
        store = self.install_fixture(with_module=True)
        self.fail_purge = True
        with self.assertRaises(RuntimeError):
            self.uninstall_fixture(store)
        self.assertTrue((self.root / 'var/lib/pxe-tools/instance.sqlite').exists())
        self.assertTrue((self.root / 'etc/pxe-tools/master.key').exists())
        self.assertTrue(self.source.exists())
        self.assertIsNotNone(self.accounts.account)
        journal = self.root / 'var/lib/pxe-tools-native/upgrade/uninstall-state.json'
        self.assertTrue(journal.exists())
        self.assertEqual(json.loads(journal.read_text())['phase'], 'purge_started')
        for unit in UNITS:
            path = self.root / 'etc/systemd/system' / unit
            self.assertTrue(path.is_symlink())
            self.assertEqual(os.readlink(path), '/dev/null')
        self.assert_external_survives()

    def test_module_uses_synthetic_nonroot_uid_without_chown_capability(self):
        # Model the CI container: euid/gid 0 and an account with nonzero IDs.
        # Only fixture-reported fstat values change; the OS owner stays ours.
        with patch('os.geteuid', return_value=0), patch('os.getegid', return_value=0):
            self.accounts = FakeAccounts()
        self.assertEqual((self.accounts.uid, self.accounts.gid), (1234, 1234))
        store = self.install_fixture(with_module=True)
        workspace = self.root / 'var/lib/pxe-tools-ansible'
        self.assertEqual((workspace.stat().st_uid, workspace.stat().st_gid),
                         (os.geteuid(), os.getegid()))
        self.assertEqual(store.read()['account']['uid'], 1234)
        self.uninstall_fixture(store)
        self.assertIsNone(self.accounts.account)
        self.assertIsNone(self.accounts.group)
        self.assert_external_survives()

    def test_base_install_remove_and_reinstall(self):
        self.exercise(with_module=False)

    def test_base_and_module_install_remove_and_reinstall(self):
        self.exercise(with_module=True)


if __name__ == '__main__':
    unittest.main()
