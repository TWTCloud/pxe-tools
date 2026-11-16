#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Account removal boundaries; no host account, command or key is touched."""
import copy
import importlib.util
import builtins
import io
import os
import pwd
import grp
import tempfile
from unittest.mock import patch
from pathlib import Path
from contextlib import contextmanager
import subprocess
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'packaging/native/uninstall-apt.py'
spec = importlib.util.spec_from_file_location('pxe_uninstall_account_fixture', SCRIPT)
uninstall = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uninstall)

NAME = 'pxe-tools-ansible'
HOME = '/var/lib/pxe-tools-ansible/home'
SHELL = '/usr/sbin/nologin'
GECOS = 'pxe-tools-0123456789abcdef0123456789abcdef'
UID = 975
GID = 976


def account(name=NAME, uid=UID, gid=GID, gecos=GECOS, home=HOME, shell=SHELL):
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_gecos=gecos,
                           pw_dir=home, pw_shell=shell)


def group(name=NAME, gid=GID, members=()):
    return SimpleNamespace(gr_name=name, gr_gid=gid, gr_mem=list(members))


def proof():
    return {'format': 1, 'directories': {'/etc/pxe-tools': {'dev': 1, 'ino': 2},
                                          '/var/lib/pxe-tools': {'dev': 1, 'ino': 3}}, 'base_phase': 'complete',
            'account': {'name': NAME, 'uid': UID, 'gid': GID, 'gecos': GECOS,
                        'home': HOME, 'shell': SHELL}}


def snapshot():
    return {
        'accounts': [account(), account('automation', 1001, 1001, 'Human automation', '/home/automation', '/bin/bash')],
        'groups': [group(), group('automation', 1001), group('www-data', 33)],
        'process_uids': set(),
        'login_defs': 'USERGROUPS_ENAB yes\n# USERDEL_CMD /disabled/example\n',
        'userdel_hooks': [],
    }


@contextmanager
def no_host_inspection():
    """Fail the fixture if production paths, NSS or real commands are used."""
    raw_open, raw_io_open, raw_os_open = builtins.open, io.open, os.open
    raw_stat, raw_lstat, raw_listdir, raw_scandir = os.stat, os.lstat, os.listdir, os.scandir
    def safe(path):
        if isinstance(path, (str, bytes, os.PathLike)):
            value = os.fsdecode(path)
            if value in ('/etc', '/proc') or value.startswith(('/etc/', '/proc/')):
                raise AssertionError('real host path forbidden: ' + value)
        return path
    def call(function):
        return lambda path, *args, **kwargs: function(safe(path), *args, **kwargs)
    with patch('builtins.open', side_effect=call(raw_open)), patch('io.open', side_effect=call(raw_io_open)), \
         patch('os.open', side_effect=call(raw_os_open)), patch('os.stat', side_effect=call(raw_stat)), \
         patch('os.lstat', side_effect=call(raw_lstat)), patch('os.listdir', side_effect=call(raw_listdir)), \
         patch('os.scandir', side_effect=call(raw_scandir)), \
         patch.object(pwd, 'getpwall', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(pwd, 'getpwnam', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(pwd, 'getpwuid', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(os, 'getgrouplist', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(grp, 'getgrall', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(grp, 'getgrnam', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(grp, 'getgrgid', side_effect=AssertionError('real NSS forbidden')), \
         patch.object(subprocess, 'run', side_effect=AssertionError('real command forbidden')), \
         patch.object(subprocess, 'Popen', side_effect=AssertionError('real command forbidden')), \
         patch('os.system', side_effect=AssertionError('real command forbidden')):
        yield


class AccountValidation(unittest.TestCase):
    def setUp(self):
        self.record = proof()
        self.state = snapshot()

    def validate(self):
        with no_host_inspection():
            return uninstall.validate_account(self.record, self.state['accounts'], self.state['groups'],
                                              self.state['process_uids'])

    def test_exact_created_dedicated_identity_is_accepted(self):
        self.assertEqual(self.validate(), self.record['account'])

    def test_missing_account_and_unused_ids_are_idempotent(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.assertIsNone(self.validate())

    def test_absent_account_without_proof_is_also_a_noop(self):
        self.record.pop('account')
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.assertIsNone(self.validate())

    def test_preexisting_account_without_creation_proof_is_preserved(self):
        self.record.pop('account')
        with self.assertRaises(ValueError):
            self.validate()
        self.assertIn(NAME, [a.pw_name for a in self.state['accounts']])

    def test_changed_gecos_or_invalid_nonce_refuses(self):
        for changed in ('', GECOS.upper(), 'pxe-tools-' + 'f' * 31,
                        'pxe-tools-' + 'f' * 32, 'pxe-tools:' + 'f' * 32):
            with self.subTest(gecos=changed):
                self.state['accounts'][0].pw_gecos = changed
                with self.assertRaises(ValueError):
                    self.validate()

    def test_changed_uid_gid_home_or_shell_refuses(self):
        for field, changed in (('pw_uid', UID + 1), ('pw_gid', GID + 1),
                               ('pw_dir', '/home/automation'), ('pw_shell', '/bin/bash')):
            with self.subTest(field=field):
                state = snapshot()
                setattr(state['accounts'][0], field, changed)
                self.state = state
                with self.assertRaises(ValueError):
                    self.validate()

    def test_root_identity_is_never_accepted_even_if_journal_matches(self):
        self.record['account']['uid'] = 0
        self.state['accounts'][0].pw_uid = 0
        with self.assertRaises(ValueError):
            self.validate()

    def test_extra_supplementary_group_refuses(self):
        self.state['groups'].append(group('operators', 42, (NAME,)))
        with self.assertRaises(ValueError):
            self.validate()

    def test_foreign_member_of_dedicated_group_refuses(self):
        self.state['groups'][0].gr_mem.append('automation')
        with self.assertRaises(ValueError):
            self.validate()

    def test_other_user_with_dedicated_primary_gid_refuses(self):
        self.state['accounts'][1].pw_gid = GID
        with self.assertRaises(ValueError):
            self.validate()

    def test_other_name_sharing_the_dedicated_uid_refuses(self):
        self.state['accounts'][1].pw_uid = UID
        with self.assertRaises(ValueError):
            self.validate()

    def test_gid_reuse_by_another_group_refuses(self):
        self.state['groups'].append(group('third-party', GID))
        with self.assertRaises(ValueError):
            self.validate()

    def test_duplicate_user_or_group_name_refuses(self):
        self.state['accounts'].append(account(uid=UID + 5))
        with self.assertRaises(ValueError):
            self.validate()
        self.state['accounts'].pop()
        self.state['groups'].append(group(gid=GID + 5))
        with self.assertRaises(ValueError):
            self.validate()

    def test_changed_or_missing_dedicated_group_refuses(self):
        self.state['groups'][0].gr_gid += 1
        with self.assertRaises(ValueError):
            self.validate()
        self.state['groups'].pop(0)
        with self.assertRaises(ValueError):
            self.validate()

    def test_active_process_as_account_refuses(self):
        self.state['process_uids'].add(UID)
        with self.assertRaises(ValueError):
            self.validate()

    def test_absent_account_with_reused_uid_refuses(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['accounts'][0].pw_uid = UID
        with self.assertRaises(ValueError):
            self.validate()

    def test_absent_account_with_reused_primary_gid_refuses(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['accounts'][0].pw_gid = GID
        with self.assertRaises(ValueError):
            self.validate()

    def test_absent_account_with_foreign_group_member_refuses(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['groups'][0].gr_mem.append('automation')
        with self.assertRaises(ValueError):
            self.validate()

    def test_absent_account_with_still_running_uid_refuses(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['process_uids'].add(UID)
        with self.assertRaises(ValueError):
            self.validate()


class AccountRemoval(unittest.TestCase):
    def setUp(self):
        self.record = proof()
        self.state = snapshot()
        self.calls = []
        self.lookups = 0
        self.fail = False
        self.remove_on_success = True

    def lookup(self):
        self.lookups += 1
        return copy.deepcopy(self.state)

    def runner(self, command, **kwargs):
        self.calls.append(list(command))
        if not self.fail and self.remove_on_success:
            self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        return SimpleNamespace(returncode=int(self.fail), stdout='', stderr='')

    def remove(self):
        with no_host_inspection():
            return uninstall.remove_account(self.record, self.runner, self.lookup)

    def test_only_userdel_without_home_or_force_is_executed(self):
        self.remove()
        self.assertEqual(len(self.calls), 1)
        command = self.calls[0]
        self.assertEqual(Path(command[0]).name, 'userdel')
        self.assertEqual(command[1:], [NAME])
        self.assertNotIn('-r', command)
        self.assertNotIn('--remove', command)
        self.assertNotIn('--force', command)
        self.assertNotIn('-f', command)
        self.assertGreaterEqual(self.lookups, 2, 'the result must be checked after userdel')
        self.assertIn('automation', [a.pw_name for a in self.state['accounts']])

    def test_global_keys_and_other_accounts_remain_untouched(self):
        with tempfile.TemporaryDirectory(prefix='pxe-account-keys-') as temporary:
            keys = Path(temporary) / 'home/automation/.ssh/authorized_keys'
            keys.parent.mkdir(parents=True)
            keys.write_text('external-key-fixture')
            with patch('os.unlink', side_effect=AssertionError('no local deletion allowed')), \
                 patch('os.remove', side_effect=AssertionError('no local deletion allowed')):
                self.remove()
            self.assertEqual(keys.read_text(), 'external-key-fixture')
            self.assertIn('automation', [a.pw_name for a in self.state['accounts']])
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0][1:], [NAME])

    def test_already_absent_account_does_not_call_userdel(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.remove()
        self.assertEqual(self.calls, [])

    def test_userdel_failure_is_reported_without_other_commands(self):
        self.fail = True
        with self.assertRaises((ValueError, RuntimeError)):
            self.remove()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(Path(self.calls[0][0]).name, 'userdel')
        self.assertIn('automation', [a.pw_name for a in self.state['accounts']])

    def test_userdel_success_without_actual_removal_is_not_reported_as_success(self):
        self.remove_on_success = False
        with self.assertRaises((ValueError, RuntimeError)):
            self.remove()
        self.assertEqual(len(self.calls), 1)

    def test_group_with_foreign_member_refuses_before_userdel(self):
        self.state['groups'][0].gr_mem.append('automation')
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_userdel_cmd_is_refused_before_userdel(self):
        for directive in ('USERDEL_CMD /usr/local/sbin/remove-data\n',
                          '  USERDEL_CMD\t/usr/local/sbin/remove-data  # local\n',
                          'USERDEL_CMD\n'):
            with self.subTest(directive=directive):
                self.state['login_defs'] = directive
                with self.assertRaises(ValueError):
                    self.remove()
                self.assertEqual(self.calls, [])

    def test_commented_userdel_cmd_and_non_executable_hooks_are_harmless(self):
        self.state['login_defs'] = '# USERDEL_CMD /not-active\nUSERGROUPS_ENAB yes\n'
        self.state['userdel_hooks'] = [{'path': '/etc/shadow-maint/userdel-pre.d/disabled',
                                        'mode': 0o644, 'kind': 'file'}]
        self.remove()
        self.assertEqual(len(self.calls), 1)

    def test_executable_shadow_maint_hook_refuses_before_userdel(self):
        for directory in ('userdel-pre.d', 'userdel-post.d'):
            with self.subTest(directory=directory):
                self.state['userdel_hooks'] = [{'path': '/etc/shadow-maint/' + directory + '/cleanup',
                                                'mode': 0o755, 'kind': 'file'}]
                with self.assertRaises(ValueError):
                    self.remove()
                self.assertEqual(self.calls, [])

    def test_linked_or_unreadable_hook_inventory_refuses(self):
        for hooks in (None, [{'path': '/etc/shadow-maint/userdel-pre.d/link',
                              'mode': 0o777, 'kind': 'symlink'}],
                      [{'path': '/etc/shadow-maint/userdel-post.d/unknown',
                        'mode': None, 'kind': 'file'}]):
            with self.subTest(hooks=hooks):
                self.state['userdel_hooks'] = hooks
                with self.assertRaises(ValueError):
                    self.remove()
                self.assertEqual(self.calls, [])

    def test_unreadable_login_defs_refuses(self):
        self.state['login_defs'] = None
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_unproven_preexisting_account_never_reaches_userdel(self):
        self.record.pop('account')
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])
        self.assertIn(NAME, [a.pw_name for a in self.state['accounts']])


class GroupRemoval(unittest.TestCase):
    def setUp(self):
        self.record = proof()
        self.state = snapshot()
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.calls = []
        self.lookups = 0
        self.fail = False
        self.remove_on_success = True

    def lookup(self):
        self.lookups += 1
        return copy.deepcopy(self.state)

    def runner(self, command, **kwargs):
        self.calls.append(list(command))
        if not self.fail and self.remove_on_success:
            self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        return SimpleNamespace(returncode=int(self.fail), stdout='', stderr='')

    def remove(self):
        with no_host_inspection():
            return uninstall.remove_group(self.record, self.runner, self.lookup)

    def test_verified_empty_group_removed_only_after_account_disappeared(self):
        self.remove()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(Path(self.calls[0][0]).name, 'groupdel')
        self.assertEqual(self.calls[0][1:], [NAME])
        self.assertGreaterEqual(self.lookups, 2)
        self.assertIn('automation', [g.gr_name for g in self.state['groups']])

    def test_missing_group_is_idempotent(self):
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.remove()
        self.assertEqual(self.calls, [])

    def test_existing_account_blocks_group_removal(self):
        self.state['accounts'].append(account())
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_missing_group_but_existing_account_still_refuses(self):
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.state['accounts'].append(account())
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_group_with_member_is_preserved(self):
        self.state['groups'][0].gr_mem.append('automation')
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_group_replaced_or_gid_shared_by_other_group_refuses(self):
        self.state['groups'][0].gr_gid = GID + 1
        with self.assertRaises(ValueError):
            self.remove()
        self.state['groups'][0].gr_gid = GID
        self.state['groups'].append(group('another-group', GID))
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_uid_or_gid_reused_by_another_account_refuses(self):
        for field, value in (('pw_uid', UID), ('pw_gid', GID)):
            with self.subTest(field=field):
                self.state = snapshot()
                self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
                setattr(self.state['accounts'][0], field, value)
                with self.assertRaises(ValueError):
                    self.remove()
                self.assertEqual(self.calls, [])

    def test_still_running_uid_refuses_group_deletion(self):
        self.state['process_uids'].add(UID)
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_unproven_group_is_not_removed(self):
        self.record.pop('account')
        with self.assertRaises(ValueError):
            self.remove()
        self.assertEqual(self.calls, [])

    def test_groupdel_failure_is_reported_and_no_other_command_runs(self):
        self.fail = True
        with self.assertRaises((ValueError, RuntimeError)):
            self.remove()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(Path(self.calls[0][0]).name, 'groupdel')
        self.assertEqual(self.calls[0][1:], [NAME])

    def test_groupdel_success_must_be_verified(self):
        self.remove_on_success = False
        with self.assertRaises((ValueError, RuntimeError)):
            self.remove()
        self.assertEqual(len(self.calls), 1)


class LocalAccountSnapshot(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pxe-snapshot-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('etc', 'etc/shadow-maint/userdel-pre.d', 'etc/shadow-maint/userdel-post.d', 'proc'):
            (self.root / name).mkdir(parents=True, exist_ok=True)
        self.nss = self.root / 'etc/nsswitch.conf'
        self.nss.write_text('passwd: files\ngroup: files\nshadow: files\n')
        self.login = self.root / 'etc/login.defs'
        self.login.write_text('# USERDEL_CMD /disabled\nUSERGROUPS_ENAB yes\n')
        self.passwd = self.root / 'etc/passwd'
        self.passwd.write_text(f'{NAME}:x:{UID}:{GID}:{GECOS}:{HOME}:{SHELL}\n'
                               'automation:x:1001:1001:Human automation:/home/automation:/bin/bash\n')
        self.group = self.root / 'etc/group'
        self.group.write_text(f'{NAME}:x:{GID}:\nautomation:x:1001:\nwww-data:x:33:\n')
        self.state = snapshot()
        self.process(1, (0, 0, 0, 0))

    def process(self, pid, ids=(1001, 1001, 1001, 1001), status=None):
        target = self.root / 'proc' / str(pid)
        target.mkdir()
        (target / 'status').write_text(status if status is not None else
                                       'Name:\tfixture\nUid:\t' + '\t'.join(map(str, ids)) + '\n')
        return target

    def take(self, *, owner=None):
        # The tested code receives fake passwd/group structures and an explicit
        # root. Trap any attempt to read the real host's /etc or /proc or NSS.
        original_open, original_io_open = builtins.open, io.open
        original_os_open, original_listdir, original_scandir = os.open, os.listdir, os.scandir
        original_stat, original_lstat, original_readlink, original_access = os.stat, os.lstat, os.readlink, os.access
        def check(path):
            if isinstance(path, (str, bytes, os.PathLike)):
                value = os.fsdecode(path)
                if value in ('/etc', '/proc') or value.startswith(('/etc/', '/proc/')):
                    raise AssertionError('real host path forbidden: ' + value)
            return path
        def safe_open(path, *args, **kwargs): return original_open(check(path), *args, **kwargs)
        def safe_io_open(path, *args, **kwargs): return original_io_open(check(path), *args, **kwargs)
        def safe_os_open(path, *args, **kwargs): return original_os_open(check(path), *args, **kwargs)
        def safe_listdir(path='.', *args, **kwargs): return original_listdir(check(path), *args, **kwargs)
        def safe_scandir(path='.', *args, **kwargs): return original_scandir(check(path), *args, **kwargs)
        def safe_stat(path, *args, **kwargs): return original_stat(check(path), *args, **kwargs)
        def safe_lstat(path, *args, **kwargs): return original_lstat(check(path), *args, **kwargs)
        def safe_readlink(path, *args, **kwargs): return original_readlink(check(path), *args, **kwargs)
        def safe_access(path, *args, **kwargs): return original_access(check(path), *args, **kwargs)
        with patch('builtins.open', side_effect=safe_open), patch('io.open', side_effect=safe_io_open), \
             patch('os.open', side_effect=safe_os_open), patch('os.listdir', side_effect=safe_listdir), \
             patch('os.scandir', side_effect=safe_scandir), patch('os.stat', side_effect=safe_stat), \
             patch('os.lstat', side_effect=safe_lstat), patch('os.readlink', side_effect=safe_readlink), \
             patch('os.access', side_effect=safe_access), patch.object(pwd, 'getpwall', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(pwd, 'getpwnam', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(pwd, 'getpwuid', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(os, 'getgrouplist', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(grp, 'getgrall', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(grp, 'getgrnam', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(grp, 'getgrgid', side_effect=AssertionError('real NSS forbidden')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('real command forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('real command forbidden')), \
             patch('os.system', side_effect=AssertionError('real command forbidden')):
            return uninstall.account_snapshot(self.root, self.state['accounts'], self.state['groups'],
                                              owner=os.geteuid() if owner is None else owner)

    def test_files_only_nss_returns_fixture_process_uids(self):
        self.process(123, (1001, 1002, 1003, 1004))
        result = self.take()
        self.assertEqual(result['process_uids'], {0, 1001, 1002, 1003, 1004})
        self.assertEqual(result['login_defs'], self.login.read_text())
        self.assertEqual(result['accounts'], self.state['accounts'])
        self.assertEqual(result['groups'], self.state['groups'])

    def test_files_then_systemd_is_supported_when_target_is_local(self):
        self.nss.write_text('passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n')
        self.process(5)
        result = self.take()
        self.assertEqual(result['process_uids'], {0, 1001})

    def test_account_already_removed_but_empty_dedicated_group_is_visible(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.passwd.write_text('automation:x:1001:1001:Human automation:/home/automation:/bin/bash\n')
        result = self.take()
        self.assertNotIn(NAME, [a.pw_name for a in result['accounts']])
        self.assertIn(NAME, [g.gr_name for g in result['groups']])

    def test_account_and_group_already_removed_are_observable(self):
        self.state['accounts'] = [a for a in self.state['accounts'] if a.pw_name != NAME]
        self.state['groups'] = [g for g in self.state['groups'] if g.gr_name != NAME]
        self.passwd.write_text('automation:x:1001:1001:Human automation:/home/automation:/bin/bash\n')
        self.group.write_text('automation:x:1001:\nwww-data:x:33:\n')
        result = self.take()
        self.assertNotIn(NAME, [a.pw_name for a in result['accounts']])
        self.assertNotIn(NAME, [g.gr_name for g in result['groups']])

    def test_target_in_nss_but_not_local_passwd_is_refused(self):
        self.nss.write_text('passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n')
        self.passwd.write_text('automation:x:1001:1001:Human automation:/home/automation:/bin/bash\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_target_group_in_nss_but_not_local_group_is_refused(self):
        self.nss.write_text('passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n')
        self.group.write_text('automation:x:1001:\nwww-data:x:33:\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_local_target_identity_different_from_nss_is_refused(self):
        self.passwd.write_text(f'{NAME}:x:{UID + 1}:{GID}:{GECOS}:{HOME}:{SHELL}\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_local_target_group_identity_different_from_nss_is_refused(self):
        self.group.write_text(f'{NAME}:x:{GID + 1}:\nautomation:x:1001:\nwww-data:x:33:\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_duplicate_local_target_records_are_refused(self):
        line = f'{NAME}:x:{UID}:{GID}:{GECOS}:{HOME}:{SHELL}\n'
        self.passwd.write_text(line + line)
        with self.assertRaises(ValueError):
            self.take()
        self.passwd.write_text(line)
        self.group.write_text(f'{NAME}:x:{GID}:\n{NAME}:x:{GID}:\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_nonlocal_nss_or_ambiguous_order_and_control_actions_are_refused(self):
        for entry in ('passwd: files sss', 'passwd: files ldap', 'passwd: compat',
                      'passwd: files nis', 'passwd: systemd files',
                      'passwd: files [SUCCESS=merge] systemd'):
            with self.subTest(entry=entry):
                self.nss.write_text(entry + '\ngroup: files\nshadow: files\n')
                with self.assertRaises(ValueError):
                    self.take()

    def test_nonlocal_group_or_shadow_nss_is_refused(self):
        for entry in ('group: files sss', 'shadow: files ldap'):
            with self.subTest(entry=entry):
                self.nss.write_text('passwd: files\n' + entry + '\n')
                with self.assertRaises(ValueError):
                    self.take()

    def test_missing_or_duplicate_nss_fields_are_refused(self):
        for text in ('passwd: files\ngroup: files\n',
                     'passwd: files\npasswd: sss\ngroup: files\nshadow: files\n'):
            with self.subTest(text=text):
                self.nss.write_text(text)
                with self.assertRaises(ValueError):
                    self.take()

    def test_linked_or_unreadable_identity_files_are_refused(self):
        for path in (self.nss, self.login, self.passwd, self.group):
            with self.subTest(path=path.name):
                original = path.read_text()
                path.unlink()
                path.symlink_to(self.root / 'external')
                with self.assertRaises((ValueError, OSError)):
                    self.take()
                path.unlink()
                path.write_text(original)
                path.chmod(0)
                with self.assertRaises((ValueError, OSError)):
                    self.take()
                path.chmod(0o644)

    def test_unexpected_owner_or_world_writable_identity_file_refuses(self):
        self.passwd.chmod(0o666)
        with self.assertRaises(ValueError):
            self.take()
        self.passwd.chmod(0o644)
        with self.assertRaises(ValueError):
            self.take(owner=-1)

    def test_bad_local_passwd_or_group_records_refuse(self):
        for path in (self.passwd, self.group):
            with self.subTest(path=path.name):
                original = path.read_text()
                path.write_text('malformed\n')
                with self.assertRaises(ValueError):
                    self.take()
                path.write_text(original)

    def test_any_of_four_process_uids_matching_target_refuses(self):
        for index in range(4):
            with self.subTest(index=index):
                ids = [1001, 1001, 1001, 1001]
                ids[index] = UID
                proc = self.process(100 + index, ids)
                with self.assertRaises(ValueError):
                    self.take()
                (proc / 'status').unlink()
                proc.rmdir()

    def test_empty_process_inventory_is_not_assumed_safe(self):
        (self.root / 'proc/1/status').unlink()
        (self.root / 'proc/1').rmdir()
        with self.assertRaises(ValueError):
            self.take()

    def test_pid_without_status_is_not_treated_as_inactive(self):
        (self.root / 'proc/42').mkdir()
        with self.assertRaises((ValueError, OSError)):
            self.take()

    def test_linked_proc_root_is_not_followed(self):
        (self.root / 'proc').rename(self.root / 'proc-original')
        external = self.root / 'external-proc'
        external.mkdir()
        (external / 'witness').write_text('keep')
        (self.root / 'proc').symlink_to(external, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.take()
        self.assertEqual((external / 'witness').read_text(), 'keep')

    def test_malformed_or_unreadable_process_status_refuses(self):
        proc = self.process(42, status='Name:\tbroken\nUid:\t1001 1001\n')
        with self.assertRaises(ValueError):
            self.take()
        (proc / 'status').write_text('Name:\tfixture\nUid:\t1001 1001 1001 1001\n')
        (proc / 'status').chmod(0)
        with self.assertRaises((ValueError, OSError)):
            self.take()

    def test_linked_numeric_proc_entry_and_status_refuse(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'status').write_text('Uid:\t1001 1001 1001 1001\n')
        (self.root / 'proc/50').symlink_to(external, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.take()
        (self.root / 'proc/50').unlink()
        proc = self.root / 'proc/51'
        proc.mkdir()
        (proc / 'status').symlink_to(external / 'status')
        with self.assertRaises((ValueError, OSError)):
            self.take()
        self.assertTrue((external / 'status').exists())

    def test_active_userdel_cmd_refuses_during_snapshot(self):
        self.login.write_text('USERDEL_CMD /usr/local/sbin/delete-other-data\n')
        with self.assertRaises(ValueError):
            self.take()

    def test_executable_or_linked_shadow_hook_refuses_during_snapshot(self):
        hook = self.root / 'etc/shadow-maint/userdel-pre.d/hook'
        hook.write_text('#!/bin/sh\nexit 0\n')
        hook.chmod(0o755)
        with self.assertRaises(ValueError):
            self.take()
        hook.unlink()
        hook.symlink_to(self.root / 'elsewhere')
        with self.assertRaises((ValueError, OSError)):
            self.take()

    def test_missing_optional_shadow_hook_directories_are_safe(self):
        (self.root / 'etc/shadow-maint/userdel-pre.d').rmdir()
        (self.root / 'etc/shadow-maint/userdel-post.d').rmdir()
        (self.root / 'etc/shadow-maint').rmdir()
        result = self.take()
        self.assertEqual(result['userdel_hooks'], [])

    def test_linked_shadow_hook_directory_is_not_followed(self):
        directory = self.root / 'etc/shadow-maint/userdel-pre.d'
        directory.rmdir()
        external = self.root / 'external-hooks'
        external.mkdir()
        (external / 'witness').write_text('keep')
        directory.symlink_to(external, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.take()
        self.assertEqual((external / 'witness').read_text(), 'keep')

    def test_non_executable_hook_is_reported_without_running(self):
        hook = self.root / 'etc/shadow-maint/userdel-post.d/disabled'
        hook.write_text('not executable')
        hook.chmod(0o644)
        result = self.take()
        self.assertEqual(result['userdel_hooks'], [{'path': '/etc/shadow-maint/userdel-post.d/disabled',
                                                    'mode': 0o644, 'kind': 'file'}])



if __name__ == '__main__':
    unittest.main()
