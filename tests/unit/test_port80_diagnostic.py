#!/usr/bin/env python3
"""Exercise read-only diagnoses and the fixed reversible nginx stop with fixtures."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'app'))
import port80_diagnostic as diagnostic
spec = importlib.util.spec_from_file_location('release_nginx', ROOT / 'docker/worker/scripts/native-release-nginx-port.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
NGINX = {'pid':'123', 'exe':'/usr/sbin/nginx', 'groups':['/system.slice/nginx.service']}
PXE = {'pid':'456', 'exe':'/usr/sbin/nginx', 'groups':['/system.slice/pxe-tools-pxe-http.service']}
ROW = {'family':4, 'address':'0.0.0.0', 'inode':'12345'}


class Diagnosis(unittest.TestCase):
    def run_diagnosis(self, rows, owners=None, healthy=False, **options):
        with patch.object(diagnostic, 'socket_rows', return_value=rows), patch.object(diagnostic, 'owners', return_value=owners or {}):
            return diagnostic.diagnose('192.0.2.17', probe=lambda address: healthy, **options)

    def test_free_is_neutral_without_process_probe(self):
        self.assertEqual(self.run_diagnosis([])['state'], 'free')
        self.assertEqual(self.run_diagnosis([dict(ROW, address='198.51.100.1')])['state'], 'free')

    def test_expected_response_is_functional_even_for_shared_nginx(self):
        result = self.run_diagnosis([ROW], {ROW['inode']:[NGINX]}, healthy=True)
        self.assertEqual(result['state'], 'ready')
        self.assertFalse(result['can_stop'])

    def test_missing_rights_are_indeterminate(self):
        result = self.run_diagnosis([ROW])
        self.assertEqual(result['state'], 'unknown')
        self.assertFalse(result['can_stop'])
        with patch.object(diagnostic, 'socket_rows', side_effect=PermissionError):
            self.assertEqual(diagnostic.diagnose('192.0.2.17')['state'], 'unknown')

    def test_expected_unit_without_health_is_not_a_competing_service(self):
        self.assertEqual(self.run_diagnosis([ROW], {ROW['inode']:[PXE]})['state'], 'starting')

    def test_legacy_health_response_never_claims_a_conflict(self):
        with patch.object(diagnostic, 'socket_rows', return_value=[ROW]):
            result = diagnostic.diagnose('192.0.2.17', probe=lambda address: 'compatible')
        self.assertEqual(result['state'], 'unknown')
        self.assertFalse(result['can_stop'])

    def test_confirmed_competing_service_and_verified_snapshot(self):
        with patch.object(diagnostic.Path, 'read_text', side_effect=['123', 'fixture-boot']), patch.object(diagnostic, 'process_start', return_value='42'):
            result = self.run_diagnosis([ROW], {ROW['inode']:[NGINX]})
        self.assertEqual(result['state'], 'conflict')
        self.assertTrue(result['can_stop'])
        self.assertEqual(result['fingerprint'], diagnostic.snapshot_fingerprint([ROW]))
        self.assertEqual(result['service'], 'nginx.service')

    def test_ipv6_wildcard_alone_does_not_prove_ipv4_collision(self):
        ipv6 = dict(ROW, family=6, address='::')
        self.assertEqual(self.run_diagnosis([ipv6], {ROW['inode']:[NGINX]})['state'], 'unknown')
        self.assertEqual(self.run_diagnosis([ROW, dict(ipv6, inode='678')], {ROW['inode']:[PXE], '678':[NGINX]})['state'], 'unknown')

    def test_docker_wildcard_considers_other_local_ipv4_addresses(self):
        row = dict(ROW, address='198.51.100.1')
        result = self.run_diagnosis([row], {row['inode']:[dict(NGINX, exe='/usr/sbin/apache2', groups=['/system.slice/apache2.service'])]}, wildcard=True)
        self.assertEqual(result['state'], 'conflict')
        self.assertFalse(result['can_stop'])

    def test_socket_tables_decode_ipv4_and_ipv6(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'net').mkdir()
            (root / 'net/tcp').write_text('header\n0: 110200C0:0050 00000000:0000 0A 0 0 0 0 0 12345\n')
            (root / 'net/tcp6').write_text('header\n0: 00000000000000000000000000000000:0050 0:0000 0A 0 0 0 0 0 67890\n')
            rows = diagnostic.socket_rows(root)
            self.assertEqual([row['address'] for row in rows], ['192.0.2.17', '::'])
            self.assertTrue(diagnostic.relevant(rows[0], ['192.0.2.17']))


class ReversibleStop(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.db = Path(self.temporary.name) / 'db.sqlite'
        self.boot = '11111111-2222-3333-4444-555555555555'
        self.snapshot = {'state':'conflict', 'can_stop':True, 'service':'nginx.service', 'pid':'123', 'start':'42',
                         'boot':self.boot, 'fingerprint':diagnostic.snapshot_fingerprint([ROW])}
        self.consent = f"nginx-consent-v2:123:42:{int(time.time())}:{self.boot}:192.0.2.17:{self.snapshot['fingerprint']}"
        self.commands = []

    def run_action(self, *, changed=False, consent=None, snapshot_changes=None, main_pid='123', boot=None, socket_race=False):
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE init_jobs (id INTEGER,job_type TEXT,status TEXT,message TEXT)')
            db.execute('INSERT INTO init_jobs VALUES (1,?,?,?)', ('system:release_nginx_port','running',consent or self.consent))
        stopped = False
        def systemctl(*args, **options):
            nonlocal stopped
            self.commands.append(args)
            if args[0] == 'stop': stopped = True
            output = main_pid if '--property=MainPID' in args else '/system.slice/nginx.service' if '--property=ControlGroup' in args else ''
            return subprocess.CompletedProcess(args, 3 if stopped and args[0] == 'is-active' else 0, output)
        snapshot = dict(self.snapshot, **(snapshot_changes or {}))
        snapshots = [dict(snapshot, fingerprint='0'*64) if changed else snapshot, {'state':'free'}]
        stat = '123 (nginx) ' + ' '.join(['S'] + ['0']*18 + ['42'])
        with patch.dict(os.environ, {'PXE_SERVICE_MANAGER':'systemd','PXE_DB_PATH':str(self.db),'WORKER_JOB_ID':'1'}), \
             patch.object(release.os, 'geteuid', return_value=0), patch.object(release.Path, 'is_dir', return_value=True), \
             patch.object(release.Path, 'read_text', side_effect=lambda path=None: self.boot), \
             patch.object(release, 'systemctl', side_effect=systemctl), patch.object(release, 'diagnose', side_effect=snapshots), \
             patch.object(release, 'socket_rows', side_effect=[[ROW], [ROW, dict(ROW, inode='678')]] if socket_race else None, return_value=[ROW]), patch.object(release, 'process_start', return_value='42'), \
             patch.object(release, 'verify_owners') as verify, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            # Existing main validates /proc stat before the shared snapshot.
            with patch.object(release.Path, 'read_text', side_effect=[boot or self.boot, stat]):
                release.main()
            verify.assert_called_once_with({ROW['inode']}, '/system.slice/nginx.service')

    def test_stop_is_reversible_and_never_changes_enabled_state(self):
        self.run_action()
        self.assertIn(('stop', 'nginx.service'), self.commands)
        self.assertFalse(any(command[0] in ('disable','mask','enable','kill') for command in self.commands))

    def test_changed_occupant_is_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(changed=True)
        self.assertNotIn(('stop','nginx.service'), self.commands)

    def test_old_unbound_confirmation_is_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(consent='nginx-consent-v1:123:42:1:' + self.boot)
        self.assertNotIn(('stop','nginx.service'), self.commands)

    def test_changed_master_pid_is_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(main_pid='999')
        self.assertNotIn(('stop','nginx.service'), self.commands)

    def test_changed_boot_is_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(boot='22222222-2222-3333-4444-555555555555')
        self.assertNotIn(('stop','nginx.service'), self.commands)

    def test_missing_identity_is_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(snapshot_changes={'can_stop':False})
        self.assertNotIn(('stop','nginx.service'), self.commands)

    def test_socket_changes_after_validation_are_rejected_without_stop(self):
        with self.assertRaises(SystemExit): self.run_action(socket_race=True)
        self.assertNotIn(('stop','nginx.service'), self.commands)


if __name__ == '__main__':
    unittest.main()
