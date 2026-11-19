#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Native maintainer-script regression; all files/services are disposable fixtures.

The test executes the real package POSTINST and secure fresh-runtime helper.
Only external service/package commands and the unrelated upgrade lifecycle are
doubled. Never execute the package-building entry point or a real service manager.
"""
import hashlib
from datetime import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


class FixtureRunner:
    """A deterministic systemd/dpkg boundary shared by the subprocess fixture."""

    def __init__(self, root, on_call=None):
        self.root = Path(root)
        self.on_call = on_call

    def __call__(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        command, args = Path(argv[0]).name, argv[1:]
        if self.on_call is not None:
            self.on_call(argv)
        state_path = self.root / 'services.json'
        state = json.loads(state_path.read_text())
        state['calls'].append(argv)
        output, status = '', 0
        if command == 'systemctl':
            action = args[0]
            unit = next((arg for arg in reversed(args) if arg.endswith(('.service', '.target'))), '')
            service = state['units'].setdefault(unit, {'active': False, 'enabled': 'static'})
            if action == 'show':
                properties = []
                for index, arg in enumerate(args):
                    if arg.startswith(('--property=', '-p=')):
                        properties.extend(arg.split('=', 1)[1].split(','))
                    elif arg in ('-p', '--property'):
                        properties.extend(args[index + 1].split(','))
                values = {
                    'Id': unit, 'LoadState': 'loaded',
                    'ActiveState': 'active' if service['active'] else 'inactive',
                    'SubState': 'running' if service['active'] else 'dead',
                    'UnitFileState': service['enabled'],
                    'MainPID': '123' if service['active'] else '0',
                    'ControlGroup': '/system.slice/nginx.service',
                    'FragmentPath': '/usr/lib/systemd/system/nginx.service',
                    'DropInPaths': '', 'NeedDaemonReload': 'no',
                    'ExecStart': '{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; }',
                }
                values.update(state.get('properties', {}))
                output = '\n'.join(values.get(prop, '') if '--value' in args
                                   else prop + '=' + values.get(prop, '') for prop in properties)
            elif action == 'is-active':
                status = 0 if service['active'] else 3
                output = 'active' if service['active'] else 'inactive'
            elif action == 'is-enabled':
                output = service['enabled']
                status = 0 if output in ('enabled', 'enabled-runtime', 'static') else 1
            elif action == 'stop':
                service['active'] = False
                if unit == 'nginx.service':
                    tcp = self.root / 'proc/net/tcp'
                    tcp.write_text(''.join(line for line in tcp.read_text().splitlines(keepends=True)
                                           if len(line.split()) < 10 or line.split()[9] != '42'))
            elif action == 'disable':
                service['enabled'] = 'disabled'
                if '--now' in args:
                    service['active'] = False
            elif action == 'enable':
                service['enabled'] = 'enabled'
                if '--now' in args:
                    service['active'] = True
            elif action == 'start':
                service['active'] = True
                if unit == 'nginx.service':
                    tcp = self.root / 'proc/net/tcp'
                    if not any(len(line.split()) >= 10 and line.split()[9] == '42'
                               for line in tcp.read_text().splitlines()):
                        with tcp.open('a') as stream:
                            stream.write('   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42 1\n')
            elif action != 'daemon-reload':
                raise AssertionError('Unexpected service mutation: ' + repr(argv))
        elif command == 'dpkg-query':
            if any('Conffiles' in arg for arg in args):
                output = '\n'.join(' ' + path + ' ' + digest
                                   for path, digest in state['conffiles'].items())
            elif '-S' in args or '--search' in args:
                output = 'nginx-common: ' + args[-1]
            elif any('Version' in arg for arg in args):
                output = '0.1.0~beta7' if args[-1] == 'pxe-tools' else '1.24.0-2ubuntu7.19'
            else:
                output = 'install ok installed'
        else:
            raise AssertionError('Unexpected external command: ' + repr(argv))
        state_path.write_text(json.dumps(state))
        result = subprocess.CompletedProcess(argv, status, output + ('\n' if output else ''), '')
        if kwargs.get('check') and status:
            raise subprocess.CalledProcessError(status, argv, output=result.stdout)
        return result


class PackageFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.write('/etc/nginx/nginx.conf',
                   'events { worker_connections 768; }\nhttp {\n'
                   ' include /etc/nginx/mime.types;\n'
                   ' include /etc/nginx/conf.d/*.conf;\n'
                   ' include /etc/nginx/sites-enabled/*;\n}\n')
        self.write('/etc/nginx/mime.types', 'types { text/html html; }\n')
        self.write('/etc/nginx/sites-available/default',
                   'server {\n listen 80 default_server;\n'
                   ' listen [::]:80 default_server;\n'
                   ' root /var/www/html;\n server_name _;\n'
                   ' location / { try_files $uri $uri/ =404; }\n}\n')
        enabled = self.path('/etc/nginx/sites-enabled/default')
        enabled.parent.mkdir(parents=True)
        enabled.symlink_to('../sites-available/default')
        self.path('/etc/nginx/conf.d').mkdir()
        self.path('/etc/nginx/modules-enabled').mkdir()
        welcome = b'<!doctype html><title>Welcome to nginx!</title>nginx.org Thank you for using nginx.\n'
        self.write('/var/www/html/index.nginx-debian.html', welcome)
        self.write('/usr/share/nginx/html/index.html', welcome)
        self.write('/usr/lib/systemd/system/nginx.service',
                   '[Service]\nType=forking\nExecStart=/usr/sbin/nginx -g daemon on; master_process on;\n')
        self.write('/usr/sbin/nginx', '#!/bin/sh\nexit 0\n')
        self.path('/usr/sbin/nginx').chmod(0o755)
        self.write('/proc/123/cgroup', '0::/system.slice/nginx.service\n')
        self.write('/proc/123/cmdline',
                   b'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\0')
        self.path('/proc/123/exe').symlink_to(self.path('/usr/sbin/nginx'))
        self.path('/proc/123/fd').mkdir()
        self.path('/proc/123/fd/5').symlink_to('socket:[42]')
        self.write('/proc/net/tcp',
                   '  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
                   '   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42 1\n')
        self.write('/proc/net/tcp6',
                   '  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n')
        self.write('/proc/sys/kernel/random/boot_id', '12345678-1234-1234-1234-123456789abc\n')
        self.path('/run/systemd/system').mkdir(parents=True)
        self.path('/run/lock').mkdir(parents=True, exist_ok=True)
        self.write('/var/log/apt/history.log',
                   'Start-Date: 2026-11-14  21:00:36\n'
                   'Commandline: apt-get install pxe-tools\n'
                   'Install: nginx:amd64 (1.24.0-2ubuntu7.19, automatic), '
                   'nginx-common:all (1.24.0-2ubuntu7.19, automatic), '
                   'pxe-tools:amd64 (0.1.0~beta7)\n'
                   'End-Date: 2026-11-14  21:01:03\n\n')
        self.write('/var/log/dpkg.log',
                   '2026-11-14 21:00:38 install nginx-common:all <none> 1.24.0-2ubuntu7.19\n'
                   '2026-11-14 21:00:38 install nginx:amd64 <none> 1.24.0-2ubuntu7.19\n'
                   '2026-11-14 21:00:40 install pxe-tools:amd64 <none> 0.1.0~beta7\n'
                   '2026-11-14 21:00:44 status installed nginx-common:all 1.24.0-2ubuntu7.19\n'
                   '2026-11-14 21:00:57 status installed nginx:amd64 1.24.0-2ubuntu7.19\n')
        conffiles = {name: hashlib.md5(self.path(name).read_bytes()).hexdigest()
                     for name in ('/etc/nginx/nginx.conf', '/etc/nginx/sites-available/default',
                                  '/etc/nginx/mime.types')}
        self.state = self.root / 'services.json'
        self.state.write_text(json.dumps({'calls': [], 'conffiles': conffiles, 'units': {
            'nginx.service': {'active': True, 'enabled': 'enabled'},
            'pxe-tools-admin.target': {'active': False, 'enabled': 'disabled'},
            'pxe-tools.target': {'active': False, 'enabled': 'disabled'},
            'pxe-tools-dnsmasq.service': {'active': False, 'enabled': 'static'},
            'pxe-tools-pxe-http.service': {'active': False, 'enabled': 'static'},
        }}))
        self.write('/var/lib/dpkg/info/nginx-common.md5sums', '\n'.join(
            hashlib.md5(self.path(name).read_bytes()).hexdigest() + '  ' + name.lstrip('/')
            for name in ('/usr/lib/systemd/system/nginx.service', '/usr/share/nginx/html/index.html')) + '\n')
        self.start_master_after_fixture()

    def path(self, name):
        return self.root / name.lstrip('/')

    def write(self, name, data):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def start_master_after_fixture(self):
        boot = int(time.time()) - 10000
        ticks = int((time.time() - boot + 0.1) * os.sysconf('SC_CLK_TCK'))
        self.write('/proc/stat', 'cpu 0 0 0 0\nbtime ' + str(boot) + '\n')
        self.write('/proc/123/stat', '123 (nginx) ' + ' '.join(['0'] * 19 + [str(ticks)]) + '\n')

    def service_state(self):
        return json.loads(self.state.read_text())

    def set_unit(self, *, active=None, enabled=None):
        state = self.service_state()
        if active is not None:
            state['units']['nginx.service']['active'] = active
        if enabled is not None:
            state['units']['nginx.service']['enabled'] = enabled
        self.state.write_text(json.dumps(state))

    def reconciler(self, *, run=None, configuring=False):
        spec = importlib.util.spec_from_file_location('nginx_ownership_under_test', ROOT / 'packaging/native/reconcile-nginx.py')
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module.Reconciler(root=self.root, run=run or FixtureRunner(self.root), configuring=configuring)

    def run_postinst(self, old_version=''):
        spec = importlib.util.spec_from_file_location('nginx_fixture_builder', ROOT / 'packaging/native/build-local-package.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        script = builder.POSTINST
        for prefix in ('/usr/lib/pxe-tools', '/run/systemd/system', '/var/lib/pxe-tools', '/etc/pxe-tools'):
            script = script.replace(prefix, str(self.path(prefix)))
        bin_dir = self.root / 'bin'
        bin_dir.mkdir(exist_ok=True)
        entry = (
            '#!' + sys.executable + '\n'
            'import os, sys, importlib.util, json\n'
            'from pathlib import Path\n'
            'sys.path.insert(0, ' + repr(str(Path(__file__).parent)) + ')\n'
            'from test_native_nginx_ownership import FixtureRunner\n'
            'root=Path(os.environ["NGINX_FIXTURE_ROOT"])\n'
        )
        systemctl = bin_dir / 'systemctl'
        systemctl.write_text(entry + 'result=FixtureRunner(root)(["systemctl", *sys.argv[1:]])\n'
                             'sys.stdout.write(result.stdout)\nsys.exit(result.returncode)\n')
        systemctl.chmod(0o755)
        python = bin_dir / 'python3'
        python.write_text(entry +
            'if Path(sys.argv[1]).name == "reconcile-nginx.py":\n'
            ' spec=importlib.util.spec_from_file_location("fixture_reconciler", '
            + repr(str(ROOT / 'packaging/native/reconcile-nginx.py')) + ')\n'
            ' module=importlib.util.module_from_spec(spec)\n'
            ' sys.modules[spec.name]=module\n spec.loader.exec_module(module)\n'
            ' result=module.Reconciler(root=root, run=FixtureRunner(root), configuring=True).reconcile()\n'
            ' print(json.dumps(result))\n'
            'elif Path(sys.argv[1]).name == "ownership-provenance.py" and sys.argv[2] == "recover-initialization":\n'
            ' print("unchanged")\n'
            'elif Path(sys.argv[1]).name == "configure-secure-tftp.py":\n'
            ' spec=importlib.util.spec_from_file_location("fixture_secure_setup", '
            + repr(str(ROOT / 'packaging/native/configure-secure-tftp.py')) + ')\n'
            ' module=importlib.util.module_from_spec(spec)\n'
            ' sys.modules[spec.name]=module\n spec.loader.exec_module(module)\n'
            ' ownspec=importlib.util.spec_from_file_location("fixture_native_ownership", '
            + repr(str(ROOT / 'packaging/native/ownership-provenance.py')) + ')\n'
            ' own=importlib.util.module_from_spec(ownspec)\n'
            ' sys.modules[ownspec.name]=own\n ownspec.loader.exec_module(own)\n'
            ' store=own.Store(root, owner=0)\n'
            ' def activate():\n'
            '  module.activate_admin(FixtureRunner(root))\n'
            ' def initialize(held):\n'
            '  store.create_base(require_runtime=True, native_fds=held, activate=activate)\n'
            ' module.prepare(base=root / "var/lib", journal=store, '
            'after_create=initialize if "--initialize-instance" in sys.argv else None)\n')
        python.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                   NGINX_FIXTURE_ROOT=str(self.root), PYTHONDONTWRITEBYTECODE='1',
                   DPKG_MAINTSCRIPT_PACKAGE='pxe-tools', DPKG_MAINTSCRIPT_NAME='postinst')
        return subprocess.run(['/bin/sh', '-s', 'configure', old_version], input=script,
                              env=env, text=True, capture_output=True, check=True)


@unittest.skipUnless(os.geteuid() == 0 and Path('/root').is_dir(), 'requires a root-owned Linux fixture')
class MaintainerRegression(unittest.TestCase):
    def test_fresh_dependency_does_not_leave_generic_nginx_owning_boot_port(self):
        with tempfile.TemporaryDirectory(prefix='pxe-nginx-ownership-', dir='/root') as directory:
            fixture = PackageFixture(directory)
            fixture.run_postinst()
            state = json.loads(fixture.state.read_text())
            self.assertFalse(state['units']['nginx.service']['active'],
                             'APT-installed stock nginx must not retain the PXE boot listener')
            self.assertEqual(state['units']['nginx.service']['enabled'], 'disabled')
            self.assertTrue(state['units']['pxe-tools-admin.target']['active'])
            for unit in ('pxe-tools.target', 'pxe-tools-dnsmasq.service', 'pxe-tools-pxe-http.service'):
                self.assertFalse(state['units'][unit]['active'], unit + ' must not start during configure')
            self.assertTrue(fixture.path('/etc/nginx/sites-enabled/default').is_symlink())
            self.assertEqual(fixture.path('/var/www/html/index.nginx-debian.html').read_bytes(),
                             fixture.path('/usr/share/nginx/html/index.html').read_bytes())
            runtime = fixture.path('/var/lib/pxe-tools-native/runtime.env')
            self.assertIn(b'TFTP_ROOT=/var/lib/pxe-tools-tftp\n', runtime.read_bytes())
            self.assertIn(b'HTTP_ROOT=/var/lib/pxe-tools-http\n', runtime.read_bytes())
            self.assertEqual(runtime.stat().st_uid, 0)
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o644)
            for name in ('pxe-tools-native', 'pxe-tools-tftp', 'pxe-tools-http'):
                path = fixture.path('/var/lib/' + name)
                self.assertEqual(path.stat().st_uid, 0)
                self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertEqual(fixture.path('/var/lib/pxe-tools-native/network.env').read_bytes(), b'')

    def test_affected_upgrade_does_not_start_previously_stopped_application_roles(self):
        with tempfile.TemporaryDirectory(prefix='pxe-nginx-upgrade-') as directory:
            fixture = PackageFixture(directory)
            history = fixture.path('/var/log/apt/history.log')
            history.write_text(history.read_text().replace('pxe-tools:amd64 (0.1.0~beta7)',
                                                           'pxe-tools:amd64 (0.1.0~beta5)'))
            fixture.run_postinst(old_version='0.1.0~beta7')
            state = fixture.service_state()
            self.assertFalse(state['units']['nginx.service']['active'])
            self.assertEqual(state['units']['nginx.service']['enabled'], 'disabled')
            for unit in ('pxe-tools-admin.target', 'pxe-tools.target',
                         'pxe-tools-dnsmasq.service', 'pxe-tools-pxe-http.service'):
                self.assertFalse(state['units'][unit]['active'], unit + ' must preserve its stopped state')
            self.assertFalse(fixture.path('/var/lib/pxe-tools-native/runtime.env').exists(),
                             'upgrade must not prepare or overwrite a fresh runtime')


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pxe-nginx-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.fixture = PackageFixture(self.temporary.name)

    def assert_generic_preserved(self, before):
        after = self.fixture.service_state()
        self.assertEqual(after['units']['nginx.service'], before['units']['nginx.service'])
        destructive = [argv for argv in after['calls'][len(before['calls']):]
                       if argv[0].endswith('systemctl') and argv[1] in ('stop', 'disable', 'mask')]
        self.assertEqual(destructive, [], 'unowned/custom nginx must not be changed')

    def test_closed_first_install_provenance_releases_stock_dependency(self):
        result = self.fixture.reconciler().reconcile()
        self.assertEqual(result['action'], 'disabled')
        state = self.fixture.service_state()
        self.assertFalse(state['units']['nginx.service']['active'])
        self.assertEqual(state['units']['nginx.service']['enabled'], 'disabled')
        journal = self.fixture.path('/var/lib/pxe-tools-nginx-ownership/state.json')
        record = json.loads(journal.read_text())
        self.assertEqual(record['format'], 1)
        self.assertEqual(record['phase'], 'complete')
        self.assertEqual(record['service'], 'nginx.service')
        self.assertEqual(record['before'], {'active': 'active', 'enabled': 'enabled'})
        self.assertEqual(record['after'], {'active': 'inactive', 'enabled': 'disabled'})
        self.assertEqual(record['provenance']['source'], 'apt-and-dpkg')
        self.assertIn('/etc/nginx/nginx.conf', record['resources'])
        self.assertEqual(journal.stat().st_uid, 0)
        self.assertEqual(journal.parent.stat().st_uid, 0)
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(journal.parent.stat().st_mode & 0o777, 0o700)

    def test_inflight_apt_transaction_is_accepted_only_in_configure_context(self):
        stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        start = stamp.replace(' ', '  ', 1)
        self.fixture.write('/var/log/apt/history.log',
                           'Start-Date: ' + start + '\nCommandline: apt-get install pxe-tools\n'
                           'Install: nginx:amd64 (1.24.0-2ubuntu7.19, automatic), '
                           'nginx-common:all (1.24.0-2ubuntu7.19, automatic), '
                           'pxe-tools:amd64 (0.1.0~beta7)\n')
        self.fixture.write('/var/log/dpkg.log',
                           stamp + ' install nginx-common:all <none> 1.24.0-2ubuntu7.19\n'
                           + stamp + ' install nginx:amd64 <none> 1.24.0-2ubuntu7.19\n'
                           + stamp + ' install pxe-tools:amd64 <none> 0.1.0~beta7\n'
                           + stamp + ' status installed nginx-common:all 1.24.0-2ubuntu7.19\n'
                           + stamp + ' status installed nginx:amd64 1.24.0-2ubuntu7.19\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)
        reconciler = self.fixture.reconciler(configuring=True)
        with patch.object(reconciler, 'apt_started', return_value=datetime.fromisoformat(stamp).timestamp()), \
                patch.dict(os.environ, {'DPKG_MAINTSCRIPT_PACKAGE': 'pxe-tools',
                                        'DPKG_MAINTSCRIPT_NAME': 'postinst'}):
            result = reconciler.reconcile()
        self.assertEqual(result['action'], 'disabled')

    def test_nginx_installed_independently_is_preserved(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace(
            ', pxe-tools:amd64 (0.1.0~beta7)', ''))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_manually_selected_nginx_in_same_transaction_is_preserved(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace(
            'nginx:amd64 (1.24.0-2ubuntu7.19, automatic)',
            'nginx:amd64 (1.24.0-2ubuntu7.19)'))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_other_manual_application_in_same_transaction_is_preserved(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace(
            'pxe-tools:amd64 (0.1.0~beta7)',
            'pxe-tools:amd64 (0.1.0~beta7), customer-web:all (1.0)'))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_core_installed_as_an_automatic_dependency_is_preserved(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace(
            'pxe-tools:amd64 (0.1.0~beta7)',
            'pxe-tools:amd64 (0.1.0~beta7, automatic)'))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_manually_requested_core_and_its_optional_module_are_owned(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace(
            'pxe-tools:amd64 (0.1.0~beta7)',
            'pxe-tools:amd64 (0.1.0~beta7), pxe-tools-ansible:all (0.1.0~beta7)'))
        result = self.fixture.reconciler().reconcile()
        self.assertEqual(result['action'], 'disabled')
        state = self.fixture.service_state()
        self.assertFalse(state['units']['nginx.service']['active'])
        self.assertEqual(state['units']['nginx.service']['enabled'], 'disabled')

    def test_failed_apt_transaction_is_not_an_ownership_receipt(self):
        history = self.fixture.path('/var/log/apt/history.log')
        history.write_text(history.read_text().replace('End-Date:',
                                                       'Error: dpkg failed\nEnd-Date:'))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_missing_history_requires_explicit_stock_confirmation(self):
        self.fixture.path('/var/log/apt/history.log').unlink()
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)
        result = self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assertEqual(result['action'], 'disabled')

    def test_modified_conffile_is_preserved_even_with_confirmation(self):
        self.fixture.write('/etc/nginx/sites-available/default',
                           'server { listen 80; root /srv/customer; }\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_extra_conf_d_site_is_preserved(self):
        self.fixture.write('/etc/nginx/conf.d/customer.conf',
                           'server { listen 443 ssl; proxy_pass http://127.0.0.1:9001; }\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_custom_web_content_is_preserved(self):
        self.fixture.write('/var/www/html/customer.html', '<h1>Customer content</h1>\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_edited_welcome_page_is_preserved(self):
        self.fixture.write('/var/www/html/index.nginx-debian.html', '<h1>Custom home</h1>\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_custom_systemd_dropin_is_preserved(self):
        state = self.fixture.service_state()
        state['properties'] = {'DropInPaths': '/etc/systemd/system/nginx.service.d/customer.conf'}
        self.fixture.state.write_text(json.dumps(state))
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_master_with_another_listening_port_is_preserved(self):
        self.fixture.path('/proc/123/fd/6').symlink_to('socket:[43]')
        with self.fixture.path('/proc/net/tcp').open('a') as output:
            output.write('   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 43 1\n')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assert_generic_preserved(before)

    def test_stock_file_changed_after_master_start_is_not_assumed_loaded(self):
        config = self.fixture.path('/etc/nginx/nginx.conf')
        # Keep the package bytes/hash, but make the file newer than the loaded
        # master. A matching file on disk does not prove its loaded contents.
        modified = time.time() + 5
        os.utime(config, (modified, modified))
        before = self.fixture.service_state()
        result = self.fixture.reconciler().reconcile(confirm_stock=True)
        self.assertEqual(result['action'], 'conflict')
        self.assert_generic_preserved(before)

    def test_intentional_service_states_are_preserved(self):
        for active, enabled in ((False, 'enabled'), (False, 'disabled'),
                                (False, 'masked'), (True, 'disabled')):
            with self.subTest(active=active, enabled=enabled):
                self.fixture.set_unit(active=active, enabled=enabled)
                before = self.fixture.service_state()
                self.fixture.reconciler().reconcile(confirm_stock=True)
                self.assert_generic_preserved(before)

    def test_reinstall_after_success_is_idempotent(self):
        first = self.fixture.reconciler().reconcile()
        self.assertEqual(first['action'], 'disabled')
        calls = len(self.fixture.service_state()['calls'])
        self.fixture.reconciler().reconcile()
        state = self.fixture.service_state()
        mutations = [argv for argv in state['calls'][calls:]
                     if argv[0].endswith('systemctl') and argv[1] in ('stop', 'disable', 'start', 'enable')]
        self.assertEqual(mutations, [])
        self.assertFalse(state['units']['nginx.service']['active'])

    def test_later_administrator_reactivation_is_not_undone(self):
        self.assertEqual(self.fixture.reconciler().reconcile()['action'], 'disabled')
        self.fixture.set_unit(active=True, enabled='enabled')
        before = self.fixture.service_state()
        self.fixture.reconciler().reconcile()
        self.assert_generic_preserved(before)

    def test_partial_journal_is_preserved_for_diagnosis_without_retrying_mutations(self):
        journal = self.fixture.write('/var/lib/pxe-tools-nginx-ownership/state.json',
                                     json.dumps({'format': 1, 'phase': 'prepared'}))
        journal.parent.chmod(0o700)
        journal.chmod(0o600)
        for active in (True, False):
            with self.subTest(active=active):
                self.fixture.set_unit(active=active)
                before = self.fixture.service_state()
                result = self.fixture.reconciler().reconcile()
                self.assertEqual(result['action'], 'conflict')
                self.assert_generic_preserved(before)
                self.assertEqual(json.loads(journal.read_text())['phase'], 'prepared')

    def test_configuration_changed_during_revalidation_is_not_stopped(self):
        calls = []

        def change_config(argv):
            if argv[0].endswith('dpkg-query') and any('Conffiles' in arg for arg in argv):
                calls.append(argv)
                if len(calls) == 2:
                    self.fixture.write('/etc/nginx/sites-available/default',
                                       'server { listen 80; root /srv/new-customer; }\n')

        before = self.fixture.service_state()
        result = self.fixture.reconciler(run=FixtureRunner(self.fixture.root, on_call=change_config)).reconcile()
        self.assertEqual(result['action'], 'conflict')
        self.assertEqual(len(calls), 2, 'the stock configuration must be revalidated before mutation')
        self.assert_generic_preserved(before)

    def test_disable_failure_keeps_incomplete_recovery_receipt(self):
        runner = FixtureRunner(self.fixture.root)

        def fail_disable(argv, **kwargs):
            if argv[0].endswith('systemctl') and argv[1] == 'disable':
                return subprocess.CompletedProcess(argv, 1, '', 'fixture disable failure')
            return runner(argv, **kwargs)

        result = self.fixture.reconciler(run=fail_disable).reconcile()
        self.assertEqual(result['action'], 'conflict')
        journal = self.fixture.path('/var/lib/pxe-tools-nginx-ownership/state.json')
        self.assertEqual(json.loads(journal.read_text())['phase'], 'prepared')
        self.assertTrue(json.loads(journal.read_text()).get('compensated'))
        self.assertTrue(self.fixture.path('/etc/nginx/sites-enabled/default').is_symlink())
        self.assertTrue(self.fixture.service_state()['units']['nginx.service']['active'])
        self.assertEqual(self.fixture.service_state()['units']['nginx.service']['enabled'], 'enabled')

    def test_disable_failure_does_not_restart_over_a_new_port80_owner(self):
        runner = FixtureRunner(self.fixture.root)

        def fail_with_new_listener(argv, **kwargs):
            if argv[0].endswith('systemctl') and argv[1] == 'disable':
                with self.fixture.path('/proc/net/tcp').open('a') as output:
                    output.write('   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 99 1\n')
                return subprocess.CompletedProcess(argv, 1, '', 'fixture disable failure')
            return runner(argv, **kwargs)

        result = self.fixture.reconciler(run=fail_with_new_listener).reconcile()
        self.assertEqual(result['action'], 'conflict')
        state = self.fixture.service_state()
        self.assertFalse(state['units']['nginx.service']['active'])
        self.assertEqual([argv for argv in state['calls']
                          if argv[0].endswith('systemctl') and argv[1] in ('start', 'enable')], [])
        journal = self.fixture.path('/var/lib/pxe-tools-nginx-ownership/state.json')
        self.assertEqual(json.loads(journal.read_text())['phase'], 'prepared')
        self.assertFalse(json.loads(journal.read_text()).get('compensated', False))


class StableNginxLockFixture(unittest.TestCase):
    """Exercise only locks and paths inside a disposable fixture."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pxe-nginx-stable-lock-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'run/lock').mkdir(parents=True)
        spec = importlib.util.spec_from_file_location('nginx_stable_lock_test', ROOT / 'packaging/native/reconcile-nginx.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.lock = self.root / 'run/lock/pxe-tools-nginx-reconcile.lock'

    def test_lock_excludes_another_process_and_is_never_unlinked(self):
        program = '''import importlib.util, os, sys\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location("fixture",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\nwith m.stable_nginx_lock(Path(sys.argv[2]),owner=os.getuid()):\n    (Path(sys.argv[2]) / "var/lib/pxe-tools-nginx-ownership").mkdir(parents=True)\n'''
        command = [sys.executable, '-c', program, str(ROOT / 'packaging/native/reconcile-nginx.py'), str(self.root)]
        journal_dir = self.root / 'var/lib/pxe-tools-nginx-ownership'
        journal_dir.mkdir(parents=True)
        with self.module.stable_nginx_lock(self.root, owner=os.getuid()):
            journal_dir.rmdir()  # The uninstall removes this while holding the stable lock.
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(journal_dir.exists())
            self.assertTrue(self.lock.is_file())
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(journal_dir.is_dir())
        self.assertTrue(self.lock.is_file())
        self.assertEqual(self.lock.stat().st_mode & 0o777, 0o600)

    def test_linked_lock_and_linked_ancestor_are_refused(self):
        external = self.root / 'external'
        external.write_text('keep')
        self.lock.symlink_to(external)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        self.assertEqual(external.read_text(), 'keep')
        self.lock.unlink()
        lock_dir = self.root / 'run/lock'
        lock_dir.rmdir()
        lock_dir.symlink_to(external)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        self.assertEqual(external.read_text(), 'keep')

    def test_hardlinked_or_unsafe_lock_is_refused(self):
        self.lock.touch(mode=0o600)
        alias = self.root / 'alias'
        os.link(self.lock, alias)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        alias.unlink()
        self.lock.chmod(0o666)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        self.assertTrue(self.lock.exists())

    def test_missing_or_untrusted_lock_directory_is_refused(self):
        lock_dir = self.root / 'run/lock'
        lock_dir.rmdir()
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        lock_dir.mkdir(mode=0o777)
        lock_dir.chmod(0o777)
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            with self.module.stable_nginx_lock(self.root, owner=os.getuid()): pass
        self.assertFalse(self.lock.exists())

    def test_sticky_lock_directory_is_accepted(self):
        (self.root / 'run/lock').chmod(0o1777)
        with self.module.stable_nginx_lock(self.root, owner=os.getuid()):
            self.assertTrue(self.lock.exists())

    def test_reconcile_checks_stable_lock_before_inspecting_nginx(self):
        events = []
        from contextlib import contextmanager
        @contextmanager
        def lock(root, *, owner=0):
            events.append('lock')
            yield
            events.append('unlock')
        reconciler = self.module.Reconciler(root=self.root)
        def state():
            events.append('state')
            return {'ActiveState': 'inactive', 'UnitFileState': 'disabled'}
        with patch.object(self.module, 'stable_nginx_lock', lock), patch.object(reconciler, 'state', state):
            result = reconciler.reconcile()
        self.assertEqual(result['action'], 'preserved')
        self.assertEqual(events, ['lock', 'state', 'unlock'])

    def test_reconcile_refuses_lock_contention_before_reading_or_creating_journal(self):
        reconciler = self.module.Reconciler(root=self.root)
        stable_lock = self.module.stable_nginx_lock
        with stable_lock(self.root, owner=os.getuid()):
            with patch.object(self.module, 'stable_nginx_lock',
                              lambda root: stable_lock(root, owner=os.getuid())):
                with patch.object(reconciler, 'state') as state:
                    result = reconciler.reconcile()
        self.assertEqual(result['action'], 'conflict')
        state.assert_not_called()
        self.assertFalse(reconciler.directory.exists())


if __name__ == '__main__':
    unittest.main()
