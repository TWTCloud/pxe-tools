#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Native maintainer-script regression; all files/services are disposable fixtures.

The test executes the real package POSTINST. Only external service/package
commands and unrelated setup helpers are doubled. Never execute this module's
package-building entry point or call a real service manager.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class FixtureRunner:
    """A deterministic systemd/dpkg boundary shared by the subprocess fixture."""

    def __init__(self, root):
        self.root = Path(root)

    def __call__(self, argv, **kwargs):
        argv = [str(value) for value in argv]
        command, args = Path(argv[0]).name, argv[1:]
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
            elif action != 'daemon-reload':
                raise AssertionError('Unexpected service mutation: ' + repr(argv))
        elif command == 'dpkg-query':
            if any('Conffiles' in arg for arg in args):
                output = '\n'.join(' ' + path + ' ' + digest
                                   for path, digest in state['conffiles'].items())
            elif '-S' in args or '--search' in args:
                output = 'nginx-common: ' + args[-1]
            elif any('Version' in arg for arg in args):
                output = '1.24.0-2ubuntu7.19'
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
        self.write('/proc/123/stat', '123 (nginx) ' + ' '.join(['0'] * 19 + ['100']) + '\n')
        self.path('/proc/123/exe').symlink_to(self.path('/usr/sbin/nginx'))
        self.write('/proc/sys/kernel/random/boot_id', '12345678-1234-1234-1234-123456789abc\n')
        self.path('/run/systemd/system').mkdir(parents=True)
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

    def path(self, name):
        return self.root / name.lstrip('/')

    def write(self, name, data):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

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
            ' print(json.dumps(result))\n')
        python.chmod(0o755)
        env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get('PATH', ''),
                   NGINX_FIXTURE_ROOT=str(self.root), PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run(['/bin/sh', '-s', 'configure', old_version], input=script,
                              env=env, text=True, capture_output=True, check=True)


class MaintainerRegression(unittest.TestCase):
    def test_fresh_dependency_does_not_leave_generic_nginx_owning_boot_port(self):
        with tempfile.TemporaryDirectory(prefix='pxe-nginx-ownership-') as directory:
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


if __name__ == '__main__':
    unittest.main()
