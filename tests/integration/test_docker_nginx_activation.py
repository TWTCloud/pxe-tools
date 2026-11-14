#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Render real Docker nginx templates across boot-network switches, without daemons.

The real PHP database reader and Python activation module use disposable SQLite
files. A bounded envsubst fixture replaces only the two administrator ports,
keeping this test runnable in the application CI image without gettext.
"""
from contextlib import closing
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / 'docker/pxe-tools/nginx'
RENDERER = ROOT / 'docker/pxe-tools/init/render-nginx-conf.sh'


class DockerNginxActivation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configuration = Path('/etc/pxe-tools/db.conf')
        if configuration.exists() or configuration.is_symlink():
            raise RuntimeError('Run without an appliance db.conf; no instance configuration may be read.')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pxe-docker-nginx-')
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.output, self.templates, binary = (self.work / name for name in ('rendered', 'templates', 'bin'))
        for folder in (self.output, self.templates, binary):
            folder.mkdir()
        self.db = self.work / 'instance.sqlite'
        self.http = self.output / 'admin-http.conf'
        self.https = self.output / 'admin-https.conf'
        self.boot = self.output / 'pxe.conf'
        for name in ('admin-http-serve.conf.tmpl', 'admin-http-redirect.conf.tmpl', 'admin-https.conf.tmpl'):
            shutil.copyfile(TEMPLATES / name, self.templates / name)
        # Match the production Dockerfile's COPY destination exactly.
        shutil.copyfile(TEMPLATES / 'pxe.conf', self.templates / 'pxe.conf.tmpl')
        self.unrelated = self.output / 'unrelated.conf'
        self.unrelated.write_text('# Another nginx configuration must remain intact.\n')
        self.env = dict(os.environ, PXE_APP_DIR=str(ROOT / 'app'), PXE_DB_PATH=str(self.db),
                        PXE_DB_DRIVER='sqlite', PXE_NGINX_CONF_DIR=str(self.output),
                        PXE_NGINX_TEMPLATE_DIR=str(self.templates), ADMIN_PORT='18443', ADMIN_HTTP_PORT='18080',
                        PATH=str(binary) + os.pathsep + os.environ['PATH'])
        substitute = binary / 'envsubst'
        substitute.write_text('#!' + sys.executable + '''
import os
import sys
if sys.argv[1:] != ['${ADMIN_PORT} ${ADMIN_HTTP_PORT}']:
    raise SystemExit('Unexpected envsubst scope')
text = sys.stdin.read()
for name in ('ADMIN_PORT', 'ADMIN_HTTP_PORT'):
    text = text.replace('${' + name + '}', os.environ[name])
sys.stdout.write(text)
''')
        substitute.chmod(0o755)

    def configure(self, enabled, https='off'):
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
            db.executemany('INSERT OR REPLACE INTO settings VALUES (?, ?)',
                           [('pxe_enabled', enabled), ('https_enabled', https)])

    def render(self):
        return subprocess.run(['/bin/sh', str(RENDERER)], env=self.env, text=True,
                              capture_output=True, timeout=20)

    def rendered_template(self, name):
        text = (TEMPLATES / name).read_text()
        return text.replace('${ADMIN_PORT}', '18443').replace('${ADMIN_HTTP_PORT}', '18080')

    def assert_console(self, https):
        expected = 'admin-http-redirect.conf.tmpl' if https == 'on' else 'admin-http-serve.conf.tmpl'
        self.assertEqual(self.http.read_text(), self.rendered_template(expected))
        self.assertIn('listen 18080 default_server;', self.http.read_text())
        self.assertEqual(self.https.exists(), https == 'on')
        if https == 'on':
            self.assertEqual(self.https.read_text(), self.rendered_template('admin-https.conf.tmpl'))
            self.assertIn('$document_root$fastcgi_script_name', self.https.read_text())
        else:
            self.assertIn('$document_root$fastcgi_script_name', self.http.read_text())
        self.assertEqual(self.unrelated.read_text(), '# Another nginx configuration must remain intact.\n')

    def test_off_on_off_keeps_http_and_https_console_and_toggles_only_boot(self):
        for https in ('off', 'on'):
            with self.subTest(console_https=https):
                self.boot.write_text('# Previous boot listener\n')
                for enabled in ('off', 'on', 'off'):
                    self.configure(enabled, https)
                    result = self.render()
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assert_console(https)
                    self.assertEqual(self.boot.exists(), enabled == 'on')
                    if enabled == 'on':
                        self.assertEqual(self.boot.read_bytes(), (TEMPLATES / 'pxe.conf').read_bytes())
                        self.assertEqual(self.boot.stat().st_mode & 0o777, 0o644)

    def test_invalid_activation_fails_and_removes_boot_without_removing_console(self):
        self.configure('on')
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.boot.is_file())
        self.configure('invalid')
        before = self.db.read_bytes()
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Réseau PXE illisible', result.stderr)
        self.assertFalse(self.boot.exists())
        self.assert_console('off')
        self.assertEqual(self.db.read_bytes(), before)

    def test_fresh_instance_keeps_console_and_does_not_create_database_despite_legacy_env(self):
        self.env.pop('PXE_DB_DRIVER')
        self.env.update(PXE_INTERFACE='eth1', PXE_IP='192.0.2.17', DHCP_MODE='proxy')
        self.boot.write_text('# Previous boot listener\n')
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_console('off')
        self.assertFalse(self.boot.exists())
        for suffix in ('', '-wal', '-shm', '-journal'):
            self.assertFalse(Path(str(self.db) + suffix).exists())

    def test_configured_missing_database_is_rejected_without_creating_it(self):
        self.http.write_text('# Existing console configuration\n')
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('impossible de lire le réglage HTTPS', result.stderr)
        self.assertEqual(self.http.read_text(), '# Existing console configuration\n')
        self.assertFalse(self.boot.exists())
        self.assertFalse(self.db.exists())


if __name__ == '__main__':
    unittest.main()
