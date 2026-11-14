#!/usr/bin/env python3
"""Exercise network onboarding, console-only completion and unprivileged port diagnosis over HTTP.

Run inside a disposable test container with no appliance configuration mounted.
"""
from pathlib import Path
import http.cookiejar
import os
import re
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parents[2]
if os.environ.get('PXE_NETWORK_ONBOARDING_TEST') != '1' or Path('/etc/pxe-tools/db.conf').exists():
    raise SystemExit('Run only in an isolated fixture without appliance data')

with tempfile.TemporaryDirectory(prefix='pxe-image-race-http-') as temporary:
    work = Path(temporary)
    db = work / 'test.sqlite'
    with sqlite3.connect(db) as connection:
        connection.executescript((root / 'app/db/schema.sqlite.sql').read_text())
        connection.executemany('INSERT INTO settings(key,value) VALUES (?,?)', [
            ('db_init_done', '1'), ('admin_created', '1'), ('wizard_completed', '0')])
    env = dict(os.environ, PXE_DB_DRIVER='sqlite', PXE_DB_PATH=str(db), PXE_SESSION_DIR=str(work / 'sessions'), PXE_SERVICE_MANAGER='systemd', PXE_INTERFACE='legacy0', PXE_IP='192.0.2.77', DHCP_MODE='proxy', DHCP_PROXY_NETWORK='192.0.2.0', DHCP_PROXY_NETMASK='255.255.255.0')
    bootstrap = "spl_autoload_register(function($c){$f=" + repr(str(root / 'app/src') + '/') + ".str_replace('\\\\','/',substr($c,6)).'.php';if(is_file($f))require_once $f;});"
    subprocess.run(['php', '-r', bootstrap + "Admin\\Models\\User::create('fixture','fixture-password');"],
                   env=env, check=True, stdout=subprocess.DEVNULL)
    # Prevent DNS/network calls in Debian discovery while keeping the real
    # catalogue's offline fallback and actual HTTP route execution.
    prepend = work / 'offline.php'
    prepend.write_text('''<?php
class OfflineHttpsFixture {
    public $context;
    public function stream_open($path,$mode,$options,&$openedPath) { return false; }
}
stream_wrapper_unregister('https');
stream_wrapper_register('https', OfflineHttpsFixture::class);
''')
    router = work / 'router.php'
    router.write_text('<?php require ' + repr(str(root / 'app/public/index.php')) + ';')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    log = work / 'server.log'
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)
    base = f'http://127.0.0.1:{port}'
    def request(path, values=None):
        data = urllib.parse.urlencode(values).encode() if values is not None else None
        try: response = client.open(base + path, data=data, timeout=25)
        except urllib.error.HTTPError as error: response = error
        return response.code, response.headers, response.read().decode('utf-8', 'replace')
    def token(body):
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if not match: raise RuntimeError('Missing CSRF token')
        return match.group(1)

    with log.open('w') as output:
        server = subprocess.Popen(['php', '-d', 'auto_prepend_file=' + str(prepend), '-S',
                                   f'127.0.0.1:{port}', str(router)], env=env, stdout=output, stderr=output)
        try:
            for _ in range(100):
                try: code, _, body = request('/login'); break
                except urllib.error.URLError: time.sleep(.05)
            else: raise RuntimeError('Fixture HTTP server did not start')
            assert code == 200
            code, headers, _ = request('/login', {'username':'fixture', 'password':'fixture-password', 'csrf_token':token(body)})
            assert code == 302 and headers['Location'] == '/init/network'
            code, _, body = request('/init/network'); assert code == 200
            assert 'value="legacy0"' in body and 'value="192.0.2.77"' in body
            assert 'name="pxe_role" value="proxy" checked' in body and 'value="192.0.2.0/24"' in body
            csrf = token(body)
            code, _, invalid = request('/init/network', {'csrf_token':csrf, 'network_mode':'detected',
                'network_address':'missing|192.0.2.17/24', 'pxe_role':'proxy', 'pxe_ip':'192.0.2.17'})
            assert code == 422 and 'Choisissez une adresse détectée' in invalid
            with sqlite3.connect(db) as connection:
                assert connection.execute("SELECT count(*) FROM settings WHERE key='pxe_enabled'").fetchone()[0] == 0
            code, _, invalid = request('/init/network', {'csrf_token':csrf, 'network_mode':'manual',
                'pxe_interface':'saved-interface', 'pxe_ip':'invalid-address', 'pxe_subnet':'198.51.100.0/24',
                'dhcp_proxy_cidr':'192.0.2.0/23', 'pxe_role':'proxy', 'network_override':'1'})
            assert code == 422 and 'saved-interface' in invalid and 'invalid-address' in invalid
            assert '198.51.100.0/24' in invalid and '192.0.2.0/23' in invalid and 'name="network_mode" value="manual" checked' in invalid
            code, headers, _ = request('/init/network', {'csrf_token':csrf, 'network_mode':'detected',
                'network_address':'', 'pxe_role':'console'})
            assert code == 302 and headers['Location'] == '/init/images'
            code, _, body = request('/init/images'); assert code == 200
            code, headers, _ = request('/init/images', {'csrf_token':token(body)})
            assert code == 302 and headers['Location'] == '/init/done'
            code, _, body = request('/init/done')
            assert code == 200 and 'console uniquement' in body and 'Tout est prêt' not in body
            code, headers, _ = request('/init/complete', {'csrf_token':token(body)})
            assert code == 302 and headers['Location'] == '/init'
            with sqlite3.connect(db) as connection:
                settings = dict(connection.execute('SELECT key,value FROM settings'))
                assert settings['pxe_enabled'] == 'off' and settings['dhcp_proxy_enabled'] == 'off'
                assert settings['wizard_completed'] == '1' and settings['pxe_ip'] == ''
                jobs = connection.execute('SELECT job_type FROM init_jobs').fetchall()
                assert ('bootstrap:restart_dnsmasq',) in jobs
                assert ('bootstrap:build_grub',) not in jobs and ('bootstrap:render_templates',) not in jobs
            code, _, body = request('/init/network?from=settings'); assert code == 200
            code, headers, _ = request('/init/network?from=settings', {'csrf_token':token(body), 'network_mode':'manual',
                'pxe_interface':'not-present', 'pxe_ip':'192.0.2.17', 'pxe_subnet':'198.51.100.0/24',
                'dhcp_proxy_cidr':'192.0.2.0/23', 'pxe_role':'proxy', 'network_override':'1'})
            assert code == 302 and headers['Location'] == '/settings'
            with sqlite3.connect(db) as connection:
                settings = dict(connection.execute('SELECT key,value FROM settings'))
                assert settings['pxe_enabled'] == 'on' and settings['dhcp_proxy_enabled'] == 'on'
                assert settings['pxe_subnet'] == '198.51.100.0/24' and settings['dhcp_proxy_network'] == '192.0.2.0'
                assert jobs == connection.execute('SELECT job_type FROM init_jobs').fetchall(), 'Saving must not apply services'
            code, _, body = request('/init/port-80'); assert code == 200
            assert 'désactivera' not in body and 'Examiner le conflit avec nginx' not in body
            csrf = token(body) if 'name="csrf_token"' in body else csrf
            code, headers, _ = request('/init/port-80', {'csrf_token':csrf})
            assert code == 302 and headers['Location'].endswith('consent=missing')
            code, headers, _ = request('/init/port-80', {'csrf_token':csrf, 'confirm_stop_nginx':'1', 'preview':'unbound'})
            assert code == 302 and headers['Location'].endswith('identity=changed')
            with sqlite3.connect(db) as connection:
                assert connection.execute("SELECT count(*) FROM init_jobs WHERE job_type='system:release_nginx_port'").fetchone()[0] == 0
            print('OK real HTTP: derived rejection, preserved 422 values, console-only completion, explicit activation, no apply on save and refused unbound stop')
        except BaseException:
            output.flush()
            print('Fixture PHP log:', log.read_text()[-4000:])
            raise
        finally:
            server.terminate()
            try: server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill(); server.wait()
