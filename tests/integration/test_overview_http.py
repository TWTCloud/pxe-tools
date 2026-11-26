#!/usr/bin/env python3
"""Read-only overview over a disposable SQLite database and local PHP server."""
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
if Path('/etc/pxe-tools/db.conf').exists() or Path('/etc/pxe-tools/db.conf').is_symlink():
    raise SystemExit('Run only on a host without appliance database configuration')

with tempfile.TemporaryDirectory(prefix='pxe-overview-test-') as temp:
    work = Path(temp)
    db = work / 'test.sqlite'
    with sqlite3.connect(db) as conn:
        conn.executescript((root / 'app/db/schema.sqlite.sql').read_text())
        conn.executemany('INSERT INTO settings(key,value) VALUES (?,?)', [
            ('db_init_done','1'), ('admin_created','1'), ('wizard_completed','1'),
            ('pxe_enabled','on'), ('dhcp_proxy_enabled','on'),
            ('pxe_interface','vlan10<script>'), ('pxe_ip','192.0.2.5')])
        conn.execute("INSERT INTO init_jobs(job_type,status,message) VALUES ('bootstrap:restart_dnsmasq','success','fixture')")
        conn.execute("INSERT INTO os_images(distro,version,version_full,arch,enabled,status) VALUES ('debian','trixie','13.7.0','amd64',1,'downloaded')")
    image_dir = work / 'http/netboot/debian/13.7.0/amd64'
    image_dir.mkdir(parents=True)
    (image_dir / 'linux').write_bytes(b'kernel')
    (image_dir / 'initrd.gz').write_bytes(b'initrd')
    env = dict(os.environ, PXE_DB_DRIVER='sqlite', PXE_DB_PATH=str(db),
               PXE_SESSION_DIR=str(work/'sessions'), PXE_HTTP_ROOT=str(work/'http'), PXE_SERVICE_MANAGER='systemd')
    bootstrap = "spl_autoload_register(function($c){$f=" + repr(str(root/'app/src')+'/') + ".str_replace('\\\\','/',substr($c,6)).'.php';if(is_file($f))require_once $f;});"
    subprocess.run(['php','-r',bootstrap+"Admin\\Models\\User::create('fixture','fixture-password');"], env=env, check=True, stdout=subprocess.DEVNULL)
    router = work / 'router.php'
    router.write_text('<?php require ' + repr(str(root/'app/public/index.php')) + ';')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl): return None
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)
    base = f'http://127.0.0.1:{port}'
    def request(path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        try: response = client.open(base+path, data=body, timeout=15)
        except urllib.error.HTTPError as exc: response = exc
        return response.code, response.headers, response.read().decode('utf-8','replace')
    with (work/'server.log').open('w') as log:
        server = subprocess.Popen(['php','-S',f'127.0.0.1:{port}',str(router)], env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                try: code, _, page = request('/login'); break
                except urllib.error.URLError: time.sleep(.05)
            else: raise RuntimeError('server did not start')
            assert code == 200
            code, headers, _ = request('/')
            assert code == 302 and headers['Location'].startswith('/login?next=')
            csrf = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            code, headers, _ = request('/login', {'username':'fixture','password':'fixture-password','csrf_token':csrf,'next':'/'})
            assert code == 302 and headers['Location'] == '/', (code, headers)
            code, _, body = request('/')
            assert code == 200, (code, body, (work/'server.log').read_text())
            assert 'Vue d’ensemble' in body and 'Proxy DHCP' in body and '192.0.2.5' in body
            assert 'vlan10&lt;script&gt;' in body and 'vlan10<script>' not in body
            assert 'Debian 13.7.0' in body and '1 disponible' in body
            assert 'Non confirmé' in body and 'Demandé' in body
            assert 'Services actifs' not in body
            (image_dir / 'initrd.gz').unlink()
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE settings SET value='off' WHERE key='pxe_enabled'")
            code, _, body = request('/')
            assert code == 200 and '0 disponible' in body and 'Fichiers absents ou illisibles' in body
            assert 'Console uniquement' in body and 'Non demandé' in body
            code, _, body = request('/admin/inventaire')
            assert code == 200 and '<h1>Inventaire</h1>' in body
            print('Overview HTTP authentication, real data, escaped values and canonical inventory route: OK')
        finally:
            server.terminate()
            try: server.wait(timeout=3)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
