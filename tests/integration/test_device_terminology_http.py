#!/usr/bin/env python3
"""Test the fixed inventory title and compatible links over authenticated HTTP."""
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
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def make_client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)

with tempfile.TemporaryDirectory(prefix='pxe-terms-test-') as temp:
    work=Path(temp); db=work/'test.sqlite'
    with sqlite3.connect(db) as conn:
        conn.executescript((root/'app/db/schema.sqlite.sql').read_text())
        conn.executemany('INSERT INTO settings(key,value) VALUES (?,?)', [('db_init_done','1'),('admin_created','1'),('wizard_completed','1')])
        conn.execute("INSERT INTO settings(key,value) VALUES ('ui_device_term','serveur')")
        conn.execute("INSERT INTO machines(mac,hostname,notes) VALUES ('02:00:00:00:00:01','machine-lab','machine personnalisée')")
    env=dict(os.environ,PXE_DB_DRIVER='sqlite',PXE_DB_PATH=str(db),PXE_SESSION_DIR=str(work/'sessions'))
    bootstrap="spl_autoload_register(function($c){$f="+repr(str(root/'app/src')+'/')+".str_replace('\\\\','/',substr($c,6)).'.php';if(is_file($f))require_once $f;});"
    subprocess.run(['php','-r',bootstrap+"Admin\\Models\\User::create('fixture','fixture-password');"],env=env,check=True,stdout=subprocess.DEVNULL)
    router=work/'router.php';router.write_text('<?php require '+repr(str(root/'app/public/index.php'))+';')
    with socket.socket() as sock: sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    base=f'http://127.0.0.1:{port}'
    def request(client,path,data=None):
        payload=urllib.parse.urlencode(data).encode() if data is not None else None
        try: resp=client.open(base+path,data=payload,timeout=20)
        except urllib.error.HTTPError as exc: resp=exc
        return resp.code,resp.headers,resp.read().decode('utf-8','replace')
    def token(body):
        m=re.search(r'name="csrf_token" value="([^"]+)"',body)
        if not m: raise RuntimeError('Missing CSRF token')
        return m.group(1)
    with (work/'server.log').open('w') as log:
        server=subprocess.Popen(['php','-S',f'127.0.0.1:{port}',str(router)],env=env,stdout=log,stderr=log)
        try:
            admin=make_client()
            for _ in range(100):
                try: code,_,page=request(admin,'/login');break
                except urllib.error.URLError:time.sleep(.05)
            else: raise RuntimeError('server not started')
            assert code==200
            code,_,_=request(admin,'/login',{'username':'fixture','password':'fixture-password','csrf_token':token(page),'next':'/'})
            assert code==302
            code, headers, page = request(admin, '/admin/inventaire')
            assert code == 200 and '<h1>Inventaire</h1>' in page and 'machine-lab' in page
            assert 'href="/admin/inventaire/1"' in page and 'href="/machines' not in page
            assert 'data-device-many="appareils"' in page

            for old_path in ('/machines', '/admin/devices', '/machines/1'):
                expected = '/admin/inventaire' + ('/1' if old_path.endswith('/1') else '')
                code, headers, _ = request(admin, old_path + '?q=machine%20lab')
                assert (code, headers.get('Location')) == (302, expected + '?q=machine%20lab')

            code, _, new_page = request(admin, '/admin/inventaire/new')
            assert code == 200 and 'Nouvel appareil' in new_page
            code, _, detail = request(admin, '/admin/inventaire/1')
            assert code == 200 and 'machine-lab' in detail and 'machine personnalisée' in detail
            code, _, install = request(admin, '/admin/inventaire/1/install')
            assert code == 200, (code, install[-500:])

            code, _, settings = request(admin, '/settings')
            assert code == 200 and 'ui_device_term' not in settings and 'Appellation' not in settings
            code, _, _ = request(admin, '/settings/terminology', {
                'ui_device_term': 'client', 'csrf_token': token(settings),
            })
            assert code == 404
            code, _, _ = request(admin, '/machines', {'mac': '02:00:00:00:00:02'})
            assert code == 403
            code, headers, _ = request(admin, '/machines', {
                'mac': '02:00:00:00:00:02', 'hostname': 'legacy-form', 'csrf_token': token(new_page),
            })
            assert code == 302 and headers['Location'].startswith('/admin/inventaire/')

            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT value FROM settings WHERE key='ui_device_term'").fetchone() == ('serveur',)
                assert conn.execute('SELECT hostname,notes FROM machines WHERE id=1').fetchone() == ('machine-lab','machine personnalisée')
                assert conn.execute("SELECT count(*) FROM machines WHERE hostname='legacy-form'").fetchone() == (1,)
            print('Canonical inventory, legacy links, fixed terminology, and CSRF: OK')
        finally:
            server.terminate()
            try: server.wait(timeout=3)
            except subprocess.TimeoutExpired: server.kill();server.wait()
