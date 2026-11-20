#!/usr/bin/env python3
"""Test the shared wording preference through real authenticated HTTP routes."""
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
        conn.execute("INSERT INTO machines(mac,hostname,notes) VALUES ('02:00:00:00:00:01','machine-lab','machine personnalisée')")
    env=dict(os.environ,PXE_DB_DRIVER='sqlite',PXE_DB_PATH=str(db),PXE_SESSION_DIR=str(work/'sessions'))
    bootstrap="spl_autoload_register(function($c){$f="+repr(str(root/'app/src')+'/')+".str_replace('\\\\','/',substr($c,6)).'.php';if(is_file($f))require_once $f;});"
    subprocess.run(['php','-r',bootstrap+"Admin\\Models\\User::create('fixture','fixture-password'); Admin\\Models\\User::create('other','other-password');"],env=env,check=True,stdout=subprocess.DEVNULL)
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
            admin=make_client(); other=make_client()
            for _ in range(100):
                try: code,_,page=request(admin,'/login');break
                except urllib.error.URLError:time.sleep(.05)
            else: raise RuntimeError('server not started')
            assert code==200
            code,_,_=request(admin,'/login',{'username':'fixture','password':'fixture-password','csrf_token':token(page),'next':'/'})
            assert code==302
            code,_,page=request(admin,'/machines')
            assert code==200 and '<h1>Machines</h1>' in page and 'machine-lab' in page
            code,_,settings=request(admin,'/settings');assert code==200
            signatures=set()
            for value,label,new_label in [('client','Clients PXE','Nouveau client PXE'),('ordinateur','Ordinateurs','Nouvel ordinateur'),('serveur','Serveurs','Nouveau serveur'),('machine','Machines','Nouvelle machine')]:
                code,_,_=request(admin,'/settings/terminology',{'ui_device_term':value,'csrf_token':token(settings)})
                assert code==302,(code,value)
                code,_,page=request(admin,'/machines');assert code==200,(code,page)
                assert '<h1>'+label+'</h1>' in page,(value,label)
                assert 'machine-lab' in page and 'href="/machines' in page
                assert 'data-device-many=' in page
                code,_,new_page=request(admin,'/machines/new'); assert code==200 and new_label in new_page
                code,_,detail=request(admin,'/machines/1'); assert code==200, (code,detail[-500:])
                assert 'machine-lab' in detail and 'machine personnalisée' in detail
                match=re.search(r'id="machine-operation-header" data-poll-scope data-sig="([^"]+)"',detail)
                assert match, 'Missing operation signature'
                signatures.add(match.group(1))
                if value=='client': assert 'Aucun rôle Ansible configuré pour ce client PXE.' in detail
                code,_,install=request(admin,'/machines/1/install'); assert code==200, (code,install[-500:])
                code,_,network=request(admin,'/init/network?from=settings'); assert code==200, (code,network[-500:])
                assert 'Connexion vers les ' in network
                code,_,settings=request(admin,'/settings');assert code==200
            assert len(signatures)==1, 'Terminology must not change operation concurrency signatures'
            code,_,_=request(admin,'/settings/terminology',{'ui_device_term':'client','csrf_token':token(settings)})
            assert code==302
            code,_,page=request(other,'/login');assert code==200
            code,_,_=request(other,'/login',{'username':'other','password':'other-password','csrf_token':token(page),'next':'/'})
            assert code==302
            code,_,page=request(other,'/machines');assert code==200 and '<h1>Clients PXE</h1>' in page
            code,_,settings=request(admin,'/settings');csrf=token(settings)
            code,_,_=request(admin,'/settings/terminology',{'ui_device_term':'<script>','csrf_token':csrf});assert code==302
            code,_,page=request(other,'/machines');assert '<h1>Clients PXE</h1>' in page
            code,_,_=request(admin,'/settings/terminology',{'ui_device_term':'serveur'});assert code==403
            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT value FROM settings WHERE key='ui_device_term'").fetchone()[0]=='client'
                assert conn.execute('SELECT hostname,notes FROM machines').fetchone()==('machine-lab','machine personnalisée')
                assert conn.execute('SELECT count(*) FROM init_jobs').fetchone()[0]==0
                conn.execute("UPDATE settings SET value='invalid' WHERE key='ui_device_term'")
            code,_,page=request(admin,'/machines'); assert code==200 and '<h1>Machines</h1>' in page
            with sqlite3.connect(db) as conn:
                assert conn.execute("SELECT value FROM settings WHERE key='ui_device_term'").fetchone()[0]=='invalid'
            print('Shared terminology, auth, CSRF, validation and data preservation: OK')
        finally:
            server.terminate()
            try: server.wait(timeout=3)
            except subprocess.TimeoutExpired: server.kill();server.wait()
