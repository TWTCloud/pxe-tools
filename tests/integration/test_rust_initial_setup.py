#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise Rust setup over TLS on a temporary SQLite instance or a disposable appliance."""
import argparse
import base64
from hashlib import sha256
import hmac
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from http.client import HTTPConnection, HTTPSConnection
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlencode


class Client:
    def __init__(self, credentials, http_port, https_port):
        self.context = ssl.create_default_context(cafile=str(credentials/'cert.pem'))
        self.http_port = http_port
        self.https_port = https_port
        self.origin = 'https://127.0.0.1' + (f':{https_port}' if https_port != 443 else '')

    def request(self, path, *, form=None, raw_body=None, authorization=None, secure=True, origin=None,
                extra_headers=None, response_headers=None):
        if secure:
            conn = HTTPSConnection('127.0.0.1', self.https_port, timeout=5, context=self.context)
        else:
            conn = HTTPConnection('127.0.0.1', self.http_port, timeout=5)
        try:
            headers = dict(extra_headers or {})
            if authorization:
                headers['Authorization'] = 'Basic ' + base64.b64encode(authorization.encode()).decode()
            if form is not None:
                headers['Origin'] = origin or self.origin
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            body = raw_body if form is None else urlencode(form)
            conn.request('GET' if body is None else 'POST', path, body=body, headers=headers)
            response = conn.getresponse()
            if response_headers is not None:
                response_headers.update((key.lower(), value) for key, value in response.getheaders())
            return response.status, response.getheader('Location'), response.read()
        finally:
            conn.close()

    def ready(self, process=None):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise RuntimeError('Rust exited while waiting for HTTPS')
            try:
                if self.request('/healthz')[0] == 200:
                    return
            except (OSError, TimeoutError):
                pass
            time.sleep(.2)
        raise RuntimeError('The isolated Rust instance did not become ready')


def setup(client, credentials, config, database):
    code = (credentials/'setup-code').read_text().strip()
    master_key = config.with_name('master.key')
    original = master_key.read_bytes()
    assert not config.exists() and not database.exists()

    assert client.request('/', secure=False)[:2] == (302, client.origin+'/admin/')
    assert client.request('/admin/')[:2] == (302, '/init/welcome')
    assert client.request('/init/db', secure=False)[0] == 404
    assert client.request('/preseed.php', secure=False)[0] == 404
    assert client.request('/init/db', form={'code': code}, origin='https://outside.example')[0] == 403
    assert client.request('/init/db', form={'code': '0'*48})[0] == 403
    assert not config.exists() and not database.exists()

    for _ in range(2):
        result = client.request('/init/db', form={'code': code})
        assert result[:2] == (303, '/init/admin'), result
    assert json.loads(config.read_text()) == {'driver': 'sqlite', 'path': str(database)}
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('PRAGMA journal_mode').fetchone() == ('wal',)
        assert dict(db.execute('SELECT key,value FROM settings'))['pxe_enabled'] == 'off'
        assert db.execute('SELECT COUNT(*) FROM users').fetchone() == (0,)

    def create(username):
        return client.request('/init/admin', form={
            'code': code, 'username': username,
            'password': 'fixture-password', 'password_confirm': 'fixture-password',
        })

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = dict(zip(('operator','other'), pool.map(create, ('operator','other')), strict=True))
    assert sorted(result[0] for result in results.values()) == [303, 409]
    winner = next(name for name, result in results.items() if result[0] == 303)
    assert results[winner][1] == '/admin/devices'
    assert create('replacement')[0] == 409
    assert client.request('/init/admin')[:2] == (302, '/admin/devices')
    assert client.request('/admin/devices')[0] == 401
    assert client.request('/admin/devices', authorization=winner+':fixture-password')[0] == 200
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT username FROM users').fetchall() == [(winner,)]
        assert db.execute("SELECT value FROM settings WHERE key='wizard_completed'").fetchone() == ('0',)
    assert master_key.read_bytes() == original
    print('Rust first-run SQLite, single admin, HTTPS access, and inactive PXE verified', flush=True)
    return winner+':fixture-password'


def verify_browser_login(client, database, authorization, *, first_run=False):
    browser = {'Accept': 'text/html'}
    result = client.request('/admin/devices?page=2', extra_headers=browser)
    assert result[:2] == (302, '/login?next=%2Fadmin%2Fdevices%3Fpage%3D2'), result
    form = client.request(result[1], extra_headers=browser)
    assert form[0] == 200 and b'name="password"' in form[2]
    assert client.request('/login', secure=False)[0] == 404
    assert client.request('/logout')[0] == 405

    username, password = authorization.split(':', 1)
    credentials = {'username': username, 'password': password, 'next': '/admin/devices?page=2'}
    assert client.request('/login', form=credentials, origin='https://other.example')[0] == 403
    assert client.request('/login', form={**credentials, 'password': 'wrong'})[0] == 401
    assert client.request('/login', form={**credentials, 'username':'not-a-pxe-account'})[0] == 401

    def sign_in(form, expected, current=None):
        headers = {}
        result = client.request('/login', form=form, extra_headers=current, response_headers=headers)
        assert result[:2] == (303, expected), result
        cookie = headers['set-cookie']
        assert all(attribute in cookie for attribute in ('; Path=/', '; Secure', '; HttpOnly',
                                                         '; SameSite=Strict', '; Max-Age=28800'))
        assert cookie.startswith('__Host-pxe-session=')
        return {**browser, 'Cookie': cookie.partition(';')[0]}

    target = '/init/network' if first_run else credentials['next']
    active = sign_in(credentials, target)
    with closing(sqlite3.connect(database)) as db:
        last_login, = db.execute('SELECT unixepoch(last_login_at) FROM users WHERE username=?', [username]).fetchone()
        assert abs(time.time()-last_login) < 10
    assert client.request(target, extra_headers=active)[0] == 200
    target = '/init/network' if first_run else '/admin/'
    previous = active
    active = sign_in({**credentials, 'next': '/%2fevil.example'}, target, current=previous)
    assert active['Cookie'] != previous['Cookie']
    assert client.request('/admin/devices', extra_headers=previous)[0] == 302

    assert client.request('/logout', form={}, extra_headers=active, origin='https://other.example')[0] == 403
    assert client.request('/admin/devices', extra_headers=active)[0] == 200
    headers = {}
    assert client.request('/logout', form={}, extra_headers=active, response_headers=headers)[:2] == (303, '/login')
    assert 'Max-Age=0' in headers['set-cookie']
    assert client.request('/admin/devices', extra_headers=active)[0] == 302
    print('Rust browser login, secure session, origin checks, token rotation and logout verified', flush=True)


class ConfirmationInputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.values = {}
        self.feed(html.decode())

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        if tag=='input' and values.get('type')=='hidden':
            self.values[values['name']] = values['value']


def verify_configuration(client, database, authorization, packaged, boot_fixture=None):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    assert client.request('/init/network')[0] == 401
    assert client.request('/init/network', secure=False)[0] == 404
    assert request('/init/network')[0] == 200
    assert request('/init/done')[:2] == (302, '/init/network')

    if packaged:
        subprocess.run(['ip','link','add','br-setup-test','type','bridge'], check=True)
        subprocess.run(['ip','addr','add','192.0.2.9/24','dev','br-setup-test'], check=True)
        subprocess.run(['ip','link','set','br-setup-test','up'], check=True)
        plan = {'role':'proxy','pxe_interface':'br-setup-test','pxe_ip':'192.0.2.9','pxe_subnet':'192.0.2.0/24'}
        assert request('/init/network', form={**plan,'pxe_ip':'192.0.2.8'})[0] == 422
        assert request('/init/network', form=plan, origin='https://other.example')[0] == 403
        assert request('/init/network', form=plan)[:2] == (303, '/init/images')
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("""INSERT INTO catalog_entries(id,distro,version_full,codename,major,arch,extract_method)
                          VALUES(9001,'debian','13.0','trixie',13,'amd64','direct')""")
        assert b'13.0' in request('/init/images')[2]
        assert request('/init/images', form={'image':'9002'})[0] == 422
        for _ in range(2):
            assert request('/init/images', form={'image':'9001'})[:2] == (303, '/init/done')
        with closing(sqlite3.connect(database)) as db:
            values = dict(db.execute('SELECT key,value FROM settings'))
            assert db.execute("SELECT COUNT(*) FROM os_images WHERE version_full='13.0'").fetchone() == (1,)
            assert values['pxe_enabled'] == 'off'
        result = request('/init/complete', form={'confirmation':'yes',
                         'plan':values['rust_wizard_network'], 'image':values['rust_wizard_image']})
        assert result[0] == 422 and 'téléchargement' in result[2].decode(), result
        print('Rust wizard validated the interface, queued Debian once, and kept PXE inactive during download', flush=True)
        if boot_fixture:
            verify_activation(client, database, request, plan, *boot_fixture)
            return

    assert request('/init/network', form={'role':'console'})[:2] == (303, '/init/done')
    fields = ConfirmationInputs(request('/init/done')[2]).values
    assert request('/init/complete', form={**fields, 'plan':'old', 'confirmation':'yes'})[0] == 422
    assert request('/init/complete', form={**fields, 'confirmation':'yes'})[:2] == (303, '/admin/devices')
    assert request('/init/complete', form={**fields, 'confirmation':'yes'})[0] == 409
    with closing(sqlite3.connect(database)) as db:
        values = dict(db.execute('SELECT key,value FROM settings'))
        assert values['wizard_completed']=='1' and values['pxe_enabled']=='off'
        assert 'rust_wizard_network' not in values
    print('Rust wizard finalized the console-only setup and refused a replay', flush=True)


def verify_activation(client, database, request, plan, http_root, tftp_root, input_dir, dnsmasq_config):
    version = http_root/'netboot/debian/13.0/amd64'
    version.mkdir(parents=True)
    for name in ('linux', 'initrd.gz', 'firmware.cpio.gz'):
        shutil.copyfile(input_dir/name, version/name)
    alias = http_root/'netboot/trixie/amd64'
    alias.parent.mkdir()
    alias.symlink_to('../debian/13.0/amd64')
    # The parent lab has authenticated these Debian netboot bytes. This
    # fixture begins with the post-download state for the chosen image.
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE os_images SET status='downloaded' WHERE version_full='13.0' AND enabled=1")
    page = request('/init/done')
    assert page[0] == 200
    fields = ConfirmationInputs(page[2]).values
    assert fields.get('image') and fields.get('plan'), page[2]
    assert request('/init/complete', form={**fields,'image':'0','confirmation':'yes'})[0] == 422
    result = request('/init/complete', form={**fields,'confirmation':'yes'})
    assert result[:2] == (303, '/admin/devices'), result

    deadline = time.monotonic() + 85
    jobs = {}
    while time.monotonic() < deadline:
        with closing(sqlite3.connect(database)) as db:
            jobs = dict(db.execute("""SELECT job_type,status FROM init_jobs
                                      WHERE job_type IN ('bootstrap:build_grub','bootstrap:render_templates',
                                                         'bootstrap:restart_dnsmasq') ORDER BY id"""))
        if len(jobs)==3 and all(status=='success' for status in jobs.values()):
            break
        if 'failed' in jobs.values():
            raise RuntimeError(f'The wizard activation job failed: {jobs}')
        time.sleep(.25)
    else:
        raise RuntimeError(f'The wizard activation did not finish: {jobs}')
    client.ready()
    with closing(sqlite3.connect(database)) as db:
        values = dict(db.execute('SELECT key,value FROM settings'))
    assert values['pxe_enabled']=='on' and values['wizard_completed']=='1'
    assert values['dhcp_proxy_enabled']=='on' and values['dhcp_proxy_network']=='192.0.2.0'
    assert all(values[key]==plan[key] for key in ('pxe_interface','pxe_ip','pxe_subnet'))
    config = dnsmasq_config.read_text().splitlines()
    assert f"interface={plan['pxe_interface']}" in config
    assert 'dhcp-range=192.0.2.0,proxy,255.255.255.0' in config
    for asset in ('lpxelinux.0','grubnetx64.efi','grubx64.efi','pxelinux.cfg/default'):
        assert (tftp_root/asset).stat().st_size > 0, asset
    assert request('/init/network')[0] == 404
    conn = HTTPConnection(plan['pxe_ip'], 80, timeout=5)
    try:
        conn.request('GET','/netboot/trixie/amd64/linux')
        answer = conn.getresponse()
        assert answer.status == 200, answer.status
        assert sha256(answer.read()).digest() == sha256((input_dir/'linux').read_bytes()).digest()
    finally:
        conn.close()
    print('Rust wizard activated the proxy, published BIOS and signed UEFI loaders and served authenticated Debian', flush=True)


def verify_worker_image_delete(database, http_root):
    image = {'id': 1, 'distro': 'debian', 'version': 'fixture', 'version_full': '13.0-fixture', 'arch': 'amd64'}
    material = http_root/'netboot'/image['distro']/image['version_full']/image['arch']
    material.mkdir(parents=True, exist_ok=True)
    files = ('linux', 'initrd.gz', 'firmware.cpio.gz')
    for asset in (*files, 'unrelated'):
        (material/asset).write_bytes(b'Disposable fixture')
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("""INSERT INTO os_images(id,distro,version,version_full,arch,enabled,status)
                       VALUES(:id,:distro,:version,:version_full,:arch,0,'downloaded')""", image)
        job = db.execute("INSERT INTO init_jobs(job_type,status,log) VALUES('image:delete:1','pending',?)",
                         (json.dumps(image),)).lastrowid
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        with closing(sqlite3.connect(database)) as db:
            status, message = db.execute('SELECT status,message FROM init_jobs WHERE id=?', (job,)).fetchone()
            exists = db.execute('SELECT EXISTS(SELECT 1 FROM os_images WHERE id=1)').fetchone()[0]
        if status == 'failed':
            raise RuntimeError(f'The packaged image deletion job failed: {message}')
        if status == 'success':
            assert not exists
            assert sorted(path.name for path in material.iterdir()) == ['unrelated']
            print('Packaged worker committed the Rust image reservation and preserved the unrelated file', flush=True)
            return
        time.sleep(.3)
    raise RuntimeError('The packaged worker did not finish the image deletion job')


def generate_tls_pair(directory, common_name):
    subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '1',
                    '-subj', f'/CN={common_name}', '-addext', 'subjectAltName=IP:127.0.0.1',
                    '-keyout', str(directory/'key.pem'), '-out', str(directory/'cert.pem')],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify_tls_import(client, original, imported, persistent, authorization):
    generate_tls_pair(imported, 'fixture-import')
    endpoint = '/admin/certificates'
    valid = {'certificate': (imported/'cert.pem').read_text(),
             'private_key': (imported/'key.pem').read_text()}
    invalid = {**valid, 'private_key': (original/'key.pem').read_text()}
    assert client.request(endpoint)[0] == 401
    assert client.request(endpoint, form=valid, authorization=authorization,
                          origin='https://other.example')[0] == 403
    assert client.request(endpoint, form=invalid, authorization=authorization)[0] == 422
    assert client.request('/healthz')[0] == 200
    assert not persistent.exists()
    assert client.request(endpoint, form=valid, authorization=authorization)[:2] == (303, endpoint)

    updated = Client(imported, client.http_port, client.https_port)
    assert b'Certificat externe' in updated.request(endpoint, authorization=authorization)[2]
    assert updated.request(endpoint, form=invalid, authorization=authorization)[0] == 422
    assert updated.request('/healthz')[0] == 200
    bundle = persistent/'external.json'
    assert stat.S_IMODE(persistent.stat().st_mode) == 0o700
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    assert json.loads(bundle.read_text()) == valid
    print('Rust imported a matching TLS pair without restart and refused the mismatched key', flush=True)
    return updated


def verify_image_console(client, database, authorization):
    endpoint = '/settings/images'

    def submit(form, **kwargs):
        return client.request(endpoint, form=form, authorization=authorization, **kwargs)

    with closing(sqlite3.connect(database)) as db, db:
        db.executemany("""INSERT INTO catalog_entries(id,distro,version_full,arch,extract_method)
                          VALUES(?,?,?,?,?)""", [(9001,'debian','13.0-console','arm64','direct'),
                                                 (9002,'other','1.0-console','amd64','direct')])
        db.execute("INSERT INTO os_images(distro,version,arch,status) VALUES('legacy','<trixie>','amd64','downloaded')")
        db.execute("INSERT INTO init_jobs(job_type,status) VALUES('bootstrap:refresh_catalog','running')")
    assert client.request(endpoint)[0] == 401
    assert client.request(endpoint, secure=False)[0] == 404
    assert submit({'action':'refresh'}, origin='https://other.example')[0] == 403
    assert submit({'action':'refresh'})[:2] == (303, endpoint)
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT COUNT(*) FROM init_jobs WHERE status IN ('running','pending')").fetchone() == (1,)
        db.execute("UPDATE init_jobs SET status='success' WHERE job_type='bootstrap:refresh_catalog'")
    assert submit({'image':'9002'})[0] == 422
    assert submit({'image':'9001'})[:2] == (303, endpoint)
    for _ in range(2):
        assert submit({'action':'refresh', 'image':'9001'})[:2] == (303, endpoint)
    with closing(sqlite3.connect(database)) as db, db:
        job, = db.execute("SELECT id FROM init_jobs WHERE job_type='bootstrap:refresh_catalog_v2'").fetchall()
        assert json.loads(db.execute("SELECT value FROM settings WHERE key='catalog_job_ids'").fetchone()[0]) == list(job)
        db.execute("UPDATE os_images SET status='downloading', progress_percent=61 WHERE version_full='13.0-console'")
    assert submit({'image':'9001'})[:2] == (303, endpoint)
    status, _, page = client.request(endpoint, authorization=authorization)
    assert status == 200 and b'Debian 13.0-console' in page
    assert b'&lt;trixie&gt;' in page and b'1.0-console' not in page
    assert b'<td>downloading</td><td>61 %</td>' in page
    print('Rust image console displays legacy and live state and queues guided downloads and refreshes once', flush=True)


def verify_job_console(client, database, authorization):
    with closing(sqlite3.connect(database)) as db, db:
        job = db.execute(
            "INSERT INTO init_jobs(job_type,status,progress_percent,message,log) VALUES(?,?,?,?,?)",
            ('bootstrap:restart_dnsmasq','running',30,'Application réseau','<fixture-log>'),
        ).lastrowid
    endpoint = f'/jobs/{job}'
    assert client.request(endpoint)[0] == 401
    assert client.request(endpoint, secure=False)[0] == 404
    assert client.request('/api/init-job-status?job_type=bootstrap:restart_dnsmasq')[0] == 401
    page = client.request('/jobs', authorization=authorization)
    assert page[0] == 200 and endpoint.encode() in page[2]
    page = client.request(endpoint, authorization=authorization)
    assert page[0] == 200 and b'&lt;fixture-log&gt;' in page[2]
    poll = client.request(endpoint+'/poll', authorization=authorization)
    assert poll[0] == 200 and b'30 %' in poll[2]
    status = client.request(endpoint+'/status', authorization=authorization)
    assert status[0] == 200 and json.loads(status[2]) == {
        'found':True,'id':job,'job_type':'bootstrap:restart_dnsmasq','status':'running',
        'progress_percent':30,'message':'Application réseau',
        'started_at':None,'ended_at':None,'updated_at':None,
    }
    latest = client.request('/api/init-job-status?job_type=bootstrap:restart_dnsmasq', authorization=authorization)
    assert latest[0] == 200 and json.loads(latest[2]) == json.loads(status[2])
    missing = client.request('/jobs/9223372036854775807/status', authorization=authorization)
    assert missing[0] == 404 and json.loads(missing[2]) == {'found':False}
    print('Rust job console preserves authenticated job status and escapes rendered logs', flush=True)


def verify_activity(client, database, authorization):
    with closing(sqlite3.connect(database)) as db, db:
        device = db.execute("INSERT INTO machines(mac,hostname) VALUES(?,?)",
                            ('02:00:00:00:20:01','activity_%')).lastrowid
        action = db.execute(
            "INSERT INTO actions(machine_id,type,status,token,created_by) VALUES(?,'install_only','running',?,?)",
            (device, secrets.token_hex(32), '<fixture-author>'),
        ).lastrowid
        db.execute("INSERT INTO machine_events(machine_id,action_id,message) VALUES(?,?,?)",
                   (device, action, '<fixture-event>'))
        db.execute("INSERT INTO installations(machine_id,install_status,action_id) VALUES(?,'success',?)",
                   (device, action))
        legacy = db.execute(
            "INSERT INTO installations(machine_id,install_status,install_log) VALUES(?,'in_progress','<legacy-log>')",
            (device,),
        ).lastrowid
    path = '/activity?' + urlencode({'type':'install', 'q':'_%', 'machine':device})
    assert client.request(path)[0] == 401
    assert client.request(path, secure=False)[0] == 404
    status, _, body = client.request(path, authorization=authorization)
    assert status == 200 and f'href="/tasks/{action}"'.encode() in body and b'&lt;fixture-author&gt;' in body
    assert body.count(b'href="/installations/') == 1 and f'href="/installations/{legacy}"'.encode() in body
    assert b'&lt;fixture-event&gt;' in body and b'<fixture-event>' not in body
    signature = body.split(b'data-sig="',1)[1].split(b'"',1)[0].decode()
    assert client.request(path.replace('/activity?', '/activity/list?')+'&sig='+signature,
                          authorization=authorization)[0] == 204
    assert b'&lt;fixture-event&gt;' in client.request(f'/tasks/{action}', authorization=authorization)[2]
    assert b'&lt;legacy-log&gt;' in client.request(f'/installations/{legacy}', authorization=authorization)[2]
    print('Rust activity preserves action and legacy install links, authenticated filtering, and progress fragments', flush=True)


def verify_appliance_settings(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    assert client.request('/settings')[0] == 401
    assert request('/settings', secure=False)[0] == 404
    assert request('/settings/https')[:2] == (302, '/admin/certificates')
    assert request('/settings/terminology', form={'ui_device_term':'ordinateur'})[:2] == (303, '/settings')
    assert request('/settings', form={'discovery_boot_proto':'invalid'})[0] == 422
    assert request('/settings', form={'discovery_boot_proto':'tftp'})[:2] == (303, '/settings')
    page = request('/settings')
    assert b'name="discovery_boot_proto"' in page[2] and b'value="tftp" selected' in page[2]
    route = '/settings/default-dns'
    valid = [('default_dns[]','192.0.2.5'), ('default_dns[]','192.0.2.5'), ('default_dns[]','192.0.2.6')]
    assert request(route, form=valid, origin='https://outside.example')[0] == 403
    assert request(route, form=valid)[:2] == (303, '/settings')
    assert request(route, form={'default_dns[]':'192.0.2.500'})[0] == 422
    assert request('/settings/ipxe', form={'ipxe_enabled':'on'})[:2] == (303, '/settings/ipxe')
    assert request('/settings/regenerate-mok', form={})[0] == 422
    assert request('/settings/apply-config', form={})[:2] == (303, '/settings')
    with closing(sqlite3.connect(database)) as db, db:
        settings = dict(db.execute('SELECT key,value FROM settings'))
        assert json.loads(settings['default_dns']) == ['192.0.2.5','192.0.2.6']
        assert settings['ipxe_enabled'] == 'on'
        ids = json.loads(settings['appliance_last_job_ids'])
        assert [db.execute('SELECT job_type,status FROM init_jobs WHERE id=?', [job]).fetchone() for job in ids] == [
            ('bootstrap:build_grub','pending'), ('bootstrap:render_templates','pending'),
            ('bootstrap:restart_dnsmasq','pending'),
        ]
        ipxe_job, = json.loads(settings['ipxe_job_ids'])
        assert db.execute('SELECT job_type,status FROM init_jobs WHERE id=?', [ipxe_job]).fetchone() == (
            'bootstrap:render_templates','pending',
        )
        assert f'href="/jobs/{ipxe_job}"'.encode() in request('/settings/ipxe')[2]
        db.execute("""CREATE TRIGGER refuse_rust_settings_fixture_job BEFORE INSERT ON init_jobs
                   WHEN NEW.job_type='bootstrap:render_templates'
                   BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
    assert request('/settings/ipxe', form={})[0] == 503
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT value FROM settings WHERE key='ipxe_enabled'").fetchone() == ('on',)
        db.execute('DROP TRIGGER refuse_rust_settings_fixture_job')
    assert request(route, form={'default_dns[]':''})[:2] == (303, '/settings')
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT value FROM settings WHERE key='default_dns'").fetchone() == ('[]',)
    print('Rust appliance settings validated DNS and boot options and rolled back failed worker scheduling', flush=True)


def verify_device_settings(client, database, authorization):
    assert client.request('/machines',authorization=authorization)[:2]==(302,'/admin/devices')
    assert client.request('/machines/new')[0]==401
    assert client.request('/machines/new',authorization=authorization)[0]==200
    assert client.request('/machines',form={'mac':'invalid'},authorization=authorization)[0]==422
    manual = {'mac':'02-00-00-00-09-04','hostname':'fixture-manual'}
    registered = client.request('/machines',form=manual,authorization=authorization)
    assert registered[0]==303 and registered[1].startswith('/machines/')
    assert client.request('/machines',form=manual,authorization=authorization)[0]==409
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT hostname,status FROM machines WHERE mac='02:00:00:00:09:04'").fetchone()==(
            'fixture-manual','discovered',
        )
        device = db.execute(
            """INSERT INTO machines(mac,hostname,status,local_boot_source,next_action,awaiting_action_until)
               VALUES('02:00:00:00:09:03','fixture-edit','installing','manual','reboot',datetime('now','+1 hour'))"""
        ).lastrowid
        action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(?,'install_only','running',?)",
                            (device,secrets.token_hex(32))).lastrowid
        db.execute("""INSERT INTO installations(machine_id,action_id,install_status,ansible_status)
                      VALUES(?,?,'installing','pending')""",(device,action))
        db.execute("INSERT INTO init_jobs(job_type,status) VALUES(?,'pending')",(f'action:render_postboot:{action}',))
    path = f'/machines/{device}'
    settings = {'_method':'PUT','notes':'<fixture & notes>','boot_mode':'tftp','hostname':'ignored'}
    assert client.request(path,form=settings)[0]==401
    assert client.request(path,form=settings,authorization=authorization,origin='https://other.example')[0]==403
    assert client.request(path,form={**settings,'local_boot_source':'pxe'},authorization=authorization)[0]==422
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT notes,boot_mode FROM machines WHERE id=?',(device,)).fetchone()==(None,'http')
    assert client.request(path,form=settings,authorization=authorization)[:2]==(303,path)
    detail = client.request(path,authorization=authorization)
    assert detail[0]==200 and b'&lt;fixture &amp; notes&gt;' in detail[2], detail
    assert b'<strong>Installation en cours</strong>' in client.request(path+'/status',authorization=authorization)[2]
    status = client.request(path+'/status',form={'status':'wiped'},authorization=authorization)
    assert status[:2]==(303,path+'#settings')
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("""SELECT hostname,notes,boot_mode,local_boot_source,status,next_action,awaiting_action_until
                             FROM machines WHERE id=?""",(device,)).fetchone()==(
            'fixture-edit','<fixture & notes>','tftp','none','wiped',None,None,
        )
        assert db.execute('SELECT status FROM actions WHERE id=?',(action,)).fetchone()==('cancelled',)
        assert db.execute('SELECT install_status,ansible_status FROM installations WHERE action_id=?',(action,)).fetchone()==(
            'aborted','aborted',
        )
        assert db.execute('SELECT status FROM init_jobs WHERE job_type=?',(f'action:render_postboot:{action}',)).fetchone()==('failed',)
        assert db.execute("SELECT COUNT(*) FROM init_jobs WHERE job_type='bootstrap:render_templates' AND status='pending'").fetchone()==(1,)
    print('Rust device settings preserve fields and close administrative tracking without a remote command', flush=True)


def verify_device_operations(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    with closing(sqlite3.connect(database)) as db, db:
        device = db.execute(
            """INSERT INTO machines(mac,hostname,status,awaiting_action_until)
               VALUES('02:00:00:00:09:20','fixture-rescue','discovered',datetime('now','+1 hour'))"""
        ).lastrowid
        db.execute("INSERT INTO disk_tests(machine_id,jobs_json,job_status) VALUES (?,'[]','running')", [device])
    path = f'/machines/{device}'
    rescue, rediscover = path+'/rescue', path+'/rediscover'
    assert client.request(rescue, form={})[0] == 401
    assert request(rescue, form={}, secure=False)[0] == 404
    assert request(rescue, form={}, origin='https://outside.example')[0] == 403
    assert request(rescue)[0] == 405
    assert request(rescue, form={})[0] == 409
    assert request(rediscover, form={})[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute('SELECT status,rescue_mode,next_action FROM machines WHERE id=?', [device]).fetchone() == (
            'discovered',0,None,
        )
        assert db.execute('SELECT id FROM init_jobs WHERE job_type=?', [f'machine:reboot:{device}']).fetchone() is None
        db.execute("UPDATE disk_tests SET job_status='success' WHERE machine_id=?", [device])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request(rescue, form={})[0], range(2)))
    assert sorted(results) == [303,409], results
    assert b'Quitter le mode' in request(path)[2]
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute('SELECT status,rescue_mode,next_action,awaiting_action_until FROM machines WHERE id=?',
                          [device]).fetchone() == ('discovered',1,'reboot',None)
        assert db.execute('SELECT status FROM init_jobs WHERE job_type=?', [f'machine:reboot:{device}']).fetchall() == [
            ('pending',),
        ]
        db.execute("UPDATE init_jobs SET status='success' WHERE job_type=?", [f'machine:reboot:{device}'])
    assert request(rescue+'/exit', form={})[:2] == (303,path)
    assert request(rediscover, form={})[:2] == (303,path)
    with closing(sqlite3.connect(database)) as db:
        assert db.execute('SELECT status,rescue_mode,next_action FROM machines WHERE id=?', [device]).fetchone() == (
            'inventorying',0,'reboot',
        )
        assert db.execute('SELECT status FROM init_jobs WHERE job_type=? ORDER BY id',
                          [f'machine:reboot:{device}']).fetchall() == [('success',),('pending',)]
    with closing(sqlite3.connect(database)) as db, db:
        power = db.execute("""INSERT INTO machines(mac,hostname,status,awaiting_action_until)
                            VALUES('02:00:00:00:09:21','fixture-power','discovered',datetime('now','+1 hour'))"""
                           ).lastrowid
    path = f'/machines/{power}'
    assert request(path+'/shutdown',form={})[:2] == (303,path)
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT next_action,awaiting_action_until IS NOT NULL FROM machines WHERE id=?",
                          [power]).fetchone() == ('poweroff',1)
        assert db.execute("SELECT id FROM init_jobs WHERE job_type=?", [f'machine:shutdown:{power}']).fetchone() is None
    assert request(path+'/power',form={'action':'cancel'})[:2] == (303,path)
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT next_action FROM machines WHERE id=?", [power]).fetchone() == (None,)
        db.execute("UPDATE machines SET status='configured',awaiting_action_until=NULL WHERE id=?", [power])
        action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(?,'install_only','pending',?)",
                            [power,secrets.token_hex(32)]).lastrowid
    assert request(path+'/wake',form={})[:2] == (303,path)
    assert request(path+'/reboot',form={})[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT status FROM init_jobs WHERE job_type=?", [f'machine:reboot:{power}']).fetchall() == [
            ('pending',),
        ]
        db.execute("UPDATE init_jobs SET status='success' WHERE job_type=?", [f'machine:reboot:{power}'])
        db.execute("UPDATE actions SET status='running' WHERE id=?", [action])
    assert request(path+'/shutdown',form={})[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE actions SET status='success' WHERE id=?", [action])
    assert request(path+'/shutdown',form={})[:2] == (303,path)
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT status FROM init_jobs WHERE job_type=?", [f'machine:shutdown:{power}']).fetchall() == [
            ('pending',),
        ]
    print('Rust recovery, inventory and power helpers reject conflicts and select the existing poll or worker channel', flush=True)


def verify_device_ansible(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    with closing(sqlite3.connect(database)) as db, db:
        device = db.execute("""INSERT INTO machines(mac,hostname,status)
                              VALUES('02:00:00:00:09:22','fixture-ansible','installed')""").lastrowid
    path = f'/machines/{device}/ansible'
    assert client.request(path+'/pull',form={})[0] == 401
    assert request(path+'/pull',form={},origin='https://outside.example')[0] == 403
    assert request(path+'/pull')[0] == 405
    assert request(path+'/redeploy',form={})[0] == 409
    assert request(path+'/retry',form={})[0] == 409
    pull = request(path+'/pull',form={})
    assert pull[0] == 303 and pull[1].startswith('/jobs/')
    assert request(path+'/pull',form={})[:2] == pull[:2]
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE machines SET install_config_json=? WHERE id=?",
                   [json.dumps({'ansible_role':'sample-role'}), device])
        action = db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES (?,'install_only','failed',?)",
                            [device,secrets.token_hex(32)]).lastrowid
        db.execute("""INSERT INTO installations(machine_id,action_id,install_status,ansible_status)
                      VALUES (?,?,'success','failed')""", [device,action])
    deploy = request(path+'/redeploy',form={})
    assert deploy[0] == 303 and deploy[1].startswith('/jobs/')
    assert request(path+'/redeploy',form={})[:2] == deploy[:2]
    assert request(path+'/retry',form={})[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE init_jobs SET status='success' WHERE id=?", [int(deploy[1].split('/')[-1])])
    assert request(path+'/retry',form={})[:2] == (303,f'/tasks/{action}')
    assert request(path+'/retry',form={})[0] == 409
    with closing(sqlite3.connect(database)) as db:
        kinds = ('ansible_repo:pull', f'machine:ansible_redeploy:{device}', f'action:ansible_retry:{action}')
        for kind in kinds:
            assert db.execute('SELECT COUNT(*) FROM init_jobs WHERE job_type=?', [kind]).fetchone() == (1,)
    print('Rust scheduled Ansible pull, redeploy and retry through the established worker queue', flush=True)


def verify_hardware_context(client, database, authorization):
    def request(path):
        return client.request(path, authorization=authorization)

    inventory = {
        'inventory':{'memory_kb':'1048576', 'boot_mode':'UEFI', 'cpu_model':' Fixture CPU ',
                     'cpu_cores':4, 'cpu_max_mhz':2100},
        'boot_mac':'02-00-00-00-09-99',
        'interfaces':[{'mac':'02:00:00:00:09:99', 'name':'eth0','speed_mbps':1000,
                       'ipv4':['192.0.2.8','192.0.2.9']}],
        'disks':[{'name':'vda','size_bytes':32000000000,'rota':False,'serial':'Dupe'},
                 {'name':'/dev/vdb','size_bytes':'64000000000','serial':'DUPE',
                  'identity':{'kind':'serial','source':'sysfs','value':'DUPE','status':'valid'}},
                 {'name':'vdc','size_bytes':'1000000000','serial':'OLD'},
                 {'name':'vdd','serial':'unknown'}],
    }
    with closing(sqlite3.connect(database)) as db, db:
        device = db.execute("""INSERT INTO machines(mac,status,inventory_json)
                              VALUES('02:00:00:00:09:23','discovered',?)""",
                            [json.dumps(inventory)]).lastrowid
    route = f'/machines/{device}/hardware-context.json'
    assert client.request(route)[0] == 401
    assert client.request(route,authorization=authorization,secure=False)[0] == 404
    response = request(route)
    assert response[0] == 200
    fields = json.loads(response[2])
    assert fields['boot_mac'] == '02:00:00:00:09:99'
    assert fields['is_uefi'] and fields['ram_kb'] == 1048576
    assert fields['cpu'] == {'model':'Fixture CPU','cores':4,'max_mhz':2100,'current_mhz':None}
    assert fields['nics'][0]['ipv4'] == '192.0.2.8, 192.0.2.9'
    assert fields['disk_capacities_mb'] == {'/dev/vda':32000,'/dev/vdb':64000,'/dev/vdc':1000}
    assert [disk['identity_status'] for disk in fields['disks']] == ['ambiguous','ambiguous','legacy','missing']
    assert fields['disks'][1]['size_mb'] == 64000
    assert fields['disks'][1]['identity'] == {'kind':'serial','value':'DUPE','source':'sysfs','status':'valid'}
    assert fields['disks'][3]['identity'] is None
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE machines SET inventory_json='invalid' WHERE id=?", [device])
    empty = json.loads(request(route)[2])
    assert empty['boot_mac'] == '' and empty['disks'] == [] and empty['disk_capacities_mb'] == []
    missing = request('/machines/123456789/hardware-context.json')
    assert missing[0] == 404 and json.loads(missing[2]) == {'error':'machine not found'}
    print('Rust exposes the historical hardware context and flags ambiguous identities', flush=True)


def verify_admin_attempt_limit(client, authorization):
    path = '/admin/devices'
    for _ in range(21):
        assert client.request(path,authorization=authorization)[0]==200
    for _ in range(20):
        assert client.request(path,authorization='fixture-unknown:invalid')[0]==401
    assert client.request(path,authorization='fixture-unknown:invalid')[0]==429
    print('Rust kept failed admin attempts rate-limited while serving a signed-in operator', flush=True)


def verify_authentik_proxy(server, client, env, registry, authorization):
    mode = {**env,'AUTH_MODE':'authentik'}
    headers = {'X-Forwarded-User':'authentik-fixture','X-Forwarded-Host':'pxe.example.test'}
    path = '/admin/settings/device-terminology'
    for name,cidrs in (
        ('untrusted','192.0.2.7/32'),('invalid','127.0.0.1/32,invalid'),('trusted','127.0.0.1/32'),
    ):
        with subprocess.Popen(server, env={**mode,'AUTHENTIK_TRUSTED_PROXY_CIDRS':cidrs}) as proxy:
            try:
                client.ready(proxy)
                assert client.request('/admin/devices',authorization=authorization)[0]==401
                if name!='trusted':
                    forged = {**headers,'X-Forwarded-For':'192.0.2.7'}
                    assert client.request('/admin/devices',extra_headers=forged)[0]==401
                    assert client.request(path,form={'ui_device_term':'serveur'},origin='https://pxe.example.test',
                                          extra_headers=forged)[0]==403
                    continue
                assert client.request('/admin/devices',extra_headers=headers)[0]==200
                assert client.request('/admin/devices',extra_headers={**headers,'X-Forwarded-User':'a,b'})[0]==401
                assert client.request(path,form={'ui_device_term':'serveur'},origin='https://outside.example',
                                      extra_headers=headers)[0]==403
                assert client.request(path,form={'ui_device_term':'serveur'},origin='https://pxe.example.test',
                                      extra_headers=headers)[:2]==(303,'/admin/devices')
                assert b'<h1>Serveurs</h1>' in client.request('/admin/devices',extra_headers=headers)[2]
                with closing(sqlite3.connect(registry)) as db:
                    assert not db.execute("SELECT 1 FROM users WHERE username='authentik-fixture'").fetchone()
            finally:
                proxy.terminate()
                proxy.wait(timeout=5)
    print('Rust accepted Authentik only from a trusted peer and verified forwarded HTTPS origin', flush=True)


def verify_guided_install(client, database, authorization):
    pull = '/presets/pull-github'
    assert client.request(pull,form={},authorization=authorization)[0]==409
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("INSERT INTO settings(key,value) VALUES('ansible_repo_url','https://example.test/presets')")
    assert client.request(pull,form={},authorization=authorization,origin='https://other.example')[0]==403
    first = client.request(pull,form={},authorization=authorization)
    assert first[0]==303 and first[1].startswith('/jobs/')
    assert client.request(pull,form={},authorization=authorization)[:2]==first[:2]
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT COUNT(*) FROM init_jobs WHERE job_type='preset:pull_github' AND status='pending'").fetchone()==(1,)
    inventory = {'disks':[{'name':'vda','serial':'FIXTURE-SERIAL',
                           'identity':{'kind':'serial','source':'sysfs','value':'FIXTURE-SERIAL','status':'valid'}}]}
    new_profile = {'name':'Debian <test>', 'login':'fixture','password':'fixture-password','confirm':'fixture-password'}
    assert client.request('/presets', form=new_profile)[0] == 401
    assert client.request('/presets', form={**new_profile,'confirm':'mismatch'}, authorization=authorization)[0] == 422
    created = client.request('/presets', form=new_profile, authorization=authorization)
    assert created[:2] == (303, '/presets'), created[:2]
    assert client.request('/presets', form=new_profile, authorization=authorization)[0] == 409
    rendered = client.request('/presets', authorization=authorization)
    assert b'Debian &lt;test&gt;' in rendered[2] and b'fixture-password' not in rendered[2]
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE settings SET value='on' WHERE key='pxe_enabled'")
        db.executemany("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                       [('pxe_subnet','192.0.2.0/24'), ('pxe_ip','192.0.2.1'),
                        ('default_dns','["192.0.2.53","192.0.2.54"]')])
        device = db.execute(
            "INSERT INTO machines(mac,hostname,status,boot_arch,inventory_json) VALUES(?,?,'discovered','arm64',?)",
            ('02:00:00:00:20:02', 'fixture-device', json.dumps(inventory)),
        ).lastrowid
        preset, password_hash = db.execute("SELECT id,admin_user_pwhash FROM presets WHERE name=?",
                                           (new_profile['name'],)).fetchone()
        assert password_hash.startswith('$6$') and 'fixture-password' not in password_hash
        image = db.execute(
            "INSERT INTO os_images(distro,version,arch,codename,version_full,enabled,status) "
            "VALUES('debian','fixture-trixie','arm64','trixie','13.7.0',1,'downloaded')",
        ).lastrowid
    end = f'/machines/{device}/install'
    form = {'hostname':'deb-fixture','disk':'/dev/vda:FIXTURE-SERIAL','preset':preset,'image':image,'confirm':'yes'}
    assert client.request(end, form=form, authorization=authorization, secure=False)[0] == 404
    assert client.request(end, form=form)[0] == 401
    assert client.request(end, form=form, origin='https://outside.example', authorization=authorization)[0] == 403
    result = client.request(end, authorization=authorization)
    assert result[0] == 200 and b'FIXTURE-SERIAL' in result[2], result[:2]
    assert b'name="static_dns" value="192.0.2.53 192.0.2.54"' in result[2]
    assert client.request(end, form={**form,'disk':'/dev/vda:STALE'}, authorization=authorization)[0] == 409
    static = {**form,'network_mode':'static','static_ip':'192.0.2.80','static_cidr':'24',
              'static_gateway':'192.0.2.1','static_dns':'192.0.2.53 192.0.2.54'}
    for invalid in ({'static_ip':'203.0.113.80'}, {'static_ip':'192.0.2.1'},
                    {'static_cidr':'31'}, {'static_gateway':'198.51.100.1'}, {'static_dns':'invalid'}):
        assert client.request(end,form={**static,**invalid},authorization=authorization)[0] == 422
    with closing(sqlite3.connect(database)) as db, db:
        other = db.execute("""INSERT INTO machines(mac,hostname,status,boot_arch,inventory_json)
                            VALUES('02:00:00:00:20:03','fixture-static','discovered','arm64',?)""",
                           [json.dumps(inventory)]).lastrowid
    static_result = client.request(f'/machines/{other}/install',form=static,authorization=authorization)
    assert static_result[0] == 303, static_result
    with closing(sqlite3.connect(database)) as db:
        raw, = db.execute('SELECT install_config_json FROM machines WHERE id=?',[other]).fetchone()
        network = json.loads(raw)
        assert (network['network_mode'], network['static_ip'], network['static_cidr'],
                network['static_gateway'], network['static_dns']) == (
                    'static','192.0.2.80',24,'192.0.2.1',['192.0.2.53','192.0.2.54'],
                )
    assert client.request(end, form={**form,'confirm':'no'}, authorization=authorization)[0] == 422
    status, location, _ = client.request(end, form=form, authorization=authorization)
    assert status == 303, status
    action = int(location.split('/')[-1])
    assert client.request(end, form=form, authorization=authorization)[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute('SELECT count(*) FROM actions WHERE machine_id=?',(device,)).fetchone() == (1,)
        state, next_action, snapshot = db.execute(
            'SELECT status,next_action,install_config_json FROM machines WHERE id=?',(device,),
        ).fetchone()
        assert (state,next_action) == ('configured',None)
        snapshot = json.loads(snapshot)
        assert snapshot['system_disk_identity']['value'] == 'FIXTURE-SERIAL'
        assert snapshot['version_full'] == '13.7.0' and snapshot['_pending_action_id'] == action
        assert db.execute("SELECT length(token),status FROM actions WHERE id=?",(action,)).fetchone()==(64,'pending')
        assert db.execute("SELECT status FROM init_jobs WHERE job_type=?",(f'action:render_postboot:{action}',)).fetchone() == ('pending',)
        db.execute("UPDATE settings SET value='off' WHERE key='pxe_enabled'")
    print('Rust guided scheduling rejected stale identity and replay, and atomically queued the selected install', flush=True)


def verify_disk_diagnostics(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE settings SET value='on' WHERE key='pxe_enabled'")
        disk = {'name':'/dev/vda','serial':'FIXTURE-DISK-TEST','size_bytes':12_000_000_000}
        other = {'name':'vdb','serial':'UNTESTED-FIXTURE','size_bytes':12_000_000_000}
        device = db.execute("""INSERT INTO machines(mac,hostname,status,boot_arch,inventory_json,awaiting_action_until)
                            VALUES('02:00:00:00:09:25','fixture-diagnostics','discovered','amd64',?,datetime('now','+30 minutes'))""",
                            [json.dumps({'disks':[disk,other]})]).lastrowid
        preset, = db.execute("SELECT id FROM presets WHERE name='Debian <test>'").fetchone()
        image, = db.execute("SELECT id FROM os_images WHERE arch='amd64' AND version_full='13.7.0' "
                            "AND status='downloaded' AND enabled=1 LIMIT 1").fetchone()
    path = f'/machines/{device}/disktest'
    fields = {'disk':'/dev/vda:FIXTURE-DISK-TEST','mode':'smart_short'}
    assert b'FIXTURE-DISK-TEST' in request(path)[2]
    assert request(path,form={**fields,'mode':'badblocks_fixed_rw'})[0] == 422
    assert request(path,form={**fields,'disk':'/dev/vda:STALE'})[0] == 409
    assert request(path,form=fields,origin='https://outside.example')[0] == 403
    scheduled = request(path,form=fields)
    assert scheduled[0] == 303 and scheduled[1].startswith('/tasks/')
    action = int(scheduled[1].split('/')[-1])
    assert request(path,form=fields)[0] == 409
    with closing(sqlite3.connect(database)) as db:
        state, commands, linked = db.execute("SELECT job_status,jobs_json,in_session FROM disk_tests WHERE action_id=?",
                                             [action]).fetchone()
        assert state=='pending' and linked==1
        jobs = json.loads(commands)
        assert jobs[0]['identity']['value'] == 'FIXTURE-DISK-TEST'
        assert db.execute("SELECT id FROM init_jobs WHERE job_type=?",[f'action:reboot:{action}']).fetchone() is None
    assert request(path+'-post-action',form={'post_action':'poweroff'})[:2] == (303,f'/machines/{device}')
    install = f'/machines/{device}/install'
    form = {'hostname':'fixture-diagnostics','disk':fields['disk'],'image':image,'preset':preset,'confirm':'yes'}
    assert b'name="after_diagnostic"' in request(install)[2]
    assert request(install,form=form)[0] == 409
    deferred = {**form,'after_diagnostic':'yes'}
    assert request(install,form={**deferred,'disk':'/dev/vdb:UNTESTED-FIXTURE'})[0] == 409
    scheduled = request(install,form=deferred)
    assert scheduled[0] == 303 and scheduled[1].startswith('/tasks/'), scheduled
    pending = int(scheduled[1].rsplit('/',1)[1])
    assert request(install,form=deferred)[0] == 409
    with closing(sqlite3.connect(database)) as db:
        state, next_action, snapshot = db.execute('SELECT status,next_action,install_config_json FROM machines '
                                                 'WHERE id=?',[device]).fetchone()
        assert state == 'testing' and next_action is None
        assert json.loads(snapshot)['wake_now'] is True
        assert db.execute('SELECT post_action FROM disk_tests WHERE action_id=?',[action]).fetchone() == ('wait',)
        assert db.execute('SELECT status FROM actions WHERE id=?',[pending]).fetchone() == ('pending',)
    assert request(path+'-cancel',form={})[:2] == (303,f'/machines/{device}')
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT job_status,post_action FROM disk_tests WHERE action_id=?",[action]).fetchone()==(
            'aborted','wait',
        )
        assert db.execute("SELECT status FROM actions WHERE id=?",[action]).fetchone()==('cancelled',)
        assert db.execute("SELECT status FROM actions WHERE id=?",[pending]).fetchone()==('cancelled',)
        assert db.execute("SELECT status FROM init_jobs WHERE job_type=?",
                          [f'action:render_postboot:{pending}']).fetchone() == ('failed',)
        assert db.execute("SELECT status FROM machines WHERE id=?",[device]).fetchone()==('discovered',)
        db.execute("UPDATE settings SET value='off' WHERE key='pxe_enabled'")
    print('Rust scheduled Debian after qualification of the selected disk and cancelled both linked actions', flush=True)


def verify_disk_wipe(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)
    inventory = {'disks':[{'name':'vda','serial':'FIXTURE-WIPE-A'}, {'name':'/dev/vdb','serial':'FIXTURE-WIPE-B'}]}
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE settings SET value='on' WHERE key='pxe_enabled'")
        device = db.execute("""INSERT INTO machines(mac,hostname,status,inventory_json,awaiting_action_until,local_boot_source)
                            VALUES('02:00:00:00:09:26','fixture-wipe','discovered',?,datetime('now','+1 hour'),'manual')""",
                            [json.dumps(inventory)]).lastrowid
    path = f'/machines/{device}/wipe-disks'
    form = [('targets[]','/dev/vda:FIXTURE-WIPE-A'),('targets[]','/dev/vdb:FIXTURE-WIPE-B'),
            ('mode[/dev/vda]','partial'),('mode[/dev/vdb]','full'),('post_action','poweroff')]
    assert b'FIXTURE-WIPE-A' in request(path)[2]
    assert request(path,form=form)[0] == 422
    assert request(path,form=form+[('confirm','EFFACER')],origin='https://outside.example')[0] == 403
    old = [('targets[]','/dev/vda:STALE'),*form[1:],('confirm','EFFACER')]
    assert request(path,form=old)[0] == 409
    saved = request(path,form=form+[('confirm','EFFACER')])
    assert saved[0] == 303 and saved[1].startswith('/tasks/')
    assert request(path,form=form+[('confirm','EFFACER')])[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        status, planned, local = db.execute(
            'SELECT status,next_action,local_boot_source FROM machines WHERE id=?',[device],
        ).fetchone()
        assert (status,planned,local) == ('wiping','reboot','none')
        kind, raw = db.execute("SELECT wipe_mode,disks_json FROM wipes WHERE machine_id=?", [device]).fetchone()
        assert kind=='mixed'
        assert [(entry['name'],entry['mode'],entry['identity']['value']) for entry in json.loads(raw)] == [
            ('vda','partial','FIXTURE-WIPE-A'),('/dev/vdb','full','FIXTURE-WIPE-B'),
        ]
        db.execute("UPDATE settings SET value='off' WHERE key='pxe_enabled'")
    print('Rust console required explicit wipe confirmation and bound both disk identities in one operation', flush=True)


def verify_custom_partition_review(client, database, authorization):
    def request(path, **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    disks = ['/dev/vda','/dev/vdb']
    inventory = {'inventory':{'boot_mode':'BIOS'}, 'disks':[
        {'name':path.removeprefix('/dev/'), 'serial':f'FIXTURE-RAID-{index}', 'size_bytes':12_000_000_000}
        for index,path in enumerate(disks)
    ]}
    plan = {'target_disks':disks,'disks':[
        {'path':path,'partitions':[
            {'id':f'bios{index}','fs':'biosgrub','size_mb':2},
            {'id':f'raid{index}','fs':'raid-member','fill':True},
        ]}
        for index,path in enumerate(disks)
    ],'raid_arrays':[{'name':'md0','level':1,'members':['raid0','raid1']}]}
    with closing(sqlite3.connect(database)) as db, db:
        db.execute("UPDATE settings SET value='on' WHERE key='pxe_enabled'")
        image = db.execute("""INSERT INTO os_images(distro,version,arch,codename,version_full,enabled,status)
                             VALUES('debian','fixture-raid','amd64','trixie','13.7.0',1,'downloaded')""").lastrowid
        password, = db.execute("SELECT admin_user_pwhash FROM presets WHERE name='Debian <test>'").fetchone()
        device = db.execute("""INSERT INTO machines(mac,hostname,status,boot_arch,inventory_json)
                            VALUES('02:00:00:00:09:24','fixture-raid','discovered','amd64',?)""",
                            [json.dumps(inventory)]).lastrowid
        preset = db.execute("""INSERT INTO presets(name,distro,variant,codename,partition_mode,partition_custom_json,
                            network_mode,root_login_mode,admin_user_login,admin_user_pwhash)
                            VALUES('RAID1 <fixture>','debian','debian','trixie','custom',?,
                                   'dhcp','disabled','fixture',?)""", [json.dumps(plan),password]).lastrowid
    preview = f'/machines/{device}/install-preview'
    target = f'/machines/{device}/install/advanced'
    form = {'hostname':'fixture-raid','image':image,'preset':preset}
    assert b'RAID1 &lt;fixture&gt;' in request(target)[2]
    assert client.request(preview,form=form)[0] == 401
    assert request(preview,form=form,origin='https://outside.example')[0] == 403
    assert request(target,form={**form,'confirm':'yes'})[0] == 422
    first = request(preview,form=form)
    assert first[0] == 200 and all(d.encode() in first[2] for d in disks), first
    assert b'FIXTURE-RAID-0' in first[2] and b'FIXTURE-RAID-1' in first[2]
    assert password.encode() not in first[2]
    commit = {**ConfirmationInputs(first[2]).values,'confirm':'yes'}
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute('SELECT COUNT(*) FROM actions WHERE machine_id=?', [device]).fetchone() == (0,)
        inventory['disks'][1]['serial']='REPLACED'
        db.execute('UPDATE machines SET inventory_json=? WHERE id=?',[json.dumps(inventory),device])
    assert request(target,form=commit)[0] == 409
    second = request(preview,form=form)
    assert second[0] == 200 and b'REPLACED' in second[2]
    saved = request(target,form={**ConfirmationInputs(second[2]).values,'confirm':'yes'})
    assert saved[0] == 303 and saved[1].startswith('/tasks/'), saved
    with closing(sqlite3.connect(database)) as db, db:
        status, raw, assigned = db.execute(
            'SELECT status,install_config_json,preset_id FROM machines WHERE id=?',[device],
        ).fetchone()
        assert (status,assigned) == ('configured',preset)
        config = json.loads(raw)
        bound = json.loads(config['partition_custom_json'])
        assert bound['target_disk_identities']['/dev/vdb']['value'] == 'REPLACED'
        assert config['review_boot_mode'] == 'BIOS' and config['version_full'] == '13.7.0'
        assert config['admin_user_pwhash'] == password
        wipe_device = db.execute("""INSERT INTO machines(mac,hostname,status,boot_arch,inventory_json)
                                   VALUES('02:00:00:00:09:70','fixture-wipe','discovered','amd64',?)""",
                                 [json.dumps(inventory)]).lastrowid
        db.execute('UPDATE presets SET pre_wipe_mode=? WHERE id=?',
                   [json.dumps({'/dev/vdc':'partial'}),preset])
    wipe_preview = f'/machines/{wipe_device}/install-preview'
    wipe_target = f'/machines/{wipe_device}/install/advanced'
    wipe_form = {**form,'hostname':'fixture-wipe'}
    assert request(wipe_preview,form=wipe_form)[0] == 409
    with closing(sqlite3.connect(database)) as db, db:
        db.execute('UPDATE presets SET pre_wipe_mode_json=? WHERE id=?',
                   [json.dumps({'/dev/vda':'partial','/dev/vdb':'aucun'}),preset])
    review = request(wipe_preview,form=wipe_form)
    assert review[0] == 200 and b'name="erase"' in review[2], review
    confirmation = {**ConfirmationInputs(review[2]).values,'confirm':'yes'}
    assert request(wipe_target,form=confirmation)[0] == 422
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute('SELECT COUNT(*) FROM wipes WHERE machine_id=?',[wipe_device]).fetchone() == (0,)
    saved = request(wipe_target,form={**confirmation,'erase':'EFFACER'})
    assert saved[0] == 303 and saved[1].startswith('/tasks/'), saved
    with closing(sqlite3.connect(database)) as db, db:
        action = int(saved[1].rsplit('/',1)[1])
        assert db.execute('SELECT type,status FROM actions WHERE machine_id=? AND id=?',
                          [wipe_device,action]).fetchone() == ('reinstall','pending')
        assert db.execute('SELECT status,preset_id,next_action FROM machines WHERE id=?',
                          [wipe_device]).fetchone() == ('wiping',preset,None)
        raw, after, chain = db.execute('SELECT disks_json,post_action,chain_install_config_json '
                                      'FROM wipes WHERE action_id=?',[action]).fetchone()
        target_disk, = json.loads(raw)
        assert (target_disk['name'],target_disk['mode'],target_disk['identity']['value']) == (
            'vda','partial','FIXTURE-RAID-0',
        )
        config = json.loads(chain)['install_config']
        assert after == 'reboot' and config['_pending_action_id'] == action
        assert json.loads(config['partition_custom_json'])['target_disks'] == disks
        db.execute("UPDATE settings SET value='off' WHERE key='pxe_enabled'")
    print('Rust reviewed RAID and pre-wipe targets, refused stale or incomplete confirmations and armed the plan',
          flush=True)


def verify_worker_commands(binary):
    templates = Path(__file__).resolve().parents[2]/'docker/worker/templates'
    parameters = {'pxe_ip':'192.0.2.9','mac':'02:00:00:00:00:01','token':'synthetic-token'}
    command = [str(binary),'--render-postboot',str(templates)]
    result = subprocess.run(command, input=json.dumps(parameters), text=True,
                            capture_output=True, check=True)
    rendered = json.loads(result.stdout)
    for field, name in (('script','postboot.sh.j2'),('service','pxe-postboot.service.j2')):
        expected = (templates/name).read_text()
        for key, value in parameters.items():
            expected = expected.replace('{{ '+key+' }}', value)
        assert rendered[field]==expected
    unsafe = subprocess.run(command, input=json.dumps({**parameters,'token':'"$(fixture)"'}),
                            text=True, capture_output=True)
    assert unsafe.returncode and not unsafe.stdout and 'fixture' not in unsafe.stderr
    print('Rust worker rendered the two postboot files and refused a token with shell syntax', flush=True)

    with tempfile.TemporaryDirectory(prefix='pxe-rust-settings-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        command = [str(binary),'--migrate-network-settings',str(config)]
        empty_env = {**os.environ,'ANSIBLE_REPO_URL':'','ANSIBLE_SSH_PUBKEY':''}
        ansible_env = {
            **empty_env,
            'ANSIBLE_REPO_URL':' https://example.test/models ',
            'ANSIBLE_SSH_PUBKEY':' synthetic-public-key ',
        }
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.executemany('INSERT INTO settings VALUES(?,?)',[
                ('orchestrator_ip','192.0.2.9'),('dhcp_mode','historical'),
                ('wizard_completed','1'),('pxe_enabled','off'),
            ])
            db.execute("""CREATE TRIGGER fixture_rollback BEFORE INSERT ON settings
                          WHEN NEW.key='dhcp_proxy_enabled' BEGIN SELECT RAISE(ABORT,'fixture'); END""")
        refused = subprocess.run(command, env=empty_env, capture_output=True, text=True)
        assert refused.returncode
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute('SELECT COUNT(*) FROM settings').fetchone()==(4,)
            db.execute('DROP TRIGGER fixture_rollback')
        subprocess.run(command, env=empty_env, check=True, capture_output=True)
        with closing(sqlite3.connect(database)) as db, db:
            assert dict(db.execute('SELECT key,value FROM settings'))=={
                'orchestrator_ip':'192.0.2.9','dhcp_mode':'historical','wizard_completed':'1',
                'pxe_enabled':'off','pxe_ip':'192.0.2.9','dhcp_proxy_enabled':'off',
                'ansible_enabled':'off',
            }
            db.execute("UPDATE settings SET value='proxy' WHERE key='dhcp_mode'")
            db.execute("INSERT INTO settings VALUES('ansible_repo_url','https://example.test/existing')")
        subprocess.run(command, env=ansible_env, check=True, capture_output=True)
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute("SELECT value FROM settings WHERE key='dhcp_proxy_enabled'").fetchone()==('off',)
            assert dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'ansible_%'"))=={
                'ansible_repo_url':'https://example.test/existing',
                'ansible_ssh_pubkey':'synthetic-public-key',
                'ansible_enabled':'off',
            }
            db.execute("DELETE FROM settings WHERE key='dhcp_proxy_enabled'")
            db.execute("DELETE FROM settings WHERE key='ansible_enabled'")
        for _ in range(2):
            subprocess.run(command, env=empty_env, check=True, capture_output=True)
        with closing(sqlite3.connect(database)) as db:
            assert db.execute("SELECT value FROM settings WHERE key='dhcp_proxy_enabled'").fetchone()==('on',)
            assert db.execute("SELECT value FROM settings WHERE key='ansible_enabled'").fetchone()==('on',)
    print('Rust settings migration preserves explicit choices, DHCP fallback and optional Ansible bootstrap', flush=True)


def verify_worker_bootstrap(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-bootstrap-') as directory:
        root = Path(directory).resolve()
        database = root/'fixture.sqlite'
        scripts = root/'scripts'
        scripts.mkdir()
        (scripts/'bootstrap-build-grub.sh').write_text(
            '#!/usr/bin/env bash\n'
            'set -euo pipefail\n'
            'test "$REBUILD" = 1\n'
            'printf "BOOT:%s\\n" "$WORKER_JOB_ID"\n'
            'printf "diagnostic\\n" >&2\n'
            'sleep 0.2\n'
        )
        (scripts/'bootstrap-generate-mok.sh').write_text(
            '#!/usr/bin/env bash\nprintf "failure fixture\\n" >&2\nexit 19\n'
        )
        (scripts/'bootstrap-refresh-catalog-v2.sh').write_text(
            '#!/usr/bin/env bash\nprintf "refresh fixture\\n"\n'
        )
        with closing(sqlite3.connect(database)) as db, db:
            schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
            db.executescript(schema.read_text())
            machine = db.execute("INSERT INTO machines(mac,status) VALUES('02:00:00:00:09:44','configured')").lastrowid
            db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES (?,'install_only','pending',?)",
                       [machine,secrets.token_hex(32)])
            db.executemany("INSERT INTO init_jobs(id,job_type,status) VALUES(?,?,'pending')",[
                (81,'bootstrap:rebuild_grub'),(82,'bootstrap:generate_mok'),
                (83,'bootstrap:restart_dnsmasq'),(84,'system:factory_reset_wipe'),
                (85,'bootstrap:auto_refresh_catalog_v2'),
            ])

        def execute(job, check=True):
            return subprocess.run([str(binary),'--run-bootstrap-job',str(database),str(job),str(scripts)],
                                  check=check,capture_output=True)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(execute, [81,81]))
        assert sum(b'rebuild_grub' in completed.stdout for completed in results) == 1
        execute(82)
        execute(83)
        assert execute(84,check=False).returncode != 0
        assert execute(85).stdout == b''
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute("SELECT status FROM init_jobs WHERE id=85").fetchone() == ('pending',)
            db.execute("UPDATE actions SET status='cancelled' WHERE machine_id=?",[machine])
        execute(85)
        with closing(sqlite3.connect(database)) as db:
            rows = db.execute("""SELECT status,progress_percent,log,message FROM init_jobs ORDER BY id""").fetchall()
            assert rows[0][:2] == ('success',100)
            assert rows[0][2].count('BOOT:81') == 1 and 'diagnostic' in rows[0][2]
            assert rows[1][:2] == ('failed',0) and 'exit code = 19' in rows[1][2]
            assert rows[2][0] == 'failed' and 'Script introuvable' in rows[2][3]
            assert rows[3][0] == 'pending'
            assert rows[4][:2] == ('success',100)
            last, = db.execute("SELECT value FROM settings WHERE key='catalog_auto_refresh_last_at'").fetchone()
            assert abs(time.time()-int(last)) < 10
    print('Rust worker serializes bootstrap claims and records output, exit status and missing scripts', flush=True)


def verify_worker_download(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-download-') as directory:
        root = Path(directory).resolve()
        database, scripts = root/'fixture.sqlite', root/'scripts'
        scripts.mkdir()
        with closing(sqlite3.connect(database)) as db, db:
            schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
            db.executescript(schema.read_text())
            db.executemany("""INSERT INTO os_images(id,distro,version,arch,enabled,status,extract_method)
                           VALUES(?,'debian',?,'amd64',1,'pending',?)""", [
                (91,'fixture-direct','direct'),(92,'fixture-iso','iso_extract'),
                (93,'fixture-missing-publication','direct'),(94,'fixture-missing-script','iso_extract'),
            ])
        (scripts/'bootstrap-download-image.sh').write_text(
            '#!/usr/bin/env bash\n'
            'set -euo pipefail\n'
            'if [[ "$IMAGE_ID" == 93 ]]; then exit 0; fi\n'
            'python3 - "$PXE_DOWNLOAD_FIXTURE_DB" "$IMAGE_ID" <<\'PYTHON\'\n'
            'import sqlite3, sys\n'
            'with sqlite3.connect(sys.argv[1]) as db:\n'
            '    assert db.execute("SELECT status FROM os_images WHERE id=?", [sys.argv[2]]).fetchone() == ("downloading",)\n'
            '    db.execute("UPDATE os_images SET status=\'downloaded\', size_bytes=42 WHERE id=?", [sys.argv[2]])\n'
            'PYTHON\n'
        )
        iso = scripts/'bootstrap-download-image-iso.sh'
        iso.write_text('#!/usr/bin/env bash\nexit 19\n')

        def execute(image):
            return subprocess.run([str(binary),'--run-image-download',str(database),str(image),str(scripts)],
                                  check=True,capture_output=True,
                                  env={**os.environ,'PXE_DOWNLOAD_FIXTURE_DB':str(database)})
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(execute, [91,91]))
        assert sum(b'downloaded' in completed.stdout for completed in results) == 1
        execute(92)
        execute(93)
        iso.unlink()
        execute(94)
        with closing(sqlite3.connect(database)) as db:
            rows = db.execute("SELECT status,size_bytes,error_msg FROM os_images ORDER BY id").fetchall()
            assert rows[0] == ('downloaded',42,None)
            assert rows[1][0] == 'failed' and rows[1][2] == 'Script exit code 19'
            assert rows[2][0] == 'failed' and 'publié' in rows[2][2]
            assert rows[3][0] == 'failed' and 'Script introuvable' in rows[3][2]
    print('Rust worker claims a download once and checks that its helper actually published an image', flush=True)

def verify_worker_recovery(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-recovery-') as temporary:
        database = Path(temporary).resolve()/'fixture.sqlite'
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--recover-interrupted-jobs',str(database)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.executemany("INSERT INTO init_jobs(job_type,status,log) VALUES(?,?,?)", [
                ('image:delete:17','running','fixture journal'),
                ('bootstrap:render_templates','running','render log'),
                ('bootstrap:build_grub','success',None),
            ])
            db.execute("INSERT INTO os_images(distro,version,status,error_msg) VALUES('debian','13','downloading','prior')")
        first = subprocess.run(command, check=True, capture_output=True)
        assert json.loads(first.stdout)=={'deletions':1,'failed':1,'downloads':1}
        repeat = subprocess.run(command, check=True, capture_output=True)
        assert json.loads(repeat.stdout)=={'deletions':0,'failed':0,'downloads':0}
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute('SELECT status,log,ended_at IS NOT NULL FROM init_jobs ORDER BY id').fetchall()==[
                ('pending','fixture journal',False),('failed','render log',True),('success',None,False),
            ]
            assert db.execute('SELECT status,error_msg FROM os_images').fetchone()==(
                'pending','prior [reaper: worker redémarré]',
            )
    print('Rust worker recovery resumes image work and preserves staged deletion journals', flush=True)


def verify_schema_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-schema-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--migrate-schema',str(config)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.execute('ALTER TABLE presets DROP COLUMN root_login_mode')
            db.execute('ALTER TABLE machines DROP COLUMN local_boot_source')
            db.execute('ALTER TABLE init_jobs DROP COLUMN updated_at')
            db.execute('DROP INDEX idx_installations_action')
            db.execute('ALTER TABLE installations DROP COLUMN action_id')
            db.execute('DROP TABLE boot_sessions')
            db.execute("INSERT INTO presets(name,distro,admin_user_login) VALUES('legacy','debian','fixture')")
            db.execute("INSERT INTO machines(id,mac,status,root_password_cipher) VALUES(10,'02:00:00:01:00:01','installed','opaque')")
            db.execute("INSERT INTO machines(id,mac,status) VALUES(11,'02:00:00:01:00:02','installed')")
            db.execute("INSERT INTO installations(machine_id,install_status) VALUES(10,'success'),(11,'failed')")
            db.execute("CREATE TRIGGER refusal BEFORE UPDATE OF local_boot_source ON machines BEGIN SELECT RAISE(ABORT,'fixture'); END")
        alias = root/'alias.sqlite'
        alias.symlink_to(database)
        adoption = [str(binary),'--adopt-existing-sqlite',str(config)]
        assert subprocess.run([*adoption,str(alias)], capture_output=True).returncode
        assert not config.exists()
        original = database.read_bytes()
        subprocess.run([*adoption,str(database)], check=True, capture_output=True)
        assert json.loads(config.read_text())=={'driver':'sqlite','path':str(database)}
        assert config.stat().st_mode & 0o777==0o600 and database.read_bytes()==original
        assert subprocess.run([*adoption,str(database)], capture_output=True).returncode
        assert json.loads(config.read_text())=={'driver':'sqlite','path':str(database)}
        refused = subprocess.run(command, capture_output=True, text=True)
        assert refused.returncode
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute("SELECT name FROM pragma_table_info('installations') WHERE name='action_id'").fetchone() is None
            assert db.execute("SELECT name FROM sqlite_schema WHERE name='boot_sessions'").fetchone() is None
            db.execute('DROP TRIGGER refusal')
            db.execute('CREATE TABLE "independent "" module" (payload TEXT)')
        refusal_cases = [
            ('INSERT INTO "independent "" module" VALUES(\'external\')',
             'DELETE FROM "independent "" module"', 'tables non reconnues'),
            ("UPDATE presets SET partition_custom_json='[]'",
             'UPDATE presets SET partition_custom_json=NULL', 'recette de partition historique'),
            ('UPDATE machines SET install_config_json=\'{"partition_mode":"home_separate"}\'',
             'UPDATE machines SET install_config_json=NULL', 'configuration machine historique'),
            ("INSERT INTO settings(key,value) VALUES('ansible_vault_applied_hash','fixture')",
             "DELETE FROM settings WHERE key='ansible_vault_applied_hash'", 'données sensibles'),
            ("INSERT INTO settings(key,value) VALUES('dhcp_mode','foreign')",
             "DELETE FROM settings WHERE key='dhcp_mode'", 'mode réseau non reconnu'),
        ]
        for insert, cleanup, reason in refusal_cases:
            with closing(sqlite3.connect(database)) as db, db:
                db.execute(insert)
            original = database.read_bytes()
            refused = subprocess.run(command, capture_output=True, text=True)
            assert refused.returncode and reason in refused.stderr, refused.stderr
            assert database.read_bytes() == original
            with closing(sqlite3.connect(database)) as db, db:
                db.execute(cleanup)
        subprocess.run(command, check=True, capture_output=True)
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute('SELECT local_boot_source,root_password_cipher FROM machines ORDER BY id').fetchall()==[
                ('pxe','opaque'),('none',None),
            ]
            assert db.execute("SELECT name FROM sqlite_schema WHERE name='idx_installations_action'").fetchone()
            assert db.execute("SELECT name FROM sqlite_schema WHERE name='boot_sessions'").fetchone()
            assert db.execute('SELECT root_login_mode FROM presets').fetchone()==('enabled',)
            db.execute("UPDATE machines SET local_boot_source='manual' WHERE id=10")
        subprocess.run(command, check=True, capture_output=True)
        with closing(sqlite3.connect(database)) as db, db:
            assert db.execute("SELECT local_boot_source FROM machines WHERE id=10").fetchone()==('manual',)
    print('Rust schema upgrade preserved historical defaults, encrypted bytes and explicit boot choices', flush=True)


def verify_preset_network_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-presets-migration-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--migrate-preset-network',str(config)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.executemany(
                'INSERT INTO presets(name,distro,admin_user_login,static_netmask,static_cidr,static_dns) '
                "VALUES(?,'debian','fixture',?,?,?)",
                [
                    ('legacy',' 255.255.254.0 ',None,'192.0.2.53, 2001:db8::53'),
                    ('explicit','255.255.0.0',24,'[ "192.0.2.54" ]'),
                    ('invalid-mask','255.0.255.0',None,None),
                    ('unset',None,None,None),
                ],
            )
        for _ in range(2):
            subprocess.run(command, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('SELECT static_cidr,static_dns FROM presets ORDER BY id').fetchall()==[
                    (23,'["192.0.2.53","2001:db8::53"]'),
                    (24,'[ "192.0.2.54" ]'),
                    (None,None),
                    (None,None),
                ]
    print('Rust migrated legacy preset network values and preserved explicit settings', flush=True)


def verify_preset_distribution_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-preset-distributions-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--migrate-preset-distributions',str(config)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.execute("INSERT INTO catalog_entries(distro,codename,version_full,arch) VALUES('ubuntu','Noble','24.04','amd64')")
            db.executemany(
                "INSERT INTO presets(name,distro,codename,admin_user_login) VALUES(?,?,?,'fixture')",
                [
                    ('legacy-debian',' Trixie ',None),
                    ('legacy-ubuntu','NOBLE',None),
                    ('explicit','debian','bookworm'),
                    ('known-distro','fedora',None),
                    ('unknown-alias','other',None),
                ],
            )
        for _ in range(2):
            subprocess.run(command, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('SELECT distro,codename FROM presets ORDER BY id').fetchall()==[
                    ('debian','trixie'),('ubuntu','noble'),('debian','bookworm'),
                    ('fedora',None),('debian','other'),
                ]
    print('Rust migrated historical preset aliases and kept explicit distributions', flush=True)


def verify_image_metadata_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-image-metadata-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--migrate-image-metadata',str(config)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.executemany(
                'INSERT INTO os_images(distro,version,minor_version,codename,major,channel,version_full) VALUES(?,?,?,?,?,?,?)',
                [
                    ('debian','trixie','13.4.0',None,None,None,None),
                    ('debian','forky',None,None,None,'explicit',None),
                    ('debian','bookworm','12.13.0','preserved',12,None,'12.14.0'),
                    ('ubuntu','noble','24.04',None,None,None,None),
                ],
            )
        for _ in range(2):
            subprocess.run(command, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('SELECT codename,major,channel,version_full FROM os_images ORDER BY id').fetchall()==[
                    ('trixie',13,'stable','13.4.0'),('forky',14,'explicit',None),
                    ('preserved',12,'oldstable','12.14.0'),(None,None,None,None),
                ]
    print('Rust migrated Debian catalog metadata and preserved explicitly selected releases', flush=True)


def verify_assigned_preset_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-preset-snapshots-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        app = Path(__file__).resolve().parents[2]/'app'
        command = [str(binary),'--migrate-assigned-presets',str(config)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript((app/'db/schema.sqlite.sql').read_text())
            layout = json.dumps({
                'target_disks':[' /dev/sda ','/dev/sda'],
                'target_disk_identities':{'/dev/sda':{'serial':'old-inventory'}},
                'disks':[{'path':'/dev/sda','partitions':[{
                    'id':' p1 ','fs':'lvm','fill':True,'reserved_pct':57,'mount_options':['noatime',' '],
                }]}],
                'vgs':[{'name':'vg0','pvs':['p1']}],
                'logical_volumes':[{'vg':'vg0','name':'root','fs':'ext4','size_mb':'2e3','mount':'/'}],
            })
            advanced = json.dumps({
                'network':{'interfaces':[
                    {'mode':'dhcp'},
                    {'match_by':'mac','match':{'mac':' 02:00:00:AB:00:01 '},'index':2,
                     'mode':'static','static':{'ip':'192.0.2.3','dns':'192.0.2.53, 2001:db8::53'},
                     'vlan':{'id':'42'},'bond':{'role':'slave','name':' bond0 '}},
                ],'primary':4},
                'localization':{'locale':'en_US.UTF-8','keymap':None},
                'apt':{'non_free':True,'unknown':'ignored'},
                'disk_target_constraints':{'/dev/sda':'fixture-serial'},
            })
            db.execute("""INSERT INTO presets(id,name,distro,admin_user_login)
                          VALUES(1,'default','debian','fixture')""")
            db.execute("""INSERT INTO presets(id,name,distro,admin_user_login,static_dns,partition_mode,
                           partition_custom_json,advanced_config_json,admin_user_password_cipher,
                           ansible_role,root_login_mode,hostname_random)
                          VALUES(2,'advanced','debian','fixture','192.0.2.54','custom',?,?,'opaque',
                                 'fixture-role','disabled',1)""", (layout,advanced))
            db.executemany(
                'INSERT INTO machines(id,mac,preset_id,install_config_json) VALUES(?,?,?,?)',
                [
                    (101,'02:00:00:00:00:01',1,None),
                    (102,'02:00:00:00:00:02',2,''),
                    (103,'02:00:00:00:00:03',2,'{"keep":true}'),
                    (104,'02:00:00:00:00:04',None,None),
                ],
            )
        reference = r'''
require $argv[1] . '/src/Models/Preset.php';
require $argv[1] . '/src/Util/DiskIdentity.php';
$presets = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
echo json_encode(array_map([Admin\Models\Preset::class, 'toInstallConfig'], $presets), JSON_THROW_ON_ERROR);
'''
        with closing(sqlite3.connect(database)) as db:
            db.row_factory = sqlite3.Row
            presets = [dict(row) for row in db.execute('SELECT * FROM presets ORDER BY id')]
        expected = json.loads(subprocess.check_output(
            ['php','-r',reference,str(app)], input=json.dumps(presets), text=True,
        ))
        for _ in range(2):
            subprocess.run(command, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                records = [item[0] for item in db.execute('SELECT install_config_json FROM machines ORDER BY id')]
            actual = [json.loads(item) for item in records[:2]]
            for values in (expected,actual):
                if isinstance(values[1]['partition_custom_json'],str):
                    values[1]['partition_custom_json'] = json.loads(values[1]['partition_custom_json'])
            assert actual==expected
            assert records[2:]==['{"keep":true}',None]
            assert 'target_disk_identities' not in actual[1]['partition_custom_json']
    print('Rust restored assigned preset snapshots with PHP parity and preserved existing machine snapshots', flush=True)


def verify_legacy_netboot_migration(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-netboot-migration-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        http = root/'http'
        netboot = http/'netboot'
        legacy = netboot/'trixie'
        installed = legacy/'amd64'
        installed.mkdir(parents=True)
        (legacy/'linux').write_bytes(b'local kernel')
        (legacy/'firmware.cpio.gz').write_bytes(b'firmware')
        (installed/'initrd.gz').write_bytes(b'initrd already moved')
        outside = root/'outside'
        (outside/'amd64').mkdir(parents=True)
        (outside/'amd64/linux').write_bytes(b'external data')
        (netboot/'other').symlink_to(outside, target_is_directory=True)
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        command = [str(binary),'--migrate-sqlite',str(config),str(http)]
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.executemany("INSERT INTO os_images(distro,version,arch,enabled) VALUES('debian',?,?,1)",
                           [('trixie','arm64'),('trixie','amd64'),('other','amd64')])
        for _ in range(2):
            subprocess.run(command, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute('PRAGMA journal_mode').fetchone()==('wal',)
                assert db.execute('SELECT status,size_bytes FROM os_images ORDER BY id').fetchall()==[
                    ('pending',None),('downloaded',len(b'local kernelfirmwareinitrd already moved')),('pending',None),
                ]
        assert (installed/'linux').read_bytes()==b'local kernel' and not (legacy/'linux').exists()
        assert (installed/'initrd.gz').read_bytes()==b'initrd already moved'
        assert (outside/'amd64/linux').read_bytes()==b'external data'
        assert not (legacy/'arm64').exists()
    print('Rust resumed a legacy image move and kept external paths and other architectures untouched', flush=True)


def verify_catalog_refresh(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-catalog-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        fetch = root/'curl'
        fetch.write_text('''#!/usr/bin/env python3
import sys
from hashlib import sha256
url = sys.argv[-1]
if url.endswith('/trixie/Release'):
    print('Version: 13.8')
elif url.endswith('/cdimage/archive/'):
    print('<a href="13.8.0/"> <a href="13.5.0/"> <a href="13.5.0/"> <a href="13.7.0-live/">')
elif url == 'https://releases.ubuntu.com/24.04/':
    print('ubuntu-24.04.6-live-server-amd64.iso')
elif url.endswith('/current/images/SHA256SUMS'):
    print(sha256(b'verified replacement').hexdigest(), './netboot/debian-installer/amd64/initrd.gz')
else:
    sys.exit(22)
''')
        fetch.chmod(0o700)
        http = root/'http'
        image = http/'netboot/debian/13.8.0/amd64'
        image.mkdir(parents=True)
        (image/'linux').write_bytes(b'published kernel')
        (image/'initrd.gz').write_bytes(b'outdated initramfs')
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        initrd = ('https://deb.debian.org/debian/dists/trixie/main/installer-amd64/current/'
                  'images/netboot/debian-installer/amd64/initrd.gz')
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.execute("INSERT INTO init_jobs(id,job_type,status) VALUES(7,'bootstrap:refresh_catalog_v2','running')")
            db.execute("""INSERT INTO os_images(distro,version,arch,version_full,status,initrd_url)
                          VALUES('debian','trixie','amd64','13.8.0','downloaded',?)""",(initrd,))
        env = {**os.environ,'HTTP_ROOT':str(http),'PATH':str(root)+os.pathsep+os.environ['PATH'],'WORKER_JOB_ID':'7'}
        for _ in range(2):
            subprocess.run([str(binary),'--refresh-catalog',str(config)], env=env, check=True, capture_output=True)
            with closing(sqlite3.connect(database)) as db:
                assert db.execute("""SELECT version_full,extract_method FROM catalog_entries
                                     WHERE distro='debian' AND codename='trixie' AND arch='amd64'
                                     ORDER BY version_full""").fetchall()==[('13.5.0','iso_extract'),('13.8.0','direct')]
                assert db.execute("""SELECT iso_url FROM catalog_entries
                                     WHERE distro='ubuntu' AND version_full='24.04.6' AND arch='arm64'""").fetchone()==(
                    'https://cdimage.ubuntu.com/releases/24.04/release/ubuntu-24.04.6-live-server-arm64.iso',
                )
                assert db.execute("SELECT COUNT(DISTINCT distro) FROM catalog_entries").fetchone()==(6,)
                assert db.execute("SELECT status FROM os_images").fetchone()==('pending',)
                assert db.execute("SELECT progress_percent FROM init_jobs WHERE id=7").fetchone()==(100,)
        assert (image/'linux').read_bytes()==b'published kernel'
        assert (image/'initrd.gz').read_bytes()==b'outdated initramfs'
    print('Rust refreshed the six catalogs and queued an authenticated replacement while keeping published files', flush=True)


def verify_preset_import(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-preset-import-') as temporary:
        root = Path(temporary).resolve()
        database = root/'fixture.sqlite'
        config = root/'db.conf'
        config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
        schema = Path(__file__).resolve().parents[2]/'app/db/schema.sqlite.sql'
        boot = {'id':'boot','fs':'ext4','mount':'/boot','size_mb':512}
        system = {'id':'root','fs':'ext4','mount':'/','size_mb':4000}
        profile = {
            'name':'Profil Café','distro':'debian','codename':'trixie',
            'root_login_mode':'enabled','admin_user_login':'fixture','partition_mode':'custom',
            'partition_custom_json':{'target_disks':['/dev/sda'],'disks':[{'path':'/dev/sda','partitions':[boot,system]}]},
            'based_on_machine_id':19,'ansible_role':'debian_test',
            'advanced_config_json':{
                'timezone':{'zone':'Europe/Paris','ntp_server':'ntp.example.test'},
                'network':{'primary':0,'interfaces':[
                    {'match_by':'mac','match':{'mac':'02:00:00:01:00:01'},'mode':'dhcp'},
                    {'match_by':'mac','match':{'mac':'02:00:00:01:00:02'},'mode':'static',
                     'static':{'ip':'192.0.2.20','cidr':24,'gateway':'192.0.2.1','dns':['192.0.2.53']},'vlan':{'id':42}},
                ]},
                'disk_target_constraints':{'/dev/sda':'fixture-serial'},
            },
        }
        with closing(sqlite3.connect(database)) as db, db:
            db.executescript(schema.read_text())
            db.execute("INSERT INTO settings(key,value) VALUES('ansible_repo_profile','profile.json')")
            db.execute("INSERT INTO machines(id,mac,inventory_json) VALUES(19,'02:00:00:01:00:01',?)",
                       (json.dumps({'disks':[{'name':'sda','size_bytes':8000000000}],
                                    'interfaces':[{'mac':'02:00:00:01:00:01'},{'mac':'02:00:00:01:00:02'}]}),))

        def ingest(row, roles=('debian_test',), repository='profile.json'):
            return subprocess.run(
                [str(binary),'--import-preset',str(config)],
                input=json.dumps({'preset':row,'allowed_roles':roles,'repository_profile':repository}),
                text=True,capture_output=True,
            )

        assert ingest(profile,[]).returncode
        assert ingest(profile,repository='stale.json').returncode
        added = ingest(profile)
        assert added.returncode==0, added.stderr
        identity = json.loads(added.stdout)
        assert identity['action']=='created' and identity['name']=='Profil Café'
        assert json.loads(ingest(profile).stdout)['action']=='unchanged'
        previous = {key:value for key,value in profile.items() if key!='root_login_mode'}
        updated = ingest({**previous,'description':'Description'})
        assert json.loads(updated.stdout)['action']=='updated'
        broken = json.loads(json.dumps(profile))
        broken['advanced_config_json']['network']['interfaces'][1]['static']['gateway'] = '198.51.100.1'
        assert ingest(broken).returncode
        broken = json.loads(json.dumps(profile))
        broken['partition_custom_json']['disks'][0]['partitions'][1]['size_mb'] = 9000
        assert ingest(broken).returncode
        assert ingest({**profile,'variant':'proxmox-ve'}).returncode
        assert ingest({**profile,'root_login_mode':'disabled'}).returncode
        with closing(sqlite3.connect(database)) as db:
            assert db.execute('SELECT id,name,description,root_login_mode FROM presets').fetchall()==[
                (identity['id'],'Profil Café','Description','enabled'),
            ]
    print('Rust imports, updates and validates repository presets with persisted identity and reference hardware', flush=True)


def verify_ansible_settings(client, database, authorization, key, vault, workdir):
    def request(path='/settings/ansible', **kwargs):
        return client.request(path, authorization=authorization, **kwargs)

    assert client.request('/settings/ansible')[0] == 401
    assert request(secure=False)[0] == 404
    assert request('/settings/ansible/vault-unlock')[0] == 405
    assert b'Module Ansible' in request()[2]
    form = {
        'ansible_enabled':'on','repo_url':'git@example.test:team/provisioning.git',
        'repo_branch':'release/next','repo_profile':'pxe/profile.json',
        'playbooks_dir':str(workdir),'target_user':'fixture_ops',
        'ssh_pubkey':'ssh-ed25519 QUJDRA== Fixture clé publique',
        'github_push_user':'fixture-bot','github_push_token':'fixture-only-token',
    }
    assert request(form=form,origin='https://outside.example')[0] == 403
    for invalid in ({'repo_branch':'main.lock'}, {'repo_profile':'.git/private.json'},
                    {'repo_url':'file:///tmp/repo.git'}, {'target_user':'root'},
                    {'playbooks_dir':'relative'}, {'ssh_pubkey':'private-key'},
                    {'ssh_privkey':'fixture-private-key'}):
        assert request(form={**form,**invalid})[0] == 422
    with closing(sqlite3.connect(database)) as db:
        assert db.execute("SELECT value FROM settings WHERE key='github_push_token'").fetchone() is None
    assert request(form=form)[:2] == (303,'/settings/ansible')
    page = request()[2]
    assert b'fixture_ops' in page and b'pxe/profile.json' in page
    assert b'fixture-only-token' not in page
    with closing(sqlite3.connect(database)) as db, db:
        secret, = db.execute("SELECT value FROM settings WHERE key='github_push_token'").fetchone()
        assert secret != form['github_push_token'] and len(base64.b64decode(secret)) > 40
        db.execute("""CREATE TRIGGER fixture_ansible_atomic BEFORE UPDATE ON settings
                      WHEN NEW.key='ansible_target_user' BEGIN SELECT RAISE(ABORT,'fixture'); END""")
    app = Path(__file__).resolve().parents[2]/'app/src/Util/Crypto.php'
    opened = subprocess.check_output([
        'php','-r','require $argv[1]; echo Admin\\Util\\Crypto::decrypt(stream_get_contents(STDIN));',str(app),
    ], input=secret, text=True, env={**os.environ,'PXE_MASTER_KEY_PATH':str(key)})
    assert opened == form['github_push_token']
    assert request(form={**form,'repo_branch':'different','github_push_token':'fixture-rollback'})[0] == 503
    with closing(sqlite3.connect(database)) as db, db:
        assert db.execute("SELECT value FROM settings WHERE key='github_push_token'").fetchone() == (secret,)
        assert db.execute("SELECT value FROM settings WHERE key='ansible_repo_branch'").fetchone() == ('release/next',)
        db.execute('DROP TRIGGER fixture_ansible_atomic')
    marker = workdir/'.git/info/sparse-checkout'
    marker.parent.mkdir(parents=True)
    marker.touch()
    assert request(form={**form,'repo_profile':''})[0] == 422
    vault_route = '/settings/ansible/vault-unlock'
    assert request(vault_route,form={'vault_password':'x'*1025})[0] == 422
    assert request(vault_route,form={'vault_password':'isolated-vault-fixture'})[:2] == (303,'/settings/ansible')
    pending = vault/'unlock'
    assert pending.stat().st_mode & 0o777 == 0o600
    assert pending.read_bytes() == b'isolated-vault-fixture'
    assert b'isolated-vault-fixture' not in request()[2]
    assert request(vault_route,form={'vault_password':'replacement-fixture'})[0] == 303
    assert pending.read_bytes() == b'replacement-fixture' and list(vault.iterdir()) == [pending]
    assert request(form={**form,'github_push_token_clear':'1'})[0] == 303
    verify_ansible_webhook(client, database, authorization, workdir)
    assert request(form={})[0] == 303
    with closing(sqlite3.connect(database)) as db:
        values = dict(db.execute("SELECT key,value FROM settings WHERE key LIKE 'ansible_%' OR key='github_push_token'"))
        assert values['ansible_enabled'] == 'off' and values['github_push_token'] == ''
        assert values['ansible_repo_profile'] == 'pxe/profile.json'
    print('Rust Ansible settings preserve scoped repositories and PHP secret format, and stage Vault unlocks privately',
          flush=True)


def verify_ansible_webhook(client, database, authorization, workdir):
    route = '/api/ansible-repo/webhook'
    (workdir/'inventory.ini').write_text('[fixture]\nwebhook-ready\nwebhook-busy\nwebhook-optout\n')
    (workdir/'playbooks').mkdir()
    (workdir/'playbooks/check.yml').write_text('- hosts: fixture\n')
    generated = client.request('/settings/ansible',
                               form={'webhook_action':'regen_secret','webhook_enabled':'on'},
                               authorization=authorization)
    assert generated[0] == 200
    secret = generated[2].split(b'id="webhook-secret">',1)[1].split(b'</code>',1)[0]
    assert len(secret) == 64
    assert secret not in client.request('/settings/ansible',authorization=authorization)[2]
    with closing(sqlite3.connect(database)) as db, db:
        machines = []
        for index, (name, status) in enumerate([
            ('webhook-ready','installed'),('webhook-busy','testing'),('webhook-optout','installed'),
        ]):
            machines.append(db.execute(
                'INSERT INTO machines(mac,hostname,status,install_config_json) VALUES (?,?,?,?)',
                [f'02:00:00:00:09:{80+index}',name,status,json.dumps({'ansible_role':'check'})],
            ).lastrowid)
    ready, busy, optout = machines
    for machine in machines:
        enable = f'/machines/{machine}/auto-deploy'
        assert client.request(enable,form={'auto_deploy':'1'})[0] == 401
        response = client.request(enable,form={'auto_deploy':'1'},authorization=authorization)
        assert response[0] == 303, response
    assert client.request(f'/machines/{optout}/auto-deploy',form={},authorization=authorization)[0] == 303
    body = json.dumps({'commits':[{'modified':['playbooks/check.yml','playbooks/check.yml']}],
                       'head_commit':{'id':'ab01234aaaaa'}}).encode()

    def delivery(event, data=body, signature=None, **kwargs):
        signature = signature if signature is not None else 'sha256='+hmac.digest(secret,data,'sha256').hex()
        return client.request(route, raw_body=data, extra_headers={
            'x-github-event':event,'x-hub-signature-256':signature,
        }, **kwargs)

    assert delivery('push',secure=False)[0] == 404
    assert delivery('push',data=b'bad json',signature='sha256='+'0'*64)[0] == 401
    assert delivery('push',data=b'bad json')[0] == 400
    assert json.loads(delivery('ping')[2]) == {'pong':True}
    first = delivery('push')
    assert first[0] == 202, first
    assert json.loads(first[2]) == {
        'commit':'ab01234','files':1,'impacted':3,
        'triggered':['webhook-ready'],'skipped':[{'hostname':'webhook-busy','reason':'machine_busy'}],
    }
    repeat = json.loads(delivery('push')[2])
    assert repeat['triggered'] == [] and repeat['skipped'][0] == {
        'hostname':'webhook-ready','reason':'already_pending',
    }
    with closing(sqlite3.connect(database)) as db:
        rows = db.execute("SELECT job_type,status FROM init_jobs WHERE job_type IN (?,?,?)",
                          [f'machine:ansible_redeploy:{machine}' for machine in machines]).fetchall()
        assert rows == [(f'machine:ansible_redeploy:{ready}','pending')]
    assert client.request('/settings/ansible',form={},authorization=authorization)[0] == 303
    assert delivery('push')[0] == 503
    print('Rust webhook verifies GitHub HMAC, scopes deployment, honors opt-in and refuses duplicate jobs',
          flush=True)


def local(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-setup-') as temp, ExitStack() as stack:
        root = Path(temp).resolve()
        data, credentials, public, conf = (root/name for name in ('data','credentials','public','conf'))
        for path in (data, credentials, public, conf):
            path.mkdir()
        sessions = root/'sessions'
        sessions.mkdir(mode=0o700)
        (conf/'master.key').write_bytes(secrets.token_bytes(32))
        (conf/'master.key').chmod(0o600)
        (credentials/'setup-code').write_text(secrets.token_hex(24)+'\n')
        generate_tls_pair(credentials, 'localhost')
        with ExitStack() as reservations:
            ports = []
            for _ in range(2):
                sock = reservations.enter_context(socket.socket())
                sock.bind(('127.0.0.1', 0))
                ports.append(sock.getsockname()[1])
        database = data/'pxe-tools.sqlite'
        config = conf/'db.conf'
        client = Client(credentials, *ports)
        env = {**os.environ, 'AUTH_MODE':'local', 'CREDENTIALS_DIRECTORY':str(credentials),
               'HTTP_ROOT':str(public), 'PXE_DB_DRIVER':'sqlite', 'PXE_DB_PATH':str(database),
               'PXE_SETUP_DATA_ROOT':str(data), 'PXE_HTTP_PORT':str(ports[0]),
               'PXE_HTTPS_PORT':str(ports[1]), 'PXE_PUBLIC_HOST':'pxe.example.test',
               'PXE_TLS_IMPORT_DIR':str(root/'tls-import'), 'PXE_SESSION_DIR':str(sessions),
               'PXE_MASTER_KEY_PATH':str(conf/'master.key'), 'PXE_VAULT_UNLOCK_DIR':str(root/'vault'),
               'ANSIBLE_WORKDIR':str(root/'playbooks'), 'PXE_ANSIBLE_HOME':str(root/'ansible-home')}
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('CREATE TABLE existing(data TEXT)')
            db.execute("INSERT INTO existing VALUES ('preserve')")
        original = database.read_bytes()
        server = stack.enter_context(subprocess.Popen([str(binary), '--serve-guided', str(config)], env=env))
        stack.callback(server.terminate)
        client.ready(server)
        code = (credentials/'setup-code').read_text().strip()
        assert client.request('/init/db', form={'code': code})[0] == 503
        assert not config.exists() and database.read_bytes() == original
        database.unlink()
        authorization = setup(client, credentials, config, database)
        verify_browser_login(client, database, authorization, first_run=True)
        verify_configuration(client, database, authorization, packaged=False)
        verify_browser_login(client, database, authorization)
        imported = root/'imported'
        imported.mkdir()
        updated = verify_tls_import(client, credentials, imported, root/'tls-import', authorization)
        server.terminate()
        server.wait(timeout=5)
        replacement = stack.enter_context(subprocess.Popen([str(binary), '--serve-guided', str(config)], env=env))
        stack.callback(replacement.terminate)
        updated.ready(replacement)
        assert b'Certificat externe' in updated.request('/admin/certificates', authorization=authorization)[2]
        print('The imported TLS pair survived a restart', flush=True)
        verify_image_console(updated, database, authorization)
        verify_job_console(updated, database, authorization)
        verify_activity(updated, database, authorization)
        replacement.terminate()
        replacement.wait(timeout=5)
        schedule_server = stack.enter_context(subprocess.Popen([str(binary), '--serve-guided', str(config)], env=env))
        stack.callback(schedule_server.terminate)
        updated.ready(schedule_server)
        verify_device_settings(updated, database, authorization)
        verify_guided_install(updated, database, authorization)
        verify_custom_partition_review(updated, database, authorization)
        verify_disk_diagnostics(updated, database, authorization)
        verify_disk_wipe(updated, database, authorization)
        verify_device_operations(updated, database, authorization)
        verify_device_ansible(updated, database, authorization)
        verify_hardware_context(updated, database, authorization)
        verify_appliance_settings(updated, database, authorization)
        verify_ansible_settings(updated, database, authorization, conf/'master.key', root/'vault', root/'playbooks')
        verify_admin_attempt_limit(updated, authorization)
        schedule_server.terminate()
        schedule_server.wait(timeout=5)
        verify_authentik_proxy([str(binary),'--serve-guided',str(config)],updated,env,database,authorization)
    verify_worker_commands(binary)
    verify_worker_bootstrap(binary)
    verify_worker_download(binary)
    verify_worker_recovery(binary)
    verify_schema_migration(binary)
    verify_preset_network_migration(binary)
    verify_preset_distribution_migration(binary)
    verify_image_metadata_migration(binary)
    verify_assigned_preset_migration(binary)
    verify_legacy_netboot_migration(binary)
    verify_catalog_refresh(binary)
    verify_preset_import(binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--http-root', type=Path)
    parser.add_argument('--netboot-fixture', type=Path)
    parser.add_argument('--tftp-root', type=Path)
    parser.add_argument('--dnsmasq-config', type=Path)
    parser.add_argument('--installed', action='store_true',
                        help='verify a newly installed test appliance in an isolated namespace')
    args = parser.parse_args()
    if args.installed:
        if os.geteuid() != 0 or os.environ.get('PXE_DISPOSABLE_SETUP_TEST') != '1':
            raise SystemExit('Run the packaged check only in its disposable fixture')
        credentials = Path('/run/pxe-tools-rust-guided')
        deadline = time.monotonic() + 40
        while not (credentials/'setup-code').is_file():
            if time.monotonic() >= deadline:
                raise RuntimeError('The appliance did not prepare the first-run credentials')
            time.sleep(.2)
        client = Client(credentials, 80, 443)
        client.ready()
        database = Path('/var/lib/pxe-tools/pxe-tools.sqlite')
        authorization = setup(client, credentials, Path('/etc/pxe-tools/db.conf'), database)
        verify_browser_login(client, database, authorization, first_run=True)
        if args.http_root:
            verify_worker_image_delete(database, args.http_root)
        boot_fixture = (args.http_root, args.tftp_root, args.netboot_fixture, args.dnsmasq_config)
        if args.netboot_fixture and not all(boot_fixture):
            parser.error('The activation probe requires the HTTP, TFTP and dnsmasq paths.')
        verify_configuration(client, database, authorization, packaged=True,
                             boot_fixture=boot_fixture if args.netboot_fixture else None)
        with tempfile.TemporaryDirectory(prefix='pxe-tls-test-') as temporary:
            verify_tls_import(client, credentials, Path(temporary),
                              database.parent/'tls-import', authorization)
    else:
        binary = args.binary or Path(__file__).resolve().parents[2]/'rust/target/release/pxe-tools-rust'
        local(binary.resolve())


if __name__ == '__main__':
    main()
