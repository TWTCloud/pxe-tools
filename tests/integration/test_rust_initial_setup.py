#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise Rust setup over TLS on a temporary SQLite instance or a disposable appliance."""
import argparse
import base64
from hashlib import sha256
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

    def request(self, path, *, form=None, authorization=None, secure=True, origin=None):
        if secure:
            conn = HTTPSConnection('127.0.0.1', self.https_port, timeout=5, context=self.context)
        else:
            conn = HTTPConnection('127.0.0.1', self.http_port, timeout=5)
        try:
            headers = {}
            if authorization:
                headers['Authorization'] = 'Basic ' + base64.b64encode(authorization.encode()).decode()
            if form is not None:
                headers['Origin'] = origin or self.origin
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            conn.request('GET' if form is None else 'POST', path,
                         body=None if form is None else urlencode(form), headers=headers)
            response = conn.getresponse()
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


def verify_guided_install(client, database, authorization):
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
    assert client.request(end, form={**form,'disk':'/dev/vda:STALE'}, authorization=authorization)[0] == 409
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
    print('Rust guided scheduling rejected stale identity and replay, and atomically queued the selected install', flush=True)


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


def local(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-setup-') as temp, ExitStack() as stack:
        root = Path(temp).resolve()
        data, credentials, public, conf = (root/name for name in ('data','credentials','public','conf'))
        for path in (data, credentials, public, conf):
            path.mkdir()
        (conf/'master.key').write_bytes(secrets.token_bytes(32))
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
               'PXE_TLS_IMPORT_DIR':str(root/'tls-import')}
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
        verify_configuration(client, database, authorization, packaged=False)
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
        verify_guided_install(updated, database, authorization)
    verify_worker_commands(binary)
    verify_worker_recovery(binary)
    verify_schema_migration(binary)
    verify_preset_network_migration(binary)
    verify_preset_distribution_migration(binary)
    verify_image_metadata_migration(binary)
    verify_assigned_preset_migration(binary)


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
