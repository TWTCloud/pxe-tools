#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise Rust setup over TLS on a temporary SQLite instance or a disposable appliance."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from http.client import HTTPConnection, HTTPSConnection
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import secrets
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


def verify_configuration(client, database, authorization, packaged):
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
            db.execute("""INSERT INTO catalog_entries(id,distro,version_full,arch,extract_method)
                          VALUES(9001,'debian','13.0-fixture','amd64','direct')""")
        assert b'13.0-fixture' in request('/init/images')[2]
        assert request('/init/images', form={'image':'9002'})[0] == 422
        for _ in range(2):
            assert request('/init/images', form={'image':'9001'})[:2] == (303, '/init/done')
        with closing(sqlite3.connect(database)) as db:
            values = dict(db.execute('SELECT key,value FROM settings'))
            assert db.execute("SELECT COUNT(*) FROM os_images WHERE version_full='13.0-fixture'").fetchone() == (1,)
            assert values['pxe_enabled'] == 'off'
        result = request('/init/complete', form={'confirmation':'yes',
                         'plan':values['rust_wizard_network'], 'image':values['rust_wizard_image']})
        assert result[0] == 422 and 'téléchargement' in result[2].decode(), result
        print('Rust wizard validated the interface, queued Debian once, and kept PXE inactive during download', flush=True)

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--http-root', type=Path)
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
        verify_configuration(client, database, authorization, packaged=True)
        with tempfile.TemporaryDirectory(prefix='pxe-tls-test-') as temporary:
            verify_tls_import(client, credentials, Path(temporary),
                              database.parent/'tls-import', authorization)
    else:
        binary = args.binary or Path(__file__).resolve().parents[2]/'rust/target/release/pxe-tools-rust'
        local(binary.resolve())


if __name__ == '__main__':
    main()
