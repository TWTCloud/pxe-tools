#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise Rust setup over TLS on a temporary SQLite instance or a disposable appliance."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from http.client import HTTPConnection, HTTPSConnection
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


def local(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-rust-setup-') as temp, ExitStack() as stack:
        root = Path(temp).resolve()
        data, credentials, public, conf = (root/name for name in ('data','credentials','public','conf'))
        for path in (data, credentials, public, conf):
            path.mkdir()
        (conf/'master.key').write_bytes(secrets.token_bytes(32))
        (credentials/'setup-code').write_text(secrets.token_hex(24)+'\n')
        subprocess.run(['openssl','req','-x509','-nodes','-newkey','rsa:2048','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1',
                        '-keyout',str(credentials/'key.pem'),'-out',str(credentials/'cert.pem')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
               'PXE_HTTPS_PORT':str(ports[1]), 'PXE_PUBLIC_HOST':'pxe.example.test'}
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
        setup(client, credentials, config, database)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
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
        setup(client, credentials, Path('/etc/pxe-tools/db.conf'), Path('/var/lib/pxe-tools/pxe-tools.sqlite'))
    else:
        binary = args.binary or Path(__file__).resolve().parents[2]/'rust/target/release/pxe-tools-rust'
        local(binary.resolve())


if __name__ == '__main__':
    main()
