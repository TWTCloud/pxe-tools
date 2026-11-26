# SPDX-License-Identifier: LGPL-3.0-only
"""A loopback-only ACME fixture for the packaged console integration suite."""

import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import secrets
import ssl
import subprocess
import threading


def decode_jose(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def generate_authority_endpoint(directory):
    options = {'cwd':directory, 'check':True, 'stdout':subprocess.DEVNULL, 'stderr':subprocess.DEVNULL}
    subprocess.run([
        'openssl','req','-x509','-nodes','-newkey','rsa:2048','-days','1',
        '-subj','/CN=fixture-ca','-keyout','ca.key','-out','ca.pem',
        '-addext','basicConstraints=critical,CA:TRUE',
        '-addext','keyUsage=critical,keyCertSign,cRLSign',
        '-addext','subjectKeyIdentifier=hash',
    ], **options)
    subprocess.run([
        'openssl','req','-new','-nodes','-newkey','rsa:2048',
        '-subj','/CN=fixture-acme-endpoint','-keyout','key.pem','-out','endpoint.csr',
    ], **options)
    (directory/'endpoint.ext').write_text('basicConstraints=critical,CA:FALSE\n'
                                          'extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n'
                                          'authorityKeyIdentifier=keyid:always\n')
    subprocess.run([
        'openssl','x509','-req','-in','endpoint.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial',
        '-days','1','-extfile','endpoint.ext','-out','cert.pem',
    ], **options)


@contextmanager
def authority(directory, challenge_port, host):
    directory.mkdir()
    generate_authority_endpoint(directory)
    ca_pem = directory / 'ca.pem'
    (directory / 'index').touch()
    (directory / 'serial').write_text('01\n')
    (directory / 'sign.cnf').write_text(
        '[ca]\ndefault_ca=fixture\n[fixture]\n'
        'database=index\nserial=serial\nnew_certs_dir=.\ncertificate=ca.pem\nprivate_key=ca.key\n'
        'default_md=sha256\npolicy=subject\ncopy_extensions=copy\nunique_subject=no\n'
        '[subject]\ncommonName=optional\n'
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')
    identifier = {'type': 'dns', 'value': host}
    orders = []
    accounts = []

    def sign_csr(csr, order_id):
        csr_path = directory / f'{order_id}.csr'
        csr_path.write_bytes(
            b'-----BEGIN CERTIFICATE REQUEST-----\n'
            + base64.encodebytes(csr)
            + b'-----END CERTIFICATE REQUEST-----\n'
        )
        now = datetime.now(timezone.utc)
        date = '%Y%m%d%H%M%SZ'
        command = [
            'openssl', 'ca', '-config', 'sign.cnf', '-batch', '-notext',
            '-in', csr_path.name,
            '-startdate', (now - timedelta(seconds=1)).strftime(date),
            '-enddate', (now + timedelta(seconds=15)).strftime(date),
        ]
        return subprocess.check_output(command, cwd=directory, stderr=subprocess.PIPE)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, body=None, *, status=200, path=None):
            if isinstance(body, bytes):
                content_type = 'application/pem-certificate-chain'
            else:
                content_type = 'application/json'
                body = b'' if body is None else json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Replay-Nonce', secrets.token_urlsafe(16))
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            if path is not None:
                self.send_header('Location', base + path)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_HEAD(self):
            assert self.path == '/nonce'
            self.reply()

        def do_GET(self):
            assert self.path == '/directory'
            self.reply({'newNonce': base + '/nonce', 'newAccount': base + '/account',
                        'newOrder': base + '/orders', 'revokeCert': base + '/revoke',
                        'keyChange': base + '/key-change'})

        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            payload = json.loads(decode_jose(message['payload'])) if message['payload'] else None
            if self.path == '/account':
                accounts.append(payload)
                self.reply({'status': 'valid'}, status=201, path='/account/1')
                return
            if self.path == '/orders':
                assert payload['identifiers'] == [identifier]
                order_id = len(orders) + 1
                orders.append({'status': 'pending', 'certificate': None})
            else:
                path, order_id = self.path[1:].split('/')
                order_id = int(order_id)
            order = orders[order_id - 1]
            token = f'http01-fixture-{order_id}'
            challenge = {'type': 'http-01', 'token': token, 'status': 'pending',
                         'url': base + f'/challenge/{order_id}'}
            if self.path != '/orders' and path == 'authorize':
                self.reply({'identifier': identifier, 'status': 'pending', 'challenges': [challenge]})
                return
            if self.path != '/orders' and path == 'challenge':
                challenge_client = HTTPConnection('127.0.0.1', challenge_port, timeout=3)
                try:
                    challenge_client.request('GET', '/.well-known/acme-challenge/' + token, headers={'Host': host})
                    response = challenge_client.getresponse()
                    assert response.status == 200 and response.read().startswith((token + '.').encode())
                finally:
                    challenge_client.close()
                order['status'] = 'ready'
                self.reply({**challenge, 'status': 'valid'})
                return
            if self.path != '/orders' and path == 'finalize':
                assert order['status'] == 'ready'
                order['certificate'] = sign_csr(decode_jose(payload['csr']), order_id)
                order['status'] = 'valid'
            if self.path != '/orders' and path == 'certificate':
                self.reply(order['certificate'])
                return
            description = {'status': order['status'], 'authorizations': [base + f'/authorize/{order_id}'],
                           'finalize': base + f'/finalize/{order_id}'}
            if order['certificate']:
                description['certificate'] = base + f'/certificate/{order_id}'
            self.reply(description, status=201 if self.path == '/orders' else 200, path=f'/order/{order_id}')

    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        base = f'https://127.0.0.1:{server.server_port}'
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield base + '/directory', ca_pem, accounts
        finally:
            server.shutdown()
            thread.join(timeout=5)
