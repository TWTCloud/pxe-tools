#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise the Rust HTTP-01 listener against a disposable localhost Pebble CA."""
import argparse
from contextlib import ExitStack
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from urllib.request import urlopen

from test_rust_initial_setup import generate_tls_pair


HOST = 'pxe.example.test'


def start(stack, command, env=None):
    process = stack.enter_context(subprocess.Popen(command, env=env))
    stack.callback(stop, process)
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)


def wait_for(operation, description, seconds=35):
    last = None
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = operation()
            if result:
                return result
        except OSError as error:
            last = error
        time.sleep(.15)
    raise RuntimeError(f'{description} did not become available') from last


def fixture_ports():
    with ExitStack() as reservations:
        ports = []
        for _ in range(6):
            sock = reservations.enter_context(socket.socket())
            sock.bind(('127.0.0.1', 0))
            ports.append(sock.getsockname()[1])
    return ports


def tls_leaf(port, context):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as conn:
        with context.wrap_socket(conn, server_hostname=HOST) as tls:
            return tls.getpeercert(binary_form=True)


def check(binary, pebble, resolver):
    ca_port, admin_port, dns_port, dns_admin, http_port, https_port = fixture_ports()
    with tempfile.TemporaryDirectory(prefix='pxe-rust-acme-') as temporary, ExitStack() as stack:
        root = Path(temporary).resolve()
        ca, default, public = (root/name for name in ('ca','selfsigned','public'))
        for directory in (ca, default, public):
            directory.mkdir()
        generate_tls_pair(ca, 'fixture-pebble-endpoint')
        generate_tls_pair(default, 'fixture-instance')
        start(stack, [resolver, '-dns01', f'127.0.0.1:{dns_port}', '-management', f'127.0.0.1:{dns_admin}',
                      '-http01', '', '-https01', '', '-tlsalpn01', '', '-doh', '', '-defaultIPv6', ''])
        settings = root/'pebble.json'
        settings.write_text(json.dumps({'pebble': {
            'listenAddress':f'127.0.0.1:{ca_port}', 'managementListenAddress':f'127.0.0.1:{admin_port}',
            'certificate':str(ca/'cert.pem'), 'privateKey':str(ca/'key.pem'),
            'httpPort':http_port, 'tlsPort':https_port, 'certificateValidityPeriod':45,
            'retryAfter':{'authz':1, 'order':1},
        }}))
        authority = start(stack, [pebble, '-config', str(settings), '-dnsserver', f'127.0.0.1:{dns_port}'],
                          {**os.environ,'PEBBLE_VA_NOSLEEP':'1','PEBBLE_VA_ALWAYS_VALID':'0',
                           'PEBBLE_WFE_NONCEREJECT':'0','PEBBLE_AUTHZREUSE':'0'})
        ca_context = ssl.create_default_context(cafile=str(ca/'cert.pem'))

        def issuer_root():
            with urlopen(f'https://127.0.0.1:{admin_port}/roots/0', context=ca_context, timeout=2) as response:
                return response.read(64*1024).decode()

        issuer = ssl.create_default_context(cadata=wait_for(issuer_root, 'Pebble CA root'))
        store = root/'private'
        command = [str(binary), '--serve-guided', str(root/'db.conf')]
        env = {**os.environ, 'CREDENTIALS_DIRECTORY':str(default), 'HTTP_ROOT':str(public),
               'PXE_TLS_IMPORT_DIR':str(store), 'PXE_HTTP_PORT':str(http_port), 'PXE_HTTPS_PORT':str(https_port),
               'PXE_PUBLIC_HOST':HOST, 'PXE_ACME':'private',
               'PXE_ACME_DIRECTORY_URL':f'https://127.0.0.1:{ca_port}/dir', 'PXE_ACME_CA_FILE':str(ca/'cert.pem')}
        service = start(stack, command, env)
        first = wait_for(lambda:tls_leaf(https_port,issuer), 'ACME certificate signed by Pebble')
        account = store/'acme-account.json'
        managed = store/'acme-certificate.json'
        assert stat.S_IMODE(store.stat().st_mode)==0o700
        assert stat.S_IMODE(account.stat().st_mode)==stat.S_IMODE(managed.stat().st_mode)==0o600
        first_account = account.read_bytes()

        def renewed():
            leaf = tls_leaf(https_port,issuer)
            return leaf if leaf!=first else None

        second = wait_for(renewed, 'Automatic ACME renewal', seconds=65)
        assert account.read_bytes()==first_account
        print('Pebble completed two real HTTP-01 challenges and Rust hot-reloaded both certificates', flush=True)
        stop(authority)
        stop(service)
        start(stack, command, env)
        assert wait_for(lambda:tls_leaf(https_port,issuer), 'Cached certificate after restart') == second
        conn = HTTPConnection('127.0.0.1', http_port, timeout=5)
        try:
            conn.request('GET','/.well-known/acme-challenge/missing',headers={'Host':HOST})
            assert conn.getresponse().status==404
        finally:
            conn.close()
        print('Rust serves the persisted certificate after restart with the ACME authority offline', flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    parser.add_argument('--binary', type=Path, default=root/'rust/target/release/pxe-tools-rust')
    parser.add_argument('--pebble', default='pebble')
    parser.add_argument('--resolver', default='pebble-challtestsrv')
    args=parser.parse_args()
    check(args.binary.resolve(), args.pebble, args.resolver)


if __name__=='__main__':
    main()
