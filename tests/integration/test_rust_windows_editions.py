#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise the Windows and Linux installer menus in an isolated network namespace."""
import base64
from http.client import HTTPConnection, HTTPSConnection
import json
import os
from pathlib import Path
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[2]
SERVER = '192.0.2.1'
WINDOWS_CLIENT = '192.0.2.10'
OTHER_CLIENT = '192.0.2.11'
OUTSIDE_CLIENT = '198.51.100.10'
HTTP = 8088
HTTPS = 8448
SETTINGS = '/settings/windows'
BOOT = '/pxe/windows/boot.ipxe'


def media(root, profile, edition, label, index):
    directory = root/'winpe'/'amd64'/profile
    directory.mkdir(parents=True)
    for name in ('wimboot', 'BCD', 'boot.sdi', 'boot.wim', 'install.wim'):
        (directory/name).write_bytes(f'{profile}:{name}'.encode())
    (directory/'case.json').write_text(json.dumps({
        'edition': edition, 'edition_label': label, 'image_index': index,
        'install_image': 'install.wim', 'install_sha256': 'a'*64,
    }))


def request(path, *, tls=None, source=None, form=None, headers=None):
    if tls:
        connection = HTTPSConnection('127.0.0.1', HTTPS, context=tls, timeout=2)
    else:
        connection = HTTPConnection(SERVER, HTTP, timeout=2, source_address=(source, 0))
    try:
        connection.request('GET' if form is None else 'POST', path,
                           None if form is None else urlencode(form), headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheader('Location'), response.read()
    finally:
        connection.close()


def linux_media(root, db):
    db.executemany("""INSERT INTO os_images(distro,version,version_full,arch,extract_method,enabled,status)
                      VALUES('ubuntu',?,?,?,'iso_extract',?,'downloaded')""", [
        ('24.04.5', '24.04.5', 'amd64', 1),
        ('26.04.1', '26.04.1', 'arm64', 1),
        ('24.04.4', '24.04.4', 'amd64', 0),
        ('22.04.5', '22.04.5', 'amd64', 1),
    ])
    db.execute("""INSERT INTO catalog_entries(distro,version_full,arch,extract_method,iso_url)
                  VALUES ('ubuntu','24.04.5','arm64','iso_extract',
                          'https://cdimage.ubuntu.com/releases/24.04/release/ubuntu-24.04.5-live-server-arm64.iso')""")
    for version, arch in [('24.04.5', 'amd64'), ('26.04.1', 'arm64'),
                          ('24.04.4', 'amd64'), ('22.04.5', 'amd64')]:
        path = root/'netboot'/'ubuntu'/version/arch
        path.mkdir(parents=True)
        for asset in ('linux', 'initrd.gz'):
            (path/asset).write_bytes(b'fixture')
        if version != '22.04.5':
            (path/'source.iso').write_bytes(b'Ubuntu fixture ISO')


def check_linux(tls, auth, form_headers):
    menu = '/pxe/linux/amd64/grub.cfg'
    assert request(menu, source=OUTSIDE_CLIENT)[0] == 403
    assert request('/pxe/linux/i386/grub.cfg', source=WINDOWS_CLIENT)[0] == 404
    status, _, grub = request(menu, source=WINDOWS_CLIENT)
    assert status == 200 and b'Ubuntu Server 24.04.5' in grub
    assert not any(version in grub for version in (b'26.04.1', b'24.04.4', b'22.04.5'))
    assert b'root=/dev/ram0 ip=dhcp cloud-config-url=/dev/null url=http://192.0.2.1:8088/netboot/ubuntu/24.04.5/amd64/source.iso' in grub
    assert b'inst.repo=http://192.0.2.99:8090/rhel/9/' in grub
    assert b'linux (http,192.0.2.99:8090)/rhel/9/images/pxeboot/vmlinuz' in grub
    assert b'autoinstall' not in grub and b'inst.ks=' not in grub
    status, _, ipxe = request('/pxe/linux/arm64/boot.ipxe', source=WINDOWS_CLIENT)
    assert status == 200 and ipxe.startswith(b'#!ipxe') and b'Ubuntu Server 26.04.1' in ipxe
    assert b'24.04.5' not in ipxe and b'Red Hat' not in ipxe
    status, _, iso = request('/netboot/ubuntu/24.04.5/amd64/source.iso', source=WINDOWS_CLIENT,
                             headers={'Range': 'bytes=0-5'})
    assert status == 206 and iso == b'Ubuntu'
    assert b'Ubuntu Server 24.04.5' in request('/settings/images/add', tls=tls, headers=auth)[2]
    assert request('/settings/images', tls=tls, form={'image': '1'}, headers=form_headers)[0] == 303
    print('Ubuntu media selection, architecture-specific menus, ISO streaming and RHEL repository verified.')


def main(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-editions-') as temporary:
        root = Path(temporary)
        public = root/'http'
        media(public, 'windows10-core', 'Core', 'Windows 10 Famille', 1)
        media(public, 'windows11-professional', 'Professional', 'Windows 11 Pro & test', 6)
        database = root/'fixture.sqlite'
        with sqlite3.connect(database) as db:
            db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
            db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [
                ('pxe_enabled', 'on'), ('pxe_ip', SERVER), ('pxe_interface', 'lo'),
                ('pxe_subnet', '192.0.2.0/24'), ('wizard_completed', '1'),
            ])
            db.execute('INSERT INTO users(username,password_hash) VALUES(?,?)', (
                'fixture-admin', '$2y$12$zGZhsSwt3AHDHVbliUPl5eMV46SsqfpLUsIOAcZiq1frkQPqxaEcK',
            ))
            linux_media(public, db)
        config = root/'db.conf'
        config.write_text(json.dumps({'driver': 'sqlite', 'path': str(database)}))
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
            '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        tls = ssl.create_default_context(cafile=str(root/'cert.pem'))
        encoded = base64.b64encode(b'fixture-admin:fixture-login-password').decode()
        auth = {'Authorization': 'Basic ' + encoded}
        form_headers = {**auth, 'Origin': f'https://127.0.0.1:{HTTPS}',
                        'Content-Type': 'application/x-www-form-urlencoded'}
        env = {**os.environ, 'HTTP_ROOT': str(public), 'TLS_DIR': str(root),
               'PXE_HTTP_PORT': str(HTTP), 'PXE_HTTPS_PORT': str(HTTPS),
               'PXE_WINPE_CLIENT_IP': WINDOWS_CLIENT,
               'PXE_RHEL9_AMD64_REPO': 'http://192.0.2.99:8090/rhel/9/',
               'PXE_RHEL9_ARM64_REPO': 'http://192.0.2.99/rhel/9/?secret=fixture'}
        with subprocess.Popen([binary, '--serve-guided', config], env=env) as service:
            try:
                for _ in range(80):
                    if service.poll() is not None:
                        raise RuntimeError('Rust listener stopped during startup')
                    try:
                        if request('/healthz', tls=tls)[0] == 200:
                            break
                    except OSError:
                        time.sleep(.2)
                else:
                    raise RuntimeError('Rust Windows edition fixture was not ready')

                assert request(SETTINGS, tls=tls)[0] == 401
                status, _, page = request(SETTINGS, tls=tls, headers=auth)
                assert status == 200 and b'Windows 10 Famille' in page and b'Windows 11 Pro &amp; test' in page
                assert request(BOOT, source=WINDOWS_CLIENT)[0] == 409
                assert request(SETTINGS, tls=tls, form={'edition': 'missing'}, headers=form_headers)[0] == 400
                for profile in ('windows10-core', 'windows11-professional'):
                    assert request(SETTINGS, tls=tls, form={'edition': profile},
                                   headers=form_headers)[:2] == (303, SETTINGS)
                    status, _, body = request(BOOT, source=WINDOWS_CLIENT)
                    assert status == 200 and f'/pxe/windows/{profile}/'.encode() in body
                    for filename in ('boot.wim', 'install.wim'):
                        path = f'/pxe/windows/{profile}/{filename}'
                        status, _, response = request(path, source=WINDOWS_CLIENT, headers={'Range': 'bytes=0-6'})
                        assert status == 206 and response == b'windows'
                        assert request(path, source=OTHER_CLIENT)[0] == 404
                    assert request(f'/pxe/windows/{profile}/case.json', source=WINDOWS_CLIENT)[0] == 404
                assert request('/pxe/windows/boot.wim', source=WINDOWS_CLIENT)[0] == 404
                check_linux(tls, auth, form_headers)
            finally:
                service.terminate()
        print('Authenticated edition selection, distinct WinPE paths and private installation media verified.')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(strict=True))
