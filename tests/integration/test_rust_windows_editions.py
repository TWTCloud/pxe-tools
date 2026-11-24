#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise the Windows and Linux installer menus in an isolated network namespace."""
import base64
from ctypes import CDLL, c_char_p
from hashlib import sha256
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import time
from urllib.parse import urlencode
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[2]
SERVER = '192.0.2.1'
WINDOWS_CLIENT = '192.0.2.10'
OTHER_CLIENT = '192.0.2.11'
OUTSIDE_CLIENT = '198.51.100.10'
HTTP = 8088
HTTPS = 8448
SETTINGS = '/settings/windows'
BOOT = '/pxe/windows/boot.ipxe'
MEDIA = '/settings/images/media'
CDN = '93.184.216.34'


def media(root, profile, edition, label, index):
    directory = root/'winpe'/'amd64'/profile
    directory.mkdir(parents=True)
    for name in ('wimboot', 'BCD', 'boot.sdi', 'boot.wim', 'install.wim'):
        (directory/name).write_bytes(f'{profile}:{name}'.encode())
    (directory/'case.json').write_text(json.dumps({
        'edition': edition, 'edition_label': label, 'image_index': index,
        'install_image': 'install.wim', 'install_sha256': 'a'*64,
    }))


def request(path, *, tls=None, source=None, form=None, headers=None, method=None):
    if tls:
        connection = HTTPSConnection('127.0.0.1', HTTPS, context=tls, timeout=2)
    else:
        connection = HTTPConnection(SERVER, HTTP, timeout=2, source_address=(source, 0))
    try:
        connection.request(method or ('GET' if form is None else 'POST'), path,
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


def check_automatic_linux(database, tls, auth, form_headers, rhel_sha):
    crypt = CDLL('libcrypt.so.1').crypt
    crypt.argtypes = (c_char_p, c_char_p)
    crypt.restype = c_char_p
    for offset, image, file in ((1, 'ubuntu-24.04.5', 'user-data'),
                                (2, 'rhel9', 'kickstart.cfg'),
                                (3, f'rhel9-{rhel_sha}', 'kickstart.cfg')):
        mac = f'02:00:00:00:50:{offset:02x}'
        serial = f'PXE-TEST-{offset}'
        inventory = {
            'boot_mac': mac, 'discovery_ip': WINDOWS_CLIENT, 'inventory': {'boot_mode': 'UEFI'},
            'disks': [{'name': 'vda', 'serial': serial}],
        }
        with sqlite3.connect(database) as db:
            device = db.execute("""INSERT INTO machines(mac,status,boot_arch,inventory_json)
                                   VALUES (?,'discovered','amd64',?) RETURNING id""",
                                (mac, json.dumps(inventory))).fetchone()[0]
        route = f'/machines/{device}/install/linux'
        grub = '/grub.php?' + urlencode({'mac': mac, 'arch': 'amd64'})
        selection = {'image': image, 'disk': f'/dev/vda:{serial}', 'hostname': f'pxe-linux-{offset}',
                     'login': 'pxecheck', 'password': 'fixture-long-password',
                     'password_confirm': 'fixture-long-password', 'confirm': 'yes'}
        assert request(route, tls=tls)[0] == 401
        assert image.encode() in request(route, tls=tls, headers=auth)[2]
        assert request(route, tls=tls, form=selection, headers=auth)[0] == 403
        assert request(route, tls=tls, form={**selection, 'disk': '/dev/vda:WRONG'},
                       headers=form_headers)[0] == 409
        status, task, _ = request(route, tls=tls, form=selection, headers=form_headers)
        assert status == 303 and task.startswith('/tasks/')
        action = int(task.rsplit('/', 1)[1])
        assert request(route, tls=tls, form=selection, headers=form_headers)[0] == 409
        assert request('/preseed.php?' + urlencode({'mac': mac}), source=WINDOWS_CLIENT)[0] == 404
        assert b'/pxe/linux/auto/' not in request(grub, source=OTHER_CLIENT)[2]
        menu = request(grub, source=WINDOWS_CLIENT)[2].decode()
        base = re.search(r'(/pxe/linux/auto/[0-9]+/[a-f0-9]{32}/)grub.cfg', menu)[1]
        boot, key = base.strip('/').split('/')[-2:]
        assert request(base + file, source=WINDOWS_CLIENT)[0] == 404
        selected = '/api/boot-selected?' + urlencode({'boot_id': boot, 'token': key, 'menu': 'install'})
        assert request(selected, source=WINDOWS_CLIENT)[0] == 200
        assert request(base + file, source=OTHER_CLIENT)[0] == 404
        assert request(base + file, source=OUTSIDE_CLIENT)[0] == 404
        assert request(base.replace(key, '0' * 32) + file, source=WINDOWS_CLIENT)[0] == 404
        status, _, chain = request(base + 'grub.cfg', source=WINDOWS_CLIENT)
        assert status == 200 and base.encode() in chain
        assert request(base + file, method='HEAD', source=WINDOWS_CLIENT) == (200, None, b'')
        with sqlite3.connect(database) as db:
            assert db.execute('SELECT COUNT(*) FROM installations WHERE action_id=?', (action,)).fetchone() == (0,)
        status, _, config = request(base + file, source=WINDOWS_CLIENT)
        assert status == 200 and b'fixture-long-password' not in config
        assert request(base + file, source=WINDOWS_CLIENT)[2] == config
        if image.startswith('ubuntu-'):
            assert b'autoinstall' in chain and b'ds=nocloud-net;s=' in chain
            assert request(base + 'meta-data', source=WINDOWS_CLIENT)[2] == f'instance-id: pxe-tools-{action}\n'.encode()
            settings = json.loads(config.removeprefix(b'#cloud-config\n'))['autoinstall']
            assert settings['storage']['layout']['match'] == {'path': '/dev/vda'}
            assert serial in settings['early-commands'][0][2]
            assert '/api/install-end' in settings['late-commands'][0][2]
        else:
            assert b'inst.ks=' in chain and b'inst.nosave=all_ks' in chain
            if offset == 3:
                assert f'url --url=http://{SERVER}:{HTTP}/pxe/rhel9/{rhel_sha}/'.encode() in config
            assert b'ignoredisk --only-use=vda\nclearpart --all --initlabel --drives=vda' in config
            assert b'%pre --erroronfail' in config and serial.encode() in config
            assert b'%packages\n@^minimal-environment\ncurl\n%end' in config
            assert b'%post --erroronfail' in config and b'/api/install-end' in config
        with sqlite3.connect(database) as db:
            assert db.execute('SELECT install_status FROM installations WHERE action_id=?', (action,)).fetchall() == [('in_progress',)]
            assert db.execute('SELECT status FROM actions WHERE id=?', (action,)).fetchone() == ('running',)
            token = db.execute('SELECT token FROM actions WHERE id=?', (action,)).fetchone()[0]
            snapshot = json.loads(db.execute('SELECT install_config_json FROM machines WHERE id=?', (device,)).fetchone()[0])
        password_hash = snapshot['linux_deployment']['password_hash'].encode()
        assert crypt(selection['password'].encode(), password_hash) == password_hash
        bearer = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/x-www-form-urlencoded'}
        complete = '/api/install-end?' + urlencode({'mac': mac, 'status': 'success'})
        assert request(complete, form={'first_boot': '1'}, source=WINDOWS_CLIENT, headers=bearer)[0] == 200
        assert request(base + file, source=WINDOWS_CLIENT)[0] == 404
        first_boot = '/api/internal/checkpoint?' + urlencode({'mac': mac, 'code': 'os_first_boot', 'ack': '1'})
        assert request(first_boot, form={}, source=WINDOWS_CLIENT, headers=bearer)[2] == b'accepted\n'
        assert request(first_boot, form={}, source=WINDOWS_CLIENT, headers=bearer)[2] == b'accepted\n'
        with sqlite3.connect(database) as db:
            assert db.execute('SELECT status,local_boot_source FROM machines WHERE id=?', (device,)).fetchone() == ('installed', 'pxe')
            assert db.execute("""SELECT COUNT(*) FROM machine_events
                                 WHERE action_id=? AND checkpoint='os_first_boot'""", (action,)).fetchone() == (1,)
    print('Ubuntu Autoinstall and RHEL Kickstart console actions, private seeds and first-boot callbacks verified.')


def create_iso(path, tree, files):
    tree.mkdir()
    for name, data in files.items():
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    subprocess.run(['genisoimage', '-R', '-o', path, tree], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return sha256(path.read_bytes()).hexdigest()


def check_media(binary, root, public, database, tls, auth, headers, env):
    inbox = public / 'media/inbox'
    inbox.mkdir(mode=0o700, parents=True)
    def submit(kind, source, digest, profile='', expected='success'):
        form = {'kind': kind, 'source': source, 'sha256': digest, 'profile': profile}
        status, location, _ = request(MEDIA, tls=tls, form=form, headers=headers)
        assert status == 303 and location.startswith('/jobs/')
        job = location.rsplit('/', 1)[1]
        if source.startswith('https://'):
            with sqlite3.connect(database) as db:
                saved = db.execute('SELECT value FROM settings WHERE key=?', (f'media_import_request_{job}',)).fetchone()[0]
                assert source not in saved and 'opaque-proof' not in saved
        subprocess.run([binary, '--run-media-import', database, job, ROOT/'docker/worker/scripts'],
                       check=True, env=env)
        with sqlite3.connect(database) as db:
            state, message = db.execute('SELECT status,message FROM init_jobs WHERE id=?', (job,)).fetchone()
            assert state == expected, (state, message)
            assert 'opaque-proof' not in message
        return message

    assert request(MEDIA, tls=tls)[0] == 401
    assert request(MEDIA, tls=tls, headers=auth)[0] == 200
    bad = {'kind':'rhel9', 'source':'../private.iso', 'sha256':'a'*64, 'profile':''}
    assert request(MEDIA, tls=tls, form=bad, headers=headers)[0] == 422
    assert request(MEDIA, tls=tls, form={**bad, 'source':'https://unauthorized.invalid/DVD.iso'}, headers=headers)[0] == 422
    boot = {name: name.encode() for name in ('images/install.img', 'images/pxeboot/vmlinuz', 'images/pxeboot/initrd.img')}
    checksums = ''.join(f'{name} = sha256:{sha256(data).hexdigest()}\n' for name, data in boot.items())
    treeinfo = f'[general]\narch = x86_64\nfamily = Red Hat Enterprise Linux\nversion = 9.9\n[checksums]\n{checksums}'.encode()
    rhel_sha = create_iso(inbox/'rhel9.iso', root/'rhel-tree', {
        **boot, '.treeinfo': treeinfo, 'BaseOS/repodata/repomd.xml': b'baseos',
        'AppStream/repodata/repomd.xml': b'appstream', 'BaseOS/Packages/example.rpm': b'fixture-rpm',
    })
    assert 'SHA-256' in submit('rhel9', 'rhel9.iso', 'a'*64, expected='failed')
    submit('rhel9', 'rhel9.iso', rhel_sha)
    submit('rhel9', 'absent.iso', rhel_sha)
    prefix = f'/pxe/rhel9/{rhel_sha}/'
    assert prefix.encode() in request('/pxe/linux/amd64/grub.cfg', source=WINDOWS_CLIENT)[2]
    assert prefix.encode() not in request('/pxe/linux/arm64/grub.cfg', source=WINDOWS_CLIENT)[2]
    assert request(prefix+'.treeinfo', source=WINDOWS_CLIENT)[2] == treeinfo
    assert request(prefix+'.treeinfo', source=OUTSIDE_CLIENT)[0] == 403
    assert request(prefix+'BaseOS/Packages/example.rpm', source=WINDOWS_CLIENT,
                   headers={'Range':'bytes=0-6'}) == (206, None, b'fixture')
    assert request(prefix+'.pxe-media.json', source=WINDOWS_CLIENT)[0] == 404
    assert request(prefix+'BaseOS/../../inbox/rhel9.iso', source=WINDOWS_CLIENT)[0] == 404

    image = b'MSWIM\0\0\0fixture Windows image'
    digest = sha256(image).hexdigest()
    class Download(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', '/install.wim?signature=opaque-proof')
                self.end_headers()
            elif self.path == '/install.wim?signature=opaque-proof':
                self.send_response(200)
                self.send_header('Content-Length', str(len(image)))
                self.end_headers()
                self.wfile.write(image)
            else:
                self.send_error(404)

    source_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    source_tls.load_cert_chain(root/'cert.pem', root/'key.pem')
    with ThreadingHTTPServer((CDN, 443), Download) as cdn:
        cdn.socket = source_tls.wrap_socket(cdn.socket, server_side=True)
        thread = Thread(target=cdn.serve_forever, daemon=True)
        thread.start()
        try:
            assert digest in submit('windows-wim', f'https://{CDN}/redirect', digest)
            message = submit('windows-esd', 'https://localhost/private?signature=opaque-proof',
                             'b'*64, expected='failed')
            assert 'adresse publique' in message
        finally:
            cdn.shutdown()
            thread.join()
    iso = create_iso(inbox/'windows.iso', root/'windows-tree', {'sources/install.wim': image})
    assert digest in submit('windows-iso', 'windows.iso', iso)
    assert digest in submit('windows-iso', 'missing.iso', iso)
    binaries = {name: name.encode() for name in ('wimboot','BCD','boot.sdi','boot.wim')}
    metadata = {'edition':'Professional', 'edition_label':'Importée Pro', 'image_index':6,
                'install_image':'install.wim', 'install_sha256':digest}
    for name, key in zip(binaries, ('wimboot_sha256','bcd_sha256','boot_sdi_sha256','winpe_sha256')):
        metadata[key] = sha256(binaries[name]).hexdigest()
    def winpe_archive(profile, edition):
        name = f'{profile}.zip'
        archive = inbox / name
        manifest = {**metadata, **edition,
                    'install_image_uri': f'http://192.0.2.1/pxe/windows/{profile}/install.wim'}
        with ZipFile(archive, 'w') as output:
            output.writestr('case.json', json.dumps(manifest))
            for asset, data in binaries.items():
                output.writestr('boot/' + asset, data)
        return name, sha256(archive.read_bytes()).hexdigest()

    professional, pro_sha = winpe_archive('kit-local', {})
    home, home_sha = winpe_archive('kit-home', {'edition': 'Core', 'edition_label': 'Importée Famille', 'image_index': 1})
    assert 'correspondre' in submit('winpe', professional, pro_sha, 'id-incorrect', expected='failed')
    submit('winpe', professional, pro_sha, 'kit-local')
    submit('winpe', home, home_sha, 'kit-home')
    submit('winpe', 'missing.zip', pro_sha, 'kit-local')
    cache = public/'media/windows-cache'/digest/'install.wim'
    assert all((public/'winpe/amd64'/profile/'install.wim').stat().st_ino == cache.stat().st_ino
               for profile in ('kit-local', 'kit-home'))
    assert 'Importée Pro'.encode() in request(SETTINGS, tls=tls, headers=auth)[2]
    assert request(SETTINGS, tls=tls, form={'edition':'kit-local'}, headers=headers)[0] == 303
    assert b'/pxe/windows/kit-local/' in request(BOOT, source=WINDOWS_CLIENT)[2]
    assert request('/pxe/windows/kit-local/install.wim', source=WINDOWS_CLIENT)[2] == image
    assert request('/pxe/windows/kit-local/install.wim', source=OTHER_CLIENT)[0] == 404
    assert request('/media/inbox/windows.iso', source=WINDOWS_CLIENT)[0] == 404
    print('Verified media preparation, approved HTTPS redirection, RHEL PXE tree, Windows deduplication and live WinPE selection.')
    return rhel_sha


def main(binary):
    with tempfile.TemporaryDirectory(prefix='pxe-editions-', dir='/run') as temporary:
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
            '-subj', '/CN=127.0.0.1', '-addext', f'subjectAltName=IP:127.0.0.1,IP:{CDN}',
            '-days', '1', '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        tls = ssl.create_default_context(cafile=str(root/'cert.pem'))
        encoded = base64.b64encode(b'fixture-admin:fixture-login-password').decode()
        auth = {'Authorization': 'Basic ' + encoded}
        form_headers = {**auth, 'Origin': f'https://127.0.0.1:{HTTPS}',
                        'Content-Type': 'application/x-www-form-urlencoded'}
        master = root/'master.key'
        master.write_bytes(b'x'*32)
        master.chmod(0o600)
        env = {**os.environ, 'HTTP_ROOT': str(public), 'TLS_DIR': str(root),
               'PXE_MASTER_KEY_PATH': str(master), 'SSL_CERT_FILE': str(root/'cert.pem'),
               'PXE_MEDIA_DOWNLOAD_HOSTS': f'{CDN},localhost',
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
                rhel_sha = check_media(binary, root, public, database, tls, auth, form_headers, env)
                check_automatic_linux(database, tls, auth, form_headers, rhel_sha)
            finally:
                service.terminate()
        print('Authenticated edition selection, distinct WinPE paths and private installation media verified.')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(strict=True))
