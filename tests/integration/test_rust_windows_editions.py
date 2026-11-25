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
LAN = '10.77.0.1'
LAN_CLIENT = '10.77.0.2'


def media(root, profile, edition, label, index):
    directory = root/'winpe'/'amd64'/profile
    directory.mkdir(parents=True)
    for name in ('wimboot', 'BCD', 'boot.sdi', 'boot.wim', 'install.wim'):
        (directory/name).write_bytes(f'{profile}:{name}'.encode())
    (directory/'case.json').write_text(json.dumps({
        'edition': edition, 'edition_label': label, 'image_index': index,
        'install_image': 'install.wim', 'install_sha256': 'a'*64,
    }))


def request(path, *, tls=None, source=None, form=None, json_body=None, headers=None, method=None, host=None,
            response_header='Location'):
    binding = (source, 0) if source else None
    if tls:
        connection = HTTPSConnection(host or '127.0.0.1', HTTPS, context=tls, timeout=2, source_address=binding)
    else:
        connection = HTTPConnection(host or SERVER, HTTP, timeout=2, source_address=binding)
    try:
        body = json.dumps(json_body) if json_body is not None else None if form is None else urlencode(form)
        connection.request(method or ('GET' if body is None else 'POST'), path, body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheader(response_header), response.read()
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
        'AppStream/repodata/repomd.xml': b'appstream', 'BaseOS/Packages/example-0^20260728.rpm': b'fixture-rpm',
    })
    assert 'SHA-256' in submit('rhel9', 'rhel9.iso', 'a'*64, expected='failed')
    submit('rhel9', 'rhel9.iso', rhel_sha)
    submit('rhel9', 'absent.iso', rhel_sha)
    prefix = f'/pxe/rhel9/{rhel_sha}/'
    assert prefix.encode() in request('/pxe/linux/amd64/grub.cfg', source=WINDOWS_CLIENT)[2]
    assert prefix.encode() not in request('/pxe/linux/arm64/grub.cfg', source=WINDOWS_CLIENT)[2]
    assert request(prefix+'.treeinfo', source=WINDOWS_CLIENT)[2] == treeinfo
    assert request(prefix+'.treeinfo', source=OUTSIDE_CLIENT)[0] == 403
    assert request(prefix+'BaseOS/Packages/example-0%5E20260728.rpm', source=WINDOWS_CLIENT,
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


def verify_access(secure, private, admin, database):
    users, tokens, api = '/admin/access/users', '/admin/access/tokens', '/api/v1'

    def form(path, fields, headers=admin, **kwargs):
        return request(path, **secure, headers=headers, form=fields, **kwargs)

    def secret(response):
        assert response[0] == 200 and response[1] == 'no-store', response[0]
        return re.search(rb'>\s*(pxe_[0-9a-f]{64})</textarea>', response[2])[1].decode()

    def bearer(token):
        return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    def api_call(path, token, **kwargs):
        return request(api+path, **secure, headers=bearer(token), **kwargs)

    credentials = {'username':'observer', 'password':'fixture-observer-password'}
    observer = {'Authorization': 'Basic '+base64.b64encode(b'observer:fixture-observer-password').decode(),
                'Origin': admin['Origin'], 'Content-Type': admin['Content-Type']}
    assert request(users, **secure, headers=admin)[0] == 200
    assert form(users, {'action':'create', **credentials, 'scope':'devices.read'})[:2] == (303, users)
    visible = request('/admin/devices', **secure, headers=observer)
    assert visible[0] == 200 and tokens.encode() in visible[2] and users.encode() not in visible[2]
    assert request(users, **secure, headers=observer)[0] == 403
    assert form(users, {'action':'create', 'username':'intrus', 'password':'fixture-attacker-password',
                        'admin':'1'}, observer)[0] == 403
    assert form('/machines', {'mac':'02:00:00:00:20:01'}, observer)[0] == 403
    with sqlite3.connect(database) as db:
        owner = db.execute("SELECT id FROM users WHERE username='observer'").fetchone()[0]
        first_admin = db.execute("SELECT id FROM users WHERE username='lan-admin'").fetchone()[0]
        assert db.execute('SELECT password_hash,managed_password_hash IS NOT NULL FROM users WHERE id=?',
                          [owner]).fetchone() == ('!', 1)
    assert form(users, {'action':'update', 'id':first_admin, 'enabled':'1'})[0] == 409
    assert form(tokens, {'action':'create', 'name':'test', 'days':'1','scope':'jobs.read'}, observer)[0] == 422
    assert form(tokens, {'action':'create', 'name':'test', 'days':'1','scope':'admin'}, observer)[0] == 422
    outside = {**observer, 'Origin':'https://outside.example'}
    assert form(tokens, {'action':'create', 'name':'test', 'days':'1','scope':'devices.read'}, outside)[0] == 403
    issued = secret(form(tokens, {'action':'create','name':'Inventaire seul','days':'1','scope':'devices.read'},
                         observer, response_header='Cache-Control'))
    assert issued.encode() not in request(tokens, **secure, headers=observer)[2]
    with sqlite3.connect(database) as db:
        token_id, digest = db.execute('SELECT id,secret_hash FROM api_tokens WHERE user_id=?', [owner]).fetchone()
        assert digest == sha256(issued.encode()).digest()
    login = form('/login', credentials, response_header='Set-Cookie')
    assert login[0] == 303 and login[1]
    cookie = {'Cookie':login[1].split(';', 1)[0]}
    assert request('/admin/devices', **secure, headers=cookie)[0] == 200
    assert request(api+'/devices', **secure, headers=cookie)[0] == 401
    assert api_call('/devices', issued)[0] == 200
    assert api_call('/jobs', issued)[0] == 403
    assert api_call('/devices', issued, json_body={'mac':'02:00:00:00:20:01'})[0] == 403
    assert request('/admin/devices', **secure, headers=bearer(issued))[0] == 401
    assert request(api+'/devices', **private, headers=bearer(issued))[0] == 404
    rotated = secret(form(tokens, {'action':'rotate','id':token_id,'scope':'devices.read'},
                           observer, response_header='Cache-Control'))
    assert rotated != issued and api_call('/devices', issued)[0] == 401
    assert api_call('/devices', rotated)[0] == 200
    assert form(tokens, {'action':'revoke','id':token_id}, observer)[:2] == (303, tokens)
    assert api_call('/devices', rotated)[0] == 401

    operator = secret(form(tokens, [('action','create'),('name','Automatisation'),('days','2'),
                                    ('scope','devices.read'),('scope','devices.write'),('scope','devices.power')],
                           response_header='Cache-Control'))
    created = api_call('/devices', operator, json_body={'mac':'02:00:00:00:20:01','hostname':'fixture-api'})
    assert created[0] == 201
    device = json.loads(created[2])['id']
    assert created[1] == f'{api}/devices/{device}'
    assert json.loads(api_call(f'/devices/{device}', operator)[2])['hostname'] == 'fixture-api'
    assert api_call(f'/devices/{device}/actions/reboot', operator, json_body={})[0] == 202
    assert api_call('/jobs', operator)[0] == 403
    assert form(tokens, {'action':'revoke','id':token_id+1}, observer)[0] == 404
    assert form(tokens, {'action':'rotate','id':token_id+1,'scope':'devices.read'}, observer)[0] == 404
    pending = secret(form(tokens, {'action':'create','name':'Interdit après désactivation','days':'1','scope':'devices.read'},
                          observer, response_header='Cache-Control'))
    assert form(users, {'action':'update','id':owner,'enabled':'1'})[:2] == (303, users)
    assert api_call('/devices', pending)[0] == 401
    assert form(users, {'action':'update','id':owner,'enabled':'1','scope':'devices.read'})[:2] == (303, users)
    assert api_call('/devices', pending)[0] == 401
    assert form(users, {'action':'update','id':owner,'scope':'devices.read'})[:2] == (303, users)
    assert request('/admin/devices', **secure, headers=observer)[0] == 401
    assert form(users, {'action':'update','id':owner,'enabled':'1','scope':'devices.read'})[:2] == (303, users)
    assert request('/admin/devices', **secure, headers=cookie)[0] in (302, 401)
    with sqlite3.connect(database) as db:
        db.execute('UPDATE api_tokens SET expires_at=unixepoch() WHERE user_id=?', [first_admin])
    assert api_call('/devices', operator)[0] == 401
    print('Verified independent accounts, granular browser and API permissions, hashed tokens, rotation, revocation and expiration.')


def verify_access_migration(binary, root):
    database = root/'legacy-access.sqlite'
    config = root/'legacy-access.conf'
    with sqlite3.connect(database) as db:
        db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
        for column in ('is_admin', 'enabled', 'permissions', 'external', 'session_epoch', 'managed_password_hash'):
            db.execute(f'ALTER TABLE users DROP COLUMN {column}')
        db.execute("INSERT INTO users(username,password_hash) VALUES('legacy','legacy-hash')")
    config.write_text(json.dumps({'driver':'sqlite','path':str(database)}))
    subprocess.run([binary, '--migrate-schema', config], check=True)
    with sqlite3.connect(database) as db:
        assert db.execute('SELECT username,password_hash,is_admin,enabled FROM users').fetchall() == [
            ('legacy','legacy-hash',1,1)]
        db.execute("INSERT INTO users(username,password_hash) VALUES('new','new-hash')")
    subprocess.run([binary, '--migrate-schema', config], check=True)
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT is_admin FROM users WHERE username='new'").fetchone() == (0,)


def verify_authentik_access(binary, config, secure, origin, env):
    users = '/admin/access/users'
    mode = {**env, 'AUTH_MODE':'authentik', 'AUTHENTIK_TRUSTED_PROXY_CIDRS':f'{LAN_CLIENT}/32'}
    with subprocess.Popen([binary, '--serve-guided', config], env=mode) as service:
        try:
            for _ in range(80):
                if service.poll() is not None:
                    raise RuntimeError('Authentik fixture stopped during startup')
                try:
                    if request('/healthz', **secure)[0] == 200:
                        break
                except OSError:
                    time.sleep(.2)
            else:
                raise RuntimeError('Authentik fixture did not start')
            admin = {'X-Forwarded-User':'sso-admin', 'Origin':origin,
                     'Content-Type':'application/x-www-form-urlencoded'}
            viewer = {**admin, 'X-Forwarded-User':'sso-viewer'}
            assert request('/admin/devices', **secure, headers=viewer)[0] == 200
            assert request(users, **secure, headers=admin, form={'action':'activate'})[:2] == (303, users)
            assert request('/admin/devices', **secure, headers=viewer)[0] == 403
            assert request(users, **secure, headers=admin,
                           form={'action':'create','username':'sso-viewer','scope':'devices.read'})[:2] == (303, users)
            assert request('/admin/devices', **secure, headers=viewer)[0] == 200
            assert request('/admin/devices', **secure, headers={**viewer,'X-Forwarded-User':'SSO-VIEWER'})[0] == 403
            assert request(users, **secure, headers=viewer)[0] == 403
            assert request('/machines', **secure, headers=viewer, form={'mac':'02:00:00:00:20:03'})[0] == 403
        finally:
            service.terminate()
    print('Verified trusted SSO transition from legacy access to explicit administrator and viewer accounts.')


def check_lan(binary, root, tls, env):
    runtime = root/'lan'
    runtime.mkdir(mode=0o700)
    sessions = runtime/'sessions'
    sessions.mkdir(mode=0o700)
    (root/'setup-code').write_text('a'*48)
    config = runtime/'db.conf'
    private = {'host': LAN, 'source': LAN_CLIENT}
    secure = {**private, 'tls': tls}
    origin = f'https://{LAN}:{HTTPS}'
    env = {**env, 'PXE_SETUP_DATA_ROOT': str(runtime), 'PXE_DB_PATH': str(runtime/'install.sqlite'),
           'PXE_SESSION_DIR': str(sessions), 'PXE_ADMIN_BIND': ''}
    with subprocess.Popen([binary, '--serve-guided', config], env=env) as service:
        try:
            for _ in range(80):
                if service.poll() is not None:
                    raise RuntimeError('LAN listener stopped during startup')
                try:
                    if request('/healthz', **secure)[0] == 200:
                        break
                except OSError:
                    time.sleep(.2)
            else:
                raise RuntimeError('LAN fixture was not ready')
            assert request('/', **private)[:2] == (302, origin+'/admin/')
            assert request('/', **private, headers={'Host': 'other.invalid'})[:2] == (302, origin+'/admin/')
            assert request('/admin/', **secure)[:2] == (302, '/init/welcome')
            assert request('/init/welcome', host=LAN, source=OUTSIDE_CLIENT, tls=tls)[0] == 404

            def wizard_page(path, phase, *, headers=None, form=None, expected=200):
                status, content_type, document = request(
                    path, **secure, headers=headers, form=form, response_header='Content-Type')
                assert status == expected and content_type.startswith('text/html'), (path, status)
                assert b'class="wizard-main"' in document
                assert b'aria-current="step">' + phase.encode() + b'</li>' in document
                link = re.search(rb'<link rel="stylesheet" href="([^"]+)">', document)
                assert link and link[1].startswith(b'/console-assets/style.css')
                return link[1].decode(), document

            def check_setup_command(path, phase):
                _, document = wizard_page(path, phase)
                assert b'<input id="setup-command" type="text" value="sudo pxe-tools setup" readonly' in document
                assert b'id="copy-setup-command"' in document
                assert b'a'*48 not in document
                _, policy, _ = request(path, **secure, response_header='Content-Security-Policy')
                script = re.search(rb'<script>(.*?)</script>', document, re.S)[1]
                digest = base64.b64encode(sha256(script).digest()).decode()
                assert f"script-src 'sha256-{digest}'" in policy.split('; ')

            css_path, welcome = wizard_page('/init/welcome', 'Stockage')
            assert b'id="setup-command"' not in welcome and b'<script>' not in welcome
            assert request('/init/db', **secure)[:2] == (302, '/init/admin')
            check_setup_command('/init/admin', 'Compte')
            style_status, css_type, style = request(css_path, **secure, response_header='Content-Type')
            assert style_status == 200 and css_type.startswith('text/css')
            assert b'.auth-layout' in style and b'.workspace' in style and b'.wizard-main' in style
            assert request('/console-assets/style.css', **private)[0] == 404
            assert request('/console-assets/private', **secure)[0] == 404
            status, policy, login = request('/login', **secure, response_header='Referrer-Policy')
            assert status == 200 and policy == 'same-origin' and b'/console-assets/style.css' in login
            try:
                request('/healthz', tls=tls, host=CDN)
            except ConnectionRefusedError:
                pass
            else:
                raise AssertionError('The console opened a non-private address')
            headers = {'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'}
            _, invalid_code = wizard_page('/init/admin', 'Compte', headers=headers,
                                          form={'code':'b'*48}, expected=403)
            assert b'Code de configuration invalide' in invalid_code and b'b'*48 not in invalid_code
            assert request('/init/admin', **secure, form={'code':'a'*48},
                           headers={**headers, 'Origin':'https://other.invalid'})[0] == 403
            credentials = {'username':'lan-admin', 'password':'fixture-lan-password'}
            assert request('/init/admin', **secure, headers=headers,
                           form={**credentials,'password_confirm': credentials['password'],'code':'a'*48})[:2] == (303,'/admin/devices')
            assert request('/login', **secure, headers=headers, form=credentials)[0] == 303
            authorization = base64.b64encode(b'lan-admin:fixture-lan-password').decode()
            admin = {'Authorization': 'Basic ' + authorization, **headers}
            wizard_page('/init/network', 'Réseau', headers=admin)
            plan = {'role':'proxy', 'pxe_interface':'lo', 'pxe_ip':LAN, 'pxe_subnet':'10.77.0.0/24'}
            assert request('/init/network', **secure, form=plan, headers=admin)[:2] == (303,'/init/images')
            wizard_page('/init/images', 'Réseau', headers=admin)
            _, pending_image = wizard_page('/init/done', 'Validation', headers=admin)
            assert b'name="confirmation"' not in pending_image
            assert request('/init/network', **secure, form={'role':'console'}, headers=admin)[:2] == (303,'/init/done')
            _, summary = wizard_page('/init/done', 'Validation', headers=admin)
            assert b'name="confirmation" value="yes"' in summary and b'Console seule' in summary
            status, csp, console = request('/admin/devices', **secure, headers=admin,
                                           response_header='Content-Security-Policy')
            assert status == 200 and b'class="rail"' in console and b'aria-current="page"' in console
            assert b'aria-controls="mobile-navigation"' in console
            assert b'<dialog id="mobile-navigation"' in console
            script = re.search(rb'<script>(.*?)</script>', console, re.S)[1]
            digest = base64.b64encode(sha256(script).digest()).decode()
            assert f"script-src 'sha256-{digest}'" in csp.split('; ')
            assert request('/pxe/linux/amd64/grub.cfg', **private)[0] == 404
            verify_access(secure, private, admin, runtime/'install.sqlite')
        finally:
            service.terminate()
    verify_authentik_access(binary, config, secure, origin, env)
    env['PXE_ADMIN_BIND'] = '127.0.0.1'
    assert subprocess.check_output([binary, '--admin-listen-addresses'], env=env, text=True).splitlines() == ['127.0.0.1']
    print('Default LAN console, HTTPS setup, login, origin checks and explicit loopback verified.')


def main(binary):
    for address in (LAN, LAN_CLIENT):
        subprocess.run(['ip', '-4', 'address', 'add', address+'/32', 'dev', 'lo', 'scope', 'global'], check=True)
    with tempfile.TemporaryDirectory(prefix='pxe-editions-', dir='/run') as temporary:
        root = Path(temporary)
        verify_access_migration(binary, root)
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
            db.execute('INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)', (
                'fixture-admin', '$2y$12$zGZhsSwt3AHDHVbliUPl5eMV46SsqfpLUsIOAcZiq1frkQPqxaEcK',
            ))
            linux_media(public, db)
        config = root/'db.conf'
        config.write_text(json.dumps({'driver': 'sqlite', 'path': str(database)}))
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=127.0.0.1', '-addext', f'subjectAltName=IP:127.0.0.1,IP:{CDN},IP:{LAN}',
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
        check_lan(binary, root, tls, env)
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
                assert request(SETTINGS, tls=tls, host=LAN, source=LAN_CLIENT, headers=auth)[0] == 200
                assert request('/pxe/linux/amd64/grub.cfg', host=LAN, source=LAN_CLIENT)[0] == 404
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
