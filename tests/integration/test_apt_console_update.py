#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Exercise the web updater and actual APT upgrade in the disposable Debian guest."""

import base64
from hashlib import sha256
from http.client import HTTPSConnection
import json
from pathlib import Path
import runpy
import sqlite3
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode

ORIGIN = 'https://127.0.0.1'
ROUTE = '/settings/updates'
RELEASES = 'https://github.com/TWTCloud/pxe-tools/releases/tag/v'
WORK = Path('/var/tmp/apt-update-fixture')
UPDATER = '/usr/lib/pxe-tools/native/apt-console-update.py'
AUTH = 'Basic ' + base64.b64encode(b'setup-fixture:fixture-only-password').decode()
CONTEXT = ssl._create_unverified_context()


def request(path, form=None, *, authenticate=True, origin=ORIGIN, as_json=False):
    options = {'Authorization': AUTH} if authenticate else {}
    if as_json:
        options['Accept'] = 'application/json'
    if form is not None:
        options.update({'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    conn = HTTPSConnection('127.0.0.1', context=CONTEXT, timeout=6)
    try:
        conn.request('GET' if form is None else 'POST', path,
                     urlencode(form).encode() if form is not None else None, options)
        reply = conn.getresponse()
        return reply.status, reply.read()
    finally:
        conn.close()


def wait_for(expected, timeout=100):
    deadline = time.monotonic() + timeout
    latest = None
    while time.monotonic() < deadline:
        try:
            code, body = request(ROUTE + '/status')
            if code == 200:
                latest = json.loads(body)['phase']
                if latest == expected:
                    return
                if latest not in ('queued', 'checking', 'install_queued', 'installing'):
                    break
        except (OSError, TimeoutError):
            pass  # the console restarts during the actual upgrade
        time.sleep(1)
    raise AssertionError(f'Expected update phase {expected!r}, got {latest!r}')


def command(*args, **options):
    return subprocess.run(args, check=True, **options)


def signed_fixture(current, target):
    WORK.mkdir(mode=0o755)
    repo = WORK / 'repo'
    repo.mkdir()
    unpack = WORK / 'unpack'
    command('dpkg-deb', '-R', '/var/tmp/pxe-tools.deb', str(unpack))
    for name, before, after in (
        ('DEBIAN/control', f'Version: {current}\n', f'Version: {target}\n'),
        ('DEBIAN/preinst', f"prepare '{current}'", f"prepare '{target}'"),
        ('usr/lib/pxe-tools/native/default.env', f'PXE_APT_PACKAGE_VERSION={current}\n',
         f'PXE_APT_PACKAGE_VERSION={target}\n'),
    ):
        file = unpack / name
        text = file.read_text()
        assert text.count(before) == 1, (name, before)
        file.write_text(text.replace(before, after))
    control = unpack / 'DEBIAN/control'
    fields = control.read_text().splitlines()
    depends = next(index for index, line in enumerate(fields) if line.startswith('Depends: '))
    fields[depends] += ', hello'  # A new dependency available only from the system's repositories.
    control.write_text('\n'.join(fields) + '\n')
    command('dpkg-deb', '--root-owner-group', '-Zgzip', '-b', str(unpack), str(repo / 'pxe-tools.deb'))
    packages = command('apt-ftparchive', 'packages', '.', cwd=repo, capture_output=True).stdout
    (repo / 'Packages').write_bytes(packages)
    release = command('apt-ftparchive', 'release', '.', cwd=repo, capture_output=True).stdout
    (repo / 'Release').write_bytes(release)
    gnupg = WORK / 'gnupg'
    gnupg.mkdir(mode=0o700)
    gpg = ['gpg', '--homedir', str(gnupg), '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
    command(*gpg, '--quick-gen-key', 'PXE Update Fixture <test@example.invalid>', 'ed25519', 'sign', '1d')
    command(*gpg, '--output', str(repo / 'InRelease'), '--clearsign', str(repo / 'Release'))
    key = WORK / 'archive.gpg'
    key.write_bytes(command(*gpg, '--export', capture_output=True).stdout)
    source = WORK / 'fixture.list'
    source.write_text(f'deb [signed-by={key}] file:{repo} ./\n')

    module = runpy.run_path(UPDATER)
    official = module['SOURCE']
    keyring = module['KEYRING']
    keyring.parent.mkdir(exist_ok=True)
    keyring.write_bytes(key.read_bytes())
    arch = command('dpkg', '--print-architecture', capture_output=True, text=True).stdout.strip()
    standard = (f'Types: deb\nURIs: {module["REPOSITORY"]}\nSuites: stable\nComponents: main\n'
                f'Architectures: {arch}\nSigned-By: {keyring}\n')
    official.write_text(standard)
    assert module['official_source']()
    official.write_text(standard + 'Trusted: yes\n')
    assert not module['official_source']()
    official.unlink()
    keyring.unlink()
    legacy_source = module['LEGACY_SOURCE']
    legacy_keyring = module['LEGACY_KEYRING']
    legacy_keyring.write_bytes(key.read_bytes())
    legacy_source.write_text(f'deb [signed-by={legacy_keyring}] {module["REPOSITORY"]}/ stable main\n')
    assert module['legacy_source']()
    legacy_source.unlink()
    legacy_keyring.unlink()

    launcher = WORK / 'launch.py'
    launcher.write_text(f"""
from contextlib import closing
from pathlib import Path
import runpy
import sqlite3
module = runpy.run_path({UPDATER!r})
lifecycle = runpy.run_path('/usr/lib/pxe-tools/native/upgrade-lifecycle.py')['Lifecycle']
with closing(sqlite3.connect(lifecycle().database(), timeout=5)) as db:
    apt = module['Apt'](Path({str(source)!r}), module['LISTS'])
    module['process'](db, apt, lifecycle.busy)
""".lstrip())
    dropin = Path('/etc/systemd/system/pxe-tools-apt-update.service.d')
    dropin.mkdir()
    (dropin / 'fixture.conf').write_text(f'[Service]\nExecStart=\nExecStart=/usr/bin/python3 {launcher}\n')
    command('systemctl', 'daemon-reload')


def main():
    current = sys.argv[1]
    target = current + '+console-test1'
    code, page = request(ROUTE)
    assert code == 200 and current.encode() in page
    assert 'Vérifier les mises à jour'.encode() in page
    assert b'data-update-progress hidden' in page
    assert b'data-update-action="install" hidden' in page
    assert (RELEASES + current.replace('~', '-')).encode() in page
    assert page.count(b'<details class="profile-menu">') == 1
    assert b'<span class="profile-name">setup-fixture</span>' in page
    assert b'href="/admin/profile/tokens"' in page and b'action="/logout"' in page
    assert request(ROUTE + '/status', authenticate=False)[0] == 401
    assert request(ROUTE, {'action': 'auto'}, origin='https://example.invalid')[0] == 403

    command('systemctl', 'stop', 'pxe-tools-worker.service')
    try:
        code, response = request(ROUTE, {'action': 'auto'})
        assert code == 200 and json.loads(response)['phase'] == 'queued'
        code, response = request(ROUTE, {'action': 'check'}, as_json=True)
        assert code == 200 and json.loads(response)['message'] == 'Recherche des mises à jour…'
        code, page = request(ROUTE)
        assert code == 200 and b'data-update-phase="queued"' in page
        assert b'<h2 id="update-heading">PXE Tools</h2>' in page
        assert 'Vérifier les mises à jour'.encode() in page
        assert 'Actualiser l’état'.encode() not in page and 'planifiée'.encode() not in page
        assert b'data-update-progress>' in page
        assert b'role="progressbar"' in page and b'aria-valuenow' not in page
    finally:
        command('systemctl', 'start', 'pxe-tools-worker.service')
    wait_for('unavailable')
    code, response = request(ROUTE, {'action': 'auto'})
    assert code == 200 and json.loads(response)['phase'] == 'unavailable'
    command('systemctl', 'is-active', '--quiet', 'dbus.socket')

    signed_fixture(current, target)
    query = subprocess.run(['dpkg-query', '-W', '-f=${db:Status-Status}', 'hello'],
                           capture_output=True, text=True)
    assert query.stdout != 'installed'
    assert request(ROUTE, {'action': 'check'})[0] == 303
    wait_for('available')
    code, page = request(ROUTE)
    assert code == 200 and target.encode() in page and b'Installer la mise' in page
    assert b'data-update-action="install"' in page and b'type="checkbox"' not in page
    success, body = request(ROUTE + '/status')
    status = json.loads(body)
    assert success == 200 and status['installed']['pxe-tools'] == current
    assert status['candidates'] == {'pxe-tools': target}
    assert status['release_notes'] == RELEASES + target.replace('~', '-')
    assert status['release_notes'].encode() in page
    install = {'action': 'install', 'plan': status['plan']}
    assert request(ROUTE, {**install, 'plan': '{}'})[0] == 409
    code, body = request(ROUTE, {**install, 'plan': '{}'}, as_json=True)
    assert code == 409 and json.loads(body)['plan'] == status['plan']
    db_path = json.loads(Path('/etc/pxe-tools/db.conf').read_text())['path']
    with sqlite3.connect(db_path) as db:
        fixture = db.execute("INSERT INTO init_jobs(job_type,status) VALUES('fixture','running')").lastrowid
    assert request(ROUTE, install)[0] == 303
    wait_for('busy')
    assert 'Des tâches PXE sont en cours'.encode() in request(ROUTE)[1]
    with sqlite3.connect(db_path) as db:
        db.execute('DELETE FROM init_jobs WHERE id=?', (fixture,))

    key = Path('/etc/pxe-tools/master.key')
    cert = Path('/var/lib/pxe-tools-native/tls/cert.pem')
    before = [sha256(file.read_bytes()).hexdigest() for file in (key, cert)]
    code, body = request(ROUTE, install, as_json=True)
    queued = json.loads(body)
    assert code == 200 and queued['phase'] == 'install_queued'
    assert queued['message'] == 'Préparation de l’installation…'
    wait_for('installed', timeout=220)
    assert command('dpkg-query', '-W', '-f=${Version}', 'pxe-tools',
                   capture_output=True, text=True).stdout == target
    assert command('dpkg-query', '-W', '-f=${db:Status-Status}', 'hello',
                   capture_output=True, text=True).stdout == 'installed'
    assert [sha256(file.read_bytes()).hexdigest() for file in (key, cert)] == before
    code, page = request(ROUTE)
    assert code == 200 and target.encode() in page and b'data-update-action="install" hidden' in page
    assert 'Mise à jour terminée'.encode() in page
    command('systemctl', 'is-active', '--quiet', 'pxe-tools-worker.service')
    print('Native web-triggered signed APT update restored HTTPS, SQLite, the master key and TLS.')


if __name__ == '__main__':
    main()
