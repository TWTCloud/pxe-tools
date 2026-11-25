#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Apply a confirmed upgrade from the native, signed PXE Tools APT source."""

from contextlib import closing
import json
import os
from pathlib import Path
import re
import runpy
import sqlite3
import stat
import subprocess
import sys
import time

KEY = 'apt_console_update'
CORE = 'pxe-tools'
MODULE = 'pxe-tools-ansible'
SOURCE = Path('/etc/apt/sources.list.d/pxe-tools.sources')
KEYRING = Path('/etc/apt/keyrings/pxe-tools-archive-keyring.gpg')
LISTS = Path('/run/pxe-tools-apt-update/lists')
REPOSITORY = 'https://packages.pxetools.com/apt'
VERSION = re.compile(r'[0-9][A-Za-z0-9.+:~\-]{0,127}')
ENVIRONMENT = {
    **os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
    'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l',
}


def trusted_file(path):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


def official_source():
    try:
        if not (trusted_file(SOURCE) and trusted_file(KEYRING)):
            return False
        text = SOURCE.read_text()
    except FileNotFoundError:
        return False
    fields = {}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'([A-Za-z-]+):[ \t]+([^\s].*)', line)
        if not match or match[1].lower() in fields:
            return False
        fields[match[1].lower()] = match[2].strip()
    uri = fields.pop('uris', '').rstrip('/')
    enabled = fields.pop('enabled', 'yes').lower()
    arches = set(fields.pop('architectures', '').split())
    return arches <= {'amd64', 'arm64'} and uri == REPOSITORY and enabled == 'yes' and fields == {
        'types': 'deb', 'suites': 'stable', 'components': 'main', 'signed-by': str(KEYRING),
    }


class Apt:
    def __init__(self, source, lists):
        lists.mkdir(parents=True, exist_ok=True)
        self.options = [
            '-o', f'Dir::Etc::sourcelist={source}', '-o', 'Dir::Etc::sourceparts=-',
            '-o', f'Dir::State::lists={lists}',
            '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
            '-o', 'Acquire::AllowInsecureRepositories=false',
            '-o', 'Acquire::AllowDowngradeToInsecureRepositories=false',
            '-o', 'Acquire::https::Verify-Peer=true', '-o', 'Acquire::https::Verify-Host=true',
        ]

    @staticmethod
    def installed():
        versions = {}
        for package in (CORE, MODULE):
            query = subprocess.run(
                ['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', package],
                env=ENVIRONMENT, text=True, capture_output=True, check=False,
            )
            status, _, version = query.stdout.strip().partition('\t')
            if query.returncode == 0 and status == 'installed' and VERSION.fullmatch(version):
                versions[package] = version
        return versions

    def candidates(self, installed):
        subprocess.run(
            ['/usr/bin/apt-get', *self.options, '-o', 'APT::Update::Error-Mode=any',
             '-o', 'Acquire::Retries=1', '-o', 'Acquire::https::Timeout=20', 'update'],
            env=ENVIRONMENT, check=True,
        )
        held = set(subprocess.check_output(
            ['/usr/bin/apt-mark', 'showhold'], env=ENVIRONMENT, text=True,
        ).splitlines())
        result = {}
        for package, current in installed.items():
            if package in held:
                continue
            policy = subprocess.check_output(
                ['/usr/bin/apt-cache', *self.options, 'policy', package],
                env=ENVIRONMENT, text=True,
            )
            candidate = next((line.split(':', 1)[1].strip() for line in policy.splitlines()
                              if line.startswith('  Candidate:')), '')
            if VERSION.fullmatch(candidate) and subprocess.run(
                ['/usr/bin/dpkg', '--compare-versions', candidate, 'gt', current],
                env=ENVIRONMENT, check=False,
            ).returncode == 0:
                result[package] = candidate
        return result

    def install(self, candidates):
        subprocess.run(
            ['/usr/bin/apt-get', *self.options, '-o', 'DPkg::Lock::Timeout=60',
             '-o', 'DPkg::Options::=--force-confdef', '-o', 'DPkg::Options::=--force-confold',
             '--no-remove', '--no-install-recommends', '--only-upgrade', '--assume-yes',
             'install', *(f'{package}={version}' for package, version in candidates.items())],
            env=ENVIRONMENT, check=True,
        )


def get_state(db):
    row = db.execute('SELECT value FROM settings WHERE key=?', (KEY,)).fetchone()
    return json.loads(row[0]) if row else {}


def set_state(db, state, **values):
    state.update(values)
    db.execute('UPDATE settings SET value=? WHERE key=?', (json.dumps(state), KEY))
    db.commit()


def process(db, apt, busy, *, recover=False):
    db.execute('BEGIN IMMEDIATE')
    state = get_state(db)
    phase = state.get('phase')
    if phase in ('checking', 'installing'):
        installed = apt.installed() if apt else Apt.installed()
        candidates = state.get('candidates', {})
        finished = phase == 'installing' and candidates and all(
            installed.get(package) == version for package, version in candidates.items()
        )
        set_state(db, state, phase='installed' if finished else 'failed', installed=installed,
                  candidates={} if finished else candidates, checked_at=int(time.time()))
        return
    if recover or phase not in ('queued', 'install_queued'):
        db.rollback()
        return
    installing = phase == 'install_queued'
    approved = state.get('candidates', {})
    set_state(db, state, phase='installing' if installing else 'checking')
    try:
        installed = apt.installed() if apt else Apt.installed()
        if CORE not in installed or apt is None:
            set_state(db, state, phase='unavailable', installed=installed, candidates={},
                      checked_at=int(time.time()))
            return
        candidates = apt.candidates(installed)
        set_state(db, state, installed=installed, candidates=candidates, checked_at=int(time.time()))
        if not installing:
            set_state(db, state, phase='available' if candidates else 'up_to_date')
            return
        if candidates != approved or not candidates:
            set_state(db, state, phase='changed' if candidates else 'up_to_date')
            return
        active = busy(db)
        if active:
            print(f'Active PXE operations: {", ".join(active)}', file=sys.stderr)
            set_state(db, state, phase='busy')
            return
        apt.install(candidates)
        installed = apt.installed()
        if any(installed.get(package) != version for package, version in candidates.items()):
            raise RuntimeError('APT did not configure the requested package versions')
        set_state(db, state, phase='installed', installed=installed, candidates={})
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'PXE Tools APT update: {error}', file=sys.stderr)
        set_state(db, state, phase='failed', checked_at=int(time.time()))


def main():
    _, *arguments = sys.argv
    if arguments not in ([], ['--recover']):
        raise SystemExit('Invalid APT update service invocation')
    lifecycle_class = runpy.run_path(str(Path(__file__).with_name('upgrade-lifecycle.py')))['Lifecycle']
    database = lifecycle_class().database()
    if database is None:
        return
    with closing(sqlite3.connect(database.as_uri() + '?mode=rw', timeout=5, uri=True)) as db:
        db.execute('PRAGMA trusted_schema=OFF')
        apt = Apt(SOURCE, LISTS) if not arguments and official_source() else None
        process(db, apt, lifecycle_class.busy, recover=bool(arguments))


if __name__ == '__main__':
    main()
