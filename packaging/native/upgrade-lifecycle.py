#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Quiesce a native instance before unpack; resume its previous roles after configure.

This file is embedded in preinst/postrm: the incoming /usr/lib payload is not
available before unpack, including when upgrading beta 5/6. Snapshots are local
root-only recovery material, not an automatic database/schema rollback.
"""
from contextlib import closing
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid


UNITS = (
    'pxe-tools.target', 'pxe-tools-admin.target', 'pxe-tools-worker.service',
    'pxe-tools-dnsmasq-tail.service', 'pxe-tools-nginx.service',
    'pxe-tools-pxe-http.service', 'pxe-tools-php.service',
    'pxe-tools-dnsmasq.service', 'pxe-tools-init.service',
)
NETWORK = {'pxe-tools.target', 'pxe-tools-dnsmasq-tail.service',
           'pxe-tools-pxe-http.service', 'pxe-tools-dnsmasq.service'}
START_ORDER = ('pxe-tools-init.service', 'pxe-tools-php.service', 'pxe-tools-nginx.service',
               'pxe-tools-pxe-http.service', 'pxe-tools-dnsmasq.service',
               'pxe-tools-dnsmasq-tail.service', 'pxe-tools-admin.target',
               'pxe-tools.target', 'pxe-tools-worker.service')
STOP_ORDER = UNITS[:2] + UNITS[2:]
# Undelivered local queue entries can resume with the next worker. Operations
# involving a booted client are deliberately conservative, including pending.
BUSY = (
    ('init_jobs', "status='running'"),
    ('os_images', "status='downloading'"),
    ('actions', "status IN ('pending','running')"),
    ('installations', "install_status='in_progress' OR ansible_status='running'"),
    ('wipes', "wipe_status IN ('pending','running')"),
    ('disk_tests', "job_status IN ('pending','running')"),
    ('discoveries', "discovery_status='running'"),
    ('machines', "status IN ('installing','wiping','testing','inventorying')"),
)


class Lifecycle:
    def __init__(self, root=Path('/'), *, runner=subprocess.run, owner=0):
        self.root = Path(root)
        self.runner = runner
        self.owner = owner
        self.home = self.path('/var/lib/pxe-tools-native/upgrade')
        self.state_file = self.home / 'state.json'

    def path(self, path):
        return self.root / str(path).lstrip('/')

    def systemctl(self, *args, check=True):
        result = self.runner(['systemctl', *args], check=False, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if check and result.returncode:
            # Do not reproduce arbitrary service output (which can contain secrets).
            raise RuntimeError('systemctl ' + args[0] + ' failed; inspect systemd status')
        return result

    def private_home(self):
        # Never place secrets through a symlink or in an administrator-writable
        # runtime ancestor. Existing directory permissions are never weakened.
        for name in ('/var', '/var/lib', '/var/lib/pxe-tools-native',
                     '/var/lib/pxe-tools-native/upgrade'):
            directory = self.path(name)
            if not directory.exists() and not directory.is_symlink():
                directory.mkdir(mode=0o700 if name.endswith('/upgrade') else 0o755)
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RuntimeError('untrusted native upgrade directory; inspect ownership and permissions')
        if stat.S_IMODE(self.home.stat().st_mode) != 0o700:
            raise RuntimeError('native upgrade directory must have mode 0700')

    def save(self, state):
        with tempfile.NamedTemporaryFile(mode='w', dir=self.home, delete=False) as output:
            temporary = Path(output.name)
            json.dump(state, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, self.state_file)
        self.sync_directory(self.home)

    @staticmethod
    def sync_directory(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def digest(path):
        value = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                value.update(block)
        return value.hexdigest()

    def load(self):
        if not self.state_file.exists():
            return None
        info = self.state_file.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise RuntimeError('untrusted native upgrade journal')
        state = json.loads(self.state_file.read_text())
        if (state.get('format') != 1 or set(state.get('units', {})) != set(UNITS)
                or not re.fullmatch(r'[a-f0-9]{32}', state.get('id', ''))):
            raise RuntimeError('invalid native upgrade journal')
        return state

    def environments(self):
        values = {}
        for name in ('/usr/lib/pxe-tools/native/default.env',
                     '/var/lib/pxe-tools-native/network.env',
                     '/var/lib/pxe-tools-native/runtime.env'):
            path = self.path(name)
            if not path.exists() and not path.is_symlink():
                continue
            if not path.is_file() or path.is_symlink():
                raise RuntimeError('invalid native environment file')
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # The generated native environment files use literal assignments.
                # Refuse other syntax rather than interpret shell or guess values.
                match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)=([^\r\n]*)', line)
                if not match:
                    raise RuntimeError('unsupported native environment syntax')
                value = match[2]
                if value.startswith(('"', "'")):
                    if len(value) < 2 or value[-1] != value[0] or '\\' in value:
                        raise RuntimeError('unsupported native environment quoting')
                    value = value[1:-1]
                values[match[1]] = value
        return values

    def database(self):
        environ = self.environments()
        config = self.path('/etc/pxe-tools/db.conf')
        if config.exists() or config.is_symlink():
            if config.is_symlink() or not config.is_file():
                raise RuntimeError('invalid database configuration')
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate configuration key')
                    result[key] = value
                return result
            data = json.loads(config.read_text(), object_pairs_hook=unique)
            if not isinstance(data, dict) or str(data.get('driver', '')).lower() != 'sqlite':
                raise RuntimeError('only SQLite native upgrades are supported; configuration preserved')
            value = data.get('path', '/var/lib/pxe-tools/pxe-tools.sqlite')
            required = True
        else:
            driver = environ.get('PXE_DB_DRIVER', '').lower()
            if driver not in ('', 'sqlite'):
                raise RuntimeError('only SQLite native upgrades are supported')
            value = (environ.get('PXE_DB_PATH') or ('/var/lib/pxe-tools/pxe-tools.sqlite' if driver == 'sqlite' else '') or environ.get('ORCHESTRATOR_DB')
                     or ('/var/lib/pxe-tools/orchestrator.sqlite'
                         if self.path('/var/lib/pxe-tools/orchestrator.sqlite').is_file()
                         else '/var/lib/pxe-tools/pxe-tools.sqlite'))
            required = driver == 'sqlite'
        if (not isinstance(value, str) or not value.startswith('/')
                or any(ord(c) < 32 for c in value) or '..' in Path(value).parts):
            raise RuntimeError('invalid SQLite path')
        path = self.path(value)
        for parent in (path, *path.parents):
            if parent == self.root:
                break
            if parent.is_symlink():
                raise RuntimeError('SQLite path must not traverse symbolic links')
        if not path.exists() and not path.is_symlink() and not required:
            return None
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('SQLite database must be a regular file')
        return path

    def capture(self, version):
        self.check_effective_configuration()
        units = {}
        for unit in UNITS:
            active = self.systemctl('show', '--property=ActiveState', '--value', unit).stdout.strip()
            if active not in ('active', 'inactive', 'failed'):
                raise RuntimeError('PXE Tools services are transitioning; retry the upgrade shortly')
            units[unit] = {'active': active == 'active',
                           'enabled': self.systemctl('is-enabled', unit, check=False).stdout.strip()}
        state = {'format': 1, 'id': uuid.uuid4().hex, 'version': version,
                 'started': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'phase': 'captured', 'units': units}
        self.save(state)
        return state

    def check_effective_configuration(self):
        for unit in ('pxe-tools-worker.service', 'pxe-tools-php.service', 'pxe-tools-init.service'):
            files = self.systemctl('show', '--property=EnvironmentFiles', '--value', unit).stdout.strip()
            expected = ['/usr/lib/pxe-tools/native/default.env']
            if unit != 'pxe-tools-init.service':
                expected.append('/var/lib/pxe-tools-native/network.env')
            expected.append('/var/lib/pxe-tools-native/runtime.env')
            parsed = re.findall(r'(/[^ ]+) \(ignore_errors=(?:yes|no)\)', files)
            if parsed != expected:
                raise RuntimeError('unsupported service EnvironmentFile override; restore the packaged environment-file list before upgrading')
            environment = self.systemctl('show', '--property=Environment', '--value', unit).stdout.strip()
            for assignment in shlex.split(environment):
                key = assignment.partition('=')[0]
                if key in ('PXE_DB_PATH', 'ORCHESTRATOR_DB', 'PXE_DB_DRIVER', 'PXE_MASTER_KEY_PATH'):
                    raise RuntimeError('unsupported service database/key Environment override; use native runtime.env before upgrading')
        command = self.systemctl('show', '--property=ExecStart', '--value', 'pxe-tools-worker.service').stdout
        if not re.search(r'argv\[\]=/usr/bin/python3 /usr/lib/pxe-tools/native/start-worker\.py\s*;', command):
            raise RuntimeError('unsupported worker command override; restore the packaged worker before upgrading')

    def freeze_worker(self, state):
        unit = 'pxe-tools-worker.service'
        if self.systemctl('is-active', '--quiet', unit, check=False).returncode:
            group = self.systemctl('show', '--property=ControlGroup', '--value', unit).stdout.strip()
            if group:
                if not group.startswith('/') or '..' in Path(group).parts:
                    raise RuntimeError('cannot inspect the inactive worker cgroup')
                directory = self.path('/sys/fs/cgroup' + group)
                for item in directory.rglob('cgroup.procs'):
                    if item.read_text().strip():
                        raise RuntimeError('inactive worker still has subprocesses; inspect its systemd status before upgrading')
            return False
        self.systemctl('freeze', unit)
        # Freeze completes before returning. Verify the kernel freezer and all
        # sub-cgroups; a git/bootstrap child without a DB job is still busy.
        group = self.systemctl('show', '--property=ControlGroup', '--value', unit).stdout.strip()
        if not group.startswith('/') or '..' in Path(group).parts:
            raise RuntimeError('cannot inspect the worker cgroup')
        directory = self.path('/sys/fs/cgroup' + group)
        if 'frozen 1' not in (directory / 'cgroup.events').read_text().splitlines():
            raise RuntimeError('worker did not reach a frozen state')
        pid = self.systemctl('show', '--property=MainPID', '--value', unit).stdout.strip()
        processes = set()
        for item in (directory / 'cgroup.procs', *directory.rglob('cgroup.procs')):
            processes.update(item.read_text().split())
        if not pid.isdigit() or pid == '0' or processes != {pid}:
            raise RuntimeError('PXE Tools worker has an active subprocess; wait for it to finish and retry')
        process = self.path('/proc/' + pid)
        before = (process / 'stat').read_text().rpartition(')')[2].split()[19]
        environment = {}
        for value in (process / 'environ').read_bytes().split(b'\0'):
            if b'=' in value:
                key, value = value.split(b'=', 1)
                environment[key.decode()] = value.decode()
        declared = self.environments()
        for key in ('PXE_DB_PATH', 'ORCHESTRATOR_DB', 'PXE_DB_DRIVER', 'PXE_MASTER_KEY_PATH', 'MOK_DIR'):
            if environment.get(key) != declared.get(key):
                raise RuntimeError('running worker database/key environment differs from native files; reconcile its configuration before upgrading')
        after = (process / 'stat').read_text().rpartition(')')[2].split()[19]
        if before != after or self.systemctl('show', '--property=MainPID', '--value', unit).stdout.strip() != pid:
            raise RuntimeError('worker identity changed during quiescence; retry the upgrade')
        return True

    @staticmethod
    def busy(connection):
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not tables:
            return []  # Deliberately unconfigured empty SQLite fixture.
        result = []
        for table, predicate in BUSY:
            # Existing supported schemas have these tables/columns. An unknown
            # schema is not silently interpreted as an idle instance.
            if table not in tables:
                raise RuntimeError('cannot establish quiescence with this database schema')
            row = connection.execute(f'SELECT id FROM {table} WHERE {predicate} LIMIT 1').fetchone()
            if row:
                result.append(table + ' id=' + str(row[0]))
        return result

    def stop(self, state, frozen):
        if frozen:
            # Queue default SIGTERM while every thread is frozen, then thaw.
            # The shipped worker has no SIGTERM handler; it exits before it can
            # spawn a new bootstrap child. systemctl stop by itself thaws first.
            self.systemctl('kill', '--kill-whom=main', '--signal=SIGTERM', 'pxe-tools-worker.service')
            self.systemctl('thaw', 'pxe-tools-worker.service')
        self.systemctl('stop', 'pxe-tools-worker.service')
        self.systemctl('stop', *STOP_ORDER)
        for unit in UNITS:
            if self.systemctl('is-active', '--quiet', unit, check=False).returncode == 0:
                raise RuntimeError('PXE Tools service remained active after stop')
        if 'snapshot' not in state:
            state['phase'] = 'stopped'
        self.save(state)

    def snapshot(self, state, database):
        destination = self.home / state['id']
        destination.mkdir(mode=0o700)
        manifest = {'format': 1, 'automatic': True, 'id': state['id'], 'database': None, 'files': [],
                    'scope': 'SQLite, configuration, native TLS and environment; boot payloads excluded'}

        def metadata(path, relative):
            info = path.lstat()
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise RuntimeError('unsupported entry in configuration snapshot; inspect configuration links')
            manifest['files'].append({'path': str(path.relative_to(self.root)),
                                      'snapshot': str(relative), 'uid': info.st_uid,
                                      'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)})

        environment = self.environments()
        names = {'/etc/pxe-tools', '/var/lib/pxe-tools-native/tls',
                 '/var/lib/pxe-tools-native/network.env', '/var/lib/pxe-tools-native/runtime.env',
                 environment.get('PXE_MASTER_KEY_PATH', '/etc/pxe-tools/master.key'),
                 environment.get('MOK_DIR', '/etc/pxe-tools/mok')}
        for unit in UNITS:
            names.add('/etc/systemd/system/' + unit + '.d')
        copied = set()
        for name in sorted(names):
            if not name.startswith('/') or '..' in Path(name).parts:
                raise RuntimeError('invalid configuration snapshot path')
            source = self.path(name)
            for parent in (source, *source.parents):
                if parent == self.root:
                    break
                if parent.is_symlink():
                    raise RuntimeError('configuration snapshot path must not traverse symbolic links')
            if not source.exists() and not source.is_symlink():
                continue
            entries = (source, *sorted(source.rglob('*'))) if source.is_dir() and not source.is_symlink() else (source,)
            for path in entries:
                if path in copied:
                    continue
                copied.add(path)
                relative = Path('files') / path.relative_to(self.root)
                metadata(path, relative)
                target = destination / relative
                if path.is_dir():
                    target.mkdir(parents=True, mode=0o700, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                    with path.open('rb') as incoming, target.open('xb') as outgoing:
                        os.chmod(target, 0o600)
                        shutil.copyfileobj(incoming, outgoing)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                    manifest['files'][-1]['sha256'] = self.digest(target)
        if database is not None:
            target = destination / 'database.sqlite'
            target.touch(mode=0o600, exist_ok=False)
            with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as source:
                with closing(sqlite3.connect(target)) as backup:
                    source.backup(backup)
                    if backup.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                        raise RuntimeError('SQLite snapshot integrity check failed')
            metadata(database, Path('database.sqlite'))
            manifest['database'] = str(database.relative_to(self.root))
            with target.open('rb') as stream:
                os.fsync(stream.fileno())
            manifest['files'][-1]['sha256'] = self.digest(target)
        manifest_file = destination / 'manifest.json'
        with manifest_file.open('x') as output:
            os.chmod(manifest_file, 0o600)
            json.dump(manifest, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        for directory in sorted((item for item in destination.rglob('*') if item.is_dir()),
                                key=lambda item: len(item.parts), reverse=True):
            self.sync_directory(directory)
        self.sync_directory(destination)
        state['phase'] = 'prepared'
        state['snapshot'] = str(destination.relative_to(self.root))
        self.save(state)
        print('PXE Tools: stopped previous roles; private recovery snapshot prepared (boot payloads excluded).')

    def restore(self, state, *, old=False):
        # Start only the previously active units. Ignore Wants/Requires during
        # replay: the original dependency closure is represented in this list.
        # Otherwise targets can activate roles that the operator had stopped.
        skipped = set()
        failures = []
        for unit in START_ORDER:
            if unit == 'pxe-tools-worker.service':
                continue
            if not state['units'][unit]['active']:
                continue
            if unit in NETWORK and not old and skipped:
                continue
            result = self.systemctl('start', '--job-mode=ignore-dependencies', unit, check=False)
            if result.returncode:
                if unit in NETWORK and not old:
                    skipped.update(NETWORK)
                    self.systemctl('stop', *sorted(NETWORK), check=False)
                    print('PXE Tools: boot network stayed stopped; verify its configured interface/IP and systemd status.', file=sys.stderr)
                else:
                    failures.append(unit)
                    break
        for unit in UNITS:
            enabled = self.systemctl('is-enabled', unit, check=False).stdout.strip()
            if enabled != state['units'][unit]['enabled']:
                failures.append(unit + ' enablement changed')
            if state['units'][unit]['active'] and unit not in skipped and unit != 'pxe-tools-worker.service':
                if self.systemctl('is-active', '--quiet', unit, check=False).returncode:
                    failures.append(unit + ' not active')
            if not state['units'][unit]['active']:
                if self.systemctl('is-active', '--quiet', unit, check=False).returncode == 0:
                    failures.append(unit + ' unexpectedly active')
        if failures:
            raise RuntimeError('previous PXE Tools roles did not resume; inspect systemd status and retry sudo dpkg --configure pxe-tools')
        worker = 'pxe-tools-worker.service'
        if state['units'][worker]['active']:
            self.systemctl('start', '--job-mode=ignore-dependencies', worker)
            if self.systemctl('is-active', '--quiet', worker, check=False).returncode:
                raise RuntimeError('worker did not resume; inspect systemd and retry sudo dpkg --configure pxe-tools')
        return sorted(skipped)

    def prepare(self, version):
        prior = self.load()
        if prior is not None:
            if prior['version'] != version:
                raise RuntimeError('an earlier PXE Tools upgrade is unfinished; run dpkg --configure -a first')
            if prior['phase'] in ('prepared', 'configuring'):
                # A configure retry may have started services before failing.
                # Do not overwrite the pre-migration snapshot with changed DB.
                try:
                    self.quiesce(prior, snapshot=False)
                except Exception:
                    self.systemctl('thaw', 'pxe-tools-worker.service', check=False)
                    print('PXE Tools: retry preparation failed; some previous roles may remain stopped. Original snapshot and journal were kept; correct the service/configuration error and retry the package operation.', file=sys.stderr)
                    raise
                return
            raise RuntimeError('an interrupted PXE Tools preparation requires inspection; journal preserved')
        state = self.capture(version)
        try:
            self.quiesce(state, snapshot=True)
        except Exception:
            try:
                self.systemctl('thaw', 'pxe-tools-worker.service', check=False)
                self.restore(state, old=True)
            except Exception:
                print('PXE Tools: upgrade preparation failed and previous roles could not all resume; inspect systemd and the private upgrade journal.', file=sys.stderr)
            else:
                self.state_file.unlink()
                self.sync_directory(self.home)
            raise

    def quiesce(self, state, *, snapshot):
        self.check_effective_configuration()
        database = self.database()
        connection = None
        try:
            if database is not None:
                connection = sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=15)
                connection.execute('BEGIN IMMEDIATE')
            frozen = self.freeze_worker(state)
            active = self.busy(connection) if connection is not None else []
            if active:
                raise RuntimeError('PXE Tools operations are still active or require reconciliation (' + ', '.join(active)
                                   + '); let them finish or inspect/cancel them in the application, then retry APT')
            self.stop(state, frozen)
        finally:
            self.systemctl('thaw', 'pxe-tools-worker.service', check=False)
            if connection is not None:
                connection.rollback()
                connection.close()
        if self.database() != database:
            raise RuntimeError('database selection changed during upgrade preparation')
        if snapshot:
            self.snapshot(state, database)
        else:
            state['phase'] = 'prepared'
            self.save(state)

    def configure(self):
        state = self.load()
        if state is None:
            return
        if state['phase'] not in ('prepared', 'configuring'):
            raise RuntimeError('upgrade preparation is incomplete; inspect the private upgrade journal')
        # A previous configure can have restored administration while keeping an
        # invalid network stopped. Re-enter the same barrier before retrying.
        self.quiesce(state, snapshot=False)
        state['phase'] = 'configuring'
        self.save(state)
        try:
            skipped = self.restore(state)
        except Exception:
            # A migration can already have committed. Preserve both the original
            # snapshot and journal; subsequent configure retries use new code.
            try:
                self.quiesce(state, snapshot=False)
            except Exception:
                print('PXE Tools: recovery journal retained; running operations prevented a second quiescence, so services were left for inspection.', file=sys.stderr)
            raise
        if skipped:
            state['network_stayed_stopped'] = skipped
            self.save(state)
            raise RuntimeError('boot network could not resume; administration is available. Correct its interface/IP or service error, then run sudo dpkg --configure pxe-tools')
        state['phase'] = 'complete'
        state['network_stayed_stopped'] = skipped
        completion = self.home / state['id'] / 'result.json'
        with completion.open('w') as output:
            os.chmod(completion, 0o600)
            json.dump(state, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        self.state_file.unlink()
        self.sync_directory(self.home)
        self.prune_complete()
        print('PXE Tools: upgrade configured; previously active roles resumed, enablement preserved.')

    def prune_complete(self):
        # Retain three completed automatic snapshots; never remove a pending or
        # manual archive, or anything whose provenance is not our own format.
        completed = []
        for directory in self.home.iterdir():
            if (not re.fullmatch(r'[a-f0-9]{32}', directory.name) or directory.is_symlink()
                    or not directory.is_dir() or directory.stat().st_uid != self.owner
                    or stat.S_IMODE(directory.stat().st_mode) != 0o700):
                continue
            result = directory / 'result.json'
            if not result.is_file() or result.is_symlink():
                continue
            try:
                for record_file in (result, directory / 'manifest.json'):
                    info = record_file.lstat()
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                        raise ValueError('untrusted automatic snapshot record')
                record = json.loads(result.read_text())
                manifest = json.loads((directory / 'manifest.json').read_text())
                if (record.get('format') == 1 and record.get('id') == directory.name
                        and record.get('phase') == 'complete' and manifest.get('format') == 1
                        and manifest.get('automatic') is True and manifest.get('id') == directory.name):
                    completed.append((record['started'], directory))
            except (OSError, ValueError, KeyError):
                continue
        for _, directory in sorted(completed, reverse=True)[3:]:
            shutil.rmtree(directory)


def main():
    os.umask(0o077)
    lifecycle = Lifecycle()
    if not Path('/run/systemd/system').is_dir():
        return
    if sys.argv[1] in ('configure', 'abort') and not (
            lifecycle.state_file.exists() or lifecycle.state_file.is_symlink()):
        # Fresh postinst must not create the native runtime: its first-install
        # provisioning deliberately refuses any pre-existing runtime tree.
        return
    lifecycle.private_home()
    lock = os.open(lifecycle.home / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1] == 'prepare':
            lifecycle.prepare(sys.argv[2])
        elif sys.argv[1] == 'configure':
            lifecycle.configure()
        elif sys.argv[1] == 'abort':
            # dpkg can invoke this after partial unpack. Preparation compensates
            # its own errors, but an unpack error cannot safely replay old code.
            if lifecycle.load() is not None:
                print('PXE Tools: interrupted upgrade kept stopped with its private snapshot; fix the package error and retry configuration. No database rollback was attempted.', file=sys.stderr)
        else:
            raise ValueError('invalid upgrade lifecycle action')
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        print('PXE Tools upgrade: ' + str(error), file=sys.stderr)
        sys.exit(1)
