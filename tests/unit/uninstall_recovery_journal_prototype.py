"""FIXTURE-ONLY SPIKE. Not a recovery format and never used by the CLI.

The plan deliberately omits the dpkg, service, mask, nginx and ownership
state needed for recovery. No deletion or replay may be based on this format.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat

_ALLOWED = frozenset(('/etc/pxe-tools', '/var/lib/pxe-tools',
    '/var/lib/pxe-tools-native', '/var/lib/pxe-tools-http',
    '/var/lib/pxe-tools-tftp', '/var/lib/pxe-tools-ansible', '/var/log/pxe-tools'))
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)


def _plan(value):
    if not isinstance(value, dict) or set(value) != {'trees'}:
        raise ValueError('invalid prototype plan')
    trees = value['trees']
    if (not isinstance(trees, list) or any(not isinstance(t, str) or t not in _ALLOWED for t in trees)
            or len(trees) != len(set(trees))):
        raise ValueError('invalid prototype trees')
    return {'trees': list(trees)}


def _record(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'phase', 'plan'}
            or type(value['version']) is not int or value['version'] != 1
            or value['phase'] not in ('planned', 'quiesced')):
        raise ValueError('invalid prototype record')
    _plan(value['plan'])
    return value


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


class Journal:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root == Path('/'):
            raise ValueError('fixture root required')
        self.owner = os.geteuid()
        self._locks = set()

    def _open_dir(self, parts, private=False):
        fd = os.open(self.root, _DIR)
        try:
            for index, name in enumerate((None, *parts)):
                if name is not None:
                    child = os.open(name, _DIR, dir_fd=fd)
                    os.close(fd)
                    fd = child
                info = os.fstat(fd)
                sticky_lock_dir = index == len(parts) and parts == ('run', 'lock') and bool(info.st_mode & stat.S_ISVTX)
                if info.st_uid != self.owner or (info.st_mode & 0o022 and not sticky_lock_dir):
                    raise ValueError('untrusted directory')
            if private and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                raise ValueError('journal directory is not private')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _file(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('untrusted journal file')

    @contextlib.contextmanager
    def hold_lock(self):
        directory = self._open_dir(('run', 'lock'))
        try:
            fd = os.open('pxe-tools-uninstall.lock', os.O_RDWR | os.O_CREAT | _FILE, 0o600, dir_fd=directory)
            try:
                self._file(os.fstat(fd))
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._locks.add(fd)
                try:
                    yield fd
                finally:
                    self._locks.remove(fd)
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def _check_lock(self, fd):
        if fd not in self._locks:
            raise ValueError('journal lock required')
        directory = self._open_dir(('run', 'lock'))
        try:
            current = os.stat('pxe-tools-uninstall.lock', dir_fd=directory, follow_symlinks=False)
            held = os.fstat(fd)
            self._file(current)
            self._file(held)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise ValueError('journal lock replaced')
        finally:
            os.close(directory)

    def _open_journal(self):
        return self._open_dir(('var', 'lib', 'pxe-tools-uninstall'), private=True)

    def _read(self, directory):
        if set(os.listdir(directory)) != {'state.json'}:
            raise ValueError('incomplete or foreign journal files')
        fd = os.open('state.json', os.O_RDONLY | _FILE, dir_fd=directory)
        try:
            info = os.fstat(fd)
            self._file(info)
            if info.st_size > 65536:
                raise ValueError('journal too large')
            data = b''
            while len(data) <= 65536:
                chunk = os.read(fd, 65537 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) > 65536:
                raise ValueError('journal too large')
            current = os.stat('state.json', dir_fd=directory, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError('journal replaced')
            def no_constant(_):
                raise ValueError('invalid JSON constant')
            try:
                return _record(json.loads(data.decode('utf8'), object_pairs_hook=_pairs, parse_constant=no_constant))
            except (UnicodeError, json.JSONDecodeError, TypeError) as exc:
                raise ValueError('invalid journal JSON') from exc
        finally:
            os.close(fd)

    def read(self, lock):
        self._check_lock(lock)
        directory = self._open_journal()
        try:
            return self._read(directory)
        finally:
            os.close(directory)

    def _write(self, directory, value):
        data = (json.dumps(_record(value), sort_keys=True, separators=(',', ':')) + '\n').encode()
        name = '.state-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE, 0o600, dir_fd=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(data)
                stream.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(name, 'state.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    def create(self, plan, lock):
        self._check_lock(lock)
        value = {'version': 1, 'phase': 'planned', 'plan': _plan(plan)}
        parent = self._open_dir(('var', 'lib'))
        try:
            os.mkdir('pxe-tools-uninstall', 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        directory = self._open_journal()
        try:
            if os.listdir(directory):
                raise ValueError('foreign journal files')
            self._write(directory, value)
            return value
        finally:
            os.close(directory)

    def advance(self, expected, next_phase, lock):
        self._check_lock(lock)
        directory = self._open_journal()
        try:
            value = self._read(directory)
            if expected != 'planned' or next_phase != 'quiesced' or value['phase'] != expected:
                raise ValueError('invalid prototype transition')
            value['phase'] = next_phase
            self._write(directory, value)
            return value
        finally:
            os.close(directory)
