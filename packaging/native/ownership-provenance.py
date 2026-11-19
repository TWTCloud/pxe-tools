#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Record resources actually created by native PXE Tools package hooks.

The journal is evidence of creation, not an instruction to remove a resource.
Consumers must independently revalidate identity, use and mount boundaries.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat


NATIVE_DIRECTORIES = frozenset(('/var/lib/pxe-tools-native', '/var/lib/pxe-tools-tftp',
                                '/var/lib/pxe-tools-http'))
DIRECTORIES = NATIVE_DIRECTORIES | frozenset(('/etc/pxe-tools', '/var/lib/pxe-tools',
                         '/var/log/pxe-tools', '/var/lib/pxe-tools-ansible'))
RUNTIME_MARKER = (b'TFTP_ROOT=/var/lib/pxe-tools-tftp\n'
                  b'HTTP_ROOT=/var/lib/pxe-tools-http\n'
                  b'PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\n'
                  b'MOK_DIR=/var/lib/pxe-tools-native/mok\n')
ACCOUNT_NAME = 'pxe-tools-ansible'
ACCOUNT_HOME = '/var/lib/pxe-tools-ansible/home'
ACCOUNT_SHELL = '/usr/sbin/nologin'


XATTR_NAME = 'trusted.pxe-tools-ownership'


def _linux_statx(fd):
    """Read Linux birthtime through the already-open FD; no path is resolved."""
    import ctypes
    import struct
    import sys
    if sys.platform != 'linux':
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.statx
        call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_uint, ctypes.c_void_p)
        call.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(256)
        # Linux UAPI: AT_EMPTY_PATH, STATX_INO, STATX_BTIME.
        if call(fd, b'', 0x1000, 0x100 | 0x800, ctypes.byref(buffer)) != 0:
            return None
        data = buffer.raw
        mask = struct.unpack_from('=I', data, 0)[0]
        if mask & (0x100 | 0x800) != (0x100 | 0x800):
            return None
        ino = struct.unpack_from('=Q', data, 32)[0]
        sec, nsec = struct.unpack_from('=qI', data, 80)
        major, minor = struct.unpack_from('=II', data, 136)
        return {'dev': os.makedev(major, minor), 'ino': ino,
                'btime_sec': sec, 'btime_nsec': nsec}
    except (AttributeError, OSError, ValueError, struct.error):
        return None


class Generation:
    """Non-exported directory creation proof using statx and trusted xattr."""
    def __init__(self, *, statx=None, setxattr=None, getxattr=None):
        self.statx = statx if statx is not None else _linux_statx
        self.setxattr = setxattr if setxattr is not None else getattr(os, 'setxattr', None)
        self.getxattr = getxattr if getxattr is not None else getattr(os, 'getxattr', None)

    @staticmethod
    def _weak(info):
        return {'dev': info.st_dev, 'ino': info.st_ino,
                'btime_sec': None, 'btime_nsec': None, 'nonce': None}

    @staticmethod
    def _valid_time(info, observed):
        return (isinstance(observed, dict) and observed.get('dev') == info.st_dev
                and observed.get('ino') == info.st_ino
                and type(observed.get('btime_sec')) is int and observed['btime_sec'] >= 0
                and type(observed.get('btime_nsec')) is int and 0 <= observed['btime_nsec'] < 1000000000)

    def capture(self, fd):
        info = os.fstat(fd)
        weak = self._weak(info)
        try:
            observed = self.statx(fd)
            if not self._valid_time(info, observed) or self.setxattr is None or self.getxattr is None:
                return weak
            nonce = secrets.token_bytes(32)
            self.setxattr(fd, XATTR_NAME, nonce, getattr(os, 'XATTR_CREATE', 1))
            if self.getxattr(fd, XATTR_NAME) != nonce:
                return weak
            return {'dev': info.st_dev, 'ino': info.st_ino,
                    'btime_sec': observed['btime_sec'], 'btime_nsec': observed['btime_nsec'],
                    'nonce': nonce.hex()}
        except (OSError, ValueError, TypeError, KeyError):
            return weak

    def matches(self, fd, proof):
        try:
            info = os.fstat(fd)
            if (not isinstance(proof, dict) or set(proof) != {'dev', 'ino', 'btime_sec', 'btime_nsec', 'nonce'}
                    or proof['dev'] != info.st_dev or proof['ino'] != info.st_ino
                    or not isinstance(proof['nonce'], str) or not re.fullmatch('[0-9a-f]{64}', proof['nonce'])
                    or self.getxattr is None):
                return False
            observed = self.statx(fd)
            return (self._valid_time(info, observed) and observed['btime_sec'] == proof['btime_sec']
                    and observed['btime_nsec'] == proof['btime_nsec']
                    and self.getxattr(fd, XATTR_NAME) == bytes.fromhex(proof['nonce']))
        except (OSError, ValueError, TypeError, KeyError):
            return False


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate ownership field')
        result[key] = value
    return result


def validate(record):
    if (not isinstance(record, dict) or not {'format', 'directories'} <= record.keys()
            or set(record) - {'format', 'directories', 'account', 'base_phase'} or type(record['format']) is not int
            or record['format'] not in (1, 2) or not isinstance(record['directories'], dict)):
        raise ValueError('invalid ownership journal')
    if ('base_phase' in record and record['base_phase'] not in ('runtime-preparing', 'runtime-prepared', 'preparing', 'prepared', 'complete')):
        raise ValueError('invalid base phase')
    if record.get('base_phase') in ('runtime-preparing', 'runtime-prepared'):
        if 'account' in record or not record['directories'].keys() <= NATIVE_DIRECTORIES:
            raise ValueError('unexpected resources in native creation phase')
        if record['base_phase'] == 'runtime-prepared' and set(record['directories']) != NATIVE_DIRECTORIES:
            raise ValueError('incomplete native runtime proof')
    if record.get('base_phase') in ('prepared', 'complete') and not {
            '/etc/pxe-tools', '/var/lib/pxe-tools'} <= record['directories'].keys():
        raise ValueError('incomplete base directory proof')
    for name, identity in record['directories'].items():
        fields = {'dev', 'ino'} if record['format'] == 1 else {'dev', 'ino', 'btime_sec', 'btime_nsec', 'nonce'}
        if (name not in DIRECTORIES or not isinstance(identity, dict) or set(identity) != fields
                or any(type(identity[key]) is not int or identity[key] < 0 for key in ('dev', 'ino'))
                or identity['ino'] == 0):
            raise ValueError('invalid directory proof')
        if record['format'] == 2:
            generation = (identity['btime_sec'], identity['btime_nsec'], identity['nonce'])
            if generation != (None, None, None) and not (
                    type(generation[0]) is int and generation[0] >= 0
                    and type(generation[1]) is int and 0 <= generation[1] < 1000000000
                    and isinstance(generation[2], str) and re.fullmatch(r'[0-9a-f]{64}', generation[2])):
                raise ValueError('invalid directory generation proof')
    if 'account' in record:
        account = record['account']
        if (not isinstance(account, dict) or set(account) != {'name', 'uid', 'gid', 'gecos', 'home', 'shell'}
                or account['name'] != ACCOUNT_NAME or account['home'] != ACCOUNT_HOME
                or account['shell'] != ACCOUNT_SHELL or not isinstance(account['gecos'], str)
                or not re.fullmatch(r'pxe-tools-[0-9a-f]{32}', account['gecos'])
                or any(type(account[key]) is not int or account[key] <= 0 for key in ('uid', 'gid'))):
            raise ValueError('invalid account proof')
    return record


class Store:
    def __init__(self, root=Path('/'), *, owner=0, generation=None):
        self.root = Path(root)
        self.owner = owner
        self.generation = generation if generation is not None else Generation()

    def _safe_dir(self, fd):
        info = os.fstat(fd)
        if info.st_uid != self.owner or info.st_mode & 0o022:
            raise ValueError('unsafe ownership ancestor')

    def _parent(self, components):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in components:
                self._safe_dir(fd)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            self._safe_dir(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextlib.contextmanager
    def _journal_locked(self, *, create=True):
        parent = self._parent(('var', 'lib'))
        directory = lock = None
        created = False
        try:
            if create:
                try:
                    os.mkdir('pxe-tools-ownership', 0o700, dir_fd=parent)
                    os.fsync(parent)
                    created = True
                except FileExistsError:
                    pass
            directory = os.open('pxe-tools-ownership', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            info = os.fstat(directory)
            if info.st_uid != self.owner or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('unsafe ownership directory')
            if not created and not self._exists(directory, 'state.json'):
                raise ValueError('pre-existing ownership directory has no journal; preserved')
            flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if created else 0)
            lock = os.open('lock', flags, 0o600, dir_fd=directory)
            info = os.fstat(lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('unsafe ownership lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield directory
        finally:
            if lock is not None:
                os.close(lock)
            if directory is not None:
                os.close(directory)
            os.close(parent)

    def _open_stable_lock(self, *, create):
        run = self._parent(('run',))
        lockdir = None
        try:
            lockdir = os.open('lock', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=run)
            info = os.fstat(lockdir)
            if (info.st_uid != self.owner or
                    (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
                raise ValueError('unsafe stable ownership lock directory')
            flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
            fd = os.open('pxe-tools-ownership.lock', flags, 0o600, dir_fd=lockdir)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                os.close(fd)
                raise ValueError('unsafe stable ownership lock')
            return fd
        finally:
            if lockdir is not None:
                os.close(lockdir)
            os.close(run)

    @contextlib.contextmanager
    def hold_lock(self):
        # This file is intentionally never removed while the host is running.
        fd = self._open_stable_lock(create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _locked(self, *, create=True, stable_fd=None):
        if stable_fd is None:
            with self.hold_lock() as held:
                with self._journal_locked(create=create) as directory:
                    yield directory
        else:
            check = self._open_stable_lock(create=False)
            try:
                if not os.path.samestat(os.fstat(stable_fd), os.fstat(check)):
                    raise ValueError('external stable lock does not match')
                fcntl.flock(stable_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(check)
            with self._journal_locked(create=create) as directory:
                yield directory

    def _read(self, directory):
        try:
            fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
                raise ValueError('unsafe ownership journal')
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                data = stream.read(65537)
            if len(data) > 65536:
                raise ValueError('oversized ownership journal')
            return validate(json.loads(data, object_pairs_hook=_unique))
        finally:
            if fd is not None:
                os.close(fd)

    def _write(self, directory, record):
        data = (json.dumps(validate(record), sort_keys=True, separators=(',', ':')) + '\n').encode()
        name = '.state-' + secrets.token_hex(16)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, 'state.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass

    def read(self):
        with self._locked(create=False) as directory:
            record = self._read(directory)
            if record is None:
                raise FileNotFoundError('ownership journal absent')
            return record

    @staticmethod
    def _exists(fd, name):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False


    def begin_runtime(self):
        self.refuse_unfinished_uninstall()
        with self._locked() as directory:
            if self._read(directory) is not None:
                raise FileExistsError('existing ownership journal was preserved')
            self._write(directory, {'format': 2, 'directories': {}, 'base_phase': 'runtime-preparing'})

    def record_runtime_created(self, path, opened):
        if path not in NATIVE_DIRECTORIES:
            raise ValueError('unsupported native runtime path')
        parent = self._parent(('var', 'lib'))
        try:
            info = os.fstat(opened)
            current = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISDIR(info.st_mode) or not stat.S_ISDIR(current.st_mode)
                    or info.st_uid != self.owner or info.st_mode & 0o022
                    or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                raise ValueError('new native directory changed before recording')
            proof = self.generation.capture(opened)
            os.fsync(opened)
            os.fsync(parent)
            with self._locked(create=False) as directory:
                record = self._read(directory)
                if record is None or record.get('base_phase') != 'runtime-preparing' or path in record['directories']:
                    raise ValueError('native creation journal unavailable or ambiguous')
                record['directories'][path] = proof
                self._write(directory, record)
        finally:
            os.close(parent)

    def _verify_runtime(self, record, *, held=None):
        if not NATIVE_DIRECTORIES <= record['directories'].keys():
            raise ValueError('native creation proof incomplete')
        parent = self._parent(('var', 'lib'))
        try:
            for path in NATIVE_DIRECTORIES:
                child = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(child)
                    proof = record['directories'][path]
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or info.st_mode & 0o022
                            or (proof['dev'], proof['ino']) != (info.st_dev, info.st_ino)):
                        raise ValueError('native runtime directory changed; preserved')
                    if held is not None and path in held:
                        if not os.path.samestat(info, os.fstat(held[path])):
                            raise ValueError('native runtime directory replaced; preserved')
                    elif record['format'] != 2 or not self.generation.matches(child, proof):
                        raise ValueError('native runtime generation not proven; preserved')
                    if record['format'] == 2 and proof['nonce'] is not None and not self.generation.matches(child, proof):
                        raise ValueError('native runtime generation changed; preserved')
                finally:
                    os.close(child)
            runtime = os.open('pxe-tools-native', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                marker = os.open('runtime.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=runtime)
                try:
                    info = os.fstat(marker)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner or info.st_nlink != 1
                            or info.st_mode & 0o022 or os.read(marker, len(RUNTIME_MARKER) + 1) != RUNTIME_MARKER):
                        raise ValueError('native runtime marker differs; preserved')
                finally:
                    os.close(marker)
            finally:
                os.close(runtime)
        finally:
            os.close(parent)

    def finish_runtime(self, *, held=None):
        with self._locked(create=False) as directory:
            record = self._read(directory)
            if record is None or record.get('base_phase') != 'runtime-preparing':
                raise ValueError('native creation journal unavailable')
            self._verify_runtime(record, held=held)
            record['base_phase'] = 'runtime-prepared'
            self._write(directory, record)

    def resume_missing_runtime(self, *, mounts=None):
        """Recreate only absent, formerly journalled runtime directories.

        A strong generation witness and the exact native marker must survive.
        No existing directory is adopted and no file is deleted. A failure
        between mkdir and recording leaves the new path for manual inspection.
        """
        if mounts is None:
            import sys
            if sys.platform != 'linux':
                raise ValueError('mount inspection requires Linux')
            with open('/proc/self/mountinfo', encoding='utf-8') as stream:
                mounts = [re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), line.split()[4])
                          for line in stream]
        for path in NATIVE_DIRECTORIES:
            target = str(self.root / path.lstrip('/'))
            if any(mount == target or mount.startswith(target + '/') for mount in mounts):
                raise ValueError('mount in native runtime; preserved')
        self.refuse_unfinished_uninstall()
        parent = self._parent(('var', 'lib'))
        try:
            with self._locked(create=False) as journal:
                record = self._read(journal)
                if record is None or record.get('format') != 2 or record.get('base_phase') != 'runtime-prepared':
                    raise ValueError('no resumable native runtime proof')
                if any(item.get('nonce') is None for item in record['directories'].values()):
                    raise ValueError('weak runtime generation proof; preserved')
                missing = []
                for path in sorted(NATIVE_DIRECTORIES):
                    try:
                        child = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    except FileNotFoundError:
                        if path == '/var/lib/pxe-tools-native':
                            raise ValueError('native runtime anchor is absent; preserved')
                        missing.append(path)
                        continue
                    try:
                        info = os.fstat(child)
                        if (info.st_uid != self.owner or info.st_mode & 0o022
                                or not self.generation.matches(child, record['directories'][path])):
                            raise ValueError('native runtime generation changed; preserved')
                        if path != '/var/lib/pxe-tools-native' and os.listdir(child):
                            raise ValueError('native runtime data is not empty; preserved')
                        if path == '/var/lib/pxe-tools-native':
                            if set(os.listdir(child)) != {'runtime.env', 'network.env', 'rendered'}:
                                raise ValueError('native runtime has additional content; preserved')
                            marker = os.open('runtime.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
                            try:
                                info = os.fstat(marker)
                                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                                        or info.st_nlink != 1 or info.st_mode & 0o022
                                        or os.read(marker, len(RUNTIME_MARKER) + 1) != RUNTIME_MARKER):
                                    raise ValueError('native runtime marker differs; preserved')
                            finally:
                                os.close(marker)
                            network = os.open('network.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child)
                            try:
                                info = os.fstat(network)
                                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                                        or info.st_nlink != 1 or info.st_mode & 0o022 or os.read(network, 1)):
                                    raise ValueError('native network configuration changed; preserved')
                            finally:
                                os.close(network)
                            rendered = os.open('rendered', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=child)
                            try:
                                info = os.fstat(rendered)
                                if info.st_uid != self.owner or info.st_mode & 0o022 or os.listdir(rendered):
                                    raise ValueError('native rendered data is not empty; preserved')
                            finally:
                                os.close(rendered)
                    finally:
                        os.close(child)
                for path in missing:
                    name = Path(path).name
                    os.mkdir(name, 0o755, dir_fd=parent)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        os.fchmod(child, 0o755)
                        proof = self.generation.capture(child)
                        if proof['nonce'] is None or not self.generation.matches(child, proof):
                            raise ValueError('new runtime generation could not be proved; preserved')
                        os.fsync(child)
                        os.fsync(parent)
                        record['directories'][path] = proof
                        self._write(journal, record)
                    finally:
                        os.close(child)
                self._verify_runtime(record)
                return tuple(missing)
        finally:
            os.close(parent)

    def create_base(self, *, require_runtime=False, native_fds=None, activate=None):
        # Check both pre-existing data roots before creating anything. Parent
        # directories cannot be replaced by unprivileged users during this step.
        etc = lib = None
        held = {}
        try:
            etc = self._parent(('etc',))
            lib = self._parent(('var', 'lib'))
            if self._exists(etc, 'pxe-tools') or self._exists(lib, 'pxe-tools'):
                raise FileExistsError('existing instance roots were preserved')
            with self._locked(create=not require_runtime) as directory:
                previous = self._read(directory)
                if require_runtime:
                    if previous is None or previous.get('base_phase') != 'runtime-prepared':
                        raise ValueError('native runtime creation proof missing')
                    if previous['format'] != 2:
                        raise ValueError('legacy runtime proof cannot be promoted')
                    self._verify_runtime(previous, held=native_fds)
                    record = previous
                    record['base_phase'] = 'preparing'
                elif previous is None:
                    record = {'format': 2, 'directories': {}, 'base_phase': 'preparing'}
                else:
                    raise FileExistsError('existing ownership journal was preserved')
                self._write(directory, record)
                for parent, name, path in ((etc, 'pxe-tools', '/etc/pxe-tools'),
                                            (lib, 'pxe-tools', '/var/lib/pxe-tools')):
                    os.mkdir(name, 0o755, dir_fd=parent)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    try:
                        os.fchmod(child, 0o755)
                        info = os.fstat(child)
                        proof = self.generation.capture(child)
                        os.fsync(child)
                        os.fsync(parent)
                        record['directories'][path] = proof
                        self._write(directory, record)
                        held[path] = child
                        child = None
                    finally:
                        if child is not None:
                            os.close(child)
                record['base_phase'] = 'prepared'
                self._write(directory, record)
                if activate is not None:
                    activate()
                    if require_runtime:
                        self._verify_runtime(record, held=native_fds)
                    self._finish_base(directory, record, held=held)
        finally:
            for descriptor in held.values():
                os.close(descriptor)
            for descriptor in (lib, etc):
                if descriptor is not None:
                    os.close(descriptor)

    def check_base(self):
        # No metadata is normal for an older installation. An existing but
        # incomplete marker is not treated as absence or silently adopted.
        parent = self._parent(('var', 'lib'))
        try:
            if not self._exists(parent, 'pxe-tools-ownership'):
                return
        finally:
            os.close(parent)
        record = self.read()
        if record.get('base_phase') in ('runtime-preparing', 'runtime-prepared', 'preparing', 'prepared'):
            raise ValueError('incomplete initial PXE Tools setup; inspect ownership journal before retry')

    def recover_initialization(self):
        """Prepare or verify a witnessed initial setup before service start."""
        try:
            record = self.read()
        except FileNotFoundError:
            return False
        phase = record.get('base_phase')
        if phase not in ('runtime-prepared', 'prepared'):
            return False
        if phase == 'runtime-prepared':
            self.resume_missing_runtime()
            # Keep the durable prepared phase until services have been started.
            self.create_base(require_runtime=True)
        with self._locked(create=False) as directory:
            record = self._read(directory)
            self._verify_runtime(record)
            self._finish_base(directory, record, finalize=False)
        return True

    def _finish_base(self, directory, record, *, held=None, finalize=True):
        if record is None or record.get('base_phase') != 'prepared':
            raise ValueError('initial PXE Tools setup was not prepared')
        if record['format'] != 2:
            raise ValueError('legacy instance proof cannot be promoted')
        for path in ('/etc/pxe-tools', '/var/lib/pxe-tools'):
            parts = Path(path).parts[1:]
            parent = self._parent(parts[:-1])
            try:
                child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(child)
                    proof = record['directories'][path]
                    if (proof['dev'], proof['ino']) != (info.st_dev, info.st_ino):
                        raise ValueError('initial PXE Tools directory was replaced')
                    if held is not None and path in held:
                        if not os.path.samestat(info, os.fstat(held[path])):
                            raise ValueError('initial PXE Tools directory was replaced')
                    elif not self.generation.matches(child, proof):
                        raise ValueError('initial PXE Tools generation not proven')
                    if proof['nonce'] is not None and not self.generation.matches(child, proof):
                        raise ValueError('initial PXE Tools generation changed')
                finally:
                    os.close(child)
            finally:
                os.close(parent)
        if finalize:
            record['base_phase'] = 'complete'
            self._write(directory, record)

    def finish_base(self):
        with self._locked(create=False) as directory:
            self._finish_base(directory, self._read(directory))

    def refuse_unfinished_uninstall(self):
        # The optional package may be installed over an older base without the
        # newer lifecycle helper. Inspect the same durable marker without ever
        # following a linked ancestor, and preserve malformed runtime trees.
        parent = self._parent(('var', 'lib'))
        try:
            if any(self._exists(parent, name) for name in ('pxe-tools-uninstall', 'pxe-tools-uninstall-complete', 'pxe-tools-uninstall-aborted')):
                raise ValueError('unfinished PXE Tools uninstall requires inspection')
            for part in ('pxe-tools-native', 'upgrade'):
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                except FileNotFoundError:
                    return
                os.close(parent)
                parent = child
                self._safe_dir(parent)
            if self._exists(parent, 'uninstall-state.json'):
                raise ValueError('unfinished PXE Tools uninstall requires inspection')
        finally:
            os.close(parent)

    def configure_ansible(self, *, accounts=None, groups=None, group_list=None,
                          runner=None, chown=None):
        """Create the dedicated account/workspace or preserve existing ones."""
        import grp
        import pwd
        import subprocess
        accounts = accounts or pwd
        groups = groups or grp
        group_list = group_list or os.getgrouplist
        runner = runner or subprocess.run
        chown = chown or os.fchown
        self.refuse_unfinished_uninstall()
        parent = self._parent(('var', 'lib'))
        try:
            with self._locked() as directory:
                record = self._read(directory)
                if record is None:
                    record = {'format': 2, 'directories': {}}
                    self._write(directory, record)
                if record.get('base_phase') in ('runtime-preparing', 'runtime-prepared', 'preparing', 'prepared'):
                    raise ValueError('incomplete initial PXE Tools setup; Ansible account preserved')
                try:
                    entry = accounts.getpwnam(ACCOUNT_NAME)
                except KeyError:
                    entry = None
                if entry is None:
                    if 'account' in record:
                        raise ValueError('recorded Ansible account disappeared; preserved for review')
                    token = 'pxe-tools-' + secrets.token_hex(16)
                    command = ['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                               '--home-dir', ACCOUNT_HOME, '--shell', ACCOUNT_SHELL,
                               '--comment', token, ACCOUNT_NAME]
                    result = runner(command, check=False)
                    if result.returncode:
                        raise RuntimeError('cannot create dedicated Ansible account')
                    entry = accounts.getpwnam(ACCOUNT_NAME)
                    if entry.pw_gecos != token:
                        raise ValueError('new Ansible account identity did not match')
                    created = True
                else:
                    created = False
                try:
                    group = groups.getgrnam(ACCOUNT_NAME)
                except KeyError as error:
                    raise ValueError('dedicated Ansible group missing') from error
                if (entry.pw_uid <= 0 or entry.pw_gid <= 0 or group.gr_gid != entry.pw_gid
                        or entry.pw_dir != ACCOUNT_HOME or entry.pw_shell != ACCOUNT_SHELL
                        or set(group_list(ACCOUNT_NAME, entry.pw_gid)) != {entry.pw_gid}
                        or set(group.gr_mem) - {ACCOUNT_NAME}):
                    raise ValueError('Ansible account or groups differ; preserved')
                identity = {'name': ACCOUNT_NAME, 'uid': entry.pw_uid, 'gid': entry.pw_gid,
                            'gecos': entry.pw_gecos, 'home': entry.pw_dir, 'shell': entry.pw_shell}
                if 'account' in record and record['account'] != identity:
                    raise ValueError('Ansible account differs from its creation proof; preserved')
                if created and record['format'] == 2:
                    record['account'] = identity
                    self._write(directory, record)
                name = 'pxe-tools-ansible'
                path = '/var/lib/pxe-tools-ansible'
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                    created_root = True
                except FileExistsError:
                    created_root = False
                base = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    if created_root:
                        # Set the private mode while still owner; root may hold
                        # CAP_CHOWN without CAP_FOWNER after transferring it.
                        os.fchmod(base, 0o700)
                        chown(base, entry.pw_uid, entry.pw_gid)
                    info = os.fstat(base)
                    if (info.st_uid != entry.pw_uid or info.st_gid != entry.pw_gid
                            or stat.S_IMODE(info.st_mode) != 0o700):
                        raise ValueError('Ansible workspace ownership or mode differs; preserved')
                    identity = {'dev': info.st_dev, 'ino': info.st_ino}
                    if path in record['directories']:
                        proof = record['directories'][path]
                        if (proof['dev'], proof['ino']) != (info.st_dev, info.st_ino):
                            raise ValueError('Ansible workspace differs from its creation proof; preserved')
                        if record['format'] == 2 and proof['nonce'] is not None and not self.generation.matches(base, proof):
                            raise ValueError('Ansible workspace generation differs; preserved')
                    if created_root and record['format'] == 2:
                        proof = self.generation.capture(base)
                        os.fsync(base)
                        os.fsync(parent)
                        record['directories'][path] = proof
                        self._write(directory, record)
                    for child_name in ('home', 'workspace'):
                        try:
                            os.mkdir(child_name, 0o700, dir_fd=base)
                            made = True
                        except FileExistsError:
                            made = False
                        child = os.open(child_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base)
                        try:
                            if made:
                                os.fchmod(child, 0o700)
                                chown(child, entry.pw_uid, entry.pw_gid)
                            info = os.fstat(child)
                            if (info.st_uid != entry.pw_uid or info.st_gid != entry.pw_gid
                                    or stat.S_IMODE(info.st_mode) != 0o700):
                                raise ValueError('Ansible directory ownership or mode differs; preserved')
                        finally:
                            os.close(child)
                    os.fsync(base)
                finally:
                    os.close(base)
        finally:
            os.close(parent)


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check-base', 'create-base', 'finish-base', 'resume-runtime',
                                           'recover-initialization', 'configure-ansible'))
    options = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('native ownership setup requires root on Linux')
    os.umask(0o077)
    store = Store()
    if options.action == 'check-base':
        store.check_base()
    elif options.action == 'create-base':
        store.refuse_unfinished_uninstall()
        store.create_base(require_runtime=True)
    elif options.action == 'finish-base':
        store.finish_base()
    elif options.action == 'resume-runtime':
        created = store.resume_missing_runtime()
        print('Recreated securely witnessed runtime directories:', ', '.join(created) or 'none')
    elif options.action == 'recover-initialization':
        print('recovered' if store.recover_initialization() else 'unchanged')
    else:
        store.configure_ansible()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        raise SystemExit('PXE Tools ownership: ' + str(exc))
