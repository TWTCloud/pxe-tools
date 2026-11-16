#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Native APT removal candidate; validation is not yet complete.

Do not publish or run this candidate on a real host.
"""
import os
from pathlib import Path
import stat

# Only package-specific, historically documented paths. Custom paths require
# explicit inspection; a pathname is never evidence that its target is ours.
TREES = frozenset({
    '/etc/pxe-tools', '/var/lib/pxe-tools', '/var/lib/pxe-tools-native',
    '/var/lib/pxe-tools-http', '/var/lib/pxe-tools-tftp',
    '/var/lib/pxe-tools-ansible', '/var/log/pxe-tools',
})


def _openat2_no_mount(parent, name):
    """Open a child directory without following symlinks or crossing mounts."""
    import ctypes
    import platform
    import sys
    if sys.platform != 'linux' or platform.machine().lower() not in ('x86_64', 'amd64', 'aarch64', 'arm64'):
        raise RuntimeError('Linux openat2 is required to delete instance data safely')
    class OpenHow(ctypes.Structure):
        _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    # RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH
    how = OpenHow(flags, 0, 0x01 | 0x02 | 0x04 | 0x08)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(437), ctypes.c_int(parent),
                          ctypes.c_char_p(os.fsencode(name)), ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)
    return int(result)


def remove_tree(root, name, *, mounts, owner=0, dry_run=False, expected=None, opener=None, generation_matches=None):
    """Delete an allowlisted tree by FD without following a mount or symlink.

    root/opener injection is internal for fixtures and never exposed via CLI.
    """
    import sys
    if name not in TREES:
        raise ValueError('unrecognised removal path')
    if any(m == name or m.startswith(name + '/') for m in mounts):
        raise ValueError('mount within removal path; preserved')
    if opener is None:
        if sys.platform == 'linux':
            opener = _openat2_no_mount
        elif Path(root) != Path('/') and owner != 0:
            # Non-Linux unit fixtures only. The CLI rejects non-Linux hosts.
            opener = lambda parent, child: os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        else:
            raise RuntimeError('Linux openat2 is required to delete instance data safely')
    parts = Path(name).parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        for component in parts[:-1]:
            info = os.fstat(parent)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted removal ancestor')
            try:
                child = os.open(component, flags, dir_fd=parent)
            except FileNotFoundError:
                return
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise ValueError('untrusted removal ancestor')
        try:
            target = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(target.st_mode):
            raise ValueError('removal root is not a directory; preserved')
        if expected is not None and (target.st_dev, target.st_ino) != (expected['dev'], expected['ino']):
            raise ValueError('recorded directory identity changed; preserved')
        target_fd = opener(parent, parts[-1])
        try:
            opened = os.fstat(target_fd)
            if (opened.st_dev, opened.st_ino) != (target.st_dev, target.st_ino):
                raise ValueError('removal root changed during inspection')
            if generation_matches is not None and not generation_matches(target_fd, expected):
                raise ValueError('recorded directory generation changed or cannot be proven')
            if dry_run:
                return
            def descend(directory):
                for child_name in os.listdir(directory):
                    info = os.stat(child_name, dir_fd=directory, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = opener(directory, child_name)
                        try:
                            current = os.fstat(child)
                            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                                raise ValueError('directory changed during removal')
                            descend(child)
                        finally:
                            os.close(child)
                        os.rmdir(child_name, dir_fd=directory)
                    else:
                        os.unlink(child_name, dir_fd=directory)
            descend(target_fd)
        finally:
            os.close(target_fd)
        os.rmdir(parts[-1], dir_fd=parent)
    finally:
        os.close(parent)


def apt_cleanup_plan(root, *, owner=0):
    """Recognise the exact installer source; always retain its APT key."""
    import re
    root = Path(root)
    source = root / 'etc/apt/sources.list.d/pxe-tools.sources'
    template = (r'Types: deb\nURIs: https://packages\.pxetools\.com/apt\n'
                r'Suites: stable\nComponents: main\nArchitectures: amd64\n'
                r'Signed-By: /etc/apt/keyrings/pxe-tools-archive-keyring\.gpg\n')
    try:
        for path in (root, root / 'etc', root / 'etc/apt', source.parent):
            if path.is_symlink() or not path.is_dir():
                return False, False
            info = path.stat()
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                return False, False
        if source.is_symlink() or not source.is_file():
            return False, False
        source_info = source.stat()
        if source_info.st_nlink != 1 or (owner is not None and
                (source_info.st_uid != owner or source_info.st_mode & 0o022)):
            return False, False
        contents = source.read_text(encoding='utf-8')
        if '..' in contents or not re.fullmatch(template, contents):
            return False, False
        # APT can load configuration and sources from nonstandard locations.
        # Until the effective configuration is verified, we cannot prove that
        # no other source uses this key, so the WIP always preserves it.
        return True, False
    except (OSError, UnicodeError):
        return False, False


def parse_mountinfo(data):
    """Extract decoded Linux mountpoints, including bind mounts."""
    import re
    result = []
    for line in data.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields[6:] or not fields[4].startswith('/'):
            raise ValueError('invalid mountinfo; refusing removal')
        mount = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        if '\\' in mount or '\x00' in mount:
            raise ValueError('unsupported mountpoint; refusing removal')
        result.append(mount)
    if not result:
        raise ValueError('empty mountinfo; refusing removal')
    return tuple(result)


def clean_dpkg_environment():
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('DPKG_')}
    environment['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    environment['LC_ALL'] = 'C'
    return environment


def purge_packages(runner, *, frontend_locked):
    """Run dpkg only while the caller owns the real frontend lock."""
    if not frontend_locked:
        raise RuntimeError('dpkg frontend lock is required')
    environment = clean_dpkg_environment()
    environment['DPKG_FRONTEND_LOCKED'] = '1'
    result = runner(['dpkg', '--purge', 'pxe-tools-ansible', 'pxe-tools'],
                    check=False, env=environment)
    if result.returncode:
        raise RuntimeError('package purge failed; packages may be partial; data and APT source were preserved')


def packages_absent(runner):
    """Require a successful exhaustive dpkg status query and fully absent packages."""
    result = runner(['dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Status}\t${db:Status-Eflag}\n'],
                    check=False, text=True, stdout=-1, stderr=-1, timeout=30,
                    env=clean_dpkg_environment())
    if result.returncode or not result.stdout.strip():
        raise RuntimeError('Cannot establish the dpkg package state')
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 3 or not all(fields):
            raise RuntimeError('Incomplete dpkg package state')
        name, status, flag = fields
        if name.partition(':')[0] in ('pxe-tools', 'pxe-tools-ansible'):
            if status != 'not-installed' or flag != 'ok':
                return False
    return True


def dpkg_frontend_lock(path, *, owner=0):
    """Use dpkg's fcntl frontend lock without unlinking its lock file."""
    import fcntl
    from contextlib import contextmanager

    @contextmanager
    def locked():
        path = Path(path_argument)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('unsafe dpkg lock directory')
            descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o640, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                    raise ValueError('unsafe dpkg frontend lock')
                fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
    path_argument = path
    return locked()


def assert_idle_database(lifecycle):
    """Reuse the package's authoritative database selection and busy rules.

    The caller must first prevent services from starting; this function alone
    is not a concurrency barrier.
    """
    import sqlite3
    from contextlib import closing
    database = lifecycle.database()
    if database is None:
        return
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=5)) as connection:
        active = lifecycle.busy(connection)
    if active:
        raise RuntimeError('PXE Tools operations are active: ' + ', '.join(active))


def service_barrier(runner, units, before_mask=lambda: None):
    """Prevent starts during removal; require the operator to stop services.

    Runtime masks created here are reverted; pre-existing masks are preserved.
    """
    from contextlib import contextmanager

    def invoke(*args):
        return runner(['systemctl', *args], check=False, text=True,
                      stdout=-1, stderr=-1, timeout=30)

    def active(unit):
        result = invoke('show', '--property=ActiveState', '--value', unit)
        state = result.stdout.strip()
        if result.returncode or state not in ('inactive', 'failed'):
            raise RuntimeError('Stop PXE Tools only after all operations finish: ' + unit)

    @contextmanager
    def barrier():
        made = []
        for unit in units:
            active(unit)
        before_mask()
        try:
            for unit in units:
                state = invoke('is-enabled', unit).stdout.strip()
                if state in ('masked', 'masked-runtime', 'not-found'):
                    continue
                if state not in ('enabled', 'enabled-runtime', 'disabled', 'static', 'indirect', 'linked', 'linked-runtime', 'generated', 'transient'):
                    raise RuntimeError('Cannot establish unit enablement: ' + unit)
                # Record before the call: a failed systemctl may still have
                # created a runtime symlink before reporting failure.
                made.append(unit)
                if invoke('mask', '--runtime', unit).returncode:
                    raise RuntimeError('Cannot prevent service start: ' + unit)
            for unit in units:
                active(unit)
            yield
        finally:
            failures = [unit for unit in reversed(made)
                        if invoke('unmask', '--runtime', unit).returncode]
            if failures:
                raise RuntimeError('Could not release runtime masks: ' + ', '.join(failures))
    return barrier()


def remove_apt_config(root, *, mounts, owner=0):
    """Remove only the recognised source; preserve the APT key."""
    source_name = '/etc/apt/sources.list.d/pxe-tools.sources'
    source_ok, _ = apt_cleanup_plan(root, owner=owner)

    def mounted(path):
        return any(m != '/' and (path == m or path.startswith(m + '/')) for m in mounts)

    def unlink_checked(path):
        parts = Path(path).parts[1:]
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(root, flags)
        try:
            for part in parts[:-1]:
                info = os.fstat(fd)
                if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                    raise ValueError('untrusted APT ancestor')
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted APT ancestor')
            info = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                raise ValueError('untrusted APT file')
            os.unlink(parts[-1], dir_fd=fd)
        finally:
            os.close(fd)

    if not source_ok or mounted(source_name):
        return False, False
    unlink_checked(source_name)
    return True, False


class BarrierRecoveryRequired(RuntimeError):
    """Mask state is uncertain; preserve the removal journal for recovery."""


def persistent_masks(root, runner, units, transaction, *, owner=0, mounts=()):
    """Install journalled persistent masks for the exact PXE units.

    The temporary hardlink pins each symlink inode through dpkg. A failed purge
    deliberately leaves both names and the durable journal for recovery.
    """
    import secrets
    from contextlib import contextmanager

    @contextmanager
    def barrier():
        names = tuple(units)
        if len(set(names)) != len(names) or any(name not in UNITS for name in names):
            raise ValueError('unsupported service in removal barrier')
        directory_name = '/etc/systemd/system'
        if any(m != '/' and (directory_name == m or directory_name.startswith(m + '/')
                             or m.startswith(directory_name + '/')) for m in mounts):
            raise ValueError('systemd directory crosses a mount boundary')
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        entries = []
        cleanup_attempted = False

        def call(*args):
            return runner(['systemctl', *args], check=False, text=True,
                          stdout=-1, stderr=-1, timeout=30)

        def check_cgroup(unit):
            result = call('show', '--property=ControlGroup', '--value', unit)
            if result.returncode:
                raise RuntimeError('cannot inspect service cgroup: ' + unit)
            group = result.stdout.strip()
            if not group:
                return
            if not group.startswith('/') or group == '/' or '..' in Path(group).parts:
                raise RuntimeError('invalid service cgroup: ' + unit)
            group_name = '/sys/fs/cgroup' + group
            if any(m == group_name or m.startswith(group_name + '/') for m in mounts):
                raise RuntimeError('service cgroup crosses a mount boundary: ' + unit)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(root, flags)
            try:
                for part in ('sys', 'fs', 'cgroup', *Path(group).parts[1:]):
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                def scan(current):
                    process_fd = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
                    try:
                        data = os.read(process_fd, 1_000_001)
                        if len(data) > 1_000_000 or data.strip():
                            raise RuntimeError('service retains processes: ' + unit)
                    finally:
                        os.close(process_fd)
                    with os.scandir(current) as entries:
                        for entry in entries:
                            if entry.is_symlink():
                                raise RuntimeError('linked service cgroup: ' + unit)
                            if entry.is_dir(follow_symlinks=False):
                                child = os.open(entry.name, flags, dir_fd=current)
                                try:
                                    scan(child)
                                finally:
                                    os.close(child)
                scan(descriptor)
            finally:
                os.close(descriptor)

        def info(name):
            try:
                return os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def check_link(name, identity, links):
            item = info(name)
            if (item is None or not stat.S_ISLNK(item.st_mode) or
                    (item.st_dev, item.st_ino) != identity or item.st_nlink != links or
                    (owner is not None and item.st_uid != owner) or
                    os.readlink(name, dir_fd=fd) != '/dev/null'):
                raise RuntimeError('removal mask changed; preserve and inspect: ' + name)

        def cleanup():
            nonlocal cleanup_attempted
            cleanup_attempted = True
            for entry in reversed(entries):
                temporary, unit = entry['temporary'], entry['unit']
                identity = entry['dev'], entry['ino']
                if entry['published']:
                    check_link(temporary, identity, 2)
                    check_link(unit, identity, 2)
                    os.unlink(unit, dir_fd=fd)
                    os.fsync(fd)
                    transaction.record_mask(unit, temporary, *identity, 'removed')
                    check_link(temporary, identity, 1)
                    os.unlink(temporary, dir_fd=fd)
                    os.fsync(fd)
                else:
                    check_link(temporary, identity, 1)
                    if entry['recorded']:
                        transaction.record_mask(unit, temporary, *identity, 'removed')
                    os.unlink(temporary, dir_fd=fd)
                    os.fsync(fd)
            if entries and call('daemon-reload').returncode:
                raise RuntimeError('systemd reload failed after mask cleanup')

        def safe_cleanup():
            try:
                cleanup()
            except Exception as error:
                raise BarrierRecoveryRequired('persistent mask cleanup requires recovery: ' + str(error)) from error

        try:
            for component in ('etc', 'systemd', 'system'):
                parent = os.fstat(fd)
                if owner is not None and (parent.st_uid != owner or parent.st_mode & 0o022):
                    raise ValueError('untrusted systemd ancestor')
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            parent = os.fstat(fd)
            if owner is not None and (parent.st_uid != owner or parent.st_mode & 0o022):
                raise ValueError('untrusted systemd directory')
            # Preflight all targets before publishing any mask.
            to_create = []
            for unit in names:
                status = call('show', '--property=ActiveState', '--value', unit)
                if status.returncode or status.stdout.strip() not in ('inactive', 'failed'):
                    raise RuntimeError('service is not quiescent: ' + unit)
                check_cgroup(unit)
                existing = info(unit)
                if existing is None:
                    to_create.append(unit)
                elif not (stat.S_ISLNK(existing.st_mode) and os.readlink(unit, dir_fd=fd) == '/dev/null'):
                    raise RuntimeError('local unit or alias requires review: ' + unit)
            for unit in to_create:
                temporary = '.pxe-uninstall-' + secrets.token_hex(16) + '-' + unit
                os.symlink('/dev/null', temporary, dir_fd=fd)
                os.fsync(fd)
                created = info(temporary)
                if created is None or not stat.S_ISLNK(created.st_mode) or created.st_nlink != 1:
                    raise RuntimeError('cannot establish temporary mask identity')
                identity = created.st_dev, created.st_ino
                entry = {'unit': unit, 'temporary': temporary, 'dev': identity[0],
                         'ino': identity[1], 'recorded': False, 'published': False}
                entries.append(entry)
                transaction.record_mask(unit, temporary, *identity, 'prepared')
                entry['recorded'] = True
                os.link(temporary, unit, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
                entry['published'] = True
                os.fsync(fd)
                check_link(temporary, identity, 2)
                check_link(unit, identity, 2)
                transaction.record_mask(unit, temporary, *identity, 'published')
            if entries and call('daemon-reload').returncode:
                raise RuntimeError('systemd reload failed when applying masks')
            for unit in names:
                active = call('show', '--property=ActiveState', '--value', unit)
                loaded = call('show', '--property=LoadState', '--value', unit)
                if (active.returncode or active.stdout.strip() not in ('inactive', 'failed') or
                        loaded.returncode or loaded.stdout.strip() != 'masked'):
                    raise RuntimeError('service mask or idle state could not be verified: ' + unit)
                check_cgroup(unit)
            try:
                yield
            except BaseException:
                if not transaction.purge_started:
                    safe_cleanup()
                raise
            else:
                safe_cleanup()
        except BaseException:
            # Failures before the yield need the same pre-purge compensation.
            # Do not retry cleanup after it itself reports uncertain ownership.
            if entries and not transaction.purge_started and not cleanup_attempted:
                safe_cleanup()
            raise
        finally:
            os.close(fd)
    return barrier()


def _open_private_journal(root, name, owner, mounts):
    allowed = {'/var/lib/pxe-tools-ownership', '/var/lib/pxe-tools-nginx-ownership'}
    if name not in allowed:
        raise ValueError('unsupported private journal')
    if any(m == name or m.startswith(name + '/') for m in mounts):
        raise ValueError('private journal crosses a mount boundary')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ('var', 'lib', Path(name).name):
            current = os.fstat(fd)
            if owner is not None and (current.st_uid != owner or current.st_mode & 0o022):
                raise ValueError('untrusted journal ancestor')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        current = os.fstat(fd)
        if (owner is not None and current.st_uid != owner) or stat.S_IMODE(current.st_mode) != 0o700:
            raise ValueError('untrusted private journal directory')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _journal_identities(fd, owner):
    if set(os.listdir(fd)) != {'state.json', 'lock'}:
        raise ValueError('unknown private journal files; preserved')
    result = {}
    for name in ('state.json', 'lock'):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600 or (owner is not None and info.st_uid != owner)):
            raise ValueError('untrusted private journal file')
        result[name] = (info.st_dev, info.st_ino)
    info = os.fstat(fd)
    result['directory'] = (info.st_dev, info.st_ino)
    return result


def _journal_bytes(fd):
    child = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(child)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2_000_000:
            raise ValueError('untrusted private journal contents')
        with os.fdopen(child, 'rb') as stream:
            child = None
            value = stream.read(2_000_001)
        if len(value) > 2_000_000:
            raise ValueError('oversized private journal')
        return value
    finally:
        if child is not None:
            os.close(child)


def remove_private_journal(root, name, fd, *, owner=0, mounts=(), identities, expected_bytes):
    """Remove known metadata only while the caller still holds its lock."""
    check = _open_private_journal(root, name, owner, mounts)
    try:
        if (_journal_identities(fd, owner) != identities or _journal_identities(check, owner) != identities
                or _journal_bytes(fd) != expected_bytes):
            raise ValueError('private journal identity or contents changed; preserved')
        parent = os.open(Path(root) / 'var/lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.stat(Path(name).name, dir_fd=parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != identities['directory']:
                raise ValueError('private journal was replaced')
            os.unlink('state.json', dir_fd=fd)
            os.fsync(fd)
            os.unlink('lock', dir_fd=fd)
            os.fsync(fd)
            os.rmdir(Path(name).name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.close(check)


def nginx_journal_guard(root, reconciler, *, owner=0, mounts=()):
    """Lock and validate #61 metadata; never mutate nginx itself."""
    import fcntl
    import json
    from contextlib import contextmanager
    from types import SimpleNamespace

    def unique(pairs):
        values = {}
        for key, value in pairs:
            if key in values:
                raise ValueError('duplicate nginx journal field')
            values[key] = value
        return values

    @contextmanager
    def guarded():
        name = '/var/lib/pxe-tools-nginx-ownership'
        try:
            fd = _open_private_journal(root, name, owner, mounts)
        except FileNotFoundError:
            yield None
            return
        lock = None
        try:
            identities = _journal_identities(fd, owner)
            lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(lock)
            if (info.st_dev, info.st_ino) != identities['lock']:
                raise ValueError('nginx journal lock changed')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            state_fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(state_fd)
                if (info.st_dev, info.st_ino) != identities['state.json'] or info.st_size > 2_000_000:
                    raise ValueError('nginx journal changed or too large')
                with os.fdopen(state_fd, 'rb') as stream:
                    state_fd = None
                    data = stream.read(2_000_001)
                if len(data) > 2_000_000:
                    raise ValueError('nginx journal too large')
                record = json.loads(data, object_pairs_hook=unique)
            finally:
                if state_fd is not None:
                    os.close(state_fd)
            if (not isinstance(record, dict) or set(record) != {'format', 'service', 'phase', 'before', 'after', 'resources', 'identity', 'provenance'}
                    or type(record['format']) is not int or record['format'] != 1
                    or record['service'] != 'nginx.service' or record['phase'] != 'complete'
                    or record['before'] != {'active': 'active', 'enabled': 'enabled'}
                    or record['after'] != {'active': 'inactive', 'enabled': 'disabled'}
                    or not isinstance(record['resources'], dict) or not isinstance(record['identity'], dict)):
                raise ValueError('nginx journal is incomplete or invalid')
            provenance = record['provenance']
            expected = {'source', 'start', 'end', 'core', 'initial_packages', 'nginx_previously_absent'}
            if (not isinstance(provenance, dict) or set(provenance) != expected or
                    provenance['source'] != 'apt-and-dpkg' or provenance['nginx_previously_absent'] is not True or
                    provenance['core'] != 'pxe-tools' or not isinstance(provenance['start'], str) or
                    not isinstance(provenance['initial_packages'], dict) or
                    set(provenance['initial_packages']) != {'nginx', 'nginx-common', 'pxe-tools'} or
                    not all(isinstance(v, str) and v for v in provenance['initial_packages'].values())):
                raise ValueError('nginx origin or administrator intent is ambiguous; preserved')
            if reconciler is None:
                raise ValueError('nginx reconciliation helper unavailable')
            try:
                current = reconciler.state()
                if (current['ActiveState'] != 'inactive' or current['UnitFileState'] != 'disabled' or
                        reconciler.stock() != record['resources']):
                    raise ValueError('nginx state or resources changed; preserved')
            except Exception as error:
                raise ValueError('nginx state cannot be revalidated; preserved') from error
            if _journal_identities(fd, owner) != identities:
                raise ValueError('nginx journal changed during inspection')
            yield SimpleNamespace(fd=fd, record=record, identities=identities, contents=data)
        finally:
            if lock is not None:
                os.close(lock)
            os.close(fd)
    return guarded()


def proven_tree_paths(root, *, owner=0, record=None, generation_matches=None):
    """Identify only directories recorded by the creation transaction."""
    if record is None:
        return ()
    if (not isinstance(record, dict) or record.get('format') != 2 or generation_matches is None or
            record.get('base_phase') != 'complete' or not isinstance(record.get('directories'), dict)):
        raise ValueError('ownership journal is incomplete or invalid')
    directories = record['directories']
    if not {'/etc/pxe-tools', '/var/lib/pxe-tools'} <= directories.keys():
        raise ValueError('base directory provenance is incomplete')
    for path, expected in directories.items():
        if (path not in TREES or not isinstance(expected, dict) or
                set(expected) != {'dev', 'ino', 'btime_sec', 'btime_nsec', 'nonce'} or
                any(type(expected[key]) is not int or expected[key] < 0 for key in ('dev', 'ino', 'btime_sec', 'btime_nsec')) or
                expected['ino'] == 0 or expected['btime_nsec'] >= 1000000000 or
                not isinstance(expected['nonce'], str) or len(expected['nonce']) != 64):
            raise ValueError('invalid recorded directory')
        remove_tree(root, path, mounts=(), owner=owner, dry_run=True, expected=expected, generation_matches=generation_matches)
    # A workspace used by a pre-existing, unproven account may be shared.
    eligible = set(directories)
    if 'account' not in record:
        eligible.discard('/var/lib/pxe-tools-ansible')
    # Keep the runtime, which contains the removal journal and lock, until last.
    return tuple(sorted((p for p in eligible if p != '/var/lib/pxe-tools-native')) +
                 (['/var/lib/pxe-tools-native'] if '/var/lib/pxe-tools-native' in eligible else []))


def run_uninstall(root, runner, lifecycle, units, mounts_provider, *, owner=0, apply=False, record=None, ownership=None, reconciler=None, account_lookup=None):
    """Prepare a bounded transaction. The root override is internal for tests."""
    root = Path(root)
    generation_matches = ownership.generation.matches if ownership is not None else None
    paths = proven_tree_paths(root, owner=owner, record=record, generation_matches=generation_matches)
    mounts = mounts_provider()
    for path in paths:
        remove_tree(root, path, mounts=mounts, owner=owner, dry_run=True, expected=record['directories'][path], generation_matches=generation_matches)
    source, key = apt_cleanup_plan(root, owner=owner)
    preserved = tuple(path for path in sorted(TREES) if path not in paths and
                      ((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink()))
    # Issue #61 records nginx state outside the application runtime. Until its
    # restore contract is implemented, refuse rather than leave an unrelated
    # service in a product-induced state or undo an administrator's choice.
    nginx_path = '/var/lib/pxe-tools-nginx-ownership'
    nginx = root / nginx_path.lstrip('/')
    nginx_present = nginx.exists() or nginx.is_symlink()
    if nginx_present and reconciler is None:
        preserved += (nginx_path,)
    elif nginx_present and not apply:
        with nginx_journal_guard(root, reconciler, owner=owner, mounts=mounts):
            pass
    plan = {'trees': paths, 'source': source, 'key': key, 'preserved': preserved}
    if not apply:
        return plan
    if preserved:
        raise RuntimeError('Cannot establish ownership of all instance paths; no package was removed')
    critical = ('/etc/pxe-tools', '/var/lib/pxe-tools', '/var/lib/pxe-tools-native')
    if lifecycle is None and any((root / p.lstrip('/')).exists() or
                                 (root / p.lstrip('/')).is_symlink() for p in critical):
        raise RuntimeError('Cannot establish whether previous PXE operations are active; preserve data and inspect the partial installation')
    with dpkg_frontend_lock(root / 'var/lib/dpkg/lock-frontend', owner=owner):
        from contextlib import nullcontext
        if record is not None and ownership is None:
            raise RuntimeError('Ownership lock is unavailable; no package was removed')
        context = ownership._locked(create=False) if record is not None else nullcontext(None)
        with context as ownership_fd:
            if record is not None and ownership._read(ownership_fd) != record:
                raise RuntimeError('ownership journal changed; no package was removed')
            ownership_identities = _journal_identities(ownership_fd, owner) if record is not None else None
            ownership_contents = _journal_bytes(ownership_fd) if record is not None else None
            if reconciler is not None and not callable(getattr(reconciler, 'stable_lock', None)):
                raise RuntimeError('Stable nginx reconciliation lock is unavailable')
            nginx_lock = reconciler.stable_lock() if reconciler is not None else nullcontext()
            with nginx_lock, nginx_journal_guard(root, reconciler, owner=owner, mounts=mounts_provider()) as nginx_journal:
                if lifecycle is None:
                    if not packages_absent(runner):
                        raise RuntimeError('Installed or partial package lacks the lifecycle safety helper')
                    for unit in units:
                        status = runner(['systemctl', 'show', '--property=ActiveState', '--value', unit],
                                        check=False, text=True, stdout=-1, stderr=-1, timeout=30)
                        if status.returncode or status.stdout.strip() not in ('inactive', 'failed'):
                            raise RuntimeError('A PXE Tools service is still active: ' + unit)
                    source_removed, key_removed = remove_apt_config(root, mounts=mounts_provider(), owner=owner)
                    plan.update(source_removed=source_removed, key_removed=key_removed)
                    return plan
                validate_product_units(root, runner, units, owner=owner)
                with upgrade_guard(lifecycle, owner=owner):
                    if record is not None and record.get('account') is not None and account_lookup is None:
                        raise RuntimeError('Ansible account inventory is unavailable; no package was removed')
                    storage = storage_snapshot(lifecycle)
                    outside = external_paths(lifecycle, paths)
                    if any((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink() for path in outside):
                        raise RuntimeError('external storage requires review; no package was removed')
                    if account_lookup is not None:
                        accounts = account_lookup()
                        validate_account(record or {}, accounts['accounts'], accounts['groups'], accounts['process_uids'])
                    def after_stop(transaction):
                        return persistent_masks(root, runner, units, transaction,
                                                owner=owner, mounts=mounts_provider())
                    with quiesced_lifecycle(lifecycle, after_stop=after_stop) as transaction:
                        assert_idle_database(lifecycle)
                        if storage_snapshot(lifecycle) != storage:
                            raise RuntimeError('storage configuration changed; no package was removed')
                        outside = external_paths(lifecycle, paths)
                        if any((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink() for path in outside):
                            raise RuntimeError('external storage requires review; no package was removed')
                        if account_lookup is not None:
                            accounts = account_lookup()
                            validate_account(record or {}, accounts['accounts'], accounts['groups'], accounts['process_uids'])
                        mounts = mounts_provider()
                        for path in paths:
                            remove_tree(root, path, mounts=mounts, owner=owner, dry_run=True, expected=record['directories'][path], generation_matches=generation_matches)
                        transaction.begin_purge()
                        purge_packages(runner, frontend_locked=True)
                        if not packages_absent(runner):
                            raise RuntimeError('Package purge did not leave both packages absent; data preserved')
                        try:
                            if account_lookup is not None and record is not None:
                                remove_account(record, runner, account_lookup)
                                if record.get('account') is not None:
                                    remove_group(record, runner, account_lookup)
                            # Keep the native journal and lock until masks are removed.
                            for path in paths:
                                if path != '/var/lib/pxe-tools-native':
                                    remove_tree(root, path, mounts=mounts_provider(), owner=owner, expected=record['directories'][path], generation_matches=generation_matches)
                            source_removed, key_removed = remove_apt_config(root, mounts=mounts_provider(), owner=owner)
                            plan.update(source_removed=source_removed, key_removed=key_removed)
                        except (OSError, ValueError, RuntimeError) as error:
                            raise RuntimeError('Package purge succeeded, but data or APT cleanup is incomplete: ' + str(error)) from error
                    if '/var/lib/pxe-tools-native' in paths:
                        try:
                            remove_tree(root, '/var/lib/pxe-tools-native', mounts=mounts_provider(), owner=owner, expected=record['directories']['/var/lib/pxe-tools-native'], generation_matches=generation_matches)
                        except (OSError, ValueError, RuntimeError) as error:
                            raise RuntimeError('Package purge succeeded, but native journal cleanup is incomplete: ' + str(error)) from error
                if nginx_journal is not None:
                    try:
                        current = reconciler.state()
                        if (current['ActiveState'] != 'inactive' or current['UnitFileState'] != 'disabled' or
                                reconciler.stock() != nginx_journal.record['resources']):
                            raise ValueError('nginx state or resources changed')
                        remove_private_journal(root, '/var/lib/pxe-tools-nginx-ownership', nginx_journal.fd,
                                               owner=owner, mounts=mounts_provider(), identities=nginx_journal.identities, expected_bytes=nginx_journal.contents)
                    except Exception as error:
                        raise RuntimeError('Package purge succeeded, but nginx provenance is preserved: ' + str(error)) from error
                if record is not None:
                    try:
                        if ownership._read(ownership_fd) != record:
                            raise ValueError('ownership journal changed')
                        remove_private_journal(root, '/var/lib/pxe-tools-ownership', ownership_fd,
                                               owner=owner, mounts=mounts_provider(), identities=ownership_identities, expected_bytes=ownership_contents)
                    except (OSError, ValueError, RuntimeError) as error:
                        raise RuntimeError('Package purge succeeded, but ownership cleanup is incomplete: ' + str(error)) from error
                return plan


def installer_lock(path, *, owner=0):
    """Coordinate with the native installer without following lock symlinks."""
    import fcntl
    from contextlib import contextmanager

    @contextmanager
    def lock():
        path = Path(path_argument)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if owner is not None and (info.st_uid != owner or
                    (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
                raise ValueError('unsafe installer lock directory')
            descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                        (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                    raise ValueError('unsafe installer lock')
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
    path_argument = path
    return lock()


def parse_arguments(argv):
    import argparse
    parser = argparse.ArgumentParser(description=(
        'Remove the native APT packages and recognised PXE Tools instance data. '
        'Data, database, local secrets, TLS/MOK files and local upgrade snapshots '
        'may be destroyed. Keep a verified external backup first. '
        'This does not remove Docker installations.'))
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--dry-run', action='store_true', help='inspect the proposed removal (default)')
    choice.add_argument('--yes', action='store_true', help='explicitly authorise destructive removal')
    return parser.parse_args(argv)


def load_package_helper(root, filename, *, owner=0):
    """Load a specific installed helper without following links."""
    if filename not in ('upgrade-lifecycle.py', 'ownership-provenance.py', 'reconcile-nginx.py'):
        raise ValueError('unsupported package helper')
    import types
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in ('usr', 'lib', 'pxe-tools', 'native'):
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted lifecycle ancestor')
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                return None
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise ValueError('untrusted lifecycle ancestor')
        try:
            child = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_000_000 or
                    (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                raise ValueError('untrusted lifecycle helper')
            with os.fdopen(child, 'rb') as stream:
                child = None
                data = stream.read(1_000_001)
            if len(data) > 1_000_000:
                raise ValueError('oversized lifecycle helper')
        finally:
            if child is not None:
                os.close(child)
    finally:
        os.close(fd)
    module = types.ModuleType('pxe_tools_installed_lifecycle')
    module.__file__ = '/usr/lib/pxe-tools/native/' + filename
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module


def load_lifecycle(root, *, owner=0):
    module = load_package_helper(root, 'upgrade-lifecycle.py', owner=owner)
    return module.Lifecycle(Path(root)) if module is not None else None


def load_ownership(root, *, owner=0):
    module = load_package_helper(root, 'ownership-provenance.py', owner=owner)
    return module.Store(Path(root), owner=owner) if module is not None else None


def load_reconciler(root, runner, *, owner=0):
    module = load_package_helper(root, 'reconcile-nginx.py', owner=owner)
    if module is None:
        return None
    reconciler = module.Reconciler(Path(root), run=runner)
    reconciler.stable_lock = lambda: module.stable_nginx_lock(Path(root), owner=owner)
    return reconciler


def _check_worker_not_prepaused(lifecycle):
    """Refuse pre-existing freezes or stopped threads before removal mutates anything.

    This cannot serialize an uncooperative administrator changing freezer or
    signal state concurrently; removal remains gated pending the Linux recipe.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    status = lifecycle.worker_status()
    if status.get('FreezerState') != 'running' or status.get('ActiveState') not in ('active', 'inactive', 'failed'):
        raise RuntimeError('worker freezer state is not safely running')
    group = status.get('ControlGroup', '')
    pid = status.get('MainPID', '')
    if not group:
        if status['ActiveState'] not in ('inactive', 'failed') or pid != '0':
            raise RuntimeError('worker identity cannot be established')
        if lifecycle.worker_status() != status:
            raise RuntimeError('worker state changed during inspection')
        return
    if (not group.startswith('/') or group == '/' or '..' in Path(group).parts
            or (status['ActiveState'] == 'active' and (not pid.isdecimal() or pid == '0'))
            or (status['ActiveState'] != 'active' and pid != '0')):
        raise RuntimeError('worker identity or cgroup cannot be established')

    def open_dir(parts):
        fd = os.open(lifecycle.root, flags)
        try:
            for part in parts:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_file(fd, name, *, raw=False):
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            value = os.read(child, 1000001)
            if len(value) > 1000000:
                raise RuntimeError('worker state exceeds inspection limit')
            return value if raw else value.decode('ascii')
        finally:
            os.close(child)

    def proc_stat(directory, name, expected):
        text = read_file(directory, name, raw=True)
        prefix, separator, suffix = text.rpartition(b')')
        fields = suffix.split()
        if (not separator or not prefix.startswith(expected.encode('ascii') + b' (') or len(fields) < 20
                or fields[0] not in (b'R', b'S', b'D', b'I') or not fields[19].isdigit()):
            raise RuntimeError('worker process is stopped or its state cannot be established')
        return fields[19]

    try:
        def check_freezer(fd):
            events = [line.split() for line in read_file(fd, 'cgroup.events').splitlines()]
            frozen = [entry for entry in events if entry and entry[0] == 'frozen']
            if frozen != [['frozen', '0']] or read_file(fd, 'cgroup.freeze').strip() != '0':
                raise RuntimeError('worker cgroup or ancestor is frozen or uncertain')

        def check_ancestors():
            parts = Path(group).parts[1:]
            # cgroup v2 does not expose cgroup.freeze on its hierarchy root.
            for end in range(1, len(parts)):
                ancestor = open_dir(('sys', 'fs', 'cgroup', *parts[:end]))
                try:
                    check_freezer(ancestor)
                finally:
                    os.close(ancestor)

        check_ancestors()
        directory = open_dir(('sys', 'fs', 'cgroup', *Path(group).parts[1:]))
        try:
            def scan(fd):
                check_freezer(fd)
                processes = read_file(fd, 'cgroup.procs').split()
                if any(not item.isdecimal() or item == '0' for item in processes):
                    raise RuntimeError('worker cgroup processes cannot be established')
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            raise RuntimeError('linked worker cgroup')
                        if entry.is_dir(follow_symlinks=False):
                            child = os.open(entry.name, flags, dir_fd=fd)
                            try:
                                processes.extend(scan(child))
                            finally:
                                os.close(child)
                return processes
            processes = scan(directory)
            if sorted(processes) != ([pid] if pid != '0' else []):
                raise RuntimeError('worker cgroup has unexpected processes')
            if pid != '0':
                process = open_dir(('proc', pid))
                try:
                    started = proc_stat(process, 'stat', pid)
                    task = os.open('task', flags, dir_fd=process)
                    try:
                        threads = os.listdir(task)
                        if pid not in threads or any(not name.isdecimal() for name in threads):
                            raise RuntimeError('worker threads cannot be established')
                        for tid in threads:
                            thread = os.open(tid, flags, dir_fd=task)
                            try:
                                thread_started = proc_stat(thread, 'stat', tid)
                                if tid == pid and thread_started != started:
                                    raise RuntimeError('worker identity changed')
                            finally:
                                os.close(thread)
                        if set(os.listdir(task)) != set(threads):
                            raise RuntimeError('worker threads changed during inspection')
                    finally:
                        os.close(task)
                    if proc_stat(process, 'stat', pid) != started:
                        raise RuntimeError('worker identity changed')
                finally:
                    os.close(process)
            check_ancestors()
            if scan(directory) != processes or lifecycle.worker_status() != status:
                raise RuntimeError('worker state changed during inspection')
        finally:
            os.close(directory)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError('cannot safely inspect worker state') from error


def quiesced_lifecycle(lifecycle, *, after_stop=None):
    """Quiesce active units using a separate durable removal journal.

    Call while holding the upgrade guard. Before dpkg, compensate only if an
    actual stop was attempted. Once purge intent is durable, never auto-restore
    a possibly partial installation.
    """
    from contextlib import contextmanager, ExitStack

    @contextmanager
    def guarded():
        if lifecycle.load() is not None:
            raise RuntimeError('an earlier upgrade requires recovery')
        removal_file = lifecycle.home / 'uninstall-state.json'
        if removal_file.exists() or removal_file.is_symlink():
            raise RuntimeError('an earlier uninstall requires recovery')
        _check_worker_not_prepaused(lifecycle)
        original_file = lifecycle.state_file
        lifecycle.state_file = removal_file
        original_busy = lifecycle.busy
        original_stop = lifecycle.stop
        original_freeze = lifecycle.freeze_worker
        original_release = lifecycle.release_worker
        override_keys = ('busy', 'stop', 'freeze_worker', 'release_worker')
        overrides = {key: lifecycle.__dict__.get(key) for key in override_keys}
        present = {key: key in lifecycle.__dict__ for key in override_keys}
        state = None
        stop_started = False
        freeze_confirmed = False

        class Transaction:
            purge_started = False
            def record_mask(self, unit, temporary, dev, ino, phase):
                state.setdefault('removal_masks', {})[unit] = {
                    'temporary': temporary, 'dev': dev, 'ino': ino, 'phase': phase}
                lifecycle.save(state)
            def begin_purge(self):
                state['phase'] = 'purge_started'
                lifecycle.save(state)
                self.purge_started = True

        transaction = Transaction()

        def removal_busy(connection):
            found = list(original_busy(connection))
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables:
                return found
            predicates = (
                ('installations', "install_status IN ('pending','running','installing','in_progress') OR ansible_status IN ('pending','running','in_progress')"),
                ('discoveries', "discovery_status IN ('pending','running','in_progress')"),
                ('init_jobs', "status IN ('pending','running') AND (job_type LIKE 'machine:reboot:%' OR job_type LIKE 'machine:shutdown:%' OR job_type LIKE 'machine:ansible_redeploy:%' OR job_type LIKE 'action:reboot:%' OR job_type LIKE 'action:ansible_retry:%')"),
            )
            for table, predicate in predicates:
                row = connection.execute(f'SELECT id FROM {table} WHERE {predicate} LIMIT 1').fetchone()
                if row:
                    found.append(table + ' id=' + str(row[0]))
            return found

        def removal_stop(state_arg, frozen):
            nonlocal stop_started
            stop_started = True
            result = original_stop(state_arg, frozen)
            if after_stop is not None:
                stack.enter_context(after_stop(transaction))
            return result

        def removal_freeze(state_arg):
            nonlocal freeze_confirmed
            _check_worker_not_prepaused(lifecycle)
            try:
                frozen = original_freeze(state_arg)
                if type(frozen) is not bool:
                    raise RuntimeError('unexpected freeze result')
            except BaseException as error:
                raise BarrierRecoveryRequired(
                    'worker freeze outcome is uncertain; journal retained for manual recovery') from error
            freeze_confirmed = frozen
            return frozen

        def removal_release():
            if freeze_confirmed:
                original_release()

        try:
            with ExitStack() as stack:
                state = lifecycle.capture('uninstall')
                lifecycle.busy = removal_busy
                lifecycle.stop = removal_stop
                lifecycle.freeze_worker = removal_freeze
                lifecycle.release_worker = removal_release
                try:
                    lifecycle.quiesce(state, snapshot=False)
                finally:
                    for key in override_keys:
                        if present[key]:
                            setattr(lifecycle, key, overrides[key])
                        else:
                            delattr(lifecycle, key)
                yield transaction
        except BaseException as error:
            if isinstance(error, BarrierRecoveryRequired):
                raise
            if not transaction.purge_started and state is not None:
                try:
                    if freeze_confirmed:
                        lifecycle.release_worker()
                    if stop_started:
                        lifecycle.restore(state, old=True)
                    removal_file.unlink()
                    lifecycle.sync_directory(lifecycle.home)
                except Exception as error:
                    raise RuntimeError('Previous PXE Tools services could not all be restored; removal journal preserved: ' + str(error)) from error
            raise
        finally:
            lifecycle.state_file = original_file
    return guarded()


def upgrade_guard(lifecycle, *, owner=0):
    """Serialize with package upgrades and refuse an unfinished journal."""
    from contextlib import contextmanager

    @contextmanager
    def guard():
        if lifecycle.home.parent.is_symlink() or not lifecycle.home.parent.is_dir():
            raise RuntimeError('Native runtime missing or unsafe; inspect the partial installation')
        lifecycle.private_home()
        with installer_lock(lifecycle.home / 'lock', owner=owner):
            if (lifecycle.home / 'uninstall-state.json').exists() or (lifecycle.home / 'uninstall-state.json').is_symlink():
                raise RuntimeError('an interrupted uninstall requires recovery')
            if lifecycle.state_file.is_symlink() or lifecycle.load() is not None:
                raise RuntimeError('An earlier PXE Tools upgrade requires recovery before removal')
            yield
    return guard()


def validate_account(record, accounts, groups, process_uids):
    """Validate the package-created identity and refuse shared UID/GID use."""
    import re
    name = 'pxe-tools-ansible'
    if not isinstance(record, dict) or not isinstance(accounts, list) or not isinstance(groups, list):
        raise ValueError('incomplete account inventory')
    matches = [entry for entry in accounts if entry.pw_name == name]
    named_groups = [group for group in groups if group.gr_name == name]
    if len(matches) > 1 or len(named_groups) > 1:
        raise ValueError('duplicate account or group name')
    proof = record.get('account')
    if proof is None:
        if matches or named_groups:
            raise ValueError('pre-existing Ansible account or group has no creation proof')
        return None
    if (not isinstance(proof, dict) or set(proof) != {'name', 'uid', 'gid', 'gecos', 'home', 'shell'} or
            proof['name'] != name or proof['home'] != '/var/lib/pxe-tools-ansible/home' or
            proof['shell'] != '/usr/sbin/nologin' or not isinstance(proof['gecos'], str) or
            not re.fullmatch(r'pxe-tools-[0-9a-f]{32}', proof['gecos']) or
            any(type(proof[key]) is not int or proof[key] <= 0 for key in ('uid', 'gid'))):
        raise ValueError('invalid Ansible account creation proof')
    uid, gid = proof['uid'], proof['gid']
    if uid in process_uids:
        raise ValueError('Ansible account still has running processes')
    if any(entry.pw_name != name and (entry.pw_uid == uid or entry.pw_gid == gid) for entry in accounts):
        raise ValueError('Ansible UID or primary group is shared')
    if any(group.gr_name != name and (group.gr_gid == gid or name in group.gr_mem) for group in groups):
        raise ValueError('Ansible account or group has additional memberships')
    if named_groups and (named_groups[0].gr_gid != gid or set(named_groups[0].gr_mem) - {name}):
        raise ValueError('Ansible group is changed or shared')
    if not matches:
        return None
    if not named_groups:
        raise ValueError('dedicated Ansible group is missing')
    entry = matches[0]
    if (entry.pw_uid, entry.pw_gid, entry.pw_gecos, entry.pw_dir, entry.pw_shell) != (
            uid, gid, proof['gecos'], proof['home'], proof['shell']):
        raise ValueError('Ansible account identity changed')
    return proof


def _validate_userdel_configuration(snapshot):
    import re
    text = snapshot.get('login_defs')
    hooks = snapshot.get('userdel_hooks')
    if not isinstance(text, str) or not isinstance(hooks, list):
        raise ValueError('cannot inspect user deletion hooks')
    for line in text.splitlines():
        line = line.split('#', 1)[0]
        if re.match(r'^\s*USERDEL_CMD(?:\s|$)', line):
            raise ValueError('USERDEL_CMD requires administrator review')
    for hook in hooks:
        if (not isinstance(hook, dict) or hook.get('kind') != 'file' or
                type(hook.get('mode')) is not int or hook['mode'] & 0o111):
            raise ValueError('user deletion hook requires administrator review')


def remove_account(record, runner, lookup):
    """Remove only a proven unused account, never its home or other files."""
    state = lookup()
    identity = validate_account(record, state['accounts'], state['groups'], state['process_uids'])
    if identity is None:
        return None
    _validate_userdel_configuration(state)
    result = runner(['/usr/sbin/userdel', 'pxe-tools-ansible'], check=False,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=30)
    if result.returncode:
        raise RuntimeError('dedicated Ansible account removal failed')
    after = lookup()
    if validate_account(record, after['accounts'], after['groups'], after['process_uids']) is not None:
        raise RuntimeError('dedicated Ansible account remains after userdel')
    return identity


def account_snapshot(root, accounts, groups, *, owner=0):
    """Collect local identity and process evidence without following links."""
    import re
    root = Path(root)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    base = os.open(root, flags)

    def trusted_directory(fd):
        info = os.fstat(fd)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise ValueError('untrusted account configuration directory')

    def read_file(directory, name, *, trusted=True, maximum=8_000_000):
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o444 or
                    (trusted and (info.st_nlink != 1 or (owner is not None and
                     (info.st_uid != owner or info.st_mode & 0o022))))):
                raise ValueError('untrusted or unreadable account configuration')
            with os.fdopen(child, 'rb') as stream:
                child = None
                data = stream.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError('account configuration is too large')
            return data.decode('utf-8')
        finally:
            if child is not None:
                os.close(child)

    try:
        trusted_directory(base)
        etc = os.open('etc', flags, dir_fd=base)
        try:
            trusted_directory(etc)
            nss = read_file(etc, 'nsswitch.conf')
            login = read_file(etc, 'login.defs')
            passwd = read_file(etc, 'passwd')
            group_text = read_file(etc, 'group')
            policies = {}
            for line in nss.splitlines():
                line = line.split('#', 1)[0].strip()
                if not line or ':' not in line:
                    continue
                key, value = line.split(':', 1)
                if key in ('passwd', 'group', 'shadow'):
                    if key in policies:
                        raise ValueError('duplicate NSS policy')
                    policies[key] = value.split()
            if set(policies) != {'passwd', 'group', 'shadow'} or any(
                    value not in (['files'], ['files', 'systemd']) for value in policies.values()):
                raise ValueError('nonlocal or ambiguous NSS policy')

            def parse(text, count, numeric):
                rows = []
                for line in text.splitlines():
                    if not line or line.startswith('#'):
                        continue
                    row = line.split(':')
                    if len(row) != count or not row[0] or any(not row[index].isdigit() for index in numeric):
                        raise ValueError('malformed local account database')
                    rows.append(row)
                return rows
            local_accounts = [row for row in parse(passwd, 7, (2, 3)) if row[0] == 'pxe-tools-ansible']
            local_groups = [row for row in parse(group_text, 4, (2,)) if row[0] == 'pxe-tools-ansible']
            nss_accounts = [entry for entry in accounts if entry.pw_name == 'pxe-tools-ansible']
            nss_groups = [entry for entry in groups if entry.gr_name == 'pxe-tools-ansible']
            if len(local_accounts) > 1 or len(local_groups) > 1 or len(nss_accounts) > 1 or len(nss_groups) > 1:
                raise ValueError('duplicate local account identity')
            if len(local_accounts) != len(nss_accounts) or len(local_groups) != len(nss_groups):
                raise ValueError('local account and NSS disagree')
            if local_accounts:
                row, entry = local_accounts[0], nss_accounts[0]
                if (int(row[2]), int(row[3]), row[4], row[5], row[6]) != (
                        entry.pw_uid, entry.pw_gid, entry.pw_gecos, entry.pw_dir, entry.pw_shell):
                    raise ValueError('local account identity differs from NSS')
            if local_groups:
                row, entry = local_groups[0], nss_groups[0]
                members = [value for value in row[3].split(',') if value]
                if int(row[2]) != entry.gr_gid or sorted(members) != sorted(entry.gr_mem):
                    raise ValueError('local group identity differs from NSS')

            hooks = []
            try:
                shadow = os.open('shadow-maint', flags, dir_fd=etc)
            except FileNotFoundError:
                shadow = None
            if shadow is not None:
                try:
                    trusted_directory(shadow)
                    for name in ('userdel-pre.d', 'userdel-post.d'):
                        try:
                            folder = os.open(name, flags, dir_fd=shadow)
                        except FileNotFoundError:
                            continue
                        try:
                            trusted_directory(folder)
                            for child_name in sorted(os.listdir(folder)):
                                info = os.stat(child_name, dir_fd=folder, follow_symlinks=False)
                                if (not stat.S_ISREG(info.st_mode) or (owner is not None and info.st_uid != owner)
                                        or info.st_mode & 0o022):
                                    raise ValueError('untrusted user deletion hook')
                                hooks.append({'path': '/etc/shadow-maint/' + name + '/' + child_name,
                                              'mode': stat.S_IMODE(info.st_mode), 'kind': 'file'})
                        finally:
                            os.close(folder)
                finally:
                    os.close(shadow)
        finally:
            os.close(etc)
        proc = os.open('proc', flags, dir_fd=base)
        try:
            process_uids = set()
            count = 0
            for pid in os.listdir(proc):
                if not pid.isdigit():
                    continue
                try:
                    process = os.open(pid, flags, dir_fd=proc)
                except FileNotFoundError:
                    continue
                try:
                    try:
                        text = read_file(process, 'status', trusted=False, maximum=1_000_000)
                    except FileNotFoundError:
                        try:
                            os.stat(pid, dir_fd=proc, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        raise ValueError('live process has no readable UID status')
                    matches = re.findall(r'(?m)^Uid:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$', text)
                    if len(matches) != 1:
                        raise ValueError('process UID status is unavailable')
                    process_uids.update(map(int, matches[0]))
                    count += 1
                finally:
                    os.close(process)
            if not count:
                raise ValueError('process inventory is empty')
        finally:
            os.close(proc)
        snapshot = {'accounts': accounts, 'groups': groups, 'process_uids': process_uids,
                    'login_defs': login, 'userdel_hooks': hooks}
        _validate_userdel_configuration(snapshot)
        if nss_accounts and nss_accounts[0].pw_uid in process_uids:
            raise ValueError('Ansible account still has running processes')
        return snapshot
    finally:
        os.close(base)


def remove_group(record, runner, lookup):
    """Remove only the empty, proven dedicated group after user deletion."""
    state = lookup()
    if validate_account(record, state['accounts'], state['groups'], state['process_uids']) is not None:
        raise ValueError('Ansible account still exists; group preserved')
    name = 'pxe-tools-ansible'
    matches = [entry for entry in state['groups'] if entry.gr_name == name]
    if not matches:
        return
    proof = record.get('account') if isinstance(record, dict) else None
    if proof is None or matches[0].gr_gid != proof['gid'] or matches[0].gr_mem:
        raise ValueError('Ansible group is unproven or not empty')
    result = runner(['/usr/sbin/groupdel', name], check=False,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=30)
    if result.returncode:
        raise RuntimeError('dedicated Ansible group removal failed')
    after = lookup()
    validate_account(record, after['accounts'], after['groups'], after['process_uids'])
    if any(entry.gr_name == name for entry in after['groups']):
        raise RuntimeError('dedicated Ansible group remains after groupdel')


STORAGE_KEYS = ('HTTP_ROOT', 'TFTP_ROOT', 'PXE_TOOLS_DATA_DIR', 'MOK_DIR', 'TLS_DIR',
                'PXE_MASTER_KEY_PATH', 'PXE_DB_PATH', 'ORCHESTRATOR_DB',
                'ANSIBLE_WORKDIR', 'PXE_ANSIBLE_HOME')


def storage_snapshot(lifecycle):
    values = lifecycle.environments()
    database = lifecycle.database()
    return tuple((key, values.get(key, '')) for key in STORAGE_KEYS), str(database) if database is not None else None


def external_paths(lifecycle, recognised):
    """Report configured paths outside the recognised roots without reading them."""
    values = lifecycle.environments()
    candidates = [values.get(key, '') for key in STORAGE_KEYS]
    database = lifecycle.database()
    if database is not None:
        try:
            candidates.append('/' + str(database.relative_to(lifecycle.root)))
        except ValueError:
            raise RuntimeError('Database is outside the inspected host root')
    result = set()
    for value in candidates:
        if not value:
            continue
        if (not value.startswith('/') or '..' in Path(value).parts or
                any(ord(char) < 32 for char in value)):
            raise RuntimeError('Unsupported configured storage path')
        if not any(value == path or value.startswith(path + '/') for path in recognised):
            result.add(value)
    return tuple(sorted(result))


def require_release_ready(apply):
    if apply:
        raise RuntimeError('This candidate is not yet validated or available for removal')


UNITS = ('pxe-tools.target', 'pxe-tools-admin.target', 'pxe-tools-worker.service',
         'pxe-tools-dnsmasq-tail.service', 'pxe-tools-nginx.service',
         'pxe-tools-pxe-http.service', 'pxe-tools-php.service',
         'pxe-tools-dnsmasq.service', 'pxe-tools-init.service')


UNIT_HASHES = {'pxe-tools-dnsmasq-tail.service': '86d1b7e600e0b9fc997aff6a9fba96b5c4522e3e6af5b63451a1f05662b245d2', 'pxe-tools-dnsmasq.service': '691030281153890ea1a1433cba22eca55bd0e772ce72254e695a899066e9c609', 'pxe-tools-init.service': '79785fa3530786658bb278d55c6356703517db00da975028963a470450df5187', 'pxe-tools-nginx.service': 'ee3a5893223d469f2021171339e67967387de4dd8f0e18e5075bd47943cc0b3e', 'pxe-tools-php.service': '12d0d54bbd463f424f0ed33850949aa245b4e15d8bec5391219d8745292eb04d', 'pxe-tools-pxe-http.service': '6bfbf1e6463786671154911b68d0c206d08192d792dd14134f6ef530ba9aedba', 'pxe-tools-worker.service': '654a7103bdea22658f79e4dfb9c135204a2584cb38c11658be26718c87fa8f1b', 'pxe-tools-admin.target': '280dd012f0ebe0720ed1f437c41ce9ccd9d5f63eb58c726fe980fb99ad79b2ac', 'pxe-tools.target': '8d3a636b9177d68ddc12cfde6449a13dc4a6acd138129db035ce83c8298af68c'}
ANSIBLE_DROPIN_HASH = 'fb7578ae9bc11b1d80d4a4e9d81ae44a455cb6b52d03fffaa343dcea00e63a57'

def validate_product_units(root, runner, units, *, owner=0):
    """Refuse local overrides or altered product units before stopping anything."""
    import hashlib
    import shlex
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, flags)
    def directory(parts, missing_ok=False):
        fd = os.dup(root_fd)
        try:
            for part in parts:
                info = os.fstat(fd)
                if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                    raise ValueError('untrusted systemd ancestor')
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError:
                    if missing_ok:
                        os.close(fd)
                        return None
                    raise
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted systemd directory')
            return fd
        except BaseException:
            try: os.close(fd)
            except OSError: pass
            raise
    def digest(directory_fd, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1_000_000 or
                    (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                raise ValueError('untrusted package unit')
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                data = stream.read(1_000_001)
            if len(data) > 1_000_000:
                raise ValueError('oversized package unit')
            return hashlib.sha256(data).hexdigest()
        finally:
            if fd is not None:
                os.close(fd)
    opened = []
    try:
        package_dir = directory(('usr', 'lib', 'systemd', 'system'))
        opened.append(package_dir)
        local_dirs = []
        for parts in (('etc', 'systemd', 'system'), ('run', 'systemd', 'system')):
            local = directory(parts, missing_ok=True)
            if local is not None:
                opened.append(local)
                local_dirs.append((parts, local))
        for unit in units:
            if unit not in UNIT_HASHES:
                raise ValueError('unsupported product unit')
            if digest(package_dir, unit) != UNIT_HASHES[unit]:
                raise ValueError('package unit changed; preserved: ' + unit)
            allowed_masks = set()
            for parts, local in local_dirs:
                try:
                    item = os.stat(unit, dir_fd=local, follow_symlinks=False)
                except FileNotFoundError:
                    item = None
                if item is not None:
                    if not stat.S_ISLNK(item.st_mode) or os.readlink(unit, dir_fd=local) != '/dev/null':
                        raise ValueError('local unit override or alias; preserved: ' + unit)
                    allowed_masks.add('/' + '/'.join(parts) + '/' + unit)
                try:
                    os.stat(unit + '.d', dir_fd=local, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('local unit drop-in; preserved: ' + unit)
            def show(prop):
                result = runner(['systemctl', 'show', '--property=' + prop, '--value', unit],
                                check=False, text=True, stdout=-1, stderr=-1, timeout=30)
                if result.returncode:
                    raise RuntimeError('cannot inspect unit: ' + unit)
                return result.stdout.strip()
            fragment = show('FragmentPath')
            standard = {'/usr/lib/systemd/system/' + unit, '/lib/systemd/system/' + unit}
            if fragment not in standard | allowed_masks:
                raise ValueError('unexpected unit fragment; preserved: ' + unit)
            if fragment in allowed_masks and show('ActiveState') not in ('inactive', 'failed'):
                raise ValueError('masked unit is still active: ' + unit)
            dropins = shlex.split(show('DropInPaths'))
            permitted = {'/usr/lib/systemd/system/pxe-tools-worker.service.d/50-ansible.conf',
                         '/lib/systemd/system/pxe-tools-worker.service.d/50-ansible.conf'}
            if dropins and (unit != 'pxe-tools-worker.service' or len(dropins) != 1 or dropins[0] not in permitted):
                raise ValueError('unsupported unit drop-in; preserved: ' + unit)
            if dropins:
                folder = os.open('pxe-tools-worker.service.d', flags, dir_fd=package_dir)
                try:
                    if digest(folder, '50-ansible.conf') != ANSIBLE_DROPIN_HASH:
                        raise ValueError('Ansible unit drop-in changed; preserved')
                finally:
                    os.close(folder)
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(root_fd)


def main(argv):
    import subprocess
    import sys
    import pwd
    import grp
    args = parse_arguments(argv)
    require_release_ready(args.yes)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Run as root on the Linux host where PXE Tools was installed')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('A running systemd host is required')
    for key in tuple(os.environ):
        if key.startswith('DPKG_'):
            del os.environ[key]
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    lifecycle = load_lifecycle(Path('/'))
    ownership = load_ownership(Path('/'))
    reconciler = load_reconciler(Path('/'), subprocess.run)
    try:
        record = ownership.read() if ownership is not None else None
    except FileNotFoundError:
        record = None
    def mounts():
        return parse_mountinfo(Path('/proc/self/mountinfo').read_text(encoding='utf-8'))
    preview = run_uninstall(Path('/'), subprocess.run, lifecycle, UNITS, mounts, apply=False, record=record, ownership=ownership, reconciler=reconciler)
    outside = external_paths(lifecycle, preview['trees']) if lifecycle is not None else ()
    outside = tuple(path for path in outside if Path(path).exists() or Path(path).is_symlink())
    print('WARNING: removal destroys the PXE Tools database, configuration, local keys, certificates,')
    print('boot files and local upgrade snapshots in recognised paths. Keep a verified external backup.')
    print('Package removal: pxe-tools-ansible and pxe-tools; dependencies are retained.')
    for path in preview['trees']:
        print('Candidate data path, if present:', path)
    for path in sorted(set(preview['preserved']) | set(outside)):
        print('Preserved for manual review:', path)
    print('APT source recognised:', 'yes' if preview['source'] else 'no; absent or preserved')
    print('APT key unshared:', 'yes' if preview['key'] else 'no; absent or preserved')
    print('Externally enrolled firmware keys and external backups are not modified.')
    if not args.yes:
        print('Preview only. Service state and active tasks will be checked during removal.')
        print('When no PXE or Ansible work remains active, use --yes to consent;')
        print('the dedicated services will be stopped safely by the script.')
        return 0
    if outside:
        raise RuntimeError('Configured paths outside recognised roots require review; no package was removed')
    with installer_lock(Path('/run/lock/pxe-tools-apt-install.lock')):
        account_lookup = lambda: account_snapshot(Path('/'), list(pwd.getpwall()), list(grp.getgrall()))
        result = run_uninstall(Path('/'), subprocess.run, lifecycle, UNITS, mounts, apply=True, record=record, ownership=ownership, reconciler=reconciler, account_lookup=account_lookup)
    print('Requested package purge completed; recognised data paths were removed where present.')
    print('APT source removed:', 'yes' if result['source_removed'] else 'no')
    print('APT key removed:', 'yes' if result['key_removed'] else 'no')
    remaining_source = Path('/etc/apt/sources.list.d/pxe-tools.sources')
    if result['preserved'] or outside or remaining_source.exists() or remaining_source.is_symlink():
        print('Some resources were preserved or their provenance could not be established; inspect them manually.')
        return 1
    return 0


if __name__ == '__main__':
    import sys
    import sqlite3
    import subprocess
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        print('PXE Tools removal stopped:', error, file=sys.stderr)
        raise SystemExit(1)
