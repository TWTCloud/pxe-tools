#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Remove a native APT installation after explicit operator consent."""
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
                child = opener(parent, component)
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
                os.fsync(directory)
            descend(target_fd)
        finally:
            os.close(target_fd)
        os.rmdir(parts[-1], dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def _apt_effective_config():
    """Query system APT without inheriting caller-controlled APT_CONFIG."""
    import shlex
    import subprocess
    command = ['/usr/bin/apt-config', 'shell',
               'SOURCE', 'Dir::Etc::sourcelist/f', 'PARTS', 'Dir::Etc::sourceparts/d',
               'TRUSTED', 'Dir::Etc::trusted/f', 'TRUSTEDPARTS', 'Dir::Etc::trustedparts/d',
               'ROOT', 'RootDir']
    result = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode or result.stderr.strip() or len(result.stdout) > 16384:
        raise ValueError('cannot query system APT configuration')
    config = {}
    for line in result.stdout.splitlines():
        pieces = shlex.split(line, posix=True)
        if len(pieces) != 1 or '=' not in pieces[0]:
            raise ValueError('unsupported system APT configuration')
        name, value = pieces[0].split('=', 1)
        if name in config or name not in ('SOURCE', 'PARTS', 'TRUSTED', 'TRUSTEDPARTS', 'ROOT'):
            raise ValueError('unsupported system APT configuration')
        config[name] = value
    return config


def _installer_source_bytes_valid(data):
    """Accept only the exact source syntax emitted by the installer."""
    import re
    pattern = (rb'Types: deb\nURIs: https://[A-Za-z0-9][A-Za-z0-9.-]*'
               rb'(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?\n'
               rb'Suites: stable\nComponents: main\nArchitectures: amd64\n'
               rb'Signed-By: /etc/apt/keyrings/pxe-tools-archive-keyring\.gpg\n')
    return isinstance(data, bytes) and b'..' not in data and re.fullmatch(pattern, data) is not None


def apt_cleanup_plan(root, *, owner=0, apt_config=None):
    """Identify the installer source and a proven key unused by system APT.

    APT invocations with a later, explicitly supplied alternative configuration
    are outside this inspection. The CLI never exposes the fixture override.
    """
    import hashlib
    import re
    import subprocess
    root = Path(root)
    source = root / 'etc/apt/sources.list.d/pxe-tools.sources'
    key = root / 'etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
    source_ok = False

    def safe_dir(path):
        if path.is_symlink() or not path.is_dir():
            return False
        info = path.stat()
        return owner is None or (info.st_uid == owner and not info.st_mode & 0o022)

    def safe_file(path, *, links=1):
        if path.is_symlink() or not path.is_file():
            return False
        info = path.stat()
        return (info.st_nlink == links and (owner is None or info.st_uid == owner)
                and not info.st_mode & 0o022)

    try:
        if not all(safe_dir(path) for path in (root, root / 'etc', root / 'etc/apt', source.parent)):
            return False, False
        source_exists = source.exists() or source.is_symlink()
        source_anchors = list(source.parent.glob('.pxe-tools-sources.*.created'))
        if source_exists or source_anchors:
            if len(source_anchors) != 1:
                return False, False
            source_anchor = source_anchors[0]
            source_proof = re.fullmatch(r'\.pxe-tools-sources\.([0-9a-f]{64})\.created', source_anchor.name)
            if source_proof is None or not safe_file(source_anchor, links=2 if source_exists else 1):
                return False, False
            if source_anchor.stat().st_size > 1048576:
                return False, False
            source_bytes = source_anchor.read_bytes()
            if (not _installer_source_bytes_valid(source_bytes) or
                    hashlib.sha256(source_bytes).hexdigest() != source_proof.group(1)):
                return False, False
            if source_exists and (not safe_file(source, links=2) or not os.path.samefile(source, source_anchor)):
                return False, False
            # An active source symlink elsewhere could use the same inode.
            # Preserve the source if such an alias is present or unclear.
            candidate_sources = [root / 'etc/apt/sources.list'] + [
                path for path in source.parent.iterdir()
                if path != source and path.suffix in ('.list', '.sources')]
            if any(path.is_symlink() for path in candidate_sources):
                return False, False
            # APT must not be configured to read our hidden witness as its
            # active source. Inspect the effective system config before even
            # removing the source; test roots may provide an injected config.
            if apt_config is None and root == Path('/'):
                apt_config = _apt_effective_config()
            if apt_config is not None and (
                    not isinstance(apt_config, dict) or apt_config.get('ROOT', '') not in ('', '/')
                    or not isinstance(apt_config.get('SOURCE'), str)
                    or not isinstance(apt_config.get('PARTS'), str)
                    or os.path.normpath(apt_config['SOURCE']) != '/etc/apt/sources.list'
                    or os.path.normpath(apt_config['PARTS']) != '/etc/apt/sources.list.d'):
                return False, False
            source_ok = True
        if not safe_dir(key.parent):
            return source_ok, False
        anchors = list(key.parent.glob('.pxe-tools-archive-keyring.*.created'))
        if len(anchors) != 1:
            return source_ok, False
        anchor = anchors[0]
        proof = re.fullmatch(r'\.pxe-tools-archive-keyring\.([0-9a-f]{64})\.created', anchor.name)
        if proof is None:
            return source_ok, False
        key_exists = key.exists() or key.is_symlink()
        if key_exists:
            if not safe_file(key, links=2) or not safe_file(anchor, links=2) or not os.path.samefile(key, anchor):
                return source_ok, False
        elif not safe_file(anchor):
            return source_ok, False
        if anchor.stat().st_size > 1048576 or hashlib.sha256(anchor.read_bytes()).hexdigest() != proof.group(1):
            return source_ok, False

        if apt_config is None:
            if root != Path('/'):
                return source_ok, False
            apt_config = _apt_effective_config()
        expected = {'SOURCE': '/etc/apt/sources.list', 'PARTS': '/etc/apt/sources.list.d',
                    'TRUSTEDPARTS': '/etc/apt/trusted.gpg.d'}
        if (not isinstance(apt_config, dict) or set(apt_config) - (set(expected) | {'ROOT', 'TRUSTED'}) or
                apt_config.get('ROOT', '') not in ('', '/') or
                any(not isinstance(apt_config.get(name), str) or
                    os.path.normpath(apt_config[name]) != path for name, path in expected.items()) or
                ('TRUSTED' in apt_config and apt_config['TRUSTED'] not in ('', '/etc/apt/trusted.gpg'))):
            return source_ok, False

        # APT's effective, standard sources are the bounded scope of this
        # check. Symlinks, unparseable source text, and global key aliases fail
        # closed; alternative APT_CONFIG/-o invocations are not discoverable.
        trusted = root / 'etc/apt/trusted.gpg'
        trusted_parts = root / 'etc/apt/trusted.gpg.d'
        if trusted.is_symlink() or (trusted.exists() and (not trusted.is_file() or os.path.samefile(trusted, anchor))):
            return source_ok, False
        if trusted_parts.is_symlink() or (trusted_parts.exists() and not safe_dir(trusted_parts)):
            return source_ok, False
        if trusted_parts.exists():
            for item in trusted_parts.iterdir():
                if item.is_symlink() or (item.exists() and (not item.is_file() or os.path.samefile(item, anchor))):
                    return source_ok, False
        others = [root / 'etc/apt/sources.list']
        others.extend(path for path in source.parent.iterdir()
                      if path != source and path.suffix in ('.list', '.sources'))
        reserved = {'/etc/apt/keyrings/pxe-tools-archive-keyring.gpg',
                    '/etc/apt/keyrings/' + anchor.name}
        for other in others:
            if other.is_symlink():
                return source_ok, False
            if not other.exists():
                continue
            if not safe_file(other) or other.stat().st_size > 1048576:
                return source_ok, False
            text = other.read_text(encoding='utf-8')
            if ('\\' in text or any(('signed-by' in line.lower() and any(c in line for c in "\"'"))
                                    for line in text.splitlines())):
                return source_ok, False
            for match in re.finditer(r'(?<![A-Za-z0-9:/])(/[^\s\[\]()\"\'\=,;]+)', text):
                name = match.group(1)
                if name in reserved or '..' in Path(name).parts or '%' in name or '\\' in name:
                    return source_ok, False
                candidate = root / name.lstrip('/')
                try:
                    candidate_info = candidate.stat()
                except FileNotFoundError:
                    continue
                if os.path.samestat(candidate_info, anchor.stat()):
                    return source_ok, False
        return source_ok, True
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        return source_ok, False


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


def packages_intact(runner):
    """Establish that a pre-purge retry still has complete installed packages."""
    result = runner(['dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Status}\t${db:Status-Eflag}\n'],
                    check=False, text=True, stdout=-1, stderr=-1, timeout=30,
                    env=clean_dpkg_environment())
    if result.returncode or not result.stdout.strip():
        raise RuntimeError('Cannot establish the dpkg package state')
    found = {}
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 3 or not all(fields):
            raise RuntimeError('Incomplete dpkg package state')
        name, status, flag = fields
        name = name.partition(':')[0]
        if name in ('pxe-tools', 'pxe-tools-ansible'):
            if name in found or flag != 'ok' or status not in ('installed', 'not-installed'):
                return False
            found[name] = status
    return found.get('pxe-tools') == 'installed'


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


def remove_apt_config(root, *, mounts, owner=0, apt_config=None, opener=None):
    """Remove the recognised source and a proven, system-unshared key."""
    import hashlib
    import re
    import sys
    if opener is None:
        if sys.platform == 'linux':
            opener = _openat2_no_mount
        elif Path(root) != Path('/') and owner != 0:
            opener = lambda parent, child: os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        else:
            raise RuntimeError('Linux openat2 is required to remove APT configuration safely')
    source_name = '/etc/apt/sources.list.d/pxe-tools.sources'
    key_name = '/etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
    source_ok, key_ok = apt_cleanup_plan(root, owner=owner, apt_config=apt_config)

    def mounted(path):
        return any(m != '/' and (path == m or path.startswith(m + '/')) for m in mounts)

    def unlink_checked(path, *, links=1, expected_bytes=None, digest=None, identity=None):
        parts = Path(path).parts[1:]
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(root, flags)
        opened = None
        try:
            for part in parts[:-1]:
                info = os.fstat(fd)
                if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                    raise ValueError('untrusted APT ancestor')
                child = opener(fd, part)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted APT ancestor')
            opened = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            info = os.fstat(opened)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != links or info.st_size > 1048576 or
                    (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                raise ValueError('untrusted APT file')
            if identity is not None and (info.st_dev, info.st_ino) != identity:
                raise ValueError('APT file identity changed')
            data = bytearray()
            while len(data) <= 1048576:
                part = os.read(opened, min(65536, 1048577 - len(data)))
                if not part:
                    break
                data.extend(part)
            if (len(data) > 1048576 or (expected_bytes is not None and data != expected_bytes) or
                    (digest is not None and hashlib.sha256(data).hexdigest() != digest)):
                raise ValueError('APT file content changed')
            current = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            if ((current.st_dev, current.st_ino, current.st_nlink) !=
                    (info.st_dev, info.st_ino, info.st_nlink)):
                raise ValueError('APT file changed during inspection')
            os.unlink(parts[-1], dir_fd=fd)
            os.fsync(fd)
        finally:
            if opened is not None:
                os.close(opened)
            os.close(fd)

    source_removed = False
    if source_ok:
        source_dir = Path(root) / 'etc/apt/sources.list.d'
        source_anchors = list(source_dir.glob('.pxe-tools-sources.*.created'))
        if len(source_anchors) != 1:
            raise ValueError('APT source witness changed')
        source_anchor_name = '/etc/apt/sources.list.d/' + source_anchors[0].name
        source_match = re.fullmatch(r'\.pxe-tools-sources\.([0-9a-f]{64})\.created', source_anchors[0].name)
        if source_match is None:
            raise ValueError('invalid APT source witness')
        if mounted(source_name) or mounted(source_anchor_name):
            return False, False
        info = source_anchors[0].stat()
        source_identity = (info.st_dev, info.st_ino)
        source_path = Path(root) / source_name.lstrip('/')
        source_removed = source_path.exists() or source_path.is_symlink()
        if source_removed:
            unlink_checked(source_name, links=2, digest=source_match.group(1), identity=source_identity)
        unlink_checked(source_anchor_name, digest=source_match.group(1), identity=source_identity)
    elif (Path(root) / source_name.lstrip('/')).exists() or (Path(root) / source_name.lstrip('/')).is_symlink():
        return False, False
    if not key_ok:
        return source_removed, False
    # Re-evaluate the effective sources after removing ours. Any changed or
    # ambiguous state preserves the key and its witness.
    _, key_ok = apt_cleanup_plan(root, owner=owner, apt_config=apt_config)
    key_dir = Path(root) / 'etc/apt/keyrings'
    anchors = list(key_dir.glob('.pxe-tools-archive-keyring.*.created'))
    if not key_ok or len(anchors) != 1:
        return source_removed, False
    match = re.fullmatch(r'\.pxe-tools-archive-keyring\.([0-9a-f]{64})\.created', anchors[0].name)
    anchor_name = '/etc/apt/keyrings/' + anchors[0].name
    if match is None or mounted(key_name) or mounted(anchor_name):
        return source_removed, False
    info = anchors[0].stat()
    identity = (info.st_dev, info.st_ino)
    key_path = Path(root) / key_name.lstrip('/')
    if key_path.exists() or key_path.is_symlink():
        unlink_checked(key_name, links=2, digest=match.group(1), identity=identity)
    unlink_checked(anchor_name, links=1, digest=match.group(1), identity=identity)
    return source_removed, True


class BarrierRecoveryRequired(RuntimeError):
    """Mask state is uncertain; preserve the removal journal for recovery."""


class RemovalJournal:
    """Durable receipt outside every tree removed by the transaction."""
    NAME = 'pxe-tools-uninstall'

    def __init__(self, root, *, owner=0):
        self.root = Path(root)
        self.owner = owner
        self.state = None

    def _directory(self, parts):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in (None, *parts):
                if name is not None:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                info = os.fstat(fd)
                if self.owner is not None and (info.st_uid != self.owner or info.st_mode & 0o022):
                    raise ValueError('untrusted removal journal ancestor')
            if parts and parts[-1] == self.NAME and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                raise ValueError('removal journal must be private')
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def validate(value):
        import re
        if (not isinstance(value, dict) or set(value) != {'format', 'phase', 'record', 'paths', 'masks', 'metadata', 'steps', 'worker', 'restore', 'initial_units'}
                or value['format'] != 1 or value['phase'] not in ('preparing', 'purge_started', 'packages_absent', 'cleaning', 'complete', 'aborted')
                or not isinstance(value['paths'], list) or len(set(value['paths'])) != len(value['paths'])
                or any(path not in TREES for path in value['paths'])
                or not isinstance(value['masks'], dict) or not isinstance(value['metadata'], dict)):
            raise ValueError('invalid removal journal')
        record = value['record']
        if record is not None:
            if (not isinstance(record, dict) or record.get('format') != 2 or record.get('base_phase') != 'complete'
                    or not isinstance(record.get('directories'), dict) or set(value['paths']) - set(record['directories'])):
                raise ValueError('invalid removal ownership record')
            for path in value['paths']:
                proof = record['directories'][path]
                if (not isinstance(proof, dict) or set(proof) != {'dev', 'ino', 'btime_sec', 'btime_nsec', 'nonce'}
                        or any(type(proof[k]) is not int or proof[k] < 0 for k in ('dev', 'ino', 'btime_sec', 'btime_nsec'))
                        or not re.fullmatch('[0-9a-f]{64}', proof['nonce'] or '')):
                    raise ValueError('invalid removal generation proof')
        elif value['paths']:
            raise ValueError('removal paths have no ownership record')
        if (not isinstance(value['steps'], dict) or set(value['steps']) != set(value['paths']) | {'account', 'group', 'apt'}
                or any(step not in ('pending', 'intent', 'done') for step in value['steps'].values())):
            raise ValueError('invalid removal cleanup steps')
        if value['restore'] not in ('pending', 'intent', 'done'):
            raise ValueError('invalid removal restoration state')
        if (not isinstance(value['initial_units'], dict) or set(value['initial_units']) - set(UNITS)
                or any(not isinstance(entry, dict) or set(entry) != {'active', 'enabled'}
                       or type(entry['active']) is not bool or not isinstance(entry['enabled'], str)
                       or len(entry['enabled']) > 80 or any(ord(c) < 32 for c in entry['enabled'])
                       for entry in value['initial_units'].values())):
            raise ValueError('invalid initial service states')
        worker = value['worker']
        if worker is not None and (not isinstance(worker, dict) or
                set(worker) != {'phase', 'boot_id', 'pid', 'starttime', 'cgroup'} or
                worker['phase'] not in ('freeze_intent', 'frozen', 'stop_intent', 'sigstop_confirmed', 'stopped') or
                not isinstance(worker['boot_id'], str) or
                not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', worker['boot_id']) or
                not isinstance(worker['pid'], str) or not worker['pid'].isdecimal() or int(worker['pid']) <= 1 or
                not isinstance(worker['starttime'], str) or not worker['starttime'].isdecimal() or
                not isinstance(worker['cgroup'], str) or not worker['cgroup'].startswith('/') or
                worker['cgroup'] == '/' or '..' in Path(worker['cgroup']).parts):
            raise ValueError('invalid recorded worker identity')
        for unit, mask in value['masks'].items():
            if (unit not in UNITS or not isinstance(mask, dict) or set(mask) != {'temporary', 'dev', 'ino', 'phase'}
                    or not isinstance(mask['temporary'], str)
                    or not re.fullmatch(r'\.pxe-uninstall-[0-9a-f]{32}-' + re.escape(unit), mask['temporary'])
                    or any(type(mask[k]) is not int or mask[k] < 0 for k in ('dev', 'ino'))
                    or mask['phase'] not in ('creating', 'prepared', 'published', 'removed')
                    or (mask['phase'] == 'creating' and (mask['dev'], mask['ino']) != (0, 0))
                    or (mask['phase'] != 'creating' and mask['ino'] == 0)):
                raise ValueError('invalid removal mask record')
        if set(value['metadata']) - {'ownership', 'nginx'}:
            raise ValueError('invalid removal metadata')
        for key, item in value['metadata'].items():
            fields = {'identities', 'sha256', 'intent'} | ({'helper', 'helper_sha256', 'record'} if key == 'nginx' else set())
            if (not isinstance(item, dict) or set(item) != fields
                    or not isinstance(item['identities'], dict) or set(item['identities']) != {'directory', 'state.json', 'lock'}
                    or any(not isinstance(identity, (list, tuple)) or len(identity) != 2
                           or any(type(part) is not int or part < 0 for part in identity)
                           for identity in item['identities'].values())
                    or not re.fullmatch('[0-9a-f]{64}', item['sha256'] or '') or type(item['intent']) is not bool):
                raise ValueError('invalid removal metadata record')
            if key == 'nginx':
                import base64
                import hashlib
                try:
                    helper = base64.b64decode(item['helper'], validate=True)
                except (ValueError, TypeError):
                    raise ValueError('invalid saved nginx verifier')
                if (not helper or len(helper) > 1_000_000 or not isinstance(item['record'], dict) or
                        hashlib.sha256(helper).hexdigest() != item['helper_sha256']):
                    raise ValueError('invalid saved nginx verifier')
        return value

    def create(self, record, paths, metadata):
        self.state = self.validate({'format': 1, 'phase': 'preparing', 'record': record,
                                    'paths': list(paths), 'masks': {}, 'metadata': metadata,
                                    'steps': {name: 'pending' for name in (*paths, 'account', 'group', 'apt')},
                                    'worker': None, 'restore': 'pending', 'initial_units': {}})
        parent = self._directory(('var', 'lib'))
        try:
            os.mkdir(self.NAME, 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.save()

    def save(self):
        import json
        import secrets
        data = (json.dumps(self.validate(self.state), sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(data) > 2_000_000:
            raise ValueError('removal journal is too large')
        directory = self._directory(('var', 'lib', self.NAME))
        try:
            name = '.state-' + secrets.token_hex(16)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
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
        finally:
            os.close(directory)

    def _entries(self, directory, *, state_required=True):
        import re
        names = set(os.listdir(directory))
        if state_required and 'state.json' not in names:
            raise ValueError('removal journal state is missing')
        for name in names - {'state.json'}:
            if not re.fullmatch(r'\.state-[0-9a-f]{32}', name):
                raise ValueError('foreign removal journal file')
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or (self.owner is not None and info.st_uid != self.owner) or info.st_size > 2_000_000):
                raise ValueError('untrusted temporary removal journal')
        return names

    def read(self, *, state_name='state.json'):
        import json
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('duplicate removal journal field')
                result[key] = value
            return result
        directory = self._directory(('var', 'lib', self.NAME))
        try:
            names = self._entries(directory, state_required=state_name == 'state.json')
            if state_name not in names:
                raise ValueError('removal journal state is missing')
            fd = os.open(state_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                        or (self.owner is not None and info.st_uid != self.owner) or info.st_size > 2_000_000):
                    raise ValueError('untrusted removal journal')
                with os.fdopen(fd, 'rb') as stream:
                    fd = None
                    data = stream.read(2_000_001)
                self.state = self.validate(json.loads(data, object_pairs_hook=unique))
                return self.state
            finally:
                if fd is not None:
                    os.close(fd)
        finally:
            os.close(directory)

    def recover_initial(self):
        """Promote only a complete, untouched first write after interruption."""
        directory = self._directory(('var', 'lib', self.NAME))
        try:
            names = self._entries(directory, state_required=False)
            if 'state.json' in names:
                return self.read()
            if len(names) != 1:
                raise ValueError('initial removal receipt is missing or ambiguous; inspect its directory')
            temporary = next(iter(names))
            state = self.read(state_name=temporary)
            if (state['phase'] != 'preparing' or state['masks'] or state['worker'] is not None
                    or state['initial_units'] or state['restore'] != 'pending'
                    or any(value != 'pending' for value in state['steps'].values())
                    or any(value['intent'] for value in state['metadata'].values())):
                raise ValueError('initial removal receipt is not an untouched transaction')
            os.rename(temporary, 'state.json', src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            return state
        finally:
            os.close(directory)

    def finish(self, *, aborted=False):
        """Publish completion before removing the private receipt."""
        self.state['phase'] = 'aborted' if aborted else 'complete'
        self.save()
        parent = self._directory(('var', 'lib'))
        completed = self.NAME + ('-aborted' if aborted else '-complete')
        try:
            try:
                os.stat(completed, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError('previous completion receipt requires inspection')
            os.rename(self.NAME, completed, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            directory = os.open(completed, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                for name in self._entries(directory) - {'state.json'}:
                    os.unlink(name, dir_fd=directory)
                    os.fsync(directory)
                os.unlink('state.json', dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(directory)
            os.rmdir(completed, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)


def removal_journal(root, record, paths, ownership_ids, ownership_bytes, nginx_journal, *, owner=0):
    """Create a durable receipt before stopping services or purging packages."""
    import base64
    import hashlib
    from contextlib import contextmanager

    @contextmanager
    def managed():
        metadata = {}
        if ownership_ids is not None:
            metadata['ownership'] = {'identities': ownership_ids,
                                     'sha256': hashlib.sha256(ownership_bytes).hexdigest(), 'intent': False}
        if nginx_journal is not None:
            helper = read_package_helper(root, 'reconcile-nginx.py', owner=owner)
            if helper is None:
                raise RuntimeError('nginx verifier unavailable for interrupted removal')
            metadata['nginx'] = {'identities': nginx_journal.identities,
                                 'sha256': hashlib.sha256(nginx_journal.contents).hexdigest(), 'intent': False,
                                 'helper': base64.b64encode(helper).decode('ascii'),
                                 'helper_sha256': hashlib.sha256(helper).hexdigest(),
                                 'record': nginx_journal.record}
        receipt = RemovalJournal(root, owner=owner)
        receipt.create(record, paths, metadata)
        try:
            yield receipt
        except BaseException as error:
            if receipt.state['phase'] == 'preparing' and not isinstance(error, BarrierRecoveryRequired):
                receipt.finish(aborted=True)
            raise
        else:
            receipt.finish()
    return managed()


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
                # Name the prospective link durably before it can appear. If a
                # crash precedes inode capture, recovery preserves an existing
                # entry rather than guessing who created it.
                transaction.record_mask(unit, temporary, 0, 0, 'creating')
                try:
                    os.symlink('/dev/null', temporary, dir_fd=fd)
                    os.fsync(fd)
                    created = info(temporary)
                    if created is None or not stat.S_ISLNK(created.st_mode) or created.st_nlink != 1:
                        raise RuntimeError('cannot establish temporary mask identity')
                except BaseException as error:
                    raise BarrierRecoveryRequired(
                        'mask creation outcome is uncertain; journal retained for inspection') from error
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


def remove_private_journal_resumable(root, name, *, owner=0, mounts=(), identities,
                                     expected_sha256, authorized=False, dry_run=False):
    """Remove a previously authorised private journal after an interruption.

    The caller must hold the corresponding stable lock throughout validation
    and removal and must have durably recorded its deletion intent before
    passing authorized=True. File descriptors pin each remaining inode while
    the entire set is checked; no unknown file or changed receipt is removed.
    """
    import hashlib
    import re

    allowed = {'/var/lib/pxe-tools-ownership', '/var/lib/pxe-tools-nginx-ownership'}
    if name not in allowed:
        raise ValueError('unsupported private journal')
    if authorized is not True:
        raise ValueError('durable journal cleanup authorization is required')
    if (not isinstance(identities, dict) or set(identities) != {'directory', 'state.json', 'lock'}
            or any(not isinstance(pair, (list, tuple)) or len(pair) != 2
                   or any(type(value) is not int or value < 0 for value in pair)
                   or pair[1] == 0 for pair in identities.values())):
        raise ValueError('invalid recorded private journal identities')
    if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('invalid recorded private journal digest')
    if any(m == name or m.startswith(name + '/') for m in mounts):
        raise ValueError('private journal crosses a mount boundary')

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    directory = None
    opened = {}

    def trusted_directory(fd, *, private=False):
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or
                (owner is not None and (info.st_uid != owner or info.st_mode & 0o022)) or
                (private and stat.S_IMODE(info.st_mode) != 0o700)):
            raise ValueError('untrusted private journal directory')
        return info

    def same_identity(info, key):
        return (info.st_dev, info.st_ino) == tuple(identities[key])

    def check_named_directory():
        current = os.stat(Path(name).name, dir_fd=parent, follow_symlinks=False)
        info = trusted_directory(directory, private=True)
        if not stat.S_ISDIR(current.st_mode) or not same_identity(current, 'directory') or not same_identity(info, 'directory'):
            raise ValueError('private journal directory was replaced')

    def validate_file(key, fd):
        info = os.fstat(fd)
        current = os.stat(key, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(current.st_mode)
                or info.st_nlink != 1 or current.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or stat.S_IMODE(current.st_mode) != 0o600
                or (owner is not None and (info.st_uid != owner or current.st_uid != owner))
                or not same_identity(info, key) or not same_identity(current, key)):
            raise ValueError('private journal file changed; preserved')
        if key == 'lock':
            if info.st_size != 0:
                raise ValueError('private journal lock is not empty')
            return
        if info.st_size > 2_000_000:
            raise ValueError('oversized private journal')
        os.lseek(fd, 0, os.SEEK_SET)
        content = bytearray()
        while len(content) <= 2_000_000:
            block = os.read(fd, min(65536, 2_000_001 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > 2_000_000 or hashlib.sha256(content).hexdigest() != expected_sha256:
            raise ValueError('private journal contents changed; preserved')
        current = os.stat(key, dir_fd=directory, follow_symlinks=False)
        if not same_identity(current, key):
            raise ValueError('private journal file changed during inspection')

    try:
        for part in ('var', 'lib'):
            trusted_directory(parent)
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        trusted_directory(parent)
        try:
            before = os.stat(Path(name).name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(before.st_mode) or not same_identity(before, 'directory'):
            raise ValueError('private journal directory changed; preserved')
        directory = os.open(Path(name).name, flags, dir_fd=parent)
        check_named_directory()
        names = set(os.listdir(directory))
        if not names <= {'state.json', 'lock'}:
            raise ValueError('unknown private journal files; preserved')
        for key in sorted(names):
            fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            opened[key] = fd
            validate_file(key, fd)
        check_named_directory()
        if set(os.listdir(directory)) != names:
            raise ValueError('private journal contents changed during inspection')
        if dry_run:
            return
        for key in ('state.json', 'lock'):
            if key in opened:
                check_named_directory()
                if set(os.listdir(directory)) != names:
                    raise ValueError('private journal contents changed; preserved')
                validate_file(key, opened[key])
                os.unlink(key, dir_fd=directory)
                names.remove(key)
                os.fsync(directory)
        check_named_directory()
        if os.listdir(directory):
            raise ValueError('private journal is not empty; preserved')
        os.rmdir(Path(name).name, dir_fd=parent)
        os.fsync(parent)
    finally:
        for fd in opened.values():
            os.close(fd)
        if directory is not None:
            os.close(directory)
        os.close(parent)


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


def recorded_generation_matches(fd, proof):
    """Recheck the creation proof without depending on removed package files."""
    import ctypes
    import re
    import struct
    try:
        info = os.fstat(fd)
        if (not isinstance(proof, dict) or set(proof) != {'dev', 'ino', 'btime_sec', 'btime_nsec', 'nonce'}
                or (info.st_dev, info.st_ino) != (proof['dev'], proof['ino'])
                or not isinstance(proof['nonce'], str) or not re.fullmatch('[0-9a-f]{64}', proof['nonce'])):
            return False
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.statx
        call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p)
        call.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(256)
        if call(fd, b'', 0x1000, 0x100 | 0x800, ctypes.byref(buffer)) != 0:
            return False
        data = buffer.raw
        mask = struct.unpack_from('=I', data, 0)[0]
        ino = struct.unpack_from('=Q', data, 32)[0]
        sec, nsec = struct.unpack_from('=qI', data, 80)
        major, minor = struct.unpack_from('=II', data, 136)
        return (mask & (0x100 | 0x800) == (0x100 | 0x800)
                and (os.makedev(major, minor), ino, sec, nsec) ==
                    (proof['dev'], proof['ino'], proof['btime_sec'], proof['btime_nsec'])
                and os.getxattr(fd, 'trusted.pxe-tools-ownership') == bytes.fromhex(proof['nonce']))
    except (AttributeError, OSError, ValueError, TypeError, KeyError, struct.error):
        return False


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
    with dpkg_frontend_lock(root / 'var/lib/dpkg/lock-frontend', owner=owner), \
            installer_lock(root / 'run/lock/pxe-tools-uninstall.lock', owner=owner):
        from contextlib import nullcontext
        if lifecycle is not None and ownership is None:
            raise RuntimeError('Ownership lock is unavailable; no package was removed')
        context = (ownership._locked(create=False) if record is not None else
                   ownership.hold_lock() if ownership is not None else nullcontext(None))
        with context as ownership_fd:
            if record is None and ownership is not None:
                directory = root / 'var/lib/pxe-tools-ownership'
                if directory.exists() or directory.is_symlink():
                    raise RuntimeError('Ownership journal appeared; no package was removed')
            if record is not None and ownership._read(ownership_fd) != record:
                raise RuntimeError('ownership journal changed; no package was removed')
            if any(((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink())
                   for path in TREES if path not in paths):
                raise RuntimeError('Unproven instance paths appeared; no package was removed')
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
                with upgrade_guard(lifecycle, owner=owner), removal_journal(
                        root, record, paths, ownership_identities, ownership_contents,
                        nginx_journal, owner=owner) as journal:
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
                    with quiesced_lifecycle(lifecycle, after_stop=after_stop, journal=journal) as transaction:
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
                        journal.state['phase'] = 'packages_absent'
                        journal.save()
                        try:
                            if account_lookup is not None and record is not None:
                                journal.state['steps']['account'] = 'intent'
                                journal.save()
                                remove_account(record, runner, account_lookup)
                                journal.state['steps']['account'] = 'done'
                                journal.save()
                                if record.get('account') is not None:
                                    journal.state['steps']['group'] = 'intent'
                                    journal.save()
                                    remove_group(record, runner, account_lookup)
                                    journal.state['steps']['group'] = 'done'
                                    journal.save()
                            # Keep native runtime until the other data is removed;
                            # the separate receipt retains recovery state.
                            for path in paths:
                                if path != '/var/lib/pxe-tools-native':
                                    journal.state['steps'][path] = 'intent'
                                    journal.save()
                                    remove_tree(root, path, mounts=mounts_provider(), owner=owner, expected=record['directories'][path], generation_matches=generation_matches)
                                    journal.state['steps'][path] = 'done'
                                    journal.save()
                            journal.state['steps']['apt'] = 'intent'
                            journal.save()
                            source_removed, key_removed = remove_apt_config(root, mounts=mounts_provider(), owner=owner)
                            journal.state['steps']['apt'] = 'done'
                            journal.save()
                            plan.update(source_removed=source_removed, key_removed=key_removed)
                        except (OSError, ValueError, RuntimeError) as error:
                            raise RuntimeError('Package purge succeeded, but data or APT cleanup is incomplete: ' + str(error)) from error
                        if '/var/lib/pxe-tools-native' in paths:
                            try:
                                journal.state['steps']['/var/lib/pxe-tools-native'] = 'intent'
                                journal.save()
                                remove_tree(root, '/var/lib/pxe-tools-native', mounts=mounts_provider(), owner=owner, expected=record['directories']['/var/lib/pxe-tools-native'], generation_matches=generation_matches)
                                journal.state['steps']['/var/lib/pxe-tools-native'] = 'done'
                                journal.save()
                            except (OSError, ValueError, RuntimeError) as error:
                                raise RuntimeError('Package purge succeeded, but native journal cleanup is incomplete: ' + str(error)) from error
                        if nginx_journal is not None:
                            try:
                                current = reconciler.state()
                                if (current['ActiveState'] != 'inactive' or current['UnitFileState'] != 'disabled' or
                                        reconciler.stock() != nginx_journal.record['resources']):
                                    raise ValueError('nginx state or resources changed')
                                journal.state['metadata']['nginx']['intent'] = True
                                journal.save()
                                remove_private_journal(root, '/var/lib/pxe-tools-nginx-ownership', nginx_journal.fd,
                                                       owner=owner, mounts=mounts_provider(), identities=nginx_journal.identities, expected_bytes=nginx_journal.contents)
                            except Exception as error:
                                raise RuntimeError('Package purge succeeded, but nginx provenance is preserved: ' + str(error)) from error
                        if record is not None:
                            try:
                                if ownership._read(ownership_fd) != record:
                                    raise ValueError('ownership journal changed')
                                journal.state['metadata']['ownership']['intent'] = True
                                journal.save()
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


def check_recovery_cgroup(root, runner, unit, *, mounts=()):
    """Refuse recovery while any process remains in a product service cgroup."""
    result = runner(['systemctl', 'show', '--property=ControlGroup', '--value', unit],
                    check=False, text=True, stdout=-1, stderr=-1, timeout=30)
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
    fd = os.open(root, flags)
    try:
        for part in ('sys', 'fs', 'cgroup', *Path(group).parts[1:]):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
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
        scan(fd)
    finally:
        os.close(fd)


def recovery_masks(root, runner, journal, units, *, owner=0, mounts=(), dry_run=False):
    """Verify and remove only the exact mask links created by this receipt."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if any(m != '/' and ('/etc/systemd/system' == m or '/etc/systemd/system'.startswith(m + '/')
                         or m.startswith('/etc/systemd/system/')) for m in mounts):
        raise ValueError('systemd directory crosses a mount boundary')
    fd = os.open(root, flags)
    try:
        for part in ('etc', 'systemd', 'system'):
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted systemd ancestor')
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise ValueError('untrusted systemd directory')
        for unit in units:
            if unit not in UNITS:
                raise ValueError('unsupported service during recovery')
            result = runner(['systemctl', 'show', '--property=ActiveState', '--value', unit],
                            check=False, text=True, stdout=-1, stderr=-1, timeout=30)
            if result.returncode or result.stdout.strip() not in ('inactive', 'failed'):
                raise RuntimeError('service is active during recovery: ' + unit)
            check_recovery_cgroup(root, runner, unit, mounts=mounts)

        def item(name):
            try:
                return os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return None

        def inspect(unit, proof):
            temporary = proof['temporary']
            temp, final = item(temporary), item(unit)
            if proof['phase'] == 'creating':
                if temp is not None or final is not None:
                    raise ValueError('mask creation was interrupted before its identity was recorded: ' + unit)
                return None, None
            present = [entry for entry in (temp, final) if entry is not None]
            for name, entry in ((temporary, temp), (unit, final)):
                if entry is not None and (not stat.S_ISLNK(entry.st_mode)
                        or (entry.st_dev, entry.st_ino) != (proof['dev'], proof['ino'])
                        or (owner is not None and entry.st_uid != owner)
                        or entry.st_nlink != len(present) or os.readlink(name, dir_fd=fd) != '/dev/null'):
                    raise ValueError('removal mask changed; preserved: ' + unit)
            if (not present and proof['phase'] != 'removed') or (final is not None and temp is None):
                raise ValueError('removal mask identity is incomplete: ' + unit)
            if proof['phase'] == 'removed' and final is not None:
                raise ValueError('removed mask was replaced: ' + unit)
            return temp, final

        for unit, proof in journal.state['masks'].items():
            if unit not in units:
                raise ValueError('unexpected removal mask')
            inspect(unit, proof)
        if dry_run:
            return
        changed = False
        for unit, proof in reversed(list(journal.state['masks'].items())):
            temp, final = inspect(unit, proof)
            if proof['phase'] == 'creating':
                del journal.state['masks'][unit]
                journal.save()
                continue
            if final is not None:
                os.unlink(unit, dir_fd=fd)
                os.fsync(fd)
                changed = True
            if proof['phase'] != 'removed':
                proof['phase'] = 'removed'
                journal.save()
            temp, final = inspect(unit, proof)
            if temp is not None:
                os.unlink(proof['temporary'], dir_fd=fd)
                os.fsync(fd)
                changed = True
        if changed:
            result = runner(['systemctl', 'daemon-reload'], check=False, text=True,
                            stdout=-1, stderr=-1, timeout=30)
            if result.returncode:
                raise RuntimeError('systemd reload failed after mask recovery')
    finally:
        os.close(fd)


def legacy_removal_receipt(lifecycle, *, owner=0, required=False):
    """Pin and validate the old in-runtime state before a pre-purge retry."""
    import json
    import re
    from contextlib import contextmanager

    @contextmanager
    def guarded():
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(lifecycle.root, flags)
        opened = None
        try:
            for part in ('var', 'lib', 'pxe-tools-native', 'upgrade'):
                info = os.fstat(directory)
                if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                    raise ValueError('untrusted old removal journal ancestor')
                child = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            info = os.fstat(directory)
            if (owner is not None and info.st_uid != owner) or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('untrusted old removal journal directory')
            try:
                opened = os.open('uninstall-state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                if required:
                    raise ValueError('old removal journal is missing; inspect the service state')
                yield (lambda: None), None
                return
            info = os.fstat(opened)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                    or (owner is not None and info.st_uid != owner) or info.st_size > 2_000_000):
                raise ValueError('untrusted old removal journal')
            data = os.read(opened, 2_000_001)
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate old removal journal field')
                    result[key] = value
                return result
            state = json.loads(data, object_pairs_hook=unique)
            if (not isinstance(state, dict) or state.get('format') != 1 or state.get('version') != 'uninstall'
                    or not isinstance(state.get('id'), str) or not re.fullmatch('[0-9a-f]{32}', state['id'])
                    or state.get('phase') not in ('captured', 'stopped', 'prepared')
                    or not isinstance(state.get('units'), dict) or not set(state['units']) <= set(UNITS)):
                raise ValueError('old removal journal is ambiguous')
            def remove():
                current = os.stat('uninstall-state.json', dir_fd=directory, follow_symlinks=False)
                if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                        or current.st_size != info.st_size):
                    raise ValueError('old removal journal changed')
                os.lseek(opened, 0, os.SEEK_SET)
                if os.read(opened, 2_000_001) != data:
                    raise ValueError('old removal journal contents changed')
                os.unlink('uninstall-state.json', dir_fd=directory)
                os.fsync(directory)
            yield remove, state
        finally:
            if opened is not None:
                os.close(opened)
            os.close(directory)
    return guarded()


def resume_uninstall(root, runner, units, mounts_provider, *, owner=0,
                     account_lookup=None, generation_matches=None, lifecycle=None, ownership=None):
    """Resume only a previously authorised purge, after verifying its receipt."""
    from contextlib import ExitStack
    root = Path(root)
    journal = RemovalJournal(root, owner=owner)
    def verify_finished(state):
        if state['phase'] == 'complete':
            if not packages_absent(runner):
                raise RuntimeError('Packages were installed after removal; completion receipt preserved')
            recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider(), dry_run=True)
        elif state['phase'] == 'aborted':
            if not packages_intact(runner):
                raise RuntimeError('Package state changed after interrupted removal; receipt preserved')
            for unit, expected in state['initial_units'].items():
                active = runner(['systemctl', 'show', '--property=ActiveState', '--value', unit],
                                check=False, text=True, stdout=-1, stderr=-1, timeout=30)
                enabled = runner(['systemctl', 'is-enabled', unit], check=False, text=True,
                                 stdout=-1, stderr=-1, timeout=30)
                actual = active.stdout.strip()
                if (active.returncode or (actual != 'active' if expected['active'] else actual not in ('inactive', 'failed'))
                        or enabled.stdout.strip() != expected['enabled']):
                    raise RuntimeError('Service state changed after interrupted removal: ' + unit)
            if state['worker'] is not None:
                subject = lifecycle or load_lifecycle(root, owner=owner)
                if subject is None:
                    raise RuntimeError('Worker state cannot be verified; receipt preserved')
                _check_worker_not_prepaused(subject)
        else:
            raise ValueError('incomplete completion receipt')
        directory = root / 'etc/systemd/system'
        for unit, proof in state['masks'].items():
            if proof['phase'] != 'removed':
                raise ValueError('completion receipt still has an unfinished mask')
            for path in (directory / unit, directory / proof['temporary']):
                if path.exists() or path.is_symlink():
                    raise ValueError('completion receipt mask path is not empty')

    with dpkg_frontend_lock(root / 'var/lib/dpkg/lock-frontend', owner=owner), \
            installer_lock(root / 'run/lock/pxe-tools-uninstall.lock', owner=owner):
        completed = root / 'var/lib/pxe-tools-uninstall-complete'
        aborted = root / 'var/lib/pxe-tools-uninstall-aborted'
        active = root / 'var/lib/pxe-tools-uninstall'
        if completed.exists() or completed.is_symlink() or aborted.exists() or aborted.is_symlink():
            if (completed.exists() or completed.is_symlink()) and (aborted.exists() or aborted.is_symlink()):
                raise RuntimeError('conflicting completion receipts require inspection')
            if active.exists() or active.is_symlink():
                raise RuntimeError('conflicting removal receipts require inspection')
            completed_name = 'pxe-tools-uninstall-aborted' if (aborted.exists() or aborted.is_symlink()) else 'pxe-tools-uninstall-complete'
            parent = journal._directory(('var', 'lib'))
            try:
                fd = os.open(completed_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if (stat.S_IMODE(info.st_mode) != 0o700 or (owner is not None and info.st_uid != owner)):
                        raise ValueError('untrusted completion receipt')
                    names = journal._entries(fd, state_required=False)
                    if 'state.json' in names:
                        journal.NAME = completed_name
                        state = journal.read()
                        if state['phase'] != ('aborted' if completed_name.endswith('-aborted') else 'complete'):
                            raise ValueError('completion receipt outcome does not match its directory')
                        verify_finished(state)
                        journal.NAME = 'pxe-tools-uninstall'
                        os.rename(completed_name, 'pxe-tools-uninstall', src_dir_fd=parent, dst_dir_fd=parent)
                        os.fsync(parent)
                        journal.finish(aborted=state['phase'] == 'aborted')
                        return
                    if names:
                        raise ValueError('completion receipt state is missing')
                    if completed_name.endswith('-aborted'):
                        if not packages_intact(runner):
                            raise RuntimeError('Empty aborted receipt requires inspection of package state')
                    elif not packages_absent(runner):
                        raise RuntimeError('Empty completion receipt requires inspection while packages are present')
                finally:
                    os.close(fd)
                os.rmdir(completed_name, dir_fd=parent)
                os.fsync(parent)
            finally:
                os.close(parent)
            return
        if not active.exists() and not active.is_symlink():
            if not packages_absent(runner):
                raise RuntimeError('No interrupted removal receipt; installed packages were preserved')
            remaining = list(TREES) + ['/var/lib/pxe-tools-ownership', '/var/lib/pxe-tools-nginx-ownership']
            if any((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink() for path in remaining):
                raise RuntimeError('No interrupted removal receipt; remaining resources were preserved for inspection')
            return 'nothing'
        state_path = active / 'state.json'
        state = (journal.read() if state_path.exists() or state_path.is_symlink()
                 else journal.recover_initial())
        if state['phase'] in ('complete', 'aborted'):
            verify_finished(state)
            journal.finish(aborted=state['phase'] == 'aborted')
            return
        if state['phase'] == 'preparing':
            if not packages_intact(runner):
                raise RuntimeError('Packages changed before purge; inspect dpkg before retrying removal')
            lifecycle = lifecycle or load_lifecycle(root, owner=owner)
            ownership = ownership or load_ownership(root, owner=owner)
            if lifecycle is None or ownership is None:
                raise RuntimeError('Installed recovery helpers are unavailable; inspect the unfinished removal')
            with ExitStack() as stack:
                if state['record'] is not None:
                    ownership_fd = stack.enter_context(ownership._locked(create=False))
                    if ownership._read(ownership_fd) != state['record']:
                        raise ValueError('ownership journal changed before retry')
                else:
                    stack.enter_context(ownership.hold_lock())
                    directory = root / 'var/lib/pxe-tools-ownership'
                    if directory.exists() or directory.is_symlink():
                        raise ValueError('ownership journal appeared before retry')
                matches = generation_matches or ownership.generation.matches
                proven_tree_paths(root, owner=owner, record=state['record'], generation_matches=matches)
                if any(((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink())
                       for path in TREES if path not in state['paths']):
                    raise ValueError('unproven instance paths appeared before retry')
                stack.enter_context(installer_lock(lifecycle.home / 'lock', owner=owner))
                required = (state['worker'] is not None or bool(state['masks'])) and state['restore'] != 'done'
                remove_legacy, prior = stack.enter_context(legacy_removal_receipt(lifecycle, owner=owner, required=required))
                if prior is not None and state['initial_units'] and prior['units'] != state['initial_units']:
                    raise ValueError('recorded service states changed before retry')
                unit_dir = root / 'etc/systemd/system'
                pending_masks = any(
                    mask['phase'] != 'removed' or
                    any(path.exists() or path.is_symlink() for path in
                        (unit_dir / unit, unit_dir / mask['temporary']))
                    for unit, mask in state['masks'].items())
                if pending_masks:
                    recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider(), dry_run=True)
                recover_recorded_worker(lifecycle, state['worker'])
                if pending_masks:
                    recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider())
                if prior is not None and state['restore'] != 'done':
                    state['restore'] = 'intent'
                    journal.save()
                    lifecycle.restore(prior, old=True)
                    state['restore'] = 'done'
                    journal.save()
                remove_legacy()
                journal.finish(aborted=True)
            return 'retry'
        if not packages_absent(runner):
            recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider(), dry_run=True)
            for unit in units:
                status = runner(['systemctl', 'show', '--property=LoadState', '--value', unit],
                                check=False, text=True, stdout=-1, stderr=-1, timeout=30)
                if status.returncode or status.stdout.strip() != 'masked':
                    raise RuntimeError('Package purge is incomplete and a service mask is missing; inspect before any package operation')
            raise RuntimeError('Package purge is incomplete. Inspect sudo dpkg --audit; after resolving errors, '
                               'run sudo dpkg --purge pxe-tools-ansible pxe-tools, then retry --resume. '
                               'Keep the PXE Tools services masked until recovery finishes.')
        generation_matches = generation_matches or recorded_generation_matches
        record = state['record']
        paths = state['paths']
        with ExitStack() as stack:
            for key in ('ownership', 'nginx'):
                if key in state['metadata']:
                    lock_name = ('pxe-tools-ownership.lock' if key == 'ownership' else 'pxe-tools-nginx-reconcile.lock')
                    stack.enter_context(installer_lock(root / 'run/lock' / lock_name, owner=owner))
            recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider(), dry_run=True)
            for path in paths:
                remove_tree(root, path, mounts=mounts_provider(), owner=owner, dry_run=True,
                            expected=record['directories'][path], generation_matches=generation_matches)
                target = root / path.lstrip('/')
                if not target.exists() and not target.is_symlink() and state['steps'][path] == 'pending':
                    raise ValueError('recorded removal directory disappeared before cleanup: ' + path)
            if record is not None and record.get('account') is not None:
                if account_lookup is None:
                    raise RuntimeError('Ansible account inventory is unavailable')
                accounts = account_lookup()
                validate_account(record, accounts['accounts'], accounts['groups'], accounts['process_uids'])
            for key, item in state['metadata'].items():
                name = '/var/lib/pxe-tools-ownership' if key == 'ownership' else '/var/lib/pxe-tools-nginx-ownership'
                remove_private_journal_resumable(root, name, owner=owner, mounts=mounts_provider(),
                    identities=item['identities'], expected_sha256=item['sha256'], authorized=True, dry_run=True)
                if not item['intent']:
                    import hashlib
                    fd = _open_private_journal(root, name, owner, mounts_provider())
                    try:
                        identities = {k: tuple(v) for k, v in item['identities'].items()}
                        if _journal_identities(fd, owner) != identities or hashlib.sha256(_journal_bytes(fd)).hexdigest() != item['sha256']:
                            raise ValueError('private journal changed before cleanup')
                    finally:
                        os.close(fd)
            if 'nginx' in state['metadata']:
                import base64
                import types
                module = types.ModuleType('pxe_saved_nginx_verifier')
                module.__file__ = '/usr/lib/pxe-tools/native/reconcile-nginx.py'
                verifier = base64.b64decode(state['metadata']['nginx']['helper'], validate=True)
                exec(compile(verifier, module.__file__, 'exec'), module.__dict__)
                reconciler = module.Reconciler(root, run=runner)
                nginx_record = state['metadata']['nginx']['record']
                current = reconciler.state()
                if (current['ActiveState'] != 'inactive' or current['UnitFileState'] != 'disabled'
                        or reconciler.stock() != nginx_record.get('resources')):
                    raise ValueError('nginx state or resources changed; preserved')
                if not state['metadata']['nginx']['intent']:
                    with nginx_journal_guard(root, reconciler, owner=owner, mounts=mounts_provider()) as nginx:
                        if nginx is None or nginx.record != nginx_record:
                            raise ValueError('nginx provenance disappeared or changed before cleanup')
                        state['metadata']['nginx']['intent'] = True
                        journal.save()
            state['phase'] = 'cleaning'
            journal.save()
            if record is not None and record.get('account') is not None:
                state['steps']['account'] = 'intent'; journal.save()
                remove_account(record, runner, account_lookup)
                state['steps']['account'] = 'done'; journal.save()
                state['steps']['group'] = 'intent'; journal.save()
                remove_group(record, runner, account_lookup)
                state['steps']['group'] = 'done'; journal.save()
            for path in paths:
                target = root / path.lstrip('/')
                if state['steps'][path] == 'done' and not target.exists() and not target.is_symlink():
                    continue
                state['steps'][path] = 'intent'; journal.save()
                remove_tree(root, path, mounts=mounts_provider(), owner=owner,
                            expected=record['directories'][path], generation_matches=generation_matches)
                state['steps'][path] = 'done'; journal.save()
            if state['steps']['apt'] != 'done':
                state['steps']['apt'] = 'intent'; journal.save()
                remove_apt_config(root, mounts=mounts_provider(), owner=owner)
                state['steps']['apt'] = 'done'; journal.save()
            for key, item in state['metadata'].items():
                item['intent'] = True; journal.save()
                name = '/var/lib/pxe-tools-ownership' if key == 'ownership' else '/var/lib/pxe-tools-nginx-ownership'
                remove_private_journal_resumable(root, name, owner=owner, mounts=mounts_provider(),
                    identities=item['identities'], expected_sha256=item['sha256'], authorized=True)
            recovery_masks(root, runner, journal, units, owner=owner, mounts=mounts_provider())
            journal.finish()


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
    choice.add_argument('--resume', action='store_true', help='resume an interrupted, authorised removal')
    return parser.parse_args(argv)


def read_package_helper(root, filename, *, owner=0):
    """Read a specific installed helper without following links."""
    if filename not in ('upgrade-lifecycle.py', 'ownership-provenance.py', 'reconcile-nginx.py'):
        raise ValueError('unsupported package helper')
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
    return data


def load_package_helper(root, filename, *, owner=0):
    import types
    data = read_package_helper(root, filename, owner=owner)
    if data is None:
        return None
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


def _worker_read(root, parts, *, maximum=65536):
    """Read a proc/cgroup observation under an injected root without links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            data = os.read(child, maximum + 1)
            if len(data) > maximum:
                raise RuntimeError('worker observation exceeds size limit')
            return data
        finally:
            os.close(child)
    finally:
        os.close(fd)


def _worker_boot_id(lifecycle):
    import re
    try:
        value = _worker_read(lifecycle.root, ('proc', 'sys', 'kernel', 'random', 'boot_id')).decode('ascii').strip()
    except (OSError, UnicodeError) as error:
        raise RuntimeError('cannot establish worker boot identity') from error
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value):
        raise RuntimeError('cannot establish worker boot identity')
    return value


def _worker_process(lifecycle, pid, group):
    """Return the original process start time and its task states."""
    def stat_record(data, expected):
        prefix, separator, suffix = data.rpartition(b')')
        fields = suffix.split()
        if (not separator or not prefix.startswith(expected.encode('ascii') + b' (')
                or len(fields) < 20 or len(fields[0]) != 1 or not fields[19].isdigit()):
            raise RuntimeError('worker process identity cannot be established')
        return fields[0].decode('ascii'), fields[19].decode('ascii')

    try:
        state, started = stat_record(_worker_read(lifecycle.root, ('proc', pid, 'stat')), pid)
        cgroups = _worker_read(lifecycle.root, ('proc', pid, 'cgroup')).decode('ascii').splitlines()
        if cgroups.count('0::' + group) != 1:
            raise RuntimeError('worker process cgroup changed')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(lifecycle.root, flags)
        try:
            for part in ('proc', pid, 'task'):
                child = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = child
            threads = os.listdir(directory)
            if pid not in threads or any(not item.isascii() or not item.isdecimal() for item in threads):
                raise RuntimeError('worker threads cannot be established')
            states = []
            for tid in threads:
                thread = os.open(tid, flags, dir_fd=directory)
                try:
                    descriptor = os.open('stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=thread)
                    try:
                        data = os.read(descriptor, 65537)
                    finally:
                        os.close(descriptor)
                    if len(data) > 65536:
                        raise RuntimeError('worker thread state too large')
                    thread_state, thread_started = stat_record(data, tid)
                    if tid == pid and (thread_started != started or thread_state != state):
                        raise RuntimeError('worker identity changed during inspection')
                    states.append(thread_state)
                finally:
                    os.close(thread)
            if set(os.listdir(directory)) != set(threads):
                raise RuntimeError('worker threads changed during inspection')
        finally:
            os.close(directory)
        if stat_record(_worker_read(lifecycle.root, ('proc', pid, 'stat')), pid) != (state, started):
            raise RuntimeError('worker identity changed during inspection')
        return started, tuple(states)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError('cannot safely inspect worker process') from error


def _worker_record(lifecycle):
    """Capture a live worker only after its current state was checked safe."""
    _check_worker_not_prepaused(lifecycle)
    before = lifecycle.worker_status()
    if before.get('ActiveState') != 'active':
        return None
    pid, group = before.get('MainPID', ''), before.get('ControlGroup', '')
    if not pid.isascii() or not pid.isdecimal() or int(pid) <= 1:
        raise RuntimeError('worker PID cannot be established')
    boot = _worker_boot_id(lifecycle)
    started, states = _worker_process(lifecycle, pid, group)
    if any(state not in ('R', 'S', 'D', 'I') for state in states):
        raise RuntimeError('worker process is stopped or its state is uncertain')
    if lifecycle.worker_status() != before or _worker_boot_id(lifecycle) != boot:
        raise RuntimeError('worker identity changed during capture')
    return {'boot_id': boot, 'pid': pid, 'starttime': started,
            'cgroup': group, 'phase': 'freeze_intent'}


def recover_recorded_worker(lifecycle, worker):
    """Undo only a recorded freeze/SIGSTOP on the same, verified worker."""
    import re
    import signal
    import time
    if worker is None:
        _check_worker_not_prepaused(lifecycle)
        return
    if (not isinstance(worker, dict) or set(worker) != {'boot_id', 'pid', 'starttime', 'cgroup', 'phase'}
            or not isinstance(worker['boot_id'], str)
            or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', worker['boot_id'])
            or not isinstance(worker['pid'], str) or not re.fullmatch(r'[0-9]+', worker['pid']) or int(worker['pid']) <= 1
            or not isinstance(worker['starttime'], str) or not re.fullmatch(r'[0-9]+', worker['starttime'])
            or not isinstance(worker['cgroup'], str) or not worker['cgroup'].startswith('/')
            or worker['cgroup'] == '/' or '..' in Path(worker['cgroup']).parts
            or worker['phase'] not in ('freeze_intent', 'frozen', 'stop_intent', 'sigstop_confirmed', 'stopped')):
        raise ValueError('invalid recorded worker identity')

    status = lifecycle.worker_status()
    boot = _worker_boot_id(lifecycle)
    # A replacement or reboot must never receive a signal intended for the old
    # process. It is safe to continue only when the current worker is healthy.
    if (boot != worker['boot_id'] or status.get('MainPID') != worker['pid']
            or status.get('ControlGroup') != worker['cgroup'] or status.get('ActiveState') != 'active'):
        _check_worker_not_prepaused(lifecycle)
        return

    pid, group = worker['pid'], worker['cgroup']
    started, states = _worker_process(lifecycle, pid, group)
    if started != worker['starttime'] or lifecycle.worker_status() != status or _worker_boot_id(lifecycle) != boot:
        raise RuntimeError('recorded worker identity changed; no signal sent')
    if worker['phase'] == 'stop_intent':
        # The syscall might have happened without its receipt reaching disk.
        # An apparently running task can still have a pending SIGSTOP.
        raise RuntimeError('worker stop outcome is uncertain; inspect before recovery')
    if any(state not in ('R', 'S', 'D', 'I', 'T') for state in states):
        raise RuntimeError('worker state cannot be recovered safely')
    stopped = 'T' in states
    if stopped and (worker['phase'] != 'sigstop_confirmed' or any(state != 'T' for state in states)):
        raise RuntimeError('worker was stopped without a matching stop intent')
    if worker['phase'] == 'stopped':
        _check_worker_not_prepaused(lifecycle)
        return

    def freezer(parts):
        freeze = _worker_read(lifecycle.root, ('sys', 'fs', 'cgroup', *parts, 'cgroup.freeze')).decode('ascii').strip()
        events = [line.split() for line in _worker_read(lifecycle.root, ('sys', 'fs', 'cgroup', *parts, 'cgroup.events')).decode('ascii').splitlines()]
        values = [entry for entry in events if entry and entry[0] == 'frozen']
        if freeze not in ('0', '1') or values not in ([['frozen', '0']], [['frozen', '1']]):
            raise RuntimeError('worker freezer state is ambiguous')
        return freeze, values[0][1]

    try:
        parts = Path(group).parts[1:]
        for end in range(1, len(parts)):
            if freezer(parts[:end]) != ('0', '0'):
                raise RuntimeError('worker ancestor is frozen; preserved')
        freeze, frozen = freezer(parts)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError('cannot establish worker freezer state') from error
    if (freeze, frozen) not in (('0', '0'), ('1', '1')) or status.get('FreezerState') not in ('running', 'frozen'):
        raise RuntimeError('worker freezer is transitioning; preserved')
    if worker['phase'] == 'freeze_intent' and (freeze != '0' or frozen != '0' or status['FreezerState'] != 'running'):
        raise RuntimeError('worker freeze outcome is uncertain; inspect before recovery')
    if freeze == '1' or status['FreezerState'] == 'frozen':
        lifecycle.thaw_worker()
        current = lifecycle.worker_status()
        after, states = _worker_process(lifecycle, pid, group)
        if (current.get('MainPID') != pid or current.get('ControlGroup') != group
                or current.get('ActiveState') != 'active' or _worker_boot_id(lifecycle) != boot
                or after != started):
            raise RuntimeError('worker identity changed during thaw; no signal sent')
        if stopped and any(state != 'T' for state in states):
            raise RuntimeError('worker state changed during thaw; no signal sent')
    if worker['phase'] == 'sigstop_confirmed':
        current = lifecycle.worker_status()
        before_signal, signal_states = _worker_process(lifecycle, pid, group)
        if (current.get('MainPID') != pid or current.get('ControlGroup') != group
                or current.get('ActiveState') != 'active' or _worker_boot_id(lifecycle) != boot
                or before_signal != started or any(state not in ('R', 'S', 'D', 'I', 'T') for state in signal_states)
                or ('T' in signal_states and any(state != 'T' for state in signal_states))):
            raise RuntimeError('worker identity changed before signal; no signal sent')
        lifecycle.signaler(int(pid), signal.SIGCONT)
        deadline = time.monotonic() + 2
        while True:
            try:
                _check_worker_not_prepaused(lifecycle)
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('worker did not resume; inspect before retrying')
                time.sleep(0.02)
    else:
        _check_worker_not_prepaused(lifecycle)


def quiesced_lifecycle(lifecycle, *, after_stop=None, journal=None):
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
        original_signaler = getattr(lifecycle, 'signaler', None)
        override_keys = ('busy', 'stop', 'freeze_worker', 'release_worker') + (
            ('signaler',) if journal is not None and callable(original_signaler) else ())
        overrides = {key: lifecycle.__dict__.get(key) for key in override_keys}
        present = {key: key in lifecycle.__dict__ for key in override_keys}
        state = None
        stop_started = False
        freeze_confirmed = False
        signal_uncertain = False

        class Transaction:
            purge_started = False
            def record_mask(self, unit, temporary, dev, ino, phase):
                state.setdefault('removal_masks', {})[unit] = {
                    'temporary': temporary, 'dev': dev, 'ino': ino, 'phase': phase}
                if journal is not None:
                    journal.state['masks'][unit] = dict(state['removal_masks'][unit])
                    journal.save()
                if journal is None or journal.state['phase'] == 'preparing':
                    lifecycle.save(state)
            def begin_purge(self):
                if journal is not None:
                    journal.state['phase'] = 'purge_started'
                    journal.save()
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
            if journal is not None and frozen:
                if not callable(original_signaler):
                    raise BarrierRecoveryRequired('worker signal instrumentation is unavailable')
                worker = journal.state.get('worker')
                if not isinstance(worker, dict) or worker.get('phase') != 'frozen':
                    raise BarrierRecoveryRequired('worker freeze receipt is incomplete; inspect before retrying')
                worker['phase'] = 'stop_intent'
                journal.save()
            stop_started = True
            result = original_stop(state_arg, frozen)
            if journal is not None and journal.state.get('worker') is not None:
                journal.state['worker']['phase'] = 'stopped'
                journal.save()
            if after_stop is not None:
                stack.enter_context(after_stop(transaction))
            return result

        def removal_freeze(state_arg):
            nonlocal freeze_confirmed
            _check_worker_not_prepaused(lifecycle)
            if journal is not None:
                journal.state['worker'] = _worker_record(lifecycle)
                journal.save()
            try:
                frozen = original_freeze(state_arg)
                if type(frozen) is not bool:
                    raise RuntimeError('unexpected freeze result')
                if journal is not None and frozen:
                    if journal.state['worker'] is None:
                        raise RuntimeError('worker became active without recorded identity')
                    journal.state['worker']['phase'] = 'frozen'
                    journal.save()
            except BaseException as error:
                raise BarrierRecoveryRequired(
                    'worker freeze outcome is uncertain; journal retained for manual recovery') from error
            freeze_confirmed = frozen
            return frozen

        def removal_release():
            if freeze_confirmed and not signal_uncertain:
                original_release()

        def removal_signaler(pid, sig):
            nonlocal signal_uncertain
            import signal
            if sig != signal.SIGSTOP:
                return original_signaler(pid, sig)
            worker = journal.state.get('worker')
            try:
                if (not isinstance(worker, dict) or worker.get('phase') != 'stop_intent'
                        or str(pid) != worker.get('pid')):
                    raise RuntimeError('worker stop intent is unavailable')
                current = lifecycle.worker_status()
                started, states = _worker_process(lifecycle, worker['pid'], worker['cgroup'])
                if (current.get('ActiveState') != 'active' or current.get('MainPID') != worker['pid']
                        or current.get('ControlGroup') != worker['cgroup']
                        or _worker_boot_id(lifecycle) != worker['boot_id'] or started != worker['starttime']
                        or any(state not in ('R', 'S', 'D', 'I') for state in states)):
                    raise RuntimeError('worker identity changed before SIGSTOP')
                result = original_signaler(pid, sig)
                worker['phase'] = 'sigstop_confirmed'
                journal.save()
                current = lifecycle.worker_status()
                started, _ = _worker_process(lifecycle, worker['pid'], worker['cgroup'])
                if (current.get('ActiveState') != 'active' or current.get('MainPID') != worker['pid']
                        or current.get('ControlGroup') != worker['cgroup']
                        or _worker_boot_id(lifecycle) != worker['boot_id'] or started != worker['starttime']):
                    raise RuntimeError('worker identity changed after SIGSTOP')
                return result
            except BaseException as error:
                # A signal may have been delivered even if the call or durable
                # receipt failed; do not thaw or issue SIGCONT on this path.
                signal_uncertain = True
                raise BarrierRecoveryRequired('worker SIGSTOP outcome is uncertain; inspect before recovery') from error

        try:
            with ExitStack() as stack:
                state = lifecycle.capture('uninstall')
                if journal is not None:
                    journal.state['initial_units'] = state.get('units', {})
                    journal.save()
                lifecycle.busy = removal_busy
                lifecycle.stop = removal_stop
                lifecycle.freeze_worker = removal_freeze
                lifecycle.release_worker = removal_release
                if 'signaler' in override_keys:
                    lifecycle.signaler = removal_signaler
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
                    if journal is not None:
                        journal.state['restore'] = 'done'
                        journal.save()
                    removal_file.unlink()
                    lifecycle.sync_directory(lifecycle.home)
                except Exception as error:
                    raise BarrierRecoveryRequired('Previous PXE Tools services could not all be restored; removal journal preserved: ' + str(error)) from error
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
    def mounts():
        return parse_mountinfo(Path('/proc/self/mountinfo').read_text(encoding='utf-8'))
    if args.resume:
        with installer_lock(Path('/run/lock/pxe-tools-apt-install.lock')):
            account_lookup = lambda: account_snapshot(Path('/'), list(pwd.getpwall()), list(grp.getgrall()))
            result = resume_uninstall(Path('/'), subprocess.run, UNITS, mounts, account_lookup=account_lookup)
            if result == 'retry':
                lifecycle = load_lifecycle(Path('/'))
                ownership = load_ownership(Path('/'))
                reconciler = load_reconciler(Path('/'), subprocess.run)
                try:
                    record = ownership.read() if ownership is not None else None
                except FileNotFoundError:
                    record = None
                run_uninstall(Path('/'), subprocess.run, lifecycle, UNITS, mounts, apply=True,
                              record=record, ownership=ownership, reconciler=reconciler,
                              account_lookup=account_lookup)
        print('No interrupted removal was found.' if result == 'nothing' else 'Interrupted removal resumed.')
        return 0
    lifecycle = load_lifecycle(Path('/'))
    ownership = load_ownership(Path('/'))
    reconciler = load_reconciler(Path('/'), subprocess.run)
    try:
        record = ownership.read() if ownership is not None else None
    except FileNotFoundError:
        record = None
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
