#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Native APT removal candidate; validation is not yet complete.

Do not publish or run this candidate on a real host.
"""
import os
from pathlib import Path
import shutil
import stat

# Only package-specific, historically documented paths. Custom paths require
# explicit inspection; a pathname is never evidence that its target is ours.
TREES = frozenset({
    '/etc/pxe-tools', '/var/lib/pxe-tools', '/var/lib/pxe-tools-native',
    '/var/lib/pxe-tools-http', '/var/lib/pxe-tools-tftp',
    '/var/lib/pxe-tools-ansible', '/var/log/pxe-tools',
})


def remove_tree(root, name, *, mounts, owner=0, dry_run=False):
    """Remove one allowlisted tree without traversing a symlink or mount.

    The fixture root is an internal parameter, not exposed through a CLI.
    Callers must establish provenance and stop services before invoking this.
    """
    if name not in TREES:
        raise ValueError('unrecognised removal path')
    if any(m == name or m.startswith(name + '/') for m in mounts):
        raise ValueError('mount within removal path; preserved')
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError('safe directory removal unavailable')
    parts = Path(name).parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root, flags)
    try:
        for component in parts[:-1]:
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                raise ValueError('untrusted removal ancestor')
            try:
                child = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                return
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise ValueError('untrusted removal ancestor')
        try:
            target = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(target.st_mode):
            raise ValueError('removal root is not a directory; preserved')
        if not dry_run:
            shutil.rmtree(parts[-1], dir_fd=fd)
    finally:
        os.close(fd)


def apt_cleanup_plan(root, *, owner=0):
    """Recognise the installer's source and preserve ambiguous key usage."""
    import re
    root = Path(root)
    source = root / 'etc/apt/sources.list.d/pxe-tools.sources'
    key = root / 'etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
    signed_by = '/etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
    template = (r'Types: deb\nURIs: https://[A-Za-z0-9][A-Za-z0-9.-]*'
                r'(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]*)?\n'
                r'Suites: stable\nComponents: main\nArchitectures: amd64\n'
                r'Signed-By: /etc/apt/keyrings/pxe-tools-archive-keyring\.gpg\n')
    try:
        for path in (root, root / 'etc', root / 'etc/apt', source.parent, key.parent):
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
        remove_key = key.is_file() and not key.is_symlink() and key.stat().st_nlink == 1
        if remove_key and owner is not None:
            key_info = key.stat()
            remove_key = key_info.st_uid == owner and not key_info.st_mode & 0o022
        sources = root / 'etc/apt/sources.list.d'
        other_sources = [root / 'etc/apt/sources.list']
        other_sources.extend(p for p in sources.iterdir() if p != source and p.suffix in ('.list', '.sources'))
        for path in other_sources:
            if path.is_symlink():
                remove_key = False
            elif path.exists():
                if not path.is_file():
                    remove_key = False
                    continue
                text = path.read_text(encoding='utf-8', errors='strict')
                if signed_by in text:
                    remove_key = False
                # Resolve absolute paths named by any other source, including
                # aliases outside keyrings. Unreadable references fail closed.
                for candidate in re.findall(r'(?<![A-Za-z0-9:])(/[A-Za-z0-9_.+/-]+)', text):
                    other = root / candidate.lstrip('/')
                    if other.exists() and key.exists() and os.path.samefile(other, key):
                        remove_key = False
        # Alias paths could make another source use this key without naming its
        # canonical path. Preserve on any symlink or hard link in APT key dirs.
        for directory in (root / 'etc/apt/keyrings', root / 'etc/apt/trusted.gpg.d'):
            if directory.is_symlink():
                remove_key = False
            elif directory.exists():
                for item in directory.iterdir():
                    if item == key:
                        continue
                    if item.is_symlink() or (item.is_file() and key.exists() and os.path.samestat(item.stat(), key.stat())):
                        remove_key = False
        return True, bool(remove_key)
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


def purge_packages(runner):
    """Ask dpkg to remove only the two packages; never remove dependencies."""
    result = runner(['dpkg', '--purge', 'pxe-tools-ansible', 'pxe-tools'], check=False)
    if result.returncode:
        raise RuntimeError('package purge failed; data and APT source were preserved')


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
    """Remove only the recognised source and its unshared key, if safe."""
    source_name = '/etc/apt/sources.list.d/pxe-tools.sources'
    key_name = '/etc/apt/keyrings/pxe-tools-archive-keyring.gpg'
    source_ok, key_ok = apt_cleanup_plan(root, owner=owner)

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
    if key_ok and not mounted(key_name):
        unlink_checked(key_name)
        return True, True
    return True, False


def proven_tree_paths(root, *, owner=0):
    """Recognise only directories created by the native runtime helper.

    The helper does not prove creation of the application database, config,
    Ansible workspace, account or log directory; all remain for review.
    """
    marker = (b'TFTP_ROOT=/var/lib/pxe-tools-tftp\n'
              b'HTTP_ROOT=/var/lib/pxe-tools-http\n'
              b'PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\n'
              b'MOK_DIR=/var/lib/pxe-tools-native/mok\n')
    fd = None
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in ('var', 'lib', 'pxe-tools-native'):
            info = os.fstat(fd)
            if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
                return ()
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            return ()
        child = os.open('runtime.env', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
                return ()
            if os.read(child, len(marker) + 1) != marker:
                return ()
        finally:
            os.close(child)
        return ('/var/lib/pxe-tools-http', '/var/lib/pxe-tools-tftp',
                '/var/lib/pxe-tools-native')
    except OSError:
        return ()
    finally:
        if fd is not None:
            os.close(fd)


def run_uninstall(root, runner, lifecycle, units, mounts_provider, *, owner=0, apply=False):
    """Prepare a bounded transaction. The root override is internal for tests."""
    root = Path(root)
    paths = proven_tree_paths(root, owner=owner)
    mounts = mounts_provider()
    for path in paths:
        remove_tree(root, path, mounts=mounts, owner=owner, dry_run=True)
    source, key = apt_cleanup_plan(root, owner=owner)
    preserved = tuple(path for path in sorted(TREES) if path not in paths and
                      ((root / path.lstrip('/')).exists() or (root / path.lstrip('/')).is_symlink()))
    plan = {'trees': paths, 'source': source, 'key': key, 'preserved': preserved}
    if not apply:
        return plan
    if preserved:
        raise RuntimeError('Cannot establish ownership of all instance paths; no package was removed')
    critical = ('/etc/pxe-tools', '/var/lib/pxe-tools', '/var/lib/pxe-tools-native')
    if lifecycle is None and any((root / p.lstrip('/')).exists() or
                                 (root / p.lstrip('/')).is_symlink() for p in critical):
        raise RuntimeError('Cannot establish whether previous PXE operations are active; preserve data and inspect the partial installation')
    from contextlib import nullcontext
    guard = upgrade_guard(lifecycle, owner=owner) if lifecycle is not None else nullcontext()
    with guard:
        def check_before_mask():
            if lifecycle is not None:
                try:
                    lifecycle.check_effective_configuration()
                    if lifecycle.freeze_worker({}):
                        raise RuntimeError('Worker unexpectedly became active')
                finally:
                    lifecycle.release_worker()
        with service_barrier(runner, units, before_mask=check_before_mask):
            if lifecycle is not None:
                assert_idle_database(lifecycle)
            # Refuse mounted or replaced paths before the package operation.
            mounts = mounts_provider()
            for path in paths:
                remove_tree(root, path, mounts=mounts, owner=owner, dry_run=True)
            purge_packages(runner)
            try:
                # Keep the native marker until last for diagnosis after failure.
                for path in paths:
                    remove_tree(root, path, mounts=mounts_provider(), owner=owner)
                source_removed, key_removed = remove_apt_config(root, mounts=mounts_provider(), owner=owner)
                plan.update(source_removed=source_removed, key_removed=key_removed)
            except (OSError, ValueError, RuntimeError) as error:
                raise RuntimeError('Package purge succeeded, but data or APT cleanup is incomplete: ' + str(error)) from error
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


def load_lifecycle(root, *, owner=0):
    """Load the installed, root-owned package helper without following links."""
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
            child = os.open('upgrade-lifecycle.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
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
    module.__file__ = '/usr/lib/pxe-tools/native/upgrade-lifecycle.py'
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module.Lifecycle(Path(root))


def upgrade_guard(lifecycle, *, owner=0):
    """Serialize with package upgrades and refuse an unfinished journal."""
    from contextlib import contextmanager

    @contextmanager
    def guard():
        if lifecycle.home.parent.is_symlink() or not lifecycle.home.parent.is_dir():
            raise RuntimeError('Native runtime missing or unsafe; inspect the partial installation')
        lifecycle.private_home()
        with installer_lock(lifecycle.home / 'lock', owner=owner):
            if lifecycle.state_file.is_symlink() or lifecycle.load() is not None:
                raise RuntimeError('An earlier PXE Tools upgrade requires recovery before removal')
            yield
    return guard()


def external_paths(lifecycle, recognised):
    """Report configured paths outside the recognised roots without reading them."""
    keys = ('HTTP_ROOT', 'TFTP_ROOT', 'PXE_TOOLS_DATA_DIR', 'MOK_DIR', 'TLS_DIR',
            'PXE_MASTER_KEY_PATH', 'PXE_DB_PATH', 'ORCHESTRATOR_DB',
            'ANSIBLE_WORKDIR', 'PXE_ANSIBLE_HOME')
    values = lifecycle.environments()
    candidates = [values.get(key, '') for key in keys]
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


def main(argv):
    import subprocess
    import sys
    args = parse_arguments(argv)
    require_release_ready(args.yes)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Run as root on the Linux host where PXE Tools was installed')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('A running systemd host is required')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    lifecycle = load_lifecycle(Path('/'))
    def mounts():
        return parse_mountinfo(Path('/proc/self/mountinfo').read_text(encoding='utf-8'))
    preview = run_uninstall(Path('/'), subprocess.run, lifecycle, UNITS, mounts, apply=False)
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
        print('After all operations finish, stop the dedicated services and use --yes to consent:')
        print('sudo systemctl stop ' + ' '.join(UNITS))
        return 0
    if outside:
        raise RuntimeError('Configured paths outside recognised roots require review; no package was removed')
    with installer_lock(Path('/run/lock/pxe-tools-apt-install.lock')):
        result = run_uninstall(Path('/'), subprocess.run, lifecycle, UNITS, mounts, apply=True)
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
