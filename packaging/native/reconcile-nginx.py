#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Read-only verifier for ownership receipts left by older installations.

The uninstaller uses this module to validate a receipt before removing it.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess


class Preserve(RuntimeError):
    """Insufficient evidence to change a service."""


@contextmanager
def stable_nginx_lock(root=Path('/'), *, owner=0):
    """Hold the permanent, shared reconciliation lock; never unlink it."""
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    lock = None
    name = 'pxe-tools-nginx-reconcile.lock'
    try:
        for part in ('run', 'lock'):
            info = os.fstat(directory)
            if info.st_uid != owner or info.st_mode & 0o022:
                raise Preserve('Ancêtre du verrou nginx non fiable.')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if info.st_uid != owner or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise Preserve('Répertoire du verrou nginx non fiable.')
        flags = os.O_RDWR | os.O_NOFOLLOW
        try:
            lock = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            os.fchmod(lock, 0o600)
            os.fsync(directory)
        except FileExistsError:
            lock = os.open(name, flags, dir_fd=directory)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise Preserve('Verrou nginx permanent non fiable.')
        identity = (info.st_dev, info.st_ino)
        for acquire in (False, True):
            if acquire:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                raise Preserve('Verrou nginx permanent remplacé.')
        yield
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


class Reconciler:
    def __init__(self, root=Path('/'), run=subprocess.run):
        self.root = Path(root).resolve()
        self.run = run

    def path(self, name):
        return self.root / str(name).lstrip('/')

    def command(self, *args):
        result = self.run(list(args), text=True, capture_output=True, timeout=15)
        if result.returncode:
            raise Preserve('Commande système non vérifiable : ' + Path(args[0]).name)
        return result.stdout.strip()

    def read(self, name, limit=2 * 1024 * 1024):
        path = self.path(name)
        # /proc/net is a kernel-provided symlink to the caller's namespace.
        # Only fixed proc paths and validated numeric PIDs reach this branch.
        if str(name).startswith('/proc/'):
            data = path.read_bytes()
            if len(data) > limit:
                raise Preserve('Observation de processus trop volumineuse.')
            return data
        for part in (path, *path.parents):
            if part == self.root:
                break
            info = part.lstat()
            if part.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise Preserve('Chemin non fiable : ' + str(name))
        if not path.is_file() or path.stat().st_size > limit:
            raise Preserve('Fichier non vérifiable : ' + str(name))
        return path.read_bytes()

    def state(self):
        return {key: self.command('/usr/bin/systemctl', 'show', '--property=' + key,
                                  '--value', 'nginx.service')
                for key in ('ActiveState', 'UnitFileState', 'MainPID', 'ControlGroup',
                            'FragmentPath', 'DropInPaths')}

    def package_sums(self):
        text = self.read('/var/lib/dpkg/info/nginx-common.md5sums').decode()
        return {parts[1]: parts[0] for line in text.splitlines()
                if len(parts := line.split()) == 2 and re.fullmatch('[0-9a-f]{32}', parts[0])}

    def stock(self):
        for package in ('nginx', 'nginx-common'):
            if self.command('/usr/bin/dpkg-query', '-W', '-f=${Status}', package) != 'install ok installed':
                raise Preserve('Le paquet ' + package + ' n’est pas configuré.')
        text = self.command('/usr/bin/dpkg-query', '-W', '-f=${Conffiles}', 'nginx-common')
        conffiles = {}
        for line in text.splitlines():
            parts = line.split()
            if len(parts) == 2 and re.fullmatch('[0-9a-f]{32}', parts[1]):
                conffiles[parts[0]] = parts[1]
        resources = {}

        def checked(name, expected):
            data = self.read(name)
            if expected is None or hashlib.md5(data).hexdigest() != expected:
                raise Preserve('Configuration ou contenu nginx personnalisé : ' + name)
            info = self.path(name).stat()
            resources[name] = {'sha256': hashlib.sha256(data).hexdigest(),
                               'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
            return data.decode()

        for name in ('/etc/nginx/nginx.conf', '/etc/nginx/sites-available/default', '/etc/nginx/mime.types'):
            checked(name, conffiles.get(name))
        master = self.read('/etc/nginx/nginx.conf').decode()
        includes = [value.strip() for value in re.findall(r'(?m)^\s*include\s+([^;\n]+);', re.sub(r'#[^\n]*', '', master))]
        allowed = {'/etc/nginx/modules-enabled/*.conf', '/etc/nginx/mime.types',
                   '/etc/nginx/conf.d/*.conf', '/etc/nginx/sites-enabled/*'}
        if not includes or set(includes) - allowed or '/etc/nginx/sites-enabled/*' not in includes:
            raise Preserve('Includes nginx non reconnus ; service conservé.')
        for name in ('/etc/nginx/conf.d', '/etc/nginx/modules-enabled'):
            directory = self.path(name)
            if directory.exists() and list(directory.iterdir()):
                raise Preserve('Autres fichiers nginx présents : ' + name)
        enabled = self.path('/etc/nginx/sites-enabled')
        link = enabled / 'default'
        if sorted(p.name for p in enabled.iterdir()) != ['default'] or not link.is_symlink():
            raise Preserve('Autres sites nginx présents ; service conservé.')
        target = os.readlink(link)
        resolved = self.path(target) if target.startswith('/') else link.parent / target
        if resolved.resolve() != self.path('/etc/nginx/sites-available/default').resolve():
            raise Preserve('Le site default ne désigne pas le fichier du paquet.')
        info = link.lstat()
        if info.st_uid != 0:
            raise Preserve('Lien nginx non fiable.')
        resources['/etc/nginx/sites-enabled/default'] = {
            'target': target, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
        webroot = self.path('/var/www/html')
        if sorted(str(p.relative_to(webroot)) for p in webroot.rglob('*')) != ['index.nginx-debian.html']:
            raise Preserve('Contenu web utilisateur présent ; service conservé.')
        sums = self.package_sums()
        welcome = checked('/usr/share/nginx/html/index.html', sums.get('usr/share/nginx/html/index.html'))
        checked('/var/www/html/index.nginx-debian.html', hashlib.md5(welcome.encode()).hexdigest())
        service = self.state()
        fragment = service['FragmentPath']
        if fragment not in ('/usr/lib/systemd/system/nginx.service', '/lib/systemd/system/nginx.service') or service['DropInPaths']:
            raise Preserve('Unité nginx personnalisée ; service conservé.')
        # Account for merged-/usr without following an arbitrary unit symlink.
        unit = '/usr/lib/systemd/system/nginx.service' if self.path('/lib').is_symlink() else fragment
        checked(unit, sums.get(unit.lstrip('/')) or sums.get(unit.removeprefix('/usr/')))
        for name in ('/etc/nginx', '/etc/nginx/sites-enabled', '/etc/nginx/conf.d',
                     '/etc/nginx/modules-enabled', '/var/www/html'):
            directory = self.path(name)
            if directory.exists():
                info = directory.lstat()
                if directory.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise Preserve('Répertoire nginx non fiable.')
                resources[name] = {'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
        return resources
