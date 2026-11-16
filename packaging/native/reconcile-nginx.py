#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Reconcile only the stock nginx service installed as our APT dependency.

No global service policy, site deletion or application/network activation. Missing
evidence is a preserved service, not permission to guess. The private journal is
also the ownership contract for a future removal tool; it is not a blanket right
to restore a service after an administrator has changed it.
"""
import argparse
from datetime import datetime
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


class Preserve(RuntimeError):
    """Insufficient evidence to change a service."""


class Reconciler:
    def __init__(self, root=Path('/'), run=subprocess.run, configuring=False):
        self.root = Path(root).resolve()
        self.run = run
        self.configuring = configuring
        self.directory = self.path('/var/lib/pxe-tools-nginx-ownership')
        self.journal = self.directory / 'state.json'

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

    def process_start(self, pid):
        text = self.read('/proc/' + pid + '/stat').decode()
        fields = text[text.rindex(') ') + 2:].split()
        return fields[19], fields[1]

    def started_at(self, pid):
        ticks, _ = self.process_start(pid)
        boot = re.search(r'(?m)^btime ([0-9]+)$', self.read('/proc/stat').decode())
        if not boot:
            raise Preserve('Date de démarrage non vérifiable.')
        return int(boot[1]) + int(ticks) / os.sysconf('SC_CLK_TCK')

    def identity(self, resources):
        service = self.state()
        pid = service['MainPID']
        if not pid.isdecimal() or int(pid) <= 1 or service['ControlGroup'] != '/system.slice/nginx.service':
            raise Preserve('Identité du service nginx non vérifiable.')
        exe = os.readlink(self.path('/proc/' + pid + '/exe'))
        if exe not in ('/usr/sbin/nginx', str(self.path('/usr/sbin/nginx'))):
            raise Preserve('Exécutable nginx non reconnu.')
        groups = self.read('/proc/' + pid + '/cgroup').decode().splitlines()
        if not any(line.split(':', 2)[-1] == '/system.slice/nginx.service' for line in groups):
            raise Preserve('Processus extérieur au service nginx.')
        command = self.read('/proc/' + pid + '/cmdline').decode().replace('\0', ' ').strip()
        if command != 'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;':
            raise Preserve('Commande du master nginx personnalisée.')
        started = self.started_at(pid)
        if started > time.time() + 1 or any(max(r['mtime_ns'], r['ctime_ns']) / 1e9 > started + 1 / os.sysconf('SC_CLK_TCK') for r in resources.values()):
            raise Preserve('Fichiers nginx modifiés après le démarrage ; configuration chargée inconnue.')
        sockets = set()
        for fd in self.path('/proc/' + pid + '/fd').iterdir():
            try:
                match = re.fullmatch(r'socket:\[([0-9]+)\]', os.readlink(fd))
                if match:
                    sockets.add(match[1])
            except FileNotFoundError:
                continue
        listeners = []
        for table in ('/proc/net/tcp', '/proc/net/tcp6'):
            for line in self.read(table).decode().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 10 and fields[3] == '0A' and fields[9] in sockets:
                    address, port = fields[1].split(':')
                    if int(port, 16) != 80 or set(address) != {'0'}:
                        raise Preserve('Autre écoute du nginx système ; service conservé.')
                    listeners.append((table, fields[9]))
        if not listeners:
            raise Preserve('Aucune écoute stock nginx confirmée.')
        return {'pid': pid, 'start': self.process_start(pid)[0],
                'boot': self.read('/proc/sys/kernel/random/boot_id').decode().strip(),
                'listeners': sorted(listeners)}

    def logs(self, folder, pattern):
        paths = sorted(self.path(folder).glob(pattern))
        if len(paths) > 20:
            raise Preserve('Historique trop volumineux ; origine non prouvée.')
        for path in paths:
            data = self.read('/' + str(path.relative_to(self.root)))
            if path.suffix == '.gz':
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                    data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise Preserve('Historique trop volumineux ; origine non prouvée.')
            yield data.decode()

    @staticmethod
    def date(value):
        return datetime.fromisoformat(' '.join(value.split())).timestamp()

    def apt_started(self):
        """An open history block must belong to our actual APT/dpkg ancestry."""
        pid = str(os.getpid())
        dpkg_seen = False
        for _ in range(20):
            if not pid.isdecimal() or int(pid) <= 1:
                break
            exe = os.readlink(self.path('/proc/' + pid + '/exe'))
            if exe == '/usr/bin/dpkg':
                dpkg_seen = True
            if dpkg_seen and exe in ('/usr/bin/apt', '/usr/bin/apt-get'):
                return self.started_at(pid)
            _, pid = self.process_start(pid)
        raise Preserve('Transaction APT ouverte non rattachée au processus courant.')

    def provenance(self):
        actions = []
        for text in self.logs('/var/log', 'dpkg.log*'):
            for line in text.splitlines():
                match = re.fullmatch(r'(\S+ \S+) (install|status installed) (nginx(?:-common)?|pxe-tools(?:-local-test)?):\S+ (.+)', line)
                if match:
                    actions.append((self.date(match[1]), match[2], match[3], match[4]))
        matches = []
        for text in self.logs('/var/log/apt', 'history.log*'):
            for block in text.split('\n\n'):
                fields = re.findall(r'(?m)^([A-Za-z-]+): (.+)$', block)
                entries = dict(fields)
                if len(entries) != len(fields):
                    continue
                if 'Start-Date' not in entries or 'Error' in entries:
                    continue
                packages = {m[0]: m[1] for m in re.findall(r'([a-z0-9+.-]+):\S+ \(([^)]+)\)', entries.get('Install', ''))}
                core = next((name for name in ('pxe-tools', 'pxe-tools-local-test') if name in packages), None)
                if core is None or any(not packages.get(name, '').endswith(', automatic') for name in ('nginx', 'nginx-common')):
                    continue
                start = self.date(entries['Start-Date'])
                if 'End-Date' in entries:
                    end = self.date(entries['End-Date'])
                else:
                    if not self.configuring or os.environ.get('DPKG_MAINTSCRIPT_PACKAGE') != core or os.environ.get('DPKG_MAINTSCRIPT_NAME') != 'postinst':
                        continue
                    if not self.apt_started() - 1 <= start <= time.time():
                        continue
                    if self.command('/usr/bin/dpkg-query', '-W', '-f=${Version}', core) != packages[core].split(',')[0]:
                        continue
                    end = time.time()
                if end < start:
                    continue
                selected = [a for a in actions if start <= a[0] <= end]
                if not all(any(a[1:3] == ('install', name) and a[3].startswith('<none> ') for a in selected)
                           for name in ('nginx', 'nginx-common', core)):
                    continue
                if not all(any(a[1:3] == ('status installed', name) for a in selected) for name in ('nginx', 'nginx-common')):
                    continue
                # A later purge/reinstall no longer belongs to that transaction.
                if any(a[0] > end and a[1:3] == ('install', 'nginx') for a in actions):
                    continue
                matches.append({'source': 'apt-and-dpkg', 'start': entries['Start-Date'],
                                'end': entries.get('End-Date'), 'core': core})
        if len(matches) != 1:
            raise Preserve('Provenance APT de la dépendance absente ou ambiguë.')
        return matches[0]

    def save(self, record):
        with tempfile.NamedTemporaryFile(mode='w', dir=self.directory, delete=False) as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
            temporary = stream.name
        os.replace(temporary, self.journal)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def reconcile(self, confirm_stock=False):
        try:
            current = self.state()
            if self.journal.exists() or self.journal.is_symlink():
                record = json.loads(self.read('/var/lib/pxe-tools-nginx-ownership/state.json').decode())
                if not isinstance(record, dict) or record.get('format') != 1 or record.get('phase') != 'complete':
                    raise Preserve('Réconciliation nginx antérieure inachevée ; consulter son journal privé.')
                reason = ('Réconciliation nginx déjà appliquée.' if current['ActiveState'] == 'inactive' and current['UnitFileState'] == 'disabled'
                          else 'Choix nginx modifié depuis la réconciliation ; service conservé.')
                return {'action': 'preserved', 'reason': reason}
            if current['ActiveState'] != 'active' or current['UnitFileState'] != 'enabled':
                return {'action': 'preserved', 'reason': 'État nginx arrêté/désactivé/masqué conservé.'}
            resources = self.stock()
            identity = self.identity(resources)
            provenance = {'source': 'explicit-stock-consent'} if confirm_stock else self.provenance()
            # Create only root-owned, private product metadata, never nginx files.
            for name in ('/var/lib/pxe-tools-nginx-ownership',):
                path = self.path(name)
                if not path.exists():
                    path.mkdir(mode=0o700, parents=False)
                info = path.lstat()
                if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise Preserve('Répertoire de provenance nginx non fiable.')
            if stat.S_IMODE(self.directory.stat().st_mode) != 0o700:
                raise Preserve('Le répertoire de provenance nginx doit être privé.')
            lock = os.open(self.directory / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if os.fstat(lock).st_uid != 0 or stat.S_IMODE(os.fstat(lock).st_mode) != 0o600:
                    raise Preserve('Verrou nginx non fiable.')
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if self.journal.exists() or self.stock() != resources or self.identity(resources) != identity or self.state() != current:
                    raise Preserve('nginx a changé pendant la vérification ; service conservé.')
                record = {'format': 1, 'service': 'nginx.service', 'phase': 'prepared',
                          'before': {'active': 'active', 'enabled': 'enabled'},
                          'after': {'active': 'inactive', 'enabled': 'disabled'},
                          'resources': resources, 'identity': identity, 'provenance': provenance}
                self.save(record)
                self.command('/usr/bin/systemctl', 'stop', 'nginx.service')
                if self.state()['ActiveState'] != 'inactive':
                    raise Preserve('Arrêt nginx non confirmé ; consulter le journal privé.')
                try:
                    self.command('/usr/bin/systemctl', 'disable', 'nginx.service')
                except Preserve:
                    # A failed disable must not silently leave a stopped service.
                    # Restore only our original active/enabled state, with the same
                    # stock files and no new TCP80 listener to displace.
                    try:
                        occupied = any(len(fields := line.split()) >= 4 and fields[3] == '0A'
                                       and fields[1].split(':')[-1] == '0050'
                                       for table in ('/proc/net/tcp', '/proc/net/tcp6')
                                       for line in self.read(table).decode().splitlines()[1:])
                        if not occupied and self.stock() == resources and self.state()['ActiveState'] == 'inactive':
                            self.command('/usr/bin/systemctl', 'enable', 'nginx.service')
                            self.command('/usr/bin/systemctl', 'start', 'nginx.service')
                            record['compensated'] = True
                            self.save(record)
                    except (OSError, Preserve, subprocess.SubprocessError):
                        pass
                    raise Preserve('Désactivation nginx échouée ; consulter le journal privé avant reprise.')
                final = self.state()
                if final['ActiveState'] != 'inactive' or final['UnitFileState'] != 'disabled':
                    raise Preserve('Désactivation nginx non confirmée ; consulter le journal privé.')
                record['phase'] = 'complete'
                self.save(record)
            finally:
                os.close(lock)
            return {'action': 'disabled', 'reason': 'nginx générique stock arrêté et désactivé ; services PXE inchangés.'}
        except (OSError, ValueError, Preserve, subprocess.SubprocessError) as error:
            return {'action': 'conflict', 'reason': str(error)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--confirm-stock-service', action='store_true',
                        help='explicit consent to stop/disable only a fully verified stock service')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('root requis pour vérifier la propriété du service')
    if not Path('/run/systemd/system').is_dir():
        return
    result = Reconciler(configuring=args.configure).reconcile(confirm_stock=args.confirm_stock_service)
    print('PXE Tools: ' + result['reason'])
    if result['action'] == 'conflict':
        print('TCP80 peut rester occupé. Vérifiez le diagnostic réseau ; aucune activation PXE automatique.')
        print('Réparation stock après examen : sudo python3 /usr/lib/pxe-tools/native/reconcile-nginx.py --confirm-stock-service')
        if args.confirm_stock_service:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
