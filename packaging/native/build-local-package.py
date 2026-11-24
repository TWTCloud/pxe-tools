#!/usr/bin/env python3
"""Build the native PXE Tools package without publishing it.

The local-test package is for isolated fixtures. A fresh installation starts
administration but keeps PXE inactive until the network is confirmed; removal
and purge preserve instance data.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
_inventory_spec = importlib.util.spec_from_file_location('pxe_source_inventory', ROOT/'packaging/native/source_inventory.py')
if _inventory_spec is None or _inventory_spec.loader is None:
    raise RuntimeError('Package source inventory unavailable')
source_inventory = importlib.util.module_from_spec(_inventory_spec)
_inventory_spec.loader.exec_module(source_inventory)
GRUB_DEPENDENCIES = {
    'amd64': 'grub-efi-amd64-bin, grub-efi-amd64-signed',
    'arm64': 'grub-efi-arm64-bin',
}
PHP_FPM_DEPENDENCY = 'php-fpm | php8.4-fpm | php8.3-fpm | php8.2-fpm, '
PHP_CURL_DEPENDENCY = 'php-curl | php8.4-curl | php8.3-curl | php8.2-curl, '
CONTROL = '''Package: {package_name}
Version: {version}
Architecture: {architecture}
Maintainer: {maintainer}
Pre-Depends: python3 (>= 3.11)
Depends: adduser, ca-certificates, cpio, curl, debian-archive-keyring, dnsmasq-base, gettext-base, git, gpgv, {grub_dependencies}, iproute2, ipxe, mokutil, {nginx_dependency}openssh-client, openssl, php-cli | php8.4-cli | php8.3-cli | php8.2-cli, {php_curl_dependency}{php_fpm_dependency}php-sqlite3 | php8.4-sqlite3 | php8.3-sqlite3 | php8.2-sqlite3, pxelinux, python3-jinja2, python3-nacl, sbsigntool, {shim_dependency}sqlite3, sshpass, syslinux-common, syslinux-efi, systemd, util-linux, wget, xz-utils, 7zip | p7zip-full
Section: admin
Priority: optional
Description: {description}
 {details}
 {startup}
'''
PREINST = '''#!/bin/sh
set -eu
if [ "$1" = install ] || [ "$1" = upgrade ]; then
    python3 - check-removal <<'PXE_UPGRADE_LIFECYCLE'
@@PXE_UPGRADE_LIFECYCLE@@
PXE_UPGRADE_LIFECYCLE
fi
if [ "$1" = install ]; then
    if [ -e /usr/lib/pxe-tools ] || [ -L /usr/lib/pxe-tools ] || \
       [ -e /opt/pxe-tools ] || [ -L /opt/pxe-tools ]; then
        # Scan both roots before removing any narrowly recognised caches.
        python3 - /usr/lib/pxe-tools /opt/pxe-tools <<'PXE_CACHE_CLEANUP'
@@PXE_CACHE_CLEANUP@@
PXE_CACHE_CLEANUP
    fi
fi
if [ "$1" = upgrade ] && [ -d /run/systemd/system ]; then
    python3 - prepare '@@PXE_PACKAGE_VERSION@@' <<'PXE_UPGRADE_LIFECYCLE'
@@PXE_UPGRADE_LIFECYCLE@@
PXE_UPGRADE_LIFECYCLE
fi
'''
PRERM = '''#!/bin/sh
set -eu
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop pxe-tools.target pxe-tools-admin.target
    for unit in pxe-tools-worker.service pxe-tools-dnsmasq-tail.service pxe-tools-nginx.service pxe-tools-pxe-http.service pxe-tools-php.service pxe-tools-dnsmasq.service pxe-tools-init.service; do
        if systemctl is-active --quiet "$unit"; then systemctl stop "$unit"; fi
    done
    systemctl disable pxe-tools.target pxe-tools-admin.target >/dev/null 2>&1 || true
fi
'''
POSTINST = '''#!/bin/sh
set -eu
if [ "$1" = configure ]; then
    # An interrupted removal must be resolved before nginx or services change.
    python3 /usr/lib/pxe-tools/native/upgrade-lifecycle.py check-removal
fi
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    recovered=$(python3 /usr/lib/pxe-tools/native/ownership-provenance.py recover-initialization)
    [ "$recovered" = recovered ] || [ "$recovered" = unchanged ] || { echo 'Invalid initialization recovery result.' >&2; exit 1; }
    if [ "$recovered" = unchanged ]; then
        python3 /usr/lib/pxe-tools/native/ownership-provenance.py check-base
    fi
    # Dependencies are configured before us and may have started stock nginx.
    # Preserve any preexisting/custom service unless ownership is proven.
    python3 /usr/lib/pxe-tools/native/reconcile-nginx.py --configure
    # The incoming code is now installed. The preinst snapshot precedes all
    # init/schema work; failed configure retains its journal for a safe retry.
    python3 /usr/lib/pxe-tools/native/upgrade-lifecycle.py configure
    # Existing instance data may contain queued jobs or an enabled DHCP setup.
    # Leave its startup under the administrator's control.
    if [ "$recovered" = recovered ]; then
        if systemctl enable pxe-tools-admin.target; then
            systemctl start pxe-tools-admin.target || echo 'PXE Tools: inspect administration service status.' >&2
        else
            echo 'PXE Tools: could not enable administration; inspect systemd status.' >&2
        fi
        python3 /usr/lib/pxe-tools/native/ownership-provenance.py finish-base
    elif [ -z "${2:-}" ] && [ ! -e /var/lib/pxe-tools ] && [ ! -L /var/lib/pxe-tools ] \
       && [ ! -e /etc/pxe-tools ] && [ ! -L /etc/pxe-tools ]; then
        # Only truly new native installations receive the protected TFTP root.
        # Existing paths are never overwritten or silently migrated.
        # Keep creation descriptors pinned across init, even on filesystems
        # without birthtime or trusted xattr support.
        python3 /usr/lib/pxe-tools/native/configure-secure-tftp.py --initialize-instance
    fi
fi
'''
POSTRM = '''#!/bin/sh
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
if [ "$1" = abort-upgrade ] && [ -d /run/systemd/system ]; then
    python3 - abort <<'PXE_UPGRADE_LIFECYCLE'
@@PXE_UPGRADE_LIFECYCLE@@
PXE_UPGRADE_LIFECYCLE
fi
if [ "$1" = purge ]; then echo 'PXE Tools: instance data, native runtime and configuration were kept.' >&2; fi
'''


def copy_tree(source: Path, destination: Path, tracked: set[str]) -> None:
    for item in [source, *source.rglob('*')]:
        if any(part == '__pycache__' for part in item.relative_to(source).parts) or item.name == '.DS_Store' or item.suffix == '.pyc':
            continue
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise ValueError('Unsupported source item: ' + str(item.relative_to(ROOT)))
        if item.is_file():
            source_inventory.checked_file(ROOT, item, tracked)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns('.DS_Store', '__pycache__', '*.pyc'))


def replace_exact(text: str, old: str, new: str) -> str:
    if old not in text:
        raise ValueError('Expected runtime configuration fragment not found')
    return text.replace(old, new)


def native_php_routes(config: str) -> str:
    config = replace_exact(config, '/app/public', '/usr/lib/pxe-tools/app/public')
    config = replace_exact(config, '/run/php/php8.4-fpm.sock', '/run/pxe-tools-php/fpm.sock')
    return replace_exact(config, 'include fastcgi_params;', 'include /etc/nginx/fastcgi_params;')


def configure_guided_units(units: Path) -> None:
    for name, php, guided in (
        ('pxe-tools-worker.service', 'pxe-tools-nginx.service', 'pxe-tools-init.service'),
        ('pxe-tools.target', 'pxe-tools-php.service pxe-tools-nginx.service ', ''),
        ('pxe-tools-admin.target', 'pxe-tools-nginx.service pxe-tools-worker.service',
         'pxe-tools-pxe-http.service pxe-tools-worker.service'),
    ):
        path = units/name
        path.write_text(replace_exact(path.read_text(), php, guided))


def build(destination: Path, version: str, *, package_name: str = 'pxe-tools-local-test',
          architecture: str = 'amd64',
          maintainer: str = 'PXE Tools local test <maintainers@example.invalid>',
          rust_binary: Path | None = None, rust_guided: bool = False) -> None:
    if package_name not in ('pxe-tools-local-test', 'pxe-tools'):
        raise ValueError('unsupported package name')
    if architecture not in GRUB_DEPENDENCIES:
        raise ValueError('supported package architectures are amd64 and arm64')
    if rust_guided and rust_binary is None:
        raise ValueError('The guided variant requires a Rust binary')
    if rust_binary is not None:
        if package_name != 'pxe-tools-local-test':
            raise ValueError('The Rust variants are only available in the local test package')
        if rust_binary.is_symlink() or not rust_binary.is_file():
            raise ValueError('Use a regular file for the Rust binary')
        with rust_binary.open('rb') as binary:
            header = binary.read(64)
        machine = {'amd64': 62, 'arm64': 183}[architecture]
        if (len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01'
                or int.from_bytes(header[18:20], 'little') != machine):
            raise ValueError('The Rust binary must be a Linux ELF for the package architecture')
    if not re.fullmatch(r'[^<>\r\n]{1,100} <[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+>', maintainer):
        raise ValueError('maintainer must be a single name and email address')
    if not destination.is_absolute() or not destination.parent.is_dir():
        raise ValueError('Use a new absolute path in an existing directory')
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Refusing to overwrite an existing package')
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+~\-]{0,40}', version):
        raise ValueError('Invalid package version')
    tracked = source_inventory.tracked_files(ROOT)
    checked = lambda path: source_inventory.checked_file(ROOT, path, tracked)
    with tempfile.TemporaryDirectory(prefix='pxe-native-package-') as temporary:
        root = Path(temporary)/'root'; control = root/'DEBIAN'; control.mkdir(parents=True)
        description, details = (('PXE network installation management',
                                 'Web administration and PXE services for Debian installations.')
                                if package_name == 'pxe-tools' else
                                ('experimental local test of PXE Tools',
                                 'This package is intended for isolated test environments.'))
        (control/'control').write_text(CONTROL.format(
            version=version, package_name=package_name, architecture=architecture,
            grub_dependencies=GRUB_DEPENDENCIES[architecture],
            nginx_dependency='' if rust_guided else 'nginx, ',
            php_curl_dependency='' if rust_guided else PHP_CURL_DEPENDENCY,
            php_fpm_dependency='' if rust_guided else PHP_FPM_DEPENDENCY,
            shim_dependency='shim-signed, ' if architecture == 'amd64' else '',
            startup=('The Rust variant starts its initial administration on the loopback interface.'
                     if rust_guided else 'On a fresh system the administration interface starts without enabling PXE.'),
            maintainer=maintainer, description=description, details=details))
        cleanup = checked(ROOT/'packaging/native/prune-package-cache.py').read_text()
        lifecycle = checked(ROOT/'packaging/native/upgrade-lifecycle.py').read_text()
        preinst = PREINST.replace('@@PXE_CACHE_CLEANUP@@', cleanup)
        postinst = POSTINST
        if rust_guided:
            postinst = replace_exact(postinst, '    python3 /usr/lib/pxe-tools/native/reconcile-nginx.py --configure\n', '')
        for name, text in [('preinst',preinst),('postinst',postinst),('prerm',PRERM),('postrm',POSTRM)]:
            text = text.replace('@@PXE_UPGRADE_LIFECYCLE@@', lifecycle).replace('@@PXE_PACKAGE_VERSION@@', version)
            p=control/name; p.write_text(text.replace('pxe-tools-local-test', package_name)); p.chmod(0o755)
        copy_tree(ROOT/'app', root/'usr/lib/pxe-tools/app', tracked)
        (root/'usr/lib/pxe-tools/app/src/native-build-version.txt').write_text(version + '\n', encoding='utf-8')
        copy_tree(ROOT/'docker/worker/scripts', root/'opt/pxe-tools/scripts', tracked)
        copy_tree(ROOT/'docker/worker/templates', root/'opt/pxe-tools/templates', tracked)
        copy_tree(ROOT/'docker/pxe-tools/init', root/'opt/pxe-tools/init', tracked)
        copy_tree(ROOT/'docker/pxe-tools/static-bin', root/'usr/lib/pxe-tools/static-bin', tracked)
        copy_tree(ROOT/'docker/pxe-tools/keyrings', root/'usr/lib/pxe-tools/keyrings', tracked)
        # Carry the selected core licence and the currently verified upstream
        # notices. Other components still require provenance and legal review.
        docs=root/'usr/share/doc'/package_name; docs.mkdir(parents=True)
        for name in ('COPYING', 'COPYING.LESSER', 'THIRD-PARTY.md'):
            shutil.copy2(checked(ROOT/name), docs/name)
        copy_tree(ROOT/'third_party/licenses', docs/'licenses', tracked)
        native=root/'usr/lib/pxe-tools/native'; native.mkdir(parents=True)
        for name in ('default.env','init.sh','start-php-fpm.sh','start-worker.py','configure-secure-tftp.py','php-fpm.conf','nginx.conf','pxe-nginx.conf','render-pxe-http.py','upgrade-lifecycle.py','reconcile-nginx.py','ownership-provenance.py','uninstall-apt.py'):
            shutil.copy2(checked(ROOT/'packaging/native'/name), native/name)
        copy_tree(ROOT/'packaging/native/keyrings', native/'keyrings', tracked)
        units=root/'usr/lib/systemd/system'; units.mkdir(parents=True)
        for unit in (sorted((ROOT/'packaging/native').glob('pxe-tools.*'))
                     + sorted((ROOT/'packaging/native').glob('pxe-tools-*.service'))
                     + sorted((ROOT/'packaging/native').glob('pxe-tools-*.target'))):
            shutil.copy2(checked(unit), units/unit.name)
        templates=root/'opt/pxe-tools/nginx'; templates.mkdir(parents=True)
        rust_assets = ROOT/'rust/packaging'
        if rust_binary is not None:
            binary = root/'usr/lib/pxe-tools/pxe-tools-rust'
            shutil.copyfile(rust_binary, binary)
            binary.chmod(0o755)
        if rust_guided:
            shutil.copy2(checked(rust_assets/'pxe-tools-pxe-http.service'), units)
            launcher = root/'usr/lib/pxe-tools/start-rust-guided.sh'
            shutil.copyfile(checked(rust_assets/'start-guided.sh'), launcher)
            launcher.chmod(0o755)
            configure_guided_units(units)
            with (native/'default.env').open('a') as environment:
                environment.write('PXE_RUST_GUIDED=1\nPXE_RUST_DIRECT_HTTP=1\n')
        else:
            php_routes = checked(ROOT/'docker/pxe-tools/nginx/pxe-php.conf').read_text()
            (templates/'pxe-routes.conf').write_text(native_php_routes(php_routes))
        if rust_binary is not None and not rust_guided:
            shutil.copy2(checked(rust_assets/'pxe-tools-rust-monitor.service'), units)
            drop_in = units/'pxe-tools-pxe-http.service.d'
            drop_in.mkdir()
            shutil.copy2(checked(rust_assets/'rust-monitor.conf'), drop_in/'50-rust-monitor.conf')
            routing = templates/'rust-monitor.d'
            routing.mkdir()
            (routing/'monitor.conf').write_text(native_php_routes(checked(rust_assets/'monitor.conf').read_text()))
        for name in ('admin-http-serve.conf.tmpl','admin-http-redirect.conf.tmpl','admin-https.conf.tmpl'):
            data=checked(ROOT/'docker/pxe-tools/nginx'/name).read_text()
            data=data.replace('/app/public','/usr/lib/pxe-tools/app/public')
            data=data.replace('/run/php/php8.4-fpm.sock','/run/pxe-tools-php/fpm.sock')
            data=data.replace('/var/log/nginx/','/var/lib/pxe-tools-native/log/')
            data=data.replace('include fastcgi_params;', 'include /etc/nginx/fastcgi_params;')
            if name == 'admin-https.conf.tmpl':
                data = replace_exact(data, '/var/lib/pxe-tools/tls/', '/var/lib/pxe-tools-native/tls/')
            (templates/name).write_text(data)
        pxe=checked(ROOT/'docker/pxe-tools/nginx/pxe.conf').read_text()
        pxe=replace_exact(pxe,'listen 80 default_server;', 'listen @@PXE_IPV4@@:80 default_server;\n    listen 127.0.0.1:80;')
        pxe=replace_exact(pxe,'    listen [::]:80 default_server;\n', '')
        pxe=replace_exact(pxe,'    root /srv/http;', '    root @@HTTP_ROOT@@;')
        pxe=pxe.replace('/var/log/nginx/','/var/lib/pxe-tools-native/log/')
        (native/'pxe.conf').write_text(pxe)
        dns=root/'opt/pxe-tools/dnsmasq'; dns.mkdir(parents=True)
        text=checked(ROOT/'docker/dnsmasq/pxe.conf.tmpl').read_text()
        text=replace_exact(text,'dhcp-script=/usr/local/bin/dhcp-hook.sh','dhcp-script=/opt/pxe-tools/native/dhcp-hook.sh')
        (dns/'pxe.conf.tmpl').write_text(text)
        helpers=root/'opt/pxe-tools/native'; helpers.mkdir(parents=True)
        for name in ('dhcp-hook.sh','dnsmasq-tail.sh'):
            shutil.copy2(checked(ROOT/'docker/dnsmasq'/name), helpers/name)
        for folder in (root/'opt/pxe-tools/scripts',root/'opt/pxe-tools/init',helpers):
            for path in folder.glob('*.sh'): path.chmod(0o755)
        for path in (root/'usr/lib/pxe-tools/static-bin').iterdir():
            if path.is_file() and path.suffix != '.md': path.chmod(0o755)
        # Normalize only the staging tree, not the checkout. copytree and
        # copy2 preserve source modes regardless of the builder's umask.
        for path in (root, *root.rglob('*')):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('Unsupported staged package item')
            mode = stat.S_IMODE(path.stat().st_mode)
            path.chmod(0o755 if path.is_dir() or mode & 0o111 else 0o644)
        archive=Path(temporary)/'package.deb'
        subprocess.run(['dpkg-deb','--build','--root-owner-group',str(root),str(archive)],check=True,stdout=subprocess.DEVNULL)
        # Exclusive open prevents destroying a previously produced artifact.
        with destination.open('xb') as output, archive.open('rb') as source:
            shutil.copyfileobj(source,output)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--version',default='0.0.1~local2')
    parser.add_argument('--architecture', choices=GRUB_DEPENDENCIES, default='amd64')
    parser.add_argument('--rust-binary', type=Path, help='include the local experimental Rust backend')
    parser.add_argument('--rust-guided', action='store_true', help='serve guided PXE using Rust without PHP-FPM')
    args=parser.parse_args()
    build(args.destination, args.version, architecture=args.architecture, rust_binary=args.rust_binary,
          rust_guided=args.rust_guided)
    print('Experimental local package built:',args.destination)
