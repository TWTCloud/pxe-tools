#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Assemble the shared runtime shipped in the Rust APT and Docker builds."""
import shutil
import sys
from pathlib import Path


def local_copy_tree(source, target, *, exclude=()):
    shutil.copytree(source, target, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store', *exclude))


def stage(source, app, runtime, *, copy_tree=local_copy_tree, copy_file=shutil.copy2):
    # The Rust binary includes its web assets. Keep only the shared SQLite
    # schema, operational helpers, and the optional Ansible adapter.
    copy_tree(source / 'app', app, exclude=(
        '*.php', 'README.md', 'public', 'src', 'migrations', 'schema.mysql.sql',
        'worker_legacy.py', 'port80_diagnostic.py',
    ))
    docker = source / 'docker'
    assets = source / 'rust/packaging'
    copy_tree(docker / 'worker/scripts', runtime / 'scripts', exclude=(
        '*.php', 'bootstrap-refresh-catalog-v2.sh', 'bootstrap-release-nginx-port.sh',
        'native-release-nginx-port.py', 'manage-pxe-pki.py',
    ))
    copy_tree(docker / 'worker/templates', runtime / 'templates', exclude=('*.php.j2',))
    copy_tree(docker / 'pxe-tools/init', runtime / 'init', exclude=(
        'healthcheck.sh', 'php-init.sh', 'reload-pxe-http.sh',
        'render-legacy-boot-templates.sh', 'render-nginx-conf.sh',
    ))
    for directory, filenames in (
        ('scripts', ('bootstrap-refresh-catalog-v2.sh',)),
        ('init', ('healthcheck.sh', 'reload-pxe-http.sh', 'sqlite-init.sh')),
    ):
        for filename in filenames:
            copy_file(assets / directory / filename, runtime / directory / filename)
    for filename in ('alpine-release.json', 'alpine-release.gpg', 'alpine-service.sh'):
        copy_file(source / 'rust/assets/pxe' / filename, runtime / 'scripts' / filename)

    for directory in ('scripts', 'init'):
        for script in (runtime / directory).glob('*.sh'):
            script.chmod(0o755)


def stage_s6(source, target):
    local_copy_tree(source / 'docker/pxe-tools/s6-rc', target, exclude=(
        'php-init', 'php-fpm', 'nginx', 'render-nginx-conf',
    ))
    (target / 'sqlite-init').mkdir()
    (target / 'sqlite-init/type').write_text('oneshot\n')
    (target / 'sqlite-init/up').write_text('/opt/pxe-tools/init/sqlite-init.sh\n')
    (target / 'rust-guided').mkdir()
    (target / 'rust-guided/type').write_text('longrun\n')
    shutil.copyfile(source / 'rust/packaging/s6-guided-run', target / 'rust-guided/run')
    (target / 'worker/run').write_text(
        '#!/command/with-contenv sh\n'
        'exec /usr/lib/pxe-tools/pxe-tools-rust --work-guided /etc/pxe-tools/db.conf /app/worker.py\n'
    )
    for service, dependencies in (
        ('bootstrap-render-templates', ('sqlite-init',)),
        ('bootstrap-tls', ('sqlite-init',)),
        ('render-dnsmasq-conf', ('sqlite-init', 'bootstrap-render-templates')),
        ('rust-guided', ('sqlite-init', 'bootstrap-tls', 'bootstrap-render-templates', 'wait-for-net')),
        ('worker', ('rust-guided',)),
    ):
        directory = target / service / 'dependencies.d'
        directory.mkdir(exist_ok=True)
        for dependency in dependencies:
            (directory / dependency).touch()
    (target / 'user/contents.d/rust-guided').touch()
    for script in target.glob('*/*'):
        if script.is_file() and script.name in ('run', 'up', 'down', 'finish'):
            script.chmod(0o755)


if __name__ == '__main__':
    source, output = map(Path, sys.argv[1:])
    stage(source, output / 'app', output / 'opt/pxe-tools')
    stage_s6(source, output / 'etc/s6-overlay/s6-rc.d')
