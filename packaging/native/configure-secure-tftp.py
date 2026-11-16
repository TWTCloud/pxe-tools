#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Prepare a new protected native TFTP root; never alter existing paths."""
import os
import subprocess
from pathlib import Path
import sys


BASE = Path('/var/lib')
RUNTIME = 'pxe-tools-native'
TFTP = 'pxe-tools-tftp'
HTTP = 'pxe-tools-http'
MARKER = (b'TFTP_ROOT=/var/lib/pxe-tools-tftp\n'
          b'HTTP_ROOT=/var/lib/pxe-tools-http\n'
          b'PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered\n'
          b'MOK_DIR=/var/lib/pxe-tools-native/mok\n')


def prepare(base=BASE, *, journal=None, root=Path('/'), owner=0, after_create=None):
    # /var and /var/lib are expected to be root-owned and not writable by the
    # web account. Open the entire path without following symlinks.
    base, root = Path(base), Path(root)
    if (not base.is_absolute() or not root.is_absolute()
            or '..' in base.parts or '..' in root.parts):
        raise ValueError('unsafe native TFTP base')
    try:
        relative = base.relative_to(root)
    except ValueError as exc:
        raise ValueError('native TFTP base outside the trusted root') from exc
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = []
    held = {}
    try:
        root_info = os.fstat(fd)
        if root_info.st_uid != owner or root_info.st_mode & 0o022:
            raise ValueError('unsafe root directory')
        for part in relative.parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != owner or info.st_mode & 0o022:
                raise ValueError('unsafe parent of native TFTP paths')
        for name in (RUNTIME, TFTP, HTTP):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError('native TFTP destination or marker already exists: ' + name)
        if journal is not None:
            journal.begin_runtime()
        for name in (RUNTIME, TFTP, HTTP):
            os.mkdir(name, 0o755, dir_fd=fd)
            created.append(name)
            opened = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fchmod(opened, 0o755)
                if journal is not None:
                    journal.record_runtime_created('/var/lib/' + name, opened)
                held['/var/lib/' + name] = opened
                opened = None
            finally:
                if opened is not None:
                    os.close(opened)
        runtime = os.open(RUNTIME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            os.mkdir('rendered', 0o755, dir_fd=runtime)
            rendered = os.open('rendered', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=runtime)
            try:
                os.fchmod(rendered, 0o755)
            finally:
                os.close(rendered)
            network = os.open('network.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o644, dir_fd=runtime)
            with os.fdopen(network, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.flush()
                os.fsync(stream.fileno())
            marker = os.open('runtime.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o644, dir_fd=runtime)
            with os.fdopen(marker, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(MARKER)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(runtime)
        finally:
            os.close(runtime)
        os.fsync(fd)
        if journal is not None:
            journal.finish_runtime(held=held)
        if after_create is not None:
            after_create(held)
    except BaseException:
        # Only remove empty directories created by this invocation. A marker
        # must never be deleted after an ambiguous failure.
        for name in reversed(created):
            try:
                os.rmdir(name, dir_fd=fd)
            except OSError:
                pass
        raise
    finally:
        for descriptor in held.values():
            os.close(descriptor)
        os.close(fd)


def activate_admin(runner=subprocess.run):
    # Preserve the package contract: inability to start administration is a
    # warning, not an APT failure. Directory ownership is independently pinned.
    for action in ('enable', 'start'):
        try:
            result = runner(['systemctl', action, 'pxe-tools-admin.target'], check=False)
            if result.returncode:
                raise OSError('systemctl ' + action + ' failed')
        except OSError:
            print('PXE Tools: could not ' + action + ' the administration service; inspect systemd status.', file=sys.stderr)
            return


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in ([], ['--initialize-instance']) or os.geteuid() != 0:
            raise ValueError('expected root and optional --initialize-instance')
        import importlib.util
        helper = Path(__file__).with_name('ownership-provenance.py')
        spec = importlib.util.spec_from_file_location('pxe_native_ownership', helper)
        if spec is None or spec.loader is None:
            raise ValueError('native ownership helper unavailable')
        ownership = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ownership)
        store = ownership.Store()
        def initialize(held):
            store.create_base(require_runtime=True, native_fds=held, activate=activate_admin)
        prepare(journal=store, after_create=initialize if sys.argv[1:] else None)
        print('Protected native TFTP root prepared; existing paths were not changed.')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f'Cannot prepare native TFTP root: {exc}')
