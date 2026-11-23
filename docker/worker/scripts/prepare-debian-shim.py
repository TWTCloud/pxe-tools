#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Acquire authentic Debian PXE firmware and optionally its amd64 GRUB modules.

This uses an isolated temporary APT state and never installs a Debian package or
changes the host's APT configuration. Candidate binaries are published only
after matching Debian's signed installer metadata and identical Built-Using
versions from the two signed archive packages.
"""
from __future__ import annotations

import hashlib
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
from contextlib import contextmanager
import resource
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request

ARCHIVE = 'https://deb.debian.org/debian'
SUITE = 'trixie'
LIMIT = 16 * 1024 * 1024
MAX_APT_FILE = 64 * 1024 * 1024
SCRIPTS = Path(__file__).resolve().parent
SHIM_MEMBER = './usr/lib/shim/shimx64.efi.signed'
MOK_MEMBER = './usr/lib/shim/mmx64.efi.signed'
GRUB_SIGNED_MEMBER = './usr/lib/grub/x86_64-efi-signed/grubnetx64.efi.signed'
GRUB_MODULE_PREFIX = './usr/lib/grub/x86_64-efi/'


def constrained():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_APT_FILE, MAX_APT_FILE))


def run(args, *, cwd=None, env=None, output=False):
    return subprocess.run(args, cwd=cwd, env=env, check=True, timeout=180,
                          stdout=subprocess.PIPE if output else subprocess.DEVNULL,
                          stderr=subprocess.PIPE, preexec_fn=constrained).stdout


def fetch(path, limit):
    url = ARCHIVE + '/' + path
    with urllib.request.urlopen(url, timeout=60) as response:
        if urllib.parse.urlsplit(response.geturl()).scheme != 'https':
            raise ValueError('Debian redirect must use HTTPS')
        data = response.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError('Debian response has an invalid size')
    return data


def release_sha256(release, relative_path):
    active = False
    sections = 0
    matches = []
    for line in release.splitlines():
        if line == 'SHA256:':
            sections += 1
            active = True
            continue
        if active and line and not line[0].isspace():
            active = False
        if active:
            fields = line.split()
            if len(fields) == 3 and fields[2] == relative_path:
                matches.append(fields[0])
    if sections != 1 or len(matches) != 1 or not re.fullmatch(r'[0-9a-f]{64}', matches[0]):
        raise ValueError('missing or ambiguous signed SHA256 entry')
    return matches[0]


def sums_sha256(sums, path):
    matches = []
    for line in sums.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip('*') == path:
            matches.append(fields[0])
    if len(matches) != 1 or not re.fullmatch(r'[0-9a-f]{64}', matches[0]):
        raise ValueError('missing or ambiguous installer SHA256 entry')
    return matches[0]


def shim_build(value):
    matches = re.findall(r'(?:^|,)\s*shim\s*\(=\s*([^()\s]+)\s*\)', value)
    if len(matches) != 1 or not re.fullmatch(r'[A-Za-z0-9.+:~\-]+', matches[0]):
        raise ValueError('missing or ambiguous shim Built-Using version')
    return matches[0]


@contextmanager
def package_tar(deb):
    # Decompress into a bounded file and let callers select regular members.
    with tempfile.TemporaryFile() as data:
        subprocess.run(['dpkg-deb', '--fsys-tarfile', str(deb)], stdout=data,
                       stderr=subprocess.PIPE, check=True, timeout=60,
                       preexec_fn=constrained)
        data.seek(0)
        with tarfile.open(fileobj=data, mode='r:') as tar:
            members = tar.getmembers()
            if len(members) > 4096:
                raise ValueError('too many package entries')
            yield tar, members


def extract_member(deb, name):
    found = []
    with package_tar(deb) as (archive, members):
        for member in members:
            if member.name != name:
                continue
            if not member.isfile() or member.size < 1 or member.size > LIMIT:
                raise ValueError('invalid selected package entry')
            with archive.extractfile(member) as source:
                found.append(source.read(LIMIT + 1))
    if len(found) != 1 or len(found[0]) > LIMIT or found[0][:2] != b'MZ':
        raise ValueError('missing or ambiguous EFI image')
    return found[0]


def extract_grub_modules(deb, destination):
    destination.mkdir()
    with package_tar(deb) as (archive, members):
        for member in members:
            if not member.name.startswith(GRUB_MODULE_PREFIX) or member.name == GRUB_MODULE_PREFIX:
                continue
            name = member.name.removeprefix(GRUB_MODULE_PREFIX)
            if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                    or not member.isfile() or member.size > LIMIT):
                raise ValueError('invalid amd64 GRUB module file')
            with archive.extractfile(member) as source, (destination / name).open('xb') as target:
                target.write(source.read(LIMIT + 1))
    if not all((destination / name).is_file() for name in
               ('kernel.img', 'moddep.lst', 'modinfo.sh', 'http.mod', 'tftp.mod')):
        raise ValueError('incomplete amd64 GRUB modules')


def downloaded_package(work, name):
    candidates = list(work.glob(name + '_*_amd64.deb'))
    if len(candidates) != 1 or candidates[0].stat().st_size > LIMIT:
        raise ValueError(f'missing, ambiguous or oversized amd64 package: {name}')
    return candidates[0]


def trusted_directory(destination):
    """Open each root-owned, non-writable component without following links."""
    path = Path(destination)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('TFTP path must be absolute and contain no parent traversal')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        root = os.fstat(fd)
        if root.st_uid != 0 or root.st_mode & 0o022:
            raise ValueError('root directory ownership or permissions are unsafe')
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            meta = os.fstat(fd)
            if meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ValueError('TFTP and every parent must be root-owned and not group/world writable')
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def locked_destination(destination):
    directory_fd = trusted_directory(destination)
    try:
        lock_fd = os.open('.pxe-debian-shim.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                          0o600, dir_fd=directory_fd)
        with os.fdopen(lock_fd, 'r+') as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError('unsafe shim lock file')
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield directory_fd
    finally:
        os.close(directory_fd)


def previous_target(directory_fd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > LIMIT):
            raise ValueError('unsafe existing EFI target')
        return stream.read(LIMIT + 1)


def write_staged(directory_fd, data):
    name = '.pxe-shim-' + secrets.token_hex(16)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644, dir_fd=directory_fd)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return name


def publish_pair(directory_fd, shim, mok):
    previous = {name: previous_target(directory_fd, name)
                for name in ('mmx64.efi', 'grubnetx64.efi')}
    staged = []
    changed = []
    try:
        for name, data in (('mmx64.efi', mok), ('grubnetx64.efi', shim)):
            staged.append((name, write_staged(directory_fd, data)))
        for name, temporary in staged:
            os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            changed.append(name)
        os.fsync(directory_fd)
    except OSError:
        for name in reversed(changed):
            if previous[name] is None:
                os.unlink(name, dir_fd=directory_fd)
            else:
                backup = write_staged(directory_fd, previous[name])
                os.replace(backup, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        raise
    finally:
        for _, temporary in staged:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def acquire(destination, keyring, *, with_grub=False):
    destination = Path(destination)
    keyring = Path(keyring)
    if (not keyring.is_absolute() or not keyring.is_file()
            or re.search(r'[\s\[\]]', str(keyring))):
        raise ValueError('Debian keyring missing or invalid')
    with locked_destination(destination) as directory_fd:
        if with_grub and set(os.listdir(directory_fd)) - {'.pxe-debian-shim.lock'}:
            raise ValueError('GRUB preparation requires a private empty staging directory')
        with tempfile.TemporaryDirectory(prefix='pxe-debian-shim-') as temporary:
            work = Path(temporary)
            inrelease = work / 'InRelease'
            inrelease.write_bytes(fetch(f'dists/{SUITE}/InRelease', 1024 * 1024))
            run(['gpgv', '--keyring', str(keyring), '--output', str(work / 'Release'), str(inrelease)])
            run(['python3', str(SCRIPTS / 'debian-release-freshness.py'), str(work / 'Release')])
            release = (work / 'Release').read_text(encoding='utf-8')
            relative = 'main/installer-amd64/current/images/SHA256SUMS'
            sums = fetch(f'dists/{SUITE}/{relative}', 4 * 1024 * 1024)
            if hashlib.sha256(sums).hexdigest() != release_sha256(release, relative):
                raise ValueError('installer checksum manifest does not match signed Release')
            expected = sums_sha256(sums.decode('ascii'), './netboot/debian-installer/amd64/bootnetx64.efi')
            netboot = fetch(f'dists/{SUITE}/main/installer-amd64/current/images/netboot/debian-installer/amd64/bootnetx64.efi', LIMIT)
            if hashlib.sha256(netboot).hexdigest() != expected:
                raise ValueError('Debian netboot shim digest mismatch')

            (work / 'lists/partial').mkdir(parents=True)
            (work / 'archives/partial').mkdir(parents=True)
            (work / 'sources.list').write_text(
                f'deb [arch=amd64 signed-by={keyring}] {ARCHIVE} {SUITE} main\n', encoding='ascii')
            opts = ['-o', f'Dir::Etc::sourcelist={work / "sources.list"}',
                    '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::Etc::main=/dev/null',
                    '-o', 'Dir::Etc::parts=-', '-o', 'Dir::Etc::preferences=/dev/null',
                    '-o', 'Dir::Etc::preferencesparts=-', '-o', 'Dir::State::status=/dev/null',
                    '-o', f'Dir::State::lists={work / "lists"}',
                    '-o', f'Dir::Cache::archives={work / "archives"}',
                    '-o', 'APT::Architecture=amd64',
                    '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
                    '-o', 'APT::Sandbox::User=root', '-o', 'Debug::NoLocking=1',
                    '-o', 'Acquire::Languages=none', '-o', 'Acquire::Max-ValidTime=15552000',
                    '-o', 'Acquire::Max-FutureTime=300', '-o', 'Acquire::Check-Valid-Until=true',
                    '-o', 'APT::Get::List-Cleanup=0']
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(work), 'LC_ALL': 'C'}
            run(['apt-get', *opts, 'update'], cwd=work, env=env)
            packages = ['shim-signed', 'shim-helpers-amd64-signed']
            if with_grub:
                packages.extend(('grub-efi-amd64-bin', 'grub-efi-amd64-signed'))
            run(['apt-get', *opts, 'download', *packages], cwd=work, env=env)
            shim_deb, mok_deb = (downloaded_package(work, name) for name in packages[:2])
            shim_version = run(['dpkg-deb', '-f', str(shim_deb), 'Built-Using'], output=True).decode().strip()
            mok_version = run(['dpkg-deb', '-f', str(mok_deb), 'Built-Using'], output=True).decode().strip()
            if shim_build(shim_version) != shim_build(mok_version):
                raise ValueError('Debian shim and MokManager source versions do not match')
            shim = extract_member(shim_deb, SHIM_MEMBER)
            mok = extract_member(mok_deb, MOK_MEMBER)
            if hashlib.sha256(shim).hexdigest() != expected or shim != netboot:
                raise ValueError('package shim does not match signed installer shim')
            if with_grub:
                modules_deb, signed_deb = (downloaded_package(work, name) for name in packages[2:])
                version = run(['dpkg-deb', '-f', str(modules_deb), 'Version'], output=True).decode().strip()
                native_version = run(['dpkg-query', '-W', '-f=${Version}', 'grub-common'],
                                     output=True).decode().strip()
                if version != native_version:
                    raise ValueError('Debian amd64 GRUB modules must match the installed grub-common version')
                extract_grub_modules(modules_deb, destination / 'x86_64-efi')
                (destination / 'grub.version').write_text(version + '\n', encoding='ascii')
                (destination / 'grubnetx64.efi.signed').write_bytes(extract_member(signed_deb, GRUB_SIGNED_MEMBER))
            # No existing binary is touched before every authenticated check passes.
            publish_pair(directory_fd, shim, mok)
            print('Authenticated Debian shim and matching MokManager prepared.')


if __name__ == '__main__':
    try:
        if sys.argv[1:2] == ['--publish-pair'] and len(sys.argv) == 4 and os.geteuid() == 0:
            source = trusted_directory(sys.argv[2])
            try:
                shim = previous_target(source, 'grubnetx64.efi')
                mok = previous_target(source, 'mmx64.efi')
                if not shim or not mok or shim[:2] != b'MZ' or mok[:2] != b'MZ':
                    raise ValueError('staged Debian EFI pair missing')
                with locked_destination(sys.argv[3]) as target:
                    publish_pair(target, shim, mok)
            finally:
                os.close(source)
        else:
            if ((len(sys.argv) != 3 and (len(sys.argv) != 4 or sys.argv[3] != '--with-grub'))
                    or os.geteuid() != 0):
                raise ValueError('expected root, destination, Debian archive keyring and optional --with-grub')
            acquire(sys.argv[1], sys.argv[2], with_grub=len(sys.argv) == 4)
    except (OSError, ValueError, UnicodeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        raise SystemExit(f'Debian shim preparation failed: {exc}')
