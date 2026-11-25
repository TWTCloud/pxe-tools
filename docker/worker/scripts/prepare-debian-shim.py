#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Acquire authenticated Debian PXE firmware and matching GRUB modules.

This uses an isolated temporary APT state and never installs a Debian package or
changes the host's APT configuration. Candidate binaries are published only
after matching Debian's signed installer metadata and identical Built-Using
versions from the two signed archive packages.
"""
from __future__ import annotations

import argparse
import hashlib
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
from contextlib import contextmanager
import resource
import struct
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

ARCHIVE = 'https://deb.debian.org/debian'
SUITE = 'trixie'
LIMIT = 16 * 1024 * 1024
MAX_APT_FILE = 64 * 1024 * 1024
SCRIPTS = Path(__file__).resolve().parent
TARGETS = {'amd64': ('x64', 'x86_64-efi', 0x8664),
           'arm64': ('aa64', 'arm64-efi', 0xAA64)}


def check_machine(image, machine):
    if len(image) < 64 or image[:2] != b'MZ':
        raise ValueError('invalid EFI image')
    header = struct.unpack_from('<I', image, 0x3c)[0]
    if (header + 6 > len(image) or image[header:header + 4] != b'PE\0\0'
            or struct.unpack_from('<H', image, header + 4)[0] != machine):
        raise ValueError('EFI image architecture does not match the Debian packages')


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
    prefix = f'./usr/lib/grub/{destination.name}/'
    destination.mkdir()
    with package_tar(deb) as (archive, members):
        for member in members:
            if not member.name.startswith(prefix) or member.name == prefix:
                continue
            name = member.name.removeprefix(prefix)
            if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                    or not member.isfile() or member.size > LIMIT):
                raise ValueError('invalid GRUB module file')
            with archive.extractfile(member) as source, (destination / name).open('xb') as target:
                target.write(source.read(LIMIT + 1))
    if not all((destination / name).is_file() for name in
               ('kernel.img', 'moddep.lst', 'modinfo.sh', 'http.mod', 'tftp.mod')):
        raise ValueError('incomplete GRUB modules')


def downloaded_package(work, name, architecture):
    candidates = list(work.glob(f'{name}_*_{architecture}.deb'))
    if len(candidates) != 1 or candidates[0].stat().st_size > LIMIT:
        raise ValueError(f'missing, ambiguous or oversized {architecture} package: {name}')
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


def publish_pair(directory_fd, shim, mok, architecture='amd64'):
    suffix, _, _ = TARGETS[architecture]
    files = ((f'mm{suffix}.efi', mok), (f'grubnet{suffix}.efi', shim))
    previous = {name: previous_target(directory_fd, name) for name, _ in files}
    staged = []
    changed = []
    try:
        for name, data in files:
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


def acquire(destination, keyring, *, with_grub=False, architecture='amd64'):
    suffix, platform, efi_machine = TARGETS[architecture]
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
            installer = f'main/installer-{architecture}/current/images'
            relative = f'{installer}/SHA256SUMS'
            sums = fetch(f'dists/{SUITE}/{relative}', 4 * 1024 * 1024)
            if hashlib.sha256(sums).hexdigest() != release_sha256(release, relative):
                raise ValueError('installer checksum manifest does not match signed Release')
            name = f'netboot/debian-installer/{architecture}/bootnet{suffix}.efi'
            expected = sums_sha256(sums.decode('ascii'), './' + name)
            netboot = fetch(f'dists/{SUITE}/{installer}/{name}', LIMIT)
            if hashlib.sha256(netboot).hexdigest() != expected:
                raise ValueError('Debian netboot shim digest mismatch')

            (work / 'lists/partial').mkdir(parents=True)
            (work / 'archives/partial').mkdir(parents=True)
            (work / 'sources.list').write_text(
                f'deb [arch={architecture} signed-by={keyring}] {ARCHIVE} {SUITE} main\n', encoding='ascii')
            opts = ['-o', f'Dir::Etc::sourcelist={work / "sources.list"}',
                    '-o', 'Dir::Etc::sourceparts=-', '-o', 'Dir::Etc::main=/dev/null',
                    '-o', 'Dir::Etc::parts=-', '-o', 'Dir::Etc::preferences=/dev/null',
                    '-o', 'Dir::Etc::preferencesparts=-', '-o', 'Dir::State::status=/dev/null',
                    '-o', f'Dir::State::lists={work / "lists"}',
                    '-o', f'Dir::Cache::archives={work / "archives"}',
                    '-o', f'APT::Architecture={architecture}',
                    '-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=',
                    '-o', 'APT::Sandbox::User=root', '-o', 'Debug::NoLocking=1',
                    '-o', 'Acquire::Languages=none', '-o', 'Acquire::Max-ValidTime=15552000',
                    '-o', 'Acquire::Max-FutureTime=300', '-o', 'Acquire::Check-Valid-Until=true',
                    '-o', 'APT::Get::List-Cleanup=0']
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(work), 'LC_ALL': 'C'}
            run(['apt-get', *opts, 'update'], cwd=work, env=env)
            packages = ['shim-signed', f'shim-helpers-{architecture}-signed']
            if with_grub:
                packages.extend((f'grub-efi-{architecture}-bin', f'grub-efi-{architecture}-signed'))
            run(['apt-get', *opts, 'download', *packages], cwd=work, env=env)
            shim_deb, mok_deb = (downloaded_package(work, name, architecture) for name in packages[:2])
            shim_version = run(['dpkg-deb', '-f', str(shim_deb), 'Built-Using'], output=True).decode().strip()
            mok_version = run(['dpkg-deb', '-f', str(mok_deb), 'Built-Using'], output=True).decode().strip()
            if shim_build(shim_version) != shim_build(mok_version):
                raise ValueError('Debian shim and MokManager source versions do not match')
            shim = extract_member(shim_deb, f'./usr/lib/shim/shim{suffix}.efi.signed')
            mok = extract_member(mok_deb, f'./usr/lib/shim/mm{suffix}.efi.signed')
            if hashlib.sha256(shim).hexdigest() != expected or shim != netboot:
                raise ValueError('package shim does not match signed installer shim')
            check_machine(shim, efi_machine)
            check_machine(mok, efi_machine)
            if with_grub:
                modules_deb, signed_deb = (downloaded_package(work, name, architecture) for name in packages[2:])
                version = run(['dpkg-deb', '-f', str(modules_deb), 'Version'], output=True).decode().strip()
                native_version = run(['dpkg-query', '-W', '-f=${Version}', 'grub-common'],
                                     output=True).decode().strip()
                if version != native_version:
                    raise ValueError('Debian GRUB modules must match the installed grub-common version')
                extract_grub_modules(modules_deb, destination / platform)
                (destination / 'grub.version').write_text(version + '\n', encoding='ascii')
                filename = f'grubnet{suffix}.efi.signed'
                signed = extract_member(signed_deb, f'./usr/lib/grub/{platform}-signed/{filename}')
                check_machine(signed, efi_machine)
                (destination / filename).write_bytes(signed)
            # No existing binary is touched before every authenticated check passes.
            publish_pair(directory_fd, shim, mok, architecture)
            print(f'Authenticated Debian {architecture} shim and matching MokManager prepared.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('keyring_or_target')
    parser.add_argument('--with-grub', action='store_true')
    parser.add_argument('--publish-pair', action='store_true')
    parser.add_argument('--architecture', choices=TARGETS, default='amd64')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Root is required')
    if args.publish_pair:
        if args.with_grub:
            parser.error('--publish-pair and --with-grub are mutually exclusive')
        suffix, _, machine = TARGETS[args.architecture]
        source = trusted_directory(args.directory)
        try:
            shim = previous_target(source, f'grubnet{suffix}.efi')
            mok = previous_target(source, f'mm{suffix}.efi')
            if not shim or not mok:
                raise ValueError('staged Debian EFI pair missing')
            check_machine(shim, machine)
            check_machine(mok, machine)
            with locked_destination(args.keyring_or_target) as target:
                publish_pair(target, shim, mok, args.architecture)
        finally:
            os.close(source)
    else:
        acquire(args.directory, args.keyring_or_target, with_grub=args.with_grub,
                architecture=args.architecture)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, UnicodeError, tarfile.TarError, subprocess.SubprocessError) as exc:
        raise SystemExit(f'Debian shim preparation failed: {exc}')
