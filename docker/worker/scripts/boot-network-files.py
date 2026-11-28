#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Generate the address-dependent boot files for each selected PXE network."""

import fcntl
import ipaddress
import json
import os
from pathlib import Path
import stat
from string import Template
import subprocess
import sys

from atomic_publish import publish

BINARY = '/usr/lib/pxe-tools/pxe-tools-rust'
CONFIG = '/etc/pxe-tools/db.conf'
SCRIPTS = Path(__file__).resolve().parent
DIRECTORY = '.pxe-networks'
ARCHES = (
    ('bios', 'x86PC', 'BIOS_BOOTLOADER', 'lpxelinux.0'),
    ('bios64', None, 'BIOS_BOOTLOADER', 'lpxelinux.0'),
    ('efi-x86', 'x86-64_EFI', 'UEFI_BOOTLOADER', 'grubnetx64.efi'),
    ('efi-x86-ebc', 'BC_EFI', 'UEFI_BOOTLOADER', 'grubnetx64.efi'),
    ('efi-arm64', 'ARM64_EFI', 'UEFI_ARM64_BOOTLOADER', 'grubnetaa64.efi'),
)


def trusted_path(path, *, create=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Chemin de publication PXE invalide')
    for parent in reversed((path, *path.parents)):
        if create and parent == path:
            parent.mkdir(mode=0o755, exist_ok=True)
        entry = parent.lstat()
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != 0 or entry.st_mode & 0o022:
            raise ValueError(f'Répertoire PXE non protégé : {parent}')
    return path


def run_script(name, environment):
    subprocess.run(['/bin/bash', str(SCRIPTS / name)], env=environment, check=True)


def prepare(networks, mode):
    if not networks:
        return
    tftp = trusted_path(os.environ.get('TFTP_ROOT', '/srv/tftp'))
    http = trusted_path(os.environ.get('HTTP_ROOT', '/srv/http'))
    tftp_root = trusted_path(tftp / DIRECTORY, create=True)
    http_root = trusted_path(http / DIRECTORY, create=True)
    lock = os.open(tftp_root / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('Verrou réseau PXE non fiable')
        fcntl.flock(lock, fcntl.LOCK_EX)
        for network in networks:
            address = network['address']
            interface = network['interface']
            boot = trusted_path(tftp_root / address, create=True)
            assets = trusted_path(http_root / address, create=True)
            marker = boot / '.ready'
            ready = (marker.is_file() and not marker.is_symlink()
                     and marker.read_text().strip() == interface)
            if mode == 'startup' and ready:
                continue
            env = dict(os.environ, TFTP_ROOT=str(boot), HTTP_ROOT=str(assets), PXE_PROFILE_ADDRESS=address)
            rebuild = mode == 'grub' or not ready
            if rebuild:
                run_script('bootstrap-install-pxe-bins.sh', env)
                run_script('bootstrap-build-grub.sh', env)
                if not (boot / 'lpxelinux.0').is_file() or not (boot / 'grubx64.efi').is_file():
                    raise ValueError(f'Chargeurs PXE incomplets pour {interface}')
            run_script('bootstrap-render-templates.sh', env)
            publish(marker, (interface + '\n').encode())
            print(f'[boot-networks] {interface} · {address}', flush=True)
    finally:
        os.close(lock)


def dnsmasq(networks, proxy, tftp, log):
    if not networks or proxy not in ('on', 'off'):
        raise ValueError('Aucune interface PXE active ou mode DHCP invalide')
    if any(not path.startswith('/') or any(char in path for char in '\r\n,') for path in (tftp, log)):
        raise ValueError('Chemin de service PXE invalide')
    extra = ["except-interface=lo"]
    if proxy == 'on':
        for tag, number in (('bios', 0), ('bios64', 5), ('efi-x8632', 6), ('efi-x86', 7),
                            ('efi-x86-ebc', 9), ('efi-arm', 10), ('efi-arm64', 11)):
            extra.append(f'dhcp-match=set:{tag},option:client-arch,{number}')
    for network in networks:
        interface, address = network['interface'], network['address']
        extra.append(f'tftp-root={tftp}/{DIRECTORY}/{address},{interface}')
        if proxy != 'on':
            continue
        subnet = ipaddress.IPv4Network(network['subnet'])
        extra.append(f'dhcp-range={subnet.network_address},proxy,{subnet.netmask}')
        for tag, service, variable, default in ARCHES:
            if tag.startswith('efi-') and os.environ.get('UEFI_ENABLED', 'true') != 'true':
                continue
            file = os.environ.get(variable, default)
            if not file or any(char in file for char in ',\r\n'):
                raise ValueError('Nom de chargeur PXE invalide')
            extra.append(f'dhcp-boot=tag:{interface},tag:{tag},{file},,{address}')
            if service is not None:
                extra.append(f'pxe-service=tag:{interface},{service},"Demarrage reseau",{file},{address}')
    template = Path('/opt/pxe-tools/dnsmasq/pxe.conf.tmpl').read_text()
    print(Template(template).substitute(
        PXE_INTERFACE='\ninterface='.join(network['interface'] for network in networks),
        TFTP_ROOT=tftp,
        DHCP_MODE='proxy' if proxy == 'on' else 'tftp_only',
        PXE_DNSMASQ_LOG=log,
        PROXY_DHCP_BLOCK='\n'.join(extra),
    ), end='')


def main():
    mode = sys.argv[1]
    if mode == 'dnsmasq':
        dnsmasq(json.load(sys.stdin), *sys.argv[2:])
    elif mode in ('grub', 'menus', 'startup'):
        networks = json.loads(subprocess.check_output([BINARY, '--pxe-networks', CONFIG]))
        if networks is None:
            raise SystemExit(2)
        prepare(networks, mode)
    else:
        raise SystemExit(2)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f'[boot-networks] {error}')
