#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Boot a prepared WinPE and the installed Windows on a disposable Linux runner."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import uuid

from test_native_discovery_install_chain_isolated import (
    ROOT, appliance_image, backend, connect_fixture_lan, diagnostic_screen, docker, image, inspect, wait_for,
)
from verify_windows_pxe_deployment import (
    PREFIX, check_boot_assets, check_fingerprint, check_media, load_json, verify,
)

CLIENT = '192.0.2.100'
SERVER = '192.0.2.1'
DHCP = '192.0.2.2'
MAC = '02:00:00:00:00:01'
SIGNED_IPXE = ('ipxe-shim.efi', 'ipxe.efi')


def check_case(media):
    case = load_json(media/'case.json')
    case['guest_id'] = str(uuid.UUID(case['guest_id']))
    if (media/'windows.iso').is_symlink():
        raise ValueError('The approved ISO must be a regular file.')
    check_media(case, media/'windows.iso', media/'boot/boot.wim')
    check_boot_assets(case, media/'boot')
    for name in SIGNED_IPXE:
        asset = media/'ipxe'/name
        if asset.is_symlink():
            raise ValueError('Signed iPXE fixture files must be regular files.')
        check_fingerprint(case['ipxe_sha256'][name], asset)
    if re.fullmatch(r'[A-Za-z0-9-]{1,20}', case['disk_serial']) is None:
        raise ValueError('An AHCI fixture serial must fit in 20 ASCII characters.')
    return case


def build_windows_runner(helper):
    docker('build','--tag',helper,'-',input=f"""FROM {image}
RUN apt-get update && apt-get install --yes --no-install-recommends ovmf swtpm \\
    && rm -rf /var/lib/apt/lists/*
""")


def configure_instance(root, media):
    for name in ('data', 'configuration', 'tftp', 'tpm'):
        (root/name).mkdir(mode=0o700 if name == 'tpm' else 0o755)
    data, configuration = root/'data', root/'configuration'
    (configuration/'db.conf').write_text(json.dumps({
        'driver':'sqlite', 'path':'/var/lib/pxe-tools/windows-fixture.sqlite',
    }))
    (configuration/'db.conf').chmod(0o600)
    key = configuration/'master.key'
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    with sqlite3.connect(data/'windows-fixture.sqlite') as db:
        db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
        db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [
            ('pxe_ip', SERVER), ('pxe_enabled', 'on'), ('pxe_subnet', '192.0.2.0/24'),
            ('pxe_interface', 'br-pxetest'), ('dhcp_proxy_enabled', 'off'),
            ('wizard_completed', '1'), ('db_init_done', '1'), ('init_completed', '1'),
            ('ansible_enabled', 'off'), ('catalog_auto_refresh_enabled', 'off'),
        ])
    (root/'tftp/autoexec.ipxe').write_text(
        f'#!ipxe\ndhcp || exit\nchain http://{SERVER}/boot.ipxe || exit\n'
    )
    if media is not None:
        for name in SIGNED_IPXE:
            shutil.copyfile(media/'ipxe'/name,root/'tftp'/name)
            (root/'tftp'/name).chmod(0o644)


def stage_boot_assets(root, media, case):
    # WSL exposes the Windows drive with permissive metadata. Stage only the
    # four HTTP files on the Linux filesystem where the service can verify
    # their ownership and mode. The ISO remains on the same runner, read-only.
    boot = root/'boot'
    boot.mkdir(mode=0o755)
    for name in ('wimboot','BCD','boot.sdi','boot.wim'):
        target = boot/name
        shutil.copyfile(media/'boot'/name,target)
        target.chmod(0o444)
    check_boot_assets(case, boot)
    return boot


def start_appliance(app, lan, probe, root, boot_assets):
    docker('run','-d','--name',app,'--network','container:'+lan,'--cap-add','NET_ADMIN','--cap-add','NET_RAW',
           '-e','PXE_WINPE_CLIENT_IP='+CLIENT,
           '--mount',f'type=bind,src={root/"data"},dst=/var/lib/pxe-tools',
           '--mount',f'type=bind,src={root/"configuration"},dst=/etc/pxe-tools',
           '--mount',f'type=bind,src={boot_assets},dst=/srv/http/winpe/amd64,readonly',
           appliance_image)

    def healthy():
        if not inspect(app)['State']['Running']:
            raise RuntimeError('The Rust appliance stopped during startup.')
        return docker('exec',probe,'curl','-fsS','--max-time','2',
                      f'http://{SERVER}/healthz',check=False).returncode==0
    try:
        wait_for(healthy, 90, 'Rust boot server')
    except RuntimeError:
        logs = docker('logs','--tail','80',app,check=False)
        print(logs.stdout+logs.stderr, end='', flush=True)
        raise
    print('Rust boot server is reachable from the isolated PXE network.',flush=True)


def preflight():

    # Probe the VM ioctl through QEMU. A visible /dev/kvm alone does not prove
    # the Windows runner can run a nested KVM guest under WSL.
    qmp = '\n'.join(json.dumps({'execute':command}) for command in ('qmp_capabilities','quit'))+'\n'
    result = docker('run','--rm','-i','--network','none','--device','/dev/kvm',
                    '--entrypoint','qemu-system-x86_64',image,
                    '-machine','q35,accel=kvm','-cpu','host','-nodefaults','-display','none',
                    '-S','-m','256','-qmp','stdio',input=qmp,check=False,timeout=30)
    if result.returncode or '"QMP"' not in result.stdout or '"return"' not in result.stdout:
        raise RuntimeError(f'The isolated runner could not start a KVM guest: {result.stderr.strip()}')
    print('QEMU opened a disposable nested KVM guest.',flush=True)
    suffix = secrets.token_hex(5)
    app, lan, probe = (f'pxe-win-preflight-{name}-{suffix}' for name in ('app','lan','probe'))
    with tempfile.TemporaryDirectory(prefix='pxe-windows-preflight-',dir='/var/tmp') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        configure_instance(root, None)
        (root/'boot').mkdir()
        try:
            for name in (lan, probe):
                docker('run','-d','--name',name,'--network','none','--entrypoint','sleep',image,'180')
            connect_fixture_lan(lan,probe)
            start_appliance(app,lan,probe,root,root/'boot')
        finally:
            for name in (app, probe, lan):
                docker('rm','-fv',name,check=False)


def count_receipts(transcript):
    if not transcript.exists():
        return 0
    with transcript.open(encoding='utf-8', errors='replace') as stream:
        return sum(line.startswith(PREFIX) and line.endswith('\n') for line in stream)


def boot_asset_served(log, name, size):
    prefix = f'PXE WinPE asset=/pxe/windows/{name} '
    responses = [line.removeprefix(prefix) for line in log.splitlines() if line.startswith(prefix)]
    if f'status=200 bytes={size} range=-' in responses:
        return True
    ranges = []
    for response in responses:
        partial = re.fullmatch(r'status=206 bytes=(\d+) range=bytes (\d+)-(\d+)/(\d+)', response)
        if partial:
            count, start, end, total = map(int, partial.groups())
            if total == size and 0 <= start <= end < size and count == end-start+1:
                ranges.append((start,end))
    covered = 0
    for start,end in sorted(ranges):
        if start > covered:
            return False
        covered = max(covered,end+1)
    return covered == size


def run_guest(client, lan, helper, root, media, case, *, discovery):
    mount = ('--mount', f'type=bind,src={root},dst=/fixture-data')
    iso = ()
    if discovery:
        iso = (
            '-drive','file=/approved.iso,format=raw,if=none,media=cdrom,readonly=on,id=windows_iso',
            '-device','ide-cd,drive=windows_iso,bus=ide.1',
        )
        mount += ('--mount', f'type=bind,src={media/"windows.iso"},dst=/approved.iso,readonly')
    (root/'qemu-monitor.sock').unlink(missing_ok=True)
    serial = 'winpe.log' if discovery else 'windows.log'
    network_order, disk_order = (1, 2) if discovery else (2, 1)
    restart = ('-no-reboot',) if discovery else ()
    docker('run','-di','--name',client,'--network','container:'+lan,'--cap-add','NET_ADMIN',
           '--device','/dev/net/tun','--device','/dev/kvm',*mount,
           '--entrypoint','qemu-system-x86_64',helper,
           '-machine','q35,smm=on,accel=kvm','-cpu','host','-smp','2','-m','6144','-display','none',
           '-global','driver=cfi.pflash01,property=secure,value=on',
           '-drive','if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
           '-drive','if=pflash,unit=1,format=raw,file=/fixture-data/vars.fd',
           '-chardev','socket,id=chrtpm,path=/fixture-data/tpm.sock',
           '-tpmdev','emulator,id=tpm0,chardev=chrtpm','-device','tpm-tis,tpmdev=tpm0',
           '-uuid',case['guest_id'],*restart,'-serial','file:/fixture-data/'+serial,
           '-monitor','unix:/fixture-data/qemu-monitor.sock,server=on,wait=off',
           '-fw_cfg','name=opt/org.tianocore/IPv6Support,string=no',
           '-drive','file=/fixture-data/client.qcow2,format=qcow2,if=none,id=disk',
           '-device',f'ide-hd,drive=disk,bus=ide.0,serial={case["disk_serial"]},bootindex={disk_order}',
           *iso,'-netdev','tap,id=lan,ifname=tap-pxetest,script=no,downscript=no',
           '-device',f'virtio-net-pci,disable-legacy=on,romfile=,netdev=lan,mac={MAC},bootindex={network_order}')
    phase = 'WinPE deployment' if discovery else 'first Windows boot'
    print(f'{phase} started on the isolated guest network.', flush=True)

    def completed():
        state = inspect(client)['State']
        if state['ExitCode'] != 0:
            errors = docker('logs','--tail','12',client,check=False).stderr.strip()
            raise RuntimeError(f'{phase} QEMU process failed: {errors}')
        receipts = count_receipts(root/serial)
        if receipts > 1:
            raise RuntimeError(f'{phase} produced duplicate receipts.')
        if not state['Running'] and receipts == 0:
            raise RuntimeError(f'{phase} shut down before producing a receipt.')
        if discovery:
            return not state['Running'] and receipts == 1
        return receipts == 1

    try:
        wait_for(completed, 900, phase)
    except RuntimeError:
        diagnostic_screen(root)
        console = docker('logs','--tail','12',client,check=False)
        if console.stderr:
            print(console.stderr[-1600:],end='',flush=True)
        raise
    docker('rm','-f',client)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('media', type=Path, nargs='?')
    parser.add_argument('--server-only', action='store_true')
    args = parser.parse_args()
    if backend != 'rust-docker' or os.uname().machine != 'x86_64' or not Path('/dev/kvm').is_char_device():
        parser.error('A disposable amd64 Linux runner with KVM and the Rust Docker image is required.')
    if args.server_only and args.media is None:
        preflight()
        return
    if args.media is None or args.server_only:
        parser.error('Select the server preflight or provide the Windows test media.')
    media = args.media.resolve(strict=True)
    case = check_case(media)
    suffix = secrets.token_hex(5)
    app, lan, dhcp, client, tpm = (f'pxe-win-{name}-{suffix}' for name in ('app','lan','dhcp','client','tpm'))
    helper = f'pxe-win-guest-{suffix}:local'
    with tempfile.TemporaryDirectory(prefix='pxe-windows-fixture-', dir='/var/tmp') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        configure_instance(root,media)
        boot_assets = stage_boot_assets(root, media, case)
        fixture = ('--mount',f'type=bind,src={root},dst=/fixture-data')
        try:
            build_windows_runner(helper)
            docker('run','--rm','--network','none',*fixture,'--entrypoint','qemu-img',
                   helper,'create','-f','qcow2','/fixture-data/client.qcow2','72G')
            docker('run','--rm','--network','none',*fixture,'--entrypoint','cp',
                   helper,'/usr/share/OVMF/OVMF_VARS_4M.ms.fd','/fixture-data/vars.fd')
            docker('run','-d','--name',tpm,'--network','none',*fixture,'--entrypoint','swtpm',helper,
                   'socket','--tpm2','--tpmstate','dir=/fixture-data/tpm',
                   '--ctrl','type=unixio,path=/fixture-data/tpm.sock')
            docker('run','-d','--name',lan,'--network','none','--entrypoint','sleep',helper,'2400')
            docker('run','-d','--name',dhcp,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
                   '--mount',f'type=bind,src={root/"tftp"},dst=/pxe,readonly',
                   '--entrypoint','sleep',helper,'2400')
            connect_fixture_lan(lan,dhcp)
            docker('exec','-d',dhcp,'dnsmasq','-k','--interface=veth-dhcp','--bind-interfaces',
                   '--no-resolv','--no-hosts','--dhcp-authoritative',
                   '--dhcp-range=192.0.2.0,static,255.255.255.0,1h',f'--dhcp-host={MAC},id:*,{CLIENT}',
                   '--dhcp-option=3','--dhcp-option=6',
                   '--dhcp-match=set:uefi,option:client-arch,7',
                   '--dhcp-match=set:uefi,option:client-arch,9',
                   '--dhcp-userclass=set:ipxe,iPXE',
                   f'--dhcp-boot=tag:uefi,tag:!ipxe,ipxe-shim.efi,,{DHCP}',
                   f'--dhcp-boot=tag:ipxe,http://{SERVER}/boot.ipxe',
                   '--enable-tftp','--tftp-root=/pxe','--log-dhcp','--log-facility=/tmp/windows-dhcp.log')
            start_appliance(app,lan,dhcp,root,boot_assets)
            wait_for(lambda:(root/'tpm.sock').is_socket(), 30, 'disposable TPM socket')
            run_guest(client,lan,helper,root,media,case,discovery=True)
            boot_log = docker('logs',app).stdout
            for name in ('wimboot','BCD','boot.sdi','boot.wim'):
                size = (boot_assets/name).stat().st_size
                if not boot_asset_served(boot_log,name,size):
                    raise RuntimeError(f'The Rust server did not serve the verified {name} to the PXE guest.')
            print('The WinPE guest sent its receipt and requested a reboot.',flush=True)
            run_guest(client,lan,helper,root,media,case,discovery=False)
            log = docker('exec',dhcp,'cat','/tmp/windows-dhcp.log').stdout
            observed = all(re.search(rf'sent .*{re.escape(name)} to {re.escape(CLIENT)}(?:\s|$)', log)
                           for name in SIGNED_IPXE)
            transcript = root/'receipts.log'
            transcript.write_bytes((root/'winpe.log').read_bytes() + b'\n' + (root/'windows.log').read_bytes())
            verify(case, {
                'guest_id':case['guest_id'], 'architecture':'uefi-amd64',
                'efi_boot_manager_transferred':observed, 'winpe_sha256':case['winpe_sha256'],
            }, transcript)
            print('Windows 11 first boot verified after isolated WinPE PXE with Secure Boot and TPM 2.0.',flush=True)
        except subprocess.CalledProcessError as error:
            if error.stderr:
                print(error.stderr[-2000:],end='',flush=True)
            raise
        finally:
            responses = docker('logs',app,check=False).stdout
            for line in responses.splitlines():
                if line.startswith('PXE WinPE asset='):
                    print(line,flush=True)
            summary = docker('exec',dhcp,'tail','-n','25','/tmp/windows-dhcp.log',check=False).stdout
            if summary:
                print(summary,end='',flush=True)
            for name in (client, app, dhcp, lan, tpm):
                docker('rm','-fv',name,check=False)
            docker('image','rm',helper,check=False)


if __name__ == '__main__':
    main()
