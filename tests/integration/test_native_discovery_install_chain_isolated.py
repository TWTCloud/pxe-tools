#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Discover, schedule and install Debian through the native test package.

Only a fresh qcow2 disk is attached. A separately connected fixture mirror
exposes authenticated Debian files over a Unix socket, not a network bridge.
The test adds a serial console to observe the first boot of the installed OS.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
if os.environ.get('PXE_NATIVE_PXE_TEST') != '1' or os.geteuid() != 0:
    raise SystemExit('Run this test only as root on a dedicated disposable test VM.')
image=os.environ.get('PXE_NATIVE_PXE_IMAGE','')
if not re.fullmatch(r'pxe-native-e2e-[a-f0-9]{10}:local',image):
    raise SystemExit('A uniquely named local fixture image is required.')
backend=os.environ.get('PXE_NATIVE_PXE_BACKEND','php')
if backend not in ('php', 'rust', 'rust-apt', 'rust-docker'):
    raise SystemExit('Unknown fixture backend.')
rust_lab=backend!='php'
packaged=backend in ('rust-apt','rust-docker')
server_arch=os.environ.get('PXE_NATIVE_PXE_ARCH','amd64')
client_arch='arm64' if packaged and server_arch=='arm64' else 'amd64'
tty='ttyAMA0' if client_arch=='arm64' else 'ttyS0'
uefi_code='/usr/share/AAVMF/AAVMF_CODE.secboot.fd' if client_arch=='arm64' else '/usr/share/OVMF/OVMF_CODE_4M.secboot.fd'
uefi_vars='/usr/share/AAVMF/AAVMF_VARS.ms.fd' if client_arch=='arm64' else '/usr/share/OVMF/OVMF_VARS_4M.ms.fd'
appliance_image=os.environ.get('PXE_RUST_GUIDED_DOCKER_IMAGE','')
if backend=='rust-docker' and not re.fullmatch(r'pxe-guided-[a-f0-9]{10}:local',appliance_image):
    raise SystemExit('A uniquely named experimental appliance image is required.')


def run(*args, check=True, **kwargs):
    return subprocess.run(args,check=check,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)


def docker(*args, check=True, **kwargs):
    return run('docker',*args,check=check,**kwargs)


def inspect(name):
    return json.loads(docker('inspect',name).stdout)[0]


def endpoint(name):
    data=inspect(name)
    if not data['State']['Running'] or data['HostConfig']['NetworkMode']!='none':
        raise RuntimeError('fixture container is not running in a dedicated network namespace')
    pid=int(data['State']['Pid'])
    inode=os.stat(f'/proc/{pid}/ns/net').st_ino
    if inode==os.stat('/proc/1/ns/net').st_ino:
        raise RuntimeError('refusing to touch the VM host network namespace')
    return pid,inode


def net(name,identity,*args):
    if endpoint(name)!=identity:
        raise RuntimeError('fixture namespace changed during test')
    return run('nsenter','-t',str(identity[0]),'-n','ip',*args)


def links(name,identity):
    return {item['ifname'] for item in json.loads(net(name,identity,'-j','link','show').stdout)}


def no_default_route(name,identity):
    routes=json.loads(net(name,identity,'-j','route','show').stdout)
    if any(item.get('dst')=='default' for item in routes):
        raise RuntimeError('fixture namespace unexpectedly has a default route')


def connect_fixture_lan(app, dhcp):
    app_ns=endpoint(app); dhcp_ns=endpoint(dhcp)
    if app_ns[1]==dhcp_ns[1] or links(app,app_ns)!={'lo'} or links(dhcp,dhcp_ns)!={'lo'}:
        raise RuntimeError('fixture interfaces are not isolated')
    no_default_route(app,app_ns);no_default_route(dhcp,dhcp_ns)
    net(app,app_ns,'link','add','br-pxetest','type','bridge')
    net(app,app_ns,'addr','add','192.0.2.1/24','dev','br-pxetest')
    net(app,app_ns,'link','set','br-pxetest','up')
    net(app,app_ns,'link','add','veth-pxe','type','veth','peer','name','veth-dhcp')
    net(app,app_ns,'link','set','veth-pxe','master','br-pxetest')
    net(app,app_ns,'link','set','veth-pxe','up')
    net(app,app_ns,'link','set','veth-dhcp','netns',str(dhcp_ns[0]))
    net(dhcp,dhcp_ns,'addr','add','192.0.2.2/24','dev','veth-dhcp')
    net(dhcp,dhcp_ns,'link','set','veth-dhcp','up')
    net(app,app_ns,'tuntap','add','dev','tap-pxetest','mode','tap')
    net(app,app_ns,'link','set','tap-pxetest','master','br-pxetest')
    net(app,app_ns,'link','set','tap-pxetest','up')
    if links(app,app_ns)!={'lo','br-pxetest','veth-pxe','tap-pxetest'} or links(dhcp,dhcp_ns)!={'lo','veth-dhcp'}:
        raise RuntimeError('unexpected interface attached to fixture')
    no_default_route(app,app_ns);no_default_route(dhcp,dhcp_ns)


def wait_for(predicate,timeout,description):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(1)
    raise RuntimeError('timed out: '+description)


def capture_screen(root):
    proof = root/'pxe-vga.ppm'
    proof.unlink(missing_ok=True)
    try:
        with socket.socket(socket.AF_UNIX) as monitor:
            monitor.settimeout(4)
            monitor.connect(str(root/'qemu-monitor.sock'))
            monitor.sendall(b'screendump /fixture-data/pxe-vga.ppm\n')
            wait_for(lambda: proof.is_file() and proof.stat().st_size > 0, 4, 'fixture screen')
        screen = subprocess.run(['tesseract', str(proof), 'stdout', '--psm', '6'],
                                text=True, capture_output=True, timeout=15, check=False)
        return screen.stdout.strip()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        return ''


def diagnostic_screen(root):
    screen=capture_screen(root)
    if screen:
        print('Isolated client screen:\n'+screen[-1500:], flush=True)


def wire_rust(app, root):
    from test_native_rust_debian_pxe import native_vhost

    docker('exec',app,'systemctl','mask','--now','php8.4-fpm.service','pxe-tools-php.service','nginx.service')
    docker('cp',str(ROOT/'tests/support/native-rust-pxe/server.py'),app+':/fixture-data/rust-server.py')
    docker('exec',app,'python3','/fixture-data/rust-server.py','wire','/fixture-data')
    nginx=root/'pxe-rust.conf'
    nginx.write_text(native_vhost('http://unix:/fixture-data/mirror.sock:'))
    docker('cp',str(nginx),app+':/usr/lib/pxe-tools/native/pxe.conf')
    docker('exec',app,'systemctl','daemon-reload')


def rust_first_boot(app, dhcp, client, root, fixture):
    docker('exec',app,'systemctl','start','pxe-tools-dnsmasq.service')
    for service in ('pxe-tools-rust-lab.service','pxe-tools-pxe-http.service','pxe-tools-dnsmasq.service'):
        docker('exec',app,'systemctl','is-active','--quiet',service)
    config=docker('exec',app,'cat','/var/lib/pxe-tools-native/rendered/dnsmasq.conf').stdout
    if 'dhcp-range=192.0.2.0,proxy,255.255.255.0' not in config:
        raise RuntimeError('Native proxy DHCP configuration not active')
    status=docker('exec',dhcp,'curl','-sS','--max-time','5','-o','/dev/null','-w','%{http_code}',
                  'http://192.0.2.1/preseed.php?mac=02:00:00:00:00:ff').stdout
    if status!='404':
        raise RuntimeError('Rust preseed did not reject the unknown machine from the lab subnet')
    docker('exec',app,'bash','-ec',
           'set -a; source /usr/lib/pxe-tools/native/default.env; source /var/lib/pxe-tools-native/runtime.env; set +a; '
           'bash /opt/pxe-tools/scripts/bootstrap-install-pxe-bins.sh')
    docker('exec','-d',app,'bash','-ec',
           'set -a; source /usr/lib/pxe-tools/native/default.env; source /var/lib/pxe-tools-native/runtime.env; set +a; '
           'exec python3 /fixture-data/rust-server.py follow /fixture-data >/fixture-data/native-status.log 2>&1')
    log=fixture/'native-status.log'
    wait_for(lambda: log.is_file() and 'PXE_NATIVE_READY' in log.read_text(), 30, 'Rust fixture ready')
    print('Native dnsmasq and Rust HTTP are ready. Both PHP-FPM units are masked.', flush=True)
    run_rust_guests(app,client,root,log)


def prepare_secure_boot(app, root, client_image, *, http_root, tftp_root, mok_root):
    # The fixture copies only the public key, generated by the actual worker.
    tftp=root/'tftp'
    suffix='aa64' if client_arch=='arm64' else 'x64'
    shim=f'grubnet{suffix}.efi'
    grub=f'grub{suffix}.efi'
    wait_for(lambda:all((tftp/name).is_file() for name in (shim,grub,f'mm{suffix}.efi')),
             180,'shim, MokManager and MOK-signed GRUB')
    mok=f'{mok_root}/MOK.pem'
    docker('exec',app,'sbverify','--cert',mok,f'{tftp_root}/{grub}')
    for artifact in (f'{tftp_root}/{shim}',f'{http_root}/netboot/debian/13.0/{client_arch}/linux'):
        print(f'UEFI signature listing for {artifact}:',flush=True)
        print(docker('exec',app,'sbverify','--list',artifact).stdout,flush=True)
    docker('cp',app+':'+mok,str(root/'fixture-mok.pem'))
    docker('run','--rm','--network','none','--mount',f'type=bind,src={root},dst=/fixture-data',
           '--entrypoint','virt-fw-vars',client_image,
           '--input',uefi_vars,
           '--output','/fixture-data/ovmf-vars.fd','--set-shim-verbose','--add-mok',str(uuid.uuid4()),'/fixture-data/fixture-mok.pem')
    print(f'Secure Boot {client_arch} fixture enrolled the instance public MOK in private UEFI variables',flush=True)


def build_secure_boot_client():
    helper=image.replace('pxe-native-e2e-','pxe-uefi-e2e-')
    firmware='qemu-system-arm qemu-efi-aarch64' if client_arch=='arm64' else 'ovmf'
    docker('build','--tag',helper,'-',input=f"""FROM {image}
RUN apt-get update && apt-get install --yes --no-install-recommends {firmware} python3-virt-firmware \
    && rm -rf /var/lib/apt/lists/*
""")
    return helper


def installer_bootloader_log(container):
    data=docker('exec',container,'cat','/tmp/fixture-installer.log',check=False).stdout
    messages=re.split(r'(?=<\d{1,3}>)|\n',data)
    return '\n'.join(message for message in messages if re.search(
        r'grub-(?:installer|install|efi|probe)|shim-signed|efibootmgr|efivarfs|'
        r'mapdevfs|mountvirtfs|partmap|/target/(?:proc|run)|oom-kill|out of memory|killed process',
        message,re.IGNORECASE,
    ))[-12000:]


def check_installed_guest(lan, identity, fixture, log, raid_level, raid_lvm, secure_boot):
    if endpoint(lan)!=identity:
        raise RuntimeError('fixture namespace changed before the SSH host-key scan')
    namespace = ('nsenter', '-t', str(identity[0]), '-n')
    address = '192.0.2.100'
    known_hosts = fixture/'known_hosts'
    if not known_hosts.exists():
        scan = run(*namespace, 'ssh-keyscan', '-T', '2', '-t', 'ed25519', address, check=False)
        if scan.returncode != 0 or not scan.stdout:
            return None
        digest = run('ssh-keygen', '-E', 'sha256', '-lf', '-', input=scan.stdout).stdout.split()[1]
        expected = re.search(r'PXE_NATIVE_INSTALL_OK .* fingerprint=(SHA256:[A-Za-z0-9+/]{43})', log.read_text())
        if expected is None or digest != expected[1]:
            raise RuntimeError('The isolated guest SSH key does not match its installer fingerprint')
        known_hosts.write_text(scan.stdout)
        known_hosts.chmod(0o600)
    commands = [
        'set -eu', 'test "$(systemctl is-active ssh.service)" = active',
        "timeout 30 /bin/sh -c 'while [ -e /etc/systemd/system-generators/pxe-first-boot ]; do sleep 1; done'",
        'test -z "$(find /etc/systemd/system /etc/systemd/system-generators -iname \'*pxe*\' -print 2>/dev/null)"',
        'test ! -e /usr/local/sbin/pxe-machine-ready', 'test ! -e /usr/local/bin/postboot.sh',
        'test "$(systemctl show -p FragmentPath --value pxe-first-boot.service)" = /run/systemd/generator/pxe-first-boot.service',
        'test "$(systemctl show -p Result --value pxe-first-boot.service)" = success',
    ]
    if secure_boot:
        architecture = 'aarch64' if client_arch == 'arm64' else 'x86_64'
        commands += [
            f'test "$(uname -m)" = {architecture}',
            'secure=0',
            'for var in /sys/firmware/efi/efivars/SecureBoot-*; do '
            'if [ "$(od -An -j4 -N1 -tu1 "$var" | tr -d " ")" = 1 ]; then secure=1; fi; done',
            'test "$secure" = 1',
        ]
    if raid_level:
        disks = ('vda', 'vdb', 'vdc') if raid_level == 5 else ('vda', 'vdb')
        commands += [
            'root="$(findmnt -n -o SOURCE --mountpoint /)"',
            'root_name="$(basename "$(readlink -f "$root")")"',
        ]
        if raid_lvm:
            commands += [
                'boot="$(findmnt -n -o SOURCE --mountpoint /boot)"',
                'boot_name="$(basename "$(readlink -f "$boot")")"',
                'test "$(lsblk -dn -o TYPE "$root")" = lvm',
                'set -- /sys/block/"$root_name"/slaves/*',
                'test "$#" = 1',
                'root_name="$(basename "$1")"',
                'test "$root_name" != "$boot_name"',
                'test "$(cat "/sys/block/$boot_name/md/level")" = raid1',
            ]
        else:
            commands += ['test "$(findmnt -n -o TARGET /boot 2>/dev/null || true)" != /boot']
        commands += [f'test "$(cat "/sys/block/$root_name/md/level")" = raid{raid_level}']
        for disk in disks:
            commands += [
                f'test "$(lsblk -dn -o PTTYPE /dev/{disk})" = gpt',
                f'test -d "/sys/block/$root_name/slaves/{disk}{3 if raid_lvm else 2}"',
            ]
            if raid_lvm:
                commands.append(f'test -d "/sys/block/$boot_name/slaves/{disk}2"')
    command = "printf '%s\\n' fixture-password | sudo -S /bin/sh -c " + shlex.quote('\n'.join(commands))
    result = guest_command(lan, identity, fixture, 'fixture', command)
    if result.returncode == 255 and ('Connection' in result.stderr or 'timed out' in result.stderr):
        return None
    if result.returncode != 0:
        raise RuntimeError('The installed Debian guest failed its disk, Secure Boot or postboot checks: ' + result.stderr)
    return True


def run_rust_guests(lan,client,root,log, *, screen_login=False, access_log=None, uefi_image=None,
                    raid_level=None, raid_lvm=False, installer_syslog=None):
    machine_arch='aarch64' if client_arch=='arm64' else 'x86_64'
    use_kvm=os.uname().machine==machine_arch and Path('/dev/kvm').is_char_device()
    if client_arch=='arm64' and os.uname().machine!=machine_arch:
        raise RuntimeError('An ARM64 runner is required for the ARM64 client')
    accelerator='kvm' if use_kvm else 'tcg'
    devices=['--device','/dev/kvm'] if use_kvm else []
    print(f'QEMU client {machine_arch} on {os.uname().machine}, accelerator={accelerator}',flush=True)
    extra_disk=[]
    raid_serials = {None: (), 1: ('TWO',), 5: ('TWO', 'THREE')}[raid_level]
    for index, serial in enumerate(raid_serials, 2):
        filename = f'fixture-raid{index}.qcow2'
        docker('run','--rm','--network','none','--mount',f'type=bind,src={root},dst=/fixture-data',
               '--entrypoint','qemu-img',image,'create','-f','qcow2',f'/fixture-data/{filename}','12G')
        extra_disk.extend((
            '-drive',f'file=/fixture-data/{filename},if=none,id=raid{index},format=qcow2',
            '-device',f'virtio-blk-pci,drive=raid{index},serial=PXE-TEST-{serial}',
        ))
    paths_seen=set()
    next_trace=0.0
    lan_identity=endpoint(lan)
    for name, boot, marker, timeout in (
        ('Discovery','n','PXE_NATIVE_DISCOVERY_OK',1500),
        ('Installer','n','PXE_NATIVE_INSTALL_OK',3900 if client_arch=='arm64' else 3000),
        ('First boot','c','PXE_NATIVE_FIRST_BOOT_OK',900),
    ):
        (root/'qemu-monitor.sock').unlink(missing_ok=True)
        disk_device='virtio-blk-pci,drive=disk,serial=PXE-TEST-ONE'
        network_device='e1000,netdev=lan,mac=02:00:00:00:00:01'
        firmware=['-machine','pc,accel='+accelerator,'-boot',boot]
        if uefi_image:
            disk_device+=',bootindex='+('1' if boot=='c' else '2')
            network_device='virtio-net-pci,disable-legacy=on,netdev=lan,mac=02:00:00:00:00:01,romfile=,bootindex='+(
                '2' if boot=='c' else '1')
            machine = 'virt,gic-version=3' if client_arch=='arm64' else 'q35,smm=on'
            security = [] if client_arch=='arm64' else ['-global','driver=cfi.pflash01,property=secure,value=on']
            firmware=['-machine',machine+',accel='+accelerator,
                      '-cpu','host' if use_kvm else 'max',*security,
                      '-device','virtio-rng-pci',
                      '-fw_cfg','name=opt/org.tianocore/IPv6Support,string=no',
                      '-drive','if=pflash,unit=0,format=raw,readonly=on,file='+uefi_code,
                      '-drive','if=pflash,unit=1,format=raw,file=/fixture-data/ovmf-vars.fd']
        docker('run','-di','--name',client,'--network','container:'+lan,'--cap-add','NET_ADMIN',
               '--device','/dev/net/tun',*devices,'--mount',f'type=bind,src={root},dst=/fixture-data',
               '--entrypoint','qemu-system-'+machine_arch,uefi_image or image,
               *firmware,'-smp','1','-m','1024','-display','none',
               '-drive','file=/fixture-data/fixture.qcow2,if=none,id=disk,format=qcow2',
               '-device',disk_device,*extra_disk,
               '-serial','stdio','-monitor','unix:/fixture-data/qemu-monitor.sock,server=on,wait=off',
               '-no-reboot','-netdev','tap,id=lan,ifname=tap-pxetest,script=no,downscript=no',
               '-device',network_device)
        print(name+' started on the isolated guest network', flush=True)
        wakeup=False
        next_screen=0.0
        next_installer_log=0.0

        def completed():
            nonlocal wakeup,next_screen,next_trace,next_installer_log
            state=inspect(client)['State']
            receipt=log.read_text()
            if 'Traceback (most recent call last)' in receipt:
                raise RuntimeError('Rust server validation failed')
            if name=='Installer' and installer_syslog and time.monotonic()>=next_installer_log:
                next_installer_log=time.monotonic()+20
                if re.search(r'main-menu.*(?:configuring|menu item).*grub-installer.*failed',
                             installer_bootloader_log(installer_syslog),re.IGNORECASE):
                    raise RuntimeError('Debian Installer reported a failure configuring GRUB')
            if access_log and time.monotonic() >= next_trace:
                next_trace=time.monotonic()+20
                access=docker('exec',*access_log[:1],'tail','-n','80',access_log[1],check=False).stdout
                for path,code in re.findall(r'"(?:GET|POST|HEAD) (/[^ ?"\\]*)(?:\?[^ "]+)? HTTP/[\d.]+" (\d{3})',access):
                    if (path,code) not in paths_seen:
                        paths_seen.add((path,code))
                        print('PXE HTTP:',path,code,flush=True)
            if uefi_image:
                output=docker('logs',client,check=False).stdout
                if 'No bootable option or device was found' in output:
                    raise RuntimeError('UEFI firmware found no usable boot option')
                if 'big file signature' in output:
                    raise RuntimeError('GRUB could not determine the signed kernel size')
                if 'bad shim signature' in output:
                    raise RuntimeError('Shim refused the signature of the downloaded kernel')
                if 'Kernel panic - not syncing:' in output:
                    raise RuntimeError(name+' kernel panicked before completing the PXE test')
            if boot=='n':
                if state['ExitCode']!=0:
                    raise RuntimeError(name+' QEMU guest failed')
                return not state['Running'] and marker in receipt
            if not state['Running']:
                raise RuntimeError('The installed guest stopped before login')
            output=docker('logs',client,check=False).stdout
            if not wakeup and f'Debian GNU/Linux 13 pxe-fixture {tty}' in output:
                wakeup=True
                try:
                    subprocess.run(['docker','attach','--sig-proxy=false',client],input='\n',
                                   text=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                   timeout=5,check=False)
                except subprocess.TimeoutExpired:
                    pass
            if marker not in receipt:
                return False
            if 'pxe-fixture login:' in output:
                return True
            if screen_login and time.monotonic() >= next_screen:
                next_screen=time.monotonic()+5
                screen=capture_screen(root)
                if (re.search(r'Debian\s+GNU/Linux\s+13\s+[op]xe.fixture\s+tty',screen,re.I)
                        and re.search(r'[op]xe.fixture\s+login\s*:',screen,re.I)):
                    return True
            return False

        wait_for(completed,min(600,timeout) if uefi_image and client_arch=='amd64' else timeout,
                 name+' and '+marker)
        print(next(line for line in log.read_text().splitlines() if line.startswith(marker)), flush=True)
        if boot == 'c':
            wait_for(lambda:check_installed_guest(lan,lan_identity,root/'ssh',log,raid_level,raid_lvm,bool(uefi_image)),
                     180,'installed guest reached strict SSH and passed the first-boot checks')
            print('Strict SSH verified the volatile first-boot unit and launcher cleanup',flush=True)
            if raid_level:
                print(f"Custom GPT/RAID{raid_level}{'/LVM' if raid_lvm else ''} partition recipe verified from the installed guest",flush=True)
            if uefi_image:
                print('UEFI Secure Boot verified in discovery and the installed guest',flush=True)
        docker('rm','-f',client)
        if uefi_image and name=='Discovery':
            # A fresh GRUB 2.12 starts again at the same TCP source port.
            # The fixture recreates the whole guest with the same IP and MAC.
            # Let the previous connections drain before reusing that identity.
            def previous_connections():
                if endpoint(lan)!=lan_identity:
                    raise RuntimeError('The UEFI fixture network namespace changed')
                return run('nsenter','-t',str(lan_identity[0]),'-n','ss','-Htn',
                           'state','all','( sport = :80 and dst 192.0.2.100 )').stdout.strip()

            remaining=previous_connections()
            if remaining:
                print(f'Draining {len(remaining.splitlines())} HTTP connection(s) before the next UEFI guest',
                      flush=True)
                wait_for(lambda:not previous_connections(),90,'previous GRUB HTTP connections to drain')
    print('Debian GNU/Linux 13 pxe-fixture login: verified with PHP-FPM stopped',flush=True)


def verify_arm64_signed_loaders(root=None, *, native=False):
    # Build with the packaged worker and a disposable key. This container
    # only downloads signed Debian archives, then exits before starting PXE.
    mounts=[]
    mok_path='/run/fixture-mok'
    http_path='/run/fixture-http'
    if root:
        if native:
            # The native publisher atomically moves the public certificate
            # within the same filesystem as the private certificate directory.
            (root/'native-certs/mok').mkdir(mode=0o700,parents=True)
            (root/'native-certs/http').mkdir()
            mounts.extend(('--mount',f'type=bind,src={root/"native-certs"},dst=/run/fixture-certs'))
            mok_path='/run/fixture-certs/mok'
            http_path='/run/fixture-certs/http'
        else:
            (root/'conf/mok').mkdir(mode=0o700)
            mounts.extend(('--mount',f'type=bind,src={root/"conf/mok"},dst={mok_path}'))
        for source,target in (('tftp','/run/fixture-tftp'),):
            mounts.extend(('--mount',f'type=bind,src={root/source},dst={target}'))
    source_image=image if native else appliance_image
    defaults=('set -a; source /usr/lib/pxe-tools/native/default.env; set +a; ' if native else '')
    arm64_on_amd64='' if client_arch=='arm64' else 'export PXE_ARM64_SECURE_BOOT=1; '
    result=docker('run','--rm','--network','bridge',*mounts,'--entrypoint','/bin/bash',source_image,'-ec',
                  defaults+arm64_on_amd64+f'export PXE_IP=192.0.2.1 MOK_DIR={mok_path} '
                  f'HTTP_ROOT={http_path} TFTP_ROOT=/run/fixture-tftp; '
                  'install -d "$HTTP_ROOT" "$TFTP_ROOT"; '
                  'bash /opt/pxe-tools/scripts/bootstrap-generate-mok.sh; '
                  'bash /opt/pxe-tools/scripts/bootstrap-install-pxe-bins.sh; '
                  'bash /opt/pxe-tools/scripts/bootstrap-build-grub.sh; '
                  'test -s "$TFTP_ROOT"/mmaa64.efi; '
                  'sbverify --list "$TFTP_ROOT"/grubnetaa64.efi; '
                  'sbverify --cert "$MOK_DIR"/MOK.pem "$TFTP_ROOT"/grubaa64.efi',check=False)
    if result.returncode:
        print((result.stdout+'\n'+result.stderr)[-7500:],flush=True)
        raise RuntimeError('The packaged worker could not prepare the signed ARM64 chain')
    if native:
        (root/'http/MOK.der').write_bytes((root/'native-certs/http/MOK.der').read_bytes())
    print('Packaged worker prepared authenticated ARM64 shim and MokManager and verified its MOK-signed ARM64 GRUB',flush=True)


def verify_packaged_rust_setup(name, boot_tree=None):
    script=ROOT/'tests/integration/test_rust_initial_setup.py'
    probe='/fixture-tests/test_rust_initial_setup.py'
    native=backend=='rust-apt'
    legacy_cli='/usr/lib/pxe-tools/app/cli/delete-image.php' if native else '/app/cli/delete-image.php'
    mount=('--mount',f'type=bind,src={script},dst={probe},readonly',
           '--mount',f'type=bind,src=/dev/null,dst={legacy_cli},readonly')
    http_root='/var/lib/pxe-tools-http' if native else '/srv/http'
    tftp_root='/var/lib/pxe-tools-tftp' if native else '/srv/tftp'
    mok_root='/var/lib/pxe-tools-native/mok' if native else '/etc/pxe-tools/mok'
    activation=()
    if boot_tree:
        input_dir='/fixture-images'
        dnsmasq_config='/var/lib/pxe-tools-native/rendered/dnsmasq.conf' if native else '/etc/dnsmasq.d/pxe.conf'
        mount+=('--mount',f'type=bind,src={boot_tree},dst={input_dir},readonly')
        activation=('--netboot-fixture',input_dir,'--dnsmasq-config',dnsmasq_config)
    try:
        if native:
            docker('run','-d','--name',name,'--network','none','--privileged','--cgroupns','private',
                   '--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp','--entrypoint','/lib/systemd/systemd',
                   *mount,image,'--unit=basic.target')
            wait_for(lambda:docker('exec',name,'systemctl','list-units','--no-legend',check=False).returncode==0,
                     60,'fresh native systemd')
            docker('exec',name,'python3','/usr/lib/pxe-tools/native/configure-secure-tftp.py','--initialize-instance')
            for unit in ('pxe-tools-admin.target','pxe-tools-pxe-http.service'):
                docker('exec',name,'systemctl','is-active','--quiet',unit)
            if docker('exec',name,'systemctl','is-active','--quiet','pxe-tools-dnsmasq.service',check=False).returncode==0:
                raise RuntimeError('Fresh native setup started dnsmasq')
        else:
            docker('run','-d','--name',name,'--network','none','--cap-add','NET_ADMIN',*mount,appliance_image)
        result=docker('exec','-e','PXE_DISPOSABLE_SETUP_TEST=1',name,'python3',probe,'--installed',
                      '--http-root',http_root,'--tftp-root',tftp_root,'--mok-root',mok_root,
                      *activation,check=False)
        print(result.stdout, end='', flush=True)
        if result.returncode:
            print(result.stderr, end='', flush=True)
            raise RuntimeError('Fresh Rust setup did not pass on the packaged appliance')
    except Exception:
        args=('exec',name,'journalctl','--no-pager','-n','60','-u','pxe-tools-init','-u','pxe-tools-pxe-http') \
            if native else ('logs','--tail','60',name)
        result=docker(*args,check=False)
        print(result.stdout+result.stderr,flush=True)
        raise
    finally:
        docker('rm','-fv',name,check=False)


def run_packaged_rust(app, lan, dhcp, client, root, fixture, discovery_template):
    native=backend=='rust-apt'
    amd64=os.environ.get('PXE_NATIVE_PXE_ARCH')=='amd64'
    boot_tree=root/f'http/netboot/debian/13.0/{client_arch}'
    verify_packaged_rust_setup(app+'-setup', boot_tree if amd64 else None)
    custom_partition=native and amd64
    raid_profile = os.environ.get('PXE_NATIVE_PXE_RAID_LEVEL', '1') if custom_partition else ''
    raid_lvm = raid_profile == '1-lvm'
    raid_level = int(raid_profile.removesuffix('-lvm')) if raid_profile else None
    if raid_level not in (None, 1, 5):
        raise RuntimeError('The isolated fixture supports RAID1, RAID5 or LVM on RAID1.')
    secure_boot=not native or client_arch=='arm64'
    if secure_boot:
        verify_arm64_signed_loaders(root if client_arch=='arm64' else None,native=native)
    http_root='/var/lib/pxe-tools-http' if native else '/srv/http'
    tftp_root='/var/lib/pxe-tools-tftp' if native else '/srv/tftp'
    mok_root='/var/lib/pxe-tools-native/mok' if native else '/etc/pxe-tools/mok'
    # Keep the same interface naming policy in d-i and the installed kernel.
    # An installer-only net.ifnames=0 writes an eth0 stanza for a device
    # which the installed system will name enp0s4.
    kernel=('language=en country=US locale=en_US.UTF-8 keymap=us '
            'ipv6.disable=1 netcfg/no_default_route=true netcfg/get_nameservers=192.0.2.2')
    if secure_boot or custom_partition:
        kernel += f' console=tty0 console={tty},115200n8'
    if client_arch=='arm64':
        kernel += ' log_host=192.0.2.2 log_port=5514'
    env=[
        'TFTP_ROOT='+tftp_root, 'HTTP_ROOT='+http_root,
        'PXE_DB_PATH=/var/lib/pxe-tools/stale.sqlite', 'WORKER_POLL_S=1', 'KERNEL_OPTS='+kernel,
        'DEBIAN_ARCH='+client_arch, 'PXE_FIXTURE_CLIENT_ARCH='+client_arch,
    ]
    http_mount=(root/'http',http_root) if native else (root/'http/netboot',http_root+'/netboot')
    mounts=[]
    for source,target in (
        (root/'data','/var/lib/pxe-tools'), (root/'conf','/etc/pxe-tools'),
        http_mount, (root/'tftp',tftp_root), (fixture,'/fixture-data'),
        (discovery_template,'/opt/pxe-tools/templates/discovery-preseed.cfg.j2'),
        (ROOT/'tests/support/native-rust-pxe/server.py','/fixture-data/rust-server.py'),
    ):
        mounts.extend(('--mount',f'type=bind,src={source},dst={target}'))
    legacy_migration = '/usr/lib/pxe-tools/app/db/migrate.php' if native else '/app/db/migrate.php'
    forbidden_migration = root/'forbidden-migration.php'
    forbidden_migration.write_text('<?php exit(89);\n')
    mounts.extend(('--mount',f'type=bind,src={forbidden_migration},dst={legacy_migration},readonly'))

    if client_arch=='arm64' and native:
        mounts.extend(('--mount',f'type=bind,src={root/"native-certs/mok"},dst={mok_root}'))
    if amd64:
        windows=root/'http/winpe/amd64'
        windows.mkdir(parents=True)
        for name in ('wimboot','BCD','boot.sdi','boot.wim'):
            (windows/name).write_text('fixture:'+name)
        env.append('PXE_WINPE_CLIENT_IP=192.0.2.2')
        if not native:
            mounts.extend(('--mount',f'type=bind,src={windows.parent},dst={http_root}/winpe,readonly'))

    if native:
        env.extend(('PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered','MOK_DIR='+mok_root))
        runtime=root/'runtime.env'
        runtime.write_text('\n'.join(item if ' ' not in item else
                                      f'{item.split("=",1)[0]}="{item.split("=",1)[1]}"' for item in env) + '\n')
        docker('run','-d','--name',app,'--network','none','--privileged','--cgroupns','private',
               '--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp','--entrypoint','/lib/systemd/systemd',
               '--mount',f'type=bind,src={runtime},dst=/var/lib/pxe-tools-native/runtime.env,readonly',
               *mounts,image,'--unit=basic.target')
        wait_for(lambda:docker('exec',app,'systemctl','list-units','--no-legend',check=False).returncode==0,
                 60,'native systemd')
        package=docker('exec',app,'dpkg-query','-W','-f=${Status}|${Version}','pxe-tools').stdout
        if package.strip()!='install ok installed|0.1.0~guided1':
            raise RuntimeError('Expected the packaged Rust APT candidate')
        docker('exec',app,'install','-d','-m','0755','/var/lib/pxe-tools-native/rendered')
        docker('exec',app,'systemctl','mask','--now','php8.4-fpm.service','pxe-tools-php.service','nginx.service')
    else:
        docker('run','-d','--name',lan,'--network','none','--entrypoint','sleep',image,'5400')

    docker('run','-d','--name',dhcp,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
           '--mount',f'type=bind,src={fixture},dst=/fixture-data,readonly',
           '--entrypoint','sleep',image,'5400')
    connect_fixture_lan(lan,dhcp)
    docker('exec','-d',dhcp,'dnsmasq','-k','--interface=veth-dhcp','--bind-interfaces',
           '--no-resolv','--no-hosts','--dhcp-authoritative','--dhcp-range=192.0.2.0,static,255.255.255.0,1h',
           '--dhcp-host=02:00:00:00:00:01,id:*,192.0.2.100','--dhcp-option=3','--dhcp-option-force=6,192.0.2.2',
           '--log-dhcp','--log-facility=/tmp/fixture-dhcp.log')
    docker('exec','-d',dhcp,'socat','TCP-LISTEN:80,bind=192.0.2.2,fork,reuseaddr',
           'UNIX-CONNECT:/fixture-data/mirror.sock')
    if client_arch=='arm64':
        docker('exec','-d',dhcp,'/bin/bash','-ec',
               'exec socat -u UDP4-RECV:5514,bind=192.0.2.2,reuseaddr STDOUT >> /tmp/fixture-installer.log')
    wait_for(lambda:docker('exec',dhcp,'curl','-fsS','--max-time','3',
                           'http://192.0.2.2/debian/dists/trixie/InRelease',check=False).returncode==0,
             30,'fixture mirror inside isolated network')

    if native:
        docker('exec',app,'systemctl','start','pxe-tools.target')
        for service in ('pxe-tools-pxe-http','pxe-tools-dnsmasq','pxe-tools-worker'):
            docker('exec',app,'systemctl','is-active','--quiet',service+'.service')
        dnsmasq_config='/var/lib/pxe-tools-native/rendered/dnsmasq.conf'
    else:
        args=[arg for item in env for arg in ('--env',item)]
        docker('run','-d','--name',app,'--network','container:'+lan,'--cap-add','NET_ADMIN','--cap-add','NET_RAW',
               *args,*mounts,appliance_image)
        expected_pid=int(inspect(lan)['State']['Pid'])
        app_pid=int(inspect(app)['State']['Pid'])
        if not app_pid or os.stat(f'/proc/{app_pid}/ns/net').st_ino != os.stat(f'/proc/{expected_pid}/ns/net').st_ino:
            raise RuntimeError('appliance did not join its isolated network')
        dnsmasq_config='/etc/dnsmasq.d/pxe.conf'

    pg=docker('exec',app,'dpkg','--print-architecture').stdout.strip()
    if pg != os.environ.get('PXE_NATIVE_PXE_ARCH','amd64'):
        raise RuntimeError('Unexpected Rust appliance architecture')
    print(f'Packaged Rust appliance {backend} on Debian 13 {pg}',flush=True)
    pxe_url='http://192.0.2.1'
    def http_ready():
        if not inspect(app)['State']['Running']:
            raise RuntimeError('The packaged appliance stopped during startup')
        return docker('exec',dhcp,'curl','-fsS','--max-time','2',pxe_url+'/healthz',check=False).returncode==0
    wait_for(http_ready,90,'packaged PXE listener')
    for package_name in ('nginx','nginx-common','php8.4-fpm','php8.4-cli','php8.4-curl','php8.4-sqlite3'):
        state=docker('exec',app,'dpkg-query','-W','-f=${Status}',package_name,check=False).stdout
        if state.strip()=='install ok installed':
            raise RuntimeError(f'Unexpected package in the guided appliance: {package_name}')
    for executable in ('php','nginx'):
        if docker('exec',app,'sh','-c','command -v "$1"','check-runtime',executable,check=False).returncode==0:
            raise RuntimeError(f'Unexpected executable in the guided appliance: {executable}')

    tls_dir='/var/lib/pxe-tools-native/tls' if native else '/var/lib/pxe-tools-tls'
    docker('cp',f'{app}:{tls_dir}/cert.pem',str(fixture/'rust-cert.pem'))
    cert='/fixture-data/rust-cert.pem'
    tls_url='https://192.0.2.1'

    def request(url, *options):
        return docker('exec',dhcp,'curl','-sS','--max-time','10','--cacert',cert,
                      '-D','-',*options,url).stdout

    redirect=request(pxe_url+'/')
    if not redirect.startswith('HTTP/1.1 302 ') or 'location: https://192.0.2.1/admin/' not in redirect.lower():
        raise RuntimeError('Expected the root redirect to the HTTPS console')
    if not request(pxe_url+'/admin/devices').startswith('HTTP/1.1 404 '):
        raise RuntimeError('The admin console should require HTTPS')
    redirect=request(tls_url+'/admin/')
    if not redirect.startswith('HTTP/1.1 302 ') or 'location: /admin/devices' not in redirect.lower():
        raise RuntimeError('Expected the canonical devices URL')
    if not request(tls_url+'/admin/devices').startswith('HTTP/1.1 401 '):
        raise RuntimeError('Expected the devices list to require authentication')
    login=('--user','fixture-admin:fixture-login-password')
    devices=request(tls_url+'/admin/devices',*login)
    if not devices.startswith('HTTP/1.1 200 ') or '<h1>Ordinateurs</h1>' not in devices:
        raise RuntimeError('The Rust console did not apply the existing device label')
    settings_url=tls_url+'/admin/settings/device-terminology'
    change=(*login,'--data','ui_device_term=serveur')
    # Basic credentials are attached automatically by browsers. Require a
    # same-origin HTTPS form before authorizing a write.
    if not request(settings_url,*change,'--header','Origin: https://external.example').startswith('HTTP/1.1 403 '):
        raise RuntimeError('A cross-origin request changed the device label')
    saved=request(settings_url,*change,'--header','Origin: '+tls_url)
    if not saved.startswith('HTTP/1.1 303 ') or 'location: /admin/devices' not in saved.lower():
        raise RuntimeError('Expected the label form to redirect to the canonical devices list')
    if '<h1>Serveurs</h1>' not in request(tls_url+'/admin/devices',*login):
        raise RuntimeError('The device label change did not preserve the canonical URL')
    if amd64:
        windows=pxe_url+'/pxe/windows/'
        boot=request(windows+'boot.ipxe')
        if not boot.startswith('HTTP/1.1 200 ') or '#!ipxe\n' not in boot:
            raise RuntimeError('Unable to load the reserved WinPE iPXE script')
        for entry in ('iseq ${platform} efi','iseq ${buildarch} x86_64','kernel ${base}wimboot',
                      'initrd --name BCD','initrd --name boot.sdi','initrd --name boot.wim'):
            if entry not in boot:
                raise RuntimeError('Incomplete WinPE iPXE script')
        menu=request(pxe_url+'/boot.ipxe')
        if not menu.startswith('HTTP/1.1 200 ') or f'chain {windows}boot.ipxe' not in menu:
            raise RuntimeError('The reserved client did not receive the WinPE chain from the iPXE entry')
        fallback=request(pxe_url+'/boot.ipxe?menu=debian')
        if not fallback.startswith('HTTP/1.1 200 ') or 'item debian-' not in fallback or '/pxe/windows/' in fallback:
            raise RuntimeError('The Debian iPXE menu was unavailable to the reserved client')
        normal=docker('exec',app,'curl','-fsS','--max-time','5','http://127.0.0.1/boot.ipxe').stdout
        if 'item debian-' not in normal or '/pxe/windows/' in normal:
            raise RuntimeError('The WinPE menu was exposed to an unreserved client')
        wim=request(windows+'boot.wim','--range','8-11')
        if not wim.startswith('HTTP/1.1 206 ') or not wim.endswith('boot'):
            raise RuntimeError('WinPE did not serve the requested WIM bytes')
        for path in ('/pxe/windows/boot.ipxe','/pxe/windows/boot.wim','/%70xe/windows/boot.wim'):
            denied=docker('exec',app,'curl','-sS','--max-time','5','-D','-',
                          '--header','X-Pxe-Client-Ip: 192.0.2.2','http://127.0.0.1'+path).stdout
            if not denied.startswith('HTTP/1.1 404 '):
                raise RuntimeError('WinPE is visible to an unreserved client')
        print('Synthetic WinPE chain and HTTP range verified for the reserved client only',flush=True)

    kernel_url=f'/netboot/debian/13.0/{client_arch}/linux'
    kernel = request(pxe_url+kernel_url,'--user-agent','GRUB 2.12','--output','/dev/null')
    if not kernel.startswith('HTTP/1.1 200 '):
        raise RuntimeError('The PXE kernel should be available directly on HTTP')
    if not re.search(r'^Content-Length: [1-9][0-9]*\s*$',kernel,re.MULTILINE):
        raise RuntimeError('GRUB requires an exact Content-Length header on the signed kernel')
    # Drop the binary response body after checking the negotiated HTTPS range.
    partial=request(tls_url+kernel_url,'--range','0-15','--output','/dev/null')
    if not partial.startswith('HTTP/1.1 206 ') or 'content-range: bytes 0-15/' not in partial.lower():
        raise RuntimeError('The PXE kernel should support byte ranges on HTTPS')
    origin=request(pxe_url+'/api/install-start','--header','X-Pxe-Client-Ip: 127.0.0.1')
    if not origin.startswith('HTTP/1.1 404 '):
        raise RuntimeError('A client header bypassed the install-start peer check')
    print('Rust HTTP/HTTPS: trusted test certificate, redirect, canonical console, kernel range and peer check verified',flush=True)

    config=docker('exec',app,'cat',dnsmasq_config).stdout
    if 'dhcp-range=192.0.2.0,proxy,255.255.255.0' not in config:
        raise RuntimeError('Packaged dnsmasq proxy configuration is missing')
    response=docker('exec',dhcp,'curl','-sS','--max-time','5','-D','-',
                    pxe_url+'/preseed.php?mac=02:00:00:00:00:ff').stdout
    if not response.startswith('HTTP/1.1 404 ') or 'x-pxe-backend: rust-guided' not in response.lower():
        raise RuntimeError('Packaged Rust preseed did not reject an unknown machine')

    tftp=root/'tftp'
    wait_for(lambda:(tftp/'lpxelinux.0').is_file() and (tftp/'pxelinux.cfg/default').is_file(),
             120,'worker rendering and bootloaders')
    worker_probe = '''
from pathlib import Path
for proc in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        command = proc.read_bytes().split(b'\\0')
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if command[:2] == [b'/usr/lib/pxe-tools/pxe-tools-rust', b'--work-guided']:
        break
else:
    raise SystemExit('The appliance worker is not running in Rust.')
'''
    docker('exec',app,'python3','-c',worker_probe)
    print('Packaged worker is running in Rust',flush=True)
    for name in ('preseed.php','grub.php'):
        if docker('exec',app,'test','-e',f'{http_root}/{name}',check=False).returncode == 0:
            raise RuntimeError(f'The guided worker rendered the legacy PHP file {name}')
    check_env=('set -a; source /usr/lib/pxe-tools/native/default.env; '
               'source /var/lib/pxe-tools-native/runtime.env; set +a; ') if native else (
               'export PXE_APP_DIR=/app; ')
    if custom_partition:
        check_env+=f'export PXE_FIXTURE_RAID_LEVEL={raid_level}; '
        if raid_lvm:
            check_env+='export PXE_FIXTURE_RAID_LVM=1; '
    uefi_image=None
    if secure_boot:
        check_env+='export PXE_FIXTURE_SECURE_BOOT=1; '
        uefi_image=build_secure_boot_client()
        prepare_secure_boot(app,root,uefi_image,http_root=http_root,tftp_root=tftp_root,mok_root=mok_root)
        for artifact in ('linux','initrd.gz','firmware.cpio.gz'):
            with (boot_tree/artifact).open('rb') as stream:
                expected=hashlib.file_digest(stream,'sha256').hexdigest()
            actual=docker('exec',dhcp,'bash','-o','pipefail','-c',
                          'curl -fsS --max-time 30 "$1" | sha256sum','check-boot-asset',
                          f'{pxe_url}/netboot/trixie/{client_arch}/{artifact}').stdout
            if actual.split()[0] != expected:
                raise RuntimeError(f'The HTTP {artifact} differs from the fixture')
    docker('exec','-d',app,'bash','-ec',
           check_env+'export PXE_FIXTURE_MIRROR_IP=192.0.2.2 PXE_FIXTURE_USE_WORKER=1; '
           'exec python3 /fixture-data/rust-server.py follow /fixture-data >/fixture-data/native-status.log 2>&1')
    status=fixture/'native-status.log'
    wait_for(lambda:status.is_file() and 'PXE_NATIVE_READY' in status.read_text(),30,'packaged Rust fixture ready')
    run_rust_guests(lan,client,root,status,screen_login=True,uefi_image=uefi_image,raid_level=raid_level,
                    raid_lvm=raid_lvm,installer_syslog=dhcp if client_arch=='arm64' else None)
    if native:
        logs=docker('exec',app,'journalctl','--no-pager','-u','pxe-tools-pxe-http.service','-o','cat').stdout
    else:
        result=docker('logs',app)
        logs=result.stdout+result.stderr
    for marker in (
        'PXE request peer=192.0.2.100 route=/api/discovery status=200',
        'PXE request peer=192.0.2.100 route=/preseed.php status=200',
        'PXE request peer=192.0.2.100 route=/api/install-end status=200',
        'PXE first boot peer=192.0.2.100 status=200 bytes=9',
    ):
        if marker not in logs.splitlines():
            raise RuntimeError(f'Missing evidence in the Rust server log: {marker}')
    if any('peer=192.0.2.100' in line and ('route=/pxe/postboot/' in line or 'route=/api/machine-ready' in line)
           for line in logs.splitlines()):
        raise RuntimeError('The installed guest requested a legacy postboot callback')
    print('Direct Rust access records and first-boot acknowledgement verified',flush=True)
    pair=('sha256sum',tls_dir+'/cert.pem',tls_dir+'/key.pem')
    before=docker('exec',app,*pair).stdout
    docker('exec',app,'bash','-ec',check_env+'exec /bin/sh /opt/pxe-tools/init/bootstrap-tls.sh')
    if docker('exec',app,*pair).stdout!=before:
        raise RuntimeError('TLS bootstrap changed the existing instance certificate or key')
    print('TLS bootstrap preserved the generated certificate and key',flush=True)


def module_image(root, base, version):
    context = root/'module'
    context.mkdir()
    run('python3',str(ROOT/'packaging/native/build-local-ansible-package.py'),
        str(context/'module.deb'),'--release','--version',version)
    tag = base.replace(':local','-ansible:local')
    docker('build','--tag',tag,'--file','-',str(context),input=f"""FROM {base}
COPY module.deb /tmp/pxe-tools-ansible.deb
RUN apt-get update && apt-get install -y --no-install-recommends /tmp/pxe-tools-ansible.deb
""")
    return tag


def write_ansible_ssh_file(app, name, content):
    docker('exec','-i',app,'runuser','-u','pxe-tools-ansible','--','/bin/sh','-ec',
           'umask 077; cat > "/var/lib/pxe-tools-ansible/home/.ssh/$1"', 'fixture', name, input=content)


def prepare_playbook(app, fixture):
    setup = r"""set -eu
work=/var/lib/pxe-tools-ansible/workspace
ssh=/var/lib/pxe-tools-ansible/home/.ssh
install -d -o pxe-tools-ansible -g pxe-tools-ansible -m 0700 "$work/playbooks" "$ssh"
printf '%s\n' '[defaults]' 'inventory = inventory.ini' 'host_key_checking = True' \
    '[ssh_connection]' 'ssh_args = -o StrictHostKeyChecking=yes -o HostKeyAlgorithms=ssh-ed25519' > "$work/ansible.cfg"
printf '%s\n' 'pxe-fixture ansible_host=192.0.2.100 ansible_python_interpreter=/usr/bin/python3' > "$work/inventory.ini"
cat > "$work/playbooks/base.yml" <<'PLAYBOOK'
- hosts: pxe-fixture
  gather_facts: false
  become: true
  tasks:
    - name: Count executions from the installed guest
      ansible.builtin.shell: "echo one >> /var/tmp/pxe-fixture-playbook"
      changed_when: true
PLAYBOOK
chown pxe-tools-ansible:pxe-tools-ansible "$work/ansible.cfg" "$work/inventory.ini" "$work/playbooks/base.yml"
"""
    docker('exec',app,'/bin/sh','-ec',setup)
    write_ansible_ssh_file(app,'ansible_automation',(fixture/'client-key').read_text())


def guest_command(app, identity, fixture, user, command):
    if endpoint(app)!=identity:
        raise RuntimeError('fixture namespace changed during the SSH check')
    # Once connected, sudo and the disk checks still run under TCG.
    return run('nsenter','-t',str(identity[0]),'-n',
               'ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
               '-o','HostKeyAlgorithms=ssh-ed25519',
               '-o','IdentitiesOnly=yes','-o','ConnectTimeout=3','-o','GlobalKnownHostsFile=/dev/null',
               '-o',f'UserKnownHostsFile={fixture/"known_hosts"}','-i',str(fixture/'client-key'),
               user+'@192.0.2.100',command,check=False,timeout=90)


def main():
    scenario = os.environ.get('PXE_NATIVE_PXE_SCENARIO','plain')
    if scenario not in ('plain','ansible'):
        raise SystemExit('Choose the plain or ansible disposable fixture.')
    provision = scenario == 'ansible'
    suffix=secrets.token_hex(5)
    app='pxe-l2-app-'+suffix; dhcp='pxe-l2-dhcp-'+suffix; client='pxe-l2-client-'+suffix
    mirror='pxe-l2-mirror-'+suffix
    lan='pxe-l2-lan-'+suffix if backend=='rust-docker' else app
    names=list(dict.fromkeys([client,app,dhcp,lan,mirror]))
    fixture_parent = os.environ.get('PXE_TEST_FIXTURE_PARENT', '/var/tmp')
    with tempfile.TemporaryDirectory(prefix='pxe-l2-fixture-',dir=fixture_parent) as temporary:
        root=Path(temporary); root.chmod(0o755)
        fixture=root/'fixture'; fixture.mkdir(mode=0o755)
        ssh_fixture=root/'ssh'; ssh_fixture.mkdir(mode=0o700)
        run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(ssh_fixture/'client-key'))
        client_pubkey=(ssh_fixture/'client-key.pub').read_text().strip()
        if rust_lab:
            (fixture/'guest-fixture.pub').write_text(client_pubkey+'\n')
        data,conf,http,tftp=(root/x for x in ('data','conf','http','tftp'))
        for directory in (data,conf,http,tftp):directory.mkdir(mode=0o755)
        (conf/'master.key').write_bytes(os.urandom(32));(conf/'master.key').chmod(0o600)
        (conf/'db.conf').write_text(json.dumps({'driver':'sqlite','path':'/var/lib/pxe-tools/chosen.sqlite'}))
        (conf/'db.conf').chmod(0o600)
        # Static bcrypt hash of the public test password fixture-login-password.
        login_hash='$2y$12$zGZhsSwt3AHDHVbliUPl5eMV46SsqfpLUsIOAcZiq1frkQPqxaEcK'
        with sqlite3.connect(data/'chosen.sqlite') as db:
            db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
            db.executemany('INSERT INTO settings(key,value) VALUES(?,?)',[
                ('pxe_enabled','on'),('pxe_ip','192.0.2.1'),('pxe_subnet','192.0.2.0/24'),('pxe_interface','br-pxetest'),
                ('dhcp_proxy_enabled','on'),('dhcp_proxy_network','192.0.2.0'),
                ('dhcp_proxy_netmask','255.255.255.0'),('https_enabled','off'),
                ('wizard_completed','1'),('db_init_done','1'),('admin_created','1'),('init_completed','1'),
                ('ansible_enabled','on' if provision else 'off'),('ansible_ssh_pubkey',client_pubkey),
                ('catalog_auto_refresh_enabled','off'),('ui_device_term','ordinateur')])
            if not rust_lab or packaged:
                db.execute('INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)',('fixture-admin',login_hash))
            db.execute("INSERT INTO os_images(distro,version,arch,codename,version_full,enabled,status) "
                       "VALUES('debian','13.0',?,'trixie','13.0',1,'downloaded')",(client_arch,))
            if client_arch=='arm64':
                # The isolated worker receives its already prepared bootloaders
                # from a build-only container with access to the Debian archive.
                db.execute("""INSERT INTO init_jobs(job_type,status)
                              VALUES('bootstrap:generate_mok','success'),('bootstrap:build_grub','success')""")
        if provision:
            (data/'chosen.sqlite').chmod(0o600)
        # A stale but valid DB must never drive the appliance, even when its
        # path is present in the inherited environment.
        with sqlite3.connect(data/'stale.sqlite') as db:
            db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
            db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [
                ('pxe_subnet','198.51.100.0/24'), ('pxe_ip','198.51.100.1'),
                ('pxe_interface','fixture-stale'), ('fixture_marker','preserved')])
            db.execute("INSERT INTO machines(id,mac,hostname,status) VALUES(1,'02:00:00:00:00:01','stale-fixture','wiping')")
        netboot=http/f'netboot/debian/13.0/{client_arch}';netboot.mkdir(parents=True)
        instrument=(ROOT/'docker/worker/templates/preseed-base.cfg.j2').read_text()
        needle="{{ '{{ADMIN_USER_BLOCK}}' }}"
        if instrument.count(needle)!=1: raise RuntimeError('unexpected preseed template')
        # Keep the same interface names as the installer in this fixture.
        names_option = '' if rust_lab else ' net.ifnames=0'
        serial=(f" ; in-target /bin/sh -c 'printf \"\\nGRUB_CMDLINE_LINUX=\\\"console=tty0 console=ttyS0,115200n8{names_option}\\\"\\n\" >> /etc/default/grub; update-grub' ; printf 'PXE_FULL_LATE_DONE\\n' >/dev/ttyS0")
        serial+=r""" ; printf 'PXE_HOST_PUBLIC ' >/dev/ttyS0 ; cat /target/etc/ssh/ssh_host_ed25519_key.pub >/dev/ttyS0 ; if [ -e /target/etc/systemd/system-generators/pxe-first-boot ]; then fixture_mode=$(in-target --pass-stdout /usr/bin/stat -c '%a' /etc/systemd/system-generators/pxe-first-boot); printf 'PXE_LAUNCHER %s\n' "$fixture_mode" >/dev/ttyS0; fi"""
        instrument=instrument.replace(needle,needle+serial)+"\nd-i mirror/udeb/suite string trixie\n"
        template=root/'preseed-base.cfg.j2';template.write_text(instrument)
        discovery=(ROOT/'docker/worker/templates/discovery-preseed.cfg.j2').read_text()
        discovery_needle='d-i mirror/http/hostname string deb.debian.org'
        if discovery.count(discovery_needle)!=1: raise RuntimeError('unexpected discovery mirror template')
        mirror_ip='192.0.2.2' if packaged else '192.0.2.1'
        discovery=discovery.replace(discovery_needle,f'd-i mirror/http/hostname string {mirror_ip}')
        if packaged:
            discovery=discovery.replace('fr_FR.UTF-8','en_US.UTF-8')
            discovery=discovery.replace('xkb-keymap select fr','xkb-keymap select us')
            discovery=discovery.replace('debian-installer/language string fr','debian-installer/language string en')
            discovery=discovery.replace('debian-installer/country string FR','debian-installer/country string US')
        discovery=discovery.replace('d-i clock-setup/ntp boolean true','d-i clock-setup/ntp boolean false')
        discovery+='\nd-i mirror/udeb/suite string trixie\n'
        discovery_template=root/'discovery-preseed.cfg.j2';discovery_template.write_text(discovery)
        # Report only which sysfs paths contain this synthetic disk's serial.
        # The production collector remains otherwise unchanged.
        discover_script=(ROOT/'docker/worker/templates/discover.sh.j2').read_text()
        marker='DISKS_JSON=""'
        if discover_script.count(marker)!=1: raise RuntimeError('unexpected discovery collector')
        probe='''for fixture_path in /sys/block/vda/device/serial /sys/block/vda/serial /sys/block/vda/device/device/serial; do
    if [ -r "$fixture_path" ] && [ "$(cat "$fixture_path")" = "PXE-TEST-ONE" ]; then
        printf 'FIXTURE_SERIAL_LOCATION=%s\\n' "$fixture_path" >/dev/ttyS0
    fi
done
'''
        discover_script=discover_script.replace(marker,probe+marker)
        discover_template=root/'discover.sh.j2';discover_template.write_text(discover_script)
        import shutil
        shutil.copytree(ROOT/'docker/pxe-tools/static-bin',http/'static-bin')
        docker('run','--rm','--network','none','--mount',f'type=bind,src={root},dst=/fixture-data',
               '--entrypoint','qemu-img',image,'create','-f','qcow2','/fixture-data/fixture.qcow2','12G')
        mounts=[]
        for src,dst in ((data,'/var/lib/pxe-tools'),(conf,'/etc/pxe-tools'),(http,'/var/lib/pxe-tools-http'),(tftp,'/var/lib/pxe-tools-tftp')):
            mounts+=['--mount',f'type=bind,src={src},dst={dst}']
        try:
            prototype=str(ROOT/'tests/support/prototype')
            docker('run','-d','--name',mirror,'--mount',f'type=bind,src={fixture},dst=/fixture-data',
                   '--mount',f'type=bind,src={ROOT},dst=/fixture-source,readonly',
                   '--mount',f'type=bind,src={prototype},dst=/fixture-prototype,readonly',
                   '-e','PXE_DISPOSABLE_APPLIANCE_MIRROR=1','-e','PXE_FIXTURE_CLIENT_ARCH='+client_arch,
                   '--entrypoint','python3',image,
                   '/fixture-source/tests/integration/appliance_pxe_fixture_mirror.py')
            def mirror_ready():
                if not inspect(mirror)['State']['Running']: raise RuntimeError('fixture mirror stopped')
                return (fixture/'ready').exists()
            wait_for(mirror_ready,600,'authenticated fixture mirror')
            for item in ('linux','initrd.gz'):
                import shutil
                shutil.copyfile(fixture/item,netboot/item)
            if packaged:
                # The downloader publishes both the versioned dir and the
                # codename alias used by the dynamic GRUB menus. The virtual
                # NIC needs no firmware, but GRUB loads the cpio alongside d-i.
                alias = http/f'netboot/trixie/{client_arch}'
                alias.parent.mkdir()
                alias.symlink_to(f'../debian/13.0/{client_arch}', target_is_directory=True)
                fields = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0)
                empty_cpio = ('070701' + ''.join(f'{field:08x}' for field in fields)).encode()
                empty_cpio += b'TRAILER!!!\0'
                empty_cpio += b'\0' * (-len(empty_cpio) % 4)
                (netboot/'firmware.cpio.gz').write_bytes(gzip.compress(empty_cpio, mtime=0))
                run_packaged_rust(app,lan,dhcp,client,root,fixture,discovery_template)
                return
            mounts += ['--mount',f'type=bind,src={fixture},dst=/fixture-data']
            # The image already contains the locally built .deb installed with
            # dpkg. Only test-specific mirror and console instrumentation are
            # copied into this disposable container, before starting services.
            package_name=os.environ.get('PXE_NATIVE_PXE_PACKAGE', 'pxe-tools-local-test')
            package_version=os.environ.get('PXE_NATIVE_PXE_VERSION', '0.0.1~local1')
            if provision and package_name!='pxe-tools':
                raise RuntimeError('The native module test requires the production-layout base candidate')
            app_image=module_image(root,image,package_version) if provision else image
            docker('run','-d','--name',app,'--network','none','--privileged','--cgroupns','private',
                   '--device','/dev/net/tun','--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',
                   '--entrypoint','/lib/systemd/systemd',*mounts,app_image,'--unit=basic.target')
            wait_for(lambda:docker('exec',app,'systemctl','list-units','--no-legend',check=False).returncode==0,
                     60,'native systemd')
            package=docker('exec',app,'dpkg-query','-W','-f=${Status}|${Version}',package_name).stdout
            if package.strip()!=f'install ok installed|{package_version}':
                raise RuntimeError('Expected native test package version was not installed')
            architecture=docker('exec',app,'dpkg','--print-architecture').stdout.strip()
            if architecture != os.environ.get('PXE_NATIVE_PXE_ARCH', 'amd64'):
                raise RuntimeError('Unexpected PXE Tools server architecture')
            print('Native Debian PXE Tools server architecture:', architecture, flush=True)
            nginx=docker('exec',app,'cat','/usr/lib/pxe-tools/native/pxe.conf').stdout
            nginx=nginx.replace('    location /netboot/ {',
                '    location ^~ /debian/ { proxy_pass http://unix:/fixture-data/mirror.sock:; proxy_read_timeout 120s; }\n\n    location /netboot/ {')
            nginx_file=root/'pxe.conf'; nginx_file.write_text(nginx)
            for source,target in ((nginx_file,'/usr/lib/pxe-tools/native/pxe.conf'),
                                  (template,'/opt/pxe-tools/templates/preseed-base.cfg.j2'),
                                  (discovery_template,'/opt/pxe-tools/templates/discovery-preseed.cfg.j2'),
                                  (discover_template,'/opt/pxe-tools/templates/discover.sh.j2')):
                if rust_lab and source!=discover_template:
                    continue
                docker('cp',str(source),app+':'+target)
            kernel_opts=(
                '' if rust_lab else
                '\'KERNEL_OPTS="language=fr country=FR locale=fr_FR.UTF-8 keymap=fr ipv6.disable=1 net.ifnames=0"\' '
            )
            docker('exec',app,'sh','-c',
                   "install -d -m 0755 /var/lib/pxe-tools-native/rendered && "
                   "printf '%s\\n' TFTP_ROOT=/var/lib/pxe-tools-tftp HTTP_ROOT=/var/lib/pxe-tools-http "
                   "PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered MOK_DIR=/var/lib/pxe-tools-native/mok "
                   "PXE_DB_PATH=/var/lib/pxe-tools/stale.sqlite WORKER_POLL_S=1 "
                   + kernel_opts +
                   "> /var/lib/pxe-tools-native/runtime.env")
            if rust_lab:
                wire_rust(app,root)
            docker('run','-d','--name',dhcp,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
                   '--entrypoint','/bin/sh',image,'-c','exec sleep 4200')
            connect_fixture_lan(app,dhcp)
            app_ns=endpoint(app)
            lease_opts=(
                ('--no-resolv','--no-hosts','--address=/pxe-native-lab.example.test/192.0.2.1',
                 '--dhcp-authoritative','--dhcp-range=192.0.2.0,static,255.255.255.0,1h',
                 '--dhcp-host=02:00:00:00:00:01,id:*,192.0.2.100','--dhcp-option=3','--dhcp-option-force=6,192.0.2.2')
                if rust_lab else
                ('--port=0','--dhcp-range=192.0.2.100,192.0.2.120,255.255.255.0,1h',
                 '--dhcp-host=02:00:00:00:00:01,192.0.2.100','--dhcp-option=6,192.0.2.1')
            )
            docker('exec','-d',dhcp,'dnsmasq','-k','--interface=veth-dhcp','--bind-interfaces',
                   *lease_opts,'--log-dhcp','--log-facility=/tmp/fixture-dhcp.log')
            if rust_lab:
                rust_first_boot(app,dhcp,client,root,fixture)
                return
            if provision:
                prepare_playbook(app,ssh_fixture)
            docker('exec',app,'systemctl','start','pxe-tools.target')
            if provision:
                def module_ready():
                    with sqlite3.connect(data/'chosen.sqlite') as db:
                        row=db.execute("SELECT value FROM settings WHERE key='ansible_runtime_status'").fetchone()
                    return row is not None and json.loads(row[0]).get('state')=='ready'
                runtime=docker('exec',app,'env','PXE_ANSIBLE_MODE=system',
                               'PXE_DB_PATH=/var/lib/pxe-tools/chosen.sqlite',
                               'PYTHONPATH=/usr/lib/pxe-tools/app',
                               'python3','-c','import worker; worker.resolve_ansible_runtime()',check=False)
                if runtime.returncode:
                    raise RuntimeError('Native Ansible runtime rejected the fixture: '+runtime.stderr)
                wait_for(module_ready,90,'packaged Ansible runtime ready')
            def ready():
                if not inspect(app)['State']['Running']:raise RuntimeError('appliance stopped during startup')
                result=docker('exec',app,'systemctl','is-active','--quiet','pxe-tools-dnsmasq.service',check=False)
                health=docker('exec',app,'curl','-sS','--max-time','2','http://127.0.0.1/healthz',check=False)
                return result.returncode==0 and health.returncode==0
            wait_for(ready,90,'appliance services')
            config=docker('exec',app,'cat','/var/lib/pxe-tools-native/rendered/dnsmasq.conf').stdout
            if 'dhcp-range=192.0.2.0,proxy,255.255.255.0' not in config:
                raise RuntimeError('actual proxy DHCP configuration not active')
            docker('exec','-e','TFTP_ROOT=/var/lib/pxe-tools-tftp','-e','PXE_SERVICE_MANAGER=systemd',app,'bash',
                   '/opt/pxe-tools/scripts/bootstrap-install-pxe-bins.sh')
            menu=tftp/'pxelinux.cfg/01-02-00-00-00-00-01'
            default_menu=tftp/'pxelinux.cfg/default'
            if not default_menu.is_file() or 'DEFAULT discovery' not in default_menu.read_text() or menu.exists():
                raise RuntimeError('client must start unknown using the discovery menu')
            outside=docker('exec',app,'curl','-sS','-o','/dev/null','-w','%{http_code}',
                           'http://127.0.0.1/preseed.php?mac=02:00:00:00:00:ff',check=False)
            if outside.returncode!=0 or outside.stdout!='403':
                raise RuntimeError('preseed did not reject an address outside the configured client subnet')
            allowed=docker('exec',dhcp,'curl','-sS','-w','\\n%{http_code}',
                           'http://192.0.2.1/preseed.php?mac=02:00:00:00:00:ff',check=False)
            if allowed.returncode!=0 or not allowed.stdout.endswith('\n404') or 'machine introuvable' not in allowed.stdout:
                raise RuntimeError('preseed did not accept the isolated client subnet before machine lookup')
            # Discovery runs on the same isolated virtual hardware and blank
            # disk later used by the installation; it must supply the serial.
            docker('run','-d','--name',client,'--network','container:'+app,'--cap-add','NET_ADMIN',
                   '--device','/dev/net/tun','--mount',f'type=bind,src={root},dst=/fixture-data','--entrypoint','qemu-system-x86_64',image,
                   '-machine','pc,accel=tcg','-smp','1','-m','1024','-display','none',
                   '-drive','file=/fixture-data/fixture.qcow2,if=none,id=disk,format=qcow2',
                   '-device','virtio-blk-pci,drive=disk,serial=PXE-TEST-ONE',
                   '-serial','stdio','-monitor','unix:/fixture-data/qemu-monitor.sock,server=on,wait=off','-no-reboot','-boot','n',
                   '-netdev','tap,id=lan,ifname=tap-pxetest,script=no,downscript=no',
                   '-device','e1000,netdev=lan,mac=02:00:00:00:00:01')
            print('Unknown BIOS client booted into Discovery on isolated virtual hardware',flush=True)
            def discovered():
                if not inspect(client)['State']['Running']: raise RuntimeError('Discovery client stopped prematurely')
                with sqlite3.connect(data/'chosen.sqlite') as db:
                    row=db.execute('SELECT status,inventory_json FROM machines WHERE mac=?',
                                   ('02:00:00:00:00:01',)).fetchone()
                if not row or row[0]!='discovered' or not row[1]: return False
                inventory=json.loads(row[1])
                disks=inventory.get('disks',[])
                if not any(disk.get('identity',{}).get('value')=='PXE-TEST-ONE'
                           and disk.get('identity',{}).get('status')=='valid' for disk in disks):
                    output=docker('logs',client,check=False).stdout
                    print('Fixture serial locations:',re.findall(r'FIXTURE_SERIAL_LOCATION=([^\r\n]+)',output),flush=True)
                    print('Fixture disk identity states:',[(d.get('name'),d.get('identity',{}).get('source'),d.get('identity',{}).get('status')) for d in disks],flush=True)
                    raise RuntimeError('Discovery did not verify the fixture disk serial')
                return True
            wait_for(discovered,1500,'Discovery inventory with verified fixture disk')
            print('Real Discovery reported the disposable disk identity',flush=True)
            ui='''import http.cookiejar,json,re,sys,time,urllib.parse,urllib.request
from pathlib import Path
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
base='http://127.0.0.1:8080'
page=opener.open(base+'/login',timeout=5).read().decode()
token=re.search(r'name="csrf_token" value="([^"]+)"',page).group(1)
def post(path,values):
    return opener.open(base+path,urllib.parse.urlencode(values).encode(),timeout=20)
post('/login',{'username':'fixture-admin','password':'fixture-login-password','csrf_token':token}).read()
if sys.argv[1]=='checklist':
    page=opener.open(base+'/tasks/'+str(int(sys.argv[2])),timeout=10).read().decode()
    if 'Démarrage du système installé' not in page:
        raise RuntimeError('The completed action did not show the confirmed first boot')
    print('The task page shows the confirmed first boot')
    sys.exit(0)
page=opener.open(base+'/machines/1/install',timeout=10).read().decode()
token=re.search(r'name="csrf_token" value="([^"]+)"',page).group(1)
values={'csrf_token':token,'hostname':'pxe-fixture','domain':'example.test','distro':'debian',
 'codename':'trixie','version_full':'13.0','network_mode':'dhcp','partition_mode':'default',
 'admin_user_login':'fixture','admin_user_password':'fixture-password','root_login_mode':'disabled',
 'pre_wipe_mode':'aucun','wake_now':'1','adv[localization][locale]':'fr_FR.UTF-8',
 'adv[localization][keymap]':'fr','adv[mirror][country]':'manual',
 'adv[mirror][hostname]':'192.0.2.1','adv[mirror][directory]':'/debian',
 'adv[timezone][utc]':'1','adv[timezone][zone]':'UTC','adv[packages][tasksel]':'ssh-server',
 'adv[packages][pkgsel_include]':'sudo,openssh-server,curl','adv[packages][upgrade]':'none',
 'adv[apt][disable_services]':'1','adv[bootloader][only_debian]':'1','adv[finish][reboot]':'quiet'}
if sys.argv[1]=='ansible':
    values['ansible_role']='base'
else:
    values['admin_user_pubkeys']=sys.argv[2]
preview=json.load(post('/machines/1/install-preview',values))
if preview.get('errors'): raise RuntimeError('Preflight refused fixture: '+str(preview['errors']))
response=post('/machines/1/install',values)
if not re.fullmatch(re.escape(base)+r'/tasks/[0-9]+',response.geturl()):
    raise RuntimeError('Install submission did not redirect to activity')
response.read()
menu=Path('/var/lib/pxe-tools-tftp/pxelinux.cfg/01-02-00-00-00-00-01')
deadline=time.monotonic()+90
while time.monotonic()<deadline:
    if menu.is_file() and 'DEFAULT install' in menu.read_text(): break
    time.sleep(1)
else: raise RuntimeError('Install menu not generated')
page=opener.open(base+'/machines/1',timeout=10).read().decode()
token=re.search(r'name="csrf_token" value="([^"]+)"',page).group(1)
post('/machines/1/reboot',{'csrf_token':token}).read()
print('Authenticated UI scheduled installation and requested reboot after menu generation')
'''
            docker('exec',app,'python3','-c',ui,scenario,client_pubkey)
            with sqlite3.connect(data/'chosen.sqlite') as db:
                config=json.loads(db.execute('SELECT install_config_json FROM machines WHERE id=1').fetchone()[0])
                if (config.get('system_disk_identity',{}).get('value')!='PXE-TEST-ONE'
                        or config.get('advanced',{}).get('apt',{}).get('services_select')!=[]):
                    raise RuntimeError('Scheduled snapshot lost disk identity or explicit APT choice')
            def discovery_rebooted():
                state=inspect(client)['State']
                if state['Running']: return False
                if state['ExitCode']!=0: raise RuntimeError('Discovery reboot failed')
                return True
            wait_for(discovery_rebooted,180,'Discovery reboot requested by the interface')
            docker('rm','-f',client)
            (root/'qemu-monitor.sock').unlink(missing_ok=True)
            docker('run','-d','--name',client,'--network','container:'+app,'--cap-add','NET_ADMIN',
                   '--device','/dev/net/tun','--mount',f'type=bind,src={root},dst=/fixture-data','--entrypoint','qemu-system-x86_64',image,
                   '-machine','pc,accel=tcg','-smp','1','-m','1024','-display','none',
                   '-drive','file=/fixture-data/fixture.qcow2,if=none,id=disk,format=qcow2',
                   '-device','virtio-blk-pci,drive=disk,serial=PXE-TEST-ONE',
                   '-serial','stdio','-monitor','unix:/fixture-data/qemu-monitor.sock,server=on,wait=off','-no-reboot','-boot','n',
                   '-netdev','tap,id=lan,ifname=tap-pxetest,script=no,downscript=no',
                   '-device','e1000,netdev=lan,mac=02:00:00:00:00:01')
            print('Discovery rebooted; watching the installer and authenticated checkpoints',flush=True)
            began=time.monotonic()
            seen=False; deadline=began+3000
            previous=None
            http_reported=set()
            screen_at=began+45
            while time.monotonic()<deadline:
                output=docker('logs',client,check=False).stdout
                if 'PXE_FULL_LATE_DONE' in output: seen=True
                with sqlite3.connect(data/'chosen.sqlite') as db:
                    progress=db.execute('SELECT install_status FROM installations ORDER BY id DESC LIMIT 1').fetchone()
                if progress and progress!=previous:
                    print('Installer receipt:', progress[0], flush=True)
                    previous=progress
                if progress==('failed',):
                    raise RuntimeError('application recorded a failed installation')
                access=docker('exec',app,'tail','-n','80','/var/lib/pxe-tools-native/log/nginx-access.log',
                              check=False).stdout
                for path, status in re.findall(r'"(?:GET|POST|HEAD) (/[^ ?"\\]*)(?:\?[^ "]+)? HTTP/[\d.]+" (\d{3}) ',access):
                    if path.startswith(('/preseed.php','/netboot/','/debian/dists/','/api/')):
                        receipt=(path,status)
                        if receipt not in http_reported:
                            print('Isolated HTTP:',*receipt,flush=True)
                            http_reported.add(receipt)
                if progress is None and time.monotonic()-began>600:
                    raise RuntimeError('no authenticated installer start on the isolated network')
                if progress is None and time.monotonic()>=screen_at:
                    diagnostic_screen(root)
                    screen_at=time.monotonic()+120
                state=inspect(client)['State']
                if not state['Running']:
                    if not seen or state['ExitCode']!=0: raise RuntimeError('installer exited before successful late command')
                    break
                time.sleep(5)
            else: raise RuntimeError('installer timed out')
            with sqlite3.connect(data/'chosen.sqlite') as db:
                installation=db.execute('SELECT action_id,install_status,ansible_status FROM installations ORDER BY id DESC LIMIT 1').fetchone()
                machine=db.execute('SELECT status,local_boot_source FROM machines WHERE id=1').fetchone()
                receipt=db.execute("SELECT message FROM machine_events WHERE action_id=? AND message LIKE 'Empreinte SSH%'",
                                   (installation[0],)).fetchone()
                premature=db.execute("SELECT checkpoint FROM machine_events WHERE checkpoint IN ('os_first_boot','ansible_started')").fetchall()
            if installation[1:]!=('success','pending') or machine!=('installed','pxe') or premature:
                raise RuntimeError('Unexpected installation or provisioning state before first boot')
            output=docker('logs',client).stdout
            public=re.search(r'PXE_HOST_PUBLIC (ssh-ed25519 [A-Za-z0-9+/=]+)',output)
            if public is None or 'PXE_LAUNCHER 700' not in output:
                raise RuntimeError('Installer SSH key or launcher mode missing or unexpected')
            (ssh_fixture/'host.pub').write_text(public[1]+'\n')
            fingerprint=run('ssh-keygen','-E','sha256','-lf',str(ssh_fixture/'host.pub')).stdout.split()[1]
            if receipt is None or not receipt[0].endswith(fingerprint):
                raise RuntimeError('Installer receipt does not match the public key from the guest console')
            (ssh_fixture/'known_hosts').write_text('192.0.2.100 '+public[1]+'\n')
            if provision:
                write_ansible_ssh_file(app,'known_hosts',(ssh_fixture/'known_hosts').read_text())
                docker('exec',app,'/bin/sh','-ec',
                       'install -d -m 0700 /dev/shm/pxe-vault; umask 077; printf "%s" fixture-vault-password > /dev/shm/pxe-vault/unlock')
            # Keep the guest powered off while the worker polls, with the Vault already open.
            time.sleep(3)
            with sqlite3.connect(data/'chosen.sqlite') as db:
                if db.execute('SELECT ansible_status FROM installations WHERE action_id=?',
                              (installation[0],)).fetchone()!=('pending',):
                    raise RuntimeError('The worker handled the installation before the installed OS reported boot')
            wait_for(lambda:menu.is_file() and 'DEFAULT localboot' in menu.read_text(),120,'worker switched the per-MAC menu to local boot')
            print('Verified action-bound install-end and public SSH fingerprint before first boot',flush=True)
            with sqlite3.connect(data/'stale.sqlite') as db:
                if (db.execute("SELECT value FROM settings WHERE key='fixture_marker'").fetchone()!=('preserved',)
                        or db.execute('SELECT status FROM machines WHERE id=1').fetchone()!=('wiping',)):
                    raise RuntimeError('stale fixture database was modified')
            user='ansible' if provision else 'fixture'
            for boot in (1,2):
                docker('rm','-f',client)
                docker('run','-di','--name',client,'--network','container:'+app,'--cap-add','NET_ADMIN',
                       '--device','/dev/net/tun','--mount',f'type=bind,src={root},dst=/fixture-data',
                       '--entrypoint','qemu-system-x86_64',image,
                       '-machine','pc,accel=tcg','-smp','1','-m','1024','-display','none','-boot','n',
                       '-serial','stdio','-monitor','none','-no-reboot',
                       '-netdev','tap,id=lan,ifname=tap-pxetest,script=no,downscript=no',
                       '-device','e1000,netdev=lan,mac=02:00:00:00:00:01',
                       '-drive','file=/fixture-data/fixture.qcow2,if=none,id=disk,format=qcow2',
                       '-device','virtio-blk-pci,drive=disk,serial=PXE-TEST-ONE')
                ssh_error=''
                def ssh_ready():
                    nonlocal ssh_error
                    if not inspect(client)['State']['Running']:
                        raise RuntimeError('The installed guest stopped before reaching SSH')
                    attempt=guest_command(app,app_ns,ssh_fixture,user,'true')
                    if 'Host key verification failed' in attempt.stderr:
                        raise RuntimeError('The pinned installed guest key was refused')
                    ssh_error=attempt.stderr.strip()
                    return attempt.returncode==0
                try:
                    wait_for(ssh_ready,600,'installed Debian reached strict SSH after network boot')
                except RuntimeError:
                    print(f'Last isolated SSH error: {ssh_error}',flush=True)
                    raise
                if boot==1:
                    def completed():
                        with sqlite3.connect(data/'chosen.sqlite') as db:
                            state=db.execute('SELECT ansible_status FROM installations WHERE action_id=?',
                                             (installation[0],)).fetchone()[0]
                        if state=='failed':
                            raise RuntimeError('Fixture Ansible provisioning failed')
                        return state==('success' if provision else 'no_role')
                    wait_for(completed,240,'worker finalized the installation')
                command=r"""
set -eu
root=$(findmnt -n -o SOURCE /)
lsblk -sno NAME "$root" | grep -qw vda
test "$(systemctl is-active ssh.service)" = active
test ! -e /etc/systemd/system-generators/pxe-first-boot
test ! -e /usr/local/sbin/pxe-machine-ready
test ! -e /usr/local/bin/postboot.sh
test -z "$(find /etc/systemd/system -iname '*pxe*' -print)"
if [ -f /var/tmp/pxe-fixture-playbook ]; then wc -l </var/tmp/pxe-fixture-playbook; else echo 0; fi
systemctl show pxe-first-boot.service -p LoadState -p FragmentPath -p Result
uname -r
"""
                sudo='sudo -n /bin/sh -c ' if provision else "printf '%s\\n' fixture-password | sudo -S /bin/sh -c "
                checked=guest_command(app,app_ns,ssh_fixture,user,sudo+shlex.quote(command))
                expected_fragment='FragmentPath=/run/systemd/generator/pxe-first-boot.service' if boot==1 else 'LoadState=not-found'
                if boot==1 and 'Result=success' not in checked.stdout:
                    raise RuntimeError('The first-boot unit did not report success')
                if checked.returncode or checked.stdout.splitlines()[:1] != ['1' if provision else '0'] or expected_fragment not in checked.stdout:
                    raise RuntimeError('Unexpected installed guest state: '+checked.stdout+checked.stderr)
                with sqlite3.connect(data/'chosen.sqlite') as db:
                    events=db.execute("SELECT checkpoint FROM machine_events WHERE action_id=? AND checkpoint IN "
                                      "('os_first_boot','os_first_boot_assumed','ansible_started','ansible_finished') ORDER BY id",
                                      (installation[0],)).fetchall()
                expected=[('os_first_boot',)]
                if provision:
                    expected.extend([('ansible_started',),('ansible_finished',)])
                if events!=expected:
                    raise RuntimeError('Unexpected provisioning checkpoints: '+str(events))
                print(f'{scenario} boot {boot}: {checked.stdout.strip()}',flush=True)
                if boot==1:
                    reboot='sudo -n systemctl reboot' if provision else "printf '%s\\n' fixture-password | sudo -S systemctl reboot"
                    guest_command(app,app_ns,ssh_fixture,user,reboot)
                    wait_for(lambda:not inspect(client)['State']['Running'],120,'isolated Debian reboot')
            print(docker('exec',app,'python3','-c',ui,'checklist',str(installation[0])).stdout.strip(),flush=True)
            print(f'OK {scenario}: PXE local boot, strict SSH, cleanup and one-time provisioning policy',flush=True)
            print('Only the disposable qcow2 disk and isolated bridge were used.',flush=True)
        except Exception:
            diagnostic_screen(root)
            if packaged and client_arch=='arm64':
                installer_log=installer_bootloader_log(dhcp)
                if installer_log:
                    installer_log=re.sub(r'https?://[^\s]+','[URL]',installer_log)
                    installer_log=re.sub(r'[A-Za-z0-9+/=]{100,}','[encoded]',installer_log)
                    print('ARM64 Debian Installer bootloader log:\n'+installer_log,flush=True)
            if packaged:
                with sqlite3.connect(data/'chosen.sqlite') as db:
                    for label, query in (
                        ('machine state', 'SELECT status,boot_arch,next_action FROM machines ORDER BY id LIMIT 4'),
                        ('UEFI boot sessions', 'SELECT default_menu,selected_menu FROM boot_sessions ORDER BY id DESC LIMIT 6'),
                        ('installation phases', 'SELECT phase_key,status FROM task_phases ORDER BY id DESC LIMIT 12'),
                    ):
                        print(f'{label}: {db.execute(query).fetchall()}',flush=True)
            if backend=='rust-docker':
                output=docker('logs','--tail','90',app,check=False)
                print((output.stdout+'\n'+output.stderr)[-6500:],flush=True)
            if rust_lab:
                status_log=fixture/'native-status.log'
                if status_log.is_file():
                    print(status_log.read_text()[-2000:],flush=True)
            for name, args in ((app, ('exec',app,'journalctl','--no-pager','-n','45','-u','pxe-tools-init','-u','pxe-tools-dnsmasq','-u','pxe-tools-pxe-http','-u','pxe-tools-worker')),
                               (dhcp, ('exec',dhcp,'cat','/tmp/fixture-dhcp.log')),
                               (client, ('logs',client)),
                               (mirror, ('logs','--tail','20',mirror))):
                result=docker(*args,check=False)
                diagnostic=result.stdout+'\n'+result.stderr
                if name==client and packaged:
                    evidence=re.findall(
                        r'^.*(?:EFI stub|RAMDISK|[Ii]nitrd|[Ii]nitramfs|Kernel command line|Kernel panic|partman|mdadm|(?:^|\s)error:).*$',
                        diagnostic,re.MULTILINE,
                    )
                    text='\n'.join(evidence)[-5000:]+'\n'+diagnostic[-3500:]
                else:
                    text=diagnostic[-3000:]
                text=re.sub(r'https?://[^\s]+','[URL]',text)
                text=re.sub(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])','[IPv4]',text)
                text=re.sub(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])','[MAC]',text)
                text=re.sub(r'[A-Za-z0-9+/=]{100,}','[encoded]',text)
                print('Fixture diagnostic ('+name.split('-')[2]+'):\n'+text,flush=True)
            raise
        finally:
            for name in names:docker('rm','-f',name,check=False)
            if backend=='rust-docker':
                docker('image','rm',image.replace('pxe-native-e2e-','pxe-uefi-e2e-'),check=False)


if __name__=='__main__':main()
