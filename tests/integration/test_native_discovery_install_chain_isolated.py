#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Discover, schedule and install Debian through the native test package.

Only a fresh qcow2 disk is attached. A separately connected fixture mirror
exposes authenticated Debian files over a Unix socket, not a network bridge.
The test adds a serial console to observe the first boot of the installed OS.
"""
from __future__ import annotations

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

ROOT=Path(__file__).resolve().parents[2]
if os.environ.get('PXE_NATIVE_PXE_TEST') != '1' or os.geteuid() != 0:
    raise SystemExit('Run this test only as root on a dedicated disposable test VM.')
image=os.environ.get('PXE_NATIVE_PXE_IMAGE','')
if not re.fullmatch(r'pxe-native-e2e-[a-f0-9]{10}:local',image):
    raise SystemExit('A uniquely named local fixture image is required.')


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


def wait_for(predicate,timeout,description):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(1)
    raise RuntimeError('timed out: '+description)


def diagnostic_screen(root):
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
        if screen.stdout.strip():
            print('Isolated client screen:\n'+screen.stdout.strip()[-1500:], flush=True)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        pass


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
    return run('nsenter','-t',str(identity[0]),'-n',
               'ssh','-F','/dev/null','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
               '-o','HostKeyAlgorithms=ssh-ed25519',
               '-o','IdentitiesOnly=yes','-o','ConnectTimeout=3','-o','GlobalKnownHostsFile=/dev/null',
               '-o',f'UserKnownHostsFile={fixture/"known_hosts"}','-i',str(fixture/'client-key'),
               user+'@192.0.2.100',command,check=False,timeout=15)


def main():
    scenario = os.environ.get('PXE_NATIVE_PXE_SCENARIO','ansible')
    if scenario not in ('plain','ansible'):
        raise SystemExit('Choose the plain or ansible disposable fixture.')
    provision = scenario == 'ansible'
    suffix=secrets.token_hex(5)
    app='pxe-l2-app-'+suffix; dhcp='pxe-l2-dhcp-'+suffix; client='pxe-l2-client-'+suffix
    mirror='pxe-l2-mirror-'+suffix
    names=[client,dhcp,app,mirror]
    fixture_parent = os.environ.get('PXE_TEST_FIXTURE_PARENT', '/var/tmp')
    with tempfile.TemporaryDirectory(prefix='pxe-l2-fixture-',dir=fixture_parent) as temporary:
        root=Path(temporary); root.chmod(0o755)
        fixture=root/'fixture'; fixture.mkdir(mode=0o755)
        ssh_fixture=root/'ssh'; ssh_fixture.mkdir(mode=0o700)
        run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(ssh_fixture/'client-key'))
        client_pubkey=(ssh_fixture/'client-key.pub').read_text().strip()
        data,conf,http,tftp=(root/x for x in ('data','conf','http','tftp'))
        for directory in (data,conf,http,tftp):directory.mkdir(mode=0o755)
        (conf/'master.key').write_bytes(os.urandom(32));(conf/'master.key').chmod(0o600)
        (conf/'db.conf').write_text(json.dumps({'driver':'sqlite','path':'/var/lib/pxe-tools/chosen.sqlite'}))
        (conf/'db.conf').chmod(0o600)
        login_hash=docker('run','--rm','--network','none','--entrypoint','php',image,'-r',
                          'echo password_hash("fixture-login-password", PASSWORD_DEFAULT);').stdout
        with sqlite3.connect(data/'chosen.sqlite') as db:
            db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
            db.executemany('INSERT INTO settings(key,value) VALUES(?,?)',[
                ('pxe_enabled','on'),('pxe_ip','192.0.2.1'),('pxe_subnet','192.0.2.0/24'),('pxe_interface','br-pxetest'),
                ('dhcp_proxy_enabled','on'),('dhcp_proxy_network','192.0.2.0'),
                ('dhcp_proxy_netmask','255.255.255.0'),('https_enabled','off'),
                ('wizard_completed','1'),('db_init_done','1'),('admin_created','1'),('init_completed','1'),
                ('ansible_enabled','on' if provision else 'off'),('ansible_ssh_pubkey',client_pubkey),
                ('catalog_auto_refresh_enabled','off')])
            db.execute('INSERT INTO users(username,password_hash) VALUES(?,?)',('fixture-admin',login_hash))
            db.execute("INSERT INTO os_images(distro,version,arch,codename,version_full,enabled,status) VALUES('debian','13.0','amd64','trixie','13.0',1,'downloaded')")
        # A stale but valid DB must never drive the appliance, even when its
        # path is present in the inherited environment.
        with sqlite3.connect(data/'stale.sqlite') as db:
            db.executescript((ROOT/'app/db/schema.sqlite.sql').read_text())
            db.executemany('INSERT INTO settings(key,value) VALUES(?,?)', [
                ('pxe_subnet','198.51.100.0/24'), ('pxe_ip','198.51.100.1'),
                ('pxe_interface','fixture-stale'), ('fixture_marker','preserved')])
            db.execute("INSERT INTO machines(id,mac,hostname,status) VALUES(1,'02:00:00:00:00:01','stale-fixture','wiping')")
        netboot=http/'netboot/debian/13.0/amd64';netboot.mkdir(parents=True)
        instrument=(ROOT/'docker/worker/templates/preseed-base.cfg.j2').read_text()
        needle="{{ '{{ADMIN_USER_BLOCK}}' }}"
        if instrument.count(needle)!=1: raise RuntimeError('unexpected preseed template')
        serial=(" ; in-target /bin/sh -c 'printf \"\\nGRUB_CMDLINE_LINUX=\\\"console=tty0 console=ttyS0,115200n8\\\"\\n\" >> /etc/default/grub; update-grub' ; printf 'PXE_FULL_LATE_DONE\\n' >/dev/ttyS0")
        serial+=r""" ; printf 'PXE_HOST_PUBLIC ' >/dev/ttyS0 ; cat /target/etc/ssh/ssh_host_ed25519_key.pub >/dev/ttyS0 ; if [ -e /target/etc/systemd/system-generators/pxe-first-boot ]; then printf 'PXE_LAUNCHER ' >/dev/ttyS0; stat -c '%a' /target/etc/systemd/system-generators/pxe-first-boot >/dev/ttyS0; fi"""
        instrument=instrument.replace(needle,needle+serial)+"\nd-i mirror/udeb/suite string trixie\n"
        template=root/'preseed-base.cfg.j2';template.write_text(instrument)
        discovery=(ROOT/'docker/worker/templates/discovery-preseed.cfg.j2').read_text()
        discovery_needle='d-i mirror/http/hostname string deb.debian.org'
        if discovery.count(discovery_needle)!=1: raise RuntimeError('unexpected discovery mirror template')
        discovery=discovery.replace(discovery_needle,'d-i mirror/http/hostname string 192.0.2.1')
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
                   '-e','PXE_DISPOSABLE_APPLIANCE_MIRROR=1','--entrypoint','python3',image,
                   '/fixture-source/tests/integration/appliance_pxe_fixture_mirror.py')
            def mirror_ready():
                if not inspect(mirror)['State']['Running']: raise RuntimeError('fixture mirror stopped')
                return (fixture/'ready').exists()
            wait_for(mirror_ready,600,'authenticated fixture mirror')
            for item in ('linux','initrd.gz'):
                import shutil
                shutil.copyfile(fixture/item,netboot/item)
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
                docker('cp',str(source),app+':'+target)
            docker('exec',app,'sh','-c',
                   "install -d -m 0755 /var/lib/pxe-tools-native/rendered && "
                   "printf '%s\\n' TFTP_ROOT=/var/lib/pxe-tools-tftp HTTP_ROOT=/var/lib/pxe-tools-http "
                   "PXE_TOOLS_DATA_DIR=/var/lib/pxe-tools-native/rendered MOK_DIR=/var/lib/pxe-tools-native/mok "
                   "PXE_DB_PATH=/var/lib/pxe-tools/stale.sqlite WORKER_POLL_S=1 "
                   "'KERNEL_OPTS=\"language=fr country=FR locale=fr_FR.UTF-8 keymap=fr ipv6.disable=1 net.ifnames=0\"' "
                   "> /var/lib/pxe-tools-native/runtime.env")
            docker('run','-d','--name',dhcp,'--network','none','--cap-add','NET_ADMIN','--cap-add','NET_RAW',
                   '--entrypoint','/bin/sh',image,'-c','exec sleep 4200')
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
            docker('exec','-d',dhcp,'dnsmasq','-k','--port=0','--interface=veth-dhcp','--bind-interfaces',
                   '--dhcp-range=192.0.2.100,192.0.2.120,255.255.255.0,1h',
                   '--dhcp-host=02:00:00:00:00:01,192.0.2.100','--dhcp-option=6,192.0.2.1','--log-dhcp','--log-facility=/tmp/fixture-dhcp.log')
            if provision:
                prepare_playbook(app,ssh_fixture)
            docker('exec',app,'systemctl','start','pxe-tools.target')
            if provision:
                def module_ready():
                    with sqlite3.connect(data/'chosen.sqlite') as db:
                        row=db.execute("SELECT value FROM settings WHERE key='ansible_runtime_status'").fetchone()
                    return row is not None and json.loads(row[0]).get('state')=='ready'
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
                installation=db.execute('SELECT action_id,install_status FROM installations ORDER BY id DESC LIMIT 1').fetchone()
                machine=db.execute('SELECT status,local_boot_source FROM machines WHERE id=1').fetchone()
                receipt=db.execute("SELECT message FROM machine_events WHERE action_id=? AND message LIKE 'Empreinte SSH%'",
                                   (installation[0],)).fetchone()
                premature=db.execute("SELECT checkpoint FROM machine_events WHERE checkpoint IN ('os_first_boot','ansible_started')").fetchall()
            if installation[1]!='success' or machine!=('installed','pxe') or premature:
                raise RuntimeError('Unexpected installation or provisioning state before first boot')
            output=docker('logs',client).stdout
            public=re.search(r'PXE_HOST_PUBLIC (ssh-ed25519 [A-Za-z0-9+/=]+)',output)
            if public is None or ('PXE_LAUNCHER 700' in output)!=provision:
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
                def ssh_ready():
                    if not inspect(client)['State']['Running']:
                        raise RuntimeError('The installed guest stopped before reaching SSH')
                    attempt=guest_command(app,app_ns,ssh_fixture,user,'true')
                    if 'Host key verification failed' in attempt.stderr:
                        raise RuntimeError('The pinned installed guest key was refused')
                    return attempt.returncode==0
                wait_for(ssh_ready,600,'installed Debian reached strict SSH after network boot')
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
                expected_fragment='FragmentPath=/run/systemd/generator/pxe-first-boot.service' if provision and boot==1 else 'LoadState=not-found'
                if provision and boot==1 and 'Result=success' not in checked.stdout:
                    raise RuntimeError('The first-boot unit did not report success')
                if checked.returncode or checked.stdout.splitlines()[:1] != ['1' if provision else '0'] or expected_fragment not in checked.stdout:
                    raise RuntimeError('Unexpected installed guest state: '+checked.stdout+checked.stderr)
                with sqlite3.connect(data/'chosen.sqlite') as db:
                    events=db.execute("SELECT checkpoint FROM machine_events WHERE action_id=? AND checkpoint IN "
                                      "('os_first_boot','os_first_boot_assumed','ansible_started','ansible_finished') ORDER BY id",
                                      (installation[0],)).fetchall()
                expected=[('os_first_boot',),('ansible_started',),('ansible_finished',)] if provision else []
                if events!=expected:
                    raise RuntimeError('Unexpected provisioning checkpoints: '+str(events))
                print(f'{scenario} boot {boot}: {checked.stdout.strip()}',flush=True)
                if boot==1:
                    reboot='sudo -n systemctl reboot' if provision else "printf '%s\\n' fixture-password | sudo -S systemctl reboot"
                    guest_command(app,app_ns,ssh_fixture,user,reboot)
                    wait_for(lambda:not inspect(client)['State']['Running'],120,'isolated Debian reboot')
            print(f'OK {scenario}: PXE local boot, strict SSH, cleanup and one-time provisioning policy',flush=True)
            print('Only the disposable qcow2 disk and isolated bridge were used.',flush=True)
        except Exception:
            diagnostic_screen(root)
            for name, args in ((app, ('exec',app,'journalctl','--no-pager','-n','45','-u','pxe-tools-init','-u','pxe-tools-dnsmasq','-u','pxe-tools-pxe-http','-u','pxe-tools-worker')),
                               (dhcp, ('exec',dhcp,'cat','/tmp/fixture-dhcp.log')),
                               (client, ('logs','--tail','20',client)),
                               (mirror, ('logs','--tail','20',mirror))):
                result=docker(*args,check=False)
                text=(result.stdout+'\n'+result.stderr)[-3000:]
                text=re.sub(r'https?://[^\s]+','[URL]',text)
                text=re.sub(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])','[IPv4]',text)
                text=re.sub(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])','[MAC]',text)
                text=re.sub(r'[A-Za-z0-9+/=]{100,}','[encoded]',text)
                print('Fixture diagnostic ('+name.split('-')[2]+'):\n'+text,flush=True)
            raise
        finally:
            for name in names:docker('rm','-f',name,check=False)


if __name__=='__main__':main()
