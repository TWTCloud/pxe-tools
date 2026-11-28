#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Boot the packaged Alpine service with 1 GiB using hardware KVM only."""

import http.server
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import re
import selectors
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

MAC = '02:00:00:48:01:01'
SERIAL = 'ALPINE-DISPOSABLE'
PEER = '192.0.2.100'
SERVER = '10.0.2.2'
BOOTIF = '01-02-00-00-48-01-01'
SCRIPTS = Path('/opt/pxe-tools/scripts')
HTTP_ROOT = Path('/var/lib/pxe-tools-http')
SCHEMA = Path('/usr/lib/pxe-tools/app/db/schema.sqlite.sql')
BINARY = '/usr/lib/pxe-tools/pxe-tools-rust'


class FixtureAPI(HTTPConnection):
    def __init__(self, address):
        super().__init__('localhost', timeout=10)
        self.address = address

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.address))


def request(address, method, route, body=None, headers=None, peer=PEER):
    client = FixtureAPI(address)
    try:
        client.request(method, route, body=body, headers={
            **(headers or {}), 'X-Pxe-Client-Ip': peer,
        })
        response = client.getresponse()
        return response.status, response.getheader('Content-Type'), response.read(1_048_577)
    finally:
        client.close()


def seed_operation(db, mode):
    identity = {'kind': 'serial', 'value': SERIAL, 'source': 'sysfs', 'status': 'valid'}
    with sqlite3.connect(db) as conn:
        machine, = conn.execute('SELECT id FROM machines WHERE mac=?', [MAC]).fetchone()
        if mode == 'disktest':
            conn.execute("UPDATE machines SET status='testing' WHERE id=?", [machine])
            action = conn.execute(
                "INSERT INTO actions(machine_id,type,status,token) VALUES (?,'disktest','pending',?)",
                [machine, '1' * 64],
            ).lastrowid
            conn.execute("INSERT INTO disk_tests(machine_id,action_id,jobs_json,post_action) VALUES(?,?,?,'poweroff')",
                         [machine, action, json.dumps([{'disk':'/dev/vda', 'mode':'badblocks_quick_ro',
                                                       'identity':identity}])])
        elif mode == 'wipe':
            conn.execute("UPDATE machines SET status='wiping' WHERE id=?", [machine])
            action = conn.execute(
                "INSERT INTO actions(machine_id,type,status,token) VALUES (?,'wipe_only','pending',?)",
                [machine, '2' * 64],
            ).lastrowid
            conn.execute("INSERT INTO wipes(machine_id,action_id,disks_json,wipe_mode,post_action) "
                         "VALUES(?,?,?,'partial','poweroff')",
                         [machine, action, json.dumps([{'name':'/dev/vda', 'mode':'partial',
                                                       'identity':identity}])])


def verify_operation(db, mode):
    with sqlite3.connect(db) as conn:
        if mode == 'discovery':
            row = conn.execute('SELECT inventory_json,boot_arch FROM machines WHERE mac=?', [MAC]).fetchone()
            if not row or not row[0]:
                return False
            assert row[1] == 'amd64' and SERIAL in row[0], row[1]
            conn.execute("UPDATE machines SET next_action='poweroff' WHERE mac=?", [MAC])
            return True
        if mode == 'disktest':
            status, = conn.execute('SELECT job_status FROM disk_tests').fetchone()
        else:
            status, = conn.execute('SELECT wipe_status FROM wipes').fetchone()
        if status == 'failed':
            raise RuntimeError(f'Alpine {mode} reported failure.')
        return status == 'success'


def main():
    if (os.environ.get('PXE_DISPOSABLE_ALPINE_BOOT') != '1'
            or not Path('/.dockerenv').is_file()
            or os.uname().machine != 'x86_64'
            or not Path('/dev/kvm').is_char_device()):
        raise SystemExit('AMD64 KVM in the disposable test container is required.')
    release = json.loads((SCRIPTS / 'alpine-release.json').read_text())
    base = f"netboot/alpine-service/{release['version']}/amd64"
    subprocess.run(['bash', str(SCRIPTS / 'bootstrap-generate-mok.sh')], check=True)
    subprocess.run(['python3', str(SCRIPTS / 'prepare-alpine-service.py'), '--arch', 'amd64'], check=True)
    subprocess.run(['systemctl', 'stop', 'pxe-tools-worker.service', 'pxe-tools-pxe-http.service'], check=True)
    with tempfile.TemporaryDirectory(prefix='pxe-alpine-test-', dir='/var/tmp') as temp:
        root = Path(temp)
        db, address, disk = root/'fixture.sqlite', root/'pxe.sock', root/'disk.raw'
        with sqlite3.connect(db) as conn:
            conn.executescript(SCHEMA.read_text())
            conn.executemany('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)', [
                ('pxe_ip', SERVER), ('pxe_subnet', '192.0.2.0/24'), ('pxe_enabled', 'on'),
            ])
        with disk.open('xb') as raw:
            raw.truncate(64 * 1024**2)
            raw.write(b'ALPINE-DISPOSABLE-DISK')
        for script in ('discover.sh', 'disktest.sh'):
            subprocess.run(['python3', str(SCRIPTS/'render_template.py'),
                            f'/opt/pxe-tools/templates/{script}.j2', str(root/script)], check=True,
                           env=dict(os.environ, PXE_PROFILE_ADDRESS=SERVER))
        with subprocess.Popen([BINARY, str(db), str(address)]) as api:
            try:
                deadline = time.monotonic() + 5
                while not address.is_socket() and api.poll() is None and time.monotonic() < deadline:
                    time.sleep(.1)
                if not address.is_socket():
                    raise RuntimeError('The packaged Rust fixture did not open its private socket.')
                run_modes(root, db, address, disk, base, release['branch'])
            finally:
                api.terminate()


def run_modes(root, db, address, disk, base, branch):
    class BootFiles(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=HTTP_ROOT, **kwargs)

        def do_GET(self):
            path = self.path.split('?', 1)[0]
            if path in ('/discover.sh', '/disktest.sh'):
                data = (root/path[1:]).read_bytes()
                self.send_response(200)
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
            elif path.startswith('/api/') or path == '/wipe.sh':
                self.forward()
            else:
                super().do_GET()

        def do_POST(self):
            self.forward()

        def forward(self):
            if not (self.path.startswith('/api/') or self.path.startswith('/wipe.sh?')):
                self.send_error(404)
                return
            length = int(self.headers.get('Content-Length', 0))
            if not 0 <= length <= 1_048_576:
                self.send_error(413)
                return
            body = self.rfile.read(length) if length else None
            headers = {key: self.headers[key] for key in ('Authorization', 'Content-Type')
                       if key in self.headers}
            status, kind, data = request(address, self.command, self.path, body, headers)
            self.send_response(status)
            if kind:
                self.send_header('Content-Type', kind)
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)

    with http.server.ThreadingHTTPServer(('127.0.0.1', 80), BootFiles) as server:
        owner = threading.Thread(target=server.serve_forever, daemon=True)
        owner.start()
        try:
            url = f'http://{SERVER}/{base}'
            for mode in ('rescue', 'discovery', 'disktest', 'wipe'):
                if mode in ('disktest', 'wipe'):
                    seed_operation(db, mode)
                    status, _, _ = request(address, 'POST',
                        f'/api/internal/dhcp-event?mac={MAC}&ip={PEER}', peer='127.0.0.1')
                    assert status == 200
                command = [
                    'qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', '1', '-m', '1024',
                    '-nodefaults', '-nographic', '-no-reboot', '-serial', 'stdio',
                    '-netdev', 'user,id=service', '-device', f'virtio-net-pci,netdev=service,mac={MAC}',
                    '-drive', f'file={disk},if=none,id=testdisk,format=raw',
                    '-device', f'virtio-blk-pci,drive=testdisk,serial={SERIAL}',
                    '-kernel', str(HTTP_ROOT / base / 'linux'), '-initrd', str(HTTP_ROOT / base / 'initrd.gz'),
                    '-append', (f"ip=dhcp modules=loop,squashfs,virtio_blk "
                                f"alpine_repo=https://dl-cdn.alpinelinux.org/alpine/{branch}/main "
                                f"modloop={url}/modloop apkovl={url}/service.apkovl.tar.gz "
                                f"pxe_server={SERVER} pxe_service={mode} BOOTIF={BOOTIF} console=ttyS0,115200n8"),
                ]
                check_console(command, mode, db)
                with disk.open('rb') as raw:
                    prefix = raw.read(len(b'ALPINE-DISPOSABLE-DISK'))
                    assert prefix == (b'\0'*len(prefix) if mode == 'wipe' else b'ALPINE-DISPOSABLE-DISK')
        finally:
            server.shutdown()
            owner.join()


def check_console(command, mode, db):
    pattern = re.compile(fr'PXE_ALPINE_SERVICE_READY mode={mode} available_kib=([0-9]+)\r*\n'.encode())
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, start_new_session=True) as guest:
        output = b''
        with selectors.DefaultSelector() as console:
            console.register(guest.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 240
            available = None
            try:
                while time.monotonic() < deadline:
                    if console.select(timeout=2):
                        block = os.read(guest.stdout.fileno(), 16384)
                        if not block:
                            break
                        print(block.decode(errors='replace'), end='', flush=True)
                        output = (output + block)[-32768:]
                    if available is None and (match := pattern.search(output)):
                        available = int(match[1])
                        if available < 65536:
                            raise RuntimeError(f'Alpine left only {available} KiB available on the 1 GiB guest')
                        if mode == 'rescue':
                            guest.stdin.write(b"printf '\\nPXE-RESCUE-SHELL-%s\\n' \"$(id -u)\"; poweroff -f\n")
                            guest.stdin.flush()
                    if available is not None:
                        completed = (re.search(rb'^PXE-RESCUE-SHELL-0\r*$', output, re.M)
                                     if mode == 'rescue' else verify_operation(db, mode))
                        if completed:
                            print(f'Alpine {mode} verified with 1024 MiB under KVM; {available} KiB available.')
                            if mode != 'rescue':
                                guest.wait(timeout=30)
                            return
            finally:
                guest.terminate()
                try:
                    guest.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    guest.kill()
        raise RuntimeError(f'Alpine {mode} did not complete on the 1 GiB guest.')


if __name__ == '__main__':
    main()
