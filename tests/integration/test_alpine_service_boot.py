#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Boot the packaged Alpine service with 1 GiB using hardware KVM only."""

import http.server
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import threading
import time


def main():
    if (os.environ.get('PXE_DISPOSABLE_ALPINE_BOOT') != '1'
            or not Path('/.dockerenv').is_file()
            or os.uname().machine != 'x86_64'
            or not Path('/dev/kvm').is_char_device()):
        raise SystemExit('AMD64 KVM in the disposable test container is required.')
    scripts = Path('/opt/pxe-tools/scripts')
    http_root = Path('/var/lib/pxe-tools-http')
    release = json.loads((scripts / 'alpine-release.json').read_text())
    base = f"netboot/alpine-service/{release['version']}/amd64"
    subprocess.run(['bash', str(scripts / 'bootstrap-generate-mok.sh')], check=True)
    subprocess.run(['python3', str(scripts / 'prepare-alpine-service.py'), '--arch', 'amd64'], check=True)

    class BootFiles(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=http_root, **kwargs)

    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), BootFiles) as server:
        owner = threading.Thread(target=server.serve_forever, daemon=True)
        owner.start()
        try:
            url = f'http://10.0.2.2:{server.server_port}/{base}'
            command = [
                'qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', '1', '-m', '1024',
                '-nodefaults', '-nographic', '-no-reboot', '-serial', 'stdio',
                '-netdev', 'user,id=service', '-device', 'virtio-net-pci,netdev=service,mac=02:00:00:48:01:01',
                '-kernel', str(http_root / base / 'linux'), '-initrd', str(http_root / base / 'initrd.gz'),
                '-append', (f"ip=dhcp alpine_repo=https://dl-cdn.alpinelinux.org/alpine/{release['branch']}/main "
                            f"modloop={url}/modloop apkovl={url}/service.apkovl.tar.gz "
                            "pxe_server=10.0.2.2 pxe_service=rescue BOOTIF=01-02-00-00-48-01-01 console=ttyS0,115200n8"),
            ]
            check_console(command)
        finally:
            server.shutdown()
            owner.join()


def check_console(command):
    pattern = re.compile(rb'PXE_ALPINE_SERVICE_READY mode=rescue available_kib=([0-9]+)')
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, start_new_session=True) as guest:
        output = b''
        with selectors.DefaultSelector() as console:
            console.register(guest.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 360
            try:
                while time.monotonic() < deadline:
                    if not console.select(timeout=2):
                        continue
                    block = os.read(guest.stdout.fileno(), 16384)
                    if not block:
                        break
                    print(block.decode(errors='replace'), end='', flush=True)
                    output = (output + block)[-32768:]
                    if match := pattern.search(output):
                        available = int(match[1])
                        if available < 65536:
                            raise RuntimeError(f'Alpine left only {available} KiB available on the 1 GiB guest')
                        print(f'Alpine rescue ready with 1024 MiB under KVM; {available} KiB available.')
                        return
            finally:
                guest.terminate()
                try:
                    guest.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    guest.kill()
        raise RuntimeError('Alpine rescue did not complete boot on the 1 GiB guest.')


if __name__ == '__main__':
    main()
