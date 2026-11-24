#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Read the latest Windows Setup messages from a powered-off fixture disk."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

import nbd
import pytsk3


class ReadOnlyDisk(pytsk3.Img_Info):
    def __init__(self, handle):
        self.handle = handle
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        pass

    def get_size(self):
        return self.handle.get_size()

    def read(self, offset, size):
        return self.handle.pread(size, offset)


def report(disk):
    # DiskPart in install-fixture.ps1 creates the 1 MiB alignment gap, the
    # 260 MiB ESP, and the 16 MiB MSR before the NTFS system partition.
    ntfs = pytsk3.FS_Info(disk, offset=277 * 1024 * 1024)
    for name in ('setuperr.log', 'setupact.log'):
        try:
            log = ntfs.open(f'/Windows/Panther/{name}')
        except OSError:
            print(f'Windows Setup diagnostic {name} is unavailable.')
            continue
        size = log.info.meta.size
        start = max(0, size - 32768)
        if not size:
            print(f'Windows Setup diagnostic {name} is empty.')
            continue
        data = log.read_random(start, size - start)
        encoding = 'utf-16le' if b'\x00' in data[:64] else 'utf-8-sig'
        if encoding == 'utf-16le' and start % 2:
            data = data[1:]
        lines = data.decode(encoding, errors='replace').splitlines()
        print(f'Windows Setup diagnostic {name} ({size} bytes):')
        for line in lines[-24:]:
            line = re.sub(r'\b(?:[A-Z0-9]{5}-){4}[A-Z0-9]{5}\b', '[redacted]', line, flags=re.I)
            print(''.join(char for char in line[:512] if char.isprintable()))


def main(image):
    with tempfile.TemporaryDirectory(prefix='pxe-setup-diag-') as directory:
        socket = Path(directory)/'disk.sock'
        with subprocess.Popen(['qemu-nbd', '--read-only', '--format=qcow2',
                               '--socket', str(socket), str(image)]) as server:
            try:
                deadline = time.monotonic() + 10
                while not socket.is_socket():
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('The read-only diagnostic disk could not be opened.')
                    time.sleep(.1)
                handle = nbd.NBD()
                handle.connect_unix(str(socket))
                try:
                    report(ReadOnlyDisk(handle))
                finally:
                    handle.shutdown()
            finally:
                if server.poll() is None:
                    server.terminate()


if __name__ == '__main__':
    try:
        main(Path(sys.argv[1]))
    except (RuntimeError, OSError, nbd.Error) as error:
        raise SystemExit(f'Windows Setup diagnostics unavailable: {error}') from error
