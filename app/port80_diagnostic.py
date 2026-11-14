#!/usr/bin/env python3
"""Read-only HTTP boot diagnosis. No service changes and no privileged helper."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys


def socket_rows(proc=Path('/proc')):
    rows = []
    for family, table in ((4, 'tcp'), (6, 'tcp6')):
        for line in (proc / 'net' / table).read_text(encoding='ascii').splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError('incomplete socket table')
            raw, port = fields[1].split(':')
            if fields[3] != '0A' or port != '0050':
                continue
            if family == 4:
                address = socket.inet_ntop(socket.AF_INET, struct.pack('<I', int(raw, 16)))
            else:
                packed = b''.join(struct.pack('<I', int(raw[n:n + 8], 16)) for n in range(0, 32, 8))
                address = socket.inet_ntop(socket.AF_INET6, packed)
            rows.append({'family': family, 'address': address, 'inode': fields[9]})
    return sorted(rows, key=lambda row: (row['family'], row['address'], row['inode']))


def relevant(row, addresses):
    if row['family'] == 4:
        return row['address'] == '0.0.0.0' or row['address'] in addresses
    # A socket's IPV6_V6ONLY flag cannot be inferred from the system default.
    address = ipaddress.IPv6Address(row['address'])
    return address.is_unspecified or (address.ipv4_mapped is not None and str(address.ipv4_mapped) in addresses)


def owners(rows, proc=Path('/proc')):
    wanted = {row['inode'] for row in rows}
    found = {inode: [] for inode in wanted}
    for directory in proc.iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            descriptors = list((directory / 'fd').iterdir())
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
                if not target.startswith('socket:[') or target[8:-1] not in wanted:
                    continue
                groups = (directory / 'cgroup').read_text().splitlines()
                units = [line.split(':', 2)[-1] for line in groups]
                exe = os.readlink(directory / 'exe')
                found[target[8:-1]].append({'pid': directory.name, 'exe': exe, 'groups': units})
            except (OSError, ValueError):
                continue
    return found


def health(address):
    connection = http.client.HTTPConnection(address, 80, timeout=.6)
    try:
        connection.request('GET', '/healthz', headers={'Host': address, 'Connection': 'close'})
        response = connection.getresponse()
        if response.status != 200 or response.read(16) != b'ok\n':
            return False
        return 'expected' if response.getheader('X-PXE-Tools-HTTP') == '1' else 'compatible'
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def snapshot_fingerprint(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def process_start(pid, proc=Path('/proc')):
    stat = (proc / str(pid) / 'stat').read_text()
    return stat[stat.rindex(') ') + 2:].split()[19]


def diagnose(address, *, proc=Path('/proc'), probe=health, wildcard=False):
    result = {'state': 'unknown', 'address': address, 'can_stop': False, 'service': None, 'listeners': []}
    try:
        parsed = ipaddress.IPv4Address(address)
        if parsed.is_unspecified or parsed.is_loopback or parsed.is_multicast:
            return dict(result, state='not_configured')
        targets = [str(parsed), '127.0.0.1']
        rows = socket_rows(proc)
        selected = rows if wildcard else [row for row in rows if relevant(row, targets)]
        result['listeners'] = [{'address': row['address'], 'family': row['family']} for row in selected]
        if not selected:
            return dict(result, state='free')
        responses = [probe(target) for target in targets]
        if all(response is True or response == 'expected' for response in responses):
            return dict(result, state='ready')
        if 'compatible' in responses:
            # Older/shared PXE nginx may serve the health endpoint without the
            # current signature. This is not proof of a competing service.
            return result
        known = owners(selected, proc)
        if any(not known.get(row['inode']) for row in selected):
            return result
        all_owners = [owner for group in known.values() for owner in group]
        expected = lambda owner: any(group.endswith('/pxe-tools-pxe-http.service') for group in owner['groups'])
        if all(expected(owner) for owner in all_owners):
            return dict(result, state='starting')
        # IPv6 wildcard alone does not prove a collision with the IPv4 bind.
        confirmed_ipv4 = [row for row in selected if row['family'] == 4 and any(not expected(owner) for owner in known[row['inode']])]
        if not confirmed_ipv4:
            return result
        result['state'] = 'conflict'
        services = sorted({group.rsplit('/', 1)[-1] for owner in all_owners for group in owner['groups'] if group.endswith('.service')})
        result['service'] = ', '.join(services) or None
        only_nginx = all(owner['exe'] == '/usr/sbin/nginx' and any(group.endswith('/nginx.service') for group in owner['groups']) for owner in all_owners)
        if only_nginx:
            pid = (proc.parent / 'run' / 'nginx.pid').read_text().strip() if proc != Path('/proc') else Path('/run/nginx.pid').read_text().strip()
            if not pid.isdecimal() or not any(owner['pid'] == pid for owner in all_owners):
                return result
            result.update(can_stop=True, service='nginx.service', pid=pid, start=process_start(pid, proc),
                          boot=(proc / 'sys/kernel/random/boot_id').read_text().strip(), fingerprint=snapshot_fingerprint(rows))
        return result
    except (OSError, ValueError, IndexError):
        return result


if __name__ == '__main__':
    print(json.dumps(diagnose(sys.argv[1] if len(sys.argv) >= 2 else '', wildcard=len(sys.argv) == 3 and sys.argv[2] == 's6')))
