#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Display the local initial setup instructions for the native package."""

import argparse
import http.client
from ipaddress import IPv4Address
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys


SERVICE = 'pxe-tools-pxe-http.service'
SETUP_CODE = Path('/run/pxe-tools-rust-guided/setup-code')
SETUP_ROUTES = {'/init/welcome', '/init/admin'}


def listeners():
    pid = subprocess.check_output(
        ['/usr/bin/systemctl', 'show', '--property=MainPID', '--value', SERVICE],
        text=True, timeout=5,
    ).strip()
    if not re.fullmatch(r'[1-9][0-9]*', pid):
        raise RuntimeError(f'La console PXE Tools est arrêtée. Vérifiez systemctl status {SERVICE}.')

    output = subprocess.check_output(
        ['/usr/bin/ss', '-H', '-ltnp', '-4'], text=True, timeout=5,
    )
    owned = re.compile(r'\bpid=' + pid + r'[,)]')
    sockets = set()
    for line in output.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6 or not owned.search(fields[5]):
            continue
        address, _, port = fields[3].rpartition(':')
        if address in ('*', '0.0.0.0'):
            continue  # The native Rust server binds explicit IPv4 addresses.
        sockets.add((IPv4Address(address), int(port)))
    return sorted(sockets)


def setup_route(address, port):
    # The listener is owned by the local service. First-run instances can
    # use self-signed TLS. The probe sends neither a setup code nor a login.
    connection = http.client.HTTPSConnection(
        str(address), port, timeout=3, context=ssl._create_unverified_context(),
    )
    try:
        connection.request('HEAD', '/admin/')
        response = connection.getresponse()
        if response.status == 302:
            route = response.getheader('Location')
            if route in SETUP_ROUTES or route == '/init':
                return route
            if route in ('/admin/devices', '/login') or (route and route.startswith('/login?')):
                return '/admin/'
        if response.status in (200, 401):
            return '/admin/'
    except (OSError, http.client.HTTPException):
        pass  # The service also owns the plain HTTP PXE listener.
    finally:
        connection.close()
    return None


def show_setup():
    endpoints = []
    for address, port in listeners():
        if route := setup_route(address, port):
            authority = str(address) if port == 443 else f'{address}:{port}'
            endpoints.append((address, route, f'https://{authority}{route}'))
    if not endpoints:
        raise RuntimeError(f'La console HTTPS est indisponible. Vérifiez systemctl status {SERVICE}.')

    pending = [endpoint for endpoint in endpoints if endpoint[1] in SETUP_ROUTES]
    resetting = [endpoint for endpoint in endpoints if endpoint[1] == '/init']
    choices = pending or resetting or endpoints
    code = None
    if pending:
        try:
            code = SETUP_CODE.read_text(encoding='ascii').strip()
        except (OSError, UnicodeError):
            raise RuntimeError('Le code de configuration est indisponible.') from None
        if not re.fullmatch(r'[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{4}){2}|[0-9a-fA-F]{12}|[0-9a-fA-F]{48}', code):
            raise RuntimeError('Le code de configuration est invalide.')

    if pending:
        print('Configuration initiale')
    elif resetting:
        print('Réinitialisation en cours')
    else:
        print('Le compte initial est déjà configuré. Ouvrez la console HTTPS.')
    for _, _, url in [endpoint for endpoint in choices if not endpoint[0].is_loopback] or choices:
        print(f'  {url}')
    if code is not None:
        print(f'Code de configuration\n  {code}')


def main():
    parser = argparse.ArgumentParser(prog='pxe-tools', description='Administration locale de PXE Tools')
    parser.add_argument('commande', choices=['setup'], help='affiche le lien et le code de configuration')
    parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'Exécutez sudo pxe-tools setup sur le serveur.\n')
    try:
        show_setup()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
