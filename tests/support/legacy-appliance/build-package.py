#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Build the historical package only for isolated compatibility tests."""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), default='amd64')
    parser.add_argument('--maintainer', default='PXE Tools fixture <fixture@example.invalid>')
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location('pxe_fixture_builder', root / 'packaging/native/build-local-package.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.build(args.destination, args.version, package_name='pxe-tools',
                  architecture=args.architecture, maintainer=args.maintainer)


if __name__ == '__main__':
    main()
