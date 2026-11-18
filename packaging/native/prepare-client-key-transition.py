#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Rehearse an APT client certificate replacement in a disposable fixture root.

This preparation is deliberately limited to fixture roots. It cannot modify
an actual client's APT configuration and is not a production migration tool.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    if spec is None or spec.loader is None:
        raise RuntimeError('required transition helper unavailable')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

uninstall = load('pxe_uninstall_for_transition', 'packaging/native/uninstall-apt.py')
inspector = load('pxe_key_inspector_for_transition', 'packaging/native/check-apt-key-transition.py')
KEY_RELATIVE = Path('etc/apt/keyrings/pxe-tools-archive-keyring.gpg')
CONFIG = {'SOURCE': '/etc/apt/sources.list', 'PARTS': '/etc/apt/sources.list.d',
          'TRUSTED': '/etc/apt/trusted.gpg', 'TRUSTEDPARTS': '/etc/apt/trusted.gpg.d', 'ROOT': ''}


def rehearse(root: Path, new_certificate: Path, old_release: Path, new_release: Path,
             primary: str, old_signer: str, new_signer: str, *, apply: bool = False) -> dict:
    if os.environ.get('PXE_APT_ROTATION_FIXTURE') != '1':
        raise ValueError('this preparation requires a disposable fixture')
    marker = root / '.pxe-rotation-fixture'
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or root.resolve().parent != Path('/tmp').resolve()
            or not root.name.startswith('pxe-rotation-client-')
            or root.stat().st_uid != os.getuid()
            or marker.is_symlink() or not marker.is_file()
            or marker.read_bytes() != b'PXE_TOOLS_ROTATION_DISPOSABLE\n'):
        raise ValueError('an explicitly marked disposable fixture root is required')
    key = root / KEY_RELATIVE
    # The existing uninstall guard proves the source and original key witness,
    # and rejects shared, redirected, symlinked or ambiguous configurations.
    if uninstall.apt_cleanup_plan(root, owner=None, apt_config=CONFIG) != (True, True):
        raise ValueError('source or key ownership and exclusive use are not established')
    report = inspector.inspect(key, new_certificate, primary, old_signer, new_signer)
    old_bytes = inspector.read_regular(key)
    new_bytes = inspector.read_regular(new_certificate)
    if hashlib.sha256(old_bytes).hexdigest() != report['old_certificate_sha256'] or \
       hashlib.sha256(new_bytes).hexdigest() != report['new_certificate_sha256']:
        raise ValueError('certificate changed after inspection')
    # Test both signers against the exact candidate bytes. This prevents a
    # certificate which cannot still authenticate the old index from being
    # installed during the overlap. These are fixture releases only.
    old_release_bytes = inspector.read_regular(old_release)
    new_release_bytes = inspector.read_regular(new_release)
    with tempfile.TemporaryDirectory(prefix='pxe-client-proof-', dir='/tmp') as temporary:
        proof_root = Path(temporary)
        old_cert_copy, new_cert_copy = proof_root / 'old.gpg', proof_root / 'new.gpg'
        old_index_copy, new_index_copy = proof_root / 'old.InRelease', proof_root / 'new.InRelease'
        for path, data in ((old_cert_copy, old_bytes), (new_cert_copy, new_bytes),
                           (old_index_copy, old_release_bytes), (new_index_copy, new_release_bytes)):
            path.write_bytes(data)
        inspector.proof.verify_signature(old_cert_copy, old_index_copy, old_signer.upper(), primary.upper())
        inspector.proof.verify_signature(new_cert_copy, old_index_copy, old_signer.upper(), primary.upper())
        inspector.proof.verify_signature(new_cert_copy, new_index_copy, new_signer.upper(), primary.upper())
    report['applied'] = False
    if not apply:
        return report
    # Keep the old hard-link witness untouched. An interrupted atomic rename
    # leaves either the old or new key at the same path; the new key is never
    # silently claimed as installer-owned by the old witness.
    directory = os.open(key.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.pxe-key-transition-' + secrets.token_hex(16)
    created = False
    try:
        if uninstall.apt_cleanup_plan(root, owner=None, apt_config=CONFIG) != (True, True):
            raise ValueError('source or key ownership changed before replacement')
        current = os.stat(key.name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or inspector.read_regular(key) != old_bytes:
            raise ValueError('installed key changed before replacement')
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                             dir_fd=directory)
        created = True
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(new_bytes)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        if uninstall.apt_cleanup_plan(root, owner=None, apt_config=CONFIG) != (True, True):
            raise ValueError('source or key ownership changed during staging')
        again = os.stat(key.name, dir_fd=directory, follow_symlinks=False)
        if (again.st_dev, again.st_ino) != (current.st_dev, current.st_ino) or inspector.read_regular(key) != old_bytes:
            raise ValueError('installed key changed during staging')
        os.replace(temporary, key.name, src_dir_fd=directory, dst_dir_fd=directory)
        created = False
        try:
            os.fsync(directory)
        except OSError as exc:
            raise RuntimeError('certificate was replaced but directory durability is uncertain; inspect before retrying') from exc
        report['applied'] = True
        return report
    finally:
        if created:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-root', required=True, type=Path)
    parser.add_argument('--new-certificate', required=True, type=Path)
    parser.add_argument('--old-inrelease', required=True, type=Path)
    parser.add_argument('--new-inrelease', required=True, type=Path)
    parser.add_argument('--primary-fingerprint', required=True)
    parser.add_argument('--old-signing-fingerprint', required=True)
    parser.add_argument('--new-signing-fingerprint', required=True)
    parser.add_argument('--apply-to-fixture', action='store_true')
    args = parser.parse_args()
    result = rehearse(args.fixture_root, args.new_certificate, args.old_inrelease, args.new_inrelease,
                      args.primary_fingerprint, args.old_signing_fingerprint, args.new_signing_fingerprint,
                      apply=args.apply_to_fixture)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(str(exc))
