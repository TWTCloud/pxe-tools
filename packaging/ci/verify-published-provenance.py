#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Allow renewal after the original build artifact expires, using signed provenance."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile

here=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('pxe_apt_proof',here/'apt-proof.py')
if spec is None or spec.loader is None:raise RuntimeError('APT proof verifier unavailable')
publisher=importlib.util.module_from_spec(spec);spec.loader.exec_module(publisher)


def verify(inrelease: Path, keyring: Path, manifest: dict, primary: str, signing: str,
           packages: Path | None = None, arm64_packages: Path | None = None) -> None:
    # The signed previous metadata may have expired: it is used only as proof
    # of an earlier publication, not accepted as a currently usable APT index.
    publisher.validate_keyring(keyring,primary,signing)
    with tempfile.TemporaryDirectory(prefix='pxe-prior-proof-') as tmp:
        clear=Path(tmp)/'Release'
        publisher.verify_signature(keyring,inrelease,signing,primary,output=clear)
        release=clear.read_bytes()
        module = ((manifest['ansible_version'], manifest['ansible_package_sha256'])
                  if 'ansible_version' in manifest else None)
        arm64_sha = manifest.get('arm64_package_sha256')
        publisher.verify_provenance(release,manifest['version'],manifest['package_sha256'],
                                    manifest['source_commit'],manifest['build_run_id'],module,arm64_sha)
        lines=release.decode('utf-8').splitlines()
        architectures = ['amd64'] + (['arm64'] if arm64_sha is not None else [])
        if [line for line in lines if line.startswith('Architectures:')] != ['Architectures: ' + ' '.join(architectures)]:
            raise ValueError('Previous signed index has unexpected architectures')
        try: offset=lines.index('SHA512:')+1
        except ValueError as exc:raise ValueError('Previous signed index has no SHA512') from exc
        indexes = {}
        for line in lines[offset:]:
            if not line.startswith(' '):break
            parts=line.split()
            if len(parts)!=3:raise ValueError('Malformed prior SHA512 section')
            if parts[2] in indexes:
                raise ValueError('Duplicate prior SHA512 entry')
            indexes[parts[2]] = parts[:2]
        for architecture, expected_sha, index_file in (
                ('amd64', manifest['package_sha256'], packages), ('arm64', arm64_sha, arm64_packages)):
            if expected_sha is None:
                if index_file is not None:
                    raise ValueError('Unexpected prior arm64 index')
                continue
            relative = f'main/binary-{architecture}'
            expected, size = indexes.get(f'{relative}/Packages', ('', '-1'))
            if not re.fullmatch(r'[a-f0-9]{128}', expected):
                raise ValueError('Prior signed package index is missing')
            size = int(size)
            if not 0 < size <= 16*1024*1024:
                raise ValueError('Prior package index has an invalid size')
            if index_file is None:
                index_file=Path(tmp)/f'Packages-{architecture}'
                url=f'https://packages.pxetools.com/apt/dists/stable/{relative}/by-hash/SHA512/{expected}'
                r=subprocess.run(['curl','--proto','=https','--silent','--show-error','--fail',
                    '--max-time','60','--max-filesize',str(size),'--user-agent','curl/8.14.1',
                    '--output',str(index_file),'--write-out','%{http_code}',url],capture_output=True)
                if r.returncode or r.stdout != b'200':raise ValueError('Prior public by-hash index unavailable')
            data=index_file.read_bytes()
            if len(data)!=size or hashlib.sha512(data).hexdigest()!=expected:
                raise ValueError('Prior package index differs from signed hash')
            version,sha=publisher.package_identity({f'dists/stable/{relative}/Packages':data}, module, architecture)
            if (version,sha)!=(manifest['version'],expected_sha):
                raise ValueError('Prior signed index does not contain the approved package')


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inrelease',type=Path,required=True);p.add_argument('--keyring',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--primary-fingerprint',required=True)
    p.add_argument('--signing-fingerprint',required=True);p.add_argument('--packages',type=Path)
    p.add_argument('--arm64-packages',type=Path)
    args=p.parse_args()
    verify(args.inrelease,args.keyring,json.loads(args.manifest.read_text()),
           args.primary_fingerprint,args.signing_fingerprint,args.packages,args.arm64_packages)
    print('Previously published signed provenance matches the approved build and package.')


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,UnicodeError) as exc:raise SystemExit(str(exc))
