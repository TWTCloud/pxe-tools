# SPDX-License-Identifier: LGPL-3.0-only
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[2] / 'packaging/native/configure-secure-tftp.py'
spec = importlib.util.spec_from_file_location('configure_secure_tftp', path)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


@unittest.skipUnless(os.geteuid() == 0 and Path('/root').is_dir(), 'requires a root-owned Linux fixture')
class ConfigureSecureRuntime(unittest.TestCase):
    def test_initial_creation_respects_mode_and_never_overwrites(self):
        with tempfile.TemporaryDirectory(prefix='pxe-runtime-test-', dir='/root') as temporary:
            base = Path(temporary)
            old_umask = os.umask(0o077)
            try:
                setup.prepare(base)
            finally:
                os.umask(old_umask)
            marker = base / setup.RUNTIME / 'runtime.env'
            self.assertEqual(marker.read_bytes(), setup.MARKER)
            self.assertEqual((base / setup.TFTP).stat().st_mode & 0o777, 0o755)
            self.assertEqual((base / setup.HTTP).stat().st_mode & 0o777, 0o755)
            self.assertEqual((base / setup.RUNTIME / 'rendered').stat().st_mode & 0o777, 0o755)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o644)
            network = base / setup.RUNTIME / 'network.env'
            self.assertEqual(network.read_bytes(), b'')
            self.assertEqual(network.stat().st_mode & 0o777, 0o644)
            with self.assertRaises(FileExistsError):
                setup.prepare(base)
            self.assertEqual(marker.read_bytes(), setup.MARKER)

    def test_refuses_existing_tftp_or_symlink_parent_without_changes(self):
        with tempfile.TemporaryDirectory(prefix='pxe-runtime-test-', dir='/root') as temporary:
            base = Path(temporary)
            (base / setup.TFTP).mkdir()
            witness = base / setup.TFTP / 'witness'; witness.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                setup.prepare(base)
            self.assertEqual(witness.read_bytes(), b'keep')
            self.assertFalse((base / setup.RUNTIME).exists())
            link = base / 'link'; link.symlink_to(base / setup.TFTP)
            with self.assertRaises(OSError):
                setup.prepare(link)
            self.assertEqual(witness.read_bytes(), b'keep')

    def test_resume_with_real_generation_proofs(self):
        helper = path.with_name('ownership-provenance.py')
        spec = importlib.util.spec_from_file_location('real_resume_ownership', helper)
        ownership = importlib.util.module_from_spec(spec); spec.loader.exec_module(ownership)
        with tempfile.TemporaryDirectory(prefix='pxe-runtime-resume-', dir='/root') as temporary:
            root = Path(temporary)
            for part in ('etc', 'var/lib', 'var/log', 'run/lock'):
                (root/part).mkdir(parents=True, exist_ok=True)
            (root/'var/log').chmod(0o775)
            store = ownership.Store(root)
            setup.prepare(base=root/'var/lib', root=root, journal=store)
            record = store.read()
            if any(proof['nonce'] is None for proof in record['directories'].values()):
                self.skipTest('strong generation proofs unavailable on fixture filesystem')
            (root/'var/lib/pxe-tools-http').rmdir()
            (root/'var/lib/pxe-tools-tftp').rmdir()
            self.assertEqual(set(store.resume_missing_runtime()),
                             {'/var/lib/pxe-tools-http', '/var/lib/pxe-tools-tftp'})
            store.create_base(require_runtime=True, activate=lambda: None)
            self.assertEqual(store.read()['base_phase'], 'complete')


if __name__ == '__main__':
    unittest.main()
