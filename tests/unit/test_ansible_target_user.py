"""The worker connects with the configured technical account and refuses an invalid one."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'app'))
import worker


class AnsibleTargetUser(unittest.TestCase):
    def test_default_and_configured_names(self):
        with patch.object(worker, 'db_setting', side_effect=lambda key, default='': default):
            self.assertEqual(worker.ansible_target_user(), 'ansible')
        for configured in ('automation', ' automation ', '_svc', 'deploy-01'):
            with self.subTest(configured=configured), patch.object(worker, 'db_setting', return_value=configured):
                self.assertEqual(worker.ansible_target_user(), configured.strip())

    def test_invalid_names_are_refused(self):
        for configured in ('root', 'Automation', '1user', 'a b', 'a;id', 'a' * 33):
            with self.subTest(configured=configured), patch.object(worker, 'db_setting', return_value=configured):
                self.assertIsNone(worker.ansible_target_user())

    def test_ssh_uses_configured_account(self):
        done = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(worker, 'db_setting', return_value='automation'), \
             patch.object(worker.subprocess, 'run', return_value=done) as run:
            self.assertEqual(worker._ssh_systemctl('192.0.2.10', 'poweroff'), (True, None))
        self.assertIn('automation@192.0.2.10', run.call_args.args[0])

    def test_ssh_refuses_invalid_account_without_connecting(self):
        with patch.object(worker, 'db_setting', return_value='root'), \
             patch.object(worker.subprocess, 'run') as run:
            ok, reason = worker._ssh_reboot('192.0.2.10')
        self.assertFalse(ok)
        self.assertIn('compte technique', reason)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
