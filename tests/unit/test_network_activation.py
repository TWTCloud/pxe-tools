#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Network activation on fresh, legacy, explicitly stopped and invalid instances."""
from contextlib import closing
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('network_activation', ROOT/'app/network_activation.py')
activation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(activation)

class NetworkActivationTests(unittest.TestCase):
    def test_fresh_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'missing.sqlite'
            self.assertFalse(activation.enabled(path))
            self.assertFalse(path.exists())

    def test_legacy_activation_and_explicit_choices(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'settings.sqlite'
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)')
            self.assertTrue(activation.enabled(path))
            for value, expected in [('off',False), ('on',True)]:
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', ('pxe_enabled',value))
                self.assertEqual(activation.enabled(path), expected)
            with closing(sqlite3.connect(path)) as db, db:
                db.execute("UPDATE settings SET value='unexpected'")
            with self.assertRaises(ValueError): activation.enabled(path)

    def test_unreadable_schema_is_not_a_legacy_activation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'empty.sqlite'
            path.touch()
            with self.assertRaises(sqlite3.Error): activation.enabled(path)

if __name__ == '__main__': unittest.main()
