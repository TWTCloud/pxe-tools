#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Read the explicit boot-network switch without creating a database.

Old configured databases lacking the key retain their behaviour. A fresh
instance has no database and must keep the boot network off.
"""
from contextlib import closing
from pathlib import Path
import sqlite3
import sys


def enabled(database):
    path = Path(database)
    if not path.exists():
        return False
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        rows = db.execute("SELECT value FROM settings WHERE key='pxe_enabled'").fetchall()
    if not rows:
        return True
    if len(rows) != 1 or rows[0][0] not in ('on', 'off'):
        raise ValueError('invalid boot-network activation setting')
    return rows[0][0] == 'on'


if __name__ == '__main__':
    from database_selection import select_database
    try:
        database, _ = select_database()
        print('on' if enabled(database) else 'off')
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f'Boot network: {error}', file=sys.stderr)
        sys.exit(1)
