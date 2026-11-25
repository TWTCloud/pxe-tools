#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Compare the PHP and Rust image reservations using disposable SQLite data."""
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = (ROOT/'app/db/schema.sqlite.sql').read_text()


def fixture(database, http, case):
    with closing(sqlite3.connect(database)) as db, db:
        db.executescript(SCHEMA)
        db.execute('PRAGMA journal_mode=WAL')
        target = {
            'id': 1, 'distro': 'debian', 'version': 'trixie', 'version_full': '13.0', 'arch': 'amd64'
        }
        db.execute("""INSERT INTO os_images(id,distro,version,version_full,arch,codename,enabled,status)
                   VALUES(:id,:distro,:version,:version_full,:arch,'trixie',1,'downloaded')""", target)
        if case != 'last-image':
            db.execute("""INSERT INTO os_images(id,distro,version,version_full,arch,codename,enabled,status)
                       VALUES(2,'debian','13.1','13.1','amd64','trixie',1,'downloaded')""")
        for version in ('13.0', '13.1'):
            path = http/'netboot'/'debian'/version/'amd64'
            path.mkdir(parents=True, exist_ok=True)
            for asset in ('linux', 'initrd.gz'):
                (path/asset).write_bytes(b'Disposable fixture')
        if case == 'stale':
            target['version_full'] = 'different'
        db.execute("INSERT INTO init_jobs(id,job_type,status,log) VALUES(3,'image:delete:1','running',?)",
                   (json.dumps(target),))
        if case in ('active', 'wipe'):
            config = {'distro': 'trixie', 'version_full': '13.0'}
            db.execute("""INSERT INTO machines(id,mac,status,boot_arch,install_config_json)
                       VALUES(4,'02:00:00:00:00:04','configured','amd64',?)""", (json.dumps(config),))
            if case == 'active':
                db.execute("INSERT INTO actions(machine_id,type,status,token) VALUES(4,'install_only','pending',?)",
                           (base64.b16encode(b'fixture').decode(),))
            else:
                db.execute("""INSERT INTO wipes(machine_id,disks_json,wipe_mode,wipe_status,chain_install_config_json)
                           VALUES(4,'["/dev/vda"]','partial','pending',?)""",
                           (json.dumps({'install_config': config}),))


def run(command, root, database, case, php):
    with subprocess.Popen([*command,'1','3',str(database)], env={**os.environ, 'HTTP_ROOT':str(root), 'PXE_HTTP_ROOT':str(root)},
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as child:
        first = child.stdout.readline()
        if first == b'READY\n':
            if not php:
                with closing(sqlite3.connect(database, timeout=.1)) as writer:
                    try:
                        writer.execute("UPDATE os_images SET enabled=0 WHERE id=2")
                    except sqlite3.OperationalError as error:
                        assert 'locked' in str(error)
                    else:
                        raise AssertionError('The reservation did not hold the SQLite write lock')
            tail, _ = child.communicate(input=b'' if case == 'abort' else b'COMMIT\n', timeout=5)
        else:
            tail, _ = child.communicate(timeout=5)
        with closing(sqlite3.connect(database)) as db:
            selected = db.execute('SELECT id FROM os_images ORDER BY id').fetchall()
        return child.returncode == 0, first + tail, selected


def main():
    if os.geteuid() == 0:
        raise SystemExit('The reservation must be exercised as an unprivileged account')
    binary = ROOT/'rust/target/release/pxe-tools-rust'
    commands = (['php',str(ROOT/'app/cli/delete-image.php')], [str(binary),'--reserve-image-deletion'])
    for case in ('last-image','stale','active','wipe','abort','commit'):
        with tempfile.TemporaryDirectory(prefix='pxe-image-reservation-') as tmp:
            root = Path(tmp).resolve()
            results = []
            for index, command in enumerate(commands):
                database = root/f'{index}.sqlite'
                http = root/'http'
                fixture(database, http, case)
                results.append(run(command,http,database,case,php=index==0))
            assert results[0] == results[1], (case, results)
            assert results[0][0] == (case=='commit'), (case, results)
            expected = [(1,)] if case=='last-image' else [(2,)] if case=='commit' else [(1,),(2,)]
            assert results[0][2] == expected, (case, results)
    print('Rust/PHP image reservation parity, lock lifetime and rollback verified')


if __name__ == '__main__':
    main()
