#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Keep the lab command on the same importer as the PXE Tools worker."""
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).resolve().parents[3] /
                   'docker/worker/scripts/cache-windows-image.py'), run_name='__main__')
