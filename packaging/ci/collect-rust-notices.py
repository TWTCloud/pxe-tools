#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Collect the crate notices and locked source URLs for a native Rust build."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib


def collect(destination):
    host = next(
        line.removeprefix("host: ")
        for line in subprocess.check_output(["rustc", "--version", "--verbose"], text=True).splitlines()
        if line.startswith("host: ")
    )
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host,
        "--manifest-path", "rust/Cargo.toml",
    ], text=True))
    checksums = {
        (entry["name"], entry["version"]): entry["checksum"]
        for entry in tomllib.loads(Path("rust/Cargo.lock").read_text())["package"]
        if entry.get("source") == "registry+https://github.com/rust-lang/crates.io-index"
    }
    used = {node["id"] for node in metadata["resolve"]["nodes"]}
    destination.mkdir()
    sources = []
    for package in sorted(metadata["packages"], key=lambda package: (package["name"], package["version"])):
        if package["id"] not in used or package["source"] is None:
            continue
        name, version = package["name"], package["version"]
        crate = Path(package["manifest_path"]).parent
        files = {
            path for path in crate.rglob("*")
            if path.is_file() and path.name.upper().startswith(("LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT"))
        }
        if package["license_file"]:
            files.add(crate / package["license_file"])
        for path in sorted(files):
            target = destination / "crates" / f"{name}-{version}" / path.relative_to(crate)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        sources.append({
            "name": name, "version": version, "license": package["license"] or package["license_file"],
            "sha256": checksums[name, version],
            "source": f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
        })
    (destination / "crates.json").write_text(json.dumps(sources, indent=2) + "\n")

    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    docs = Path(sysroot) / "share/doc/rust"
    shutil.copytree(docs / "licenses", destination / "rust-library-licenses")
    shutil.copyfile(docs / "COPYRIGHT-library.html", destination / "COPYRIGHT-library.html")


if __name__ == "__main__":
    collect(Path(sys.argv[1]))
