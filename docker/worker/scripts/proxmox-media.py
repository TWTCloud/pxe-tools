# SPDX-License-Identifier: LGPL-3.0-only
"""Prepare verified upstream Proxmox VE media with the vendor's assistant."""

from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from tempfile import TemporaryDirectory

VERSION = "9.2-1"
ASSISTANT = "9.2.13"
ISO_HASH = {
    "amd64": "4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c",
    "arm64": "b1619dcd1f5b1a6d67d77b59e7e2fa2033174551d1e1b9dc22b2171ec093abbd",
}
ASSISTANT_HASH = {
    "amd64": "fc5323e06655b8a188e97949562e991f052de23c47ce128c3d400852c0e25598",
    "arm64": "62c232d562bdf246738e0f5d7fa9471f6c2010cb4a4543db7038217209eb4780",
}


def prepare(request, root, download, fingerprint, directory, error):
    arch = request["source"]
    address, port, pin = request["profile"].split(":")
    ip = IPv4Address(address)
    if (arch not in ISO_HASH or request["sha256"] != ISO_HASH[arch] or request["remote"]
            or ip.is_unspecified or ip.is_loopback or ip.is_multicast or not 0 < int(port) <= 65535
            or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin)):
        raise error("Configuration du média Proxmox invalide.")
    host_arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if host_arch is None or not all(shutil.which(tool) for tool in ("xorriso", "dpkg-deb")):
        raise error("La préparation Proxmox nécessite xorriso et dpkg-deb sur un serveur amd64 ou ARM64.")
    parent = directory(root, f"netboot/proxmox/{VERSION}")
    target = parent / arch
    marker = target / ".managed-answer"
    metadata = json.dumps({"pin": pin, "authority": f"{ip}:{port}"}, sort_keys=True)
    if target.is_dir() and not target.is_symlink():
        if (marker.is_file() and not marker.is_symlink() and marker.read_text() == metadata
                and all((target / name).is_file() and (target / name).stat().st_size
                        for name in ("linux", "initrd.gz", "source.iso"))):
            return f"Proxmox VE {VERSION} {arch} est déjà prêt."
        # Do not overwrite externally prepared media under the same version and architecture.
        if not marker.is_file() or marker.is_symlink():
            raise error("Ce média Proxmox existe déjà. Retirez le média préparé manuellement avant de réessayer.")
    expected_size = 8 * 1024**3
    if shutil.disk_usage(parent).free < expected_size:
        raise error("Prévoyez au moins 8 Gio libres pour préparer l’installateur Proxmox.")
    # Stage privately on the same filesystem as the serving tree.
    with TemporaryDirectory(prefix=".proxmox-", dir=parent) as temporary:
        stage = Path(temporary)
        iso_name = f"proxmox-ve_{VERSION}{'-arm64' if arch == 'arm64' else ''}.iso"
        iso = download("https://enterprise.proxmox.com/iso/" + iso_name,
                       stage / iso_name, {"enterprise.proxmox.com"})
        if fingerprint(iso) != ISO_HASH[arch]:
            raise error("L’empreinte de l’ISO Proxmox diffère de celle publiée par l’éditeur.")
        pkg = f"proxmox-auto-install-assistant_{ASSISTANT}_{host_arch}.deb"
        package = download(
            f"https://download.proxmox.com/debian/pve/dists/trixie/pve-no-subscription/binary-{host_arch}/{pkg}",
            stage / pkg, {"download.proxmox.com"},
        )
        if fingerprint(package) != ASSISTANT_HASH[host_arch]:
            raise error("L’empreinte de l’assistant Proxmox est invalide.")
        extract = stage / "assistant"
        subprocess.run(["dpkg-deb", "-x", package, extract], check=True, capture_output=True)
        output = stage / "output"
        output.mkdir()
        subprocess.run([
            extract / "usr/bin/proxmox-auto-install-assistant", "prepare-iso", iso,
            "--fetch-from", "http", "--url", f"https://{ip}:{port}/pxe/proxmox/answer",
            "--cert-fingerprint", pin, "--pxe", "--output", output,
        ], check=True, capture_output=True)
        prepared = list(output.glob("*.iso"))
        if len(prepared) != 1:
            raise error("L’assistant Proxmox a produit un média incomplet.")
        for original, name in [(output / "vmlinuz", "linux"), (output / "initrd.img", "initrd.gz"),
                               (prepared[0], "source.iso")]:
            if not original.is_file() or original.is_symlink() or not original.stat().st_size:
                raise error("L’assistant Proxmox a produit un fichier de démarrage invalide.")
            original.rename(output / name)
            (output / name).chmod(0o444)
        (output / ".managed-answer").write_text(metadata)
        if target.exists():
            target.rename(stage / "previous")
        try:
            output.rename(target)
        except OSError:
            if (stage / "previous").exists():
                (stage / "previous").rename(target)
            raise
    return f"Proxmox VE {VERSION} {arch} prêt dans le menu PXE."
