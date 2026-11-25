#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Prepare an approved media file in the root-owned PXE store."""
from configparser import ConfigParser, Error as ConfigError
from contextlib import closing
import fcntl
from http.client import HTTPException, HTTPSConnection
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlencode, urljoin, urlsplit
from zipfile import BadZipFile, ZipFile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("Media preparation files are missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load("native_media", "validate-native-runtime.py")
windows = load("windows_media", "cache-windows-image.py")
SHA256 = windows.SHA256
CHUNK = 1024 * 1024
MAX_MEDIA = 64 * 1024**3
BOOT_ASSETS = {"wimboot": "wimboot_sha256", "BCD": "bcd_sha256",
               "boot.sdi": "boot_sdi_sha256", "boot.wim": "winpe_sha256"}
RHEL_FILES = {".treeinfo", ".discinfo", "media.repo", "RPM-GPG-KEY-redhat-release",
              "RPM-GPG-KEY-redhat-beta", "images/install.img", "images/efiboot.img",
              "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img"}
RHEL_PREFIXES = ("BaseOS/", "AppStream/")
REDHAT_CDN_HOSTS = {"access.cdn.redhat.com", "cdn.redhat.com"}
REDHAT_JSON_LIMIT = 64 * 1024
RHEL_BOOT = ("images/install.img", "images/pxeboot/vmlinuz", "images/pxeboot/initrd.img")


class MediaError(Exception):
    """A failure that can be displayed without leaking paths or URLs."""


def directory(root, relative):
    native.ensure_http_tree(root, relative)
    return root / relative


class PublicHttpsConnection(HTTPSConnection):
    def connect(self):
        answers = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        addresses = [answer[4][0] for answer in answers]
        parsed = [ipaddress.ip_address(address) for address in addresses]
        parsed = [getattr(address, "ipv4_mapped", None) or address for address in parsed]
        if not parsed or any(not address.is_global or address.is_multicast or address.is_reserved
                             or getattr(address, "is_site_local", False) for address in parsed):
            raise MediaError("Le téléchargement doit pointer vers une adresse publique.")
        # Resolve once and use that exact address, retaining the DNS name for TLS.
        for address in dict.fromkeys(addresses):
            try:
                stream = socket.create_connection((address, 443), timeout=self.timeout)
            except OSError:
                continue
            try:
                self.sock = ssl.create_default_context().wrap_socket(stream, server_hostname=self.host)
                return
            except BaseException:
                stream.close()
                raise
        raise MediaError("Le serveur de téléchargement ne répond pas.")


def copy_bounded(source, destination, limit, report=None):
    written = 0
    while chunk := source.read(CHUNK):
        written += len(chunk)
        if written > limit:
            raise MediaError("La taille du média dépasse la limite de préparation.")
        destination.write(chunk)
        if report is not None:
            report(written)
    return written


def download(url, target, hosts, progress=None):
    for _ in range(6):
        parsed = urlsplit(url)
        if (len(url) > 4096 or parsed.scheme != "https" or not parsed.hostname
                or parsed.hostname not in hosts or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname)
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443) or parsed.fragment or "\\" in url):
            raise MediaError("L’hôte HTTPS de la source ou de sa redirection est refusé.")
        resource = parsed.path or "/"
        if parsed.query:
            resource += "?" + parsed.query
        with closing(PublicHttpsConnection(parsed.hostname, timeout=30)) as connection:
            connection.request("GET", resource)
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308) and response.getheader("Location"):
                url = urljoin(url, response.getheader("Location"))
                continue
            if response.status != 200:
                raise MediaError("La source HTTPS ne fournit pas le média demandé.")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_MEDIA):
                raise MediaError("La taille annoncée du média dépasse la limite de préparation.")
            length = int(length) if length is not None else None
            report = None
            if progress is not None and length:
                if length > shutil.disk_usage(target.parent).free:
                    raise MediaError("Espace insuffisant pour télécharger le DVD RHEL.")
                last = 15

                def report(written):
                    nonlocal last
                    percent = min(80, 15 + 5 * (13 * written // length))
                    if percent > last:
                        last = percent
                        progress(percent)

            with target.open("xb") as destination:
                size = copy_bounded(response, destination, MAX_MEDIA, report)
            if not size or length is not None and size != length:
                raise MediaError("Le téléchargement du média est incomplet.")
            return target
    raise MediaError("La source HTTPS a fourni trop de redirections.")



def redhat_json(host, method, resource, *, body=None, headers=None, denied):
    # Never follow a redirect from a request carrying a Red Hat credential.
    try:
        with closing(PublicHttpsConnection(host, timeout=30)) as connection:
            connection.request(method, resource, body=body, headers=headers or {})
            response = connection.getresponse()
            if response.status in (400, 401, 403):
                raise MediaError(denied)
            if response.status == 404 and method == "GET":
                raise MediaError("Ce DVD est indisponible via l’API Red Hat. Vérifiez l’accès du compte ou importez le DVD.")
            if response.status != 200:
                raise MediaError("Le service Red Hat est indisponible. Réessayez dans quelques instants.")
            raw = response.read(REDHAT_JSON_LIMIT + 1)
            if len(raw) > REDHAT_JSON_LIMIT:
                raise ValueError("Oversized Red Hat API response")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("Invalid Red Hat API response")
            return result
    except (OSError, HTTPException):
        raise MediaError("Connexion à Red Hat impossible. Vérifiez l’accès Internet du serveur.") from None
    except ValueError:
        raise MediaError("Réponse inattendue de Red Hat. Réessayez ou importez le DVD.") from None


def redhat_download_url(sha, offline_token):
    token = redhat_json(
        "sso.redhat.com", "POST", "/auth/realms/redhat-external/protocol/openid-connect/token",
        body=urlencode({"grant_type": "refresh_token", "client_id": "rhsm-api", "refresh_token": offline_token}),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        denied="Jeton API Red Hat refusé. Générez un nouveau jeton dans le portail Red Hat.",
    ).get("access_token")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,8192}", token):
        raise MediaError("Red Hat n’a pas fourni de jeton d’accès. Réessayez ou importez le DVD.")
    result = redhat_json(
        "api.access.redhat.com", "GET", f"/management/v1/images/{sha}/download",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        denied="Ce compte Red Hat ne peut pas télécharger le DVD. Vérifiez ses droits dans le portail Red Hat.",
    ).get("body")
    url = result.get("href") if isinstance(result, dict) else None
    if not isinstance(url, str) or not url:
        raise MediaError("Red Hat n’a pas fourni de lien pour ce DVD. Réessayez ou importez le DVD.")
    return url

def local_file(inbox, name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name):
        raise MediaError("Le nom de fichier dans le dossier privé est invalide.")
    source = inbox / name
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_MEDIA):
        raise MediaError("Le média local doit être un fichier ordinaire protégé appartenant à root.")
    return source


def rhel_members(iso):
    listing = subprocess.check_output(["7z", "l", "-slt", "-ba", "-sccUTF-8", iso], text=True)
    files = {}
    total = 0
    for block in listing.split("\n\n"):
        fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        name = fields.get("Path", "")
        if name not in RHEL_FILES and not name.startswith(RHEL_PREFIXES):
            continue
        if (not all(re.fullmatch(r"[A-Za-z0-9_.+~^-]{1,255}", part)
                    and part not in (".", "..") for part in name.split("/"))
                or fields.get("Symbolic Link") or fields.get("Hard Link")
                or fields.get("Mode", "").startswith("l")):
            raise MediaError("Le DVD contient un chemin ou un lien non autorisé.")
        if fields.get("Folder") == "+":
            continue
        if name in files or not fields.get("Size", "").isdecimal():
            raise MediaError("Le DVD contient des fichiers ambigus.")
        files[name] = int(fields["Size"])
        total += files[name]
        if total > MAX_MEDIA:
            raise MediaError("L’arbre RHEL extrait dépasse la limite de préparation.")
    required = [".treeinfo", *RHEL_BOOT, "BaseOS/repodata/repomd.xml", "AppStream/repodata/repomd.xml"]
    if any(not files.get(name) for name in required):
        raise MediaError("Le DVD doit contenir les dépôts BaseOS et AppStream et les images de démarrage.")
    return files, total


def rhel_info(tree):
    info = ConfigParser(interpolation=None)
    with (tree / ".treeinfo").open(encoding="utf-8") as stream:
        info.read_file(stream)
    version = info["general"]["version"]
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(info["general"]["arch"])
    if (info["general"]["family"] != "Red Hat Enterprise Linux" or architecture is None
            or re.fullmatch(r"9(?:\.[0-9]{1,3}){1,2}", version) is None):
        raise MediaError("L’ISO doit être un DVD officiel RHEL 9 amd64 ou ARM64.")
    for name in RHEL_BOOT:
        if info["checksums"][name] != "sha256:" + windows.fingerprint(tree / name):
            raise MediaError("Une image de démarrage RHEL diffère de son empreinte.")
    return {"version": version, "arch": architecture}


def prepare_rhel(iso, stage, location):
    selected, size = rhel_members(iso)
    if shutil.disk_usage(stage).free < size:
        raise MediaError("Espace insuffisant pour préparer les dépôts du DVD.")
    tree = stage / "rhel-tree"
    tree.mkdir()
    listing = stage / "rhel-files.txt"
    listing.write_text("\n".join(selected) + "\n", encoding="utf-8")
    subprocess.run(["7z", "x", "-bd", "-y", "-spd", "-scsUTF-8", f"-o{tree}", iso, f"@{listing}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    extracted = set()
    for path in tree.rglob("*"):
        meta = path.lstat()
        if stat.S_ISDIR(meta.st_mode):
            path.chmod(0o755)
        elif (stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
              and selected.get(path.relative_to(tree).as_posix()) == meta.st_size):
            path.chmod(0o444)
            extracted.add(path.relative_to(tree).as_posix())
        else:
            raise MediaError("Les fichiers extraits diffèrent de l’inventaire du DVD.")
    if extracted != selected.keys():
        raise MediaError("Il manque des fichiers dans les dépôts extraits du DVD.")
    details = rhel_info(tree)
    (tree / ".pxe-media.json").write_text(json.dumps(details), encoding="utf-8")
    (tree / ".pxe-media.json").chmod(0o444)
    tree.chmod(0o755)
    tree.rename(location)
    return f"RHEL {details['version']} {details['arch']} prêt dans le menu PXE."


def prepare_image(source, stage, cache, name, digest):
    with source.open("rb") as stream:
        if stream.read(8) != b"MSWIM\0\0\0":
            raise MediaError("Le fichier ne contient pas d’image WIM ou ESD.")
    location = cache / digest
    location.mkdir(exist_ok=True)
    destination = location / name
    if destination.exists():
        if windows.fingerprint(destination) != digest:
            raise MediaError("L’image Windows en cache diffère de son empreinte.")
        return
    copy = stage / name
    shutil.copyfile(source, copy)
    if windows.fingerprint(copy) != digest:
        raise MediaError("L’image Windows a changé pendant sa mise en cache.")
    copy.chmod(0o444)
    copy.rename(destination)


def publish_winpe(archive, stage, cache, destination, bundle_sha):
    existing = sum(
        re.fullmatch(r"[a-z0-9-]{1,40}", path.name) is not None and not path.is_symlink() and path.is_dir()
        for path in destination.parent.iterdir()
    )
    if existing >= 32:
        raise MediaError("Le serveur accepte au plus 32 éditions Windows.")
    bundle = stage / "profile"
    bundle.mkdir()
    required = {"case.json", *(f"boot/{name}" for name in BOOT_ASSETS)}
    with ZipFile(archive) as source:
        files = [info for info in source.infolist() if not info.is_dir()]
        if len(files) != len(required) or {info.filename for info in files} != required:
            raise MediaError("Le ZIP doit contenir case.json et les quatre fichiers du dossier boot.")
        for info in files:
            limit = 32768 if info.filename == "case.json" else 2 * 1024**3
            if not 0 < info.file_size <= limit:
                raise MediaError("Un fichier WinPE est vide ou trop volumineux.")
            with source.open(info) as opened, (bundle / Path(info.filename).name).open("xb") as output:
                if copy_bounded(opened, output, limit) != info.file_size:
                    raise MediaError("Le fichier WinPE extrait est incomplet.")
    data = json.loads((bundle / "case.json").read_text(encoding="utf-8"))
    image = data["install_image"]
    digest = data["install_sha256"]
    if (image not in ("install.wim", "install.esd") or not SHA256.fullmatch(digest)
            or not re.fullmatch(r"[A-Za-z0-9]{1,40}", data["edition"])
            or type(data["image_index"]) is not int or not 1 <= data["image_index"] <= 128
            or not 0 < len(data["edition_label"].encode("utf-8")) <= 120
            or not data["edition_label"].strip() or not data["edition_label"].isprintable()):
        raise MediaError("Le manifeste de l’édition WinPE est invalide.")
    if "install_image_uri" in data:
        uri = urlsplit(data["install_image_uri"])
        if (uri.scheme not in ("http", "https") or not uri.hostname
                or uri.username is not None or uri.password is not None or uri.query or uri.fragment
                or uri.path != f"/pxe/windows/{destination.name}/{image}"):
            raise MediaError("L’adresse intégrée à WinPE doit correspondre à l’identifiant et à l’image importés.")
    for name, key in BOOT_ASSETS.items():
        if windows.fingerprint(bundle / name) != data[key]:
            raise MediaError("Un fichier de démarrage WinPE diffère de son empreinte.")
    cached = cache / digest / image
    if not cached.is_file():
        raise MediaError("Importez d’abord l’image Windows indiquée dans le manifeste WinPE.")
    if windows.fingerprint(cached) != digest:
        raise MediaError("L’image Windows en cache diffère de son empreinte.")
    os.link(cached, bundle / image)
    (bundle / ".pxe-bundle-sha256").write_text(bundle_sha + "\n", encoding="ascii")
    for path in bundle.iterdir():
        path.chmod(0o444)
    bundle.chmod(0o755)
    bundle.rename(destination)
    return f"Édition Windows {destination.name} prête dans la console."


def prepare(request, root, progress):
    kind, sha, profile = request["kind"], request["sha256"], request["profile"]
    if kind == "proxmox":
        media = directory(root, "media")
        with (media / ".import-lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return load("proxmox_media", "proxmox-media.py").prepare(
                request, root, download, windows.fingerprint, directory, MediaError,
            )
    if (kind not in ("rhel9", "windows-iso", "windows-wim", "windows-esd", "winpe")
            or not SHA256.fullmatch(sha)
            or (not re.fullmatch(r"[a-z0-9-]{1,40}", profile) if kind == "winpe" else profile != "")):
        raise MediaError("Le type, l’identifiant ou l’empreinte du média est invalide.")
    offline_token = request.get("redhat_token")
    if offline_token is not None and (kind != "rhel9" or request["remote"] or request["source"]
                                      or not re.fullmatch(r"[A-Za-z0-9._~-]{1,4096}", offline_token)):
        raise MediaError("Le jeton API Red Hat est invalide.")
    media = directory(root, "media")
    inbox = directory(root, "media/inbox")
    inbox.chmod(0o700)
    with (media / ".import-lock").open("a+b") as lock, tempfile.TemporaryDirectory(prefix=".prepare-", dir=media) as tmp:
        fcntl.flock(lock, fcntl.LOCK_EX)
        stage = Path(tmp)
        cache = directory(root, "media/windows-cache")
        rhel = directory(root, "media/rhel9") / sha if kind == "rhel9" else None
        if rhel is not None and (rhel / ".pxe-media.json").is_file():
            return "DVD RHEL déjà préparé dans le cache PXE."
        if kind == "windows-iso" and (cache / f"iso-{sha}.json").is_file():
            data = windows.extract(None, sha, cache)
            return f"Image Windows déjà en cache · {data['install_image']} · SHA-256 {data['install_sha256']}"
        name = {"windows-wim": "install.wim", "windows-esd": "install.esd"}.get(kind)
        if name and (cache / sha / name).is_file() and windows.fingerprint(cache / sha / name) == sha:
            return f"Image Windows déjà en cache · {name} · SHA-256 {sha}"
        profile_path = directory(root, "winpe/amd64") / profile if kind == "winpe" else None
        if profile_path is not None and (profile_path.exists() or profile_path.is_symlink()):
            marker = profile_path / ".pxe-bundle-sha256"
            if marker.is_file() and marker.read_text(encoding="ascii").strip() == sha:
                return f"Édition Windows {profile} déjà prête."
            raise MediaError("Cet identifiant Windows est déjà utilisé. Choisissez un autre identifiant.")
        if offline_token is not None:
            progress(10)
            url = redhat_download_url(sha, offline_token)
            progress(15)
            source = download(url, stage / "download", REDHAT_CDN_HOSTS, progress)
            progress(85)
        elif request["remote"]:
            hosts = {host.strip().lower() for host in os.environ.get("PXE_MEDIA_DOWNLOAD_HOSTS", "").split(",")}
            source = download(request["source"], stage / "download", hosts)
        else:
            source = local_file(inbox, request["source"])
        if windows.fingerprint(source) != sha:
            raise MediaError("L’empreinte SHA-256 ne correspond pas au média fourni.")
        if rhel is not None:
            if offline_token is not None:
                progress(95)
            return prepare_rhel(source, stage, rhel)
        if profile_path is not None:
            return publish_winpe(source, stage, cache, profile_path, sha)
        if kind == "windows-iso":
            data = windows.extract(source, sha, cache)
            return f"Image Windows préparée · {data['install_image']} · SHA-256 {data['install_sha256']}"
        assert name is not None
        prepare_image(source, stage, cache, name, sha)
        return f"Image Windows préparée · {name} · SHA-256 {sha}"


if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            raise MediaError("La préparation doit être exécutée par le worker PXE Tools.")
        print(prepare(
            json.loads(sys.stdin.buffer.read(16384)), Path(os.environ["HTTP_ROOT"]),
            lambda percent: print(f"progress:{percent}", flush=True),
        ))
    except MediaError as error:
        print(error)
        sys.exit(1)
    except FileNotFoundError:
        print("Le fichier local ou un outil de préparation est introuvable.")
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, ConfigError, HTTPException,
            BadZipFile, subprocess.SubprocessError):
        print("Le média ne peut pas être lu ou préparé. Vérifiez le format, les droits et l’espace du stockage PXE.")
        sys.exit(1)
