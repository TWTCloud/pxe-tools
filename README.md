# PXE Tools

PXE Tools fournit une interface web pour découvrir des machines et installer
Debian par le réseau. Le socle comprend les services PXE, l'interface et son
worker. Ansible reste facultatif et absent du socle. Le [module complémentaire](modules/ansible/NATIVE.md) est disponible dans le
dépôt APT et s’utilise avec le worker existant.

Le serveur PXE Tools prend en charge **Debian 13 amd64 et arm64**. Les essais
couvrent les paquets APT et les images Docker des deux architectures. Le
serveur ARM64 a installé un client Debian 13 BIOS amd64 sur un banc isolé.
Consultez [la documentation native](docs/native-preparation.md) pour les
limites et instructions de sécurité.

## Installation avec APT

Téléchargez la clé publique, puis vérifiez son empreinte avant de l'utiliser :

```sh
sudo apt update
sudo apt install --no-install-recommends ca-certificates curl gpg
curl -fsSLo pxe-tools-archive-keyring.gpg https://packages.pxetools.com/pxe-tools-archive-keyring.gpg
gpg --show-keys --fingerprint pxe-tools-archive-keyring.gpg
```

L'empreinte attendue de la clé principale est :

```text
1741 0C3B 457E 5742 5728 1551 CFC3 5C53 6A61 C3CF
```

Après comparaison, ajoutez le dépôt et installez le paquet :

```sh
sudo install -m 0644 pxe-tools-archive-keyring.gpg /usr/share/keyrings/pxe-tools-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/pxe-tools-archive-keyring.gpg] https://packages.pxetools.com/apt/ stable main' | sudo tee /etc/apt/sources.list.d/pxe-tools.list >/dev/null
sudo apt update
sudo apt install --no-install-recommends pxe-tools
```

Pour ajouter le module Ansible facultatif après l’installation du socle :

```sh
sudo apt install --no-install-recommends pxe-tools-ansible
```

Consultez le [guide du module natif](modules/ansible/NATIVE.md) pour préparer
les accès, redémarrer le worker et activer explicitement le module.

À partir de la bêta 14, une instance neuve ouvre la console HTTPS sur
les IPv4 privées actives du serveur. Depuis un autre poste du réseau,
ouvrez `https://<IPv4-du-serveur>/admin/`. Lisez le code de l’assistant
sur le serveur avec `sudo cat /run/pxe-tools-rust-guided/setup-code`.
Le proxy DHCP s’active après votre confirmation de la configuration
réseau dans l’assistant.

Pour Secure Boot, la clé MOK de votre instance doit être enrôlée sur chaque
client x86 concerné avant d'utiliser le chargeur signé par cette instance.

## Installation avec Docker

L’image bêta 14 est disponible pour Linux amd64 et arm64. Depuis la racine
du dépôt sur un hôte Docker Linux, téléchargez l'image et démarrez l'appliance.

```sh
docker pull ghcr.io/williamboglietti/pxe-tools-appliance:v0.1.0-beta14
PXE_TOOLS_IMAGE=ghcr.io/williamboglietti/pxe-tools-appliance:v0.1.0-beta14 \
  docker compose -f compose/docker-compose.yml up -d
```

Le fichier Compose utilise le réseau de l’hôte pour le PXE. Ouvrez
`https://<IPv4-du-serveur>/admin/` et lisez le code de l’assistant dans
le conteneur.

```sh
PXE_TOOLS_IMAGE=ghcr.io/williamboglietti/pxe-tools-appliance:v0.1.0-beta14 \
  docker compose -f compose/docker-compose.yml exec pxe-tools cat /run/pxe-tools-rust-guided/setup-code
```

Les notes de mise à niveau et les offres de sources accompagnent la
[bêta 14](https://github.com/williamboglietti/pxe-tools/releases/tag/v0.1.0-beta14).

## Données et limites

La base SQLite, la clé de chiffrement et les fichiers persistants doivent être
sauvegardés ensemble. Une procédure de [sauvegarde chiffrée et restauration
en veille](docs/backup-restore.md) est disponible en ligne de commande. Une
désinstallation du paquet conserve les données.
MySQL et MariaDB sont actuellement désactivés : une configuration existante
est conservée mais n'est pas migrée automatiquement.

Le code du socle est distribué sous [LGPL-3.0](COPYING.LESSER). Les composants
tiers et leurs notices sont recensés dans [THIRD-PARTY.md](THIRD-PARTY.md).
Les sources et matériaux de reliage des utilitaires embarqués sont disponibles
dans [la notice et les archives correspondantes](https://github.com/williamboglietti/pxe-tools/releases/tag/sources-2026-11-12).
