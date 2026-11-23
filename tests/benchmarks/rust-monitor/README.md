# Portage Rust de PXE Tools

Le binaire expérimental dans [rust/](../../../rust/) s'exécute avec nginx
et une base SQLite jetable. Il écoute sur un socket Unix privé. Le nginx
du banc renseigne l'adresse du pair pour chaque requête. Les deux backends
passent par nginx et PHP exécute le vrai routeur de l'application.

## Vérifier la parité HTTP

Depuis la racine du dépôt, sous un compte ordinaire sur un hôte de
test sans `/etc/pxe-tools/db.conf` :

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml
python3 tests/benchmarks/rust-monitor/parity.py
PXE_APP_DIR="$PWD/app" python3 tests/unit/test_preseed_install_invariants.py
```

Le banc demande Python 3.10+, PHP CLI avec PDO SQLite, PHP-FPM, nginx,
Rust et un compilateur C pour SQLite. Selon l'installation, passer
`--fpm /usr/sbin/php-fpm8.4` et `--nginx /usr/sbin/nginx`.

| Surface exercée | Attendu |
| --- | --- |
| `GET /api/monitoring/installs` | Même ordre et mêmes valeurs pour 69 installations, sur les quatre types suivis. Filtre des 24 h, dernier événement, progression disque, checkpoints répétés, libellés sans MAC. Même politique IPv4, refus hors sous-réseau ou avec sous-réseau invalide. |
| `GET /api/boot-selected` | Mêmes statuts et commentaires GRUB. Vérification du sous-réseau et du couple identifiant-jeton. Rejeu idempotent, refus de changer de menu, journal et checkpoint `install_reboot_done`. |
| `GET/POST /api/discovery?phase=…` | Mêmes réponses et niveaux de journal, recherche par MAC primaire ou secondaire, fermeture de la fenêtre d'attente après le signal d'arrêt. |
| `GET/POST /api/discovery`, inventaire et poll | JSON ou base64, limites de taille, conflits entre fiches, statuts préservés, séries et WWID, métadonnées de stockage et consommation du redémarrage. |
| `GET /preseed.php` | Comparaison des directives Debian sur un profil guidé, du garde disque embarqué, des refus réseau et de la fermeture après installation. |
| Retours Debian | Démarrage local et réessais, journal borné, accès aux artefacts postboot, fin d'installation avec jeton lié à l'action, accusé du premier démarrage et rejouabilité. |

Les requêtes de mutation utilisent deux copies d'une même fixture. Le test
compare les écritures SQLite et vérifie que le catalogue compilé dans Rust
correspond à celui de PHP. Les pings de découverte et la sélection GRUB
regroupent leurs écritures dans une transaction. Une erreur d'écriture
annule l'ensemble de la mutation Rust.

## Essayer la distribution du suivi Rust

Les variantes locales amd64 et arm64 activent Rust pour
`GET /api/monitoring/installs` sur le port PXE. nginx lui passe l'adresse
réelle du client sur un socket Unix privé. Le suivi ouvre la base SQLite
déclarée dans `/etc/pxe-tools/db.conf` en lecture seule. Si le service, le
fichier de configuration ou SQLite est indisponible, nginx confie cette
lecture à PHP. Un refus réseau reste un refus. Une réponse de Rust
contient l'en-tête `X-PXE-Monitor-Backend: rust`.

Depuis Debian 13, construire le paquet de test ou l'image expérimentale.

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml
strip rust/target/release/pxe-tools-rust
python3 packaging/native/build-local-package.py /tmp/pxe-tools-rust-test.deb \
  --architecture "$(dpkg --print-architecture)" \
  --rust-binary rust/target/release/pxe-tools-rust
docker build --target rust-experimental -f docker/pxe-tools/Dockerfile -t pxe-tools:rust-lab .
```

Le paquet de test lance le service expérimental avec le service HTTP de
démarrage. Après une mise à niveau qui reprend un service HTTP déjà actif,
`systemctl start pxe-tools-rust-monitor.service` active le suivi Rust.
Pour vérifier le retour à PHP, arrêter ce service ou, dans le conteneur,
utiliser `/command/s6-svc -d /run/service/rust-monitor`.

L'interface d'administration, le preseed, les retours d'installation et
les autres routes de ces variantes passent par PHP. Le parcours Rust
complet utilise le banc dédié ci-dessous. Le script de distribution
exerce les deux variantes sur un hôte Linux jetable, avec une ancienne
base SQLite, une clé maître et une donnée chiffrée synthétiques.

```sh
bash tests/integration/test_rust_monitor_distribution.sh "$(dpkg --print-architecture)"
```

## Essayer le parcours Debian guidé sans PHP-FPM

Sur Debian 13 amd64 ou arm64, les commandes suivantes construisent le
paquet local de test et la cible Docker dédiée.

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml
strip rust/target/release/pxe-tools-rust
python3 packaging/native/build-local-package.py /tmp/pxe-tools-guided.deb \
  --architecture "$(dpkg --print-architecture)" --rust-guided \
  --rust-binary rust/target/release/pxe-tools-rust
docker build --target rust-guided -f docker/pxe-tools/Dockerfile -t pxe-tools:rust-guided .
```

Ces variantes réutilisent le `db.conf`, la clé maître et les données
d'une instance SQLite existante. Sur une instance vierge, la console
écoute uniquement sur `127.0.0.1`. Ouvrir
`https://127.0.0.1/admin/` localement ou par un tunnel SSH vers cette
boucle locale. Le compte root peut lire le code de configuration dans
`/run/pxe-tools-rust-guided/setup-code`. Pour Docker, utiliser
`docker exec` depuis l'hôte pour lire le code à l'intérieur du conteneur.
Le lanceur génère un nouveau code à chaque démarrage du service.

L'assistant crée la base SQLite et le premier compte local. Le compte
existant ferme cette phase. Cette première partie de l'assistant laisse
le PXE désactivé. Le réglage du réseau, le choix des images et la validation
finale sont encore en cours de portage. Pour une instance dont le réseau
PXE est préparé, le paquet active le parcours avec
`systemctl start pxe-tools.target`. L'image utilise ses volumes et son
superviseur s6.

Le binaire Rust écoute sur le port 80 et le port 443 de l’adresse IPv4 PXE.
La racine HTTP redirige vers `/admin/` en HTTPS. Le preseed, les ressources
de démarrage et les retours d’installation restent disponibles en HTTP.
Rust sert aussi ces ressources sur HTTPS. Le certificat auto-signé est
créé au premier démarrage et conservé dans le répertoire TLS de l’instance.
Pour Docker, réutiliser un volume nommé monté sur `/var/lib/pxe-tools-tls`
pour garder le certificat en recréant le conteneur. Pour reprendre une
paire existante, placer `cert.pem` et `key.pem` dans ce volume avant le
démarrage, avec le répertoire et la clé privés et propriété de root.

La vue HTTPS `/admin/devices` permet de consulter la liste avec le compte
local SQLite existant. Le formulaire d’appellation enregistre le réglage
`ui_device_term` dans la même base et revient à `/admin/devices`. Pour un
accès par nom DNS, définir `PXE_PUBLIC_HOST` avec ce nom pour la redirection
et la validation du formulaire. La gestion des certificats et les autres
écrans d'administration restent à porter.

Les deux variantes fonctionnent sans installer Nginx ni PHP-FPM.
Les migrations des bases existantes et certaines opérations du worker
utilisent encore PHP CLI. Les plans de partition personnalisés, le wipe et les tests de
disques restent à porter. Le renderer prend en charge les interfaces
secondaires DHCP ou statiques, les VLAN secondaires et les bonds. Ces
profils réseau sont vérifiés par comparaison de leur preseed et de leurs
scripts générés. Le parcours de bout en bout utilise une seule interface.

Les essais GitHub construisent les deux livrables sur les runners amd64
et arm64. Ils vérifient HTTP et HTTPS, puis démarrent un client Debian
BIOS amd64 sur un réseau isolé avec un proxy DHCP/TFTP et un miroir Debian
authentifié. Le test de parité couvre également les réponses GRUB.

## Mesurer l'API de suivi

```sh
python3 tests/benchmarks/rust-monitor/benchmark.py --fpm /usr/sbin/php-fpm8.4 > /tmp/pxe-rust-monitor.json
```

Sur macOS, remplacer le chemin FPM par celui de l'installation locale.
Le banc exige un checkout propre et relève son commit dans le JSON.
Il compare PHP-FPM dynamique (plafond de 8), PHP-FPM à la demande
(plafond de 3) et Rust (3 threads). Le scénario historique couvre
80 machines et attend 64 objets de type `install_only`. Par défaut, les
variantes tournent trois fois, avec quatre clients pendant quatre secondes.

Le RSS cumulé additionne les pages partagées entre processus. Sous Linux,
le banc relève aussi la PSS du backend si `smaps_rollup` est lisible et
la pression mémoire de l'hôte via PSI. Les temps de réponse incluent nginx.
Le débit, la première requête après repos et les p50/p95 sont mesurés
depuis le client.

### Mesure historique du prototype

Mac ARM64, PHP-FPM 8.5.12 avec OPcache, nginx 1.31.9 et Rust 1.96. Le
[relevé brut](resultat-mac.json) correspond au prototype initial au commit
`5f83fb980b28de4253a572a0522882a4980dd4fd`. Les valeurs ci-dessous sont
les médianes des trois passages, avec le pic RSS de chaque passage.

| Variante | RSS au repos | Pic RSS sous charge | p95 | Requêtes/s |
| --- | ---: | ---: | ---: | ---: |
| PHP-FPM dynamique | 40,6 Mio | 69,8 Mio | 3,43 ms | 1 827 |
| PHP-FPM à la demande | 9,1 Mio | 37,2 Mio | 3,82 ms | 1 768 |
| Rust | 4,2 Mio | 5,8 Mio | 4,03 ms | 1 469 |

Les 64 objets étaient identiques. Les 1,20 Mio compressés mesuraient le
binaire du prototype Mac. Le banc versionné utilise désormais le vrai
schéma et un socket Unix pour Rust.

## Démarrage Debian sans PHP-FPM

Le [banc QEMU](../../integration/test_rust_debian_pxe_qemu.py) démarre
une machine BIOS inconnue en PXE avec un disque qcow2 jetable. Il utilise
PXELINUX et les fichiers netboot vérifiés contre les index signés Debian.
Après la collecte par le vrai `discover.sh`, le banc programme directement
une action SQLite à partir du numéro de série reçu. Le client redémarre
via le poll de découverte, installe Debian 13 et démarre sur ce disque.
Le test exige l'invite de connexion série, le garde disque réussi, le statut
d'installation `success`, le retour de disponibilité et le checkpoint
`os_first_boot` associé à l'action.

```sh
cargo build --locked --release --manifest-path rust/Cargo.toml
PXE_RUST_QEMU_TEST=1 python3.13 tests/integration/test_rust_debian_pxe_qemu.py --fetch-inputs
```

Le banc demande également `qemu-system-x86_64`, `qemu-img`, `dpkg-deb`,
`gpgv`, nginx avec `ngx_http_sub_module` et au moins 1,5 Gio d'espace
disponible au démarrage. Le réseau QEMU est fermé. Son DHCP/TFTP ne publie
aucun service sur le réseau hôte. Un socket Unix privé relie le client à nginx
et au miroir de fichiers Debian authentifiés. nginx route l'API vers Rust et
ajoute les paramètres série et de miroir propres à la fixture. Aucun PHP-FPM
n'entre dans ce parcours. Le worker et la console sont remplacés par la
programmation et le dépôt d'artefacts de la fixture.

## Qualification native Debian 13 avec dnsmasq

Le [banc natif Rust](../../integration/test_native_rust_debian_pxe.py)
installe le paquet APT local dans une VM Debian 13 amd64. Une seconde VM
démarre en PXE sur un commutateur Ethernet privé, avec le vrai
`pxe-tools-dnsmasq.service` en proxy DHCP/TFTP et un serveur de baux
dans un namespace distinct. La VM serveur accède au miroir Debian
authentifié par un unique relais QEMU vers un socket Unix. La VM cliente
dispose uniquement de la liaison Ethernet privée. Un bail réservé par
MAC garde son adresse lors du passage du firmware à Debian.

Le banc remplace le backend du vhost PXE par Rust dans la VM jetable.
Il conserve le démarrage des services natifs, les répertoires protégés,
la sélection SQLite par `db.conf`, les menus PXELINUX générés et le
rendu des artefacts postboot par la fonction du worker. Il masque les
unités PHP-FPM et surveille leur état et les processus pendant tout
le parcours. Il exige l'invite de connexion Debian, la fin d'installation
en SQLite et l'accusé `accepted` du checkpoint `os_first_boot` associé à
l'action. Le vhost doit observer l'adresse IPv4 réelle du client,
y compris au premier boot.

```sh
python3 packaging/native/build-local-package.py /tmp/pxe-tools-local.deb --version 0.0.1~local1
PXE_NATIVE_RUST_QEMU_TEST=1 python3.13 tests/integration/test_native_rust_debian_pxe.py \
    --cloud-image "$debian13_amd64_qcow2" --cloud-sha512 "$debian13_sha512" \
    --inputs "$debian_netboot_inputs" --package /tmp/pxe-tools-local.deb \
    --rust "$pxe_tools_rust_linux_amd64"
```

L'image est fournie avec sa somme SHA-512. Le répertoire des entrées
netboot correspond à celui conservé par le banc QEMU précédent avec
`--fetch-inputs --keep-fixture`. Le binaire Rust doit être exécutable
sur Debian 13 amd64 et le paquet local se construit hors publication.
Le banc requiert QEMU x86-64, `qemu-img`, `xorriso`, `gpgv` et assez
d'espace pour deux disques QCOW2 jetables. L'option `--mirror-cache`
réutilise les fichiers déjà authentifiés d'un précédent essai.

## Périmètre du renderer et étapes restantes

- Le renderer Rust lit les snapshots SQLite du mode Debian guidé et
  leurs configurations réseau. Il réutilise la base preseed du dépôt et
  les scripts d’identité disque, de journal, de nom d’hôte et de bond du
  renderer PHP. Les plans de partition et les templates personnalisés
  restent à porter. Le renderer refuse les plans qu’il ne sait pas
  interpréter.
- Le binaire de banc reçoit le chemin SQLite explicitement. Il lit les
  empreintes stockées pour préparer Debian. Le banc natif passe le chemin
  choisi par le sélecteur de base existant et vérifie la conservation
  de la clé de fixture pendant le parcours. La reprise des données
  chiffrées avec la clé maître reste à éprouver. La console PHP et le
  worker restent les points d'entrée de l'appliance.
- Sur Debian 13 amd64 avec environ 1 Gio de RAM, mesurer la PSS du service
  et du worker, la pression mémoire PSI, les latences, le débit et la durée
  d'installation. Comparer le `.deb` et l'image Docker complets une fois le
  service intégré. Le socle APT bêta 10 mesure 4,15 Mio et le seuil Cloudflare
  de 25 Mio s'applique par fichier.

## Critères de livraison du portage complet

Le binaire Rust définit les écouteurs HTTP et HTTPS et sert directement la
console d'administration, l'API et les ressources PXE. Les ressources
incluent les menus, scripts, noyaux, initramfs, images et le preseed
dynamique. La configuration expose les écouteurs correspondant à l'instance
et charge le certificat et sa clé depuis les chemins persistants prévus.
Les écouteurs conservent les restrictions du réseau PXE et les protections
de la console et de l'API. Les lectures de fichiers respectent les contrôles
d'accès des artefacts postboot et des payloads netboot.

### Console, écouteurs et certificats

- La liste des appareils a pour URL canonique `/admin/devices`. Le
  réglage `ui_device_term` de la bêta 12 change le libellé dans la console.
  Un changement de libellé conserve la même URL et les liens existants.
- Sur HTTP 80, la racine `/` redirige directement vers `/admin/` en HTTPS
  sur le port 443. La règle vise la seule racine. Les images, le preseed et
  les retours d'installation gardent leurs réponses HTTP directes.
- La gestion TLS fait partie du produit dans le paquet comme dans l'image.
  Le premier démarrage génère un certificat auto-signé propre à l'instance
  et le conserve avec sa clé dans le stockage persistant. La console permet
  aussi d'importer un certificat externe et de configurer l'émission et le
  renouvellement automatiques via ACME. Les trois modes de Proxmox VE
  servent de référence fonctionnelle. Proxmox VE utilise par défaut un
  certificat signé par la CA du cluster, tandis que PXE Tools génère le
  certificat d'instance auto-signé demandé. [Gestion des certificats dans Proxmox VE](https://pve.proxmox.com/pve-docs/pve-admin-guide.pdf)

### Chantiers du portage

| Chantier | Critère de passage |
| --- | --- |
| Assistant initial et données | Sur APT et Docker vierges, créer le compte, confirmer le réseau et choisir une image avant d’activer le PXE. Sur une instance reprise, conserver les utilisateurs, les chemins SQLite, les données chiffrées et la clé maître. |
| Console et API | Porter la connexion locale et Authentik, le parc, les modèles et leurs imports, les installations, les tâches, les images et les réglages. Qualifier les formulaires, l’autorisation et les actions de la fiche appareil jusqu’au worker. |
| Certificats | Servir une paire importée après validation depuis la console. Tester l’émission et le renouvellement ACME avec une autorité de test. Conserver la paire précédente lorsqu’une opération échoue. |
| Profils avancés | Porter les recettes de partition personnalisées, les templates et les opérations de diagnostic. Comparer le rendu et les refus à PHP, puis vérifier l’identité de chaque disque et le système installé sur un banc jetable. |
| Worker et migrations | Porter les migrations SQLite, l’import de modèles et la suppression d’images, puis les familles de tâches en conservant transactions, reprises et compatibilité Ansible. Contrôler le lancement et les tâches sur des livrables sans PHP. |
| Qualification | Construire les deux formats sur Debian 13 amd64 et arm64, valider la reprise d’une instance et les démarrages BIOS et UEFI, puis mesurer les tailles et la mémoire du livrable. |

### Contrôles des deux distributions

1. Remplacer les routes nginx et les appels locaux qui en dépendent par
   le serveur HTTP/HTTPS Rust. Qualifier la console, les API, les téléchargements
   et le preseed sur les deux protocoles. Réutiliser les données SQLite, la clé
   maître, les certificats et les réglages existants après mise à niveau.
   Vérifier l'URL de la liste avant et après un changement de libellé, la
   redirection directe de la racine et les réponses HTTP des clients PXE.
2. Porter les parcours d'installation et d'administration encore pris en charge
   par PHP, ainsi que les migrations et les opérations du worker qui en
   dépendent. Préserver les transitions, les refus et les jetons liés à une action.
3. Installer le paquet APT sur Debian 13 amd64 et arm64 depuis une base sans
   Nginx ni PHP. Construire l'image Docker sans ces paquets, y compris dans ses
   couches. Contrôler les dépendances, les services et les processus au démarrage
   pour les deux distributions, puis tester directement les écouteurs Rust.
4. Sur les runners GitHub isolés, vérifier un cycle PXE jusqu'à la connexion
   Debian et à l'accusé `os_first_boot` pour chaque couple distribution et
   architecture serveur. Exercer le démarrage BIOS et les chemins UEFI pris en
   charge. Vérifier le chargement des ressources PXE et les refus d'accès
   en HTTP et HTTPS selon le client.
5. Tester les trois modes TLS sur chaque distribution. Vérifier la création
   initiale et la conservation du certificat auto-signé au redémarrage, le
   certificat externe réellement servi après import, et l'émission puis le
   renouvellement ACME sur un serveur de test. La clé privée reste dans le
   stockage persistant de l'instance.
6. Mesurer les livrables complets et l'appliance en activité. Comparer la taille
   du `.deb` et de l'image Docker, ainsi que la PSS, la pression mémoire,
   les latences et le débit sous Debian 13 amd64 avec environ 1 Gio de RAM.
