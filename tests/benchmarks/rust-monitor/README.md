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
| Retours Debian | Démarrage local et réessais, journal borné, accès aux artefacts postboot, fin d'installation avec jeton lié à l'action, checkpoint du premier démarrage. |

Les requêtes de mutation utilisent deux copies d'une même fixture. Le test
compare les écritures SQLite et vérifie que le catalogue compilé dans Rust
correspond à celui de PHP. Les pings de découverte et la sélection GRUB
regroupent leurs écritures dans une transaction. Une erreur d'écriture
annule l'ensemble de la mutation Rust.

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
dispose uniquement de la liaison Ethernet privée.

Le banc remplace le backend du vhost PXE par Rust dans la VM jetable.
Il conserve le démarrage des services natifs, les répertoires protégés,
la sélection SQLite par `db.conf`, les menus PXELINUX générés et le
rendu des artefacts postboot par la fonction du worker. Il masque les
unités PHP-FPM et surveille leur état et les processus pendant tout
le parcours. Il exige l'invite de connexion Debian, la fin d'installation
en SQLite et le checkpoint `os_first_boot` associé à l'action. Le vhost
doit observer l'adresse IPv4 réelle du client, y compris au premier boot.

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

- Le renderer Rust lit les snapshots SQLite du mode Debian guidé avec une
  seule interface DHCP ou statique. Il réutilise la base preseed du dépôt
  et les scripts d'identité disque, de journal et de nom d'hôte du renderer
  PHP. Les plans de partition personnalisés, les réseaux multi-interface,
  VLAN et bonds ainsi que les templates personnalisés restent à porter.
  Le renderer expérimental refuse les plans qu'il ne sait pas interpréter.
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
