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
| Rendu PHP du preseed | Cas de référence sur les accès, le jeton d'action, la fermeture du preseed et les règles de partitionnement. |

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

## Critères du premier démarrage sans PHP-FPM

1. Compléter le portage du dépôt d'inventaire et de sa réconciliation
   multi-interface, du poll `/api/discovery-action` et des configurations
   de boot qui dépendent de PHP. Vérifier les réponses, les refus et les
   états SQLite avec les fixtures de découverte actuelles.
2. Porter le preseed, les retours d'installation et les endpoints de
   checkpoints, journaux et postboot du parcours Debian. Comparer le rendu
   et les écritures avec une base de test clonée. Couvrir le disque
   attendu et un disque d'identité différente, les jetons valides,
   absents et périmés, ainsi que le refus de rouvrir une installation
   terminée. Vérifier la lecture des données et secrets de test existants
   avec la clé maître d'origine. Les routes actuelles restent servies par PHP.
3. Reprendre le
   [banc de boot natif](../../integration/test_native_discovery_install_chain_isolated.py)
   sur une VM Linux jetable avec Docker, `nsenter`, TAP et une image de
   fixture locale. Le scénario existant passe par l'interface PHP pour
   programmer l'installation. Utiliser un état préprogrammé à partir du même
   schéma, ou préparer l'action avant la fenêtre de validation. Sur la
   fenêtre certifiée, contrôler l'arrêt de PHP-FPM et retrouver les hits
   PXE dans les journaux, la fin d'installation en SQLite et l'invite de
   connexion Debian sur le disque qcow2 vierge. Le premier boot est
   aujourd'hui lancé sans carte réseau dans ce banc. Pour attester aussi
   `os_first_boot`, rattacher uniquement ce redémarrage au pont isolé et
   vérifier le checkpoint et son association à l'action.
4. Sur Debian 13 amd64 avec environ 1 Gio de RAM, comparer le service
   complet en veille, sous collecte PDM et pendant le boot. Relever la PSS
   du backend et du worker, la variation des compteurs PSI, les latences,
   le débit et la durée d'installation. Construire et mesurer le `.deb`
   et l'image Docker candidats complets. Le socle APT bêta 10 sert de
   référence à 4,15 Mio. Le contrôle Cloudflare de 25 Mio s'applique
   par fichier. Mesurer aussi les dépendances sur une Debian vierge avec
   le module Ansible facultatif hors du socle.
