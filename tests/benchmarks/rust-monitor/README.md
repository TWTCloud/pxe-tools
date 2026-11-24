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

L'assistant crée la base SQLite et le premier compte local. Après la
connexion, il propose la console seule, le DHCP externe ou le proxy
DHCP. Le mode PXE vérifie l'adresse IPv4 déjà attribuée à l'interface
sur Linux. L'administrateur choisit ensuite une image Debian du
catalogue. La confirmation finale vérifie les mêmes réglages et attend
le téléchargement avant de mettre les tâches réseau en file. Un
déploiement déjà configuré peut démarrer le paquet avec
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
et la validation du formulaire. La page HTTPS `/admin/certificates` permet
d’importer une chaîne de certificats et sa clé privée au format PEM. Après
vérification de la paire, les nouvelles connexions utilisent le certificat
importé et le service le recharge au redémarrage.
`/var/lib/pxe-tools/tls-import/external.json` contient la clé privée et doit
être conservé avec les données sensibles de l’instance, avec les permissions
du service.

Depuis la fiche d’un appareil inventorié, l’installation guidée choisit
une image Debian 13 publiée pour son architecture et un modèle compatible.
La page `/presets` permet de créer ce modèle. L’opérateur confirme le disque
identifié avant le repartitionnement. Rust vérifie de nouveau l’identité,
l’état de l’appareil et les travaux concurrents avant de programmer le
prochain boot PXE. Le mot de passe du compte installé est stocké sous forme
de hash SHA-512 crypt. Pour une adresse IPv4 statique, la console propose
les DNS configurés dans `/settings` et vérifie que l’adresse du client
appartient au sous-réseau PXE autorisé.

En mode local, la console ouvre `/login` dans le navigateur et conserve la
session HTTPS pendant huit heures. La déconnexion révoque la session.
L’authentification HTTP Basic reste disponible pour les clients en ligne
de commande.

Le mode facultatif `AUTH_MODE=authentik` reprend l’identité transmise par
un reverse proxy qui authentifie le navigateur. Dans Docker, définir
les variables d’environnement du service. En APT, les fournir dans une
surcharge systemd de `pxe-tools-pxe-http.service`. Le proxy établit une
connexion HTTPS à la console et remplace les en-têtes
`X-Forwarded-User` et `X-Forwarded-Host` par les valeurs vérifiées.
`AUTHENTIK_TRUSTED_PROXY_CIDRS` contient les adresses réelles des proxys,
et `PXE_PUBLIC_HOST` accepte le nom DNS public. Rust vérifie le pair
réseau, l’unicité de l’en-tête d’identité et l’origine HTTPS du formulaire.
Le test isolé simule les en-têtes pour les pairs autorisés et refusés.

Pour activer ACME, définir `PXE_PUBLIC_HOST` avec le nom DNS, puis ouvrir
`/admin/certificates` et choisir le mode de test ou de production de
Let’s Encrypt. Le formulaire enregistre le consentement et peut renseigner
un contact. Le nom DNS doit permettre à l’autorité d’atteindre le port
HTTP 80. Le serveur répond au défi HTTP-01 sur ce port. Il renouvelle
le certificat au dernier tiers de sa durée de vie et conserve la paire
précédente si le renouvellement échoue. La désactivation rétablit le
certificat de l’instance. Le certificat externe importé est prioritaire.

Les exploitants peuvent imposer un mode en définissant `PXE_ACME`
(`off`, `staging`, `production` ou `private`) et un contact facultatif
`PXE_ACME_EMAIL`. Sur APT, placer ces variables dans
`/etc/pxe-tools/acme.env`. Pour Docker, utiliser l’environnement du conteneur. Le fichier Compose
transmet ces variables et conserve la paire d’instance dans le volume
nommé `pxe_tls`.
Pour une autorité privée, fournir son URL HTTPS dans
`PXE_ACME_DIRECTORY_URL` et un chemin absolu lisible vers son autorité de
confiance dans `PXE_ACME_CA_FILE`. Ces deux valeurs rendent également
l’autorité privée disponible dans la console quand le mode est piloté
depuis la console. Les fichiers `acme-settings.json`, `acme-account.json`
et `acme-certificate.json` restent dans le dossier privé d’import TLS.

Le banc `test_rust_acme_pebble.py` active le mode privé depuis la console,
exerce deux défis HTTP-01, vérifie la reprise sans l’autorité après
redémarrage, puis désactive ACME. Pebble et son serveur DNS restent sur
la boucle locale.
La page `/settings/images` affiche l’état du catalogue et la progression des
images enregistrées. Elle permet de demander une actualisation du catalogue
et d’ajouter une image Debian amd64 ou arm64. Le téléchargement reste assuré
par le worker. La vue `/jobs` ouvre les tâches du worker, leurs états et
les dernières lignes du journal. Les URL de suivi par identifiant et l’API
de statut par type restent accessibles à la console authentifiée.

La fiche appareil expose son contexte matériel en JSON et programme la
récupération, un nouvel inventaire ou une commande d’alimentation. Pour un
appareil en attente, le prochain appel de découverte reçoit la commande.
Le worker traite les demandes destinées au système installé. La fiche
permet également de demander la synchronisation Ansible, un redéploiement
ou le réessai d’une phase en échec quand le module est activé.
La console permet de sélectionner un modèle Debian 13 et de contrôler
un lot d’appareils. Elle choisit une image disponible pour chaque
architecture, affiche les disques associés et exige une nouvelle
vérification après tout changement du plan avant la programmation.
Un modèle à adresse statique partagée doit être adapté individuellement.
Les pré-effacements affichés demandent une confirmation explicite.
La suppression d’une fiche ou d’un lot verrouille les menus PXE. Si une
suppression échoue, la transaction et les menus sont restaurés. La
réinitialisation du parc supprime les fiches et leur historique. Le worker
efface les menus propres aux anciennes fiches en préservant les menus
partagés et ceux des appareils découverts entre-temps.

La réinitialisation de l’appliance supprime aussi les comptes, les
paramètres, les modèles et les artefacts de démarrage. Le worker désactive
le PXE, efface les fichiers dans les répertoires PXE de l’instance, puis
relance la préparation des chargeurs et de la clé MOK. Le certificat HTTPS
et la clé maître sont conservés. L’assistant local rouvre la création du
compte après le traitement avec le code de configuration.

La page `/settings` enregistre le protocole de découverte et les DNS IPv4
proposés aux prochains déploiements. Elle permet de demander au worker
d’appliquer la configuration, de reconstruire GRUB ou de régénérer la clé
MOK après confirmation. `/settings/ipxe` programme la régénération des
menus après un changement d’option. Les pages affichent les liens des
tâches enregistrées avec le changement.

Les variantes guidées APT et Docker construisent leur environnement
d’exécution sans Nginx ni PHP.
Dans la variante guidée, Rust réserve la suppression d’une image en
contrôlant ses dépendances et en gardant le verrou SQLite pendant que
le worker Rust déplace les trois fichiers autorisés dans le stockage
protégé. La réservation SQLite utilise le compte web. Le worker vérifie
la validation de la transaction avant d’effacer les fichiers mis de côté
et les restaure si la transaction échoue. Rust rend aussi le script et l’unité postboot
par action à partir des variables du worker. Ce rendu accepte les variables
`pxe_ip`, `mac` et `token` des templates livrés. Rust reprend les anciens
réglages réseau SQLite en gardant les choix explicites et le mode PXE
existant. La variante guidée peut recréer la configuration d’accès à une
base existante détectée par l’installateur. Son démarrage exécute en Rust
les contrôles de compatibilité et les migrations SQLite, dont les anciens
modèles, leurs snapshots d’installation, le netboot et les réglages du module
Ansible facultatif.
Pour les tâches de préparation PXE, Rust réserve chaque tâche SQLite,
lance l’outil système correspondant et enregistre la sortie et le résultat.
Le socle APT et Docker lance la boucle du worker en Rust. Elle attend la
configuration SQLite, respecte l’ordre des tâches de préparation MOK et
GRUB et clôture la phase post-installation sans rôle après le retour de
premier démarrage ou son délai. Rust efface au lancement les mots de passe
Vault temporaires d’une exécution interrompue. Les opérations qui utilisent encore du
code Python, dont l’exécution des playbooks et la synchronisation des
dépôts Ansible, le démarrent à la demande.
Rust réserve aussi chaque téléchargement une seule fois et vérifie
son état à l’issue du script. L’actualisation automatique attend la fin des
opérations PXE et enregistre la date du dernier succès dans la même
transaction que le résultat.
La reprise du worker remet en file les téléchargements
et suppressions interrompus et conserve le journal de suppression.
Rust actualise les six catalogues d’images et planifie le téléchargement
des remplacements Debian. Le worker vérifie leur intégrité avant de les
publier. L’import des modèles du dépôt Ansible utilise le même binaire
pour valider le rôle, la recette de disque et les interfaces de référence.
Pour un modèle Debian 13 à partition personnalisée et réseau DHCP, la
console vérifie le firmware, la capacité et l’identité des disques, puis
affiche les cibles à confirmer. La confirmation devient caduque si le modèle,
l’image ou le matériel vérifié change. Le rendu est vérifié avant
d’enregistrer l’action et le garde-fou recontrôle les disques au démarrage.

Le renderer couvre les recettes de partition
sur un disque identifié, avec partitions physiques BIOS ou UEFI. Un plan
LVM sur ce disque peut définir ses groupes de volumes et volumes logiques.
La vérification compare le rendu à PHP et refuse les volumes qui désignent
un groupe ou une partition physique absente. Les plans LVM peuvent
référencer des PV supplémentaires sur des disques identifiés. Le profil
RAID place la racine sur une grappe avec une recette BIOS GPT symétrique.
Les essais différentiels couvrent le rendu des niveaux 0, 1, 5, 6 et 10,
dont des disques de secours pour les niveaux redondants. Le banc amd64
vérifie séparément le démarrage sur une racine RAID1 ou RAID5. Un plan BIOS
GPT symétrique peut aussi déclarer deux grappes, une pour `/boot` et une
pour le PV d’un unique groupe LVM contenant la racine. Le profil de banc
`1-lvm` vérifie la racine LVM et les deux grappes depuis le système installé.
[Recette LVM sur RAID de Debian](https://sources.debian.org/src/debian-installer/20250803%2Bdeb13u8/doc/devel/partman-auto-raid-recipe.txt)

Rust refuse
les membres ambigus ou réutilisés, les recettes RAID asymétriques et les
recettes multi-disques en mode régulier. La console programme des tests
SMART ou de surface, collecte leurs résultats et permet de modifier
l’action de fin ou d’annuler le suivi. Le test de parité vérifie la
rotation du jeton de session, sa liaison à l’adresse DHCP observée, la
progression et les instantanés SMART. Le parcours d’installation peut
enchaîner la qualification du disque et l’installation avec leurs actions
et jetons propres.
La console peut aussi programmer un effacement de plusieurs disques après
confirmation explicite. Le script vérifie à nouveau leur identité et
utilise un jeton propre à l’opération. Le test de parité couvre aussi
l’enchaînement d’un effacement déjà planifié vers son installation.
Le renderer prend en charge les interfaces
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

## Périmètre du renderer et étapes restantes lors du premier banc

- Le renderer Rust lit les snapshots SQLite du mode Debian guidé et
  leurs configurations réseau. Il réutilise la base preseed du dépôt et
  les scripts d’identité disque, de journal, de nom d’hôte et de bond du
  renderer PHP. Le banc compare aussi les recettes personnalisées d'un
  disque physique et vérifie le garde-fou BIOS ou UEFI. Les recettes
  multi-disques, LVM et RAID ainsi que les templates personnalisés
  restent à porter.
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
| Qualification | Construire les deux formats sur Debian 13 amd64 et arm64, valider la reprise d’une instance et les démarrages BIOS et UEFI avec Secure Boot, puis mesurer les tailles et la mémoire du livrable. |

### Reprise APT et désactivation du PXE

Sur `b44a5b0`, deux VM Debian 13 amd64 ont installé le paquet APT publié
de la bêta 12, puis le candidat Rust `0.1.0~rust1` depuis un dépôt signé
avec une clé de test. Le socle seul et le scénario avec proxy DHCP et
module Ansible ont conservé la clé maître, la base SQLite, le compte
administrateur, les données chiffrées et les fichiers témoins. Le test
vérifie le processus Rust et l’accès HTTPS après remplacement des services
PHP et Nginx de PXE Tools. Le module Ansible conserve son identité et son
runtime. [Socle](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45318129101/job/138189845916) ·
[Module Ansible et proxy DHCP](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45318129101/job/138189846255)

Pour une reprise Docker depuis la bêta 12, conserver les volumes de la
configuration et des données, puis ajouter le volume privé monté dans
`/var/lib/pxe-tools-tls`. Au premier démarrage, l’image guidée y reprend
la paire TLS historique depuis le volume de données après vérification
des chemins, des permissions et de la correspondance entre la clé et le
certificat. Le même démarrage peut reprendre une copie interrompue si la
partie déjà copiée correspond à la paire existante.

Les deux livrables amd64 sur `69fbe8a` vérifient aussi que l’arrêt du
PXE ferme l’écoute sur l’interface de test et garde la console HTTPS
sur la boucle locale. Un client distinct installe ensuite Debian sur un
second banc et remet le retour de premier démarrage `os_first_boot`.
[APT](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45317928052/job/138189193598) ·
[Docker](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45317928052/job/138189194848)

### UEFI, Secure Boot et premier déploiement Windows

Les qualifications PXE tournent dans GitHub Actions sur le dépôt PXE Tools.
Sur une PR issue du dépôt, l’ajout du label `ci:pxe-debian` lance la matrice
APT et Docker amd64/ARM64. Le label `ci:pxe-windows` lance le banc Windows
avec les médias Microsoft sur le runner Windows. Le label `ci:pxe-raid-lvm`
exerce le profil LVM sur RAID1 avec APT amd64. Chaque workflow récupère
le SHA exact de la PR. Le déclenchement manuel est aussi disponible
depuis Actions une fois les workflows présents sur la branche par défaut.

Le client de test Debian x86-64 utilise OVMF avec Secure Boot actif.
Le banc prend le shim et le GRUB signés que fournit le serveur, inscrit
la clé publique MOK de l’instance d’essai dans une copie privée des
variables du firmware et demande une preuve d’activation dans
l’inventaire de découverte puis dans le premier démarrage installé.
L’architecture du serveur et celle du client sont distinctes.
Le worker des distributions Rust sur ARM64 prépare par défaut le shim et le
MokManager ARM64 authentifiés depuis Debian, puis publie un GRUB ARM64
signé par la MOK de l’instance. L’option `PXE_ARM64_SECURE_BOOT=1` active
cette chaîne sur un serveur amd64. Le preseed trixie demande les paquets
signés adaptés à l’architecture du client UEFI. Les bancs APT et Docker
lancent un invité AArch64 avec AAVMF sur le runner GitHub ARM64. Sur
`14b5188`, les deux ont vérifié Secure Boot dans l’inventaire et au premier
démarrage du disque. Le serveur a accepté `os_first_boot` avec PHP-FPM
arrêté. Le test sur un appareil physique reste à mener.
[APT ARM64](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45306043139/job/138150020539) ·
[Docker ARM64](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45306043139/job/138150020332) ·
[GRUB signé ARM64 de Debian](https://packages.debian.org/trixie/arm64/grub-efi-arm64-signed/filelist)

Sur `b64f5cd`, APT a confirmé le résultat. Le client Docker a atteint
l’installateur signé et le garde-fou disque, puis a affiché un échec de
l’installation de GRUB. Le banc ARM64 recueille désormais les messages de
l’installateur liés au chargeur dans le segment isolé.
[APT](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45306396700/job/138151182095) ·
[Échec Docker](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45306396700/job/138151181785) ·
[Journal distant dans l’installateur Debian](https://www.debian.org/releases/trixie/arm64/ch05s03.en.html)

Sur `4634f8d`, la matrice ARM64 a repassé les deux parcours Secure Boot,
jusqu’à l’écran de connexion et au checkpoint accepté sans PHP-FPM.
[APT ARM64](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45315004920/job/138179622076) ·
[Docker ARM64](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45315004920/job/138179621919)

Le banc Windows utilise Windows 11 Enterprise Evaluation amd64. L’instance de
test doit disposer d’un firmware UEFI, de Secure Boot actif, d’un TPM
virtuel 2.0 et d’un disque vierge jetable. Préparer WinPE avec le module
complémentaire de l’ADK et les composants WMI, PowerShell, StorageWMI,
SecureStartup et SecureBootCmdlets requis par la sonde. Le média Windows
et le WIM WinPE sont fournis au banc sous forme de fichiers de test avec
empreintes SHA-256 approuvées. [Prérequis Windows 11](https://learn.microsoft.com/windows/whats-new/windows-11-requirements) · [Composants optionnels de WinPE](https://learn.microsoft.com/windows-hardware/manufacture/desktop/winpe-add-packages--optional-components-reference)

- Créer une VM isolée avec un UUID SMBIOS et un numéro de série de disque
  uniques au test. Connecter la carte au segment privé des services DHCP,
  TFTP et WinPE du banc. Donner la priorité au démarrage réseau. Le disque
  est vierge et l’ISO d’installation est présent en lecture seule.
- Démarrer un iPXE signé sur le réseau isolé et le chaîner vers
  `http://<serveur-pxe>/pxe/windows/boot.ipxe`. Cette route Rust est activée
  pour une adresse réservée avec `PXE_WINPE_CLIENT_IP`. Le client réservé
  qui atteint l’entrée iPXE habituelle `/boot.ipxe` est dirigé vers WinPE
  s’il est en UEFI amd64. Le menu Debian reste disponible via
  `/boot.ipxe?menu=debian`. La route WinPE sert le script
  UEFI x86-64 et les quatre fichiers préparés dans `winpe/amd64` sous la
  racine HTTP de l’instance, `wimboot`, `BCD`, `boot.sdi` et `boot.wim`.
  Utiliser un `wimboot` signé et un WinPE personnalisé pour Windows 11.
  Préparer la preuve du transfert EFI et du WIM
  côté serveur. Exécuter la sonde `collect.ps1` dans WinPE, puis déployer
  l’édition attendue sur le disque jetable. [Secure Boot avec iPXE](https://ipxe.org/secboot) · [Prise en charge de WinPE pour Windows 11](https://learn.microsoft.com/windows/deployment/wds-boot-support)
- Pour le premier démarrage installé, démarrer depuis le disque et exécuter
  à nouveau la sonde. Elle écrit ses mesures sur le port série. Le
  vérificateur exige les deux phases et contrôle l’identité, le disque
  initialement vierge, la partition système GPT, Secure Boot et le TPM 2.0.
- Exécuter le banc sur un runner jetable disposant des médias autorisés.
  Le runner Windows prépare les médias avec l’ADK et utilise WSL 2 avec
  Docker et KVM pour exécuter le banc Linux sur place. Les médias restent
  dans le stockage temporaire du runner. Seuls les journaux de test
  sont visibles dans GitHub Actions.

Sur le poste de préparation Windows isolé, le script
`tests/support/windows-pxe/prepare-winpe.ps1` utilise l’ADK et son
complément WinPE déjà installés. Il vérifie les empreintes de l’ISO et de
`wimboot` fournies au banc, ajoute les composants nécessaires et lance la
sonde depuis `startnet.cmd`. Le répertoire de sortie doit être neuf. Son
sous-répertoire `boot` et son manifeste `case.json` restent privés et
temporaires. [Personnalisation WinPE](https://learn.microsoft.com/windows-hardware/manufacture/desktop/winpe-mount-and-customize?view=windows-11)

```powershell
.\tests\support\windows-pxe\prepare-winpe.ps1 `
  -WindowsIso $iso -WindowsIsoSha256 $isoSha256 -Wimboot $wimboot `
  -WimbootSha256 $wimbootSha256 -OutputDirectory $output `
  -GuestId $guestId -DiskSerial $diskSerial -Edition $edition
```

Pour l’installation automatisée, fournir en plus `-InstallImageIndex`
avec l’index de l’édition approuvée. La VM démarre WinPE par le réseau et
accède à l’ISO Windows sur un lecteur optique en lecture seule, sans le
sélectionner comme périphérique d’amorçage. WinPE exige Secure Boot, un
TPM 2.0, l’UUID du banc et un seul disque modifiable, vierge et identifié
par son numéro de série. DISM applique l’image sur ce disque. La sonde
s’exécute de nouveau pendant le premier démarrage, dans la phase
`specialize`. Les deux étapes déposent leur preuve dans la partition EFI
du disque jetable et arrêtent la VM. Le banc relit les fichiers après
chaque arrêt sans monter la partition en écriture.

Le manifeste du cas contient `guest_id` (UUID), `disk_serial`,
`edition` (par exemple `Professional`), `iso_sha256` et
`winpe_sha256`. La preuve réseau produite côté serveur contient
`guest_id`, `architecture` (`uefi-amd64`),
`efi_boot_manager_transferred` et `winpe_sha256`. Le journal série
contient les lignes émises par `tests/support/windows-pxe/collect.ps1`.

```bash
python3 tests/integration/verify_windows_pxe_deployment.py \
  --case "$case" --iso "$windows_iso" --winpe "$winpe_wim" \
  --network-proof "$network_proof" --serial "$serial_log"
```

Le banc Linux `tests/integration/test_windows_pxe_isolated.py` requiert
un runner amd64 jetable avec QEMU, les images de test Docker et un
répertoire de médias préparé pour le test. Y placer `windows.iso`,
`case.json`, `boot/` et les deux binaires Secure Boot amd64 issus de la
même livraison iPXE dans `ipxe/`, `ipxe-shim.efi` et `ipxe.efi`. Le
manifeste ajoute leurs empreintes dans `ipxe_sha256`. Le banc vérifie
les médias, crée son propre réseau sans route par défaut, un TPM
jetable et un disque qcow2 neuf. Le second démarrage ne monte plus l’ISO
et doit produire la preuve Windows depuis le système installé. L’accélération KVM
est utilisée par défaut. L’option `--accelerator tcg` permet de répéter le
même parcours avec le processeur émulé, Secure Boot et TPM 2.0 actifs.

L’option `--boot-root` vérifie aussi les quatre fichiers publiés avec
`wimboot_sha256`, `bcd_sha256`, `boot_sdi_sha256` et `winpe_sha256` dans le
manifeste. Le banc des paquets utilise des fichiers synthétiques pour vérifier
le script, les plages HTTP et le refus d’un autre client. Le banc GitHub a
vérifié les médias réels obtenus auprès de Microsoft. Sur `7e6071e`, le
client iPXE signé a atteint le script Rust et demandé les quatre fichiers.
Rust a répondu en HTTP 200, dont une réponse de 502 104 147 octets pour le
WIM. Le banc KVM s’est arrêté sans preuve série WinPE.
[Journal Windows KVM](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45316153541/job/138183384980)

Sur `a1a0f5f`, QEMU TCG exécute le WinPE personnalisé après amorçage
PXE. La sonde atteint l’écriture de sa preuve après les contrôles du
firmware, du TPM et du disque vierge. Elle échoue parce que WinPE ne
voit pas COM1, avant l’application de l’image Windows au disque.
[Journal Windows TCG](https://github.com/williamboglietti/pxe-tools-rust-lab-20261123/actions/runs/45320450489/job/138197444715)

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
