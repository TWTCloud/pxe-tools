# Cycle automatique de mise à niveau APT — bêta 7 publiée

Ce document décrit le correctif de l’issue #56, publié le 15 novembre 2026 dans la [release v0.1.0-beta7](https://github.com/williamboglietti/pxe-tools/releases/tag/v0.1.0-beta7) et le dépôt APT signé. La [publication APT, run 43719131612](https://github.com/williamboglietti/pxe-tools/actions/runs/43719131612), a réussi après l’accord de publication. Les anciens paquets bêta 6 conservent leur refus d’upgrade lorsque les services sont actifs ; leurs octets et leurs liens immuables restent conservés.

## Comportement recherché

Une mise à niveau APT normale, y compris sans terminal interactif, doit assurer sa propre fenêtre de maintenance lorsque l’instance est au repos. L’administrateur ne doit pas arrêter manuellement les neuf unités ni fournir une phrase de passe à chaque mise à jour. Aucun cron, daemon ou réglage global unattended-upgrades n’est ajouté.

Le paquet conserve les états actifs et les politiques enabled/disabled. Il vérifie quelle base et quelle clé sont effectivement utilisées, quiesce le worker et les points d’entrée, puis prépare un snapshot local privé avant le remplacement et les migrations existantes. Il redémarre ensuite les seuls rôles précédemment actifs. Les noms de compte, les réglages, les données, la clé maîtresse et l’état d’onboarding ne sont pas réinitialisés. Un réseau PXE auparavant arrêté n’est pas activé.

## Travaux en cours

Le fonctionnement d’un service ne constitue pas une occupation bloquante. Les tâches techniques simplement en attente restent en file pour le nouveau worker. En revanche, une opération démarrée ou une tâche client PXE déjà engagée peut nécessiter un refus conservateur : une absence de processus local ne prouve pas la fin d’un travail distant.

Un refus doit indiquer le type et l’identifiant de l’opération à terminer ou à examiner dans l’interface, sans imprimer de jeton, mot de passe ou contenu de configuration. Le paquet ne modifie pas les statuts en base pour contourner cette barrière.

La barrière worker doit être validée sous systemd réel, et non seulement avec des doublures de test. Les transitions entre inspection de la base, gel, arrêt et redémarrage sont particulièrement importantes : arrêter nginx ou PHP trop tôt pourrait arrêter le worker par dépendance, avant le contrôle de son activité.

## Snapshots et reprise

Les snapshots automatiques restent sur le même disque, dans un répertoire réservé à root. Ils sont non interactifs et ne constituent ni une sauvegarde distante ni une garantie de rollback de schéma. Ils conservent notamment la base cohérente, la configuration et la clé effective, ainsi que les petits fichiers natifs nécessaires avec leurs empreintes et métadonnées. Les médias HTTP/TFTP et ISO ne sont pas recopiés à chaque upgrade.

La rétention est limitée aux snapshots automatiques terminés et reconnus. Une archive manuelle ou un état en échec/en attente doit être conservé.

Avant dépaquetage, une erreur de préparation peut reprendre l’ancien état seulement si aucun remplacement n’a eu lieu. Après un échec de dépaquetage, les fichiers peuvent être mixtes : ne pas relancer aveuglément l’ancien programme ni réinjecter une base. Après un échec de configuration ou de migration, le journal et le snapshot antérieur restent disponibles ; la reprise garde l’intention initiale plutôt que de capturer les services désormais arrêtés comme nouvel état voulu.

Une correction suivie de `sudo dpkg --configure pxe-tools` est une reprise ciblée envisageable dans le cas d’un paquet dépaqueté mais non configuré. Elle ne remplace pas le diagnostic d’un autre état dpkg ni ne justifie `dpkg --configure -a`, `--fix-broken` ou une suppression de fichiers à l’aveugle.

## Réception du cycle avant diffusion

Les résultats doivent distinguer :

- SQLite et fichiers réels avec systemd simulé ;
- transitions réelles depuis les paquets publics bêta 5 et bêta 6 dans le laboratoire Zorin ;
- proxy actif, DHCP externe actif, réseau arrêté et services déjà arrêtés avec target enabled ;
- échecs de préparation, travail réellement en cours, configuration interrompue et retry ciblé ;
- tests CI Debian et éventuelles autres VM de distribution, sans étendre leur portée par simple similarité de version PHP ou systemd.

Les essais décrits ici n’autorisaient aucun test sur le réseau PXE domestique, aucune modification de l’Atom ou de la machine utilisateur, ni une nouvelle release. Les versions et empreintes exactes reçues sur Zorin sont consignées ci-dessous ; la publication bêta 7 a ensuite reçu un accord distinct.

## Références

- [Debian Policy, scripts de maintenance et procédure d’installation](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) : ordre ancien/nouveau paquet, échecs et idempotence.
- [systemctl — gel et dégel des unités](https://www.freedesktop.org/software/systemd/man/255/systemctl.html#freeze%20PATTERN%E2%80%A6) : comportement à confirmer sur les versions réellement exécutées.

### Résultats reçus sur le code `ce09d2ca`

| Environnement | Réception effective |
|---|---|
| Zorin OS 18.1, systemd 255, VM Hyper-V | Vraies transactions APT non interactives depuis bêta 5 (proxy actif) et bêta 6 (DHCP externe actif, console seule, toutes unités arrêtées mais target enabled). Aucun préarrêt manuel du candidat ; reprise exacte des rôles et enabled, données/clé/configuration/médias et compte préservés, sans reset du wizard. |
| Zorin, travail concurrent | Vrai refresh catalogue avec enfants du worker : refus conservateur reçu, mêmes PID/starttimes encore présents au refus, puis fin normale du travail. Aucun enfant n’est tué pour forcer la mise à niveau. |
| Zorin, configure échoué | Faute PHP de laboratoire : journal et snapshot initial conservés ; après retrait du seul drop-in fautif, `dpkg --configure pxe-tools` reprend la même transaction et réussit sans rollback de base. |
| Debian 12, systemd 252.39, VM existante | Bêta 6 publique authentifiée → candidat 7 par APT, administration active et réseau arrêté, puis réinstallation du même candidat : réussite, rôles/enabled et données préservés. |
| Ubuntu 26.04.1, systemd 259.5, VM existante | Même transition et réinstallation réussies ; administration active avec policy disabled conservée et réseau arrêté. |
| Debian 13, CI | Suite applicative complète, tests SQLite/fichiers et cycle avec systemd simulé. Pas de transaction systemd réelle Debian 13 dans cette recette. |
| Ubuntu 24.04 direct | Pas de nouvelle VM vanilla dans cette recette ; Zorin fournit une réception réelle de sa base Ubuntu noble, sans équivaloir à une validation directe de toutes les installations Ubuntu 24.04. |

Les baselines de distribution ont été préparées dans des VM de laboratoire existantes, avec archives privées ; ce ne sont pas des OS vierges. Les commandes APT utilisent des sources/listes de fixture isolées et le vrai status dpkg, pas une mise à niveau globale de tous les paquets de l’OS. Aucun trafic PXE sur le LAN réel, poste utilisateur, Atom ou NAS n’a été utilisé.

Le candidat initial `6835b67` échouait réellement au dégel sur Debian 12. Le correctif évite la terminaison fatale du main avant normalisation du freezer : gel vérifié, pause SIGSTOP ciblée après contrôle d’identité, dégel systemd/noyau vérifié, même processus à l’arrêt, puis arrêt standard TERM/CONT. Le pont et sa compensation ont été reçus en vrai ; le contrôle PID/starttime/cgroup avant signal n’est pas une garantie d’atomicité face à une intervention extérieure entre contrôle et signal.

Les paquets de laboratoire ont des métadonnées Maintainer propres aux essais et leurs hashes diffèrent. Ils ne sont pas promus comme artefacts de publication. La réception du build canonique exact est consignée ci-dessous ; elle ne transforme pas les essais Debian et Ubuntu précédents en réception de ces octets.

### Réception des paquets canoniques sur Zorin

Le 15 novembre 2026, le smoke réel sur la VM Zorin OS 18.1 a réussi avec les paquets de la source `52c31ffc98df79c8a31b7239ada652a5c9e11e12`, issus du [run GitHub Actions 43711527397](https://github.com/williamboglietti/pxe-tools/actions/runs/43711527397).

| Paquet canonique `0.1.0~beta7` | SHA-256 |
|---|---|
| `pxe-tools` | `cca1e2978716acad39cd654c996fd487d272e19c01c6d33bb07d66aff93c6467` |
| `pxe-tools-ansible` | `2a03855e5045191220f2124febff1ec244dc7ae2840e86f6b802e093b5f58790` |

Les deux paquets publics bêta 6 étaient déjà installés. Une transaction `DEBIAN_FRONTEND=noninteractive apt-get -y upgrade`, avec sources/listes/cache APT de fixture isolés et le vrai status dpkg, les a mis à niveau vers ces deux paquets canoniques bêta 7 sans préarrêt manuel ; APT a terminé avec le code zéro. Ce parcours vérifie la mise à niveau normale des deux paquets installés, sans mise à niveau globale des autres paquets de l’OS.

La réception a vérifié :

- la conservation exacte des états actifs et des politiques de démarrage des neuf unités ; l’administration reprend, le réseau PXE et le proxy restent arrêtés ;
- la conservation des données, de la configuration, de la clé, des médias, du compte et de l’assistant terminé ;
- le runtime Ansible `ready`, avec son compte, ses groupes, son espace de travail et son drop-in conservés ;
- le snapshot `93a7b56bef384f519044e49350c9ea74` en phase `complete`, une intégrité SQLite `ok`, des répertoires root `0700` et des fichiers `0600`, sans journal inachevé ;
- le worker dégelé et le PID du nginx système étranger à PXE Tools inchangé ;
- la correspondance du payload installé avec les DEB canoniques : 406 entrées du socle et 11 du module, plus les quatre scripts de maintenance de chaque paquet.

La preuve locale de cette réception est `canonical-zorin-smoke.json`, conservée dans le dossier d’audit de la préparation de diffusion. Cette réception n’établit ni une comparaison binaire ni une nouvelle transaction de ces octets sur Debian ou Ubuntu ; elle ne valide aucun boot client PXE ou matériel physique supplémentaire.

### Publication et réception du dépôt public

Après l’accord de publication, la [release v0.1.0-beta7](https://github.com/williamboglietti/pxe-tools/releases/tag/v0.1.0-beta7) a publié les deux DEB canoniques de la source `52c31ffc98df79c8a31b7239ada652a5c9e11e12` et du build `43711527397`, avec les SHA-256 ci-dessus. Le manifeste de production a été intégré par la PR #59 au commit `e31c7ae8f0610311350346f0a0d62767b12e2270` ; sa [CI après fusion, run 43719060899](https://github.com/williamboglietti/pxe-tools/actions/runs/43719060899), puis la [publication APT signée, run 43719131612](https://github.com/williamboglietti/pxe-tools/actions/runs/43719131612), ont réussi.

La réception publique du 15 novembre 2026 a vérifié l’InRelease signé avec la clé primaire et la sous-clé attendues, sa validité jusqu’au 22 novembre 2026, les index SHA-256/SHA-512 et leurs accès by-hash. Les deux paquets `0.1.0~beta7` sont téléchargeables anonymement avec HTTP 200 et leurs empreintes correspondent aux DEB canoniques. Les liens immuables des deux paquets bêta 6 restent accessibles et leurs empreintes ont été vérifiées. La preuve locale est `public-apt-receipt.json`, conservée dans le dossier d’audit de la publication.

Cette réception confirme la distribution publique des octets reçus sur Zorin ; elle ne constitue ni une nouvelle transaction APT sur un client, ni une réception supplémentaire sur Debian ou Ubuntu, ni un nouveau boot PXE ou matériel physique.
