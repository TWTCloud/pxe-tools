# Cycle automatique de mise à niveau APT — candidat

Ce document décrit le correctif de l’issue #56. La bêta 6 publiée conserve son refus d’upgrade lorsque les services sont actifs. Le candidat ne remplace pas les octets de cette version et n’est pas encore distribué dans le dépôt APT.

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

## Validation avant livraison

Les résultats doivent distinguer :

- SQLite et fichiers réels avec systemd simulé ;
- transitions réelles depuis les paquets publics bêta 5 et bêta 6 dans le laboratoire Zorin ;
- proxy actif, DHCP externe actif, réseau arrêté et services déjà arrêtés avec target enabled ;
- échecs de préparation, travail réellement en cours, configuration interrompue et retry ciblé ;
- tests CI Debian et éventuelles autres VM de distribution, sans étendre leur portée par simple similarité de version PHP ou systemd.

Le correctif n’autorise aucun test sur le réseau PXE domestique, aucune modification de l’Atom ou de la machine utilisateur, ni une nouvelle release. Les versions et empreintes exactes du candidat seront figées avec les preuves reçues avant une décision de publication distincte.

## Références

- [Debian Policy, scripts de maintenance et procédure d’installation](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) : ordre ancien/nouveau paquet, échecs et idempotence.
- [systemctl — gel et dégel des unités](https://www.freedesktop.org/software/systemd/man/255/systemctl.html#freeze%20PATTERN%E2%80%A6) : comportement à confirmer sur les versions réellement exécutées.
