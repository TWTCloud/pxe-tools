# Recette isolée à préparer — désinstallation APT

## Décision du 16 novembre 2026

William a refusé la création du laboratoire et demandé la livraison directe après les contrôles existants. **Aucune VM ni autre ressource de laboratoire ne doit être créée.** Les propositions de recette ci-dessous sont conservées comme historique, et ne sont plus un prérequis de livraison. Les tests sur fixtures et la CI ne démontrent pas un fonctionnement sur Zorin ou sur les autres distributions sans essai réel ; le bilan de diffusion doit le dire. Ne pas exécuter la désinstallation sur le Mac mini, la Zorin de William, le NAS ou l'Atom. Le chat #61 coordonne la publication commune du paquet, du script, du dépôt signé et du site.

Le candidat devient exécutable avec consentement explicite ; la présence d'un journal de retrait impose une reprise explicite. Les contrôles d'activité, de propriété et de préservation restent applicables.

## Ancienne proposition de laboratoire — abandonnée

- Une VM jetable amd64 par système : Debian 12 et 13, Ubuntu 24.04 et 26.04, Zorin OS 18.1 (base Ubuntu noble). Capturer le nom et la version exacts de l'image, le noyau et la version systemd/dpkg. Les dérivés supplémentaires restent non testés.
- Réseau de laboratoire isolé des LAN et de tout client PXE réel, sans accès aux secrets, sauvegardes ni partages de William. Aucun DHCP ne doit atteindre un réseau réel. Utiliser des témoins synthétiques et des noms de domaines réservés.
- Construire les deux DEB candidats à partir du SHA exact à tester dans l'environnement de CI ou de laboratoire autorisé, avec une version locale de test et une clé APT jetable. Publier un dépôt de test uniquement dans le laboratoire ; ne pas modifier le manifeste ni le dépôt APT public. Enregistrer les SHA des paquets, du script et des fichiers du dépôt de test.
- Prendre un snapshot vierge et rétablir une VM propre entre scénarios. Les instantanés et résultats restent dans le périmètre du laboratoire ; aucune suppression de branche ou de worktree n'est nécessaire.

## Scénarios et preuves

1. Installer le socle puis éventuellement `pxe-tools-ansible` depuis le dépôt signé jetable, initialiser des données et secrets synthétiques, vérifier la console et les unités. Comparer l'aperçu aux fichiers et à l'état de paquets réels. Confirmer ensuite la suppression autorisée et vérifier le statut dpkg, les unités et les ressources dont la propriété est prouvée. Recommencer avec et sans module, puis relancer la commande pour vérifier l'absence de dégâts.
2. Depuis un autre snapshot, créer avant installation un nginx personnalisé et un site témoin ; vérifier son contenu, son état actif/enablement et sa réponse avant et après. Répéter avec la situation nginx stock gérée par #61, en comparant le journal avant/après et en testant aussi une modification ultérieure par l'administrateur.
3. Tester clé APT partagée et alias, source modifiée, paquets absents ou partiellement configurés, échec dpkg, service encore actif, job PXE/Ansible en cours et journal de mise à niveau inachevé. Vérifier que l'échec est clair, qu'aucune donnée nécessaire n'est effacée et qu'aucun service tiers n'est interrompu.
4. Créer sous des racines candidates des liens symboliques vers une arborescence témoin et des bind mounts de fichiers et dossiers extérieurs, avec témoins et sommes avant/après. Le script doit refuser ou préserver ces cas sans suivre les cibles ni traverser les montages. Vérifier les parents liés, chemins personnalisés et sauvegardes externes.
5. Tester les comptes préexistants, l'utilisateur `automation` synthétique, le compte de module créé par le paquet et leurs groupes, homes et clés. Vérifier que seuls les éléments dont la création et l'usage exclusif sont prouvés sont candidats au retrait. Contrôler que les clés firmware inscrites ne changent pas.
6. Pour chaque cas : conserver les commandes, codes de sortie, journal dpkg/systemd expurgé, preuves d'état avant/après et SHA exacts ; ne pas recopier de secrets. Documenter tout refus sûr et les ressources préservées. Les tests Mac sur fixtures et les résultats d'une distribution ne valent pas couverture d'une autre.

La FAQ ne peut être publiée qu'après livraison du script final à l'URL exacte et contrôle HTTP de cette URL, en tenant compte du déploiement automatique possible sur la branche principale du site. La publication coordonnée du lot est prise en charge par #61 conformément à la décision de William.

## Reprise explicite et limites

Le script conserve un journal privé hors des arbres à supprimer. Il enregistre les identités de création, les masques et les étapes avant leurs mutations. Après interruption, `--resume` vérifie l’état dpkg et les preuves avant de poursuivre ; une purge partielle, un état de worker ambigu ou une ressource remplacée entraîne un refus et conserve le reçu. Les masques temporaires empêchent les seuls services PXE Tools de redémarrer pendant une purge inachevée ; aucun service autonome de nettoyage n’est installé.

Une installation antérieure sans preuve de création suffisante peut nécessiter une intervention manuelle. La suppression de la source et de la clé APT est limitée aux fichiers créés par l’installateur, avec témoins d’identité et vérification de la configuration APT système effective. Une configuration APT ad hoc utilisée ultérieurement n’est pas inspectable à l’avance. Les chemins personnalisés, montages, sauvegardes externes et ressources tierces non prouvées sont conservés.

Les étapes de restauration avant purge sont journalisées et ne signalent un worker que si son identité et l’action antérieure sont établies. Un changement concurrent par un administrateur root ou un ancêtre cgroup masqué peut rendre l’état impossible à prouver : le script s’arrête alors pour inspection. La reprise doit être demandée explicitement, jamais lancée automatiquement après redémarrage.

La validation automatisée utilise les CI existantes et des fixtures temporaires ; elle ne constitue pas un essai réel sur Zorin, Debian ou Ubuntu. Aucun laboratoire ni nouvelle VM ne sera créé pour cette livraison. La vérification du paquet signé, du manifeste, de l’URL du script et de la publication coordonnée est prise en charge par #61.
