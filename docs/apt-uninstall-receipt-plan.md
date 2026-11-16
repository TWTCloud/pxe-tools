# Recette isolée à préparer — désinstallation APT

Ce plan n'est pas une preuve d'exécution et ne constitue pas une autorisation de créer une VM ou de publier une version APT. Le script candidat reste verrouillé tant que les preuves de propriété des données et le contrat nginx de #61 ne sont pas intégrés et revus. Ne l'exécuter ni sur le Mac mini, ni sur la Zorin de William, ni sur le NAS ou l'Atom.

## Environnement proposé

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

La FAQ ne peut être publiée qu'après livraison du script final à l'URL exacte et contrôle HTTP de cette URL, en tenant compte du déploiement automatique possible sur la branche principale du site. La publication d'un nouvel ensemble APT reste une décision distincte.
