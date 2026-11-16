# Désinstallation APT — plan de réalisation

**Objectif :** retrait explicite du socle et du module avec aperçu, garde des ressources partagées et procédure APT claire.

**Architecture :** script Python autonome canonique dans `packaging/native/uninstall-apt.py`, téléchargeable depuis le dépôt produit après fusion. Il refuse les cas dont la propriété ou la mise au repos ne sont pas établies ; il ne touche qu'aux deux paquets et chemins reconnus. La FAQ du site propose ce script et son avertissement seulement une fois l'URL disponible. La provenance nginx reste celle du chantier #61.

1. Tester d'abord les suppressions bornées dans un arbre temporaire : chemins normaux, liens externes, montages, ancêtres inattendus et réexécution. Implémenter les contrôles sans option CLI permettant de changer la racine réelle.
2. Tester l'analyse des sources et clés APT, avec références tierces et sources modifiées ; conserver les cas ambigus. Tester ensuite le comportement des deux paquets et l'arrêt immédiat après échec, avec processus simulés.
3. Réutiliser ou adapter le contrat existant de mise au repos du worker et des opérations, sans modifier les maintainer scripts réservés à #61 ; refuser les états non contrôlables. Tester les échecs et les cas partiels.
4. Ajouter aide, aperçu et consentement explicite ; préciser suppression, sauvegardes et limites. Tester la CLI sans exécuter la suppression sur l'hôte.
5. Préparer la FAQ bilingue avec commande de téléchargement et copie, liée à la disponibilité du script. Valider les deux branches, réconcilier #61 et exécuter les contrôles isolés autorisés. Ne pas publier une version APT ou une FAQ pointant vers un endpoint absent.
