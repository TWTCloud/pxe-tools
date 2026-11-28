# Configuration réseau au premier démarrage

## Choisir plusieurs réseaux

Dans l’assistant ou dans **Paramètres → Réseau**, cochez les interfaces qui
desservent les appareils. Choisissez une IPv4 par interface et des sous-réseaux
distincts. La liste indique l’adresse PXE que les clients utiliseront sur
chaque réseau. Avec un DHCP externe déjà configuré pour PXE, annoncez sur chaque
réseau l’adresse indiquée pour ce réseau, dans les options de démarrage du DHCP.

Les installations déjà configurées conservent leur sélection à la mise à niveau.
L’adresse peut être redétectée au démarrage dans le sous-réseau associé.

L’ISO automatique Proxmox VE embarque une adresse HTTPS et l’empreinte du
certificat. Ce média est utilisable sur le réseau pour lequel il a été préparé.

Ce parcours est un candidat de développement ; il ne modifie pas une installation existante tant que les réglages ne sont pas enregistrés et appliqués. Sa validation et sa publication dans une nouvelle version APT sont deux étapes distinctes.

## Parcours courant

Le serveur détecte les adresses IPv4 de ses interfaces et présente une proposition cohérente : interface, adresse actuelle et réseau correspondant. Ces valeurs sont lues sur la machine qui exécute PXE Tools. Une suggestion n'atteste ni le câblage vers les clients, ni la présence d'un DHCP externe, ni l'absence d'un autre serveur PXE.

Une seule connexion utilisable peut être proposée directement. Plusieurs connexions ou adresses, une interface virtuelle ou un réseau inaccessible nécessitent un choix explicite. Un bridge peut être légitime ; il ne faut pas l'écarter systématiquement. Les réglages avancés restent disponibles pour les réseaux distants et les configurations particulières.

Le mode de démarrage distingue :

- **Console seule** : configurer et consulter PXE Tools sans servir le démarrage réseau.
- **Démarrage avec proxy DHCP** : le DHCP existant continue d'attribuer les adresses IP ; PXE Tools fournit les indications de démarrage aux clients du réseau choisi. Ce mode demande une activation explicite.
- **Démarrage avec un DHCP déjà configuré pour PXE** : le DHCP externe fournit les indications de démarrage et PXE Tools sert les fichiers. Il faut configurer ce DHCP séparément.

Les deux réglages avancés de réseau ont des usages distincts : `pxe_subnet` délimite les clients autorisés à certains endpoints PXE ; `dhcp_proxy_network` et `dhcp_proxy_netmask` définissent la portée du proxy dnsmasq. Le cas courant utilise le même réseau détecté, mais une configuration existante peut avoir des valeurs différentes.

Au démarrage, PXE Tools retrouve l’IPv4 de l’interface choisie. Si l’ancienne
adresse a disparu, le service reprend une adresse de remplacement unique sur
le même réseau et dans la portée du proxy DHCP lorsqu’il est activé. Il
reconstruit les chargeurs et les menus avant d’annoncer la nouvelle adresse.
Si l’interface est absente ou si plusieurs adresses sont possibles, la console
reste disponible et indique que le démarrage PXE est suspendu.

## Console et services de démarrage

Sur une instance neuve, `sudo pxe-tools setup` fournit un lien HTTPS vers
l’assistant. Le code se trouve dans le fragment du lien (`#code=…`) et reste
dans le navigateur jusqu’à la validation du formulaire. Vous pouvez aussi
saisir le code manuellement. Après validation, créez le compte puis
connectez-vous avec son identifiant et son mot de passe.

La console Rust en APT et Docker utilise le port HTTPS TCP 443 par défaut.
Le démarrage utilise TCP 80 en HTTP, UDP 69 pour TFTP et UDP 67/4011 pour le proxy DHCP.

Dans **Paramètres → Accès à la console**, autorisez le nouveau port dans votre
pare-feu, puis cliquez sur **Tester le port**. Ouvrez le lien proposé et
confirmez sur le nouveau port dans les deux minutes. Si le lien est
inaccessible, l’ancien port reste utilisable et l’essai expire.
Préparez de nouveau les médias Proxmox VE qui incorporent l’ancienne URL HTTPS.

Si le port 443 est occupé lors d’une installation APT, le paquet déballé permet
d’enregistrer un autre port avec `sudo pxe-tools web-port 8443` lorsque le
service web est arrêté ou en échec. Reprenez ensuite la configuration du paquet
avec `sudo dpkg --configure pxe-tools`. Sur Docker, définissez
`PXE_HTTPS_PORT=8443` avant le premier démarrage. Le port confirmé dans la
console est conservé dans le volume de configuration et devient prioritaire.

Le réglage `pxe_enabled` sépare l'activation des services de démarrage de la configuration conservée. Il utilise la table `settings` existante, sans migration de schéma :

- Une base nouvellement créée reçoit `pxe_enabled=off` avant d'être utilisée.
- Une instance sans base reste inactive, même si d'anciennes variables réseau sont présentes dans l'environnement.
- Une base héritée sans cette clé conserve son comportement antérieur ; une clé explicite `off` reste prioritaire sur les variables d'environnement.
- Une valeur illisible ou invalide ne doit pas être interprétée comme une demande d'activation.

Pour les anciennes configurations natives, PHP, le worker, dnsmasq et le service HTTP de démarrage chargent le même environnement dans l’ordre `default.env`, `network.env`, puis `runtime.env`. L’assistant affiche ainsi les valeurs effectivement utilisées lorsque les clés réseau sont absentes de SQLite. Une valeur déjà enregistrée dans SQLite, même vide, garde la priorité. Aucun élargissement des droits du service web n’est ajouté.

En mode console seule, le rendu dnsmasq est inerte. L'application native arrête ses propres services HTTP de démarrage et dnsmasq et retire le démarrage automatique de sa propre target PXE. La console et le worker restent indépendants. Dans Docker, nginx continue à servir la console et sa configuration HTTP de démarrage est retirée ; dnsmasq est arrêté lors de l'application explicite. Les modèles de configuration conservés restent disponibles pour une activation ultérieure.

## Port 80 et diagnostic

L'absence du marqueur de disponibilité ne prouve pas un conflit de port. Le diagnostic doit distinguer un port libre, une réponse HTTP de démarrage attendue, une occupation concurrente confirmée et une vérification indéterminée. L'interface ne doit pas présenter un nom de processus comme une preuve suffisante de conflit : nginx peut être le serveur attendu ou partager d'autres services.

L'adresse de liaison, IPv4/IPv6 et les droits de lecture disponibles limitent le diagnostic. Quand l'identité d'un concurrent ne peut pas être établie, une vérification manuelle reste nécessaire. Aucun élargissement des permissions n'est prévu pour obtenir ces détails.

Si le service concurrent peut être identifié avec certitude et qu'une action contrôlée est disponible, l'interface présente l'interruption attendue et demande confirmation. L'action revalide l'occupant, effectue un arrêt propre et vérifie le résultat. Elle ne doit ni tuer arbitrairement un PID, ni désactiver ou masquer durablement un service tiers. Un refus de confirmation ne change aucun service.

## Retour à une version antérieure

Une version antérieure au candidat ne connaît pas `pxe_enabled` : cette seule valeur ne garantit donc pas qu'elle gardera le réseau arrêté. Avant un retour arrière, arrêter les services de démarrage et conserver une sauvegarde cohérente des réglages et de leurs fichiers associés. Reprendre la configuration et la supervision adaptées à la version restaurée, puis vérifier les écoutes effectives avant toute activation. Le candidat ne déclenche aucune rétrogradation automatique.

## Changement d'hôte et sauvegardes

Il n'existe actuellement aucun export portable complet d'instance ; les modèles JSON et l'inventaire de migration ne sont pas un tel transfert. L'archive de récupération complète reste une sauvegarde fidèle, avec la base et ses paramètres d'origine.

La copie préparée pour restauration est séparément mise en veille : `wizard_completed=0`, `pxe_enabled=off` et proxy DHCP désactivé. Les valeurs historiques d'interface, d'adresse et de réseau restent présentes pour comparaison, mais ne constituent pas une identité réseau valable sur la destination. Le parcours doit proposer et revalider les adresses de l'hôte de destination avant toute activation. L'archive d'origine n'est pas réécrite.

Une restauration de contrôle en laboratoire ne vaut pas autorisation de remplacer une instance de production. Aucune mise à niveau de la machine utilisateur ni publication APT n'est déclenchée par ce candidat.

## Références

- [Manuel dnsmasq : mode proxy DHCP et interfaces](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
- [Sauvegarde et restauration](backup-restore.md).
- [Préparation du paquet natif](native-preparation.md).
