# Comptes, droits et API

Dans la console, **Accès → Comptes et droits** permet à un administrateur de créer des comptes, leur attribuer des permissions et les désactiver. Un compte personnalisé reçoit les droits cochés. Le statut d’administrateur donne accès à l’ensemble de la console. La dernière personne disposant de ce statut reste active. Les comptes locaux préexistants deviennent administrateurs lors de la première migration. Le journal de cette page retrace les modifications de comptes et de jetons.

Les droits s’appliquent à l’instance PXE entière. La consultation et les mutations sont indépendantes. Par exemple, un compte d’inventaire peut recevoir `devices.read`, alors qu’un opérateur peut aussi recevoir `devices.power`. La programmation d’une installation peut repartitionner des disques. Les commandes d’effacement et les diagnostics en écriture ont leur propre autorisation. L’activation réseau, TLS, l’administration des comptes et la relance générique des tâches sont réservées aux administrateurs.

En mode Authentik, un administrateur connecté via le proxy de confiance peut activer la gestion des comptes depuis **Comptes et droits**. Son identité devient le premier administrateur. Ajoutez ensuite chaque identité Authentik autorisée en reprenant exactement son identifiant. L’accès hérité du proxy s’applique jusqu’à cette activation.

La désactivation d’un compte local ou la réinitialisation de son mot de passe invalide ses sessions et révoque ses jetons. La désactivation d’un compte Authentik bloque son accès à la console et révoque également ses jetons. Les retraits de droits restreignent immédiatement les jetons déjà délivrés. Pour revenir à une version antérieure de PXE Tools, restaurez d’abord une sauvegarde antérieure à la mise à niveau, y compris la configuration Authentik.

## Jetons

Dans **Accès → Jetons d’API**, choisissez un nom, une durée de 1 à 365 jours et les droits d’API à attribuer. Les permissions proposées sont celles que possède le compte émetteur et que l’API prend en charge. Copiez le secret lors de l’émission. Le serveur conserve son empreinte SHA-256. Une rotation remplace le secret et peut modifier les droits du jeton tout en gardant sa date d’expiration. Une révocation invalide le secret pour les requêtes suivantes. Un administrateur peut révoquer les jetons de tous les comptes.

## API JSON v1

Envoyez le secret dans l’en-tête `Authorization: Bearer <jeton>` sur la console HTTPS. Envoyez `Content-Type: application/json` pour les requêtes POST.

| Méthode et chemin | Droit requis |
| --- | --- |
| `GET /api/v1/devices` et `GET /api/v1/devices/{id}` | `devices.read` |
| `GET /api/v1/installations` et `GET /api/v1/installations/{id}` | `activity.read` |
| `GET /api/v1/jobs` et `GET /api/v1/jobs/{id}` | `jobs.read` |
| `GET /api/v1/images` et `GET /api/v1/images/{id}` | `images.read` |
| `POST /api/v1/devices` | `devices.write` |
| `POST /api/v1/devices/{id}/actions/{reboot,shutdown,rediscover}` | `devices.power` |

Les collections utilisent `?page=1` avec 100 entrées par page et renvoient `items`, `page` et `next_page`. L’ajout d’un appareil attend un objet contenant `mac` et, éventuellement, `hostname`. Il renvoie `201` et l’identifiant de l’appareil. Les commandes d’alimentation ou d’inventaire attendent un objet vide `{}` et renvoient `202` à l’acceptation. La réalisation de l’opération dépend de l’état de l’appareil.

Un jeton absent, expiré ou révoqué renvoie `401`. Un jeton valide dont les droits sont insuffisants renvoie `403` avec le droit attendu.
