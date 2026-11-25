# Orchestrator Admin App

Interface web + API pour piloter le serveur PXE.

## Architecture

```
/srv/admin/                     # ce répertoire (déployé par Ansible)
├── public/                     # DocumentRoot nginx :8080
│   ├── index.php              # Front controller (router minimal)
│   ├── htmx.min.js            # HTMX local
│   ├── toast.js               # Toast notifications (window.PxeToast)
│   ├── style.tailwind.css     # Tailwind v4 build (cf. scripts/build-css.sh)
│   └── style.css              # Composants legacy (en cours de migration)
├── src/                       # Code application
│   ├── Db.php                 # PDO singleton SQLite
│   ├── Router.php             # Routes + dispatch
│   ├── Auth.php               # Stub Authentik forward auth
│   ├── View.php               # Render layout / partial / json / redirect
│   ├── Models/                # PDO data access
│   │   ├── Machine.php
│   │   ├── Preset.php
│   │   └── Installation.php
│   ├── Controllers/
│   │   ├── MachineController.php
│   │   ├── PresetController.php
│   │   ├── InstallationController.php
│   │   └── PxeController.php  # endpoints /api/discovery, /api/install-{start,end}
│   └── Views/                 # PHP templates
│       ├── layout.php
│       ├── machines/{index,show,new}.php
│       ├── presets/{index,edit}.php
│       └── installations/{index,show,_log}.php
├── db/
│   └── schema.sql             # CREATE TABLE IF NOT EXISTS — idempotent
├── worker.py                  # Worker Ansible (systemd : pxe-tools-worker.service)
└── discover.sh                # Script discovery boot (déployé aussi dans /srv/http/)
```

## Appellation des équipements

Dans **Appliance → Vue d’ensemble → Appellation des machines clientes**, un administrateur peut choisir « Machine » (défaut), « Client PXE », « Ordinateur » ou « Serveur ». Le réglage est partagé par l’instance et modifie les libellés de la console. Les onglets déjà ouverts peuvent nécessiter un rechargement.

Les noms d’hôte, les notes et les données existantes restent identiques, ainsi que les URL, les formats des API et les messages déjà enregistrés dans l’historique. Ce choix ne modifie pas la configuration PXE et ne demande aucun redémarrage de service.

## Endpoints

### UI (port 8080)

| Méthode | Path                      | Action |
|--|--|--|
| GET     | `/`                       | Liste des machines |
| GET     | `/machines/{id}`          | Détail machine + assign preset |
| POST    | `/machines`               | Créer machine manuellement |
| PUT     | `/machines/{id}`          | Update (preset, hostname...) |
| POST    | `/machines/{id}/wipe`     | Reset status → `discovered` |
| DELETE  | `/machines/{id}`          | Supprimer |
| GET     | `/presets`                | Liste presets |
| GET     | `/presets/new` / `/{id}`  | Form create/edit |
| POST/PUT| `/presets[/{id}]`         | Save |
| DELETE  | `/presets/{id}`           | Supprimer |
| GET     | `/installations`          | Historique installs |
| GET     | `/installations/{id}`     | Log streaming (HTMX poll 2s) |

### API PXE (port 80 — vhost PXE + port 8080)

Les clients PXE utilisent ces routes hors session web. Les filtres réseau
utilisent l'adresse du pair vue par le serveur.

| Méthode | Route | Contrôle ou effet |
|--|--|--|
| GET/POST | `/api/discovery` | Inventaire complet en JSON ou en base64. Un ping `phase` consigne un événement. |
| GET/POST | `/api/install-start` | Boucle locale uniquement. Machine configurée ou en cours d'installation, dans une phase d'installation ouverte. |
| GET/POST | `/api/install-end` | Sous-réseau PXE IPv4 et jeton Bearer de l'action d'installation de cette machine. L'installation la plus récente doit correspondre à l'action. |
| GET | `/preseed.php?mac=…` | Sous-réseau PXE IPv4 et phase d'installation ouverte. Le rendu lance `install-start` en boucle locale. |
| GET | `/api/monitoring/installs` | Boucle locale IPv4 ou sous-réseau PXE IPv4. Résumé en lecture seule. |

## DB SQLite

Le chemin par défaut est `/var/lib/pxe-tools/pxe-tools.sqlite`. La configuration
`/etc/pxe-tools/db.conf` fait foi lorsqu'elle existe. Le schéma se trouve dans
[db/schema.sqlite.sql](db/schema.sqlite.sql).

`Db::get()` active par défaut le mode WAL et configure un délai d'attente
SQLite de 5 secondes. Le répertoire de la base doit permettre la gestion des
fichiers `-wal` et `-shm` par les services qui accèdent à la base.

Les premiers essais de portage utilisent le même schéma sur des fixtures
jetables. Voir le [banc Rust](../tests/benchmarks/rust-monitor/README.md).

## États d'une machine

```
unknown ──(MAC vue PXE)──▶ discovered ──(admin save preset)──▶ configured
configured ──(early_cmd POST)──▶ installing ──(late_cmd POST)──▶ installed
installed ──(worker exec ansible)──▶ provisioned   /   ──(KO)──▶ failed
```

## Worker

`pxe-tools-worker.service` (systemd, user `ansible`) poll `installations.ansible_status='pending'`, lance `ansible-playbook playbooks/<role>.yml --limit <hostname>`, stream le stdout dans la table.

Le `late_command` de Debian Installer transmet `install-end` avant le redémarrage. Le reçu autorise le démarrage sur disque local et peut inclure l’empreinte publique de la clé d’hôte SSH pour le journal de l’installation. La vérification de la clé d’hôte par Ansible garde ses propres règles.

Pour toute installation Debian suivie, le preseed dépose un lanceur temporaire. Au premier démarrage, systemd génère son unité `oneshot` sous `/run` et la lance après le réseau et SSH. Le lanceur confirme le démarrage avec `os_first_boot` et se retire après l’accusé, la clôture de l’action ou l’épuisement des tentatives. Le worker attend cette confirmation avant de clore une installation Debian seule ou de prendre en charge le rôle si le module Ansible est actif. Les installations déjà lancées avec un ancien preseed conservent leur parcours.

`/home/ansible/ansible/` doit contenir un repo Ansible (avec `playbooks/`, `inventory/`, `ansible.cfg`). Cloner ou monter selon besoin.

## Proxy inverse et origine des formulaires

La protection CSRF compare l’origine du formulaire à l’en-tête `Host`. Si le
proxy remplace `Host` et transmet le nom public dans `X-Forwarded-Host`, il faut
déclarer explicitement les adresses ou CIDR des **pairs réseau réellement vus
par PXE Tools** dans `AUTHENTIK_TRUSTED_PROXY_CIDRS`, même lorsque
`AUTH_MODE=local`. Malgré son nom historique, cette liste sert aussi au
contrôle de l’origine en mode local. Sans liste valide, l’en-tête transmis est
ignoré et un formulaire dont l’origine ne correspond pas à `Host` est refusé.
La liste accepte IPv4 et IPv6 séparées par des virgules, mais refuse notamment
les entrées mal formées et les réseaux qui acceptent toutes les adresses.
Ne pas y placer les adresses des navigateurs : `X-Forwarded-For` ne détermine
pas si le pair est fiable.

Exemple de variable d’environnement, à adapter à l’adresse effective du proxy :

```text
AUTHENTIK_TRUSTED_PROXY_CIDRS=192.0.2.7/32
```

Cette déclaration signifie que l’on fait confiance au proxy : il doit supprimer
ou remplacer les en-têtes `X-Forwarded-Host`, `X-Forwarded-Proto` et
`X-Forwarded-User` fournis par les clients, selon la configuration vérifiée du
service. Restreindre l’accès direct à l’administration et ne déclarer que les
proxys administrés. Le jeton CSRF reste obligatoire, même pour un proxy fiable.
La connexion locale et les cas de pair fiable/non fiable ont été testés avec le
véritable routeur sur une boucle locale isolée ; ces essais simulaient les
en-têtes et ne validaient pas un proxy externe ou un fournisseur SSO réel.

## Authentik via proxy externe

Avec `AUTH_MODE=authentik`, `AUTHENTIK_TRUSTED_PROXY_CIDRS` doit lister les
adresses réelles des proxys qui exécutent l'authentification. Le proxy doit
remplacer `X-Forwarded-User` par l'identité vérifiée par l'outpost et l'accès
direct aux ports admin doit être limité. L'accès navigateur doit utiliser HTTPS ;
le proxy écrase `X-Forwarded-Proto` selon le protocole extérieur vérifié et
`X-Forwarded-Host` selon l'hôte public prévu. Sans HTTPS détecté, le cookie de
session n'est pas marqué `Secure`. Une configuration absente ou invalide
refuse l'accès ; les formulaires restent protégés par CSRF. Voir
`docker/pxe-tools/nginx/admin-authentik.conf.example` et le README principal.

## Bêta UX/UI locale

La branche `codex/ux-beta` contient la refonte de la console. Voir la [procédure de démonstration, les preuves et les limites matérielles](../docs/ux-beta/livraison.md). La démo web utilise des données temporaires, sans worker ni accès aux machines réelles.
