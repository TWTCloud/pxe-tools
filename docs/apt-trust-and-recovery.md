# Dépôt APT : état de la rotation et reprise des instantanés

Ce document décrit l'état de la distribution au 18 novembre 2026 et prépare la
résolution de [pxetools.com #2](https://github.com/williamboglietti/pxetools.com/issues/2).
Il ne donne pas l'autorisation d'effectuer une rotation ou une restauration en
production. Les modifications de clés, secrets, workflows et déploiements
nécessitent leur propre validation et une autorisation ciblée.

## Rotation de la signature : blocages constatés

La clé publique actuellement servie possède une clé primaire et une sous-clé
de signature. Le bootstrap du site épingle l'empreinte de la primaire, puis
l'installateur place la clé vérifiée dans
`/etc/apt/keyrings/pxe-tools-archive-keyring.gpg` et utilise `Signed-By`. Il ne
met pas automatiquement à jour cette clé chez les clients existants. Une
nouvelle sous-clé ajoutée au certificat public n'est donc pas connue d'un
client qui a conservé l'ancien certificat. Le test isolé ci-dessous démontre ce
comportement avec des clés jetables :

```sh
python3 tests/integration/test_apt_signing_rotation.py -v
```

Le même test confirme que `ci-sign-apt-candidate.py` refuse par défaut un
trousseau CI contenant deux sous-clés privées. Le mode de transition préparé
importe séparément l'ancien certificat public, contrôle les deux empreintes et
refuse tout ajout de matériel privé ; il n'est pas raccordé à la publication.
Par ailleurs :

- `build-local-apt-repository.py` exige **par défaut** que l'instantané
  précédent soit signé par la même sous-clé que le suivant. Un mode explicite
  de répétition permet de distinguer les deux sous-clés sous une primaire
  épinglée ; il n'est pas raccordé au workflow de production ;
- la récupération de l'instantané et les workflows épinglent encore les
  empreintes courantes. La vérification de provenance préparée accepte une
  deuxième sous-clé uniquement si elle est explicitement épinglée ; la
  signature reste vérifiée contre le signataire attendu ;
- le désinstallateur suit la provenance du trousseau par une empreinte du
  contenu. Les fixtures testent la mise à jour en place et le remplacement
  atomique : dans les deux cas le trousseau modifié est conservé, car son
  témoin d'origine ne prouve plus les nouveaux octets.

Changer la clé de production, le secret CI ou une seule empreinte entraînerait
donc un blocage de publication ou des clients incapables de vérifier le dépôt.
**La rotation transparente n'est pas implémentée et aucune rotation réelle n'a
été effectuée.** La répétition isolée peut être lancée sur un environnement
Linux jetable avec `PXE_APT_ROTATION_FIXTURE=1 bash
tests/integration/test_apt_rotation_rehearsal.sh`. Elle génère ses propres
clés et paquets ; elle ne modifie aucun état APT système ni aucun secret. Le
workflow de vérification des PR l'exécute sans accès à l'environnement de
production ; le workflow de publication reste inchangé. Une nouvelle primaire, une sous-clé renouvelée et une
compromission exigent des plans distincts ; un certificat compromis ne doit pas
être utilisé pour authentifier sans examen sa propre relève.

### Travail requis pour une transition sûre

1. Définir le modèle de confiance et la méthode de vérification indépendante
   des empreintes, y compris la conservation et la révocation des clés. Décider
   comment les clients existants recevront le nouveau certificat **avant** que
   le dépôt soit exclusivement signé par la nouvelle sous-clé ; le certificat
   servi aux nouvelles installations ne modifie pas les clients déjà installés.
2. Concevoir et revoir une transition explicite : vérifier l'ancien instantané
   avec l'ancienne identité attendue et signer le suivant avec la nouvelle,
   sans autoriser un signataire arbitraire. Traiter séparément la récupération,
   la preuve de provenance, la validation statique, la publication et les
   chemins client. Préserver les contrôles d'objets immuables et les refus sur
   toute identité ou provenance inattendue.
3. Tester avec des clés jetables et de vrais clients APT isolés : ancien client,
   certificat mis à jour, nouveau client, mauvaise empreinte, sous-clé inconnue,
   instantané précédent invalide, interruption et reprise. Inclure la
   cohabitation ou la propagation des versions à l'edge et le comportement du
   désinstallateur après mise à jour du trousseau.
4. Préparer les changements précis de code, des deux dépôts, des workflows et
   des secrets, ainsi que le plan de retour et la réception des clients. La
   modification des secrets et l'exécution de la transition de production
   nécessitent une autorisation ciblée ; ne pas contourner les protections.

### Préparer la distribution aux clients existants

Cette séquence est un cahier des charges à recevoir, pas une commande de
rotation disponible. Elle concerne uniquement l'ajout d'une sous-clé certifiée
par une primaire non compromise ; le cas d'une nouvelle primaire ou d'une clé
compromise exige un autre modèle de confiance.

1. Obtenir par un canal indépendant les empreintes complètes de la primaire et
   des deux sous-clés, ainsi que l'identité et l'empreinte du certificat public
   proposé. Contrôler les signatures de certification, les dates et révocations
   dans un trousseau GnuPG isolé. Un téléchargement HTTPS depuis le même dépôt
   ne constitue pas à lui seul une vérification indépendante.
2. Vérifier sans modifier le système la source APT effective, son `Signed-By`,
   les éventuels autres dépôts ou alias qui utilisent le même fichier, les liens
   symboliques et les témoins de création. Si la propriété, la configuration ou
   l'usage exclusif ne peuvent pas être établis, préserver le fichier et demander
   une inspection : ajouter une sous-clé à un trousseau partagé pourrait élargir
   la confiance d'un autre dépôt.
3. Préparer une mise à jour atomique et récupérable : conserver l'ancien
   certificat, vérifier les octets attendus immédiatement avant remplacement,
   écrire un nouveau fichier protégé et contrôler ses permissions et son
   empreinte. Définir un journal et une reprise pour chaque interruption. Le
   témoin par lien physique et empreinte créé par l'installateur doit être
   traité explicitement ; il ne faut ni le réécrire aveuglément ni prétendre
   que le désinstallateur est autorisé à effacer un nouveau certificat inconnu.
4. Prouver sur un client isolé l'acceptation des métadonnées signées par
   l'ancienne puis la nouvelle sous-clé, et le refus en cas d'empreinte,
   certificat ou signature erronés. Tester aussi le remplacement interrompu,
   les configurations partagées et la désinstallation. Ne pas interpréter
   `apt update` seul comme une installation ou un boot PXE réussis.
5. Définir la gestion des clients absents ou hors ligne et la période de
   coexistence avant toute signature exclusive par la nouvelle sous-clé. Une
   propagation partielle des versions du Worker doit être prise en compte ;
   le maintien de la seule nouvelle signature peut interrompre les anciens
   clients. La révocation de l'ancienne sous-clé et toute intervention réelle
   suivent une décision de production distincte.

Aucun outil de mise à jour client ni basculement de production n'est livré par
la présente préparation. Les fixtures ne modifient que leurs répertoires
jetables ; elles ne prouvent pas le déploiement du certificat sur les machines
existantes.

## Instantanés : ce qui est vérifié

Le [run planifié 44077918347](https://github.com/williamboglietti/pxe-tools/actions/runs/44077918347)
du 17 novembre 2026 a réussi les étapes de récupération de l'instantané,
signature, conservation persistante, déploiement et contrôle public. Le script
`packaging/ci/worker-snapshot.py` sélectionne l'asset le plus récent de la
release `apt-snapshots`, exige sa concordance exacte avec l'`InRelease` public,
puis vérifie l'archive, les signatures, le manifeste et les objets ; il refuse
un retour automatique à un instantané plus ancien. La préparation de la PR
valide l'extraction dans un répertoire temporaire avant de rendre la destination
disponible ; une signature ou un objet invalide ne laisse pas d'instantané
partiel utilisable. Une fixture signée répète l'interruption avant déploiement,
le refus d'un état public ancien, puis la reprise après concordance. Les tests
`tests/test_worker_snapshot.py` couvrent notamment les archives dangereuses,
une réponse publique ancienne et le refus d'amorcer sur erreur réseau.

Le 18 novembre, une lecture isolée a téléchargé l'asset
`snapshot-44077918347-1.tar.gz`, vérifié sa taille et son SHA-256 GitHub,
comparé son `InRelease` au document public et vérifié signatures, manifeste,
index, objets by-hash et paquets. L'essai s'est limité à des fichiers sous
`/tmp` : il ne constitue pas une restauration ou un déploiement réels. Sur le
Mac utilisé, GnuPG 2.5 a laissé le résultat clair dans un fichier `.part` ; la
validation locale a utilisé une adaptation ponctuelle pour comparer son contenu.
La procédure CI reste celle du runner Linux existant.
Les deux paquets publics bêta 8 ont aussi été téléchargés en lecture seule : leurs SHA-256 correspondent au manifeste suivi. La clé publique servie est identique à la copie suivie par le projet. Ces comparaisons ne sont pas une installation APT cliente.

En cas d'échec, conserver les preuves, vérifier les versions réellement actives,
l'`InRelease` public, son expiration et les derniers snapshots signés. Ne pas
relancer aveuglément une ancienne exécution, supprimer un snapshot ni supposer
qu'un run rouge signifie absence de déploiement. La documentation existante
`packaging/ci/README.md` décrit les garde-fous et le seuil de rotation des
assets. [Cloudflare précise](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)
qu'un rollback est un déploiement et que sa propagation prend du temps ; il
peut servir une ancienne collection d'assets et des métadonnées expirées. Il ne
réconcilie pas à lui seul l'archive GitHub et le dépôt public. Une restauration
réelle exige donc un scénario, une revue et une autorisation ciblée.

## Réception APT : portée des preuves

- Le [contrôle APT en lecture seule du 18 novembre](https://github.com/williamboglietti/pxe-tools/actions/runs/44379836320)
  utilise un état client vide et la clé suivie : APT a vérifié les métadonnées
  publiques puis téléchargé les deux paquets bêta 8, dont les empreintes
  correspondent au manifeste. Aucun paquet n'a été installé et ce résultat ne
  reçoit ni l'installateur complet ni toutes les distributions.
- La [CI du site](https://github.com/williamboglietti/pxetools.com/actions/runs/44358444883)
  a exécuté l'installateur contre une fixture signée isolée. Elle couvre des
  refus d'empreinte et d'objets altérés ; il s'agit d'un paquet synthétique,
  pas de la bêta 8 publiée.
- Le test `tests/integration/test_apt_release_candidate.sh` construit des
  dépôts et paquets jetables, utilise un état APT distinct, simule l'installation,
  conserve les liens immuables lors d'un changement de version et refuse les
  index ou paquets altérés. Le run planifié ci-dessus l'a exécuté en CI. La
  répétition de transition utilise également un état APT vide, des clés
  jetables et une simulation d'installation du paquet synthétique.
- La [réception bêta 7 sur Zorin](apt-upgrade-lifecycle.md#réception-des-paquets-canoniques-sur-zorin)
  et les essais des versions antérieures ont des périmètres propres. La bêta 8
  n'a pas bénéficié d'une nouvelle campagne native multi-OS, d'une installation
  sur client vierge de chaque plateforme ou d'une réinstallation PXE complète.

Pour une future réception, consigner pour chaque distribution l'environnement
isolé, la version exacte, la source du paquet, la signature et l'empreinte,
les étapes réellement exécutées, ainsi que le résultat et les limites. Les
fixtures synthétiques, le paquet public et un démarrage PXE réel ne sont pas
interchangeables. Ne pas utiliser les machines de William comme banc jetable.
