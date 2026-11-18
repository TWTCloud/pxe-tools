# Candidat de transition du certificat APT

Ce dossier est un candidat de code pour une transition **préparée mais non
activée**. Il ne contient aucun certificat, index signé ni secret. Ne pas
l'exécuter sur une machine de production avant revue et autorisation de la
transition concernée. `SHA256SUMS` permet de vérifier l'intégrité des fichiers,
mais pas leur authenticité : vérifier indépendamment la provenance du dossier.

La commande `python3 packaging/native/prepare-client-key-transition.py --help`
décrit les paramètres. Il faut notamment obtenir par un canal indépendant les
empreintes complètes et vérifiées de la primaire et des deux sous-clés, ainsi
que les anciens et nouveaux index signés. `--inspect-system` ne modifie pas APT.
`--apply-system` demande root et une confirmation explicite de ces empreintes ;
il ne télécharge rien et ne déclenche pas de signature ni de rotation serveur.
La prise en charge des clients hors ligne, des configurations APT alternatives,
des reprises après interruption et la procédure de production doivent encore
être revues avant une utilisation réelle.

`python3 packaging/native/stage-client-transition-data.py --help` décrit la
préparation d'un dossier local contenant les deux certificats publics, les
deux index signés et leurs empreintes. Le programme vérifie les signatures
avant de produire le dossier ; il n'envoie rien. Son manifeste n'authentifie
pas ses propres empreintes et ne démontre pas la fraîcheur des index : les
vérifications indépendantes restent nécessaires côté opérateur et client.
