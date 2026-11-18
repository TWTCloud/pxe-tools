# Désinstallation APT d'une installation ancienne

Une instance créée avant l'enregistrement de provenance peut posséder un
journal Ansible vide (`format: 2`, `directories: {}`, sans `base_phase`). Ce
journal ne prouve pas la création des répertoires existants. Le désinstallateur
continue à refuser ce cas par défaut ; `--allow-legacy` propose un aperçu
distinct, limité à ce journal vide exact et aux chemins PXE Tools connus. Les
journaux incomplets d'autres formes restent refusés.

L'aperçu indique les répertoires proposés, les ressources conservées et une
empreinte du plan. Après examen et consentement explicite de l'administrateur,
`--yes --allow-legacy --legacy-plan-sha256 EMPREINTE` ne poursuit que si les
mêmes identités de répertoires et les mêmes exclusions sont toujours présentes.
Le lanceur du site transmet cette empreinte après confirmation interactive.
Ces identités constituent une photographie approuvée, pas une affirmation que
PXE Tools a créé les répertoires. Le contrôle exige `statx` avec date de
création, `openat2`, un système de fichiers approprié et refuse liens,
montages, chemins modifiés, opérations en cours ou compte Ansible partagé.

Le compte et le groupe Ansible préexistants, la source et la clé APT sont
conservés : le journal ancien ne permet pas de les attribuer. Un répertoire de
journaux dont le parent est modifiable par un autre utilisateur ou groupe est
également conservé et signalé ; c'est notamment le cas d'un `/var/log` en
`root:syslog` et mode `0775`. Les dépendances et ressources externes restent
préservées. Une suppression partielle de ressources conservées est signalée
avec un code de sortie non nul pour permettre leur examen.

Le reçu de désinstallation distingue le consentement explicite de l'ancienne
preuve de création. Après interruption, `--resume` réutilise ce reçu ; si
l'interruption a précédé la purge, les services sont remis dans leur état
antérieur puis un nouvel aperçu et une nouvelle confirmation sont nécessaires.
Les tests automatisés simulent la purge et les interruptions ; ils ne prouvent
pas qu'une désinstallation réelle a été réalisée sur une machine de William.
