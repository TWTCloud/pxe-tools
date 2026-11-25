# Installateurs Linux dans PXE Tools

Dans l’assistant, sélectionnez une image Debian pour la découverte et le
secours. Ubuntu Server, CentOS Stream, Fedora Server, AlmaLinux et Rocky Linux
peuvent être préparés en parallèle. Les images supplémentaires apparaissent
dans le menu **Installateurs Linux** après leur téléchargement.

Ubuntu utilise l’ISO officielle et Autoinstall. Les distributions RPM utilisent
le noyau et l’initrd de l’arbre d’installation officiel. PXE Tools vérifie les
empreintes de ces deux fichiers dans le `.treeinfo` publié en HTTPS par le
miroir. L’installateur récupère le reste depuis ce miroir. Relancez le
téléchargement des images RPM préparées par les anciennes versions de PXE Tools.

Pour programmer un Autoinstall ou un Kickstart depuis la console, inventoriez
d’abord le client en UEFI. Le formulaire d’installation Linux demande un disque
identifié par son numéro de série, puis l’installateur vérifie ce disque et la
carte réseau avant le partitionnement.

## Proxmox VE

Dans **Images → Ajouter une image → Proxmox VE**, choisissez l’architecture
du client et lancez **Télécharger et préparer**. PXE Tools télécharge l’ISO
officielle de Proxmox VE 9.2-1 ainsi que l’assistant de l’éditeur, vérifie les
empreintes, puis prépare le noyau, l’initrd et l’ISO avec `prepare-iso --pxe`.
Prévoyez au moins 8 Gio libres sur le serveur et 6 Gio de mémoire sur le client
pour charger l’ISO en RAM.

Le menu **Installateurs Linux** propose une installation interactive.
Pour une installation automatisée, inventoriez le client en UEFI, puis
ouvrez **Installation automatique Linux** sur sa fiche. Choisissez
Proxmox VE et le disque à effacer par son chemin et son numéro de série.
Saisissez un nom complet (par exemple `pve01.exemple.fr`), un e-mail et le mot
de passe de `root`. Ce parcours utilise la configuration réseau reçue via
DHCP, le format ext4 et les paramètres régionaux France.

PXE Tools fournit le fichier de réponse en HTTPS à l’installateur du client
sélectionné. L’ISO préparée référence l’empreinte du certificat TLS du serveur.
Relancez **Télécharger et préparer** après un changement de certificat, de
port HTTPS ou d’adresse PXE. Le suivi distingue la fin de l’installation et
le premier démarrage du système, signalé après le lancement de `pveproxy`
sur le port 8006.

### Média préparé à l’extérieur

Les médias préparés avec `proxmox-auto-install-assistant prepare-iso --pxe`
peuvent aussi être placés dans `netboot/proxmox/<version>/<arch>/` sous les noms
`linux` (vmlinuz), `initrd.gz` (initrd.img) et `source.iso`. Pour ajouter
l’entrée automatique externe, placez la ligne `http` dans `.external-answer`
et utilisez une ISO préparée avec un serveur de réponses HTTPS. Le serveur
externe doit autoriser uniquement les clients prévus et imposer une sélection
explicite du disque. Les clients PXE peuvent lire les trois fichiers de média,
donc gardez les mots de passe, les jetons et les réponses sur le serveur HTTPS.

[ISO officielles Proxmox VE](https://www.proxmox.com/en/downloads/proxmox-virtual-environment/) ·
[Assistant Proxmox et préparation PXE](https://github.com/proxmox/pve-installer/tree/master/proxmox-auto-install-assistant)
