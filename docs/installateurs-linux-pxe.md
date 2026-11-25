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

Préparez l’ISO officielle sur un hôte Linux disposant de
`proxmox-auto-install-assistant` avec l’option `--pxe`. Vérifiez au préalable
son empreinte avec celle publiée sur le site de Proxmox.

```bash
proxmox-auto-install-assistant prepare-iso proxmox-ve_9.2-1.iso \
  --fetch-from http --url https://answer.example.net/proxmox \
  --pxe --output ./proxmox-pxe
```

Dans le stockage HTTP de PXE Tools, créez `netboot/proxmox/<version>/<arch>/`
avec `amd64` ou `arm64` selon l’ISO préparée. Copiez les fichiers produits sous
les noms `linux` (le `vmlinuz`), `initrd.gz` (l’`initrd.img`) et
`source.iso` (l’ISO préparée). Le menu PXE propose alors l’installateur
guidé Proxmox pour cette architecture.

Pour afficher également l’entrée automatique, placez la ligne `http` dans
un fichier nommé `.external-answer` dans ce dossier. L’ISO doit alors avoir été préparée
avec `--fetch-from http`. Le serveur de réponses HTTPS doit autoriser
uniquement les machines prévues et fournir une sélection explicite du disque.
Les trois fichiers du dossier sont lisibles par les clients PXE. Gardez
les mots de passe, les jetons et les fichiers de réponse sur le serveur HTTPS.

[ISO officielles Proxmox VE](https://proxmox.com/en/downloads/proxmox-virtual-environment/iso) ·
[Assistant Proxmox](https://github.com/proxmox/pve-installer/tree/master/proxmox-auto-install-assistant)
