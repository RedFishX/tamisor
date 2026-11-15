# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/). Les versions suivent le versionnement
sémantique ; avant la 1.0, une version mineure peut modifier un comportement.

## 0.1.0 — 2026-11-15

Première version publiée sous le nom **Tamisor** (anciennement FortiScope, puis Shadowline). Le dépôt est distribué
sous licence AGPL-3.0 ou ultérieure, avec un accord de contribution (CLA).

### Analyse
- Règles permissives, règles masquées par une règle précédente (recouvrement total ou partiel) et règles sans
  journalisation, avec plan de remédiation, exemple de commande CLI et référence à la documentation Fortinet.
- Import d'un export de configuration FortiGate (`show full-configuration`) ou d'un export CSV de la console.
- Groupes d'adresses et de services imbriqués, services par protocole et ports, VDOM et IPv4/IPv6 analysés
  séparément.
- Score de configuration, priorités et familles de constats ; vue d'ensemble par VDOM.
- Filtre par nombre d'utilisations (hit count), constats acquittés localement.

### Application
- Mode réunion : tableau des policies à discuter, séance plein écran, décisions au clavier, compte rendu en
  Markdown ou HTML imprimable.
- Comparaison de deux audits (policies ajoutées, modifiées, supprimées).
- Exports : constats CSV, rapport HTML autonome, commandes CLI de remédiation.
- Interface en français et en anglais ; accessibilité visée WCAG 2.2 AA.
- Les fichiers sont analysés dans le navigateur (Web Worker) et ne sont jamais transmis.

### Intégration continue
- Commande `tamisor` : rapports SARIF 2.1.0 et JSON, seuil d'échec, acquittements, référence de comparaison.
  Codes de sortie : 0 réussite, 1 constats bloquants, 2 erreur d'usage ou d'import.
- Images Docker `ghcr.io/redfishx/tamisor` (application) et `ghcr.io/redfishx/tamisor-cli` (commande CI),
  publiées à chaque version.

### Extensions
- Points d'extension neutres (`registerEdition`) pour héberger une édition qui restreint ou complète
  l'application : fonctions verrouillées, contrôle avant import et après analyse, bannière, entrée de barre d'outils,
  actions d'export supplémentaires. Sans édition enregistrée, l'application est entière.

### Changements par rapport aux préversions
- Renommage : la commande `fortiscope` devient `tamisor`. Les préférences enregistrées sous `fortiscope-*` et
  `shadowline-*` sont reprises automatiquement dans `tamisor-*`.
- Les références au référentiel CIS FortiGate ont été retirées.
- Les préversions publiées sous le nom Shadowline ne sont plus maintenues.
