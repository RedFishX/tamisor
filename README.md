# Shadowline

Application locale d’aide à l’audit des politiques FortiGate. Elle signale les règles très permissives, les règles entièrement masquées par une règle précédente et les règles sans journalisation.

Chaque constat fournit un plan de remédiation contextualisé, un exemple CLI à adapter et une référence vers la documentation officielle Fortinet. Les recommandations suivent notamment les critères de correspondance des politiques FortiOS, leur ordre d’évaluation et le principe de restriction des sources, destinations et services.

> Outil indépendant pour FortiGate®, non affilié à Fortinet, Inc. FortiGate et FortiOS sont des marques de Fortinet.

## Déploiement avec Docker

```bash
docker compose up -d          # construit l'image et sert l'application sur http://localhost:8080
PORT=9000 docker compose up -d   # autre port
```

L'image ne contient que des fichiers statiques servis par nginx (utilisateur non root, système de fichiers en
lecture seule, en-têtes CSP stricts avec `connect-src 'self'`). L'analyse s'exécute dans le navigateur : aucune
configuration n'est envoyée au conteneur, qui refuse d'ailleurs tout corps de requête.

Images publiées à chaque version (`v*`) : `ghcr.io/redfishx/shadowline` (application) et
`ghcr.io/redfishx/shadowline-cli` (commande CI) :

```bash
docker run --rm -v "$PWD:/work" ghcr.io/redfishx/shadowline-cli firewalls/fw-siege.conf --sarif shadowline.sarif
```

## Utilisation en développement

```bash
npm install
npm run dev
```

Ouvrez ensuite `http://127.0.0.1:5173` et déposez un export CLI `.conf` ou `.txt`, ou un export de politiques `.csv`.

Pour produire un export exploitable depuis la CLI FortiGate :

```text
show full-configuration
```

La configuration est analysée exclusivement dans le navigateur. Elle n’est envoyée à aucun serveur.

Le bouton de thème dans l’en-tête bascule entre les affichages clair et sombre. La préférence est conservée localement; sans préférence enregistrée, Shadowline suit le thème du système.

Les exports CSV avec séparateur virgule ou point-virgule sont reconnus. Les en-têtes FortiGate usuels sont acceptés, notamment `Policy ID`, `Name`, `From`, `To`, `Source`, `Destination`, `Schedule`, `Service`, `Action`, `NAT`, `Security Profiles`, `Log Traffic` et `Status`. Les exports GUI utilisant une colonne combinée `Policy` au format `Nom (ID)` et des lignes de section sont également pris en charge.

Les compteurs Alertes critiques, Règles permissives et Règles masquées filtrent directement les constats. Cliquez une seconde fois sur le compteur actif pour réafficher tous les résultats.

Le profil de risque peut être réglé sur Standard ou Strict. Le détail d’un constat présente surtout une matrice métier pour chaque élément de la règle : interfaces, sources, destinations, services, horaire, action, NAT, profils de sécurité et journalisation. Chaque ligne indique un niveau faible, moyen ou élevé, la valeur concernée et une justification opérationnelle, sans exposer la formule de calcul.

Le filtre « Hit count » range les policies par tranche d'utilisation (jamais, faible, moyenne, forte). Il n'est disponible qu'avec un export CSV qui contient la colonne `Hit Count`. Les constats peuvent être acquittés localement et restaurés avec l’option `Afficher les acquittés`. Une seconde configuration peut être sélectionnée avec `Comparer` pour compter les politiques ajoutées, modifiées et supprimées. Les exports CSV peuvent aussi fournir `Hit Count` et `Last Used`.

Le menu `Exporter` regroupe les constats CSV, le rapport HTML interactif et les commandes CLI. Le rapport autonome reprend le langage visuel de Shadowline, permet de rechercher et filtrer les constats, de déplier leur détail et de lancer une impression propre. L’export CLI regroupe séparément les commandes de remédiation à examiner et adapter avant application.

Depuis le détail d’un constat, `Créer la documentation Markdown` ouvre une fiche dédiée à la policy sélectionnée, prête à être copiée. Elle explique son sens de circulation, ses critères, ses statistiques d’utilisation et l’ensemble de ses constats avec leurs recommandations. Aucun fichier n’est téléchargé.

Les exemples CLI sont des propositions, pas des commandes à appliquer aveuglément. Sauvegardez la configuration, vérifiez les compteurs et le Policy Match, puis testez tout changement sur un périmètre contrôlé.

## Mode réunion

L'onglet « Réunion » prépare et anime la revue des règles en équipe. Chaque carte du kanban représente une policy et regroupe tous ses constats. Les colonnes sont : À discuter, Supprimer, Modifier, Conserver et Reporter.

- **Préparation** : le tableau se remplit tout seul avec chaque policy qui a au moins un constat ouvert (les constats sur des objets non référencés en sont exclus). Une policy dont tous les constats sont acquittés quitte le tableau, sauf si sa carte a déjà été travaillée (note, décision). La colonne « À discuter » est rangée en groupes repliables : Proposé supprimer, Proposé modifier, Proposé conserver, Sans proposition. Glisser une carte d'un groupe à l'autre change la proposition. Dans chaque groupe, les policies sont classées par hit count croissant, puis par sévérité ; « Trier par priorité » rétablit cet ordre après des déplacements à la main. La séance suit cet ordre. Les cartes affichent le hit count et chacune accepte une note.
- **Séance** : « Démarrer la séance » ouvre une fiche plein écran. À gauche, l'ordre du jour liste les policies par proposition avec leur état (✓ décidée, ↷ reportée, ● en cours) et leur hit count ; un clic ouvre la policy voulue. Au centre, la proposition préparée est colorée (rouge supprimer, ambre modifier, vert conserver) avec l'argument d'usage et la note de préparation, puis le flux (interfaces, adresses, service) et les constats. En bas, une barre de décision toujours visible regroupe les boutons, la justification et l'échéance. Les décisions se prennent avec `S`, `M`, `C`, `R`, et `←`/`→` changent de policy. Sur le tableau, une carte se déplace par glisser-déposer ou avec les touches `1` à `5`.
- **Compte rendu** : il est produit en Markdown (à copier ou télécharger) ou en HTML imprimable, avec les policies regroupées par décision.

Le tableau est enregistré dans le `localStorage` du navigateur, par nom de fichier. Après un nouvel import, une policy qui n'existe plus reste sur le tableau et y est signalée. « Réinitialiser le tableau » efface notes et décisions et reconstruit le tableau à partir des constats ouverts.

## Conformité et historique

Chaque constat affiche les exigences de référentiels concernées (PCI-DSS v4.0, CIS FortiGate, ANSSI), dans le détail, l'export CSV, le rapport HTML et la documentation Markdown. La correspondance est indicative.

Après chaque import, la note globale et les compteurs (jamais le contenu de la configuration) sont enregistrés dans IndexedDB, dans le navigateur. Le panneau « Historique des audits » montre l'évolution par nom de fichier.

## Détection

- Une règle est permissive lorsqu’au moins deux dimensions importantes sont globales (`all`, `ALL` ou `any`).
- Une règle est masquée lorsqu’une règle `accept` active, placée avant elle, couvre entièrement ses interfaces, adresses, services et horaires. La preuve détaille chaque dimension comparée. Les services sont modélisés par protocole, ports destination et ports source. TCP, UDP et SCTP restent distincts; ICMP et ICMP6 utilisent leurs types et codes; les services `IP` utilisent leur numéro de protocole; les groupes imbriqués sont développés récursivement. Un service inconnu n’en couvre un autre que par identité explicite, et seul `ALL` placé dans la règle précédente couvre tous les services.
- Une règle présente un chevauchement partiel lorsque son espace d’adresses et de services intersecte une règle précédente sans être entièrement couvert.
- Les groupes d’adresses et de services sont développés récursivement.
- Les sous-réseaux IPv4, plages IP et plages de ports des services personnalisés sont comparés par leurs bornes réelles.
- Les VDOM sont analysés indépendamment afin d’éviter les collisions d’identifiants et les faux masquages entre contextes.
- Les politiques IPv4 et IPv6 sont analysées séparément, y compris les valeurs globales `all_ipv4` et `all_ipv6`.
- Les politiques au périmètre strictement équivalent sont distinguées des règles simplement masquées.
- Les VIP publiées depuis toutes les sources sont signalées; les IP pools et Internet Services associés aux politiques sont conservés dans l’analyse.
- Les règles désactivées sont exclues des constats.

L’analyse reste volontairement conservatrice pour les objets dynamiques et les fonctions NAT qui ne peuvent pas être résolues depuis la seule table de politiques.

## Intégration continue (SARIF / JSON)

Shadowline peut auditer une configuration versionnée à chaque merge request. La commande `shadowline` produit un rapport **SARIF 2.1.0** (affiché par GitHub code scanning, et lu par Azure DevOps, SonarQube ou DefectDojo) et un rapport **JSON** propre à Shadowline, puis fait échouer le job si des constats dépassent un seuil. Les deux formats sont aussi disponibles dans l'application, menu Exporter.

```bash
npm run build:cli            # produit dist-cli/shadowline.mjs : un seul fichier, Node 20 ou plus, sans dépendance
node dist-cli/shadowline.mjs firewalls/fw-siege.conf \
  --sarif shadowline.sarif --json shadowline.json \
  --fail-on high \
  --acknowledgements acquittements-shadowline.json \
  --baseline baseline.json
```

| Option | Rôle |
| --- | --- |
| `--fail-on` | Sévérité à partir de laquelle un constat ouvert fait échouer le job : `critical`, `high` (défaut), `medium`, `low` ou `none`. |
| `--acknowledgements` | Acquittements exportés depuis l'application : ces constats ne bloquent pas et apparaissent comme *suppressions* dans le SARIF. Un acquittement dont la date de révision est passée ne protège plus. |
| `--baseline` | Rapport JSON de la branche cible : seuls les constats nouveaux bloquent (état `new` / `unchanged` dans le SARIF). Fichier absent : analyse sans référence. |
| `--source-uri` | Chemin du fichier dans le dépôt, repris dans les rapports. |
| `--lang` | Langue des constats, `fr` (défaut) ou `en`. |

Codes de sortie : `0` seuil respecté, `1` constats bloquants, `2` erreur d'utilisation ou d'import. Le résumé affiché dans le journal liste les constats bloquants avec `fichier:ligne`.

Chaque constat d'un export CLI pointe la ligne `edit` de la policy ou de l'objet concerné (VDOM et IPv6 compris) ; un export CSV pointe le fichier sans ligne. L'identifiant du constat sert d'empreinte SARIF : un même constat est suivi d'une analyse à l'autre.

Deux exemples prêts à adapter sont fournis dans `examples/ci/` : `gitlab-ci.yml` et `github-code-scanning.yml`. Ils recalculent la référence à partir du fichier de la branche cible (`git show`), si bien qu'une merge request n'échoue que sur les constats qu'elle introduit, et ne bloquent pas la branche principale (rapports seulement). GitLab n'affiche pas le SARIF dans la merge request : les rapports y sont publiés comme artefacts.

## Langue

L'interface existe en français et en anglais. Les constats, les recommandations, les correspondances de conformité, les exports et le compte rendu de réunion sont aussi traduits. Au premier lancement, la langue suit celle du navigateur ; le bouton `EN` / `FR` de la barre supérieure la change et la mémorise.

Changer de langue recharge la page. Le fichier en cours d'analyse est confié au `sessionStorage` de l'onglet le temps du rechargement, puis effacé dès qu'il est relu et réanalysé dans la nouvelle langue. Si le fichier est trop volumineux pour ce stockage, l'application prévient qu'il faudra le réimporter.

Les identifiants des constats ne dépendent pas de la langue : les acquittements et le tableau de réunion restent valables d'une langue à l'autre. Les textes saisis par l'utilisateur (titre de réunion, notes, justifications) ne sont pas traduits.

## Accessibilité

L'application vise le niveau WCAG 2.2 AA :

- **Clavier** : lien d'évitement vers le contenu, onglets au clavier (`←`/`→`, `Début`/`Fin`), raccourcis dans la liste des constats (`/`, `J`/`K`, `A`, `C`), déplacement des cartes de réunion avec `1` à `5` en alternative au glisser-déposer, décisions de séance au clavier (`S`/`M`/`C`/`R` en français, `D`/`M`/`K`/`P` en anglais). Les boîtes de dialogue sont modales et rendent le focus à l'élément d'origine.
- **Lecteurs d'écran** : langue du document déclarée, repères (`main`, régions nommées), dialogues nommés par leur titre, zone `aria-live` qui annonce la fin d'une analyse, le nombre de constats après un filtre, le déplacement d'une carte et chaque décision de séance.
- **Lisibilité** : contrastes d'au moins 4,5:1 en thème clair et sombre, mise en page sans défilement horizontal jusqu'à 320 px de large, animations coupées si le système demande de réduire les mouvements.

L'audit a été fait avec axe-core (règles WCAG 2.0 à 2.2 A/AA et bonnes pratiques) sur chaque vue et chaque boîte de dialogue, dans les deux thèmes et les deux langues, sans violation restante, puis complété par un parcours au clavier. `src/presentation/accessibility.test.ts` protège ces corrections contre les régressions. Un test avec un vrai lecteur d'écran (NVDA, VoiceOver) reste recommandé avant une diffusion large.

## Vérification

```bash
npm test
npm run build
```

## Licence

Shadowline est un logiciel libre distribué sous [GNU AGPL-3.0-or-later](LICENSE). Si vous proposez une version
modifiée à des utilisateurs via un réseau, vous devez leur donner accès à son code source. Les composants tiers
et leurs licences sont listés dans [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Les contributions sont
acceptées sous [CLA](CLA.md) (voir [CONTRIBUTING.md](CONTRIBUTING.md)).

L'outil aide à l'audit mais ne garantit pas l'exhaustivité des constats : il est fourni « en l'état », sans
garantie (articles 15 et 16 de la licence).
