# FortiScope

Application locale d’aide à l’audit des politiques FortiGate. Elle signale les règles très permissives, les règles entièrement masquées par une règle précédente et les règles sans journalisation.

Chaque constat fournit un plan de remédiation contextualisé, un exemple CLI à adapter et une référence vers la documentation officielle Fortinet. Les recommandations suivent notamment les critères de correspondance des politiques FortiOS, leur ordre d’évaluation et le principe de restriction des sources, destinations et services.

## Utilisation

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

Le bouton de thème dans l’en-tête bascule entre les affichages clair et sombre. La préférence est conservée localement; sans préférence enregistrée, FortiScope suit le thème du système.

Les exports CSV avec séparateur virgule ou point-virgule sont reconnus. Les en-têtes FortiGate usuels sont acceptés, notamment `Policy ID`, `Name`, `From`, `To`, `Source`, `Destination`, `Schedule`, `Service`, `Action`, `NAT`, `Security Profiles`, `Log Traffic` et `Status`. Les exports GUI utilisant une colonne combinée `Policy` au format `Nom (ID)` et des lignes de section sont également pris en charge.

Les compteurs Alertes critiques, Règles permissives et Règles masquées filtrent directement les constats. Cliquez une seconde fois sur le compteur actif pour réafficher tous les résultats.

Le profil de risque peut être réglé sur Standard ou Strict. Le détail d’un constat présente surtout une matrice métier pour chaque élément de la règle : interfaces, sources, destinations, services, horaire, action, NAT, profils de sécurité et journalisation. Chaque ligne indique un niveau faible, moyen ou élevé, la valeur concernée et une justification opérationnelle, sans exposer la formule de calcul.

Le filtre « Hit count » range les policies par tranche d'utilisation (jamais, faible, moyenne, forte). Il n'est disponible qu'avec un export CSV qui contient la colonne `Hit Count`. Les constats peuvent être acquittés localement et restaurés avec l’option `Afficher les acquittés`. Une seconde configuration peut être sélectionnée avec `Comparer` pour compter les politiques ajoutées, modifiées et supprimées. Les exports CSV peuvent aussi fournir `Hit Count` et `Last Used`.

Le menu `Exporter` regroupe les constats CSV, le rapport HTML interactif et les commandes CLI. Le rapport autonome reprend le langage visuel de FortiScope, permet de rechercher et filtrer les constats, de déplier leur détail et de lancer une impression propre. L’export CLI regroupe séparément les commandes de remédiation à examiner et adapter avant application.

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

## Vérification

```bash
npm test
npm run build
```