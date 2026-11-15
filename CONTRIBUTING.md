# Contribuer à Shadowline

Merci de votre intérêt. Les signalements de faux positifs ou faux négatifs sont particulièrement utiles :
joignez un extrait de configuration **anonymisé** (adresses, noms, mots de passe, clés et certificats retirés).

## Avant d'ouvrir une pull request

```bash
npm install
npm test
npm run build   # typecheck strict + application + commande CI
```

- Chaque texte visible est une paire `tr('français', 'English')` (`src/i18n.ts`) ; pas d'appel à `tr()` au niveau
  module dans le code chargé par le worker (`analyzer.ts`, `csv-policy-parser.ts`).
- Les identifiants de constats ne dépendent pas de la langue, et le format JSON / les empreintes SARIF sont un
  contrat pour les utilisateurs de la CI : ne les changez pas sans discussion.
- Accessibilité WCAG 2.2 AA : chemin clavier pour chaque interaction, annonces via `announce()`.
- Ajoutez un test pour toute règle de détection nouvelle ou modifiée.

## Accord de contribution (CLA)

Shadowline est publié sous AGPL-3.0 et pourra aussi être proposé sous une licence commerciale. Pour que cela
reste possible, chaque contributeur accepte le [CLA](CLA.md) une seule fois, au moment de sa première pull
request (un commentaire automatique explique comment faire). Vous conservez le droit d'auteur sur vos
contributions.
