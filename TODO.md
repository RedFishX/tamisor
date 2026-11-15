# TODO

Priorités : 🔴 haute · 🟠 moyenne · ⚪ basse

## Détection

- [x] 🔴 **Objets inutilisés / en doublon** : adresses, services et groupes non référencés par une policy, objets identiques sous deux noms. *(Les membres de groupes référencés sont désormais comptés comme utilisés ; doublons détectés pour adresses, services et groupes. Limite : les références hors policies, ex. routes statiques ou SSL-VPN, ne sont pas vues.)*
- [x] 🔴 **Profils de sécurité absents** : règle `accept` sans AV, IPS, web filter ou SSL inspection. *(Aucun profil = moyen, profils partiels IPS/AV/Web = faible, `profile-group` résolu. Ignoré pour les imports CSV, qui n'exposent pas les profils.)*
- [x] 🟠 **Politiques jamais touchées** : croiser avec les hit counts (`diagnose firewall iprope` ou colonne « Hit count » d'un export CSV) pour repérer les règles sans trafic sur 90 jours. *(Déjà présent pour le CSV ; ajouts : séparateurs de milliers dans « Hit Count », « Last Used = Never ». Un export CLI ne contient pas ces compteurs.)*
- [x] 🟠 **Règles trop larges côté interface** : `any` en `srcintf`/`dstintf`, services type `ALL_TCP`. À intégrer au critère « permissive ». *(ALL_TCP/ALL_UDP/ALL_SCTP comptent comme service global ; une interface `any` isolée donne un constat moyen « Interfaces non restreintes ».)*
- [ ] ⚪ **Hygiène de configuration** : admin sans MFA, `trusted-host` absents, HTTP/Telnet activé sur les interfaces, firmware vulnérable.

## Produit

- [x] 🟠 **Historique local** (IndexedDB) pour suivre l'évolution du score entre plusieurs audits. *(Statistiques seules, jamais le contenu de la config ; panneau dans la barre latérale, par nom de fichier, bouton Effacer.)*
- [x] 🟠 **Mapping de conformité** : lier chaque finding à CIS FortiGate, ANSSI, PCI-DSS. *(Indicatif : PCI-DSS v4.0 référencé par numéro ; CIS et ANSSI par thème, sans numéro de contrôle à vérifier à la source. Affiché dans le détail, le CSV, le rapport HTML et la doc Markdown.)*
- [x] 🟠 **Mode réunion** : kanban des policies à revoir (À discuter, Supprimer, Modifier, Conserver, Reporter), fiche plein écran avec décisions au clavier, compte rendu Markdown/HTML. *(Tableau local par fichier ; pas de partage multi-postes.)*
- [ ] ⚪ **Export SARIF / JSON** pour intégration CI (audit d'un `.conf` versionné à chaque merge request).
- [ ] ⚪ **i18n** : version anglaise de l'interface ; revue accessibilité.

## Qualité

- [x] 🟠 **Performance de l'analyseur** : 5000 policies passent de ~8 s à ~0,8 s. *(Profilage : comparaisons de paires de policies. Corrigé en développant les groupes une seule fois (cache) et en ne comparant que les policies dont les interfaces sont compatibles. Résultat vérifié identique à la recherche exhaustive sur 4 configs de 1200 policies ; le test de volumétrie impose maintenant < 5 s.)*
- [ ] ⚪ **CI GitHub Actions** (`npm test` + `npm run build`) et déploiement statique (Cloudflare Pages ou GitHub Pages).
- [x] 🟠 **Fixtures réalistes anonymisées**, dont une grosse config (> 5000 policies) pour `analyzer.performance.test.ts`. *(Générateur synthétique `src/test-fixtures/realistic-config.ts` ; de vraies configs anonymisées restent à fournir.)*
- [x] 🟠 **Tests de la couche présentation** : `audit-report.ts`, `policy-documentation.ts` *(Déjà couverts : rapport, doc, export, thème. Ajoutés : conformité, historique. `main.ts`, qui porte l'état et le DOM, reste sans test.)*



# UI
- [] Modifier le design des 0 . supprimer le point à l'intérieur