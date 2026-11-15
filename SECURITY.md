# Sécurité

## Signaler une vulnérabilité

Ne créez pas d'issue publique. Utilisez le signalement privé de GitHub :
onglet **Security** du dépôt, puis **Report a vulnerability**. Une première réponse est donnée sous 7 jours.

## Modèle de menace

- L'application web analyse les fichiers **dans le navigateur** (Web Worker). Le conteneur Docker ne sert que
  des fichiers statiques et refuse les corps de requête ; aucune configuration n'est transmise à un serveur.
- Les préférences, acquittements et le tableau de réunion sont stockés dans le `localStorage` du navigateur ;
  l'historique ne contient que des compteurs (IndexedDB), jamais le contenu de la configuration.
- Les exports FortiGate contiennent souvent des données sensibles : ne joignez jamais une configuration réelle
  non anonymisée à une issue.
