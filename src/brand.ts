/**
 * Identité de l'application, en un seul endroit : nom affiché, identifiant technique (fichiers exportés,
 * commande CI, clés de stockage du navigateur) et dépôt du code source (exigence de l'AGPL pour un usage réseau).
 *
 * Module sans dépendance, sans appel à `tr()` : il est chargé par le worker d'analyse et par la commande CI.
 */
export const APP_NAME = 'Shadowline'
export const APP_SLUG = 'shadowline'
export const SOURCE_URL = 'https://github.com/RedFishX/shadowline'

/** Préfixe des clés `localStorage` / `sessionStorage`. `public/boot.js` le reprend (script classique, sans import). */
export const STORAGE_PREFIX = `${APP_SLUG}-`
/** Préfixe utilisé avant le changement de nom : les clés sont recopiées au démarrage par `public/boot.js`. */
export const LEGACY_STORAGE_PREFIX = 'fortiscope-'

export const storageKey = (name: string): string => `${STORAGE_PREFIX}${name}`
