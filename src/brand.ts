/**
 * Identité de l'application, en un seul endroit : nom affiché, identifiant technique (fichiers exportés,
 * commande CI, clés de stockage du navigateur) et dépôt du code source (exigence de l'AGPL pour un usage réseau).
 *
 * Module sans dépendance, sans appel à `tr()` : il est chargé par le worker d'analyse et par la commande CI.
 */
export const APP_NAME = 'Tamisor'
export const APP_SLUG = 'tamisor'
export const SOURCE_URL = 'https://github.com/RedFishX/tamisor'

/** Préfixe des clés `localStorage` / `sessionStorage`. `public/boot.js` le reprend (script classique, sans import). */
export const STORAGE_PREFIX = `${APP_SLUG}-`
/** Préfixes des noms précédents : les clés sont recopiées au démarrage par `public/boot.js`. */
export const LEGACY_STORAGE_PREFIXES = ['fortiscope-', 'shadowline-'] as const

export const storageKey = (name: string): string => `${STORAGE_PREFIX}${name}`
