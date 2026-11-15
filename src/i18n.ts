/**
 * Langue de l'interface et des textes produits par l'analyse (français ou anglais).
 *
 * Chaque texte est écrit à l'endroit où il est utilisé, sous forme de paire : `tr('Constats', 'Findings')`.
 * La langue est fixée pour toute la durée de la page : la changer recharge l'application.
 *
 * - Thread principal : la langue est lue au chargement de ce module (préférence enregistrée, sinon
 *   langue du navigateur). Ce module n'a aucune dépendance : il est évalué avant tous ceux qui l'importent.
 * - Web Worker d'analyse : il reçoit la langue avec chaque fichier et appelle `setLocale` avant l'analyse.
 *   Le code exécuté dans le worker (analyseur) n'appelle donc jamais `tr` au niveau module.
 */
export type Locale = 'fr' | 'en'

export const locales: Locale[] = ['fr', 'en']
export const localeStorageKey = 'fortiscope-locale'

export const isLocale = (value: unknown): value is Locale => value === 'fr' || value === 'en'

/** Préférence enregistrée, sinon langue du navigateur (français pour toute variante `fr-*`, anglais sinon). */
export const resolveLocale = (stored: string | null | undefined, browserLanguage: string | undefined): Locale =>
  isLocale(stored) ? stored : browserLanguage?.toLowerCase().startsWith('fr') ? 'fr' : 'en'

const initialLocale = (): Locale => {
  try {
    if (typeof localStorage === 'undefined' || typeof navigator === 'undefined') return 'fr'
    return resolveLocale(localStorage.getItem(localeStorageKey), navigator.language)
  } catch {
    return 'fr'
  }
}

let current: Locale = initialLocale()

export const getLocale = (): Locale => current
export const setLocale = (locale: Locale): void => { current = locale }

/** Texte bilingue, choisi selon la langue courante. */
export const tr = (fr: string, en: string): string => current === 'en' ? en : fr

/**
 * Accord en nombre. Le français met le singulier à 0 et 1 (« 0 constat »), l'anglais seulement à 1 (« 0 findings »).
 * Renvoie uniquement le mot, sans le nombre.
 */
export const plural = (count: number, fr: [string, string], en: [string, string]): string =>
  current === 'en' ? (count === 1 ? en[0] : en[1]) : (count <= 1 ? fr[0] : fr[1])

/** Locale Intl correspondante, pour les dates et les nombres. */
export const intlLocale = (): string => current === 'en' ? 'en-GB' : 'fr-FR'

export const formatNumber = (value: number): string => value.toLocaleString(intlLocale())

export const formatDate = (iso: string, options: Intl.DateTimeFormatOptions = { day: '2-digit', month: 'short', year: 'numeric' }): string => {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString(intlLocale(), options)
}
