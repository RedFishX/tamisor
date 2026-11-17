// Neutralisation du texte importé (config, CSV) avant qu'il atteigne un format orienté lignes :
// script CLI FortiOS, journal de CI. Pur, sans I/O ni traduction (chargé par le worker).

const LINE_BREAKS_AND_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g

/** Remplace tout saut de ligne ou caractère de contrôle par une espace : le résultat tient sur une ligne. */
export const singleLine = (value: string): string => value.replace(LINE_BREAKS_AND_CONTROLS, ' ').trim()

/**
 * Identifiant utilisable après `edit` dans un script FortiOS : les identifiants de politique
 * sont numériques et restent tels quels ; toute autre valeur est mise entre guillemets
 * (guillemets et antislashs échappés), sur une seule ligne.
 */
export const cliEditToken = (id: string): string => {
  const safe = singleLine(id)
  return /^\d+$/.test(safe) ? safe : `"${safe.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/** Neutralise une cellule CSV qu'un tableur interpréterait comme une formule (=, +, -, @, tabulation, CR). */
export const neutralizeSpreadsheetFormula = (value: string): string => (/^[=+\-@\t\r]/.test(value) ? `'${value}` : value)
