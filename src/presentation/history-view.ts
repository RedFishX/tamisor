import { entriesForSource, type HistoryEntry } from '../application/audit-history'
import { formatDate, plural, tr } from '../i18n'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)

const formatDelta = (delta: number): string => (delta > 0 ? `+${delta}` : String(delta))

export const renderHistory = (entries: HistoryEntry[], sourceName: string, unavailable = false): string => {
  if (unavailable) return `<p class="history-empty">${tr('Historique indisponible dans ce navigateur.', 'History is not available in this browser.')}</p>`
  const history = entriesForSource(entries, sourceName).slice(-6).reverse()
  if (!history.length) return `<p class="history-empty">${tr('Aucun audit enregistré pour ce fichier.', 'No audit recorded for this file.')}</p>`
  return `<ol class="history-list">${history.map((entry, index) => {
    const older = history[index + 1]
    const delta = older ? entry.score - older.score : null
    const tone = delta === null || delta === 0 ? 'flat' : delta > 0 ? 'up' : 'down'
    return `<li><time datetime="${escapeHtml(entry.analyzedAt)}">${escapeHtml(formatDate(entry.analyzedAt))}</time>`
      + `<strong>${entry.score}<small>/100</small></strong>`
      + `<span class="history-delta ${tone}">${delta === null ? '<span aria-hidden="true">—</span>' : formatDelta(delta)}</span>`
      + `<small>${entry.findings} ${plural(entry.findings, ['constat', 'constats'], ['finding', 'findings'])}, ${entry.critical} ${plural(entry.critical, ['critique', 'critiques'], ['critical', 'critical'])}</small></li>`
  }).join('')}</ol>`
}
