import { entriesForSource, type HistoryEntry } from '../application/audit-history'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)

const formatDate = (iso: string): string => {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' })
}

const formatDelta = (delta: number): string => (delta > 0 ? `+${delta}` : String(delta))

export const renderHistory = (entries: HistoryEntry[], sourceName: string, unavailable = false): string => {
  if (unavailable) return '<p class="history-empty">Historique indisponible dans ce navigateur.</p>'
  const history = entriesForSource(entries, sourceName).slice(-6).reverse()
  if (!history.length) return '<p class="history-empty">Aucun audit enregistré pour ce fichier.</p>'
  return `<ol class="history-list">${history.map((entry, index) => {
    const older = history[index + 1]
    const delta = older ? entry.score - older.score : null
    const tone = delta === null || delta === 0 ? 'flat' : delta > 0 ? 'up' : 'down'
    return `<li><time datetime="${escapeHtml(entry.analyzedAt)}">${escapeHtml(formatDate(entry.analyzedAt))}</time>`
      + `<strong>${entry.score}<small>/100</small></strong>`
      + `<span class="history-delta ${tone}">${delta === null ? '—' : formatDelta(delta)}</span>`
      + `<small>${entry.findings} constat(s), ${entry.critical} critique(s)</small></li>`
  }).join('')}</ol>`
}
