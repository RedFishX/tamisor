import type { AuditResult } from '../domain/audit'
import { calculateConfigurationScore } from '../domain/risk-score'

export interface HistoryEntry {
  id: string
  sourceName: string
  analyzedAt: string
  score: number
  activePolicies: number
  critical: number
  high: number
  findings: number
}

export interface HistoryStore {
  list: () => Promise<HistoryEntry[]>
  add: (entry: HistoryEntry) => Promise<void>
  clear: () => Promise<void>
}

export interface HistoryTrend {
  current: HistoryEntry
  previous?: HistoryEntry
  scoreDelta?: number
  findingsDelta?: number
}

const MAX_ENTRIES_PER_SOURCE = 50

/** Seules des statistiques sont conservées : jamais le contenu de la configuration. */
export const createHistoryEntry = (audit: AuditResult, sourceName: string, now: Date): HistoryEntry => ({
  id: `${now.getTime()}-${sourceName}`,
  sourceName,
  analyzedAt: now.toISOString(),
  score: calculateConfigurationScore(audit),
  activePolicies: audit.stats.activePolicies,
  critical: audit.stats.critical,
  high: audit.stats.high,
  findings: audit.findings.length,
})

const sameSnapshot = (left: HistoryEntry, right: HistoryEntry): boolean =>
  left.score === right.score && left.activePolicies === right.activePolicies && left.critical === right.critical &&
  left.high === right.high && left.findings === right.findings

export const entriesForSource = (entries: HistoryEntry[], sourceName: string): HistoryEntry[] =>
  entries.filter((entry) => entry.sourceName === sourceName).sort((left, right) => left.analyzedAt.localeCompare(right.analyzedAt))

export const computeTrend = (entries: HistoryEntry[], sourceName: string): HistoryTrend | null => {
  const history = entriesForSource(entries, sourceName)
  const current = history.at(-1)
  if (!current) return null
  const previous = history.at(-2)
  return {
    current,
    previous,
    scoreDelta: previous ? current.score - previous.score : undefined,
    findingsDelta: previous ? current.findings - previous.findings : undefined,
  }
}

/** Enregistre l'audit sauf s'il est identique au dernier de la même source (rechargement du même fichier). */
export const recordAudit = async (
  store: HistoryStore,
  audit: AuditResult,
  sourceName: string,
  now: Date = new Date(),
): Promise<HistoryEntry[]> => {
  const entry = createHistoryEntry(audit, sourceName, now)
  const existing = await store.list()
  const latest = entriesForSource(existing, sourceName).at(-1)
  if (!latest || !sameSnapshot(latest, entry)) await store.add(entry)
  const all = await store.list()
  return entriesForSource(all, sourceName).slice(-MAX_ENTRIES_PER_SOURCE)
}
