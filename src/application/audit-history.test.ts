import { describe, expect, it } from 'vitest'
import type { AuditResult } from '../domain/audit'
import { computeTrend, recordAudit, type HistoryEntry, type HistoryStore } from './audit-history'

const audit = (critical: number, findings: number): AuditResult => ({
  policies: [],
  findings: Array.from({ length: findings }, (_, index) => ({
    id: `f${index}`, policyId: String(index), policyName: `P${index}`, order: index, severity: index < critical ? 'critical' : 'low',
    category: 'permissive', title: 't', detail: 'd', evidence: [],
    recommendation: { summary: 's', actions: [], reference: { title: 'r', url: 'https://example.test' } },
  })),
  stats: { activePolicies: 10, critical, high: 0, shadowed: 0, overlaps: 0, duplicates: 0, exposures: 0, permissive: findings, unused: 0, indeterminate: 0 },
})

const memoryStore = (): HistoryStore & { entries: HistoryEntry[] } => {
  const entries: HistoryEntry[] = []
  return { entries, list: async () => [...entries], add: async (entry) => { entries.push(entry) }, clear: async () => { entries.length = 0 } }
}

describe('audit history', () => {
  it('conserve uniquement des statistiques et calcule la tendance entre deux audits', async () => {
    const store = memoryStore()
    await recordAudit(store, audit(3, 6), 'siege.conf', new Date('2026-09-01T09:00:00Z'))
    const entries = await recordAudit(store, audit(1, 3), 'siege.conf', new Date('2026-10-01T09:00:00Z'))

    expect(entries).toHaveLength(2)
    expect(Object.keys(entries[0]).sort()).toEqual(['activePolicies', 'analyzedAt', 'critical', 'findings', 'high', 'id', 'score', 'sourceName'])
    const trend = computeTrend(entries, 'siege.conf')!
    expect(trend.scoreDelta).toBeGreaterThan(0)
    expect(trend.findingsDelta).toBe(-3)
  })

  it('ignore un rechargement identique du même fichier et sépare les sources', async () => {
    const store = memoryStore()
    await recordAudit(store, audit(1, 3), 'siege.conf', new Date('2026-09-01T09:00:00Z'))
    await recordAudit(store, audit(1, 3), 'siege.conf', new Date('2026-09-01T10:00:00Z'))
    await recordAudit(store, audit(0, 1), 'agence.conf', new Date('2026-09-01T11:00:00Z'))

    expect(store.entries).toHaveLength(2)
    expect(computeTrend(store.entries, 'agence.conf')?.previous).toBeUndefined()
    expect(computeTrend(store.entries, 'absent.conf')).toBeNull()
  })
})
