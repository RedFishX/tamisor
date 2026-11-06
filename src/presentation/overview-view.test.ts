import { describe, expect, it } from 'vitest'
import type { HistoryEntry } from '../application/audit-history'
import { renderOverview, renderScoreSparkline, type OverviewModel } from './overview-view'

const entry = (score: number, analyzedAt: string): HistoryEntry => ({
  id: analyzedAt, sourceName: 'fw.conf', analyzedAt, score, activePolicies: 10, critical: 0, high: 0, findings: 0,
})

const model = (overrides: Partial<OverviewModel> = {}): OverviewModel => ({
  score: 62,
  tone: 'warning',
  criticalCount: 0,
  history: [],
  families: [],
  vdoms: [],
  priorities: [],
  openFindings: 0,
  ...overrides,
})

describe('renderScoreSparkline', () => {
  it('explique l’absence de courbe au premier audit', () => {
    expect(renderScoreSparkline([entry(62, '2026-11-04T10:00:00Z')])).toContain('Premier audit de ce fichier')
  })

  it('trace une courbe et étiquette le premier et le dernier audit', () => {
    const svg = renderScoreSparkline([entry(48, '2026-06-12T10:00:00Z'), entry(62, '2026-11-04T10:00:00Z')])
    expect(svg).toContain('<polyline')
    expect(svg).toContain('Note de 48 à 62 sur 2 audits')
  })
})

describe('renderOverview', () => {
  it('formule l’écart et le gain possible sans double ponctuation', () => {
    const html = renderOverview(model({ scoreDelta: 7, previousDate: '2026-10-21T10:00:00Z', scoreAfterCritical: 78, criticalCount: 2 }))
    expect(html).toContain('+7 points depuis l’audit du 21 oct.')
    expect(html).not.toContain('..')
    expect(html).toContain('Corriger les 2 constats critiques la porterait à 78.')
  })

  it('signale une note stable', () => {
    expect(renderOverview(model({ scoreDelta: 0, previousDate: '2026-10-21T10:00:00Z' }))).toContain('Note stable depuis l’audit du 21 oct.')
  })

  it('échappe les noms de VDOM', () => {
    const html = renderOverview(model({ vdoms: [{ vdom: '<root>', policies: 1, findings: 0, critical: 0 }] }))
    expect(html).toContain('&lt;root&gt;')
    expect(html).not.toContain('<root>')
  })
})
