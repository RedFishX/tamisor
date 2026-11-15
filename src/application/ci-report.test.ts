import { describe, expect, it } from 'vitest'
import type { AuditResult, Finding } from '../domain/audit'
import { meetingFinding as finding } from '../test-fixtures/meeting-fixtures'
import {
  buildJsonReport, buildSarifReport, classifyFindings, evaluateGate, parseBaselineIds, renderTextSummary, ruleId, type ReportContext,
} from './ci-report'

const audit = (findings: Finding[]): AuditResult => ({
  policies: [],
  findings,
  stats: { activePolicies: 12, critical: 0, high: 0, shadowed: 0, overlaps: 0, duplicates: 0, exposures: 0, permissive: 0, unused: 0, indeterminate: 0 },
})

const findings = [
  finding({ id: 'permissive-root-ipv4-10', policyId: '10', policyName: 'Internet', severity: 'critical', category: 'permissive', title: 'Règle très permissive' }),
  finding({ id: 'shadowed-root-ipv4-20', policyId: '20', policyName: 'Web', severity: 'high', category: 'shadowed', title: 'Règle masquée' }),
  finding({ id: 'visibility-root-ipv4-30', policyId: '30', policyName: 'DNS', severity: 'medium', category: 'visibility', title: 'Journalisation désactivée' }),
]

const context = (overrides: Partial<ReportContext> = {}): ReportContext => ({
  audit: audit(findings),
  sourceUri: 'firewalls/fw-siege.conf',
  toolVersion: '1.2.0',
  locate: (item) => ({ '10': 41, '20': 57 } as Record<string, number>)[item.policyId],
  today: '2026-11-20',
  generatedAt: '2026-11-20T08:00:00.000Z',
  ...overrides,
})

const acknowledgement = (id: string, reviewDate: string) => ({
  key: `fw-siege.conf:${id}`, justification: 'Flux validé par la DSI (CHG-4812)', reviewDate, acknowledgedAt: '2026-10-01T00:00:00.000Z',
})

describe('seuil de CI', () => {
  it('bloque les constats ouverts au niveau du seuil ou au-dessus', () => {
    expect(evaluateGate(classifyFindings(context()), 'high')).toEqual({ failOn: 'high', blocking: 2, passed: false })
    expect(evaluateGate(classifyFindings(context({ failOn: 'critical' })), 'critical').blocking).toBe(1)
    expect(evaluateGate(classifyFindings(context({ failOn: 'none' })), 'none').passed).toBe(true)
  })

  it('ne bloque pas un constat acquitté, sauf si sa date de révision est passée', () => {
    const reported = classifyFindings(context({
      acknowledgements: [acknowledgement('permissive-root-ipv4-10', '2027-03-01'), acknowledgement('shadowed-root-ipv4-20', '2026-11-01')],
    }))
    expect(reported.map((item) => [item.status, item.blocking])).toEqual([
      ['acknowledged', false], ['acknowledgement-expired', true], ['open', false],
    ])
  })

  it('avec une référence, ne bloque que les constats nouveaux', () => {
    const reported = classifyFindings(context({ baselineIds: new Set(['permissive-root-ipv4-10']) }))
    expect(reported.map((item) => [item.baseline, item.blocking])).toEqual([['unchanged', false], ['new', true], ['new', false]])
  })
})

describe('rapport JSON', () => {
  it('décrit la source, le résumé, le seuil et chaque constat avec sa ligne', () => {
    const report = buildJsonReport(context({ baselineIds: new Set(['permissive-root-ipv4-10', 'disparu']) }))
    expect(report).toMatchObject({
      format: 'tamisor-report', version: 1, tool: { name: 'Tamisor', version: '1.2.0' }, source: { file: 'firewalls/fw-siege.conf' },
      summary: { activePolicies: 12, findings: 3, open: 3, bySeverity: { critical: 1, high: 1, medium: 1, low: 0 }, baseline: { new: 2, fixed: 1 }, gate: { blocking: 1, passed: false } },
    })
    expect(report.findings[0]).toMatchObject({ id: 'permissive-root-ipv4-10', status: 'open', baseline: 'unchanged', policy: { id: '10', line: 41 } })
    expect(report.findings[2].policy).not.toHaveProperty('line')
  })

  it('se relit comme référence, et refuse un autre format', () => {
    expect(parseBaselineIds(JSON.stringify(buildJsonReport(context())))).toEqual(new Set(findings.map((item) => item.id)))
    expect(() => parseBaselineIds('{"runs": []}')).toThrow()
  })
})

describe('rapport SARIF', () => {
  it('suit la structure SARIF 2.1.0 avec une règle par catégorie présente', () => {
    const sarif = buildSarifReport(context())
    expect(sarif.version).toBe('2.1.0')
    const run = sarif.runs[0]
    expect(run.tool.driver.rules.map((rule) => rule.id)).toEqual([ruleId('permissive'), ruleId('shadowed'), ruleId('visibility')])
    expect(run.tool.driver.rules[0].properties['security-severity']).toBe('9.5')
    expect(run.results.map((result) => result.level)).toEqual(['error', 'error', 'warning'])
  })

  it('localise chaque résultat et lui donne une empreinte stable', () => {
    const [first, , third] = buildSarifReport(context()).runs[0].results
    expect(first.locations[0].physicalLocation).toEqual({ artifactLocation: { uri: 'firewalls/fw-siege.conf', index: 0 }, region: { startLine: 41 } })
    expect(third.locations[0].physicalLocation).not.toHaveProperty('region')
    expect(first.partialFingerprints).toEqual({ 'tamisorFindingId/v1': 'permissive-root-ipv4-10' })
    expect(first.ruleIndex).toBe(0)
  })

  it('déclare les acquittements comme suppressions et l’état par rapport à la référence', () => {
    const results = buildSarifReport(context({
      acknowledgements: [acknowledgement('permissive-root-ipv4-10', '2027-03-01')],
      baselineIds: new Set(['shadowed-root-ipv4-20']),
    })).runs[0].results
    expect(results[0].suppressions).toEqual([{ kind: 'external', status: 'accepted', justification: 'Flux validé par la DSI (CHG-4812)' }])
    expect(results[1]).not.toHaveProperty('suppressions')
    expect(results.map((result) => result.baselineState)).toEqual(['new', 'unchanged', 'new'])
  })
})

describe('résumé texte', () => {
  it('liste les constats bloquants avec fichier et ligne', () => {
    const text = renderTextSummary(context())
    expect(text).toContain('Seuil « high » dépassé : 2 constat(s) bloquant(s).')
    expect(text).toContain('  - [critical] firewalls/fw-siege.conf:41 #10 Internet — Règle très permissive')
  })
})
