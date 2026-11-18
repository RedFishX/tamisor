import { describe, expect, it } from 'vitest'
import type { AuditResult, Finding, FirewallPolicy } from './audit'
import { calculateConfigurationScore } from './risk-score'
import { categoryFamilies, prioritizeFindings, scoreWithoutCritical, summarizeFamilies, summarizeVdoms } from './overview'

const finding = (overrides: Partial<Finding>): Finding => ({
  id: overrides.id ?? `f-${Math.random()}`,
  policyId: '1',
  policyName: 'LAN_vers_DMZ',
  order: 1,
  severity: 'medium',
  category: 'permissive',
  title: 'Constat',
  detail: '',
  evidence: [],
  recommendation: { summary: '', actions: [], reference: { title: '', url: '' } },
  ...overrides,
})

const policy = (overrides: Partial<FirewallPolicy>): FirewallPolicy => ({
  id: '1', order: 1, name: 'p', srcintf: [], dstintf: [], srcaddr: [], dstaddr: [], service: [], schedule: [],
  action: 'accept', status: 'enable', nat: 'disable', utmStatus: 'disable', logtraffic: 'all', comments: '',
  destinationVips: [], internetServices: [], ipPools: [],
  ...overrides,
})

describe('categoryFamilies', () => {
  it('range chaque catégorie dans une famille', () => {
    expect(Object.keys(categoryFamilies)).toHaveLength(13)
    expect(categoryFamilies.shadowed).toBe('risk')
    expect(categoryFamilies.visibility).toBe('hygiene')
    expect(categoryFamilies.inspection).toBe('governance')
  })
})

describe('summarizeFamilies', () => {
  it('compte les constats par famille et par sévérité, dans un ordre fixe', () => {
    const summary = summarizeFamilies([
      finding({ category: 'permissive', severity: 'critical' }),
      finding({ category: 'shadowed', severity: 'high' }),
      finding({ category: 'unused', severity: 'medium' }),
    ])
    expect(summary.map((item) => item.family)).toEqual(['risk', 'hygiene', 'governance'])
    expect(summary[0]).toMatchObject({ total: 2, bySeverity: { critical: 1, high: 1, medium: 0, low: 0 } })
    expect(summary[1].total).toBe(1)
    expect(summary[2].total).toBe(0)
  })
})

describe('summarizeVdoms', () => {
  it('compte les politiques actives et les constats par VDOM, les plus critiques en premier', () => {
    const summary = summarizeVdoms(
      [policy({ vdom: 'root' }), policy({ id: '2', vdom: 'root', status: 'disable' }), policy({ id: '3', vdom: 'dmz' })],
      [finding({ vdom: 'dmz', severity: 'critical' }), finding({ vdom: 'root' }), finding({ vdom: 'root' })],
    )
    expect(summary).toEqual([
      { vdom: 'dmz', policies: 1, findings: 1, critical: 1 },
      { vdom: 'root', policies: 1, findings: 2, critical: 0 },
    ])
  })

  it('regroupe les éléments sans VDOM sous « global »', () => {
    expect(summarizeVdoms([policy({})], [])[0].vdom).toBe('global')
  })
})

describe('prioritizeFindings', () => {
  it('trie par risque et signale les constats levés par la même correction', () => {
    const permissive = finding({ id: 'a', policyId: '22', severity: 'critical', category: 'permissive' })
    const shadowed = finding({ id: 'b', policyId: '9', severity: 'high', category: 'shadowed', shadowedBy: '22' })
    const minor = finding({ id: 'c', policyId: '3', severity: 'low', category: 'unused' })
    const result = prioritizeFindings([minor, shadowed, permissive], 2)
    expect(result.map((item) => item.finding.id)).toEqual(['a', 'b'])
    expect(result[0].alsoResolves).toBe(1)
    expect(result[1].alsoResolves).toBe(0)
  })
})

describe('scoreWithoutCritical', () => {
  it('recalcule la note sans les constats critiques', () => {
    const audit = {
      policies: [],
      findings: [finding({ severity: 'critical', policyId: '1' }), finding({ severity: 'low', policyId: '2' })],
      stats: { activePolicies: 4 },
    } as unknown as AuditResult
    expect(scoreWithoutCritical(audit)).toBeGreaterThan(calculateConfigurationScore(audit))
    expect(scoreWithoutCritical(audit)).toBe(calculateConfigurationScore({ ...audit, findings: [audit.findings[1]] }))
  })
})
