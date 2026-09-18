import { describe, expect, it } from 'vitest'
import type { AuditResult, Finding } from './audit'
import { calculateConfigurationScore, calculateRiskScore, explainRiskScore } from './risk-score'

const finding = {
  severity: 'high',
  category: 'exposure',
} as Finding

describe('calculateRiskScore', () => {
  it('calcule un score borné pour le profil standard', () => {
    expect(calculateRiskScore(finding, 'standard')).toBe(80)
  })

  it('augmente le score avec le profil strict sans dépasser 100', () => {
    expect(calculateRiskScore(finding, 'strict')).toBe(95)
    expect(calculateRiskScore({ ...finding, severity: 'critical' }, 'strict')).toBe(100)
  })

  it('détaille chaque composante et le plafonnement du score', () => {
    expect(explainRiskScore(finding, 'strict')).toEqual({
      score: 95,
      severityBase: 70,
      categoryBonus: 10,
      profileBonus: 15,
      capped: false,
      reasons: [
        'Sévérité élevée : 70 points',
        'Exposition d’une VIP : +10 points',
        'Profil strict : +15 points',
      ],
    })
    expect(explainRiskScore({ ...finding, severity: 'critical' }, 'strict').capped).toBe(true)
  })

  it('calcule une note globale sur 100 et plafonne la pénalité par policy', () => {
    const audit = {
      policies: [{ id: '1' }],
      findings: [
        { ...finding, policyId: '1', severity: 'critical' },
        { ...finding, policyId: '1', severity: 'high' },
      ],
      stats: { activePolicies: 1 },
    } as AuditResult

    expect(calculateConfigurationScore(audit)).toBe(0)
    expect(calculateConfigurationScore({ ...audit, findings: [] })).toBe(100)
  })
})