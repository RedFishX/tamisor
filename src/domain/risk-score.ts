import type { AuditResult, Finding, Severity } from './audit'

export type RiskProfile = 'standard' | 'strict'

const severityScores: Record<Severity, number> = {
  critical: 90,
  high: 70,
  medium: 40,
  low: 15,
}

const categoryBonus: Partial<Record<Finding['category'], number>> = {
  exposure: 10,
  permissive: 5,
  shadowed: 5,
}

const severityLabels: Record<Severity, string> = {
  critical: 'Sévérité critique',
  high: 'Sévérité élevée',
  medium: 'Sévérité moyenne',
  low: 'Sévérité faible',
}

const categoryReasons: Partial<Record<Finding['category'], string>> = {
  exposure: 'Exposition d’une VIP',
  permissive: 'Périmètre permissif',
  shadowed: 'Règle masquée',
}

const configurationPenalties: Record<Severity, number> = {
  critical: 18,
  high: 10,
  medium: 4,
  low: 1,
}

export const calculateConfigurationScore = (audit: AuditResult): number => {
  const penaltyByPolicy = new Map<string, number>()
  for (const finding of audit.findings) {
    const key = `${finding.vdom ?? 'global'}:${finding.family ?? 'ipv4'}:${finding.policyId}`
    const current = penaltyByPolicy.get(key) ?? 0
    penaltyByPolicy.set(key, Math.min(25, current + configurationPenalties[finding.severity]))
  }
  const penalty = [...penaltyByPolicy.values()].reduce((total, value) => total + value, 0)
  return Math.max(0, Math.round(100 - (penalty / Math.max(1, audit.stats.activePolicies)) * 10))
}

export interface RiskAssessment {
  score: number
  severityBase: number
  categoryBonus: number
  profileBonus: number
  capped: boolean
  reasons: string[]
}

export const explainRiskScore = (finding: Finding, profile: RiskProfile): RiskAssessment => {
  const severityBase = severityScores[finding.severity]
  const findingCategoryBonus = categoryBonus[finding.category] ?? 0
  const strictBonus = profile === 'strict' ? 15 : 0
  const rawScore = severityBase + findingCategoryBonus + strictBonus
  const reasons = [`${severityLabels[finding.severity]} : ${severityBase} points`]
  if (findingCategoryBonus) reasons.push(`${categoryReasons[finding.category]} : +${findingCategoryBonus} points`)
  if (strictBonus) reasons.push(`Profil strict : +${strictBonus} points`)
  return {
    score: Math.min(100, rawScore),
    severityBase,
    categoryBonus: findingCategoryBonus,
    profileBonus: strictBonus,
    capped: rawScore > 100,
    reasons,
  }
}

export const calculateRiskScore = (finding: Finding, profile: RiskProfile): number =>
  explainRiskScore(finding, profile).score
