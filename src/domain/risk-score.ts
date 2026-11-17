import type { AuditResult, Finding, Severity } from './audit'
import { tr } from '../i18n'
import { policyKey } from './policy-key'

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

const severityLabels = (): Record<Severity, string> => ({
  critical: tr('Sévérité critique', 'Critical severity'),
  high: tr('Sévérité élevée', 'High severity'),
  medium: tr('Sévérité moyenne', 'Medium severity'),
  low: tr('Sévérité faible', 'Low severity'),
})

const categoryReasons = (): Partial<Record<Finding['category'], string>> => ({
  exposure: tr('Exposition d’une VIP', 'VIP exposure'),
  permissive: tr('Périmètre permissif', 'Permissive scope'),
  shadowed: tr('Règle masquée', 'Shadowed rule'),
})

const configurationPenalties: Record<Severity, number> = {
  critical: 18,
  high: 10,
  medium: 4,
  low: 1,
}

export const calculateConfigurationScore = (audit: AuditResult): number => {
  const penaltyByPolicy = new Map<string, number>()
  for (const finding of audit.findings) {
    const key = policyKey(finding)
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
  const separator = tr(' : ', ': ')
  const reasons = [`${severityLabels()[finding.severity]}${separator}${severityBase} points`]
  if (findingCategoryBonus) reasons.push(`${categoryReasons()[finding.category]}${separator}+${findingCategoryBonus} points`)
  if (strictBonus) reasons.push(`${tr('Profil strict', 'Strict profile')}${separator}+${strictBonus} points`)
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
