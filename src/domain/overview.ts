import type { AuditResult, Finding, FirewallPolicy, Severity } from './audit'
import { calculateConfigurationScore, calculateRiskScore } from './risk-score'

export type FindingFamily = 'risk' | 'hygiene' | 'governance'

/** Regroupe les 13 catégories de constats en trois familles lisibles. */
export const categoryFamilies: Record<Finding['category'], FindingFamily> = {
  permissive: 'risk',
  shadowed: 'risk',
  overlap: 'risk',
  exposure: 'risk',
  visibility: 'hygiene',
  unused: 'hygiene',
  temporary: 'hygiene',
  duplicate: 'hygiene',
  object: 'hygiene',
  governance: 'governance',
  security: 'governance',
  inspection: 'governance',
  indeterminate: 'governance',
}

export const familyOrder: FindingFamily[] = ['risk', 'hygiene', 'governance']
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low']

export interface FamilySummary {
  family: FindingFamily
  total: number
  bySeverity: Record<Severity, number>
}

export const summarizeFamilies = (findings: Finding[]): FamilySummary[] => familyOrder.map((family) => {
  const inFamily = findings.filter((finding) => categoryFamilies[finding.category] === family)
  const bySeverity = Object.fromEntries(
    severityOrder.map((severity) => [severity, inFamily.filter((finding) => finding.severity === severity).length]),
  ) as Record<Severity, number>
  return { family, total: inFamily.length, bySeverity }
})

export interface VdomSummary {
  vdom: string
  policies: number
  findings: number
  critical: number
}

const vdomOf = (item: Pick<FirewallPolicy, 'vdom'>) => item.vdom ?? 'global'

export const summarizeVdoms = (policies: FirewallPolicy[], findings: Finding[]): VdomSummary[] => {
  const vdoms = [...new Set([...policies.map(vdomOf), ...findings.map(vdomOf)])]
  return vdoms
    .map((vdom) => {
      const inVdom = findings.filter((finding) => vdomOf(finding) === vdom)
      return {
        vdom,
        policies: policies.filter((policy) => vdomOf(policy) === vdom && policy.status !== 'disable').length,
        findings: inVdom.length,
        critical: inVdom.filter((finding) => finding.severity === 'critical').length,
      }
    })
    .sort((left, right) => right.critical - left.critical || right.findings - left.findings || left.vdom.localeCompare(right.vdom))
}

export interface PriorityFinding {
  finding: Finding
  riskScore: number
  /** Autres constats levés si cette règle est corrigée (règles qu’elle masque ou chevauche). */
  alsoResolves: number
}

export const prioritizeFindings = (findings: Finding[], limit = 3): PriorityFinding[] => findings
  .map((finding) => ({
    finding,
    riskScore: calculateRiskScore(finding, 'standard'),
    alsoResolves: findings.filter((candidate) =>
      vdomOf(candidate) === vdomOf(finding) &&
      (candidate.shadowedBy === finding.policyId || candidate.overlapsWith === finding.policyId),
    ).length,
  }))
  .sort((left, right) => right.riskScore - left.riskScore || right.alsoResolves - left.alsoResolves || left.finding.order - right.finding.order)
  .slice(0, limit)

/** Note obtenue si tous les constats critiques étaient corrigés. */
export const scoreWithoutCritical = (audit: AuditResult): number =>
  calculateConfigurationScore({ ...audit, findings: audit.findings.filter((finding) => finding.severity !== 'critical') })
