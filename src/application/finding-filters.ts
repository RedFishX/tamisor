import type { FirewallPolicy, Finding, Severity } from '../domain/audit'

export interface FindingFilters {
  severity: Severity | 'all'
  category: Finding['category'] | 'all'
}

export type MetricFilter = 'critical' | 'permissive' | 'shadowed'

const metricFilters: Record<MetricFilter, FindingFilters> = {
  critical: { severity: 'critical', category: 'all' },
  permissive: { severity: 'all', category: 'permissive' },
  shadowed: { severity: 'all', category: 'shadowed' },
}

export const applyMetricFilter = (current: FindingFilters, metric: MetricFilter): FindingFilters => {
  const target = metricFilters[metric]
  if (current.severity === target.severity && current.category === target.category) {
    return { severity: 'all', category: 'all' }
  }
  return target
}

type SearchablePolicy = Pick<FirewallPolicy, 'srcintf' | 'dstintf' | 'srcaddr' | 'dstaddr' | 'service' | 'internetServices'>

const normalize = (value: string): string =>
  value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase()

/**
 * Recherche libre : chaque mot saisi doit apparaître dans le nom, l’ID ou le titre du constat,
 * ou dans les interfaces, adresses et services de la politique. Insensible à la casse et aux accents.
 */
export const matchesFindingQuery = (
  finding: Pick<Finding, 'policyId' | 'policyName' | 'title'>,
  policy: SearchablePolicy | undefined,
  query: string,
): boolean => {
  const terms = normalize(query).split(/\s+/).filter(Boolean)
  if (!terms.length) return true
  const haystack = normalize([
    finding.policyId,
    finding.policyName,
    finding.title,
    ...(policy?.srcintf ?? []),
    ...(policy?.dstintf ?? []),
    ...(policy?.srcaddr ?? []),
    ...(policy?.dstaddr ?? []),
    ...(policy?.service ?? []),
    ...(policy?.internetServices ?? []),
  ].join('\n'))
  return terms.every((term) => haystack.includes(term))
}
