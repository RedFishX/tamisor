import type { Finding, Severity } from '../domain/audit'

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
