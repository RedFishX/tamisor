import { describe, expect, it } from 'vitest'
import { applyMetricFilter, type FindingFilters } from './finding-filters'

const noFilters: FindingFilters = { severity: 'all', category: 'all' }

describe('applyMetricFilter', () => {
  it.each([
    ['critical', { severity: 'critical', category: 'all' }],
    ['permissive', { severity: 'all', category: 'permissive' }],
    ['shadowed', { severity: 'all', category: 'shadowed' }],
  ] as const)('active le filtre associé à la métrique %s', (metric, expected) => {
    expect(applyMetricFilter(noFilters, metric)).toEqual(expected)
  })

  it('désactive une métrique déjà sélectionnée', () => {
    expect(applyMetricFilter({ severity: 'all', category: 'shadowed' }, 'shadowed')).toEqual(noFilters)
  })

  it('remplace les autres filtres lors du changement de métrique', () => {
    expect(applyMetricFilter({ severity: 'critical', category: 'all' }, 'permissive')).toEqual({
      severity: 'all',
      category: 'permissive',
    })
  })
})