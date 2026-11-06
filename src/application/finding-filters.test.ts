import { describe, expect, it } from 'vitest'
import { applyMetricFilter, matchesFindingQuery, type FindingFilters } from './finding-filters'

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
describe('matchesFindingQuery', () => {
  const finding = { policyId: '22', policyName: 'LAN_vers_DMZ_tmp', title: 'Règle permissive : service ALL' }
  const policy = {
    srcintf: ['port1'],
    dstintf: ['port2'],
    srcaddr: ['all'],
    dstaddr: ['grp_Serveurs_DMZ'],
    service: ['ALL'],
    internetServices: [],
  }

  it('accepte une recherche vide', () => {
    expect(matchesFindingQuery(finding, policy, '   ')).toBe(true)
  })

  it('trouve par nom, ID, interface, adresse ou service, sans tenir compte de la casse', () => {
    expect(matchesFindingQuery(finding, policy, 'lan_vers')).toBe(true)
    expect(matchesFindingQuery(finding, policy, '22')).toBe(true)
    expect(matchesFindingQuery(finding, policy, 'PORT2')).toBe(true)
    expect(matchesFindingQuery(finding, policy, 'serveurs_dmz')).toBe(true)
  })

  it('ignore les accents', () => {
    expect(matchesFindingQuery(finding, policy, 'regle')).toBe(true)
  })

  it('exige que tous les mots correspondent', () => {
    expect(matchesFindingQuery(finding, policy, 'port1 port2')).toBe(true)
    expect(matchesFindingQuery(finding, policy, 'port1 wan1')).toBe(false)
  })

  it('cherche dans le constat seul quand la politique est inconnue', () => {
    expect(matchesFindingQuery(finding, undefined, 'tmp')).toBe(true)
    expect(matchesFindingQuery(finding, undefined, 'port1')).toBe(false)
  })
})
