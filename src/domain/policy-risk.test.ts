import { describe, expect, it } from 'vitest'
import type { FirewallPolicy } from './audit'
import { assessPolicyElements } from './policy-risk'

const policy = (overrides: Partial<FirewallPolicy> = {}): FirewallPolicy => ({
  id: '1', family: 'ipv4', order: 1, name: 'Test', srcintf: ['lan'], dstintf: ['wan'],
  srcaddr: ['all'], dstaddr: ['all'], service: ['ALL'], schedule: ['always'], action: 'accept',
  status: 'enable', nat: 'disable', utmStatus: 'disable', logtraffic: 'disable', comments: '',
  destinationVips: [], internetServices: [], ipPools: [], ...overrides,
})

describe('assessPolicyElements', () => {
  it('qualifie chaque élément risqué d’une règle permissive sans détail de calcul', () => {
    const assessments = assessPolicyElements(policy())

    expect(assessments).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'interfaces', level: 'low', value: 'lan → wan' }),
      expect.objectContaining({ key: 'sources', level: 'high', value: 'all', reason: expect.stringContaining('toutes les sources') }),
      expect.objectContaining({ key: 'destinations', level: 'high', value: 'all' }),
      expect.objectContaining({ key: 'services', level: 'high', value: 'ALL', reason: expect.stringContaining('tous les services') }),
      expect.objectContaining({ key: 'schedule', level: 'medium', value: 'always' }),
      expect.objectContaining({ key: 'security', level: 'medium', value: 'Désactivés' }),
      expect.objectContaining({ key: 'logging', level: 'high', value: 'Désactivée' }),
    ]))
    expect(JSON.stringify(assessments)).not.toMatch(/points|bonus|calcul/i)
  })

  it('classe comme faibles les éléments explicitement restreints et supervisés', () => {
    const assessments = assessPolicyElements(policy({
      srcaddr: ['Postes'], dstaddr: ['Serveur-Web'], service: ['HTTPS'], schedule: ['Heures-Ouvrées'],
      utmStatus: 'enable', logtraffic: 'all',
    }))

    expect(assessments.every((assessment) => assessment.level === 'low')).toBe(true)
  })
})