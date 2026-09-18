import { describe, expect, it } from 'vitest'
import { analyzePolicies } from './analyzer'
import type { FirewallPolicy } from './audit'

const policies = (count: number): FirewallPolicy[] => Array.from({ length: count }, (_, index) => ({
  id: String(index + 1),
  order: index + 1,
  name: `Policy ${index + 1}`,
  srcintf: ['lan'],
  dstintf: ['wan'],
  srcaddr: [`Source-${index}`],
  dstaddr: [`Destination-${index}`],
  service: ['HTTPS'],
  schedule: ['always'],
  action: 'accept',
  status: 'enable',
  nat: 'disable',
  utmStatus: 'enable',
  logtraffic: 'all',
  comments: '',
  destinationVips: [],
  internetServices: [],
  ipPools: [],
}))

describe('analyzePolicies performance', () => {
  it('analyse plusieurs milliers de policies sans perdre de résultat', () => {
    const result = analyzePolicies(policies(2000))
    expect(result.policies).toHaveLength(2000)
    expect(result.stats.activePolicies).toBe(2000)
  })
})
