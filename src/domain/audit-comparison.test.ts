import { describe, expect, it } from 'vitest'
import type { FirewallPolicy } from './audit'
import { comparePolicies } from './audit-comparison'

const policy = (id: string, name: string, service = 'HTTPS'): FirewallPolicy => ({
  id, family: 'ipv4', order: Number(id), name, srcintf: ['lan'], dstintf: ['wan'],
  srcaddr: ['Postes'], dstaddr: ['Internet'], service: [service], schedule: ['always'],
  action: 'accept', status: 'enable', nat: 'disable', utmStatus: 'disable', logtraffic: 'all',
  comments: '', destinationVips: [], internetServices: [], ipPools: [],
})

describe('comparePolicies', () => {
  it('distingue les règles ajoutées, supprimées et modifiées', () => {
    const result = comparePolicies(
      [policy('1', 'Ancienne'), policy('2', 'À supprimer')],
      [policy('1', 'Nouvelle', 'HTTP'), policy('3', 'Ajoutée')],
    )

    expect(result.added.map((item) => item.id)).toEqual(['3'])
    expect(result.removed.map((item) => item.id)).toEqual(['2'])
    expect(result.modified.map((item) => item.after.id)).toEqual(['1'])
  })
})