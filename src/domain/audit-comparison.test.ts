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

  it('ne confond pas deux politiques dont le VDOM ou l’id contient le séparateur', () => {
    // Ancien séparateur « : » : les deux donnaient « a:ipv4:ipv4:b ».
    const first = { ...policy('ipv4:b', 'A'), vdom: 'a' }
    const second = { ...policy('b', 'B'), vdom: 'a:ipv4' }
    const result = comparePolicies([first], [second])
    expect(result.added.map((item) => item.name)).toEqual(['B'])
    expect(result.removed.map((item) => item.name)).toEqual(['A'])
    expect(result.modified).toEqual([])
  })
})
