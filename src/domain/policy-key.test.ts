import { describe, expect, it } from 'vitest'
import { policyKey } from './policy-key'

describe('policyKey', () => {
  it('garde l’ancien format pour les valeurs ordinaires', () => {
    expect(policyKey({ vdom: 'root', family: 'ipv4', policyId: '10' })).toBe('root|ipv4|10')
    expect(policyKey({ id: '7' })).toBe('global|ipv4|7')
    expect(policyKey({ policyId: '3', family: 'ipv6' })).toBe('global|ipv6|3')
  })

  it('est identique pour une policy (id) et ses constats (policyId)', () => {
    expect(policyKey({ vdom: 'dmz', id: '4' })).toBe(policyKey({ vdom: 'dmz', policyId: '4' }))
  })

  it('ne confond pas deux policies dont le VDOM ou l’id contient « | » ou « % »', () => {
    // Ancien format : « a|ipv4|b|ipv4|c » pour les deux.
    expect(policyKey({ vdom: 'a', family: 'ipv4', policyId: 'b|ipv4|c' })).not.toBe(policyKey({ vdom: 'a|ipv4|b', family: 'ipv4', policyId: 'c' }))
    expect(policyKey({ policyId: 'a%7Cb' })).not.toBe(policyKey({ policyId: 'a|b' }))
  })
})
