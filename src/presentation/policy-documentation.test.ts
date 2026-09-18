import { describe, expect, it } from 'vitest'
import type { Finding, FirewallPolicy } from '../domain/audit'
import { generatePolicyMarkdown } from './policy-documentation'

const policy: FirewallPolicy = {
  id: '42', vdom: 'root', family: 'ipv4', order: 3, name: 'Web <public>',
  srcintf: ['wan1'], dstintf: ['dmz'], srcaddr: ['Partenaires'], dstaddr: ['VIP-WEB'],
  service: ['HTTPS'], schedule: ['business-hours'], action: 'accept', status: 'enable',
  nat: 'disable', utmStatus: 'enable', logtraffic: 'all', comments: 'Ticket CHG-42',
  destinationVips: ['VIP-WEB'], internetServices: [], ipPools: [], hitCount: 125, lastUsed: '2026-09-14',
}

const finding = {
  policyId: '42', title: 'VIP exposée', detail: 'Contrôler les sources.', severity: 'high',
  recommendation: { summary: 'Limiter le trafic.', actions: ['Valider les partenaires.'] },
} as Finding

describe('generatePolicyMarkdown', () => {
  it('explique la policy, ses critères et ses constats en Markdown copiable', () => {
    const markdown = generatePolicyMarkdown(policy, [finding], 'site.conf')

    expect(markdown).toContain('# Web <public>')
    expect(markdown).toContain('**Policy :** #42')
    expect(markdown).toContain('Du réseau **Partenaires** vers **VIP-WEB**')
    expect(markdown).toContain('| Correspondances | 125 |')
    expect(markdown).toContain('### VIP exposée')
    expect(markdown).toContain('- Valider les partenaires.')
    expect(markdown).not.toContain('<!doctype html>')
  })
})