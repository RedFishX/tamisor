import type { Finding, FirewallPolicy } from '../domain/audit'

let sequence = 0

export const meetingFinding = (overrides: Partial<Finding>): Finding => ({
  id: overrides.id ?? `f-${++sequence}`,
  policyId: '12',
  policyName: 'LAN_vers_ERP',
  order: 4,
  severity: 'medium',
  category: 'permissive',
  title: 'Règle trop permissive',
  detail: 'Source et service globaux.',
  evidence: [],
  recommendation: { summary: 'Restreindre la source.', actions: ['Limiter à 10.20.4.0/24'], reference: { title: 'Fortinet', url: 'https://docs.fortinet.com' } },
  ...overrides,
})

export const meetingPolicy = (overrides: Partial<FirewallPolicy>): FirewallPolicy => ({
  id: '12', order: 4, name: 'LAN_vers_ERP', srcintf: ['port1'], dstintf: ['port3'], srcaddr: ['all'], dstaddr: ['SRV_ERP'], service: ['ALL'], schedule: ['always'],
  action: 'accept', status: 'enable', nat: 'disable', utmStatus: 'disable', logtraffic: 'all', comments: '',
  destinationVips: [], internetServices: [], ipPools: [],
  ...overrides,
})
