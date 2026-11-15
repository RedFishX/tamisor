import Papa from 'papaparse'
import type { FirewallPolicy } from '../domain/audit'
import { tr } from '../i18n'

type CsvRow = Record<string, string>

const HEADER_ALIASES: Record<string, string[]> = {
  policy: ['policy'],
  id: ['policy id', 'policyid', 'id', 'policy id number'],
  name: ['name', 'policy name'],
  srcintf: ['from', 'incoming interface', 'incoming interfaces', 'srcintf', 'source interface'],
  dstintf: ['to', 'outgoing interface', 'outgoing interfaces', 'dstintf', 'destination interface'],
  srcaddr: ['source', 'source address', 'source addresses', 'srcaddr'],
  dstaddr: ['destination', 'destination address', 'destination addresses', 'dstaddr'],
  users: ['users', 'user', 'source users', 'source user'],
  groups: ['groups', 'user groups', 'source groups'],
  devices: ['devices', 'device', 'source devices'],
  schedule: ['schedule'],
  service: ['service', 'services'],
  action: ['action'],
  nat: ['nat'],
  utmStatus: ['security profiles', 'security profile', 'utm status', 'utm-status'],
  logtraffic: ['log traffic', 'logging', 'logtraffic', 'log'],
  status: ['status'],
  comments: ['comments', 'comment'],
  hitCount: ['hit count', 'hitcount', 'hits'],
  lastUsed: ['last used', 'lastused', 'last matched'],
  expiration: ['expiration', 'expiry', 'expires', 'expiration date'],
  ticket: ['ticket', 'change ticket', 'change ticket id'],
  owner: ['owner', 'policy owner'],
  temporary: ['temporary', 'temporaire'],
  inspectionProfile: ['ssl ssh profile', 'ssl-ssh-profile', 'inspection profile'],
}

const normalizeHeader = (value: string): string => value
  .replace(/^\uFEFF/, '')
  .trim()
  .toLowerCase()
  .replace(/[_-]+/g, ' ')
  .replace(/\s+/g, ' ')

const valueFor = (row: CsvRow, field: keyof typeof HEADER_ALIASES): string => {
  const aliases = HEADER_ALIASES[field]
  const entry = Object.entries(row).find(([header]) => aliases.includes(normalizeHeader(header)))
  return entry?.[1]?.trim() ?? ''
}

const splitList = (value: string): string[] => value
  .split(/\s*(?:,|\n|\r|\|)\s*/)
  .map((item) => item.trim())
  .filter(Boolean)

const enabledValue = (value: string, fallback: 'enable' | 'disable'): 'enable' | 'disable' => {
  if (!value) return fallback
  return /^(disable|disabled|off|no|none)$/i.test(value) ? 'disable' : 'enable'
}

const logValue = (value: string): string => {
  if (!value || /^(disable|disabled|off|no|none)$/i.test(value)) return 'disable'
  return /all/i.test(value) ? 'all' : value.toLowerCase()
}

const parseHitCount = (value: string): number | undefined => {
  const digits = value.replace(/[\s\u00a0\u202f,.]/g, '')
  return /^\d+$/.test(digits) ? Number(digits) : undefined
}

// Libellés évalués à l'usage : ce module tourne dans le worker, où la langue est fixée juste avant l'analyse.
const REQUIRED_FIELDS = [
  ['srcintf', () => tr('interface entrante', 'incoming interface')],
  ['dstintf', () => tr('interface sortante', 'outgoing interface')],
  ['srcaddr', () => 'source'],
  ['dstaddr', () => 'destination'],
  ['service', () => 'service'],
  ['action', () => 'action'],
] as const

export const parseCsvPolicies = (content: string): { policies: FirewallPolicy[], errors: string[] } => {
  const parsed = Papa.parse<CsvRow>(content.replace(/^\uFEFF/, ''), {
    header: true,
    skipEmptyLines: 'greedy',
    transformHeader: (header) => header.trim(),
  })

  const syntaxErrors = parsed.errors.filter((error) => ['Delimiter', 'Quotes'].includes(error.type))
  if (syntaxErrors.length) return { policies: [], errors: [tr(`CSV invalide : ${syntaxErrors[0].message}`, `Invalid CSV: ${syntaxErrors[0].message}`)] }

  const normalizedHeaders = (parsed.meta.fields ?? []).map(normalizeHeader)
  const missingFields = REQUIRED_FIELDS.filter(([field]) =>
    !HEADER_ALIASES[field].some((alias) => normalizedHeaders.includes(alias)),
  ).map(([, label]) => label())
  if (missingFields.length) return { policies: [], errors: [tr(`Colonnes CSV obligatoires absentes : ${missingFields.join(', ')}.`, `Required CSV columns missing: ${missingFields.join(', ')}.`)] }

  const policies = parsed.data.map((row, index) => {
    const combinedPolicy = valueFor(row, 'policy')
    const combinedMatch = combinedPolicy.match(/^(.*?)\s*\((\d+)\)\s*$/)
    const combinedId = /^\d+$/.test(combinedPolicy) ? combinedPolicy : combinedMatch?.[2]
    const id = valueFor(row, 'id') || combinedId || String(index + 1)
    const combinedName = combinedMatch?.[1].trim() || (/^\d+$/.test(combinedPolicy) ? '' : combinedPolicy)
    const schedules = splitList(valueFor(row, 'schedule'))
    return {
      id,
      family: 'ipv4' as const,
      order: index + 1,
      name: valueFor(row, 'name') || combinedName || `Policy ${id}`,
      srcintf: splitList(valueFor(row, 'srcintf')),
      dstintf: splitList(valueFor(row, 'dstintf')),
      srcaddr: splitList(valueFor(row, 'srcaddr')),
      dstaddr: splitList(valueFor(row, 'dstaddr')),
      users: splitList(valueFor(row, 'users')),
      groups: splitList(valueFor(row, 'groups')),
      devices: splitList(valueFor(row, 'devices')),
      service: splitList(valueFor(row, 'service')),
      schedule: schedules.length ? schedules : ['always'],
      action: valueFor(row, 'action').toLowerCase() || 'deny',
      status: enabledValue(valueFor(row, 'status'), 'enable'),
      nat: enabledValue(valueFor(row, 'nat'), 'disable'),
      utmStatus: enabledValue(valueFor(row, 'utmStatus'), 'disable'),
      logtraffic: logValue(valueFor(row, 'logtraffic')),
      comments: valueFor(row, 'comments'),
      destinationVips: [],
      internetServices: [],
      ipPools: [],
      hitCount: parseHitCount(valueFor(row, 'hitCount')),
      lastUsed: valueFor(row, 'lastUsed') || undefined,
      expirationDate: valueFor(row, 'expiration') || undefined,
      ticket: valueFor(row, 'ticket') || undefined,
      owner: valueFor(row, 'owner') || undefined,
      temporary: enabledValue(valueFor(row, 'temporary'), 'disable') === 'enable',
      inspectionProfile: valueFor(row, 'inspectionProfile') || undefined,
    }
  }).filter((policy) => policy.srcintf.length || policy.dstintf.length || policy.srcaddr.length)
  return { policies, errors: [] }
}
