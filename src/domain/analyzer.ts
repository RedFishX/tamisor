export type {
  AuditResult,
  FirewallPolicy,
  Finding,
  Recommendation,
  Severity,
} from './audit'
import type { AuditResult, FirewallPolicy, Finding, Severity } from './audit'
import { tr } from '../i18n'

type Fields = Record<string, string[]>

const FORTINET_FIREWALL_POLICY_REFERENCE = {
  title: 'Fortinet - Firewall policy',
  url: 'https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/656084/firewall-policy',
}

const findingId = (category: Finding['category'], policy: FirewallPolicy): string =>
  `${policy.vdom ? `${policy.vdom}-` : ''}${policy.family ?? 'ipv4'}-${category}-${policy.id}`

const tokenize = (value: string): string[] => {
  const tokens: string[] = []
  const expression = /"((?:\\.|[^"])*)"|(\S+)/g
  let match: RegExpExecArray | null
  while ((match = expression.exec(value)) !== null) {
    tokens.push((match[1] ?? match[2]).replace(/\\"/g, '"'))
  }
  return tokens
}

const parseSection = (configuration: string, sectionName: string): Map<string, Fields> => {
  const entries = new Map<string, Fields>()
  const lines = configuration.replace(/\r/g, '').split('\n')
  let inSection = false
  let depth = 0
  let currentId: string | null = null
  let currentFields: Fields = {}

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!inSection) {
      if (line === `config ${sectionName}`) {
        inSection = true
        depth = 1
      }
      continue
    }

    if (line.startsWith('config ')) {
      depth += 1
      continue
    }
    if (line === 'end') {
      depth -= 1
      if (depth === 0) inSection = false
      continue
    }
    if (depth !== 1) continue

    if (line.startsWith('edit ')) {
      currentId = tokenize(line.slice(5))[0] ?? ''
      currentFields = {}
    } else if (line === 'next' && currentId !== null) {
      entries.set(currentId, currentFields)
      currentId = null
    } else if (currentId !== null && line.startsWith('set ')) {
      const [key, ...values] = tokenize(line.slice(4))
      if (key) currentFields[key] = values
    } else if (currentId !== null && line.startsWith('unset ')) {
      currentFields[line.slice(6).trim()] = []
    }
  }

  return entries
}

const field = (fields: Fields, key: string, fallback: string[] = []): string[] =>
  fields[key]?.length ? fields[key] : fallback

const dynamicAddressNames = (configuration: string): Set<string> => {
  const dynamic = new Set<string>()
  for (const section of ['firewall address', 'firewall address6']) {
    for (const [name, fields] of parseSection(configuration, section)) {
      const type = field(fields, 'type')[0]?.toLowerCase() ?? ''
      const dynamicFields = ['fqdn', 'country', 'filter', 'sdn-tag', 'fabric-object', 'obj-tag']
      if (['fqdn', 'geography', 'dynamic', 'mac', 'interface-subnet'].includes(type) || dynamicFields.some((key) => fields[key])) {
        dynamic.add(name.toLowerCase())
      }
    }
  }
  return dynamic
}

const parsePolicies = (
  configuration: string,
  sectionName = 'firewall policy',
  family: 'ipv4' | 'ipv6' = 'ipv4',
): FirewallPolicy[] => {
  const vipNames = new Set(parseSection(configuration, 'firewall vip').keys())
  const dynamicNames = dynamicAddressNames(configuration)
  const profileGroups = parseSection(configuration, 'firewall profile-group')
  return [...parseSection(configuration, sectionName)].map(([id, fields], order) => {
    const name = field(fields, 'name')[0]
    const comments = field(fields, 'comments').join(' ')
    const expirationDate = field(fields, 'expiration', field(fields, 'expiry', field(fields, 'expires')))[0]
    const ticket = field(fields, 'ticket', field(fields, 'change-ticket', field(fields, 'change-ticket-id')))[0]
      || comments.match(/\b(?:ticket|change)\s*[:#-]?\s*([A-Z]{2,}-\d+|\w+)/i)?.[1]
    const owner = field(fields, 'owner', field(fields, 'policy-owner'))[0]
      || comments.match(/\bowner\s*[:#-]?\s*([\w.-]+)/i)?.[1]
    const profileGroupName = field(fields, 'profile-group')[0]
    const profileGroup = profileGroupName ? profileGroups.get(profileGroupName) : undefined
    const profileKeys = ['av-profile', 'webfilter-profile', 'application-list', 'ips-sensor', 'dnsfilter-profile']
    const profileValues = (key: string) => [...field(fields, key), ...(profileGroup ? field(profileGroup, key) : [])]
    const securityProfileKinds = profileKeys.filter((key) => profileValues(key).length)
    const securityProfiles = [
      ...profileKeys.flatMap(profileValues),
      ...(profileGroupName && !profileGroup ? [profileGroupName] : []),
    ]
    const inspectionProfile = profileValues('ssl-ssh-profile')[0]
    const temporary = field(fields, 'temporary')[0] === 'enable' || Boolean(expirationDate) || /\btemporary\b|\btemporaire\b/i.test(comments)
    const governanceGaps = [
      !name ? tr('Nom de règle absent', 'Missing rule name') : '',
      !comments ? tr('Commentaire absent', 'Missing comment') : '',
      !ticket ? tr('Ticket de changement absent', 'Missing change ticket') : '',
      !owner ? tr('Propriétaire absent', 'Missing owner') : '',
    ].filter(Boolean)
    return {
    id,
    family,
    order: order + 1,
    name: name || `Policy ${id}`,
    srcintf: field(fields, 'srcintf'),
    dstintf: field(fields, 'dstintf'),
    srcaddr: field(fields, 'srcaddr'),
    dstaddr: field(fields, 'dstaddr'),
    users: field(fields, 'users'),
    groups: field(fields, 'groups'),
    devices: field(fields, 'devices'),
    indeterminateCriteria: [
      ...field(fields, 'srcaddr').filter((name) => dynamicNames.has(name.toLowerCase())).map((name) => tr(`Source dynamique : ${name}`, `Dynamic source: ${name}`)),
      ...field(fields, 'dstaddr').filter((name) => dynamicNames.has(name.toLowerCase())).map((name) => tr(`Destination dynamique : ${name}`, `Dynamic destination: ${name}`)),
    ],
    service: field(fields, 'service'),
    schedule: field(fields, 'schedule', ['always']),
    action: field(fields, 'action', ['deny'])[0],
    status: field(fields, 'status', ['enable'])[0],
    nat: field(fields, 'nat', ['disable'])[0],
    utmStatus: field(fields, 'utm-status', ['disable'])[0],
    logtraffic: field(fields, 'logtraffic', ['disable'])[0],
    comments,
    destinationVips: field(fields, 'dstaddr').filter((name) => vipNames.has(name)),
    internetServices: field(fields, 'internet-service')[0] === 'enable'
      ? [...field(fields, 'internet-service-name'), ...field(fields, 'internet-service-id')]
      : [],
    ipPools: field(fields, 'ippool')[0] === 'enable' ? field(fields, 'poolname') : [],
    expirationDate,
    ticket,
    owner,
    temporary,
    securityProfiles,
    securityProfileKinds,
    inspectionProfile,
    governanceGaps,
  }
  })
}

const buildGroupResolver = (configuration: string, sectionName: string) => {
  const groups = parseSection(configuration, sectionName)
  const resolve = (names: string[], visited = new Set<string>()): Set<string> => {
    const resolved = new Set<string>()
    for (const name of names) {
      if (visited.has(name)) continue
      const members = groups.get(name)?.member
      if (!members?.length) {
        resolved.add(name.toLowerCase())
        continue
      }
      visited.add(name)
      for (const member of resolve(members, visited)) resolved.add(member)
    }
    return resolved
  }
  return resolve
}

/** Le même ensemble de noms est comparé à chaque paire de policies : on ne développe les groupes qu'une fois. */
const memoizeExpansion = (resolve: (names: string[]) => Set<string>) => {
  const cache = new Map<string, string[]>()
  return (names: string[]): string[] => {
    const key = names.join('\u0000')
    let value = cache.get(key)
    if (!value) {
      value = [...resolve(names)]
      cache.set(key, value)
    }
    return value
  }
}

interface SpaceMatcher {
  contains: (container: string[], candidate: string[], universal: string[]) => boolean
  intersects: (left: string[], right: string[], universal: string[]) => boolean
}

interface Interval {
  kind: string
  start: number | bigint
  end: number | bigint
}

const intervalsContain = (container: Interval[], candidate: Interval[]): boolean =>
  candidate.every((target) => container.some(
    (source) => source.kind === target.kind && source.start <= target.start && source.end >= target.end,
  ))

const intervalsIntersect = (left: Interval[], right: Interval[]): boolean =>
  left.some((first) => right.some(
    (second) => first.kind === second.kind && first.start <= second.end && second.start <= first.end,
  ))

const buildSpaceMatcher = (
  resolve: ReturnType<typeof buildGroupResolver>,
  intervalsFor: (name: string) => Interval[] | undefined = () => undefined,
): SpaceMatcher => {
  const expanded = memoizeExpansion(resolve)
  const entityContains = (container: string, candidate: string) => {
    if (container === candidate) return true
    const containerIntervals = intervalsFor(container)
    const candidateIntervals = intervalsFor(candidate)
    return Boolean(
      containerIntervals?.length &&
      candidateIntervals?.length &&
      intervalsContain(containerIntervals, candidateIntervals),
    )
  }
  const entitiesIntersect = (left: string, right: string) => {
    if (left === right) return true
    const leftIntervals = intervalsFor(left)
    const rightIntervals = intervalsFor(right)
    return Boolean(leftIntervals?.length && rightIntervals?.length && intervalsIntersect(leftIntervals, rightIntervals))
  }
  return {
    contains: (container, candidate, universal) => {
      const containerNames = expanded(container)
      const candidateNames = expanded(candidate)
      if (universal.some((value) => containerNames.includes(value))) return true
      return candidateNames.every((target) => containerNames.some((source) => entityContains(source, target)))
    },
    intersects: (left, right, universal) => {
      const leftNames = expanded(left)
      const rightNames = expanded(right)
      if (universal.some((value) => leftNames.includes(value) || rightNames.includes(value))) return true
      return leftNames.some((first) => rightNames.some((second) => entitiesIntersect(first, second)))
    },
  }
}

const ipv4ToNumber = (address: string): number | null => {
  const octets = address.split('.').map(Number)
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0
}

const ipv6ToBigInt = (address: string): bigint | null => {
  const normalized = address.toLowerCase().split('%')[0]
  if (normalized.includes('.')) return null
  const sections = normalized.split('::')
  if (sections.length > 2) return null
  const left = sections[0] ? sections[0].split(':') : []
  const right = sections[1] ? sections[1].split(':') : []
  const missing = 8 - left.length - right.length
  if ((sections.length === 1 && missing !== 0) || missing < 0) return null
  const groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right]
  if (groups.length !== 8 || groups.some((group) => !/^[\da-f]{1,4}$/.test(group))) return null
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n)
}

const ipv6PrefixInterval = (value: string, prefixValue?: string): Interval | null => {
  const [address, inlinePrefix] = value.split('/')
  const prefix = Number(prefixValue ?? inlinePrefix)
  const numericAddress = ipv6ToBigInt(address)
  if (numericAddress === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) return null
  const hostBits = 128n - BigInt(prefix)
  const start = (numericAddress >> hostBits) << hostBits
  return { kind: 'ipv6', start, end: start + (1n << hostBits) - 1n }
}

const buildAddressMatcher = (configuration: string): SpaceMatcher => {
  const addresses = new Map([...parseSection(configuration, 'firewall address'), ...parseSection(configuration, 'firewall address6')])
  const intervals = new Map<string, Interval[]>()
  for (const [name, fields] of addresses) {
    const startIp = field(fields, 'start-ip')[0]
    const endIp = field(fields, 'end-ip')[0]
    const subnet = field(fields, 'subnet')
    if (startIp && endIp) {
      const start = ipv4ToNumber(startIp)
      const end = ipv4ToNumber(endIp)
      if (start !== null && end !== null) intervals.set(name.toLowerCase(), [{ kind: 'ipv4', start, end }])
    } else if (subnet.length >= 2) {
      const address = ipv4ToNumber(subnet[0])
      const mask = ipv4ToNumber(subnet[1])
      if (address !== null && mask !== null) {
        const start = (address & mask) >>> 0
        const end = (start | (~mask >>> 0)) >>> 0
        intervals.set(name.toLowerCase(), [{ kind: 'ipv4', start, end }])
      }
    } else {
      const subnet6 = field(fields, 'subnet6')
      const interval = subnet6.length ? ipv6PrefixInterval(subnet6[0], subnet6[1]) : null
      if (interval) intervals.set(name.toLowerCase(), [interval])
    }
  }
  const ipv4Resolve = buildGroupResolver(configuration, 'firewall addrgrp')
  const ipv6Resolve = buildGroupResolver(configuration, 'firewall addrgrp6')
  return buildSpaceMatcher((names) => new Set([...ipv4Resolve(names), ...ipv6Resolve(names)]), (name) => intervals.get(name))
}

const buildInterfaceMatcher = (configuration: string): SpaceMatcher => {
  const zones = parseSection(configuration, 'system zone')
  const resolve = (names: string[], visited = new Set<string>()): Set<string> => {
    const resolved = new Set<string>()
    for (const name of names) {
      const normalized = name.toLowerCase()
      if (visited.has(normalized)) continue
      const members = zones.get(name)?.interface ?? zones.get(normalized)?.interface
      if (!members?.length) {
        resolved.add(normalized)
        continue
      }
      visited.add(normalized)
      for (const member of resolve(members, visited)) resolved.add(member)
    }
    return resolved
  }
  return buildSpaceMatcher(resolve)
}

const scheduleTime = (value: string): number | null => {
  const match = value.match(/^(\d{1,2}):(\d{2})$/)
  if (!match) return null
  const hours = Number(match[1])
  const minutes = Number(match[2])
  return hours <= 23 && minutes <= 59 ? hours * 60 + minutes : null
}

const buildScheduleMatcher = (configuration: string): SpaceMatcher => {
  const intervals = new Map<string, Interval[]>()
  const dayIndexes: Record<string, number> = {
    sunday: 0, monday: 1, tuesday: 2, wednesday: 3, thursday: 4, friday: 5, saturday: 6,
  }
  for (const [name, fields] of parseSection(configuration, 'firewall schedule recurring')) {
    const days = field(fields, 'day').map((day) => dayIndexes[day.toLowerCase()]).filter((day) => day !== undefined)
    const starts = field(fields, 'start').map(scheduleTime)
    const ends = field(fields, 'end').map(scheduleTime)
    const scheduleIntervals = days.flatMap((day) => starts.flatMap((start, index) => {
      const end = ends[index]
      return start !== null && end !== undefined && end !== null
        ? [{ kind: `recurring:${day}`, start: day * 1440 + start, end: day * 1440 + end }]
        : []
    }))
    if (scheduleIntervals.length) intervals.set(name.toLowerCase(), scheduleIntervals)
  }
  for (const [name, fields] of parseSection(configuration, 'firewall schedule onetime')) {
    const start = Date.parse(field(fields, 'start')[0] ?? '')
    const end = Date.parse(field(fields, 'end')[0] ?? '')
    if (!Number.isNaN(start) && !Number.isNaN(end)) intervals.set(name.toLowerCase(), [{ kind: 'onetime', start, end }])
  }
  return buildSpaceMatcher((names) => new Set(names.map((name) => name.toLowerCase())), (name) => intervals.get(name))
}

const buildPrincipalMatcher = (configuration: string): SpaceMatcher =>
  buildSpaceMatcher(buildGroupResolver(configuration, 'user group'))

interface ServiceAtom {
  protocol: string
  destinationStart: number
  destinationEnd: number
  sourceStart: number
  sourceEnd: number
}

const parseNumericRange = (value: string, maximum: number): [number, number] | null => {
  const [startText, endText = startText] = value.split('-')
  const start = Number(startText)
  const end = Number(endText)
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > maximum) return null
  return [start, end]
}

const parseTransportAtoms = (values: string[], protocol: string): ServiceAtom[] => values.flatMap((value) =>
  value.split(/\s+/).filter(Boolean).flatMap((range) => {
    const [destinationText, sourceText = '0-65535'] = range.split(':')
    const destination = parseNumericRange(destinationText, 65535)
    const source = parseNumericRange(sourceText, 65535)
    return destination && source ? [{
      protocol,
      destinationStart: destination[0],
      destinationEnd: destination[1],
      sourceStart: source[0],
      sourceEnd: source[1],
    }] : []
  }),
)

const protocolNumberName = (protocolNumber: number): string => ({
  1: 'icmp',
  6: 'tcp',
  17: 'udp',
  58: 'icmp6',
  132: 'sctp',
})[protocolNumber] ?? `ip:${protocolNumber}`

const fullProtocolAtom = (protocol: string): ServiceAtom => ({
  protocol,
  destinationStart: 0,
  destinationEnd: protocol === 'icmp' || protocol === 'icmp6' || protocol.startsWith('ip:') ? 255 : 65535,
  sourceStart: 0,
  sourceEnd: protocol === 'icmp' || protocol === 'icmp6' || protocol.startsWith('ip:') ? 255 : 65535,
})

const serviceAtoms = (fields: Fields): ServiceAtom[] => {
  const atoms = [
    ...parseTransportAtoms(field(fields, 'tcp-portrange'), 'tcp'),
    ...parseTransportAtoms(field(fields, 'udp-portrange'), 'udp'),
    ...parseTransportAtoms(field(fields, 'sctp-portrange'), 'sctp'),
  ]
  const protocol = field(fields, 'protocol')[0]?.toUpperCase()
  if (protocol === 'ICMP' || protocol === 'ICMP6') {
    const type = parseNumericRange(field(fields, 'icmptype')[0] ?? '0-255', 255)
    const code = parseNumericRange(field(fields, 'icmpcode')[0] ?? '0-255', 255)
    if (type && code) atoms.push({
      protocol: protocol.toLowerCase(),
      destinationStart: type[0],
      destinationEnd: type[1],
      sourceStart: code[0],
      sourceEnd: code[1],
    })
  } else if (protocol === 'IP') {
    const protocolNumberValue = field(fields, 'protocol-number')[0]
    atoms.push(protocolNumberValue && Number(protocolNumberValue) !== 0
      ? fullProtocolAtom(protocolNumberName(Number(protocolNumberValue)))
      : fullProtocolAtom('*'))
  } else if (protocol === 'ALL' && !atoms.length) {
    atoms.push(fullProtocolAtom('*'))
  }
  return atoms
}

const serviceAtomContains = (container: ServiceAtom, candidate: ServiceAtom): boolean =>
  (container.protocol === '*' || container.protocol === candidate.protocol) &&
  container.destinationStart <= candidate.destinationStart &&
  container.destinationEnd >= candidate.destinationEnd &&
  container.sourceStart <= candidate.sourceStart &&
  container.sourceEnd >= candidate.sourceEnd

const serviceAtomsIntersect = (left: ServiceAtom, right: ServiceAtom): boolean =>
  (left.protocol === '*' || right.protocol === '*' || left.protocol === right.protocol) &&
  left.destinationStart <= right.destinationEnd &&
  right.destinationStart <= left.destinationEnd &&
  left.sourceStart <= right.sourceEnd &&
  right.sourceStart <= left.sourceEnd

const buildServiceMatcher = (configuration: string): SpaceMatcher => {
  const services = parseSection(configuration, 'firewall service custom')
  const definitions = new Map<string, ServiceAtom[]>()
  for (const [name, fields] of services) {
    const atoms = serviceAtoms(fields)
    if (atoms.length) definitions.set(name.toLowerCase(), atoms)
  }
  const resolve = buildGroupResolver(configuration, 'firewall service group')
  const expanded = memoizeExpansion(resolve)
  const entityContains = (container: string, candidate: string): boolean => {
    if (container === candidate) return true
    const containerAtoms = definitions.get(container)
    const candidateAtoms = definitions.get(candidate)
    return Boolean(
      containerAtoms?.length &&
      candidateAtoms?.length &&
      candidateAtoms.every((target) => containerAtoms.some((source) => serviceAtomContains(source, target))),
    )
  }
  const entitiesIntersect = (left: string, right: string): boolean => {
    if (left === right) return true
    const leftAtoms = definitions.get(left)
    const rightAtoms = definitions.get(right)
    return Boolean(
      leftAtoms?.some((first) => rightAtoms?.some((second) => serviceAtomsIntersect(first, second))),
    )
  }
  return {
    contains: (container, candidate, universal) => {
      const containerNames = expanded(container)
      const candidateNames = expanded(candidate)
      if (universal.some((value) => containerNames.includes(value))) return true
      return candidateNames.every((target) => containerNames.some((source) => entityContains(source, target)))
    },
    intersects: (left, right, universal) => {
      const leftNames = expanded(left)
      const rightNames = expanded(right)
      if (universal.some((value) => leftNames.includes(value) || rightNames.includes(value))) return true
      return leftNames.some((first) => rightNames.some((second) => entitiesIntersect(first, second)))
    },
  }
}

const exactMatcher = buildSpaceMatcher((names) => new Set(names.map((name) => name.toLowerCase())))

const unrestrictedContains = (container: string[], candidate: string[], matcher: SpaceMatcher): boolean =>
  !container.length || (candidate.length > 0 && matcher.contains(container, candidate, []))

const unrestrictedIntersects = (left: string[], right: string[], matcher: SpaceMatcher): boolean =>
  (!left.length && !right.length) || (!left.length || !right.length) || matcher.intersects(left, right, [])

const principals = (policy: FirewallPolicy): string[] => [...(policy.users ?? []), ...(policy.groups ?? [])]

const effectiveServices = (policy: FirewallPolicy): string[] => policy.internetServices.length
  ? policy.internetServices.map((service) => `internet:${service.toLowerCase()}`)
  : policy.service

const policyContains = (
  earlier: FirewallPolicy,
  later: FirewallPolicy,
  addressMatcher: SpaceMatcher,
  serviceMatcher: SpaceMatcher,
  interfaceMatcher: SpaceMatcher,
  scheduleMatcher: SpaceMatcher,
  principalMatcher: SpaceMatcher,
) => {
  if ((earlier.family ?? 'ipv4') !== (later.family ?? 'ipv4')) return false
  if (earlier.indeterminateCriteria?.length || later.indeterminateCriteria?.length) return false
  return (
    interfaceMatcher.contains(earlier.srcintf, later.srcintf, ['any']) &&
    interfaceMatcher.contains(earlier.dstintf, later.dstintf, ['any']) &&
    addressMatcher.contains(earlier.srcaddr, later.srcaddr, ['all', 'all_ipv4', 'all_ipv6']) &&
    addressMatcher.contains(earlier.dstaddr, later.dstaddr, ['all', 'all_ipv4', 'all_ipv6']) &&
    serviceMatcher.contains(effectiveServices(earlier), effectiveServices(later), ['all']) &&
    scheduleMatcher.contains(earlier.schedule, later.schedule, ['always']) &&
    unrestrictedContains(principals(earlier), principals(later), principalMatcher) &&
    unrestrictedContains(earlier.devices ?? [], later.devices ?? [], exactMatcher)
  )
}

const policiesIntersect = (
  earlier: FirewallPolicy,
  later: FirewallPolicy,
  addressMatcher: SpaceMatcher,
  serviceMatcher: SpaceMatcher,
  interfaceMatcher: SpaceMatcher,
  scheduleMatcher: SpaceMatcher,
  principalMatcher: SpaceMatcher,
) => (
  (earlier.family ?? 'ipv4') === (later.family ?? 'ipv4') &&
  !earlier.indeterminateCriteria?.length && !later.indeterminateCriteria?.length &&
  interfaceMatcher.intersects(earlier.srcintf, later.srcintf, ['any']) &&
  interfaceMatcher.intersects(earlier.dstintf, later.dstintf, ['any']) &&
  addressMatcher.intersects(earlier.srcaddr, later.srcaddr, ['all', 'all_ipv4', 'all_ipv6']) &&
  addressMatcher.intersects(earlier.dstaddr, later.dstaddr, ['all', 'all_ipv4', 'all_ipv6']) &&
  serviceMatcher.intersects(effectiveServices(earlier), effectiveServices(later), ['all']) &&
  scheduleMatcher.intersects(earlier.schedule, later.schedule, ['always']) &&
  unrestrictedIntersects(principals(earlier), principals(later), principalMatcher) &&
  unrestrictedIntersects(earlier.devices ?? [], later.devices ?? [], exactMatcher)
)

const coverageEvidence = (covering: FirewallPolicy, covered: FirewallPolicy): string[] => [
  tr(`Interfaces entrantes couvertes : ${covering.srcintf.join(', ')} couvre ${covered.srcintf.join(', ')}`, `Incoming interfaces covered: ${covering.srcintf.join(', ')} covers ${covered.srcintf.join(', ')}`),
  tr(`Interfaces sortantes couvertes : ${covering.dstintf.join(', ')} couvre ${covered.dstintf.join(', ')}`, `Outgoing interfaces covered: ${covering.dstintf.join(', ')} covers ${covered.dstintf.join(', ')}`),
  tr(`Sources couvertes : ${covering.srcaddr.join(', ')} couvre ${covered.srcaddr.join(', ')}`, `Sources covered: ${covering.srcaddr.join(', ')} covers ${covered.srcaddr.join(', ')}`),
  tr(`Destinations couvertes : ${covering.dstaddr.join(', ')} couvre ${covered.dstaddr.join(', ')}`, `Destinations covered: ${covering.dstaddr.join(', ')} covers ${covered.dstaddr.join(', ')}`),
  tr(`Services couverts : ${covering.service.join(', ')} couvre ${covered.service.join(', ')}`, `Services covered: ${covering.service.join(', ')} covers ${covered.service.join(', ')}`),
  tr(`Horaires couverts : ${covering.schedule.join(', ')} couvre ${covered.schedule.join(', ')}`, `Schedules covered: ${covering.schedule.join(', ')} covers ${covered.schedule.join(', ')}`),
  tr(`Action identique : ${covered.action}`, `Same action: ${covered.action}`),
]

const permissiveFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || policy.action !== 'accept') return null
  const evidence: string[] = []
  const universalAddresses = ['all', 'all_ipv4', 'all_ipv6']
  const hasAllSource = policy.srcaddr.some((value) => universalAddresses.includes(value.toLowerCase()))
  const hasAllDestination = policy.dstaddr.some((value) => universalAddresses.includes(value.toLowerCase()))
  const broadServices = policy.service.filter((value) => ['all', 'all_tcp', 'all_udp', 'all_sctp'].includes(value.toLowerCase()))
  const hasAllServices = broadServices.length > 0
  const hasAnyInterface = [...policy.srcintf, ...policy.dstintf].some((value) => value.toLowerCase() === 'any')

  if (hasAllSource) evidence.push('Source: all')
  if (hasAllDestination) evidence.push('Destination: all')
  if (hasAllServices) evidence.push(`Service: ${broadServices.join(', ')}`)
  if (hasAnyInterface) evidence.push('Interface: any')
  if (policy.schedule.some((value) => value.toLowerCase() === 'always')) evidence.push(tr('Horaire: always', 'Schedule: always'))
  if (policy.utmStatus !== 'enable') evidence.push(tr('Profils de sécurité: désactivés', 'Security profiles: disabled'))

  const broadDimensions = [hasAllSource, hasAllDestination, hasAllServices, hasAnyInterface].filter(Boolean).length
  if (broadDimensions < 2 && !hasAnyInterface) return null
  // Une interface « any » isolée n'est pas une règle permissive, mais elle étend la règle à tous les chemins réseau.
  const interfaceOnly = broadDimensions < 2
  const severity: Severity = interfaceOnly ? 'medium' : broadDimensions >= 3 ? 'critical' : 'high'
  const actions: string[] = []
  const cliChanges: string[] = []
  if (hasAllSource) {
    actions.push(tr('Remplacer les sources globales par les objets ou groupes autorisés.', 'Replace the global sources with the authorised objects or groups.'))
    cliChanges.push(tr('set srcaddr "<groupe-sources-validé>"', 'set srcaddr "<approved-source-group>"'))
  }
  if (hasAllDestination) {
    actions.push(tr('Limiter les destinations aux ressources nécessaires au flux.', 'Limit destinations to the resources the flow actually needs.'))
    cliChanges.push(tr('set dstaddr "<groupe-destinations-validé>"', 'set dstaddr "<approved-destination-group>"'))
  }
  if (hasAllServices) {
    actions.push(tr('Remplacer ALL, ALL_TCP et ALL_UDP par les services applicatifs strictement requis.', 'Replace ALL, ALL_TCP and ALL_UDP with the application services strictly required.'))
    cliChanges.push(tr('set service "<groupe-services-validé>"', 'set service "<approved-service-group>"'))
  }
  if (hasAnyInterface) actions.push(tr('Sélectionner explicitement les interfaces d’entrée et de sortie attendues.', 'Explicitly select the expected incoming and outgoing interfaces.'))
  if (policy.utmStatus !== 'enable') actions.push(tr('Évaluer et activer les profils de sécurité adaptés au trafic autorisé.', 'Assess and enable the security profiles suited to the allowed traffic.'))
  return {
    id: findingId('permissive', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity,
    category: 'permissive',
    title: interfaceOnly ? tr('Interfaces non restreintes', 'Unrestricted interfaces') : severity === 'critical' ? tr('Règle très permissive', 'Highly permissive rule') : tr('Périmètre trop large', 'Scope too broad'),
    detail: interfaceOnly
      ? tr('Cette règle utilise l’interface « any » : elle s’applique à tous les chemins réseau, y compris ceux qui n’étaient pas prévus.', 'This rule uses the “any” interface: it applies to every network path, including unintended ones.')
      : tr('Cette règle autorise plusieurs dimensions sans restriction. Vérifiez que son périmètre correspond au besoin métier.', 'This rule allows several dimensions without restriction. Check that its scope matches the business need.'),
    evidence,
    recommendation: {
      summary: tr('Appliquer le principe du moindre privilège à chaque critère de correspondance de la politique.', 'Apply the principle of least privilege to every match criterion of the policy.'),
      actions,
      cli: cliChanges.length
        ? `config firewall policy\n    edit ${policy.id}\n        ${cliChanges.join('\n        ')}\n    next\nend`
        : undefined,
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const exposureFinding = (policy: FirewallPolicy): Finding | null => {
  const hasAllSource = policy.srcaddr.some((value) => ['all', 'all_ipv4', 'all_ipv6'].includes(value.toLowerCase()))
  if (policy.status === 'disable' || policy.action !== 'accept' || !policy.destinationVips.length || !hasAllSource) return null
  return {
    id: findingId('exposure', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'high',
    category: 'exposure',
    title: tr('VIP exposée à toutes les sources', 'VIP exposed to all sources'),
    detail: tr(`La publication ${policy.destinationVips.join(', ')} accepte des connexions depuis toutes les adresses source.`, `The published service ${policy.destinationVips.join(', ')} accepts connections from every source address.`),
    evidence: ['Source: all', `VIP: ${policy.destinationVips.join(', ')}`],
    recommendation: {
      summary: tr('Limiter l’exposition de la ressource publiée aux sources qui ont réellement besoin d’y accéder.', 'Limit exposure of the published resource to the sources that actually need access.'),
      actions: [
        tr('Définir des objets ou groupes pour les sources autorisées lorsque le service n’est pas public.', 'Define objects or groups for the authorised sources when the service is not public.'),
        tr('Conserver uniquement les services requis et activer les profils de sécurité adaptés.', 'Keep only the required services and enable suitable security profiles.'),
      ],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const unusedFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable') return null
  const staleCutoff = Date.now() - 90 * 24 * 60 * 60 * 1000
  const neverUsed = policy.hitCount === 0 || (policy.lastUsed !== undefined && /^(never|jamais)$/i.test(policy.lastUsed.trim()))
  const stale = policy.lastUsed !== undefined && !Number.isNaN(Date.parse(policy.lastUsed)) && Date.parse(policy.lastUsed) < staleCutoff
  if (!neverUsed && !stale) return null
  const reason = neverUsed ? tr('aucune correspondance enregistrée', 'no recorded hits') : tr(`dernière utilisation le ${policy.lastUsed}`, `a last use on ${policy.lastUsed}`)
  return {
    id: findingId('unused', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'medium',
    category: 'unused',
    title: tr('Règle probablement inutilisée', 'Rule probably unused'),
    detail: tr(`Cette règle est active mais présente ${reason}. Validez son usage avant de la conserver ou de la supprimer.`, `This rule is active but shows ${reason}. Confirm its use before keeping or deleting it.`),
    evidence: [
      policy.hitCount !== undefined ? `Hit Count: ${policy.hitCount}` : '',
      policy.lastUsed ? `Last Used: ${policy.lastUsed}` : '',
    ].filter(Boolean),
    recommendation: {
      summary: tr('Valider l’absence de trafic métier avant de désactiver cette règle.', 'Confirm there is no business traffic before disabling this rule.'),
      actions: [
        tr('Confirmer avec les journaux et le propriétaire applicatif qu’aucun flux légitime ne dépend de cette règle.', 'Check the logs and the application owner to confirm that no legitimate flow depends on this rule.'),
        tr('Désactiver la règle pendant une période d’observation avant sa suppression.', 'Disable the rule for an observation period before deleting it.'),
      ],
      cli: `config firewall policy\n    edit ${policy.id}\n        set status disable\n    next\nend`,
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const indeterminateFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || !policy.indeterminateCriteria?.length) return null
  return {
    id: findingId('indeterminate', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'medium',
    category: 'indeterminate',
    title: tr('Analyse indéterminée pour un objet dynamique', 'Inconclusive analysis for a dynamic object'),
    detail: tr('Le contenu de cet objet dépend d’une source externe ou dynamique et ne peut pas être comparé localement de façon fiable.', 'This object’s content depends on an external or dynamic source and cannot be reliably compared locally.'),
    evidence: policy.indeterminateCriteria,
    recommendation: {
      summary: tr('Valider le contenu actuel de l’objet dynamique sur le FortiGate avant de conclure à une couverture ou une équivalence.', 'Check the dynamic object’s current content on the FortiGate before concluding on coverage or equivalence.'),
      actions: [
        tr('Vérifier la résolution effective de l’objet et sa fraîcheur sur l’équipement.', 'Check how the object actually resolves on the device and how fresh it is.'),
        tr('Comparer les règles avec les résultats Policy Match et les journaux avant toute remédiation.', 'Compare the rules with Policy Match results and logs before any remediation.'),
      ],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const dateValue = (value: string | undefined): number | null => {
  if (!value) return null
  const timestamp = Date.parse(value.replace(/\//g, '-'))
  return Number.isNaN(timestamp) ? null : timestamp
}

const temporaryFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || !policy.temporary) return null
  const expiration = dateValue(policy.expirationDate)
  const expired = expiration !== null && expiration < Date.now()
  const missingDate = expiration === null
  return {
    id: findingId('temporary', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: expired ? 'high' : 'medium',
    category: 'temporary',
    title: expired ? tr('Règle temporaire expirée', 'Expired temporary rule') : tr('Règle temporaire à encadrer', 'Temporary rule to be governed'),
    detail: expired
      ? tr(`La règle temporaire a dépassé sa date d’expiration (${policy.expirationDate}).`, `The temporary rule is past its expiry date (${policy.expirationDate}).`)
      : missingDate
        ? tr('La règle est identifiée comme temporaire mais ne possède pas de date d’expiration exploitable.', 'The rule is marked as temporary but has no usable expiry date.')
        : tr(`La règle temporaire expire le ${policy.expirationDate}.`, `The temporary rule expires on ${policy.expirationDate}.`),
    evidence: [
      tr('Règle temporaire', 'Temporary rule'),
      policy.expirationDate ? tr(`Expiration : ${policy.expirationDate}`, `Expiry: ${policy.expirationDate}`) : tr('Expiration absente', 'No expiry date'),
    ],
    recommendation: {
      summary: expired ? tr('Désactiver ou renouveler explicitement la règle après validation du besoin.', 'Disable the rule, or explicitly renew it once the need is confirmed.') : tr('Associer une date d’expiration et un responsable à cette exception.', 'Give this exception an expiry date and an owner.'),
      actions: [
        tr('Confirmer le ticket et le propriétaire de l’exception.', 'Confirm the exception’s ticket and owner.'),
        expired ? tr('Désactiver la règle si le besoin n’est plus justifié.', 'Disable the rule if the need is no longer justified.') : tr('Planifier une revue avant l’expiration.', 'Schedule a review before it expires.'),
      ],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const governanceFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || !policy.governanceGaps?.length) return null
  return {
    id: findingId('governance', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'low',
    category: 'governance',
    title: tr('Métadonnées de gouvernance incomplètes', 'Incomplete governance metadata'),
    detail: tr('Le nom, le contexte ou la traçabilité de cette policy ne permet pas d’identifier clairement sa justification.', 'This policy’s name, context or traceability does not clearly show why it exists.'),
    evidence: policy.governanceGaps,
    recommendation: {
      summary: tr('Documenter la policy avec un nom, un commentaire, un ticket et un propriétaire identifiables.', 'Document the policy with an identifiable name, comment, ticket and owner.'),
      actions: [tr('Compléter les métadonnées avant la prochaine revue de configuration.', 'Complete the metadata before the next configuration review.')],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const securityFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || policy.action !== 'accept') return null
  const base = {
    id: findingId('security', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    category: 'security' as const,
  }
  // securityProfiles n'est renseigné que par l'import CLI : un CSV (colonne « Security Profiles ») ne détaille pas les profils.
  if (policy.utmStatus === 'enable' && policy.securityProfiles && !policy.securityProfiles.length) {
    return {
      ...base,
      severity: 'high',
      title: tr('Profils de sécurité non identifiés', 'Security profiles not identified'),
      detail: tr('La policy indique que les profils UTM sont activés, mais aucun profil IPS, antivirus, Web ou applicatif n’a été identifié dans l’export.', 'The policy states that UTM profiles are enabled, but no IPS, antivirus, web or application profile was found in the export.'),
      evidence: ['utm-status: enable', tr('Aucun profil de sécurité référencé', 'No security profile referenced')],
      recommendation: {
        summary: tr('Vérifier les profils réellement associés à cette policy sur le FortiGate.', 'Check which profiles are actually attached to this policy on the FortiGate.'),
        actions: [tr('Contrôler IPS, antivirus, filtrage Web, contrôle applicatif et inspection SSL selon le flux.', 'Review IPS, antivirus, web filtering, application control and SSL inspection according to the flow.')],
        reference: FORTINET_FIREWALL_POLICY_REFERENCE,
      },
    }
  }
  // securityProfiles est renseigné uniquement par l'import CLI : un export CSV ne permet pas de conclure.
  if (!policy.securityProfiles) return null
  if (!policy.securityProfiles.length) {
    return {
      ...base,
      severity: 'medium',
      title: tr('Aucun profil de sécurité', 'No security profile'),
      detail: tr('Cette policy autorise le trafic sans profil antivirus, IPS, filtrage Web, contrôle applicatif ni filtrage DNS.', 'This policy allows traffic without any antivirus, IPS, web filtering, application control or DNS filtering profile.'),
      evidence: [tr('Aucun profil de sécurité ni profile-group', 'No security profile or profile-group'), `utm-status: ${policy.utmStatus}`],
      recommendation: {
        summary: tr('Associer au minimum un profil IPS et, selon le flux, antivirus et filtrage Web.', 'Attach at least an IPS profile and, depending on the flow, antivirus and web filtering.'),
        actions: [
          tr('Identifier la nature du flux (sortant Internet, entrant, inter-zones internes).', 'Identify the type of flow (outbound to the Internet, inbound, between internal zones).'),
          tr('Appliquer les profils adaptés ou documenter l’exception si le flux est interne et maîtrisé.', 'Apply suitable profiles, or document the exception if the flow is internal and controlled.'),
        ],
        cli: `config firewall policy\n    edit ${policy.id}\n        set utm-status enable\n        set ips-sensor "default"\n        set av-profile "default"\n        set ssl-ssh-profile "certificate-inspection"\n    next\nend`,
        reference: FORTINET_FIREWALL_POLICY_REFERENCE,
      },
    }
  }
  const kinds = policy.securityProfileKinds ?? []
  const missing = [
    ['ips-sensor', 'IPS'],
    ['av-profile', 'antivirus'],
    ['webfilter-profile', tr('filtrage Web', 'web filtering')],
  ].filter(([key]) => !kinds.includes(key)).map(([, label]) => label)
  if (!missing.length) return null
  return {
    ...base,
    severity: 'low',
    title: tr('Profils de sécurité incomplets', 'Incomplete security profiles'),
    detail: tr(`Cette policy applique des profils de sécurité mais n’a pas de profil : ${missing.join(', ')}.`, `This policy applies security profiles but has no ${missing.join(', ')} profile.`),
    evidence: [tr(`Profils présents : ${kinds.join(', ') || 'aucun'}`, `Profiles present: ${kinds.join(', ') || 'none'}`), ...missing.map((label) => tr(`Manquant : ${label}`, `Missing: ${label}`))],
    recommendation: {
      summary: tr('Vérifier que l’absence de ces profils est voulue pour ce flux.', 'Check that the absence of these profiles is intended for this flow.'),
      actions: [tr('Compléter les profils manquants ou documenter l’exception dans le commentaire de la policy.', 'Add the missing profiles, or document the exception in the policy comment.')],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const inspectionFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || policy.action !== 'accept' || policy.inspectionProfile?.toLowerCase() !== 'no-inspection') return null
  return {
    id: findingId('inspection', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'high',
    category: 'inspection',
    title: tr('Inspection SSL désactivée', 'SSL inspection disabled'),
    detail: tr('Cette policy utilise no-inspection, ce qui réduit la visibilité et les contrôles sur les flux chiffrés.', 'This policy uses no-inspection, which reduces visibility and control over encrypted flows.'),
    evidence: ['ssl-ssh-profile: no-inspection'],
    recommendation: {
      summary: tr('Valider explicitement l’exception no-inspection pour ce flux sensible.', 'Explicitly approve the no-inspection exception for this sensitive flow.'),
      actions: [tr('Utiliser le profil d’inspection SSL adapté lorsque les exigences de confidentialité et de conformité le permettent.', 'Use the appropriate SSL inspection profile where privacy and compliance requirements allow.')],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const objectFindings = (configuration: string, policies: FirewallPolicy[]): Finding[] => {
  const definitions = [
    ['address', 'firewall address'],
    ['address', 'firewall address6'],
    ['address-group', 'firewall addrgrp'],
    ['address-group', 'firewall addrgrp6'],
    ['service', 'firewall service custom'],
    ['service-group', 'firewall service group'],
    ['vip', 'firewall vip'],
    ['ip-pool', 'firewall ippool'],
  ] as const
  const groupMembers = new Map<string, string[]>()
  for (const section of ['firewall addrgrp', 'firewall addrgrp6', 'firewall service group']) {
    for (const [name, fields] of parseSection(configuration, section)) {
      groupMembers.set(name.toLowerCase(), field(fields, 'member'))
    }
  }
  const references = new Set<string>()
  const pending = policies.filter((policy) => policy.status !== 'disable').flatMap((policy) => [
    ...policy.srcaddr,
    ...policy.dstaddr,
    ...policy.service,
    ...policy.internetServices,
    ...policy.destinationVips,
    ...policy.ipPools,
  ].map((value) => value.toLowerCase()))
  // Un membre d'un groupe référencé est lui-même utilisé : on suit les groupes imbriqués.
  while (pending.length) {
    const name = pending.pop()!
    if (references.has(name)) continue
    references.add(name)
    for (const member of groupMembers.get(name) ?? []) pending.push(member.toLowerCase())
  }
  const findings = definitions.flatMap(([kind, section]) => [...parseSection(configuration, section)].flatMap(([name, fields]) => {
    const empty = Object.values(fields).every((values) => !values.length)
    const unused = !references.has(name.toLowerCase())
    if (!empty && !unused) return []
    const reason = empty && unused ? tr('Objet vide et non référencé', 'Empty and unreferenced object') : empty ? tr('Objet vide', 'Empty object') : tr('Objet non référencé par une policy active', 'Object not referenced by any active policy')
    return [{
      id: `object-${kind}-${name}`,
      policyId: `object:${kind}:${name}`,
      policyName: name,
      order: 0,
      severity: empty ? 'medium' : 'low',
      category: 'object',
      title: reason,
      detail: tr(`L’objet ${kind} « ${name} » devrait être supprimé, complété ou rattaché à un besoin documenté.`, `The ${kind} object “${name}” should be deleted, completed or tied to a documented need.`),
      evidence: [tr(`Type : ${kind}`, `Type: ${kind}`), reason],
      recommendation: {
        summary: tr('Nettoyer les objets inutilisés et compléter les objets vides avant la prochaine revue.', 'Clean up unused objects and complete empty ones before the next review.'),
        actions: [tr('Vérifier les références indirectes et l’inventaire avant suppression.', 'Check indirect references and the inventory before deleting.')],
        reference: FORTINET_FIREWALL_POLICY_REFERENCE,
      },
    } satisfies Finding]
  }))
  return [...findings, ...duplicateObjectFindings(configuration)]
}

const duplicateObjectFindings = (configuration: string): Finding[] => {
  const cosmeticKeys = new Set(['uuid', 'comment', 'color', 'visibility', 'fabric-object', 'tags'])
  const sections = [
    ['address', 'firewall address'],
    ['address', 'firewall address6'],
    ['address-group', 'firewall addrgrp'],
    ['address-group', 'firewall addrgrp6'],
    ['service', 'firewall service custom'],
    ['service-group', 'firewall service group'],
  ] as const
  const findings: Finding[] = []
  for (const [kind, section] of sections) {
    const firstByDefinition = new Map<string, string>()
    for (const [name, fields] of parseSection(configuration, section)) {
      const significant = Object.entries(fields)
        .filter(([key, values]) => !cosmeticKeys.has(key) && values.length)
        .map(([key, values]) => [key, kind.endsWith('group') && key === 'member' ? [...values].sort() : values] as const)
        .sort(([left], [right]) => left.localeCompare(right))
      if (!significant.length) continue
      const definition = JSON.stringify(significant).toLowerCase()
      const original = firstByDefinition.get(definition)
      if (!original) {
        firstByDefinition.set(definition, name)
        continue
      }
      findings.push({
        id: `object-duplicate-${kind}-${name}`,
        policyId: `object:${kind}:${name}`,
        policyName: name,
        order: 0,
        severity: 'low',
        category: 'object',
        title: tr('Objet en doublon', 'Duplicate object'),
        detail: tr(`L’objet ${kind} « ${name} » a la même définition que « ${original} ».`, `The ${kind} object “${name}” has the same definition as “${original}”.`),
        evidence: [tr(`Type : ${kind}`, `Type: ${kind}`), tr(`Définition identique à : ${original}`, `Same definition as: ${original}`)],
        recommendation: {
          summary: tr('Consolider les objets identiques pour limiter les erreurs de maintenance.', 'Merge identical objects to reduce maintenance errors.'),
          actions: [
            tr(`Remplacer les références à « ${name} » par « ${original} » dans les policies et groupes.`, `Replace references to “${name}” with “${original}” in policies and groups.`),
            tr('Supprimer le doublon une fois qu’il n’est plus référencé.', 'Delete the duplicate once it is no longer referenced.'),
          ],
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
      })
    }
  }
  return findings
}

export const analyzePolicies = (
  policies: FirewallPolicy[],
  addressMatcher: SpaceMatcher = exactMatcher,
  serviceMatcher: SpaceMatcher = exactMatcher,
  interfaceMatcher: SpaceMatcher = exactMatcher,
  scheduleMatcher: SpaceMatcher = exactMatcher,
  principalMatcher: SpaceMatcher = exactMatcher,
): AuditResult => {
  const findings: Finding[] = []
  const activePolicies = policies.filter((policy) => policy.status !== 'disable')

  // Les policies sont regroupées par interfaces : seuls les groupes dont les interfaces sont compatibles
  // avec la policy étudiée sont parcourus, au lieu de comparer chaque paire de policies.
  const buckets = new Map<string, Array<{ policy: FirewallPolicy, index: number }>>()
  activePolicies.forEach((policy, index) => {
    const key = `${policy.family ?? 'ipv4'}|${policy.srcintf.join(',')}|${policy.dstintf.join(',')}`
    const bucket = buckets.get(key)
    if (bucket) bucket.push({ policy, index })
    else buckets.set(key, [{ policy, index }])
  })
  const findEarlier = (
    policy: FirewallPolicy,
    interfacesCompatible: (earlier: FirewallPolicy) => boolean,
    matches: (earlier: FirewallPolicy) => boolean,
  ): FirewallPolicy | undefined => {
    let best: { policy: FirewallPolicy, index: number } | undefined
    for (const bucket of buckets.values()) {
      if (!interfacesCompatible(bucket[0].policy)) continue
      for (const entry of bucket) {
        if (best && entry.index > best.index) break
        if (entry.policy.order < policy.order && matches(entry.policy)) {
          best = entry
          break
        }
      }
    }
    return best?.policy
  }
  const interfacesContain = (policy: FirewallPolicy) => (earlier: FirewallPolicy) =>
    interfaceMatcher.contains(earlier.srcintf, policy.srcintf, ['any']) &&
    interfaceMatcher.contains(earlier.dstintf, policy.dstintf, ['any'])
  const interfacesIntersect = (policy: FirewallPolicy) => (earlier: FirewallPolicy) =>
    interfaceMatcher.intersects(earlier.srcintf, policy.srcintf, ['any']) &&
    interfaceMatcher.intersects(earlier.dstintf, policy.dstintf, ['any'])

  for (const policy of activePolicies) {
    const permissive = permissiveFinding(policy)
    if (permissive) findings.push(permissive)
    const exposure = exposureFinding(policy)
    if (exposure) findings.push(exposure)
    const unused = unusedFinding(policy)
    if (unused) findings.push(unused)
    const indeterminate = indeterminateFinding(policy)
    if (indeterminate) findings.push(indeterminate)
    const temporary = temporaryFinding(policy)
    if (temporary) findings.push(temporary)
    const governance = governanceFinding(policy)
    if (governance) findings.push(governance)
    const security = securityFinding(policy)
    if (security) findings.push(security)
    const inspection = inspectionFinding(policy)
    if (inspection) findings.push(inspection)

    if (policy.action !== 'accept') continue
    const duplicatePolicy = findEarlier(
      policy,
      interfacesContain(policy),
      (earlier) =>
        earlier.action === policy.action &&
        policyContains(earlier, policy, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher) &&
        policyContains(policy, earlier, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher),
    )
    if (duplicatePolicy) {
      findings.push({
        id: findingId('duplicate', policy),
        policyId: policy.id,
        vdom: policy.vdom,
        family: policy.family,
        policyName: policy.name,
        order: policy.order,
        severity: 'medium',
        category: 'duplicate',
        title: tr('Règle dupliquée', 'Duplicate rule'),
        detail: tr(`Le périmètre et l’action sont identiques à la règle #${duplicatePolicy.id} « ${duplicatePolicy.name} ».`, `Scope and action are identical to rule #${duplicatePolicy.id} “${duplicatePolicy.name}”.`),
        evidence: [tr(`Règle équivalente: #${duplicatePolicy.id}`, `Equivalent rule: #${duplicatePolicy.id}`), tr('Critères de correspondance et action identiques', 'Identical match criteria and action')],
        recommendation: {
          summary: tr('Consolider les règles équivalentes pour réduire la complexité et les erreurs de maintenance.', 'Merge equivalent rules to reduce complexity and maintenance errors.'),
          actions: [
            tr('Comparer les options annexes, les compteurs et les commentaires des deux règles.', 'Compare the secondary options, counters and comments of both rules.'),
            tr('Conserver la règle de référence puis désactiver le doublon pendant une période d’observation.', 'Keep the reference rule, then disable the duplicate for an observation period.'),
          ],
          cli: `config firewall policy\n    edit ${policy.id}\n        set status disable\n    next\nend`,
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
        duplicateOf: duplicatePolicy.id,
      })
    } else {
      const shadowingPolicy = findEarlier(
        policy,
        interfacesContain(policy),
        (earlier) => policyContains(earlier, policy, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher),
      )
      if (shadowingPolicy) {
      findings.push({
        id: findingId('shadowed', policy),
        policyId: policy.id,
        vdom: policy.vdom,
        family: policy.family,
        policyName: policy.name,
        order: policy.order,
        severity: 'high',
        category: 'shadowed',
        title: tr('Règle masquée par une règle précédente', 'Rule shadowed by an earlier rule'),
        detail: tr(
          `Le trafic correspondant est déjà ${shadowingPolicy.action === 'deny' ? 'refusé' : 'accepté'} par la règle #${shadowingPolicy.id} « ${shadowingPolicy.name} ».`,
          `Matching traffic is already ${shadowingPolicy.action === 'deny' ? 'denied' : 'accepted'} by rule #${shadowingPolicy.id} “${shadowingPolicy.name}”.`,
        ),
        evidence: [
          tr(`Règle couvrante: #${shadowingPolicy.id}`, `Covering rule: #${shadowingPolicy.id}`),
          tr(`Position précédente: ${shadowingPolicy.order}`, `Earlier position: ${shadowingPolicy.order}`),
          tr(`Action couvrante : ${shadowingPolicy.action}`, `Covering action: ${shadowingPolicy.action}`),
          ...coverageEvidence(shadowingPolicy, policy),
        ],
        recommendation: {
          summary: tr(
            `La règle #${shadowingPolicy.id} ${shadowingPolicy.action === 'deny' ? 'refuse' : 'couvre'} déjà ce trafic : confirmer l’intention avant toute modification.`,
            `Rule #${shadowingPolicy.id} already ${shadowingPolicy.action === 'deny' ? 'denies' : 'covers'} this traffic: confirm the intent before changing anything.`,
          ),
          actions: [
            tr('Comparer les compteurs de trafic et la date de dernière utilisation des deux règles.', 'Compare the traffic counters and last-use dates of both rules.'),
            tr(`Si la règle #${policy.id} est nécessaire, la déplacer avant la règle #${shadowingPolicy.id} puis tester le Policy Match.`, `If rule #${policy.id} is needed, move it above rule #${shadowingPolicy.id}, then test with Policy Match.`),
            tr('Sinon, désactiver la règle masquée pendant une période d’observation avant de la supprimer.', 'Otherwise, disable the shadowed rule for an observation period before deleting it.'),
          ],
          cli: `config firewall policy\n    edit ${policy.id}\n        set status disable\n    next\nend`,
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
        shadowedBy: shadowingPolicy.id,
      })
      } else {
      const overlappingPolicy = findEarlier(
        policy,
        interfacesIntersect(policy),
        (earlier) => policiesIntersect(earlier, policy, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher),
      )
      if (overlappingPolicy) {
        findings.push({
          id: findingId('overlap', policy),
          policyId: policy.id,
          vdom: policy.vdom,
          family: policy.family,
          policyName: policy.name,
          order: policy.order,
          severity: 'medium',
          category: 'overlap',
          title: tr('Chevauchement partiel, sans masquage complet', 'Partial overlap, not fully shadowed'),
          detail: tr(
            `Une partie du trafic correspond aussi à la règle #${overlappingPolicy.id} « ${overlappingPolicy.name} », mais la règle #${policy.id} n’est pas masquée : elle reste évaluée pour le trafic hors du périmètre commun.`,
            `Part of the traffic also matches rule #${overlappingPolicy.id} “${overlappingPolicy.name}”, but rule #${policy.id} is not shadowed: it is still evaluated for traffic outside the shared scope.`,
          ),
          evidence: [
            tr(`Règle en intersection: #${overlappingPolicy.id}`, `Overlapping rule: #${overlappingPolicy.id}`),
            tr(`Services en intersection : ${overlappingPolicy.service.join(', ')} avec ${policy.service.join(', ')}`, `Overlapping services: ${overlappingPolicy.service.join(', ')} with ${policy.service.join(', ')}`),
            tr(`Sources en intersection : ${overlappingPolicy.srcaddr.join(', ')} avec ${policy.srcaddr.join(', ')}`, `Overlapping sources: ${overlappingPolicy.srcaddr.join(', ')} with ${policy.srcaddr.join(', ')}`),
            tr(`Destinations en intersection : ${overlappingPolicy.dstaddr.join(', ')} avec ${policy.dstaddr.join(', ')}`, `Overlapping destinations: ${overlappingPolicy.dstaddr.join(', ')} with ${policy.dstaddr.join(', ')}`),
            tr(`La règle #${policy.id} reste applicable au trafic non couvert par la règle #${overlappingPolicy.id}`, `Rule #${policy.id} still applies to traffic not covered by rule #${overlappingPolicy.id}`),
          ],
          recommendation: {
            summary: tr('Clarifier les périmètres afin qu’un même flux ne dépende pas involontairement de l’ordre des règles.', 'Clarify the scopes so that a single flow does not accidentally depend on rule order.'),
            actions: [
              tr('Identifier les adresses et services communs aux deux règles.', 'Identify the addresses and services shared by both rules.'),
              tr('Scinder ou restreindre les objets concernés, puis valider avec Policy Match.', 'Split or narrow the objects involved, then validate with Policy Match.'),
            ],
            reference: FORTINET_FIREWALL_POLICY_REFERENCE,
          },
          overlapsWith: overlappingPolicy.id,
        })
      }
      }
    }

    if (policy.logtraffic === 'disable') {
      findings.push({
        id: findingId('visibility', policy),
        policyId: policy.id,
        vdom: policy.vdom,
        family: policy.family,
        policyName: policy.name,
        order: policy.order,
        severity: 'medium',
        category: 'visibility',
        title: tr('Journalisation désactivée', 'Logging disabled'),
        detail: tr('Les flux acceptés par cette règle ne seront pas suffisamment visibles pendant l’audit.', 'Flows accepted by this rule will not be visible enough during the audit.'),
        evidence: ['logtraffic: disable'],
        recommendation: {
          summary: tr('Conserver une trace des sessions acceptées afin de contrôler l’usage réel de la politique.', 'Keep a record of accepted sessions so the policy’s real use can be checked.'),
          actions: [
            tr('Activer la journalisation de toutes les sessions autorisées par cette règle.', 'Enable logging for every session this rule allows.'),
            tr('Vérifier la destination des journaux et leur durée de conservation avant la mise en production.', 'Check where logs are sent and how long they are kept before going live.'),
          ],
          cli: `config firewall policy\n    edit ${policy.id}\n        set logtraffic all\n    next\nend`,
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
      })
    }
  }

  const severityRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  findings.sort((left, right) => severityRank[left.severity] - severityRank[right.severity] || left.order - right.order)
  return {
    policies,
    findings,
    stats: {
      activePolicies: activePolicies.length,
      critical: findings.filter((finding) => finding.severity === 'critical').length,
      high: findings.filter((finding) => finding.severity === 'high').length,
      shadowed: findings.filter((finding) => finding.category === 'shadowed').length,
      overlaps: findings.filter((finding) => finding.category === 'overlap').length,
      duplicates: findings.filter((finding) => finding.category === 'duplicate').length,
      exposures: findings.filter((finding) => finding.category === 'exposure').length,
      permissive: findings.filter((finding) => finding.category === 'permissive').length,
      unused: findings.filter((finding) => finding.category === 'unused').length,
      indeterminate: findings.filter((finding) => finding.category === 'indeterminate').length,
    },
  }
}

const analyzeSingleConfiguration = (configuration: string, vdom?: string): AuditResult => {
  const result = analyzePolicies(
    [
      ...parsePolicies(configuration),
      ...parsePolicies(configuration, 'firewall policy6', 'ipv6'),
    ].map((policy) => ({ ...policy, vdom })),
    buildAddressMatcher(configuration),
    buildServiceMatcher(configuration),
    buildInterfaceMatcher(configuration),
    buildScheduleMatcher(configuration),
    buildPrincipalMatcher(configuration),
  )
  return { ...result, findings: [...result.findings, ...objectFindings(configuration, result.policies)] }
}

const splitVdomConfigurations = (configuration: string): Array<{ name: string, configuration: string }> => {
  const vdoms: Array<{ name: string, configuration: string }> = []
  const lines = configuration.replace(/\r/g, '').split('\n')
  let inVdoms = false
  let depth = 0
  let currentName: string | null = null
  let currentLines: string[] = []

  for (const rawLine of lines) {
    const line = rawLine.trim()
    if (!inVdoms) {
      if (line === 'config vdom') {
        inVdoms = true
        depth = 1
      }
      continue
    }
    if (depth === 1 && line.startsWith('edit ')) {
      currentName = tokenize(line.slice(5))[0] ?? ''
      currentLines = []
      continue
    }
    if (depth === 1 && line === 'next' && currentName !== null) {
      vdoms.push({ name: currentName, configuration: currentLines.join('\n') })
      currentName = null
      continue
    }
    if (line.startsWith('config ')) {
      if (currentName !== null) currentLines.push(rawLine)
      depth += 1
      continue
    }
    if (line === 'end') {
      if (depth > 1 && currentName !== null) currentLines.push(rawLine)
      depth -= 1
      if (depth === 0) inVdoms = false
      continue
    }
    if (currentName !== null) currentLines.push(rawLine)
  }
  return vdoms
}

export const analyzeConfiguration = (configuration: string): AuditResult => {
  const vdoms = splitVdomConfigurations(configuration)
  if (!vdoms.length) return analyzeSingleConfiguration(configuration)

  const results = vdoms.map((vdom) => analyzeSingleConfiguration(vdom.configuration, vdom.name))
  const policies = results.flatMap((result) => result.policies)
  const findings = results.flatMap((result) => result.findings)
  const activePolicies = policies.filter((policy) => policy.status !== 'disable')
  return {
    policies,
    findings,
    stats: {
      activePolicies: activePolicies.length,
      critical: findings.filter((finding) => finding.severity === 'critical').length,
      high: findings.filter((finding) => finding.severity === 'high').length,
      shadowed: findings.filter((finding) => finding.category === 'shadowed').length,
      overlaps: findings.filter((finding) => finding.category === 'overlap').length,
      duplicates: findings.filter((finding) => finding.category === 'duplicate').length,
      exposures: findings.filter((finding) => finding.category === 'exposure').length,
      permissive: findings.filter((finding) => finding.category === 'permissive').length,
      unused: findings.filter((finding) => finding.category === 'unused').length,
      indeterminate: findings.filter((finding) => finding.category === 'indeterminate').length,
    },
  }
}