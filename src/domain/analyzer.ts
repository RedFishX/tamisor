export type {
  AuditResult,
  FirewallPolicy,
  Finding,
  Recommendation,
  Severity,
} from './audit'
import type { AuditResult, FirewallPolicy, Finding, Severity } from './audit'

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
  return [...parseSection(configuration, sectionName)].map(([id, fields], order) => {
    const name = field(fields, 'name')[0]
    const comments = field(fields, 'comments').join(' ')
    const expirationDate = field(fields, 'expiration', field(fields, 'expiry', field(fields, 'expires')))[0]
    const ticket = field(fields, 'ticket', field(fields, 'change-ticket', field(fields, 'change-ticket-id')))[0]
      || comments.match(/\b(?:ticket|change)\s*[:#-]?\s*([A-Z]{2,}-\d+|\w+)/i)?.[1]
    const owner = field(fields, 'owner', field(fields, 'policy-owner'))[0]
      || comments.match(/\bowner\s*[:#-]?\s*([\w.-]+)/i)?.[1]
    const securityProfiles = ['av-profile', 'webfilter-profile', 'application-list', 'ips-sensor', 'dnsfilter-profile']
      .flatMap((key) => field(fields, key))
    const inspectionProfile = field(fields, 'ssl-ssh-profile')[0]
    const temporary = field(fields, 'temporary')[0] === 'enable' || Boolean(expirationDate) || /\btemporary\b|\btemporaire\b/i.test(comments)
    const governanceGaps = [
      !name ? 'Nom de règle absent' : '',
      !comments ? 'Commentaire absent' : '',
      !ticket ? 'Ticket de changement absent' : '',
      !owner ? 'Propriétaire absent' : '',
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
      ...field(fields, 'srcaddr').filter((name) => dynamicNames.has(name.toLowerCase())).map((name) => `Source dynamique : ${name}`),
      ...field(fields, 'dstaddr').filter((name) => dynamicNames.has(name.toLowerCase())).map((name) => `Destination dynamique : ${name}`),
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
  const expanded = (names: string[]) => [...resolve(names)]
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
  const expanded = (names: string[]) => [...resolve(names)]
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
  `Interfaces entrantes couvertes : ${covering.srcintf.join(', ')} couvre ${covered.srcintf.join(', ')}`,
  `Interfaces sortantes couvertes : ${covering.dstintf.join(', ')} couvre ${covered.dstintf.join(', ')}`,
  `Sources couvertes : ${covering.srcaddr.join(', ')} couvre ${covered.srcaddr.join(', ')}`,
  `Destinations couvertes : ${covering.dstaddr.join(', ')} couvre ${covered.dstaddr.join(', ')}`,
  `Services couverts : ${covering.service.join(', ')} couvre ${covered.service.join(', ')}`,
  `Horaires couverts : ${covering.schedule.join(', ')} couvre ${covered.schedule.join(', ')}`,
  `Action identique : ${covered.action}`,
]

const permissiveFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || policy.action !== 'accept') return null
  const evidence: string[] = []
  const universalAddresses = ['all', 'all_ipv4', 'all_ipv6']
  const hasAllSource = policy.srcaddr.some((value) => universalAddresses.includes(value.toLowerCase()))
  const hasAllDestination = policy.dstaddr.some((value) => universalAddresses.includes(value.toLowerCase()))
  const hasAllServices = policy.service.some((value) => value.toLowerCase() === 'all')
  const hasAnyInterface = [...policy.srcintf, ...policy.dstintf].some((value) => value.toLowerCase() === 'any')

  if (hasAllSource) evidence.push('Source: all')
  if (hasAllDestination) evidence.push('Destination: all')
  if (hasAllServices) evidence.push('Service: ALL')
  if (hasAnyInterface) evidence.push('Interface: any')
  if (policy.schedule.some((value) => value.toLowerCase() === 'always')) evidence.push('Horaire: always')
  if (policy.utmStatus !== 'enable') evidence.push('Profils de sécurité: désactivés')

  const broadDimensions = [hasAllSource, hasAllDestination, hasAllServices, hasAnyInterface].filter(Boolean).length
  if (broadDimensions < 2) return null
  const severity: Severity = broadDimensions >= 3 ? 'critical' : 'high'
  const actions: string[] = []
  const cliChanges: string[] = []
  if (hasAllSource) {
    actions.push('Remplacer les sources globales par les objets ou groupes autorisés.')
    cliChanges.push('set srcaddr "<groupe-sources-validé>"')
  }
  if (hasAllDestination) {
    actions.push('Limiter les destinations aux ressources nécessaires au flux.')
    cliChanges.push('set dstaddr "<groupe-destinations-validé>"')
  }
  if (hasAllServices) {
    actions.push('Remplacer ALL par les services applicatifs strictement requis.')
    cliChanges.push('set service "<groupe-services-validé>"')
  }
  if (hasAnyInterface) actions.push('Sélectionner explicitement les interfaces d’entrée et de sortie attendues.')
  if (policy.utmStatus !== 'enable') actions.push('Évaluer et activer les profils de sécurité adaptés au trafic autorisé.')
  return {
    id: findingId('permissive', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity,
    category: 'permissive',
    title: severity === 'critical' ? 'Règle très permissive' : 'Périmètre trop large',
    detail: 'Cette règle autorise plusieurs dimensions sans restriction. Vérifiez que son périmètre correspond au besoin métier.',
    evidence,
    recommendation: {
      summary: 'Appliquer le principe du moindre privilège à chaque critère de correspondance de la politique.',
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
    title: 'VIP exposée à toutes les sources',
    detail: `La publication ${policy.destinationVips.join(', ')} accepte des connexions depuis toutes les adresses source.`,
    evidence: ['Source: all', `VIP: ${policy.destinationVips.join(', ')}`],
    recommendation: {
      summary: 'Limiter l’exposition de la ressource publiée aux sources qui ont réellement besoin d’y accéder.',
      actions: [
        'Définir des objets ou groupes pour les sources autorisées lorsque le service n’est pas public.',
        'Conserver uniquement les services requis et activer les profils de sécurité adaptés.',
      ],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const unusedFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable') return null
  const staleCutoff = Date.now() - 90 * 24 * 60 * 60 * 1000
  const neverUsed = policy.hitCount === 0
  const stale = policy.lastUsed !== undefined && !Number.isNaN(Date.parse(policy.lastUsed)) && Date.parse(policy.lastUsed) < staleCutoff
  if (!neverUsed && !stale) return null
  const reason = neverUsed ? 'aucune correspondance enregistrée' : `dernière utilisation le ${policy.lastUsed}`
  return {
    id: findingId('unused', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'medium',
    category: 'unused',
    title: 'Règle probablement inutilisée',
    detail: `Cette règle est active mais présente ${reason}. Validez son usage avant de la conserver ou de la supprimer.`,
    evidence: [
      policy.hitCount !== undefined ? `Hit Count: ${policy.hitCount}` : '',
      policy.lastUsed ? `Last Used: ${policy.lastUsed}` : '',
    ].filter(Boolean),
    recommendation: {
      summary: 'Valider l’absence de trafic métier avant de désactiver cette règle.',
      actions: [
        'Confirmer avec les journaux et le propriétaire applicatif qu’aucun flux légitime ne dépend de cette règle.',
        'Désactiver la règle pendant une période d’observation avant sa suppression.',
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
    title: 'Analyse indéterminée pour un objet dynamique',
    detail: 'Le contenu de cet objet dépend d’une source externe ou dynamique et ne peut pas être comparé localement de façon fiable.',
    evidence: policy.indeterminateCriteria,
    recommendation: {
      summary: 'Valider le contenu actuel de l’objet dynamique sur le FortiGate avant de conclure à une couverture ou une équivalence.',
      actions: [
        'Vérifier la résolution effective de l’objet et sa fraîcheur sur l’équipement.',
        'Comparer les règles avec les résultats Policy Match et les journaux avant toute remédiation.',
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
    title: expired ? 'Règle temporaire expirée' : 'Règle temporaire à encadrer',
    detail: expired
      ? `La règle temporaire a dépassé sa date d’expiration (${policy.expirationDate}).`
      : missingDate
        ? 'La règle est identifiée comme temporaire mais ne possède pas de date d’expiration exploitable.'
        : `La règle temporaire expire le ${policy.expirationDate}.`,
    evidence: [
      'Règle temporaire',
      policy.expirationDate ? `Expiration : ${policy.expirationDate}` : 'Expiration absente',
    ],
    recommendation: {
      summary: expired ? 'Désactiver ou renouveler explicitement la règle après validation du besoin.' : 'Associer une date d’expiration et un responsable à cette exception.',
      actions: [
        'Confirmer le ticket et le propriétaire de l’exception.',
        expired ? 'Désactiver la règle si le besoin n’est plus justifié.' : 'Planifier une revue avant l’expiration.',
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
    title: 'Métadonnées de gouvernance incomplètes',
    detail: 'Le nom, le contexte ou la traçabilité de cette policy ne permet pas d’identifier clairement sa justification.',
    evidence: policy.governanceGaps,
    recommendation: {
      summary: 'Documenter la policy avec un nom, un commentaire, un ticket et un propriétaire identifiables.',
      actions: ['Compléter les métadonnées avant la prochaine revue de configuration.'],
      reference: FORTINET_FIREWALL_POLICY_REFERENCE,
    },
  }
}

const securityFinding = (policy: FirewallPolicy): Finding | null => {
  if (policy.status === 'disable' || policy.action !== 'accept' || policy.utmStatus !== 'enable' || policy.securityProfiles?.length) return null
  return {
    id: findingId('security', policy),
    policyId: policy.id,
    vdom: policy.vdom,
    family: policy.family,
    policyName: policy.name,
    order: policy.order,
    severity: 'high',
    category: 'security',
    title: 'Profils de sécurité non identifiés',
    detail: 'La policy indique que les profils UTM sont activés, mais aucun profil IPS, antivirus, Web ou applicatif n’a été identifié dans l’export.',
    evidence: ['utm-status: enable', 'Aucun profil de sécurité référencé'],
    recommendation: {
      summary: 'Vérifier les profils réellement associés à cette policy sur le FortiGate.',
      actions: ['Contrôler IPS, antivirus, filtrage Web, contrôle applicatif et inspection SSL selon le flux.'],
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
    title: 'Inspection SSL désactivée',
    detail: 'Cette policy utilise no-inspection, ce qui réduit la visibilité et les contrôles sur les flux chiffrés.',
    evidence: ['ssl-ssh-profile: no-inspection'],
    recommendation: {
      summary: 'Valider explicitement l’exception no-inspection pour ce flux sensible.',
      actions: ['Utiliser le profil d’inspection SSL adapté lorsque les exigences de confidentialité et de conformité le permettent.'],
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
  const references = new Set(policies.filter((policy) => policy.status !== 'disable').flatMap((policy) => [
    ...policy.srcaddr,
    ...policy.dstaddr,
    ...policy.service,
    ...policy.internetServices,
    ...policy.destinationVips,
    ...policy.ipPools,
  ].map((value) => value.toLowerCase())))
  return definitions.flatMap(([kind, section]) => [...parseSection(configuration, section)].flatMap(([name, fields]) => {
    const empty = Object.values(fields).every((values) => !values.length)
    const unused = !references.has(name.toLowerCase())
    if (!empty && !unused) return []
    const reason = empty && unused ? 'Objet vide et non référencé' : empty ? 'Objet vide' : 'Objet non référencé par une policy active'
    return [{
      id: `object-${kind}-${name}`,
      policyId: `object:${kind}:${name}`,
      policyName: name,
      order: 0,
      severity: empty ? 'medium' : 'low',
      category: 'object',
      title: reason,
      detail: `L’objet ${kind} « ${name} » devrait être supprimé, complété ou rattaché à un besoin documenté.`,
      evidence: [`Type : ${kind}`, reason],
      recommendation: {
        summary: 'Nettoyer les objets inutilisés et compléter les objets vides avant la prochaine revue.',
        actions: ['Vérifier les références indirectes et l’inventaire avant suppression.'],
        reference: FORTINET_FIREWALL_POLICY_REFERENCE,
      },
    }]
  }))
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
    const duplicatePolicy = activePolicies.find(
      (earlier) =>
        earlier.order < policy.order &&
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
        title: 'Règle dupliquée',
        detail: `Le périmètre et l’action sont identiques à la règle #${duplicatePolicy.id} « ${duplicatePolicy.name} ».`,
        evidence: [`Règle équivalente: #${duplicatePolicy.id}`, 'Critères de correspondance et action identiques'],
        recommendation: {
          summary: 'Consolider les règles équivalentes pour réduire la complexité et les erreurs de maintenance.',
          actions: [
            'Comparer les options annexes, les compteurs et les commentaires des deux règles.',
            'Conserver la règle de référence puis désactiver le doublon pendant une période d’observation.',
          ],
          cli: `config firewall policy\n    edit ${policy.id}\n        set status disable\n    next\nend`,
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
        duplicateOf: duplicatePolicy.id,
      })
    } else {
      const shadowingPolicy = activePolicies.find(
        (earlier) =>
          earlier.order < policy.order &&
          policyContains(earlier, policy, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher),
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
        title: 'Règle masquée par une règle précédente',
        detail: `Le trafic correspondant est déjà ${shadowingPolicy.action === 'deny' ? 'refusé' : 'accepté'} par la règle #${shadowingPolicy.id} « ${shadowingPolicy.name} ».`,
        evidence: [
          `Règle couvrante: #${shadowingPolicy.id}`,
          `Position précédente: ${shadowingPolicy.order}`,
          `Action couvrante : ${shadowingPolicy.action}`,
          ...coverageEvidence(shadowingPolicy, policy),
        ],
        recommendation: {
          summary: `La règle #${shadowingPolicy.id} ${shadowingPolicy.action === 'deny' ? 'refuse' : 'couvre'} déjà ce trafic : confirmer l’intention avant toute modification.`,
          actions: [
            'Comparer les compteurs de trafic et la date de dernière utilisation des deux règles.',
            `Si la règle #${policy.id} est nécessaire, la déplacer avant la règle #${shadowingPolicy.id} puis tester le Policy Match.`,
            'Sinon, désactiver la règle masquée pendant une période d’observation avant de la supprimer.',
          ],
          cli: `config firewall policy\n    edit ${policy.id}\n        set status disable\n    next\nend`,
          reference: FORTINET_FIREWALL_POLICY_REFERENCE,
        },
        shadowedBy: shadowingPolicy.id,
      })
      } else {
      const overlappingPolicy = activePolicies.find(
        (earlier) =>
          earlier.order < policy.order &&
          policiesIntersect(earlier, policy, addressMatcher, serviceMatcher, interfaceMatcher, scheduleMatcher, principalMatcher),
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
          title: 'Chevauchement partiel, sans masquage complet',
          detail: `Une partie du trafic correspond aussi à la règle #${overlappingPolicy.id} « ${overlappingPolicy.name} », mais la règle #${policy.id} n’est pas masquée : elle reste évaluée pour le trafic hors du périmètre commun.`,
          evidence: [
            `Règle en intersection: #${overlappingPolicy.id}`,
            `Services en intersection : ${overlappingPolicy.service.join(', ')} avec ${policy.service.join(', ')}`,
            `Sources en intersection : ${overlappingPolicy.srcaddr.join(', ')} avec ${policy.srcaddr.join(', ')}`,
            `Destinations en intersection : ${overlappingPolicy.dstaddr.join(', ')} avec ${policy.dstaddr.join(', ')}`,
            `La règle #${policy.id} reste applicable au trafic non couvert par la règle #${overlappingPolicy.id}`,
          ],
          recommendation: {
            summary: 'Clarifier les périmètres afin qu’un même flux ne dépende pas involontairement de l’ordre des règles.',
            actions: [
              'Identifier les adresses et services communs aux deux règles.',
              'Scinder ou restreindre les objets concernés, puis valider avec Policy Match.',
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
        title: 'Journalisation désactivée',
        detail: 'Les flux acceptés par cette règle ne seront pas suffisamment visibles pendant l’audit.',
        evidence: ['logtraffic: disable'],
        recommendation: {
          summary: 'Conserver une trace des sessions acceptées afin de contrôler l’usage réel de la politique.',
          actions: [
            'Activer la journalisation de toutes les sessions autorisées par cette règle.',
            'Vérifier la destination des journaux et leur durée de conservation avant la mise en production.',
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