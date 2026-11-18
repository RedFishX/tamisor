/**
 * Génère une configuration FortiGate synthétique mais réaliste (sites, VLAN, serveurs, groupes,
 * services personnalisés, quelques défauts volontaires) pour les tests de volumétrie.
 * Aucune donnée client : les plages utilisent des réseaux privés et de documentation.
 */
export interface RealisticConfigOptions {
  policies: number
  seed?: number
}

const prng = (seed: number) => () => {
  seed = (seed * 1664525 + 1013904223) >>> 0
  return seed / 0x100000000
}

const ZONES = ['lan', 'dmz', 'voip', 'wifi-invites', 'wifi-corp', 'mgmt', 'wan1']
const SERVICES = ['HTTPS', 'HTTP', 'DNS', 'SSH', 'NTP', 'SMTP', 'RDP', 'SMB']

export const generateRealisticConfig = ({ policies, seed = 42 }: RealisticConfigOptions): string => {
  const random = prng(seed)
  const pick = <T,>(values: T[]): T => values[Math.floor(random() * values.length)]
  const hostCount = Math.max(20, Math.ceil(policies / 2))
  const groupCount = Math.max(5, Math.ceil(policies / 25))
  const out: string[] = []

  out.push('config firewall address')
  for (let index = 0; index < hostCount; index++) {
    const net = 10 + (index % 4)
    out.push(`    edit "SRV-${String(index).padStart(4, '0')}"`, `        set subnet ${net}.${Math.floor(index / 250) % 250}.${index % 250}.0 255.255.255.0`, '    next')
  }
  out.push('end', 'config firewall addrgrp')
  for (let group = 0; group < groupCount; group++) {
    const members = Array.from({ length: 4 }, () => `"SRV-${String(Math.floor(random() * hostCount)).padStart(4, '0')}"`)
    out.push(`    edit "GRP-${group}"`, `        set member ${[...new Set(members)].join(' ')}`, '    next')
  }
  out.push('end', 'config firewall service custom')
  for (let index = 0; index < 30; index++) {
    out.push(`    edit "APP-${8000 + index}"`, `        set tcp-portrange ${8000 + index}`, '    next')
  }
  out.push('end', 'config firewall policy')
  for (let index = 1; index <= policies; index++) {
    const source = random() < 0.4 ? `"GRP-${Math.floor(random() * groupCount)}"` : `"SRV-${String(Math.floor(random() * hostCount)).padStart(4, '0')}"`
    const destination = random() < 0.05 ? '"all"' : `"SRV-${String(Math.floor(random() * hostCount)).padStart(4, '0')}"`
    const service = random() < 0.05 ? '"ALL"' : random() < 0.3 ? `"APP-${8000 + Math.floor(random() * 30)}"` : `"${pick(SERVICES)}"`
    const withProfiles = random() < 0.7
    out.push(
      `    edit ${index}`,
      `        set name "Flux-${index}"`,
      `        set srcintf "${pick(ZONES)}"`,
      `        set dstintf "${pick(ZONES)}"`,
      `        set srcaddr ${source}`,
      `        set dstaddr ${destination}`,
      `        set action accept`,
      `        set schedule "always"`,
      `        set service ${service}`,
      `        set logtraffic ${random() < 0.9 ? 'all' : 'disable'}`,
      ...(withProfiles ? ['        set utm-status enable', '        set ips-sensor "default"', '        set av-profile "default"', '        set webfilter-profile "default"'] : []),
      `        set comments "Ticket CHG-${100000 + index}"`,
      '    next',
    )
  }
  out.push('end')
  return out.join('\n')
}
