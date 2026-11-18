import type { Finding } from '../domain/audit'

/**
 * Retrouve la ligne de chaque `edit` d'un export CLI FortiGate (`show full-configuration`), pour que les rapports
 * SARIF pointent la policy ou l'objet en cause dans le fichier versionné.
 *
 * Index : `vdom|section|nom` → numéro de ligne (1 = première ligne). Hors VDOM, la partie VDOM est vide.
 * Un export CSV n'est pas indexé : ses rapports pointent le fichier sans ligne.
 */
export type ConfigLocator = (finding: Pick<Finding, 'policyId' | 'vdom' | 'family'>) => number | undefined

const unquote = (value: string): string => value.trim().replace(/^"(.*)"$/, '$1')

export const indexConfigLines = (content: string): Map<string, number> => {
  const index = new Map<string, number>()
  const stack: Array<{ section: string }> = []
  let vdom = ''
  content.split(/\r?\n/).forEach((raw, position) => {
    const line = raw.trim()
    const config = line.match(/^config\s+(.+)$/)
    if (config) {
      stack.push({ section: config[1].trim() })
      return
    }
    const top = stack[stack.length - 1]
    const edit = line.match(/^edit\s+(.+)$/)
    if (edit && top) {
      const name = unquote(edit[1])
      if (top.section === 'vdom' && stack.length === 1) vdom = name
      const key = `${vdom}|${top.section}|${name}`
      if (!index.has(key)) index.set(key, position + 1)
      return
    }
    if (line === 'next' && top?.section === 'vdom' && stack.length === 1) vdom = ''
    else if (line === 'end') stack.pop()
  })
  return index
}

/** Sections où chercher un objet signalé, selon le type porté par son identifiant `object:<type>:<nom>`. */
const objectSections: Record<string, string[]> = {
  'address': ['firewall address', 'firewall address6'],
  'address-group': ['firewall addrgrp', 'firewall addrgrp6'],
  'service': ['firewall service custom'],
  'service-group': ['firewall service group'],
  'vip': ['firewall vip'],
  'ip-pool': ['firewall ippool'],
}

export const createConfigLocator = (content: string, fileName: string): ConfigLocator => {
  if (fileName.toLowerCase().endsWith('.csv')) return () => undefined
  const index = indexConfigLines(content)
  const lookup = (vdoms: string[], sections: string[], name: string): number | undefined => {
    for (const vdom of vdoms) {
      for (const section of sections) {
        const line = index.get(`${vdom}|${section}|${name}`)
        if (line) return line
      }
    }
    return undefined
  }
  const allVdoms = () => [...new Set([...index.keys()].map((key) => key.split('|')[0]))]
  return (finding) => {
    const object = finding.policyId.match(/^object:([^:]+):(.+)$/)
    if (object) return lookup(finding.vdom !== undefined ? [finding.vdom] : allVdoms(), objectSections[object[1]] ?? [], object[2])
    const sections = finding.family === 'ipv6' ? ['firewall policy6', 'firewall policy'] : ['firewall policy']
    return lookup([finding.vdom ?? ''], sections, finding.policyId)
  }
}
