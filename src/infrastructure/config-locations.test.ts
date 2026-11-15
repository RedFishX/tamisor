import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { analyzeConfiguration } from '../domain/analyzer'
import { createConfigLocator, indexConfigLines } from './config-locations'

const multiVdom = readFileSync(new URL('../../test/multi-vdom-ipv6.conf', import.meta.url), 'utf8')
const lineOf = (content: string, line: number) => content.split('\n')[line - 1].trim()

describe('indexConfigLines', () => {
  it('indexe chaque edit par VDOM et par section', () => {
    const index = indexConfigLines('config firewall policy\n    edit 7\n    next\nend\nconfig firewall address\n    edit "SRV-1"\n    next\nend\n')
    expect(index.get('|firewall policy|7')).toBe(2)
    expect(index.get('|firewall address|SRV-1')).toBe(6)
  })
})

describe('createConfigLocator', () => {
  it('pointe la ligne edit de chaque constat, IPv6 et VDOM compris', () => {
    const locate = createConfigLocator(multiVdom, 'campus.conf')
    const findings = analyzeConfiguration(multiVdom).findings
    expect(findings.length).toBeGreaterThan(10)
    for (const finding of findings) {
      const line = locate(finding)
      expect(line, finding.id).toBeDefined()
      const name = finding.policyId.replace(/^object:[^:]+:/, '')
      expect(lineOf(multiVdom, line!)).toMatch(new RegExp(`^edit "?${name}"?$`))
    }
  })

  it('distingue la même policy dans deux VDOM', () => {
    const locate = createConfigLocator(multiVdom, 'campus.conf')
    const lines = analyzeConfiguration(multiVdom).findings
      .filter((finding) => finding.policyId === '3' && finding.family !== 'ipv6')
      .map((finding) => `${finding.vdom}:${locate(finding)}`)
    expect(new Set(lines.map((entry) => entry.split(':')[1])).size).toBe(new Set(lines.map((entry) => entry.split(':')[0])).size)
  })

  it('ne localise pas les lignes d’un export CSV', () => {
    expect(createConfigLocator('ID;Name\n1;a', 'export.csv')({ policyId: '1' })).toBeUndefined()
  })
})
