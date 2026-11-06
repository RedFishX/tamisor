import { describe, expect, it } from 'vitest'
import { analyzeConfiguration } from './analyzer'
import { analyzeImportedConfiguration } from '../infrastructure/configuration-import'

const policy = (id: string, fields: Record<string, string>) => `
    edit ${id}
${Object.entries({ srcintf: '"lan"', dstintf: '"wan"', srcaddr: '"LAN-NET"', dstaddr: '"WEB-SRV"', action: 'accept', service: '"HTTPS"', logtraffic: 'all', ...fields })
    .map(([key, value]) => `        set ${key} ${value}`).join('\n')}
    next`

const permissive = (configuration: string) => analyzeConfiguration(configuration).findings.filter((finding) => finding.category === 'permissive')

const config = (...policies: string[]) => `config firewall policy${policies.join('')}\nend`

describe('règles trop larges côté interface et service', () => {
  it('traite ALL_TCP comme un service global dans le calcul de permissivité', () => {
    const findings = permissive(config(policy('1', { srcaddr: '"all"', service: '"ALL_TCP"' })))
    expect(findings).toEqual([expect.objectContaining({ category: 'permissive', severity: 'high', evidence: expect.arrayContaining(['Service: ALL_TCP']) })])
  })

  it('signale une interface « any » isolée avec une sévérité moyenne', () => {
    const findings = permissive(config(policy('1', { dstintf: '"any"' })))
    expect(findings).toEqual([expect.objectContaining({ category: 'permissive', severity: 'medium', title: 'Interfaces non restreintes' })])
  })

  it('ne signale rien pour une règle explicite', () => {
    expect(permissive(config(policy('1', {})))).toEqual([])
  })
})

describe('politiques jamais touchées (export CSV)', () => {
  const header = 'Policy ID,Name,From,To,Source,Destination,Schedule,Service,Action,NAT,Security Profiles,Log Traffic,Status,Hit Count,Last Used'
  const unused = (csv: string) => analyzeImportedConfiguration(csv, 'p.csv').findings.filter((finding) => finding.category === 'unused').map((finding) => finding.policyId)

  it('signale un compteur à zéro et une dernière utilisation « Never »', () => {
    const csv = `${header}
1,A,lan,wan,LAN-NET,Srv,always,HTTPS,ACCEPT,Disabled,default,All Sessions,Enabled,0,
2,B,lan,wan,LAN-NET,Srv2,always,DNS,ACCEPT,Disabled,default,All Sessions,Enabled,"1,234",Never
3,C,lan,wan,LAN-NET,Srv3,always,SSH,ACCEPT,Disabled,default,All Sessions,Enabled,"12,345",2020-01-01
4,D,lan,wan,LAN-NET,Srv4,always,NTP,ACCEPT,Disabled,default,All Sessions,Enabled,"9 876",2999-01-01`
    expect(unused(csv).sort()).toEqual(['1', '2', '3'])
  })

  it('lit un compteur avec séparateur de milliers sans le confondre avec zéro', () => {
    const csv = `${header}
1,A,lan,wan,LAN-NET,Srv,always,HTTPS,ACCEPT,Disabled,default,All Sessions,Enabled,"1,200",2999-01-01`
    expect(analyzeImportedConfiguration(csv, 'p.csv').policies[0].hitCount).toBe(1200)
  })
})

describe('profils de sécurité (export CSV)', () => {
  it('ne signale pas des profils manquants quand le CSV n’en donne pas le détail', () => {
    const csv = `Policy ID,Name,From,To,Source,Destination,Schedule,Service,Action,NAT,Security Profiles,Log Traffic,Status
1,Postes,lan,wan1,LAN-Postes,Srv,always,HTTPS,ACCEPT,Enabled,default,All Sessions,Enabled`
    const findings = analyzeImportedConfiguration(csv, 'p.csv').findings
    expect(findings.filter((finding) => finding.category === 'security')).toEqual([])
  })
})
