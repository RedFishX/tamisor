import { describe, expect, it } from 'vitest'
import { analyzeImportedConfiguration } from './configuration-import'

describe('analyzeImportedConfiguration', () => {
  it('analyse un export CSV FortiGate séparé par des virgules', () => {
    const csv = `Policy ID,Name,From,To,Source,Destination,Schedule,Service,Action,NAT,Security Profiles,Log Traffic,Status
10,Accès global,lan,wan1,all,all,always,ALL,ACCEPT,Enabled,None,All Sessions,Enabled
20,Web utilisateurs,lan,wan1,Utilisateurs,all,always,"HTTP, HTTPS",ACCEPT,Enabled,default,All Sessions,Enabled`

    const result = analyzeImportedConfiguration(csv, 'policies.csv')

    expect(result.policies).toHaveLength(2)
    expect(result.policies[1]).toMatchObject({
      id: '20',
      srcintf: ['lan'],
      service: ['HTTP', 'HTTPS'],
      action: 'accept',
      status: 'enable',
      logtraffic: 'all',
    })
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '10', category: 'permissive' }),
      expect.objectContaining({ policyId: '20', category: 'shadowed', shadowedBy: '10' }),
    ]))
  })

  it('reconnaît un export CSV séparé par des points-virgules et ses variantes d’en-têtes', () => {
    const csv = `ID;Policy Name;Incoming Interface;Outgoing Interface;Source Address;Destination Address;Schedule;Services;Action;Log Traffic;Status
7;DNS sortant;LAN;WAN;Postes;DNS-Publics;always;DNS;Accept;Disable;Enable`

    const result = analyzeImportedConfiguration(csv, 'firewall-policy.csv')

    expect(result.policies).toEqual([
      expect.objectContaining({
        id: '7',
        name: 'DNS sortant',
        srcintf: ['LAN'],
        dstintf: ['WAN'],
        srcaddr: ['Postes'],
        dstaddr: ['DNS-Publics'],
        service: ['DNS'],
      }),
    ])
    expect(result.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '7', category: 'visibility' }),
    ]))
  })

  it('conserve l’analyse CLI pour les fichiers conf et txt', () => {
    const cli = `config firewall policy
edit 1
set name "Test"
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "ALL"
next
end`

    expect(analyzeImportedConfiguration(cli, 'backup.conf').policies).toHaveLength(1)
  })

  it('applique les valeurs FortiOS par défaut lorsque les colonnes optionnelles sont absentes', () => {
    const csv = `ID,Name,From,To,Source,Destination,Service,Action
8,Web minimal,lan,wan1,Postes,Internet,HTTPS,Accept`

    expect(analyzeImportedConfiguration(csv, 'minimal.csv').policies[0]).toMatchObject({
      schedule: ['always'],
      status: 'enable',
      nat: 'disable',
      utmStatus: 'disable',
      logtraffic: 'disable',
    })
  })

  it('retourne la liste lisible des colonnes obligatoires absentes', () => {
    const result = analyzeImportedConfiguration('ID,Name,Source\n1,Incomplète,all', 'incomplete.csv')

    expect(result.policies).toHaveLength(0)
    expect(result.importErrors).toEqual([
      'Colonnes CSV obligatoires absentes : interface entrante, interface sortante, destination, service, action.',
    ])
  })

  it('retourne les erreurs de syntaxe du CSV', () => {
    const malformed = 'ID,Name,From,To,Source,Destination,Service,Action\n1,"Nom non fermé,lan,wan,all,all,ALL,Accept'
    const result = analyzeImportedConfiguration(malformed, 'malformed.csv')

    expect(result.policies).toHaveLength(0)
    expect(result.importErrors[0]).toContain('CSV invalide')
  })

  it('importe les statistiques Hit Count et Last Used lorsqu’elles sont disponibles', () => {
    const csv = `ID,Name,From,To,Source,Destination,Service,Action,Hit Count,Last Used
9,Web,lan,wan,Postes,Internet,HTTPS,Accept,1542,2026-09-14 18:42:00`

    expect(analyzeImportedConfiguration(csv, 'statistics.csv').policies[0]).toMatchObject({
      hitCount: 1542,
      lastUsed: '2026-09-14 18:42:00',
    })
  })

  it('ne déclare pas une règle CSV en ALL masquée par une règle à service unique', () => {
    const csv = `ID,Name,From,To,Source,Destination,Service,Action,Log Traffic
1,HTTPS spécifique,lan,wan,Postes,Internet,HTTPS,Accept,All Sessions
2,Tous services,lan,wan,Postes,Internet,ALL,Accept,All Sessions`

    const findings = analyzeImportedConfiguration(csv, 'policies.csv').findings
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'shadowed' }),
    ]))
    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ policyId: '2', category: 'overlap' }),
    ]))
  })
})