import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { renderTextSummary } from './application/ci-report'
import type { AuditResult, Finding } from './domain/audit'
import { analyzeConfiguration } from './domain/analyzer'
import { cliEditToken, neutralizeSpreadsheetFormula, singleLine } from './domain/text-safety'
import { analyzeImportedConfiguration } from './infrastructure/configuration-import'
import { serializeRecommendationsCli } from './presentation/audit-report'
import { serializeFindingsCsv } from './presentation/recommendation-view'
import { meetingFinding } from './test-fixtures/meeting-fixtures'

// Régressions de l'audit de sécurité (run-1) : texte importé -> formats orientés lignes / tableur / DOM.

const MULTILINE_ID = '1\nend\nconfig system admin\nedit x'
const csvWithMultilineId = [
  'Policy ID,Name,From,To,Source,Destination,Schedule,Service,Action,NAT,Security Profiles,Log Traffic,Status',
  `"${MULTILINE_ID}","a\n::error file=x::forged",lan,wan1,all,all,always,ALL,ACCEPT,Enabled,None,Disable,Enabled`,
].join('\n')

describe('text-safety', () => {
  it('aplatit retours à la ligne et caractères de contrôle', () => {
    expect(singleLine('a\r\nb\tc\u0085d\u2028e')).toBe('a b c d e')
  })

  it('laisse un identifiant numérique tel quel et cite le reste pour le CLI', () => {
    expect(cliEditToken('10')).toBe('10')
    expect(cliEditToken('x"y\\z')).toBe('"x\\"y\\\\z"')
    expect(cliEditToken('1\nend')).toBe('"1 end"')
  })

  it('neutralise les déclencheurs de formule de tableur', () => {
    for (const trigger of ['=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx']) expect(neutralizeSpreadsheetFormula(trigger)).toBe(`'${trigger}`)
    expect(neutralizeSpreadsheetFormula('Règle 10')).toBe('Règle 10')
  })
})

describe('tokenize (config importée)', () => {
  it('reste linéaire sur une valeur entre guillemets jamais fermée', () => {
    const config = `config firewall policy\n    edit 1\n        set name "${'\\'.repeat(5000)}\n    next\nend`
    const started = performance.now()
    analyzeConfiguration(config)
    expect(performance.now() - started).toBeLessThan(1000)
  })

  it('conserve les guillemets échappés dans une valeur fermée', () => {
    const result = analyzeConfiguration('config firewall policy\n    edit 1\n        set name "a\\"b"\n        set srcintf "lan"\n        set dstintf "wan"\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n        set action accept\n    next\nend')
    expect(result.policies[0].name).toBe('a"b')
  })
})

describe('import CSV multiligne', () => {
  const result = analyzeImportedConfiguration(csvWithMultilineId, 'policies.csv')

  it('ramène id et nom sur une seule ligne', () => {
    expect(result.policies[0].id).toBe('1 end config system admin edit x')
    expect(result.policies[0].name).not.toMatch(/[\r\n]/)
  })

  it('n’injecte aucune commande dans le CLI de remédiation exporté', () => {
    const cli = serializeRecommendationsCli(result.findings)
    expect(cli).not.toBe('')
    expect(cli).not.toMatch(/^config system admin$/m)
    expect(cli).not.toMatch(/^edit x$/m)
    for (const finding of result.findings) expect(finding.recommendation.cli ?? '').not.toMatch(/^\s*config system admin$/m)
  })
})

describe('résumé texte de CI', () => {
  it('ne laisse jamais une ligne démarrer par « :: » (commande de workflow)', () => {
    const finding: Finding = meetingFinding({ policyId: '10', policyName: 'Internet\n::error file=x::forged', severity: 'critical', title: 'Règle\r\n::add-mask::secret' })
    const audit: AuditResult = {
      policies: [],
      findings: [finding],
      stats: { activePolicies: 1, critical: 1, high: 0, shadowed: 0, overlaps: 0, duplicates: 0, exposures: 0, permissive: 1, unused: 0, indeterminate: 0 },
    }
    const text = renderTextSummary({ audit, sourceUri: 'fw.csv\n::warning::x', toolVersion: '1.0.0', locate: () => undefined, today: '2026-11-20', generatedAt: '2026-11-20T00:00:00.000Z' })
    expect(text).toContain('forged')
    expect(text.split('\n').filter((line) => line.startsWith('::'))).toEqual([])
  })
})

describe('export CSV des constats', () => {
  it('préfixe les cellules issues de la config qui commencent par un déclencheur de formule', () => {
    const csv = serializeFindingsCsv([meetingFinding({ policyId: '@x', policyName: '=HYPERLINK("http://example.test")', title: '-1+1' })])
    expect(csv).toContain('"\'@x"')
    expect(csv).toContain('"\'=HYPERLINK(""http://example.test"")"')
    expect(csv).toContain('"\'-1+1"')
  })
})

describe('liste des constats (DOM)', () => {
  it('échappe finding.id dans l’attribut data-finding-id', () => {
    const source = readFileSync(new URL('./presentation/main.ts', import.meta.url), 'utf8')
    expect(source).toContain('data-finding-id="${escapeHtml(finding.id)}"')
    expect(source).not.toContain('data-finding-id="${finding.id}"')
  })
})
