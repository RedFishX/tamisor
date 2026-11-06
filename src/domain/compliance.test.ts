import { describe, expect, it } from 'vitest'
import type { Finding } from './audit'
import { complianceReferences } from './compliance'
import { renderCompliance, serializeFindingsCsv } from '../presentation/recommendation-view'
import { renderHtmlReport } from '../presentation/audit-report'
import { generatePolicyMarkdown } from '../presentation/policy-documentation'
import { analyzeConfiguration } from './analyzer'

const categories: Finding['category'][] = [
  'duplicate', 'shadowed', 'overlap', 'permissive', 'exposure', 'visibility', 'unused',
  'indeterminate', 'temporary', 'governance', 'security', 'inspection', 'object',
]

describe('correspondance de conformité', () => {
  it.each(categories)('référence au moins un contrôle pour %s', (category) => {
    expect(complianceReferences({ category }).length).toBeGreaterThan(0)
  })

  it('relie la journalisation à PCI-DSS 10.2.1 et une règle permissive à PCI-DSS 1.2.5', () => {
    expect(complianceReferences({ category: 'visibility' })).toEqual(expect.arrayContaining([expect.objectContaining({ framework: 'PCI-DSS v4.0', control: '10.2.1' })]))
    expect(complianceReferences({ category: 'permissive' })).toEqual(expect.arrayContaining([expect.objectContaining({ control: '1.2.5' })]))
  })

  const audit = analyzeConfiguration(`config firewall policy
    edit 1
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set logtraffic disable
    next
end`)

  it('apparaît dans la vue de détail, le CSV, le rapport HTML et la documentation Markdown', () => {
    const finding = audit.findings.find((item) => item.category === 'visibility')!
    expect(renderCompliance(finding)).toContain('PCI-DSS v4.0')
    expect(serializeFindingsCsv([finding])).toContain('conformite')
    expect(serializeFindingsCsv([finding])).toContain('PCI-DSS v4.0 10.2.1')
    expect(renderHtmlReport(audit, 'test.conf')).toContain('Référentiels concernés')
    expect(generatePolicyMarkdown(audit.policies[0], audit.findings, 'test.conf')).toContain('PCI-DSS v4.0 10.2.1')
  })
})
