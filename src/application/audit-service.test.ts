import { describe, expect, it, vi } from 'vitest'
import { createAuditService } from './audit-service'

const audit = {
  policies: [],
  findings: [],
  stats: {
    activePolicies: 0,
    critical: 0,
    high: 0,
    shadowed: 0,
    overlaps: 0,
    duplicates: 0,
    exposures: 0,
    permissive: 0,
    unused: 0,
    indeterminate: 0,
  },
}

describe('createAuditService', () => {
  it('délègue les configurations CLI au moteur de configuration', () => {
    const analyzeConfiguration = vi.fn(() => audit)
    const service = createAuditService({
      analyzeConfiguration,
      analyzePolicies: vi.fn(() => audit),
      parseCsvPolicies: vi.fn(() => ({ policies: [], errors: [] })),
      emptyAudit: () => audit,
    })

    expect(service.analyze('config firewall policy', 'policy.conf')).toMatchObject({ importErrors: [] })
    expect(analyzeConfiguration).toHaveBeenCalledWith('config firewall policy')
  })

  it('retourne les erreurs du parseur CSV sans lancer l’analyse', () => {
    const analyzePolicies = vi.fn(() => audit)
    const parseCsvPolicies = vi.fn(() => ({ policies: [], errors: ['CSV invalide'] }))
    const service = createAuditService({
      analyzeConfiguration: vi.fn(() => audit),
      analyzePolicies,
      parseCsvPolicies,
      emptyAudit: () => audit,
    })

    expect(service.analyze('bad,csv', 'export.csv')).toMatchObject({
      policies: [],
      importErrors: ['CSV invalide'],
    })
    expect(analyzePolicies).not.toHaveBeenCalled()
  })
})
