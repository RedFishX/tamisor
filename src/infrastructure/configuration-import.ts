import { analyzeConfiguration, analyzePolicies } from '../domain/analyzer'
import type { AuditResult } from '../domain/audit'
import { createAuditService, type ImportedAuditResult } from '../application/audit-service'
import { parseCsvPolicies } from './csv-policy-parser'

export type { ImportedAuditResult }

export const emptyAudit = (): AuditResult => ({
  policies: [],
  findings: [],
  stats: { activePolicies: 0, critical: 0, high: 0, shadowed: 0, overlaps: 0, duplicates: 0, exposures: 0, permissive: 0, unused: 0, indeterminate: 0 },
})

const auditService = createAuditService({ analyzeConfiguration, analyzePolicies, parseCsvPolicies, emptyAudit })

export const analyzeImportedConfiguration = auditService.analyze