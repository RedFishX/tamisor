import type { AuditResult, FirewallPolicy } from '../domain/audit'

export interface ImportedAuditResult extends AuditResult {
  importErrors: string[]
}

interface AuditServiceDependencies {
  analyzeConfiguration: (content: string) => AuditResult
  analyzePolicies: (policies: FirewallPolicy[]) => AuditResult
  parseCsvPolicies: (content: string) => { policies: FirewallPolicy[], errors: string[] }
  emptyAudit: () => AuditResult
}

export const createAuditService = ({
  analyzeConfiguration,
  analyzePolicies,
  parseCsvPolicies,
  emptyAudit,
}: AuditServiceDependencies) => ({
  analyze: (content: string, fileName: string): ImportedAuditResult => {
    if (!fileName.toLowerCase().endsWith('.csv')) {
      return { ...analyzeConfiguration(content), importErrors: [] }
    }
    const parsed = parseCsvPolicies(content)
    return {
      ...(parsed.errors.length ? emptyAudit() : analyzePolicies(parsed.policies)),
      importErrors: parsed.errors,
    }
  },
})
