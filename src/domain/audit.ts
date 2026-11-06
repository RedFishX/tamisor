export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface FirewallPolicy {
  id: string
  vdom?: string
  family?: 'ipv4' | 'ipv6'
  order: number
  name: string
  srcintf: string[]
  dstintf: string[]
  srcaddr: string[]
  dstaddr: string[]
  users?: string[]
  groups?: string[]
  devices?: string[]
  indeterminateCriteria?: string[]
  expirationDate?: string
  ticket?: string
  owner?: string
  temporary?: boolean
  securityProfiles?: string[]
  securityProfileKinds?: string[]
  inspectionProfile?: string
  governanceGaps?: string[]
  service: string[]
  schedule: string[]
  action: string
  status: string
  nat: string
  utmStatus: string
  logtraffic: string
  comments: string
  destinationVips: string[]
  internetServices: string[]
  ipPools: string[]
  hitCount?: number
  lastUsed?: string
}

export interface Finding {
  id: string
  policyId: string
  vdom?: string
  family?: 'ipv4' | 'ipv6'
  policyName: string
  order: number
  severity: Severity
  category: 'duplicate' | 'shadowed' | 'overlap' | 'permissive' | 'exposure' | 'visibility'
  | 'unused' | 'indeterminate' | 'temporary' | 'governance' | 'security' | 'inspection' | 'object'
  title: string
  detail: string
  evidence: string[]
  recommendation: Recommendation
  shadowedBy?: string
  overlapsWith?: string
  duplicateOf?: string
}

export interface Recommendation {
  summary: string
  actions: string[]
  cli?: string
  reference: {
    title: string
    url: string
  }
}

export interface AuditResult {
  policies: FirewallPolicy[]
  findings: Finding[]
  stats: {
    activePolicies: number
    critical: number
    high: number
    shadowed: number
    overlaps: number
    duplicates: number
    exposures: number
    permissive: number
    unused: number
    indeterminate: number
  }
}
