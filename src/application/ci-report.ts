import type { AuditResult, Finding, Severity } from '../domain/audit'
import { complianceReferences } from '../domain/compliance'
import { categoryFilterLabel, findingCategories } from '../domain/labels'
import { calculateConfigurationScore } from '../domain/risk-score'
import { singleLine } from '../domain/text-safety'
import type { AcknowledgementRecord } from './finding-acknowledgement'
import { acknowledgementKey } from './finding-acknowledgement'
import { getLocale, tr } from '../i18n'
import { APP_NAME, APP_SLUG, SOURCE_URL } from '../brand'

/**
 * Rapports pour l'intégration continue : JSON (format propre à Tamisor, stable et versionné) et SARIF 2.1.0
 * (lu par GitHub code scanning, Azure DevOps, SonarQube, DefectDojo…). Fonctions pures, partagées par
 * l'export du navigateur et la commande `tamisor` exécutée en CI.
 */

export const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low']
export type FailOn = Severity | 'none'

export interface ReportContext {
  audit: AuditResult
  /** Nom du fichier analysé, tel qu'il apparaît dans le dépôt (chemin relatif conseillé pour SARIF). */
  sourceUri: string
  toolVersion: string
  /** Ligne de la policy ou de l'objet dans le fichier ; `undefined` pour un CSV. */
  locate?: (finding: Finding) => number | undefined
  acknowledgements?: AcknowledgementRecord[]
  /** Identifiants de constats d'un rapport précédent : seuls les nouveaux comptent pour le seuil. */
  baselineIds?: Set<string>
  failOn?: FailOn
  /** Date du jour (AAAA-MM-JJ) pour décider si un acquittement est échu ; injectable pour les tests. */
  today?: string
  generatedAt?: string
}

export type FindingStatus = 'open' | 'acknowledged' | 'acknowledgement-expired'

export interface ReportedFinding {
  finding: Finding
  status: FindingStatus
  acknowledgement?: AcknowledgementRecord
  baseline?: 'new' | 'unchanged'
  line?: number
  blocking: boolean
}

const fileName = (uri: string) => uri.split(/[\\/]/).pop() ?? uri

/**
 * Rapproche chaque constat de son acquittement (exporté depuis l'application, clé `fichier:identifiant`).
 * Un acquittement dont la date de révision est passée ne protège plus le constat : il faut le revoir.
 */
export const classifyFindings = (context: ReportContext): ReportedFinding[] => {
  const today = context.today ?? new Date().toISOString().slice(0, 10)
  const records = new Map((context.acknowledgements ?? []).map((record) => [record.key, record]))
  const threshold = context.failOn ?? 'high'
  const thresholdRank = threshold === 'none' ? -1 : severityOrder.indexOf(threshold)
  return context.audit.findings.map((finding) => {
    const acknowledgement = records.get(acknowledgementKey(fileName(context.sourceUri), finding))
    const status: FindingStatus = !acknowledgement
      ? 'open'
      : acknowledgement.reviewDate && acknowledgement.reviewDate < today ? 'acknowledgement-expired' : 'acknowledged'
    const baseline = context.baselineIds ? (context.baselineIds.has(finding.id) ? 'unchanged' : 'new') : undefined
    const blocking = status !== 'acknowledged'
      && thresholdRank >= 0 && severityOrder.indexOf(finding.severity) <= thresholdRank
      && baseline !== 'unchanged'
    return { finding, status, acknowledgement, baseline, line: context.locate?.(finding), blocking }
  })
}

export interface GateResult {
  failOn: FailOn
  blocking: number
  passed: boolean
}

export const evaluateGate = (reported: ReportedFinding[], failOn: FailOn = 'high'): GateResult => {
  const blocking = reported.filter((item) => item.blocking).length
  return { failOn, blocking, passed: blocking === 0 }
}

const countBy = <K extends string>(keys: K[], values: K[]): Record<K, number> =>
  Object.fromEntries(keys.map((key) => [key, values.filter((value) => value === key).length])) as Record<K, number>

/* ---------- JSON ---------- */

export const JSON_REPORT_FORMAT = `${APP_SLUG}-report`
export const JSON_REPORT_VERSION = 1

export const buildJsonReport = (context: ReportContext) => {
  const reported = classifyFindings(context)
  const gate = evaluateGate(reported, context.failOn)
  const { audit } = context
  const baselineFixed = context.baselineIds
    ? [...context.baselineIds].filter((id) => !audit.findings.some((finding) => finding.id === id)).length
    : undefined
  return {
    format: JSON_REPORT_FORMAT,
    version: JSON_REPORT_VERSION,
    tool: { name: APP_NAME, version: context.toolVersion },
    generatedAt: context.generatedAt ?? new Date().toISOString(),
    locale: getLocale(),
    source: { file: context.sourceUri },
    summary: {
      score: calculateConfigurationScore(audit),
      activePolicies: audit.stats.activePolicies,
      findings: audit.findings.length,
      open: reported.filter((item) => item.status !== 'acknowledged').length,
      acknowledged: reported.filter((item) => item.status === 'acknowledged').length,
      acknowledgementsExpired: reported.filter((item) => item.status === 'acknowledgement-expired').length,
      bySeverity: countBy(severityOrder, audit.findings.map((finding) => finding.severity)),
      byCategory: countBy(findingCategories, audit.findings.map((finding) => finding.category)),
      ...(context.baselineIds ? { baseline: { new: reported.filter((item) => item.baseline === 'new').length, fixed: baselineFixed } } : {}),
      gate,
    },
    findings: reported.map(({ finding, status, acknowledgement, baseline, line, blocking }) => ({
      id: finding.id,
      category: finding.category,
      severity: finding.severity,
      status,
      blocking,
      ...(baseline ? { baseline } : {}),
      policy: {
        id: finding.policyId,
        name: finding.policyName,
        ...(finding.vdom ? { vdom: finding.vdom } : {}),
        family: finding.family ?? 'ipv4',
        order: finding.order,
        ...(line ? { line } : {}),
      },
      title: finding.title,
      detail: finding.detail,
      evidence: finding.evidence,
      recommendation: finding.recommendation,
      compliance: complianceReferences(finding),
      ...(acknowledgement ? { acknowledgement: { justification: acknowledgement.justification, reviewDate: acknowledgement.reviewDate } } : {}),
      ...(finding.shadowedBy ? { shadowedBy: finding.shadowedBy } : {}),
      ...(finding.duplicateOf ? { duplicateOf: finding.duplicateOf } : {}),
      ...(finding.overlapsWith ? { overlapsWith: finding.overlapsWith } : {}),
    })),
  }
}

export type JsonReport = ReturnType<typeof buildJsonReport>

/** Relit les identifiants d'un rapport JSON précédent (référence de la branche cible). */
export const parseBaselineIds = (content: string): Set<string> => {
  const parsed: unknown = JSON.parse(content)
  const report = parsed as Partial<JsonReport> | null
  if (!report || report.format !== JSON_REPORT_FORMAT || !Array.isArray(report.findings)) {
    throw new Error(tr(`Référence invalide : un rapport JSON ${APP_NAME} est attendu.`, `Invalid baseline: a ${APP_NAME} JSON report is expected.`))
  }
  return new Set(report.findings.map((finding) => (finding as { id?: unknown }).id).filter((id): id is string => typeof id === 'string'))
}

/* ---------- SARIF 2.1.0 ---------- */

const sarifLevel: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' }
/** Échelle `security-severity` de GitHub : ≥ 9 critique, ≥ 7 élevée, ≥ 4 moyenne, sinon faible. */
const securitySeverity: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' }

const ruleNames: Record<Finding['category'], string> = {
  permissive: 'PermissiveRule', shadowed: 'ShadowedRule', overlap: 'PartialOverlap', duplicate: 'DuplicateRule',
  exposure: 'ExposedVip', visibility: 'LoggingDisabled', unused: 'UnusedRule', indeterminate: 'DynamicObjectToValidate',
  temporary: 'TemporaryRule', governance: 'MissingGovernanceMetadata', security: 'MissingSecurityProfile',
  inspection: 'SslInspectionDisabled', object: 'UnusedOrDuplicateObject',
}

export const ruleId = (category: Finding['category']): string => `${APP_SLUG}/${category}`

export const buildSarifReport = (context: ReportContext) => {
  const reported = classifyFindings(context)
  const categories = findingCategories.filter((category) => context.audit.findings.some((finding) => finding.category === category))
  const worstSeverity = (category: Finding['category']) =>
    severityOrder.find((severity) => context.audit.findings.some((finding) => finding.category === category && finding.severity === severity)) ?? 'low'
  const example = (category: Finding['category']) => context.audit.findings.find((finding) => finding.category === category)!
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: APP_NAME,
          informationUri: SOURCE_URL,
          version: context.toolVersion,
          semanticVersion: context.toolVersion,
          rules: categories.map((category) => ({
            id: ruleId(category),
            name: ruleNames[category],
            shortDescription: { text: categoryFilterLabel(category) },
            fullDescription: { text: example(category).recommendation.summary },
            helpUri: example(category).recommendation.reference.url,
            help: { text: example(category).recommendation.summary },
            defaultConfiguration: { level: sarifLevel[worstSeverity(category)] },
            properties: {
              tags: ['security', 'firewall', 'fortigate'],
              'security-severity': securitySeverity[worstSeverity(category)],
            },
          })),
        },
      },
      artifacts: [{ location: { uri: context.sourceUri } }],
      invocations: [{ executionSuccessful: true }],
      results: reported.map(({ finding, status, acknowledgement, baseline, line }) => ({
        ruleId: ruleId(finding.category),
        ruleIndex: categories.indexOf(finding.category),
        level: sarifLevel[finding.severity],
        message: {
          text: `${finding.title} — ${finding.policyName} (#${finding.policyId})${finding.vdom ? `, VDOM ${finding.vdom}` : ''}. ${finding.detail} ${finding.recommendation.summary}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: context.sourceUri, index: 0 },
            ...(line ? { region: { startLine: line } } : {}),
          },
          logicalLocations: [{
            name: finding.policyName,
            fullyQualifiedName: `${finding.vdom ?? 'global'}/${finding.policyId}`,
            kind: 'resource',
          }],
        }],
        // Identifiant stable entre deux analyses : l'outil de CI suit un même constat d'un commit à l'autre.
        partialFingerprints: { [`${APP_SLUG}FindingId/v1`]: finding.id },
        ...(baseline ? { baselineState: baseline } : {}),
        ...(status === 'acknowledged' && acknowledgement ? {
          suppressions: [{ kind: 'external', status: 'accepted', justification: acknowledgement.justification }],
        } : {}),
        properties: {
          severity: finding.severity,
          category: finding.category,
          policyId: finding.policyId,
          ...(finding.vdom ? { vdom: finding.vdom } : {}),
          status,
          evidence: finding.evidence,
          actions: finding.recommendation.actions,
          ...(finding.recommendation.cli ? { cli: finding.recommendation.cli } : {}),
        },
      })),
    }],
  }
}

/* ---------- Résumé texte (journal de CI) ---------- */

export const renderTextSummary = (context: ReportContext): string => {
  const reported = classifyFindings(context)
  const gate = evaluateGate(reported, context.failOn)
  const counts = countBy(severityOrder, context.audit.findings.map((finding) => finding.severity))
  const lines = [
    `${APP_NAME} ${context.toolVersion} · ${singleLine(context.sourceUri)}`,
    tr(
      `${context.audit.stats.activePolicies} policies actives, ${context.audit.findings.length} constats `
        + `(critiques ${counts.critical}, élevés ${counts.high}, moyens ${counts.medium}, faibles ${counts.low}), note ${calculateConfigurationScore(context.audit)}/100`,
      `${context.audit.stats.activePolicies} active policies, ${context.audit.findings.length} findings `
        + `(critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}), score ${calculateConfigurationScore(context.audit)}/100`,
    ),
  ]
  const acknowledged = reported.filter((item) => item.status === 'acknowledged').length
  const expired = reported.filter((item) => item.status === 'acknowledgement-expired').length
  if (acknowledged || expired) lines.push(tr(`Acquittés : ${acknowledged}, acquittements échus : ${expired}`, `Acknowledged: ${acknowledged}, expired acknowledgements: ${expired}`))
  if (context.baselineIds) lines.push(tr(`Nouveaux par rapport à la référence : ${reported.filter((item) => item.baseline === 'new').length}`, `New since the baseline: ${reported.filter((item) => item.baseline === 'new').length}`))
  if (gate.failOn === 'none') {
    lines.push(tr('Seuil désactivé (--fail-on none).', 'Threshold disabled (--fail-on none).'))
  } else {
    lines.push(gate.passed
      ? tr(`Seuil « ${gate.failOn} » respecté : aucun constat bloquant.`, `Threshold “${gate.failOn}” met: no blocking finding.`)
      : tr(`Seuil « ${gate.failOn} » dépassé : ${gate.blocking} constat(s) bloquant(s).`, `Threshold “${gate.failOn}” exceeded: ${gate.blocking} blocking finding(s).`))
    for (const { finding, line } of reported.filter((item) => item.blocking).slice(0, 20)) {
      lines.push(`  - [${finding.severity}] ${singleLine(context.sourceUri)}${line ? `:${line}` : ''} #${singleLine(finding.policyId)} ${singleLine(finding.policyName)} — ${singleLine(finding.title)}`)
    }
    if (gate.blocking > 20) lines.push(tr(`  … et ${gate.blocking - 20} autre(s)`, `  … and ${gate.blocking - 20} more`))
  }
  return lines.join('\n')
}
