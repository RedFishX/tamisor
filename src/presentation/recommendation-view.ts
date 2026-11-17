import type { Finding, Recommendation } from '../domain/audit'
import { tr } from '../i18n'
import { complianceReferences, formatComplianceReference } from '../domain/compliance'
import { neutralizeSpreadsheetFormula } from '../domain/text-safety'
import { escapeHtml } from './html'


export const renderRecommendation = (recommendation: Recommendation): string => `
  <div class="recommendation">
    <span>${tr('Plan de remédiation', 'Remediation plan')}</span>
    <p>${escapeHtml(recommendation.summary)}</p>
    <ol>
      ${recommendation.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join('')}
    </ol>
    ${recommendation.cli ? `
      <div class="cli-preview">
        <div class="cli-header"><span>${tr('Exemple CLI à adapter', 'CLI example to adapt')}</span><button class="copy-cli" type="button" data-copy-cli aria-keyshortcuts="C">${tr('Copier', 'Copy')}</button></div>
        <pre><code>${escapeHtml(recommendation.cli)}</code></pre>
      </div>
    ` : ''}
    <a href="${escapeHtml(recommendation.reference.url)}" target="_blank" rel="noreferrer noopener">
      ${escapeHtml(recommendation.reference.title)}<span class="sr-only"> ${tr('(nouvel onglet)', '(opens in a new tab)')}</span>
    </a>
  </div>
`

export const renderCompliance = (finding: Pick<Finding, 'category'>): string => {
  const references = complianceReferences(finding)
  if (!references.length) return ''
  return `
  <div class="compliance">
    <span>${tr('Référentiels concernés', 'Related frameworks')} <small>${tr('(correspondance indicative)', '(indicative mapping)')}</small></span>
    <ul>
      ${references.map((reference) => `<li><strong>${escapeHtml(reference.framework)}</strong> ${escapeHtml(reference.control)} · ${escapeHtml(reference.title)}</li>`).join('')}
    </ul>
  </div>
`
}

const csvCell = (value: string): string => `"${neutralizeSpreadsheetFormula(value).replace(/"/g, '""')}"`

export const serializeFindingsCsv = (findings: Finding[]): string => {
  const headers = tr(
    'severite;type;regle;nom;constat;detail;recommandation;actions;cli;reference;conformite',
    'severity;type;rule;name;finding;detail;recommendation;actions;cli;reference;compliance',
  ).split(';')
  const rows = findings.map((finding) => [
    finding.severity,
    finding.category,
    finding.policyId,
    finding.policyName,
    finding.title,
    finding.detail,
    finding.recommendation.summary,
    finding.recommendation.actions.join(' | '),
    finding.recommendation.cli ?? '',
    finding.recommendation.reference.url,
    complianceReferences(finding).map(formatComplianceReference).join(' | '),
  ])
  return [headers.join(';'), ...rows.map((row) => row.map(csvCell).join(';'))].join('\n')
}
