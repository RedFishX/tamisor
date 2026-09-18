import type { Finding, Recommendation } from '../domain/audit'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character] ?? character)

export const renderRecommendation = (recommendation: Recommendation): string => `
  <div class="recommendation">
    <span>Plan de remédiation</span>
    <p>${escapeHtml(recommendation.summary)}</p>
    <ol>
      ${recommendation.actions.map((action) => `<li>${escapeHtml(action)}</li>`).join('')}
    </ol>
    ${recommendation.cli ? `
      <div class="cli-preview">
        <span>Exemple CLI à adapter</span>
        <pre><code>${escapeHtml(recommendation.cli)}</code></pre>
      </div>
    ` : ''}
    <a href="${escapeHtml(recommendation.reference.url)}" target="_blank" rel="noreferrer noopener">
      ${escapeHtml(recommendation.reference.title)}
    </a>
  </div>
`

const csvCell = (value: string): string => `"${value.replace(/"/g, '""')}"`

export const serializeFindingsCsv = (findings: Finding[]): string => {
  const headers = [
    'severite', 'type', 'regle', 'nom', 'constat', 'detail',
    'recommandation', 'actions', 'cli', 'reference',
  ]
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
  ])
  return [headers.join(';'), ...rows.map((row) => row.map(csvCell).join(';'))].join('\n')
}
