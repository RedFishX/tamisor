import type { HistoryEntry } from '../application/audit-history'
import type { Severity } from '../domain/audit'
import type { FamilySummary, FindingFamily, PriorityFinding, VdomSummary } from '../domain/overview'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)

export const familyLabels: Record<FindingFamily, string> = {
  risk: 'Risque',
  hygiene: 'Hygiène',
  governance: 'Gouvernance',
}

const familyHints: Record<FindingFamily, string> = {
  risk: 'Permissives, masquées, chevauchements, expositions',
  hygiene: 'Journalisation, règles inutilisées, temporaires, doublons, objets',
  governance: 'Profils de sécurité, inspection SSL, règles à valider',
}

const severityLabels: Record<Severity, string> = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible' }
const severities: Severity[] = ['critical', 'high', 'medium', 'low']

export interface OverviewModel {
  score: number
  tone: 'good' | 'warning' | 'critical'
  scoreDelta?: number
  previousDate?: string
  scoreAfterCritical?: number
  criticalCount: number
  history: HistoryEntry[]
  families: FamilySummary[]
  vdoms: VdomSummary[]
  priorities: PriorityFinding[]
  openFindings: number
}

const formatDate = (iso: string) => {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' })
}

const plural = (count: number, singular: string, pluralForm = `${singular}s`) => `${count} ${count > 1 ? pluralForm : singular}`

/** Courbe de la note sur les derniers audits du fichier, échelle fixe 0–100. */
export const renderScoreSparkline = (history: HistoryEntry[]): string => {
  const points = history.slice(-12)
  if (points.length < 2) {
    return '<p class="overview-note">Premier audit de ce fichier. La courbe d’évolution apparaîtra au prochain import.</p>'
  }
  const width = 300
  const top = 8
  const bottom = 64
  const x = (index: number) => 6 + (index * (width - 12)) / (points.length - 1)
  const y = (score: number) => bottom - ((bottom - top) * Math.max(0, Math.min(100, score))) / 100
  const line = points.map((entry, index) => `${x(index).toFixed(1)},${y(entry.score).toFixed(1)}`).join(' ')
  const area = `${x(0).toFixed(1)},${bottom} ${line} ${x(points.length - 1).toFixed(1)},${bottom}`
  const first = points[0]
  const last = points[points.length - 1]
  return `
    <svg class="sparkline" viewBox="0 0 ${width} 72" preserveAspectRatio="none" role="img" aria-label="Note de ${first.score} à ${last.score} sur ${points.length} audits">
      <line class="sparkline-base" x1="0" y1="${bottom}" x2="${width}" y2="${bottom}" />
      <polygon class="sparkline-area" points="${area}" />
      <polyline class="sparkline-line" points="${line}" />
      <circle class="sparkline-end" cx="${x(points.length - 1).toFixed(1)}" cy="${y(last.score).toFixed(1)}" r="4" />
    </svg>
    <div class="sparkline-labels"><span>${escapeHtml(formatDate(first.analyzedAt))} · ${first.score}</span><span>${escapeHtml(formatDate(last.analyzedAt))} · ${last.score}</span></div>
  `
}

const renderFamilies = (families: FamilySummary[]) => {
  const max = Math.max(1, ...families.map((family) => family.total))
  return families.map((family) => `
    <button class="family-row" type="button" data-family="${family.family}" ${family.total ? '' : 'disabled'} title="${escapeHtml(familyHints[family.family])}">
      <span class="family-name">${familyLabels[family.family]}</span>
      <span class="family-track" aria-hidden="true">${severities
        .filter((severity) => family.bySeverity[severity])
        .map((severity) => `<i class="${severity}" style="width:${((family.bySeverity[severity] / max) * 100).toFixed(1)}%"></i>`)
        .join('')}</span>
      <span class="family-count">${family.total}</span>
      <span class="sr-only">${severities.filter((severity) => family.bySeverity[severity]).map((severity) => `${family.bySeverity[severity]} ${severityLabels[severity].toLowerCase()}`).join(', ')}</span>
    </button>
  `).join('')
}

const renderVdoms = (vdoms: VdomSummary[]) => vdoms.map((vdom) => `
  <button class="vdom-row" type="button" data-vdom="${escapeHtml(vdom.vdom)}">
    <strong>${escapeHtml(vdom.vdom)}</strong>
    <span>${plural(vdom.policies, 'politique')}</span>
    <span class="vdom-findings">${vdom.critical ? `<span class="severity-badge critical">${vdom.critical} crit.</span>` : ''}${plural(vdom.findings, 'constat')}</span>
  </button>
`).join('')

const renderPriorities = (priorities: PriorityFinding[]) => priorities.length
  ? priorities.map(({ finding, riskScore, alsoResolves }) => `
    <button class="finding-row priority-row" type="button" data-priority-id="${escapeHtml(finding.id)}">
      <span class="severity-line ${finding.severity}"></span>
      <span class="finding-main">
        <strong>${escapeHtml(finding.policyName)} · ${escapeHtml(finding.title)}</strong>
        <small>Règle #${escapeHtml(finding.policyId)}${finding.vdom ? ` · ${escapeHtml(finding.vdom)}` : ''} · risque ${riskScore}/100${alsoResolves ? ` · sa correction lève aussi ${plural(alsoResolves, 'autre constat', 'autres constats')}` : ''}</small>
      </span>
      <span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span>
    </button>
  `).join('')
  : '<p class="overview-note">Aucun constat ouvert. Les constats acquittés ne sont pas repris ici.</p>'

export const renderOverview = (model: OverviewModel): string => {
  const previous = model.previousDate ? formatDate(model.previousDate) : ''
  const since = previous ? `depuis l’audit du ${escapeHtml(previous)}${previous.endsWith('.') ? '' : '.'}` : ''
  const delta = model.scoreDelta === undefined || !since
    ? ''
    : model.scoreDelta === 0
      ? `Note stable ${since}`
      : `${model.scoreDelta > 0 ? '+' : '−'}${plural(Math.abs(model.scoreDelta), 'point')} ${since}`
  const gain = model.scoreAfterCritical !== undefined && model.criticalCount && model.scoreAfterCritical > model.score
    ? ` Corriger ${model.criticalCount > 1 ? `les ${model.criticalCount} constats critiques` : 'le constat critique'} la porterait à ${model.scoreAfterCritical}.`
    : ''
  return `
    <section class="overview-score" aria-labelledby="overview-score-title">
      <h2 class="overview-label" id="overview-score-title">Note de la configuration</h2>
      <p class="overview-big ${model.tone}">${model.score}<small>/100</small></p>
      ${delta || gain ? `<p class="overview-note">${delta}${gain}</p>` : ''}
      ${renderScoreSparkline(model.history)}
    </section>
    <section class="overview-block" aria-labelledby="overview-families-title">
      <h2 class="overview-label" id="overview-families-title">Constats ouverts par famille</h2>
      <div class="family-list">${renderFamilies(model.families)}</div>
      <div class="severity-legend" aria-hidden="true">${severities.map((severity) => `<span><i class="${severity}"></i>${severityLabels[severity]}</span>`).join('')}</div>
    </section>
    <section class="overview-block" aria-labelledby="overview-vdoms-title">
      <h2 class="overview-label" id="overview-vdoms-title">Par VDOM</h2>
      <div class="vdom-list">${renderVdoms(model.vdoms)}</div>
    </section>
    <section class="overview-priorities" aria-labelledby="overview-priorities-title">
      <div class="overview-priorities-header">
        <h2 class="overview-label" id="overview-priorities-title">À traiter en premier</h2>
        <button class="secondary-button" type="button" data-show-findings>Voir les ${plural(model.openFindings, 'constat')}</button>
      </div>
      ${renderPriorities(model.priorities)}
    </section>
  `
}
