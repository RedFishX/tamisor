import type { HistoryEntry } from '../application/audit-history'
import type { Severity } from '../domain/audit'
import type { FamilySummary, FindingFamily, PriorityFinding, VdomSummary } from '../domain/overview'
import { severityLabel } from '../domain/labels'
import { formatDate, plural as pluralWord, tr } from '../i18n'
import { escapeHtml } from './html'


export const familyLabel = (family: FindingFamily): string => ({
  risk: tr('Risque', 'Risk'),
  hygiene: tr('Hygiène', 'Hygiene'),
  governance: tr('Gouvernance', 'Governance'),
})[family]

const familyHint = (family: FindingFamily): string => ({
  risk: tr('Permissives, masquées, chevauchements, expositions', 'Permissive, shadowed, overlapping, exposed'),
  hygiene: tr('Journalisation, règles inutilisées, temporaires, doublons, objets', 'Logging, unused and temporary rules, duplicates, objects'),
  governance: tr('Profils de sécurité, inspection SSL, règles à valider', 'Security profiles, SSL inspection, rules to validate'),
})[family]

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

const shortDate = (iso: string) => Number.isNaN(new Date(iso).getTime()) ? '' : formatDate(iso, { day: 'numeric', month: 'short' })

/** « 3 constats » / « 3 findings ». */
const count = (value: number, fr: [string, string], en: [string, string]) => `${value} ${pluralWord(value, fr, en)}`

/** Courbe de la note sur les derniers audits du fichier, échelle fixe 0–100. */
export const renderScoreSparkline = (history: HistoryEntry[]): string => {
  const points = history.slice(-12)
  if (points.length < 2) {
    return `<p class="overview-note">${tr('Premier audit de ce fichier. La courbe d’évolution apparaîtra au prochain import.', 'First audit of this file. The trend line will appear after the next import.')}</p>`
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
    <svg class="sparkline" viewBox="0 0 ${width} 72" preserveAspectRatio="none" role="img" aria-label="${tr(`Note de ${first.score} à ${last.score} sur ${points.length} audits`, `Score from ${first.score} to ${last.score} over ${points.length} audits`)}">
      <line class="sparkline-base" x1="0" y1="${bottom}" x2="${width}" y2="${bottom}" />
      <polygon class="sparkline-area" points="${area}" />
      <polyline class="sparkline-line" points="${line}" />
      <circle class="sparkline-end" cx="${x(points.length - 1).toFixed(1)}" cy="${y(last.score).toFixed(1)}" r="4" />
    </svg>
    <div class="sparkline-labels" aria-hidden="true"><span>${escapeHtml(shortDate(first.analyzedAt))} · ${first.score}</span><span>${escapeHtml(shortDate(last.analyzedAt))} · ${last.score}</span></div>
  `
}

const renderFamilies = (families: FamilySummary[]) => {
  const max = Math.max(1, ...families.map((family) => family.total))
  return families.map((family) => `
    <button class="family-row" type="button" data-family="${family.family}" ${family.total ? '' : 'disabled'} title="${escapeHtml(familyHint(family.family))}">
      <span class="family-name">${familyLabel(family.family)}</span>
      <span class="family-track" aria-hidden="true">${severities
        .filter((severity) => family.bySeverity[severity])
        .map((severity) => `<i class="${severity}" style="width:${((family.bySeverity[severity] / max) * 100).toFixed(1)}%"></i>`)
        .join('')}</span>
      <span class="family-count">${family.total}<span class="sr-only"> ${pluralWord(family.total, ['constat', 'constats'], ['finding', 'findings'])}</span></span>
      <span class="sr-only">${severities.filter((severity) => family.bySeverity[severity]).map((severity) => `${family.bySeverity[severity]} ${severityLabel(severity).toLowerCase()}`).join(', ')}</span>
    </button>
  `).join('')
}

const renderVdoms = (vdoms: VdomSummary[]) => vdoms.map((vdom) => `
  <button class="vdom-row" type="button" data-vdom="${escapeHtml(vdom.vdom)}">
    <strong>${escapeHtml(vdom.vdom)}</strong>
    <span>${count(vdom.policies, ['politique', 'politiques'], ['policy', 'policies'])}</span>
    <span class="vdom-findings">${vdom.critical ? `<span class="severity-badge critical">${vdom.critical} <abbr title="${tr('critiques', 'critical')}">crit.</abbr></span>` : ''}${count(vdom.findings, ['constat', 'constats'], ['finding', 'findings'])}</span>
  </button>
`).join('')

const renderPriorities = (priorities: PriorityFinding[]) => priorities.length
  ? priorities.map(({ finding, riskScore, alsoResolves }) => `
    <button class="finding-row priority-row" type="button" data-priority-id="${escapeHtml(finding.id)}">
      <span class="severity-line ${finding.severity}"></span>
      <span class="finding-main">
        <strong>${escapeHtml(finding.policyName)} · ${escapeHtml(finding.title)}</strong>
        <small>${tr('Règle', 'Rule')} #${escapeHtml(finding.policyId)}${finding.vdom ? ` · ${escapeHtml(finding.vdom)}` : ''} · ${tr('risque', 'risk')} ${riskScore}/100${alsoResolves ? ` · ${tr('sa correction lève aussi', 'fixing it also clears')} ${count(alsoResolves, ['autre constat', 'autres constats'], ['other finding', 'other findings'])}` : ''}</small>
      </span>
      <span class="severity-badge ${finding.severity}">${severityLabel(finding.severity)}</span>
    </button>
  `).join('')
  : `<p class="overview-note">${tr('Aucun constat ouvert. Les constats acquittés ne sont pas repris ici.', 'No open finding. Acknowledged findings are not listed here.')}</p>`

export const renderOverview = (model: OverviewModel): string => {
  const previous = model.previousDate ? shortDate(model.previousDate) : ''
  const since = previous ? tr(`depuis l’audit du ${escapeHtml(previous)}${previous.endsWith('.') ? '' : '.'}`, `since the audit of ${escapeHtml(previous)}.`) : ''
  const delta = model.scoreDelta === undefined || !since
    ? ''
    : model.scoreDelta === 0
      ? `${tr('Note stable', 'Score unchanged')} ${since}`
      : `${model.scoreDelta > 0 ? '+' : '−'}${count(Math.abs(model.scoreDelta), ['point', 'points'], ['point', 'points'])} ${since}`
  const gain = model.scoreAfterCritical !== undefined && model.criticalCount && model.scoreAfterCritical > model.score
    ? tr(
      ` Corriger ${model.criticalCount > 1 ? `les ${model.criticalCount} constats critiques` : 'le constat critique'} la porterait à ${model.scoreAfterCritical}.`,
      ` Fixing ${model.criticalCount > 1 ? `the ${model.criticalCount} critical findings` : 'the critical finding'} would raise it to ${model.scoreAfterCritical}.`,
    )
    : ''
  return `
    <section class="overview-score" aria-labelledby="overview-score-title">
      <h2 class="overview-label" id="overview-score-title">${tr('Note de la configuration', 'Configuration score')}</h2>
      <p class="overview-big ${model.tone}">${model.score}<small>/100</small></p>
      ${delta || gain ? `<p class="overview-note">${delta}${gain}</p>` : ''}
      ${renderScoreSparkline(model.history)}
    </section>
    <section class="overview-block" aria-labelledby="overview-families-title">
      <h2 class="overview-label" id="overview-families-title">${tr('Constats ouverts par famille', 'Open findings by family')}</h2>
      <div class="family-list">${renderFamilies(model.families)}</div>
      <div class="severity-legend" aria-hidden="true">${severities.map((severity) => `<span><i class="${severity}"></i>${severityLabel(severity)}</span>`).join('')}</div>
    </section>
    <section class="overview-block" aria-labelledby="overview-vdoms-title">
      <h2 class="overview-label" id="overview-vdoms-title">${tr('Par VDOM', 'By VDOM')}</h2>
      <div class="vdom-list">${renderVdoms(model.vdoms)}</div>
    </section>
    <section class="overview-priorities" aria-labelledby="overview-priorities-title">
      <div class="overview-priorities-header">
        <h2 class="overview-label" id="overview-priorities-title">${tr('À traiter en premier', 'Address first')}</h2>
        <button class="secondary-button" type="button" data-show-findings>${tr(`Voir les ${count(model.openFindings, ['constat', 'constats'], ['', ''])}`, `See all ${count(model.openFindings, ['', ''], ['finding', 'findings'])}`)}</button>
      </div>
      ${renderPriorities(model.priorities)}
    </section>
  `
}
