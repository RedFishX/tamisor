import {
  AlertTriangle,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clipboard,
  Download,
  FileSearch,
  FileText,
  Filter,
  GitCompareArrows,
  Info,
  Moon,
  PanelLeft,
  Plus,
  Search,
  ShieldCheck,
  SquareTerminal,
  Sun,
  TableProperties,
  Upload,
  X,
  createIcons,
} from 'lucide'
import './style.css'
import { type AuditResult, type Finding, type Severity } from '../domain/audit'
import { emptyAudit } from '../infrastructure/configuration-import'
import type { ImportedAuditResult } from '../application/audit-service'
import { applyMetricFilter, matchesFindingQuery, type MetricFilter } from '../application/finding-filters'
import { computeTrend, recordAudit, type HistoryEntry, type HistoryStore } from '../application/audit-history'
import { createIndexedDbHistoryStore } from '../infrastructure/indexeddb-history-store'
import { renderHistory } from './history-view'
import { renderCompliance, renderRecommendation, serializeFindingsCsv } from './recommendation-view'
import { calculateConfigurationScore, calculateRiskScore } from '../domain/risk-score'
import { assessPolicyElements, type ElementRiskLevel } from '../domain/policy-risk'
import { renderExportMenu } from './export-menu'
import { acknowledgementKey, filterAcknowledgedFindings, parseAcknowledgements, serializeAcknowledgements, toggleAcknowledgement, type AcknowledgementRecord } from '../application/finding-acknowledgement'
import { comparePolicies } from '../domain/audit-comparison'
import { createExecutiveSummary, renderHtmlReport, serializeRecommendationsCli } from './audit-report'
import { resolveTheme, toggleTheme, type ResolvedTheme, type ThemePreference } from './theme'
import { generatePolicyMarkdown } from './policy-documentation'

const severityLabels: Record<Severity, string> = {
  critical: 'Critique',
  high: 'Élevée',
  medium: 'Moyenne',
  low: 'Faible',
}

const categoryLabels: Record<Finding['category'], string> = {
  duplicate: 'Doublon',
  shadowed: 'Masquée',
  overlap: 'Chevauchement',
  permissive: 'Permissive',
  exposure: 'Exposition',
  unused: 'Règles inutilisées',
  indeterminate: 'À valider',
  temporary: 'Temporaire',
  governance: 'Gouvernance',
  security: 'Profils de sécurité',
  inspection: 'Inspection SSL',
  object: 'Objets',
  visibility: 'Visibilité',
}

const elementRiskLabels: Record<ElementRiskLevel, string> = {
  high: 'Élevé',
  medium: 'Moyen',
  low: 'Faible',
}

let audit: AuditResult = emptyAudit()
let sourceName = ''
let activeSeverity = 'all'
let activeCategory = 'all'
let activeVdom = 'all'
let activeInterface = 'all'
let activeSource = 'all'
let activeDestination = 'all'
let activeService = 'all'
let selectedFindingId: string | null = audit.findings[0]?.id ?? null
let showAcknowledged = false
let searchQuery = ''
const compactLayout = window.matchMedia('(max-width: 900px)')
let historyStore: HistoryStore | null = null
let historyEntries: HistoryEntry[] = []
let historyUnavailable = false
try { historyStore = createIndexedDbHistoryStore() } catch { historyUnavailable = true }
let acknowledged = new Set<string>(JSON.parse(localStorage.getItem('fortiscope-acknowledged') ?? '[]'))
let acknowledgementMetadata = new Map<string, AcknowledgementRecord>(Object.entries(JSON.parse(localStorage.getItem('fortiscope-acknowledgement-meta') ?? '{}')) as Array<[string, AcknowledgementRecord]>)
let pendingAcknowledgement: { key: string, finding: Finding } | null = null
const systemTheme = window.matchMedia('(prefers-color-scheme: dark)')
const storedTheme = localStorage.getItem('fortiscope-theme') as ThemePreference | null
let resolvedTheme: ResolvedTheme = resolveTheme(storedTheme ?? 'system', systemTheme.matches)
document.documentElement.dataset.theme = resolvedTheme

const escapeHtml = (value: string) =>
  value.replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character] ?? character)

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <header class="topbar">
    <button class="icon-button sidebar-toggle" id="sidebar-toggle" type="button" aria-controls="sidebar" aria-expanded="false" aria-label="Afficher la source et l’historique" title="Source et historique">
      <i data-lucide="panel-left"></i>
    </button>
    <a class="brand" href="#" aria-label="FortiScope - accueil">
      <span class="brand-mark"><i data-lucide="shield-check"></i></span>
      <span>Forti<span>Scope</span></span>
    </a>
    <div class="topbar-actions">
      <button class="secondary-button" id="compare-button" type="button" disabled>
        <i data-lucide="git-compare-arrows"></i> Comparer
      </button>
      ${renderExportMenu(false)}
      <button class="icon-button theme-toggle" id="theme-toggle" type="button" aria-label="Activer le thème sombre" title="Activer le thème sombre"></button>
    </div>
    <input id="compare-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
    <input id="ack-import-input" type="file" accept=".json,application/json" hidden />
  </header>

  <main class="workspace">
    <aside class="sidebar" id="sidebar" aria-label="Source et historique">
      <div>
        <p class="eyebrow">Source de l’audit</p>
        <label class="dropzone" id="dropzone" for="file-input" tabindex="0">
          <span class="dropzone-icon"><i data-lucide="upload"></i></span>
          <strong>Déposez votre export FortiGate</strong>
          <small>ou cliquez pour choisir un fichier</small>
          <span class="file-types">.conf · .txt · .csv · 10 Mo max.</span>
        </label>
        <input id="file-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
      </div>

      <div class="source-file" id="source-file"></div>

      <section class="history" aria-labelledby="history-title">
        <div class="history-heading">
          <p class="eyebrow" id="history-title">Historique de ce fichier</p>
          <button class="text-button" id="history-clear" type="button" hidden>Effacer</button>
        </div>
        <div id="history-content"></div>
      </section>

      <details class="limitations">
        <summary>Limites de l’analyse</summary>
        <p>Les objets dynamiques, les préfixes IPv6 imbriqués et le contenu des objets référencés uniquement par un CSV ne sont pas résolus. Les horaires nommés sont comparés par identité.</p>
      </details>
    </aside>
    <div class="sidebar-scrim" id="sidebar-scrim" hidden></div>

    <section class="content">
      <div class="page-heading">
        <div>
          <p class="eyebrow">Revue de configuration</p>
          <h1>Politiques à examiner</h1>
        </div>
        <div class="configuration-score" id="configuration-score" aria-label="Note globale de la configuration"></div>
      </div>

      <div class="metrics" id="metrics"></div>
      <p class="executive-summary" id="executive-summary"></p>
      <div class="import-feedback" id="import-feedback" role="alert" hidden></div>
      <div class="comparison-summary" id="comparison-summary" hidden></div>

      <section class="audit-panel">
        <div class="toolbar">
          <label class="search-field">
            <i data-lucide="search"></i>
            <input id="finding-search" type="search" placeholder="Rechercher une politique, une adresse, un service" aria-label="Rechercher dans les constats" autocomplete="off" />
            <kbd aria-hidden="true">/</kbd>
          </label>
          <div class="filter-chips" id="filter-chips" aria-label="Filtres actifs"></div>
          <details class="filter-menu" id="filter-menu">
            <summary class="chip" aria-label="Ajouter un filtre"><i data-lucide="plus"></i> Filtre</summary>
            <div class="filter-options">
              <label class="select-field"><span>Type de constat</span>
                <select id="category-filter" aria-label="Filtrer par type">
                  <option value="all">Tous les constats</option>
                  <option value="permissive">Règles permissives</option>
                  <option value="shadowed">Règles masquées</option>
                  <option value="overlap">Chevauchements partiels</option>
                  <option value="duplicate">Règles dupliquées</option>
                  <option value="exposure">VIP exposées</option>
                  <option value="visibility">Visibilité</option>
                  <option value="unused">Règles inutilisées</option>
                  <option value="indeterminate">À valider</option>
                  <option value="temporary">Règles temporaires</option>
                  <option value="governance">Gouvernance</option>
                  <option value="security">Profils de sécurité</option>
                  <option value="inspection">Inspection SSL</option>
                  <option value="object">Objets</option>
                </select>
              </label>
              <label class="select-field"><span>VDOM</span><select id="vdom-filter" aria-label="Filtrer par VDOM"><option value="all">Tous</option></select></label>
              <label class="select-field"><span>Interface</span><select id="interface-filter" aria-label="Filtrer par interface"><option value="all">Toutes</option></select></label>
              <label class="select-field"><span>Source</span><select id="source-filter" aria-label="Filtrer par source"><option value="all">Toutes</option></select></label>
              <label class="select-field"><span>Destination</span><select id="destination-filter" aria-label="Filtrer par destination"><option value="all">Toutes</option></select></label>
              <label class="select-field"><span>Service</span><select id="service-filter" aria-label="Filtrer par service"><option value="all">Tous</option></select></label>
            </div>
          </details>
          <label class="acknowledged-toggle">
            <input id="show-acknowledged" type="checkbox" />
            Afficher les acquittés
          </label>
        </div>

        <div class="severity-tabs" id="severity-tabs" aria-label="Filtrer par sévérité"></div>
        <div class="results-layout" id="results-layout">
          <div class="findings-list" id="findings-list"></div>
          <div class="detail-scrim" id="detail-scrim"></div>
          <aside class="finding-detail" id="finding-detail" aria-label="Détail du constat"></aside>
        </div>
      </section>
    </section>
  </main>
  <dialog class="markdown-dialog" id="markdown-dialog">
    <div class="dialog-header">
      <div><p class="eyebrow">Documentation de policy</p><h2>Markdown prêt à copier</h2></div>
      <button class="icon-button" id="close-markdown" type="button" aria-label="Fermer" title="Fermer"><i data-lucide="x"></i></button>
    </div>
    <textarea id="policy-markdown" readonly aria-label="Documentation Markdown de la policy"></textarea>
    <div class="dialog-actions">
      <span id="copy-status" role="status"></span>
      <button class="acknowledge-button" id="copy-markdown" type="button"><i data-lucide="clipboard"></i>Copier le Markdown</button>
    </div>
  </dialog>
  <dialog class="acknowledgement-dialog" id="acknowledgement-dialog">
    <div class="dialog-header">
      <div><p class="eyebrow">Revue du constat</p><h2>Acquitter ce constat</h2></div>
      <button class="icon-button" id="close-acknowledgement" type="button" aria-label="Annuler" title="Annuler"><i data-lucide="x"></i></button>
    </div>
    <form id="acknowledgement-form">
      <p id="acknowledgement-title" class="acknowledgement-title"></p>
      <label class="dialog-field">Justification de l’acquittement<textarea id="acknowledgement-justification" required rows="4" placeholder="Expliquez pourquoi ce constat est accepté temporairement ou définitivement."></textarea></label>
      <label class="dialog-field">Date de révision<input id="acknowledgement-review-date" type="date" required /></label>
      <div class="dialog-actions">
        <button class="secondary-button" id="cancel-acknowledgement" type="button">Annuler</button>
        <button class="acknowledge-button" type="submit"><i data-lucide="check"></i>Acquitter</button>
      </div>
    </form>
  </dialog>
`

const renderIcons = () => createIcons({
  icons: { AlertTriangle, BookOpen, Check, CheckCircle2, ChevronDown, ChevronRight, Clipboard, Download, FileSearch, FileText, Filter, GitCompareArrows, Info, Moon, PanelLeft, Plus, Search, ShieldCheck, SquareTerminal, Sun, TableProperties, Upload, X },
})

const renderThemeToggle = () => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle')!
  const nextLabel = resolvedTheme === 'dark' ? 'Activer le thème clair' : 'Activer le thème sombre'
  button.setAttribute('aria-label', nextLabel)
  button.title = nextLabel
  button.innerHTML = `<i data-lucide="${resolvedTheme === 'dark' ? 'sun' : 'moon'}"></i>`
  renderIcons()
}

const policyForFinding = (finding: Finding) => audit.policies.find((candidate) =>
  candidate.id === finding.policyId && candidate.vdom === finding.vdom && candidate.family === finding.family,
)

const filteredFindings = (options: { ignoreSeverity?: boolean } = {}) => filterAcknowledgedFindings(audit.findings, acknowledged, sourceName, showAcknowledged).filter((finding) => {
  const matchesSeverity = options.ignoreSeverity || activeSeverity === 'all' || finding.severity === activeSeverity
  const matchesCategory = activeCategory === 'all' || finding.category === activeCategory
  const policy = policyForFinding(finding)
  if (!matchesFindingQuery(finding, policy, searchQuery)) return false
  const matchesVdom = activeVdom === 'all' || (policy?.vdom ?? 'global') === activeVdom
  const matchesInterface = activeInterface === 'all' || [...(policy?.srcintf ?? []), ...(policy?.dstintf ?? [])].includes(activeInterface)
  const matchesSource = activeSource === 'all' || (policy?.srcaddr ?? []).includes(activeSource)
  const matchesDestination = activeDestination === 'all' || (policy?.dstaddr ?? []).includes(activeDestination)
  const matchesService = activeService === 'all' || [...(policy?.service ?? []), ...(policy?.internetServices ?? [])].includes(activeService)
  return matchesSeverity && matchesCategory && matchesVdom && matchesInterface && matchesSource && matchesDestination && matchesService
})

const renderContextFilters = () => {
  const options = (values: string[], selected: string, fallback: string) => [`<option value="all">${fallback}</option>`, ...[...new Set(values)].sort().map((value) => `<option value="${escapeHtml(value)}"${value === selected ? ' selected' : ''}>${escapeHtml(value)}</option>`)].join('')
  const policies = audit.policies
  const filterOptions: Array<[string, string[], string]> = [
    ['vdom-filter', policies.map((policy) => policy.vdom ?? 'global'), activeVdom],
    ['interface-filter', policies.flatMap((policy) => [...policy.srcintf, ...policy.dstintf]), activeInterface],
    ['source-filter', policies.flatMap((policy) => policy.srcaddr), activeSource],
    ['destination-filter', policies.flatMap((policy) => policy.dstaddr), activeDestination],
    ['service-filter', policies.flatMap((policy) => [...policy.service, ...policy.internetServices]), activeService],
  ]
  for (const [id, values, selected] of filterOptions) {
    const select = document.querySelector<HTMLSelectElement>(`#${id}`)
    if (select) select.innerHTML = options(values, selected, id === 'vdom-filter' ? 'Tous' : id === 'service-filter' ? 'Tous' : 'Toutes')
  }
  document.querySelector<HTMLSelectElement>('#category-filter')!.value = activeCategory
  renderFilterChips()
}

const categoryOptionLabel = (value: string) =>
  document.querySelector<HTMLOptionElement>(`#category-filter option[value="${CSS.escape(value)}"]`)?.textContent ?? value

const renderFilterChips = () => {
  const chips: Array<[string, string, string]> = [
    ['category', 'Type', activeCategory === 'all' ? '' : categoryOptionLabel(activeCategory)],
    ['vdom', 'VDOM', activeVdom === 'all' ? '' : activeVdom],
    ['interface', 'Interface', activeInterface === 'all' ? '' : activeInterface],
    ['source', 'Source', activeSource === 'all' ? '' : activeSource],
    ['destination', 'Destination', activeDestination === 'all' ? '' : activeDestination],
    ['service', 'Service', activeService === 'all' ? '' : activeService],
  ]
  document.querySelector<HTMLDivElement>('#filter-chips')!.innerHTML = chips
    .filter(([, , value]) => value)
    .map(([key, label, value]) => `
      <button class="chip" type="button" data-clear-filter="${key}" aria-label="Retirer le filtre ${escapeHtml(label)} ${escapeHtml(value)}">
        ${escapeHtml(label)} <b>${escapeHtml(value)}</b><i data-lucide="x"></i>
      </button>
    `).join('')
}

const clearFilter = (key: string) => {
  if (key === 'category') activeCategory = 'all'
  if (key === 'vdom') activeVdom = 'all'
  if (key === 'interface') activeInterface = 'all'
  if (key === 'source') activeSource = 'all'
  if (key === 'destination') activeDestination = 'all'
  if (key === 'service') activeService = 'all'
}

const renderSource = () => {
  document.querySelector<HTMLButtonElement>('#compare-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#html-report-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#cli-export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#ack-export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#ack-import-button')!.disabled = !sourceName
  if (!sourceName) {
    document.querySelector<HTMLDivElement>('#source-file')!.innerHTML = `
      <div class="source-icon"><i data-lucide="file-search"></i></div>
      <div><span>En attente</span><strong>Aucune configuration</strong></div>
    `
    return
  }
  document.querySelector<HTMLDivElement>('#source-file')!.innerHTML = `
    <div class="source-icon"><i data-lucide="file-search"></i></div>
    <div><span>Configuration analysée</span><strong title="${escapeHtml(sourceName)}">${escapeHtml(sourceName)}</strong></div>
    <span class="source-status"><i data-lucide="check-circle-2"></i></span>
  `
}

const acknowledgedCount = () => sourceName
  ? audit.findings.filter((finding) => acknowledged.has(acknowledgementKey(sourceName, finding))).length
  : 0

const renderMetrics = () => {
  if (!sourceName) {
    document.querySelector<HTMLDivElement>('#metrics')!.innerHTML = ''
    return
  }
  const metricFilters = [
    ['Critiques', audit.stats.critical, audit.stats.critical > 0 ? 'critical' : '', 'critical'],
    ['Permissives', audit.stats.permissive, '', 'permissive'],
    ['Masquées', audit.stats.shadowed, '', 'shadowed'],
  ] as const
  document.querySelector<HTMLDivElement>('#metrics')!.innerHTML = `
    <article class="metric">
      <span>Politiques actives</span>
      <strong>${audit.stats.activePolicies}</strong>
    </article>
    ${metricFilters.map(([label, value, tone, filter]) => {
      const isActive = (filter === 'critical' && activeSeverity === 'critical' && activeCategory === 'all') ||
        (filter !== 'critical' && activeSeverity === 'all' && activeCategory === filter)
      return `
        <button class="metric ${tone} ${isActive ? 'active' : ''}" type="button" data-metric-filter="${filter}" aria-pressed="${isActive}">
          <span>${label}</span>
          <strong>${value}</strong>
        </button>
      `
    }).join('')}
    <button class="metric ${showAcknowledged ? 'active' : ''}" type="button" data-metric-acknowledged aria-pressed="${showAcknowledged}" title="Afficher ou masquer les constats acquittés">
      <span>Acquittés</span>
      <strong>${acknowledgedCount()}</strong>
    </button>
  `
}

const formatShortDate = (iso: string) => {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' })
}

const renderConfigurationScore = () => {
  const container = document.querySelector<HTMLDivElement>('#configuration-score')!
  if (!sourceName) {
    container.className = 'configuration-score'
    container.innerHTML = ''
    return
  }
  const score = calculateConfigurationScore(audit)
  const tone = score >= 80 ? 'good' : score >= 60 ? 'warning' : 'critical'
  const trend = computeTrend(historyEntries, sourceName)
  const delta = trend?.previous && trend.scoreDelta !== undefined
    ? `${trend.scoreDelta > 0 ? '+' : ''}${trend.scoreDelta} depuis le ${formatShortDate(trend.previous.analyzedAt)}`
    : ''
  container.className = `configuration-score ${tone}`
  container.innerHTML = `<strong>${score}<small>/100</small></strong>${delta ? `<span>${escapeHtml(delta)}</span>` : ''}`
}

const renderTabs = () => {
  const visible = filteredFindings({ ignoreSeverity: true })
  const count = (severity: Severity) => visible.filter((finding) => finding.severity === severity).length
  const tabs: Array<[string, string, number]> = [
    ['all', 'Tous', visible.length],
    ['critical', 'Critiques', count('critical')],
    ['high', 'Élevés', count('high')],
    ['medium', 'Moyens', count('medium')],
    ['low', 'Faibles', count('low')],
  ]
  document.querySelector<HTMLDivElement>('#severity-tabs')!.innerHTML = tabs.map(([value, label, count]) => `
    <button type="button" data-severity="${value}" class="${activeSeverity === value ? 'active' : ''}" aria-pressed="${activeSeverity === value}">
      ${label}<span>${count}</span>
    </button>
  `).join('')
}

const renderDetail = (finding: Finding | undefined) => {
  const detail = document.querySelector<HTMLElement>('#finding-detail')!
  if (!finding) {
    detail.innerHTML = `<div class="empty-detail"><i data-lucide="check-circle-2"></i><strong>Aucun constat</strong><span>Modifiez les filtres ou chargez une autre configuration.</span></div>`
    return
  }
  const findingKey = acknowledgementKey(sourceName, finding)
  const isAcknowledged = acknowledged.has(findingKey)
  const acknowledgement = acknowledgementMetadata.get(findingKey)
  const policy = policyForFinding(finding)
  const riskScore = calculateRiskScore(finding, 'standard')
  const elementRisks = policy ? assessPolicyElements(policy) : []
  detail.innerHTML = `
    <button class="icon-button detail-close" type="button" data-close-detail aria-label="Fermer le détail" title="Fermer"><i data-lucide="x"></i></button>
    <div class="detail-header">
      <span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span>
      <span>${escapeHtml(categoryLabels[finding.category])} · règle #${escapeHtml(finding.policyId)} · seq ${finding.order}</span>
      <strong class="risk-score">Risque ${riskScore}/100</strong>
    </div>
    <h2>${escapeHtml(finding.title)}</h2>
    <p class="detail-policy">${escapeHtml(finding.policyName)}</p>
    ${acknowledgement ? `<p class="acknowledgement-note">Acquitté : ${escapeHtml(acknowledgement.justification)} · Revue : ${escapeHtml(acknowledgement.reviewDate || 'non planifiée')}</p>` : ''}
    ${policy?.hitCount !== undefined || policy?.lastUsed ? `
      <div class="usage-stats">
        ${policy.hitCount !== undefined ? `<span><strong>${policy.hitCount.toLocaleString('fr-FR')}</strong> correspondances</span>` : ''}
        ${policy.lastUsed ? `<span>Dernière utilisation <strong>${escapeHtml(policy.lastUsed)}</strong></span>` : ''}
      </div>
    ` : ''}
    <p class="detail-copy">${escapeHtml(finding.detail)}</p>
    ${elementRisks.length ? `
      <section class="policy-risk-matrix">
        <h3>Niveau de risque par élément</h3>
        ${elementRisks.map((element) => `
          <article class="element-risk">
            <div><strong>${escapeHtml(element.label)}</strong><span class="element-risk-badge ${element.level}">${elementRiskLabels[element.level]}</span></div>
            <code>${escapeHtml(element.value)}</code>
            <p>${escapeHtml(element.reason)}</p>
          </article>
        `).join('')}
      </section>
    ` : ''}
    <div class="evidence">
      <span>Éléments détectés</span>
      ${finding.evidence.map((item) => `<p><i data-lucide="alert-triangle"></i>${escapeHtml(item)}</p>`).join('')}
    </div>
    ${renderRecommendation(finding.recommendation)}
    ${renderCompliance(finding)}
    <div class="detail-actions">
      <button class="acknowledge-button ${isAcknowledged ? 'restore' : ''}" type="button" data-acknowledge="${escapeHtml(finding.id)}" aria-keyshortcuts="A">
        <i data-lucide="check"></i>${isAcknowledged ? 'Restaurer le constat' : 'Acquitter le constat'}<kbd aria-hidden="true">A</kbd>
      </button>
      ${policy ? `<button class="policy-doc-button" type="button" data-policy-doc="${escapeHtml(finding.id)}"><i data-lucide="book-open"></i>Documentation Markdown</button>` : ''}
    </div>
  `
}

const hasActiveFilters = () => Boolean(searchQuery.trim()) || [activeSeverity, activeCategory, activeVdom, activeInterface, activeSource, activeDestination, activeService].some((value) => value !== 'all')

const renderNoResult = () => hasActiveFilters()
  ? `<div class="empty-list"><i data-lucide="filter"></i><strong>Aucun constat pour ces filtres</strong><span>Élargissez la recherche ou retirez un filtre.</span><button class="secondary-button" type="button" data-reset-filters>Retirer tous les filtres</button></div>`
  : `<div class="empty-list"><i data-lucide="check-circle-2"></i><strong>Aucun constat</strong><span>Aucune règle ne présente de problème détecté par l’analyse.</span></div>`

const renderFindings = () => {
  const findings = filteredFindings()
  if (!findings.some((finding) => finding.id === selectedFindingId)) selectedFindingId = findings[0]?.id ?? null
  const list = document.querySelector<HTMLDivElement>('#findings-list')!
  if (!sourceName) {
    list.innerHTML = `<div class="empty-list"><i data-lucide="upload"></i><strong>Aucune configuration analysée</strong><span>Importez un export FortiGate (.conf, .txt ou .csv). L’analyse se fait dans votre navigateur, aucun fichier n’est envoyé.</span><label class="secondary-button" for="file-input" tabindex="0"><i data-lucide="upload"></i> Choisir un fichier</label></div>`
    document.querySelector<HTMLElement>('#finding-detail')!.innerHTML = `<div class="empty-detail"><i data-lucide="file-search"></i><span>Le détail de chaque constat et son plan de remédiation s’afficheront ici.</span></div>`
    renderIcons()
    return
  }
  list.innerHTML = findings.length ? findings.map((finding) => `
    <button type="button" class="finding-row ${finding.id === selectedFindingId ? 'selected' : ''}" data-finding-id="${finding.id}" aria-current="${finding.id === selectedFindingId}">
      <span class="severity-line ${finding.severity}"></span>
      <span class="finding-main">
        <span class="finding-meta"><span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span>${categoryLabels[finding.category]}</span>
        <strong>${escapeHtml(finding.policyName)}</strong>
        <small>Règle #${escapeHtml(finding.policyId)} · ${escapeHtml(finding.title)}</small>
      </span>
      <i data-lucide="chevron-right"></i>
    </button>
  `).join('') : renderNoResult()
  renderDetail(findings.find((finding) => finding.id === selectedFindingId))
  renderIcons()
}

const renderHistoryPanel = () => {
  document.querySelector<HTMLDivElement>('#history-content')!.innerHTML = sourceName
    ? renderHistory(historyEntries, sourceName, historyUnavailable)
    : '<p class="history-empty">Importez une configuration pour suivre sa note dans le temps.</p>'
  document.querySelector<HTMLButtonElement>('#history-clear')!.hidden = !historyEntries.length
}

const refreshHistory = async () => {
  if (!historyStore) return
  try {
    historyEntries = await recordAudit(historyStore, audit, sourceName)
    historyUnavailable = false
  } catch {
    historyUnavailable = true
  }
  renderHistoryPanel()
  renderConfigurationScore()
}

const renderAll = () => {
  renderSource()
  renderHistoryPanel()
  renderConfigurationScore()
  renderContextFilters()
  renderMetrics()
  renderTabs()
  renderFindings()
  document.querySelector<HTMLParagraphElement>('#executive-summary')!.textContent = sourceName
    ? createExecutiveSummary(audit)
    : 'Importez une configuration pour démarrer l’audit.'
  renderIcons()
  renderThemeToggle()
}

const renderImportErrors = (errors: string[]) => {
  const feedback = document.querySelector<HTMLDivElement>('#import-feedback')!
  feedback.classList.remove('is-progress')
  feedback.hidden = errors.length === 0
  feedback.innerHTML = errors.length
    ? `<i data-lucide="alert-triangle"></i><div><strong>Import impossible</strong>${errors.map((error) => `<p>${escapeHtml(error)}</p>`).join('')}</div>`
    : ''
  renderIcons()
}

const renderImportProgress = (message: string) => {
  const feedback = document.querySelector<HTMLDivElement>('#import-feedback')!
  feedback.hidden = false
  feedback.classList.add('is-progress')
  feedback.innerHTML = `<div role="status">${escapeHtml(message)}</div>`
}

const analyzeWithWorker = (content: string, fileName: string): Promise<ImportedAuditResult> => new Promise((resolve, reject) => {
  const worker = new Worker(new URL('./audit.worker.ts', import.meta.url), { type: 'module' })
  worker.onmessage = (event: MessageEvent<{ type: string, message?: string, result?: ImportedAuditResult }>) => {
    if (event.data.type === 'progress' && event.data.message) renderImportProgress(event.data.message)
    if (event.data.type === 'result' && event.data.result) {
      worker.terminate()
      resolve(event.data.result)
    }
  }
  worker.onerror = (error) => {
    worker.terminate()
    reject(error)
  }
  worker.postMessage({ content, fileName })
})

const loadConfiguration = async (content: string, name: string) => {
  const nextAudit = await analyzeWithWorker(content, name)
  renderImportErrors(nextAudit.importErrors)
  if (!nextAudit.policies.length) {
    return
  }
  audit = nextAudit
  sourceName = name
  selectedFindingId = audit.findings[0]?.id ?? null
  renderAll()
  await refreshHistory()
}

const handleFile = async (file?: File) => {
  if (!file) return
  if (file.size > 10 * 1024 * 1024) {
    window.alert('Le fichier dépasse la limite de 10 Mo.')
    return
  }
  await loadConfiguration(await file.text(), file.name)
}

document.querySelector<HTMLInputElement>('#file-input')!.addEventListener('change', (event) => {
  void handleFile((event.target as HTMLInputElement).files?.[0])
})
document.querySelector<HTMLButtonElement>('#history-clear')!.addEventListener('click', async () => {
  if (!historyStore || !window.confirm('Effacer l’historique de tous les audits enregistrés dans ce navigateur ?')) return
  try { await historyStore.clear() } catch { historyUnavailable = true }
  historyEntries = []
  renderHistoryPanel()
})
document.querySelector<HTMLButtonElement>('#theme-toggle')!.addEventListener('click', () => {
  resolvedTheme = toggleTheme(resolvedTheme)
  document.documentElement.dataset.theme = resolvedTheme
  localStorage.setItem('fortiscope-theme', resolvedTheme)
  renderThemeToggle()
})
document.querySelector<HTMLButtonElement>('#compare-button')!.addEventListener('click', () => document.querySelector<HTMLInputElement>('#compare-input')!.click())
document.querySelector<HTMLInputElement>('#compare-input')!.addEventListener('change', (event) => {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  void file.text().then((content) => analyzeWithWorker(content, file.name)).then((compared) => {
    renderImportErrors(compared.importErrors)
    if (compared.importErrors.length) return
    const comparison = comparePolicies(audit.policies, compared.policies)
    const summary = document.querySelector<HTMLDivElement>('#comparison-summary')!
    summary.hidden = false
    const modifications = comparison.modified.map(({ after, changedFields }) =>
      `<li>Règle #${escapeHtml(after.id)} : ${escapeHtml(changedFields.join(', ') || 'champs non détaillés')}</li>`,
    ).join('')
    summary.innerHTML = `<strong>Comparaison avec ${escapeHtml(file.name)}</strong><span>${comparison.added.length} ajoutée(s)</span><span>${comparison.modified.length} modifiée(s)</span><span>${comparison.removed.length} supprimée(s)</span>${modifications ? `<ul>${modifications}</ul>` : ''}`
  })
})
document.querySelector<HTMLSelectElement>('#category-filter')!.addEventListener('change', (event) => {
  activeCategory = (event.target as HTMLSelectElement).value
  refreshFindingsView()
})
const contextFilters: Array<[string, (value: string) => void]> = [
  ['vdom-filter', (value) => { activeVdom = value }],
  ['interface-filter', (value) => { activeInterface = value }],
  ['source-filter', (value) => { activeSource = value }],
  ['destination-filter', (value) => { activeDestination = value }],
  ['service-filter', (value) => { activeService = value }],
]
for (const [id, update] of contextFilters) {
  document.querySelector<HTMLSelectElement>(`#${id}`)!.addEventListener('change', (event) => {
    update((event.target as HTMLSelectElement).value)
    refreshFindingsView()
  })
}
document.querySelector<HTMLInputElement>('#show-acknowledged')!.addEventListener('change', (event) => {
  showAcknowledged = (event.target as HTMLInputElement).checked
  refreshFindingsView()
})
document.querySelector<HTMLDivElement>('#severity-tabs')!.addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-severity]')
  if (!button) return
  activeSeverity = button.dataset.severity ?? 'all'
  refreshFindingsView()
})
document.querySelector<HTMLDivElement>('#metrics')!.addEventListener('click', (event) => {
  if ((event.target as HTMLElement).closest('[data-metric-acknowledged]')) {
    showAcknowledged = !showAcknowledged
    document.querySelector<HTMLInputElement>('#show-acknowledged')!.checked = showAcknowledged
    refreshFindingsView()
    return
  }
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-metric-filter]')
  if (!button) return
  const filters = applyMetricFilter(
    { severity: activeSeverity as Severity | 'all', category: activeCategory as Finding['category'] | 'all' },
    button.dataset.metricFilter as MetricFilter,
  )
  activeSeverity = filters.severity
  activeCategory = filters.category
  refreshFindingsView()
})
document.querySelector<HTMLDivElement>('#findings-list')!.addEventListener('click', (event) => {
  const row = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-finding-id]')
  if (row) {
    selectFinding(row.dataset.findingId ?? null)
    if (compactLayout.matches) openDetailSheet()
    return
  }
  if ((event.target as HTMLElement).closest('[data-reset-filters]')) {
    searchQuery = ''
    document.querySelector<HTMLInputElement>('#finding-search')!.value = ''
    activeSeverity = 'all'
    for (const key of ['category', 'vdom', 'interface', 'source', 'destination', 'service']) clearFilter(key)
    renderContextFilters()
    refreshFindingsView()
  }
})
document.querySelector<HTMLElement>('#finding-detail')!.addEventListener('click', (event) => {
  if ((event.target as HTMLElement).closest('[data-close-detail]')) {
    closeDetailSheet()
    return
  }
  const copyButton = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-copy-cli]')
  if (copyButton) {
    copyCli(copyButton)
    return
  }
  const documentationButton = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-policy-doc]')
  if (documentationButton) {
    const finding = audit.findings.find((candidate) => candidate.id === documentationButton.dataset.policyDoc)
    const policy = finding && policyForFinding(finding)
    if (finding && policy) {
      const relatedFindings = audit.findings.filter((candidate) =>
        candidate.policyId === policy.id && candidate.vdom === policy.vdom && candidate.family === policy.family,
      )
      document.querySelector<HTMLTextAreaElement>('#policy-markdown')!.value = generatePolicyMarkdown(
        policy,
        relatedFindings,
        sourceName,
      )
      document.querySelector<HTMLSpanElement>('#copy-status')!.textContent = ''
      document.querySelector<HTMLDialogElement>('#markdown-dialog')!.showModal()
    }
    return
  }
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-acknowledge]')
  const finding = audit.findings.find((candidate) => candidate.id === button?.dataset.acknowledge)
  if (!button || !finding) return
  const key = acknowledgementKey(sourceName, finding)
  if (!acknowledged.has(key)) {
    pendingAcknowledgement = { key, finding }
    document.querySelector<HTMLParagraphElement>('#acknowledgement-title')!.textContent = `${finding.policyName} · ${finding.title}`
    document.querySelector<HTMLTextAreaElement>('#acknowledgement-justification')!.value = ''
    document.querySelector<HTMLInputElement>('#acknowledgement-review-date')!.value = ''
    document.querySelector<HTMLDialogElement>('#acknowledgement-dialog')!.showModal()
    return
  } else {
    acknowledgementMetadata.delete(key)
  }
  acknowledged = toggleAcknowledgement(acknowledged, key)
  localStorage.setItem('fortiscope-acknowledged', JSON.stringify([...acknowledged]))
  localStorage.setItem('fortiscope-acknowledgement-meta', JSON.stringify(Object.fromEntries(acknowledgementMetadata)))
  refreshFindingsView()
})

document.querySelector<HTMLButtonElement>('#close-markdown')!.addEventListener('click', () => {
  document.querySelector<HTMLDialogElement>('#markdown-dialog')!.close()
})
document.querySelector<HTMLButtonElement>('#copy-markdown')!.addEventListener('click', () => {
  const textarea = document.querySelector<HTMLTextAreaElement>('#policy-markdown')!
  const copy = navigator.clipboard?.writeText(textarea.value) ?? Promise.reject()
  void copy.catch(() => {
    textarea.select()
    document.execCommand('copy')
  }).finally(() => {
    document.querySelector<HTMLSpanElement>('#copy-status')!.textContent = 'Markdown copié'
  })
})
const closeAcknowledgementDialog = () => {
  pendingAcknowledgement = null
  document.querySelector<HTMLDialogElement>('#acknowledgement-dialog')!.close()
}
document.querySelector<HTMLButtonElement>('#close-acknowledgement')!.addEventListener('click', closeAcknowledgementDialog)
document.querySelector<HTMLButtonElement>('#cancel-acknowledgement')!.addEventListener('click', closeAcknowledgementDialog)
document.querySelector<HTMLFormElement>('#acknowledgement-form')!.addEventListener('submit', (event) => {
  event.preventDefault()
  if (!pendingAcknowledgement) return
  const justification = document.querySelector<HTMLTextAreaElement>('#acknowledgement-justification')!.value.trim()
  const reviewDate = document.querySelector<HTMLInputElement>('#acknowledgement-review-date')!.value
  if (!justification || !reviewDate) return
  const { key } = pendingAcknowledgement
  const previousList = filteredFindings()
  const previousIndex = previousList.findIndex((finding) => finding.id === selectedFindingId)
  acknowledgementMetadata.set(key, { key, justification, reviewDate, acknowledgedAt: new Date().toISOString() })
  acknowledged = toggleAcknowledgement(acknowledged, key)
  localStorage.setItem('fortiscope-acknowledged', JSON.stringify([...acknowledged]))
  localStorage.setItem('fortiscope-acknowledgement-meta', JSON.stringify(Object.fromEntries(acknowledgementMetadata)))
  closeAcknowledgementDialog()
  const nextList = filteredFindings()
  if (!nextList.some((finding) => finding.id === selectedFindingId) && nextList.length) {
    selectedFindingId = nextList[Math.min(Math.max(previousIndex, 0), nextList.length - 1)].id
  }
  refreshFindingsView()
})

const dropzone = document.querySelector<HTMLLabelElement>('#dropzone')!
for (const eventName of ['dragenter', 'dragover']) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault()
    dropzone.classList.add('dragging')
  })
}
for (const eventName of ['dragleave', 'drop']) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault()
    dropzone.classList.remove('dragging')
  })
}
dropzone.addEventListener('drop', (event) => void handleFile(event.dataTransfer?.files[0]))

document.querySelector<HTMLButtonElement>('#export-button')!.addEventListener('click', () => {
  const csv = serializeFindingsCsv(audit.findings)
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' }))
  link.download = 'audit-fortigate.csv'
  link.click()
  URL.revokeObjectURL(link.href)
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})

const downloadText = (content: string, fileName: string, type: string) => {
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([content], { type }))
  link.download = fileName
  link.click()
  URL.revokeObjectURL(link.href)
}

document.querySelector<HTMLButtonElement>('#html-report-button')!.addEventListener('click', () => {
  downloadText(renderHtmlReport(audit, sourceName), 'rapport-fortiscope.html', 'text/html;charset=utf-8')
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})
document.querySelector<HTMLButtonElement>('#cli-export-button')!.addEventListener('click', () => {
  downloadText(serializeRecommendationsCli(audit.findings), 'remediations-fortigate.cli', 'text/plain;charset=utf-8')
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})
document.querySelector<HTMLButtonElement>('#ack-export-button')!.addEventListener('click', () => {
  downloadText(serializeAcknowledgements([...acknowledgementMetadata.values()]), 'acquittements-fortiscope.json', 'application/json;charset=utf-8')
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})
document.querySelector<HTMLButtonElement>('#ack-import-button')!.addEventListener('click', () => document.querySelector<HTMLInputElement>('#ack-import-input')!.click())
document.querySelector<HTMLInputElement>('#ack-import-input')!.addEventListener('change', (event) => {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  void file.text().then((content) => {
    try {
      const records = parseAcknowledgements(content)
      for (const record of records) {
        acknowledgementMetadata.set(record.key, record)
        acknowledged.add(record.key)
      }
      localStorage.setItem('fortiscope-acknowledged', JSON.stringify([...acknowledged]))
      localStorage.setItem('fortiscope-acknowledgement-meta', JSON.stringify(Object.fromEntries(acknowledgementMetadata)))
      refreshFindingsView()
    } catch {
      renderImportErrors(['Fichier d’acquittements invalide.'])
    }
  })
})

const refreshFindingsView = () => {
  renderFilterChips()
  renderMetrics()
  renderTabs()
  renderFindings()
}

const selectFinding = (id: string | null) => {
  selectedFindingId = id
  renderFindings()
  document.querySelector<HTMLButtonElement>(`[data-finding-id="${CSS.escape(id ?? '')}"]`)?.scrollIntoView({ block: 'nearest' })
}

const moveSelection = (step: number) => {
  const findings = filteredFindings()
  if (!findings.length) return
  const index = findings.findIndex((finding) => finding.id === selectedFindingId)
  const next = findings[Math.min(Math.max(index + step, 0), findings.length - 1)]
  selectFinding(next.id)
  document.querySelector<HTMLButtonElement>(`[data-finding-id="${CSS.escape(next.id)}"]`)?.focus()
}

const copyCli = (button: HTMLButtonElement) => {
  const code = button.closest('.cli-preview')?.querySelector('code')?.textContent ?? ''
  const done = () => {
    button.textContent = 'Copié'
    window.setTimeout(() => { button.textContent = 'Copier' }, 2000)
  }
  void (navigator.clipboard?.writeText(code) ?? Promise.reject(new Error('clipboard'))).then(done, () => {
    const range = document.createRange()
    const target = button.closest('.cli-preview')?.querySelector('code')
    if (!target) return
    range.selectNodeContents(target)
    window.getSelection()?.removeAllRanges()
    window.getSelection()?.addRange(range)
  })
}

const openDetailSheet = () => document.querySelector<HTMLDivElement>('#results-layout')!.classList.add('detail-open')
const closeDetailSheet = () => document.querySelector<HTMLDivElement>('#results-layout')!.classList.remove('detail-open')
document.querySelector<HTMLDivElement>('#detail-scrim')!.addEventListener('click', closeDetailSheet)

const sidebar = document.querySelector<HTMLElement>('#sidebar')!
const sidebarToggle = document.querySelector<HTMLButtonElement>('#sidebar-toggle')!
const sidebarScrim = document.querySelector<HTMLDivElement>('#sidebar-scrim')!
const setSidebarOpen = (open: boolean) => {
  sidebar.classList.toggle('open', open)
  sidebarScrim.hidden = !open
  sidebarToggle.setAttribute('aria-expanded', String(open))
}
sidebarToggle.addEventListener('click', () => setSidebarOpen(!sidebar.classList.contains('open')))
sidebarScrim.addEventListener('click', () => setSidebarOpen(false))
compactLayout.addEventListener('change', () => {
  setSidebarOpen(false)
  closeDetailSheet()
})

let searchTimer: number | undefined
document.querySelector<HTMLInputElement>('#finding-search')!.addEventListener('input', (event) => {
  window.clearTimeout(searchTimer)
  const value = (event.target as HTMLInputElement).value
  searchTimer = window.setTimeout(() => {
    searchQuery = value
    refreshFindingsView()
  }, 150)
})
document.querySelector<HTMLDivElement>('#filter-chips')!.addEventListener('click', (event) => {
  const chip = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-clear-filter]')
  if (!chip) return
  clearFilter(chip.dataset.clearFilter ?? '')
  renderContextFilters()
  refreshFindingsView()
})
document.querySelector<HTMLDetailsElement>('#filter-menu')!.addEventListener('change', () => {
  document.querySelector<HTMLDetailsElement>('#filter-menu')!.open = false
})
document.addEventListener('keydown', (event) => {
  if (!(event.target instanceof HTMLLabelElement) || event.target.htmlFor !== 'file-input') return
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    document.querySelector<HTMLInputElement>('#file-input')!.click()
  }
})

const isTyping = (target: EventTarget | null) =>
  target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))

const inFindingsList = (target: EventTarget | null) =>
  target instanceof HTMLElement && Boolean(target.closest('#findings-list'))

document.addEventListener('keydown', (event) => {
  if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return
  if (document.querySelector('dialog[open]')) return
  const search = document.querySelector<HTMLInputElement>('#finding-search')!
  if (event.key === 'Escape') {
    if (document.activeElement === search && search.value) {
      search.value = ''
      searchQuery = ''
      refreshFindingsView()
      return
    }
    document.querySelectorAll<HTMLDetailsElement>('#filter-menu[open], #export-menu[open]').forEach((menu) => { menu.open = false })
    closeDetailSheet()
    setSidebarOpen(false)
    return
  }
  if (isTyping(event.target) || !sourceName) return
  const key = event.key.toLowerCase()
  if (event.key === '/') {
    event.preventDefault()
    search.focus()
  } else if (key === 'j' || (event.key === 'ArrowDown' && inFindingsList(event.target))) {
    event.preventDefault()
    moveSelection(1)
  } else if (key === 'k' || (event.key === 'ArrowUp' && inFindingsList(event.target))) {
    event.preventDefault()
    moveSelection(-1)
  } else if (key === 'a') {
    document.querySelector<HTMLButtonElement>('#finding-detail [data-acknowledge]')?.click()
  } else if (key === 'c') {
    const button = document.querySelector<HTMLButtonElement>('#finding-detail [data-copy-cli]')
    if (button) copyCli(button)
  }
})

renderAll()
