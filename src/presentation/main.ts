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
import { applyMetricFilter, type MetricFilter } from '../application/finding-filters'
import { renderRecommendation, serializeFindingsCsv } from './recommendation-view'
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
    <a class="brand" href="#" aria-label="FortiScope - accueil">
      <span class="brand-mark"><i data-lucide="shield-check"></i></span>
      <span>Forti<span>Scope</span></span>
    </a>
    <button class="icon-button theme-toggle" id="theme-toggle" type="button" aria-label="Activer le thème sombre" title="Activer le thème sombre"></button>
    <button class="icon-button mobile-upload" type="button" aria-label="Importer une configuration" title="Importer une configuration">
      <i data-lucide="upload"></i>
    </button>
  </header>

  <main class="workspace">
    <aside class="sidebar">
      <div>
        <p class="eyebrow">Source de l’audit</p>
        <label class="dropzone" id="dropzone" for="file-input">
          <span class="dropzone-icon"><i data-lucide="upload"></i></span>
          <strong>Déposez votre export FortiGate</strong>
          <small>ou cliquez pour choisir un fichier</small>
          <span class="file-types">.conf · .txt · .csv · 10 Mo max.</span>
        </label>
        <input id="file-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
      </div>

      <div class="source-file" id="source-file"></div>

      <details class="limitations">
        <summary>Limites de l’analyse</summary>
        <p>Les objets dynamiques, les préfixes IPv6 imbriqués et le contenu des objets référencés uniquement par un CSV ne sont pas résolus. Les horaires nommés sont comparés par identité.</p>
      </details>
    </aside>

    <section class="content">
      <div class="page-heading">
        <div>
          <p class="eyebrow">Revue de configuration</p>
          <h1>Politiques à examiner</h1>
          <div class="configuration-score" id="configuration-score" aria-label="Note globale de la configuration"></div>
        </div>
        <div class="heading-actions">
          <button class="secondary-button" id="compare-button" type="button" disabled>
            <i data-lucide="git-compare-arrows"></i> Comparer
          </button>
          ${renderExportMenu(false)}
          <input id="compare-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
          <input id="ack-import-input" type="file" accept=".json,application/json" hidden />
        </div>
      </div>

      <div class="metrics" id="metrics"></div>
      <p class="executive-summary" id="executive-summary"></p>
      <div class="import-feedback" id="import-feedback" role="alert" hidden></div>
      <div class="comparison-summary" id="comparison-summary" hidden></div>

      <section class="audit-panel">
        <div class="toolbar">
          <label class="select-field">
            <i data-lucide="filter"></i>
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
          <label class="acknowledged-toggle">
            <input id="show-acknowledged" type="checkbox" />
            Afficher les acquittés
          </label>
        </div>

        <div class="severity-tabs" id="severity-tabs" aria-label="Filtrer par sévérité"></div>
        <div class="results-layout">
          <div class="findings-list" id="findings-list"></div>
          <aside class="finding-detail" id="finding-detail"></aside>
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
  icons: { AlertTriangle, BookOpen, Check, CheckCircle2, ChevronDown, ChevronRight, Clipboard, Download, FileSearch, FileText, Filter, GitCompareArrows, Info, Moon, ShieldCheck, SquareTerminal, Sun, TableProperties, Upload, X },
})

const renderThemeToggle = () => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle')!
  const nextLabel = resolvedTheme === 'dark' ? 'Activer le thème clair' : 'Activer le thème sombre'
  button.setAttribute('aria-label', nextLabel)
  button.title = nextLabel
  button.innerHTML = `<i data-lucide="${resolvedTheme === 'dark' ? 'sun' : 'moon'}"></i>`
  renderIcons()
}

const filteredFindings = () => filterAcknowledgedFindings(audit.findings, acknowledged, sourceName, showAcknowledged).filter((finding) => {
  const matchesSeverity = activeSeverity === 'all' || finding.severity === activeSeverity
  const matchesCategory = activeCategory === 'all' || finding.category === activeCategory
  const policy = audit.policies.find((candidate) => candidate.id === finding.policyId && candidate.vdom === finding.vdom && candidate.family === finding.family)
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

const renderMetrics = () => {
  const metricFilters = [
    ['Alertes critiques', audit.stats.critical, 'critical', 'critical'],
    ['Règles permissives', audit.stats.permissive, 'warning', 'permissive'],
    ['Règles masquées', audit.stats.shadowed, 'shadowed', 'shadowed'],
  ] as const
  document.querySelector<HTMLDivElement>('#metrics')!.innerHTML = `
    <article class="metric neutral">
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
  `
}

const renderConfigurationScore = () => {
  const score = calculateConfigurationScore(audit)
  const tone = score >= 80 ? 'good' : score >= 60 ? 'warning' : 'critical'
  document.querySelector<HTMLDivElement>('#configuration-score')!.innerHTML = `
    <span>Note globale</span><strong class="${tone}">${score}<small>/100</small></strong>
  `
}

const renderTabs = () => {
  const tabs: Array<[string, string, number]> = [
    ['all', 'Toutes', audit.findings.length],
    ['critical', 'Critiques', audit.stats.critical],
    ['high', 'Élevées', audit.stats.high],
    ['medium', 'Moyennes', audit.findings.filter((finding) => finding.severity === 'medium').length],
  ]
  document.querySelector<HTMLDivElement>('#severity-tabs')!.innerHTML = tabs.map(([value, label, count]) => `
    <button type="button" data-severity="${value}" class="${activeSeverity === value ? 'active' : ''}">
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
  const policy = audit.policies.find((candidate) =>
    candidate.id === finding.policyId && candidate.vdom === finding.vdom && candidate.family === finding.family,
  )
  const riskScore = calculateRiskScore(finding, 'standard')
  const elementRisks = policy ? assessPolicyElements(policy) : []
  detail.innerHTML = `
    <div class="detail-header">
      <span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span>
      <span>Règle #${escapeHtml(finding.policyId)}</span>
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
    <button class="acknowledge-button ${isAcknowledged ? 'restore' : ''}" type="button" data-acknowledge="${escapeHtml(finding.id)}">
      <i data-lucide="check"></i>${isAcknowledged ? 'Restaurer le constat' : 'Acquitter le constat'}
    </button>
    ${policy ? `<button class="policy-doc-button" type="button" data-policy-doc="${escapeHtml(finding.id)}"><i data-lucide="book-open"></i>Créer la documentation Markdown</button>` : ''}
  `
}

const renderFindings = () => {
  const findings = filteredFindings()
  if (!findings.some((finding) => finding.id === selectedFindingId)) selectedFindingId = findings[0]?.id ?? null
  const list = document.querySelector<HTMLDivElement>('#findings-list')!
  list.innerHTML = findings.length ? findings.map((finding) => `
    <button type="button" class="finding-row ${finding.id === selectedFindingId ? 'selected' : ''}" data-finding-id="${finding.id}">
      <span class="severity-line ${finding.severity}"></span>
      <span class="finding-main">
        <span class="finding-meta"><span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span>${categoryLabels[finding.category]}</span>
        <strong>${escapeHtml(finding.policyName)}</strong>
        <small>Règle #${escapeHtml(finding.policyId)} · ${escapeHtml(finding.title)}</small>
      </span>
      <i data-lucide="chevron-right"></i>
    </button>
  `).join('') : `<div class="empty-list"><i data-lucide="check-circle-2"></i><strong>Aucun résultat</strong><span>Aucun constat ne correspond aux filtres actuels.</span></div>`
  renderDetail(findings.find((finding) => finding.id === selectedFindingId))
  renderIcons()
}

const renderAll = () => {
  renderSource()
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
  feedback.hidden = errors.length === 0
  feedback.innerHTML = errors.length
    ? `<i data-lucide="alert-triangle"></i><div><strong>Import impossible</strong>${errors.map((error) => `<p>${escapeHtml(error)}</p>`).join('')}</div>`
    : ''
  renderIcons()
}

const renderImportProgress = (message: string) => {
  const feedback = document.querySelector<HTMLDivElement>('#import-feedback')!
  feedback.hidden = false
  feedback.innerHTML = `<div>${escapeHtml(message)}</div>`
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
document.querySelector<HTMLButtonElement>('.mobile-upload')!.addEventListener('click', () => document.querySelector<HTMLInputElement>('#file-input')!.click())
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
  renderMetrics()
  renderFindings()
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
    renderFindings()
  })
}
document.querySelector<HTMLInputElement>('#show-acknowledged')!.addEventListener('change', (event) => {
  showAcknowledged = (event.target as HTMLInputElement).checked
  renderFindings()
})
document.querySelector<HTMLDivElement>('#severity-tabs')!.addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-severity]')
  if (!button) return
  activeSeverity = button.dataset.severity ?? 'all'
  renderMetrics()
  renderTabs()
  renderFindings()
})
document.querySelector<HTMLDivElement>('#metrics')!.addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-metric-filter]')
  if (!button) return
  const filters = applyMetricFilter(
    { severity: activeSeverity as Severity | 'all', category: activeCategory as Finding['category'] | 'all' },
    button.dataset.metricFilter as MetricFilter,
  )
  activeSeverity = filters.severity
  activeCategory = filters.category
  document.querySelector<HTMLSelectElement>('#category-filter')!.value = activeCategory
  renderMetrics()
  renderTabs()
  renderFindings()
})
document.querySelector<HTMLDivElement>('#findings-list')!.addEventListener('click', (event) => {
  const row = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-finding-id]')
  if (!row) return
  selectedFindingId = row.dataset.findingId ?? null
  renderFindings()
})
document.querySelector<HTMLElement>('#finding-detail')!.addEventListener('click', (event) => {
  const documentationButton = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-policy-doc]')
  if (documentationButton) {
    const finding = audit.findings.find((candidate) => candidate.id === documentationButton.dataset.policyDoc)
    const policy = finding && audit.policies.find((candidate) =>
      candidate.id === finding.policyId && candidate.vdom === finding.vdom && candidate.family === finding.family,
    )
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
  renderFindings()
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
  acknowledgementMetadata.set(key, { key, justification, reviewDate, acknowledgedAt: new Date().toISOString() })
  acknowledged = toggleAcknowledgement(acknowledged, key)
  localStorage.setItem('fortiscope-acknowledged', JSON.stringify([...acknowledged]))
  localStorage.setItem('fortiscope-acknowledgement-meta', JSON.stringify(Object.fromEntries(acknowledgementMetadata)))
  closeAcknowledgementDialog()
  renderFindings()
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
      renderFindings()
    } catch {
      renderImportErrors(['Fichier d’acquittements invalide.'])
    }
  })
})

renderAll()
