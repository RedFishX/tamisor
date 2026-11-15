import {
  AlertTriangle,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
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
  Presentation,
  Search,
  ShieldCheck,
  Square,
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
import { computeTrend, entriesForSource, recordAudit, type HistoryEntry, type HistoryStore } from '../application/audit-history'
import { categoryFamilies, prioritizeFindings, scoreWithoutCritical, summarizeFamilies, summarizeVdoms, type FindingFamily } from '../domain/overview'
import { familyLabel, renderOverview } from './overview-view'
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
import {
  addPolicies, agenda, cardsInColumn, createBoard, findingsForCard, hasCard, meetingColumnLabel, meetingColumns, moveCard,
  moveToDiscussGroup, policyForCard, policyKey, reconcileBoard, sortDiscussByPriority, syncBoard, updateCard,
  type MeetingBoard, type MeetingCard, type MeetingCardPatch, type MeetingColumn, type MeetingProposal,
} from '../domain/meeting'
import { renderMinutesMarkdown } from '../domain/meeting-minutes'
import { createMeetingStore } from '../application/meeting-store'
import { decisionKeys, renderMeetingBoard, renderMeetingFocus, type MeetingCardContext } from './meeting-view'
import { renderMinutesHtml } from './meeting-minutes-report'
import { usageBand, usageBandLabel, usageBands, type UsageBand } from '../domain/policy-usage'
import { categoryFilterLabel, categoryLabel, findingCategories, severityLabel } from '../domain/labels'
import { formatDate, formatNumber, getLocale, localeStorageKey, plural, tr, type Locale } from '../i18n'

const elementRiskLabel = (level: ElementRiskLevel): string => ({
  high: tr('Élevé', 'High'),
  medium: tr('Moyen', 'Medium'),
  low: tr('Faible', 'Low'),
})[level]

const otherLocale: Locale = getLocale() === 'fr' ? 'en' : 'fr'
document.documentElement.lang = getLocale()
document.title = tr('FortiScope · Audit de politiques FortiGate', 'FortiScope · FortiGate policy audit')

let audit: AuditResult = emptyAudit()
let sourceName = ''
let activeSeverity = 'all'
let activeCategory = 'all'
let activeVdom = 'all'
let activeInterface = 'all'
let activeSource = 'all'
let activeDestination = 'all'
let activeService = 'all'
let activeUsage: UsageBand | 'all' = 'all'
let selectedFindingId: string | null = audit.findings[0]?.id ?? null
let showAcknowledged = false
let searchQuery = ''
let activeFamily: FindingFamily | 'all' = 'all'
type View = 'overview' | 'findings' | 'meeting'
const views: View[] = ['overview', 'findings', 'meeting']
const viewHashes: Record<View, string> = { overview: '#synthese', findings: '#constats', meeting: '#reunion' }
let activeView: View = 'findings'
const compactLayout = window.matchMedia('(max-width: 900px)')
let historyStore: HistoryStore | null = null
let historyEntries: HistoryEntry[] = []
let historyUnavailable = false
try { historyStore = createIndexedDbHistoryStore() } catch { historyUnavailable = true }
let acknowledged = new Set<string>(JSON.parse(localStorage.getItem('fortiscope-acknowledged') ?? '[]'))
let acknowledgementMetadata = new Map<string, AcknowledgementRecord>(Object.entries(JSON.parse(localStorage.getItem('fortiscope-acknowledgement-meta') ?? '{}')) as Array<[string, AcknowledgementRecord]>)
let pendingAcknowledgement: { key: string, finding: Finding } | null = null
const meetingStore = createMeetingStore(localStorage)
let meetingBoard: MeetingBoard = createBoard('')
/** File de navigation du mode focus : figée à l'ouverture pour que décider une carte ne la fasse pas sauter. */
let focusQueue: string[] = []
let focusKey: string | null = null
/** Groupes de « À discuter » repliés (état d'affichage, non persistant). */
const collapsedGroups = new Set<string>()
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
  <a class="skip-link" href="#main-content">${tr('Aller au contenu', 'Skip to content')}</a>
  <header class="topbar">
    <button class="icon-button sidebar-toggle" id="sidebar-toggle" type="button" aria-controls="sidebar" aria-expanded="false" aria-label="${tr('Afficher la source et l’historique', 'Show source and history')}" title="${tr('Source et historique', 'Source and history')}">
      <i data-lucide="panel-left"></i>
    </button>
    <a class="brand" href="#" aria-label="${tr('FortiScope - accueil', 'FortiScope - home')}">
      <span class="brand-mark" aria-hidden="true"><i data-lucide="shield-check"></i></span>
      <span>Forti<span>Scope</span></span>
    </a>
    <div class="topbar-actions">
      <button class="secondary-button" id="compare-button" type="button" disabled>
        <i data-lucide="git-compare-arrows"></i> ${tr('Comparer', 'Compare')}
      </button>
      ${renderExportMenu(false)}
      <button class="icon-button locale-toggle" id="locale-toggle" type="button" lang="${otherLocale}"
        aria-label="${otherLocale === 'en' ? 'Switch to English' : 'Passer en français'}" title="${otherLocale === 'en' ? 'Switch to English' : 'Passer en français'}">${otherLocale.toUpperCase()}</button>
      <button class="icon-button theme-toggle" id="theme-toggle" type="button"></button>
    </div>
    <input id="compare-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
    <input id="ack-import-input" type="file" accept=".json,application/json" hidden />
  </header>

  <div class="workspace">
    <aside class="sidebar" id="sidebar" aria-label="${tr('Source et historique', 'Source and history')}">
      <div>
        <h2 class="eyebrow" id="source-title">${tr('Source de l’audit', 'Audit source')}</h2>
        <button class="dropzone" id="dropzone" type="button" data-choose-file aria-describedby="file-types">
          <span class="dropzone-icon" aria-hidden="true"><i data-lucide="upload"></i></span>
          <strong>${tr('Déposez votre export FortiGate', 'Drop your FortiGate export')}</strong>
          <small>${tr('ou cliquez pour choisir un fichier', 'or click to choose a file')}</small>
          <span class="file-types" id="file-types">.conf · .txt · .csv · ${tr('10 Mo max.', '10 MB max.')}</span>
        </button>
        <input id="file-input" type="file" accept=".conf,.txt,.csv,text/plain,text/csv" hidden />
      </div>

      <div class="source-file" id="source-file"></div>

      <section class="history" aria-labelledby="history-title">
        <div class="history-heading">
          <h2 class="eyebrow" id="history-title">${tr('Historique de ce fichier', 'History of this file')}</h2>
          <button class="text-button" id="history-clear" type="button" hidden>${tr('Effacer', 'Clear')}</button>
        </div>
        <div id="history-content"></div>
      </section>

      <details class="limitations">
        <summary>${tr('Limites de l’analyse', 'Analysis limits')}</summary>
        <p>${tr(
          'Les objets dynamiques, les préfixes IPv6 imbriqués et le contenu des objets référencés uniquement par un CSV ne sont pas résolus. Les horaires nommés sont comparés par identité.',
          'Dynamic objects, nested IPv6 prefixes and the content of objects referenced only by a CSV are not resolved. Named schedules are compared by name.',
        )}</p>
      </details>
    </aside>
    <div class="sidebar-scrim" id="sidebar-scrim" hidden></div>

    <main class="content" id="main-content" tabindex="-1">
      <div class="page-heading">
        <div>
          <p class="eyebrow">${tr('Revue de configuration', 'Configuration review')}</p>
          <h1>${tr('Politiques à examiner', 'Policies to review')}</h1>
        </div>
        <div class="configuration-score" id="configuration-score"></div>
      </div>

      <div class="view-tabs" role="tablist" aria-label="${tr('Vues de l’audit', 'Audit views')}">
        <button type="button" role="tab" id="tab-overview" aria-controls="view-overview" data-view="overview">${tr('Vue d’ensemble', 'Overview')}</button>
        <button type="button" role="tab" id="tab-findings" aria-controls="view-findings" data-view="findings">${tr('Constats', 'Findings')} <span id="tab-findings-count"></span></button>
        <button type="button" role="tab" id="tab-meeting" aria-controls="view-meeting" data-view="meeting">${tr('Réunion', 'Meeting')} <span id="tab-meeting-count"></span></button>
      </div>

      <div class="import-feedback" id="import-feedback" role="alert" hidden></div>
      <div class="comparison-summary" id="comparison-summary" role="status" hidden></div>

      <div class="overview" id="view-overview" role="tabpanel" aria-labelledby="tab-overview" tabindex="0" hidden></div>
      <div class="meeting" id="view-meeting" role="tabpanel" aria-labelledby="tab-meeting" hidden></div>

      <div class="view-panel" id="view-findings" role="tabpanel" aria-labelledby="tab-findings">
      <div class="metrics" id="metrics" role="group" aria-label="${tr('Indicateurs', 'Key figures')}"></div>
      <p class="executive-summary" id="executive-summary"></p>

      <section class="audit-panel" aria-label="${tr('Liste des constats', 'Findings list')}">
        <div class="toolbar">
          <label class="search-field">
            <i data-lucide="search"></i>
            <span class="sr-only">${tr('Rechercher dans les constats', 'Search findings')}</span>
            <input id="finding-search" type="search" placeholder="${tr('Rechercher une politique, une adresse, un service', 'Search a policy, an address, a service')}" autocomplete="off" aria-keyshortcuts="/" />
            <kbd aria-hidden="true">/</kbd>
          </label>
          <div class="filter-chips" id="filter-chips" role="group" aria-label="${tr('Filtres actifs', 'Active filters')}"></div>
          <details class="filter-menu" id="filter-menu">
            <summary class="chip"><i data-lucide="plus"></i> ${tr('Filtre', 'Filter')}<span class="sr-only"> : ${tr('ajouter un filtre', 'add a filter')}</span></summary>
            <div class="filter-options">
              <label class="select-field"><span>${tr('Type de constat', 'Finding type')}</span>
                <select id="category-filter">
                  <option value="all">${tr('Tous les constats', 'All findings')}</option>
                  ${findingCategories.map((category) => `<option value="${category}">${categoryFilterLabel(category)}</option>`).join('')}
                </select>
              </label>
              <label class="select-field"><span>VDOM</span><select id="vdom-filter"><option value="all">${tr('Tous', 'All')}</option></select></label>
              <label class="select-field"><span>Interface</span><select id="interface-filter"><option value="all">${tr('Toutes', 'All')}</option></select></label>
              <label class="select-field"><span>Source</span><select id="source-filter"><option value="all">${tr('Toutes', 'All')}</option></select></label>
              <label class="select-field"><span>Destination</span><select id="destination-filter"><option value="all">${tr('Toutes', 'All')}</option></select></label>
              <label class="select-field"><span>Service</span><select id="service-filter"><option value="all">${tr('Tous', 'All')}</option></select></label>
              <label class="select-field"><span>Hit count</span><select id="usage-filter"><option value="all">${tr('Tous', 'All')}</option></select></label>
            </div>
          </details>
          <label class="acknowledged-toggle">
            <input id="show-acknowledged" type="checkbox" />
            ${tr('Afficher les acquittés', 'Show acknowledged')}
          </label>
        </div>

        <div class="severity-tabs" id="severity-tabs" role="group" aria-label="${tr('Filtrer par sévérité', 'Filter by severity')}"></div>
        <div class="results-layout" id="results-layout">
          <div class="findings-list" id="findings-list" role="region" aria-label="${tr('Constats filtrés', 'Filtered findings')}" aria-keyshortcuts="J K"></div>
          <div class="detail-scrim" id="detail-scrim"></div>
          <section class="finding-detail" id="finding-detail" aria-label="${tr('Détail du constat', 'Finding details')}"></section>
        </div>
      </section>
      </div>
    </main>
  </div>
  <div class="sr-only" id="live-region" role="status" aria-live="polite" aria-atomic="true"></div>
  <dialog class="markdown-dialog" id="markdown-dialog" aria-labelledby="markdown-dialog-title">
    <div class="dialog-header">
      <div><p class="eyebrow">${tr('Documentation de policy', 'Policy documentation')}</p><h2 id="markdown-dialog-title">${tr('Markdown prêt à copier', 'Markdown ready to copy')}</h2></div>
      <button class="icon-button" id="close-markdown" type="button" aria-label="${tr('Fermer', 'Close')}" title="${tr('Fermer', 'Close')}"><i data-lucide="x"></i></button>
    </div>
    <textarea id="policy-markdown" readonly aria-label="${tr('Documentation Markdown de la policy', 'Policy documentation in Markdown')}"></textarea>
    <div class="dialog-actions">
      <span id="copy-status" role="status"></span>
      <button class="acknowledge-button" id="copy-markdown" type="button"><i data-lucide="clipboard"></i>${tr('Copier le Markdown', 'Copy the Markdown')}</button>
    </div>
  </dialog>
  <dialog class="meeting-focus" id="meeting-focus" aria-labelledby="focus-title"></dialog>
  <dialog class="markdown-dialog" id="minutes-dialog" aria-labelledby="minutes-dialog-title">
    <div class="dialog-header">
      <div><p class="eyebrow">${tr('Réunion de revue', 'Review meeting')}</p><h2 id="minutes-dialog-title">${tr('Compte rendu', 'Minutes')}</h2></div>
      <button class="icon-button" id="close-minutes" type="button" aria-label="${tr('Fermer', 'Close')}" title="${tr('Fermer', 'Close')}"><i data-lucide="x"></i></button>
    </div>
    <textarea id="minutes-markdown" readonly aria-label="${tr('Compte rendu au format Markdown', 'Minutes in Markdown')}"></textarea>
    <div class="dialog-actions">
      <span id="minutes-status" role="status"></span>
      <button class="secondary-button" id="download-minutes-html" type="button"><i data-lucide="file-text"></i>${tr('HTML imprimable', 'Printable HTML')}</button>
      <button class="secondary-button" id="download-minutes-md" type="button"><i data-lucide="download"></i>${tr('Télécharger .md', 'Download .md')}</button>
      <button class="acknowledge-button" id="copy-minutes" type="button"><i data-lucide="clipboard"></i>${tr('Copier', 'Copy')}</button>
    </div>
  </dialog>
  <dialog class="confirm-dialog" id="confirm-dialog" aria-labelledby="confirm-title" aria-describedby="confirm-message">
    <form method="dialog">
      <div class="dialog-header"><div><p class="eyebrow" id="confirm-eyebrow"></p><h2 id="confirm-title"></h2></div></div>
      <p class="confirm-message" id="confirm-message"></p>
      <div class="dialog-actions">
        <button class="secondary-button" id="confirm-cancel" type="submit" value="cancel">${tr('Annuler', 'Cancel')}</button>
        <button class="acknowledge-button" id="confirm-accept" type="submit" value="confirm"></button>
      </div>
    </form>
  </dialog>
  <dialog class="acknowledgement-dialog" id="acknowledgement-dialog" aria-labelledby="acknowledgement-dialog-title" aria-describedby="acknowledgement-title">
    <div class="dialog-header">
      <div><p class="eyebrow">${tr('Revue du constat', 'Finding review')}</p><h2 id="acknowledgement-dialog-title">${tr('Acquitter ce constat', 'Acknowledge this finding')}</h2></div>
      <button class="icon-button" id="close-acknowledgement" type="button" aria-label="${tr('Annuler', 'Cancel')}" title="${tr('Annuler', 'Cancel')}"><i data-lucide="x"></i></button>
    </div>
    <form id="acknowledgement-form">
      <p id="acknowledgement-title" class="acknowledgement-title"></p>
      <label class="dialog-field">${tr('Justification de l’acquittement', 'Reason for acknowledging')}<textarea id="acknowledgement-justification" required rows="4" autofocus placeholder="${tr('Expliquez pourquoi ce constat est accepté temporairement ou définitivement.', 'Explain why this finding is accepted, temporarily or permanently.')}"></textarea></label>
      <label class="dialog-field">${tr('Date de révision', 'Review date')}<input id="acknowledgement-review-date" type="date" required /></label>
      <div class="dialog-actions">
        <button class="secondary-button" id="cancel-acknowledgement" type="button">${tr('Annuler', 'Cancel')}</button>
        <button class="acknowledge-button" type="submit"><i data-lucide="check"></i>${tr('Acquitter', 'Acknowledge')}</button>
      </div>
    </form>
  </dialog>
`

interface ConfirmationOptions {
  eyebrow: string
  title: string
  message: string
  confirmLabel: string
  /** `null` : simple information, sans bouton d'annulation. */
  cancelLabel?: string | null
  tone?: 'danger' | 'neutral'
}

/** Remplace `window.confirm`/`window.alert` par une boîte de dialogue aux couleurs de l'application. */
const askConfirmation = (options: ConfirmationOptions): Promise<boolean> => new Promise((resolve) => {
  const dialog = document.querySelector<HTMLDialogElement>('#confirm-dialog')!
  const cancel = document.querySelector<HTMLButtonElement>('#confirm-cancel')!
  const accept = document.querySelector<HTMLButtonElement>('#confirm-accept')!
  document.querySelector<HTMLElement>('#confirm-eyebrow')!.textContent = options.eyebrow
  document.querySelector<HTMLElement>('#confirm-title')!.textContent = options.title
  document.querySelector<HTMLElement>('#confirm-message')!.textContent = options.message
  accept.textContent = options.confirmLabel
  accept.classList.toggle('danger', options.tone === 'danger')
  cancel.hidden = options.cancelLabel === null
  cancel.textContent = options.cancelLabel ?? tr('Annuler', 'Cancel')
  dialog.returnValue = ''
  dialog.addEventListener('close', () => resolve(dialog.returnValue === 'confirm'), { once: true })
  dialog.showModal()
  // Action destructrice : le focus initial reste sur « Annuler ».
  ;(options.tone === 'danger' && !cancel.hidden ? cancel : accept).focus()
})

const renderIcons = () => createIcons({
  icons: { AlertTriangle, BookOpen, Check, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, Clipboard, Download, FileSearch, FileText, Filter, GitCompareArrows, Info, Moon, PanelLeft, Plus, Presentation, Search, ShieldCheck, Square, SquareTerminal, Sun, TableProperties, Upload, X },
})

const renderThemeToggle = () => {
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle')!
  const nextLabel = resolvedTheme === 'dark' ? tr('Activer le thème clair', 'Switch to light theme') : tr('Activer le thème sombre', 'Switch to dark theme')
  button.setAttribute('aria-label', nextLabel)
  button.title = nextLabel
  button.innerHTML = `<i data-lucide="${resolvedTheme === 'dark' ? 'sun' : 'moon'}" aria-hidden="true"></i>`
  renderIcons()
}

const policyForFinding = (finding: Finding) => audit.policies.find((candidate) =>
  candidate.id === finding.policyId && candidate.vdom === finding.vdom && candidate.family === finding.family,
)

const filteredFindings = (options: { ignoreSeverity?: boolean } = {}) => filterAcknowledgedFindings(audit.findings, acknowledged, sourceName, showAcknowledged).filter((finding) => {
  const matchesSeverity = options.ignoreSeverity || activeSeverity === 'all' || finding.severity === activeSeverity
  const matchesCategory = (activeCategory === 'all' || finding.category === activeCategory) &&
    (activeFamily === 'all' || categoryFamilies[finding.category] === activeFamily)
  const policy = policyForFinding(finding)
  if (!matchesFindingQuery(finding, policy, searchQuery)) return false
  const matchesVdom = activeVdom === 'all' || (policy?.vdom ?? 'global') === activeVdom
  const matchesInterface = activeInterface === 'all' || [...(policy?.srcintf ?? []), ...(policy?.dstintf ?? [])].includes(activeInterface)
  const matchesSource = activeSource === 'all' || (policy?.srcaddr ?? []).includes(activeSource)
  const matchesDestination = activeDestination === 'all' || (policy?.dstaddr ?? []).includes(activeDestination)
  const matchesService = activeService === 'all' || [...(policy?.service ?? []), ...(policy?.internetServices ?? [])].includes(activeService)
  const matchesUsage = activeUsage === 'all' || usageBand(policy) === activeUsage
  return matchesSeverity && matchesCategory && matchesVdom && matchesInterface && matchesSource && matchesDestination && matchesService && matchesUsage
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
    if (select) select.innerHTML = options(values, selected, id === 'vdom-filter' || id === 'service-filter' ? tr('Tous', 'All') : tr('Toutes', 'All'))
  }
  document.querySelector<HTMLSelectElement>('#category-filter')!.value = activeCategory
  renderUsageFilter()
  renderFilterChips()
}

/** Tranches de hit count, avec le nombre de policies concernées ; désactivé si l'import n'en fournit pas (export CLI). */
const renderUsageFilter = () => {
  // Les tranches vides ne sont pas proposées.
  const select = document.querySelector<HTMLSelectElement>('#usage-filter')!
  const counts = new Map<UsageBand, number>()
  for (const policy of audit.policies) counts.set(usageBand(policy), (counts.get(usageBand(policy)) ?? 0) + 1)
  const available = audit.policies.length > 0 && (counts.get('unknown') ?? 0) < audit.policies.length
  select.disabled = !available
  select.title = available ? '' : tr('Hit count absent : importez un export CSV qui contient la colonne « Hit Count ».', 'No hit count: import a CSV export that has a “Hit Count” column.')
  select.innerHTML = `<option value="all">${available ? tr('Tous', 'All') : tr('Non disponible (export CLI)', 'Not available (CLI export)')}</option>` + (available
    ? usageBands.filter((band) => counts.get(band) || band === activeUsage).map((band) => `<option value="${band}"${band === activeUsage ? ' selected' : ''}>${usageBandLabel(band)} · ${counts.get(band) ?? 0}</option>`).join('')
    : '')
}

const categoryOptionLabel = (value: string) =>
  document.querySelector<HTMLOptionElement>(`#category-filter option[value="${CSS.escape(value)}"]`)?.textContent ?? value

const renderFilterChips = () => {
  const chips: Array<[string, string, string]> = [
    ['family', tr('Famille', 'Family'), activeFamily === 'all' ? '' : familyLabel(activeFamily)],
    ['category', 'Type', activeCategory === 'all' ? '' : categoryOptionLabel(activeCategory)],
    ['vdom', 'VDOM', activeVdom === 'all' ? '' : activeVdom],
    ['interface', 'Interface', activeInterface === 'all' ? '' : activeInterface],
    ['source', 'Source', activeSource === 'all' ? '' : activeSource],
    ['destination', 'Destination', activeDestination === 'all' ? '' : activeDestination],
    ['service', 'Service', activeService === 'all' ? '' : activeService],
    ['usage', 'Hit count', activeUsage === 'all' ? '' : usageBandLabel(activeUsage)],
  ]
  document.querySelector<HTMLDivElement>('#filter-chips')!.innerHTML = chips
    .filter(([, , value]) => value)
    .map(([key, label, value]) => `
      <button class="chip" type="button" data-clear-filter="${key}" aria-label="${escapeHtml(tr(`Retirer le filtre ${label} : ${value}`, `Remove filter ${label}: ${value}`))}">
        ${escapeHtml(label)} <b>${escapeHtml(value)}</b><i data-lucide="x" aria-hidden="true"></i>
      </button>
    `).join('')
}

const clearFilter = (key: string) => {
  if (key === 'family') activeFamily = 'all'
  if (key === 'category') activeCategory = 'all'
  if (key === 'vdom') activeVdom = 'all'
  if (key === 'interface') activeInterface = 'all'
  if (key === 'source') activeSource = 'all'
  if (key === 'destination') activeDestination = 'all'
  if (key === 'service') activeService = 'all'
  if (key === 'usage') activeUsage = 'all'
}

const renderSource = () => {
  document.querySelector<HTMLButtonElement>('#compare-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#html-report-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#cli-export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#ack-export-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#ack-import-button')!.disabled = !sourceName
  document.querySelector<HTMLButtonElement>('#minutes-export-button')!.disabled = !sourceName || !meetingBoard.cards.length
  if (!sourceName) {
    document.querySelector<HTMLDivElement>('#source-file')!.innerHTML = `
      <div class="source-icon" aria-hidden="true"><i data-lucide="file-search"></i></div>
      <div><span>${tr('En attente', 'Waiting')}</span><strong>${tr('Aucune configuration', 'No configuration')}</strong></div>
    `
    return
  }
  document.querySelector<HTMLDivElement>('#source-file')!.innerHTML = `
    <div class="source-icon" aria-hidden="true"><i data-lucide="file-search"></i></div>
    <div><span>${tr('Configuration analysée', 'Analysed configuration')}</span><strong title="${escapeHtml(sourceName)}">${escapeHtml(sourceName)}</strong></div>
    <span class="source-status" aria-hidden="true"><i data-lucide="check-circle-2"></i></span>
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
    [tr('Critiques', 'Critical'), audit.stats.critical, audit.stats.critical > 0 ? 'critical' : '', 'critical'],
    [tr('Permissives', 'Permissive'), audit.stats.permissive, '', 'permissive'],
    [tr('Masquées', 'Shadowed'), audit.stats.shadowed, '', 'shadowed'],
  ] as const
  document.querySelector<HTMLDivElement>('#metrics')!.innerHTML = `
    <article class="metric">
      <span>${tr('Politiques actives', 'Active policies')}</span>
      <strong>${audit.stats.activePolicies}</strong>
    </article>
    ${metricFilters.map(([label, value, tone, filter]) => {
      const isActive = (filter === 'critical' && activeSeverity === 'critical' && activeCategory === 'all') ||
        (filter !== 'critical' && activeSeverity === 'all' && activeCategory === filter)
      return `
        <button class="metric ${tone} ${isActive ? 'active' : ''}" type="button" data-metric-filter="${filter}" aria-pressed="${isActive}"
          title="${tr(`Filtrer : ${label.toLowerCase()}`, `Filter: ${label.toLowerCase()}`)}">
          <span>${label}</span>
          <strong>${value}</strong>
        </button>
      `
    }).join('')}
    <button class="metric ${showAcknowledged ? 'active' : ''}" type="button" data-metric-acknowledged aria-pressed="${showAcknowledged}" title="${tr('Afficher ou masquer les constats acquittés', 'Show or hide acknowledged findings')}">
      <span>${tr('Acquittés', 'Acknowledged')}</span>
      <strong>${acknowledgedCount()}</strong>
    </button>
  `
}

const formatShortDate = (iso: string) => Number.isNaN(new Date(iso).getTime()) ? '' : formatDate(iso, { day: 'numeric', month: 'short' })

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
    ? tr(`${trend.scoreDelta > 0 ? '+' : ''}${trend.scoreDelta} depuis le ${formatShortDate(trend.previous.analyzedAt)}`, `${trend.scoreDelta > 0 ? '+' : ''}${trend.scoreDelta} since ${formatShortDate(trend.previous.analyzedAt)}`)
    : ''
  container.className = `configuration-score ${tone}`
  container.innerHTML = `<span class="sr-only">${tr('Note globale de la configuration :', 'Overall configuration score:')} </span><strong>${score}<small>/100</small></strong>${delta ? `<span>${escapeHtml(delta)}</span>` : ''}`
}

const renderTabs = () => {
  const visible = filteredFindings({ ignoreSeverity: true })
  const count = (severity: Severity) => visible.filter((finding) => finding.severity === severity).length
  const tabs: Array<[string, string, number]> = [
    ['all', tr('Tous', 'All'), visible.length],
    ['critical', tr('Critiques', 'Critical'), count('critical')],
    ['high', tr('Élevés', 'High'), count('high')],
    ['medium', tr('Moyens', 'Medium'), count('medium')],
    ['low', tr('Faibles', 'Low'), count('low')],
  ]
  document.querySelector<HTMLDivElement>('#severity-tabs')!.innerHTML = tabs.map(([value, label, count]) => `
    <button type="button" data-severity="${value}" class="${activeSeverity === value ? 'active' : ''}" aria-pressed="${activeSeverity === value}">
      ${label}<span><span class="sr-only">, </span>${count}</span>
    </button>
  `).join('')
}

const renderDetail = (finding: Finding | undefined) => {
  const detail = document.querySelector<HTMLElement>('#finding-detail')!
  if (!finding) {
    detail.innerHTML = `<div class="empty-detail"><i data-lucide="check-circle-2" aria-hidden="true"></i><strong>${tr('Aucun constat', 'No finding')}</strong><span>${tr('Modifiez les filtres ou chargez une autre configuration.', 'Change the filters or load another configuration.')}</span></div>`
    return
  }
  const findingKey = acknowledgementKey(sourceName, finding)
  const isAcknowledged = acknowledged.has(findingKey)
  const acknowledgement = acknowledgementMetadata.get(findingKey)
  const policy = policyForFinding(finding)
  const riskScore = calculateRiskScore(finding, 'standard')
  const elementRisks = policy ? assessPolicyElements(policy) : []
  detail.innerHTML = `
    <button class="icon-button detail-close" type="button" data-close-detail aria-label="${tr('Fermer le détail', 'Close details')}" title="${tr('Fermer', 'Close')}"><i data-lucide="x"></i></button>
    <div class="detail-header">
      <span class="severity-badge ${finding.severity}">${severityLabel(finding.severity)}</span>
      <span>${escapeHtml(categoryLabel(finding.category))} · ${tr('règle', 'rule')} #${escapeHtml(finding.policyId)} · seq ${finding.order}</span>
      <strong class="risk-score">${tr('Risque', 'Risk')} ${riskScore}/100</strong>
    </div>
    <h2 id="finding-detail-title">${escapeHtml(finding.title)}</h2>
    <p class="detail-policy">${escapeHtml(finding.policyName)}</p>
    ${acknowledgement ? `<p class="acknowledgement-note">${tr('Acquitté :', 'Acknowledged:')} ${escapeHtml(acknowledgement.justification)} · ${tr('Revue :', 'Review:')} ${escapeHtml(acknowledgement.reviewDate || tr('non planifiée', 'not scheduled'))}</p>` : ''}
    ${policy?.hitCount !== undefined || policy?.lastUsed ? `
      <div class="usage-stats">
        ${policy.hitCount !== undefined ? `<span><strong>${formatNumber(policy.hitCount)}</strong> ${plural(policy.hitCount, ['correspondance', 'correspondances'], ['hit', 'hits'])}</span>` : ''}
        ${policy.lastUsed ? `<span>${tr('Dernière utilisation', 'Last used')} <strong>${escapeHtml(policy.lastUsed)}</strong></span>` : ''}
      </div>
    ` : ''}
    <p class="detail-copy">${escapeHtml(finding.detail)}</p>
    ${elementRisks.length ? `
      <section class="policy-risk-matrix" aria-labelledby="risk-matrix-title">
        <h3 id="risk-matrix-title">${tr('Niveau de risque par élément', 'Risk level per element')}</h3>
        ${elementRisks.map((element) => `
          <article class="element-risk">
            <div><strong>${escapeHtml(element.label)}</strong><span class="element-risk-badge ${element.level}">${elementRiskLabel(element.level)}</span></div>
            <code>${escapeHtml(element.value)}</code>
            <p>${escapeHtml(element.reason)}</p>
          </article>
        `).join('')}
      </section>
    ` : ''}
    <div class="evidence">
      <span>${tr('Éléments détectés', 'Detected items')}</span>
      ${finding.evidence.map((item) => `<p><i data-lucide="alert-triangle" aria-hidden="true"></i>${escapeHtml(item)}</p>`).join('')}
    </div>
    ${renderRecommendation(finding.recommendation)}
    ${renderCompliance(finding)}
    <div class="detail-actions">
      <button class="acknowledge-button ${isAcknowledged ? 'restore' : ''}" type="button" data-acknowledge="${escapeHtml(finding.id)}" aria-keyshortcuts="A">
        <i data-lucide="check"></i>${isAcknowledged ? tr('Restaurer le constat', 'Restore the finding') : tr('Acquitter le constat', 'Acknowledge the finding')}<kbd aria-hidden="true">A</kbd>
      </button>
      ${policy ? `<button class="policy-doc-button" type="button" data-policy-doc="${escapeHtml(finding.id)}"><i data-lucide="book-open"></i>${tr('Documentation Markdown', 'Markdown documentation')}</button>` : ''}
      ${hasCard(meetingBoard, policyKey(finding))
        ? `<button class="policy-doc-button" type="button" data-meeting-open="${escapeHtml(policyKey(finding))}"><i data-lucide="presentation"></i>${tr('Voir en réunion', 'View in meeting')}</button>`
        : ''}
    </div>
  `
}

const hasActiveFilters = () => Boolean(searchQuery.trim()) || [activeSeverity, activeCategory, activeFamily, activeVdom, activeInterface, activeSource, activeDestination, activeService, activeUsage].some((value) => value !== 'all')

const renderNoResult = () => hasActiveFilters()
  ? `<div class="empty-list"><i data-lucide="filter" aria-hidden="true"></i><strong>${tr('Aucun constat pour ces filtres', 'No finding for these filters')}</strong><span>${tr('Élargissez la recherche ou retirez un filtre.', 'Broaden the search or remove a filter.')}</span><button class="secondary-button" type="button" data-reset-filters>${tr('Retirer tous les filtres', 'Remove all filters')}</button></div>`
  : `<div class="empty-list"><i data-lucide="check-circle-2" aria-hidden="true"></i><strong>${tr('Aucun constat', 'No finding')}</strong><span>${tr('Aucune règle ne présente de problème détecté par l’analyse.', 'The analysis found no issue in any rule.')}</span></div>`

const renderFindings = () => {
  const findings = filteredFindings()
  if (!findings.some((finding) => finding.id === selectedFindingId)) selectedFindingId = findings[0]?.id ?? null
  const list = document.querySelector<HTMLDivElement>('#findings-list')!
  if (!sourceName) {
    list.innerHTML = `<div class="empty-list"><i data-lucide="upload" aria-hidden="true"></i><strong>${tr('Aucune configuration analysée', 'No configuration analysed')}</strong><span>${tr('Importez un export FortiGate (.conf, .txt ou .csv). L’analyse se fait dans votre navigateur, aucun fichier n’est envoyé.', 'Import a FortiGate export (.conf, .txt or .csv). The analysis runs in your browser; no file is uploaded.')}</span><button class="secondary-button" type="button" data-choose-file><i data-lucide="upload"></i> ${tr('Choisir un fichier', 'Choose a file')}</button></div>`
    document.querySelector<HTMLElement>('#finding-detail')!.innerHTML = `<div class="empty-detail"><i data-lucide="file-search" aria-hidden="true"></i><span>${tr('Le détail de chaque constat et son plan de remédiation s’afficheront ici.', 'Each finding’s details and remediation plan will appear here.')}</span></div>`
    renderIcons()
    return
  }
  list.innerHTML = findings.length ? findings.map((finding) => `
    <button type="button" class="finding-row ${finding.id === selectedFindingId ? 'selected' : ''}" data-finding-id="${finding.id}"${finding.id === selectedFindingId ? ' aria-current="true"' : ''} aria-controls="finding-detail">
      <span class="severity-line ${finding.severity}"></span>
      <span class="finding-main">
        <span class="finding-meta"><span class="severity-badge ${finding.severity}">${severityLabel(finding.severity)}</span>${categoryLabel(finding.category)}</span>
        <strong>${escapeHtml(finding.policyName)}</strong>
        <small>${tr('Règle', 'Rule')} #${escapeHtml(finding.policyId)} · ${escapeHtml(finding.title)}</small>
      </span>
      <i data-lucide="chevron-right" aria-hidden="true"></i>
    </button>
  `).join('') : renderNoResult()
  renderDetail(findings.find((finding) => finding.id === selectedFindingId))
  renderIcons()
}

const renderHistoryPanel = () => {
  document.querySelector<HTMLDivElement>('#history-content')!.innerHTML = sourceName
    ? renderHistory(historyEntries, sourceName, historyUnavailable)
    : `<p class="history-empty">${tr('Importez une configuration pour suivre sa note dans le temps.', 'Import a configuration to track its score over time.')}</p>`
  document.querySelector<HTMLButtonElement>('#history-clear')!.hidden = !historyEntries.length
}

/** Enregistre l'audit dans l'historique ; une réanalyse après changement de langue relit seulement l'historique. */
const refreshHistory = async (restored = false) => {
  if (!historyStore) return
  try {
    historyEntries = restored ? await historyStore.list() : await recordAudit(historyStore, audit, sourceName)
    historyUnavailable = false
  } catch {
    historyUnavailable = true
  }
  renderHistoryPanel()
  renderConfigurationScore()
  renderOverviewPanel()
}

const openFindings = () => sourceName ? filterAcknowledgedFindings(audit.findings, acknowledged, sourceName, false) : []

const renderOverviewPanel = () => {
  const panel = document.querySelector<HTMLDivElement>('#view-overview')!
  const open = openFindings()
  document.querySelector<HTMLSpanElement>('#tab-findings-count')!.textContent = sourceName ? String(open.length) : ''
  document.querySelector<HTMLButtonElement>('#tab-overview')!.disabled = !sourceName
  if (!sourceName) {
    panel.innerHTML = ''
    return
  }
  const score = calculateConfigurationScore(audit)
  const trend = computeTrend(historyEntries, sourceName)
  panel.innerHTML = renderOverview({
    score,
    tone: score >= 80 ? 'good' : score >= 60 ? 'warning' : 'critical',
    scoreDelta: trend?.previous ? trend.scoreDelta : undefined,
    previousDate: trend?.previous?.analyzedAt,
    scoreAfterCritical: scoreWithoutCritical(audit),
    criticalCount: audit.stats.critical,
    history: entriesForSource(historyEntries, sourceName),
    families: summarizeFamilies(open),
    vdoms: summarizeVdoms(audit.policies, open),
    priorities: prioritizeFindings(open, 3),
    openFindings: open.length,
  })
}

const viewFromHash = (): View | null => views.find((view) => viewHashes[view] === location.hash) ?? null

const setView = (view: View, updateHash = true) => {
  activeView = sourceName ? view : 'findings'
  document.querySelector<HTMLElement>('.content')!.dataset.view = activeView
  document.querySelector<HTMLDivElement>('#view-overview')!.hidden = activeView !== 'overview'
  document.querySelector<HTMLDivElement>('#view-findings')!.hidden = activeView !== 'findings'
  document.querySelector<HTMLDivElement>('#view-meeting')!.hidden = activeView !== 'meeting'
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.view-tabs [data-view]')) {
    const selected = tab.dataset.view === activeView
    tab.setAttribute('aria-selected', String(selected))
    tab.tabIndex = selected ? 0 : -1
  }
  const hash = viewHashes[activeView]
  if (updateHash && sourceName && location.hash !== hash) history.replaceState(null, '', hash)
}

const renderAll = () => {
  renderSource()
  renderOverviewPanel()
  renderMeetingPanel()
  renderHistoryPanel()
  renderConfigurationScore()
  renderContextFilters()
  renderMetrics()
  renderTabs()
  renderFindings()
  document.querySelector<HTMLParagraphElement>('#executive-summary')!.textContent = sourceName
    ? createExecutiveSummary(audit)
    : tr('Importez une configuration pour démarrer l’audit.', 'Import a configuration to start the audit.')
  renderIcons()
  renderThemeToggle()
}

const renderImportErrors = (errors: string[]) => {
  const feedback = document.querySelector<HTMLDivElement>('#import-feedback')!
  feedback.classList.remove('is-progress')
  feedback.hidden = errors.length === 0
  feedback.innerHTML = errors.length
    ? `<i data-lucide="alert-triangle" aria-hidden="true"></i><div><strong>${tr('Import impossible', 'Import failed')}</strong>${errors.map((error) => `<p>${escapeHtml(error)}</p>`).join('')}</div>`
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
  worker.postMessage({ content, fileName, locale: getLocale() })
})

/** Dernier fichier importé, gardé en mémoire pour le réanalyser après un changement de langue. */
let lastImport: { content: string, name: string } | null = null

const loadConfiguration = async (content: string, name: string, options: { restored?: boolean } = {}) => {
  const nextAudit = await analyzeWithWorker(content, name)
  renderImportErrors(nextAudit.importErrors)
  if (!nextAudit.policies.length) {
    return
  }
  lastImport = { content, name }
  audit = nextAudit
  sourceName = name
  meetingBoard = reconcileBoard(meetingStore.load(name) ?? createBoard(name), audit)
  syncMeeting()
  selectedFindingId = audit.findings[0]?.id ?? null
  renderAll()
  setView(viewFromHash() ?? 'overview')
  document.querySelector<HTMLDivElement>('#import-feedback')!.hidden = !nextAudit.importErrors.length
  announce(tr(
    `Analyse terminée : ${audit.stats.activePolicies} politiques actives, ${audit.findings.length} constats.`,
    `Analysis complete: ${audit.stats.activePolicies} active policies, ${audit.findings.length} findings.`,
  ))
  await refreshHistory(options.restored)
}

const handleFile = async (file?: File) => {
  if (!file) return
  if (file.size > 10 * 1024 * 1024) {
    const size = (file.size / 1024 / 1024).toLocaleString(getLocale() === 'en' ? 'en-GB' : 'fr-FR', { maximumFractionDigits: 1 })
    void askConfirmation({
      eyebrow: tr('Import impossible', 'Import failed'),
      title: tr('Fichier trop volumineux', 'File too large'),
      message: tr(
        `${file.name} pèse ${size} Mo, au-delà de la limite de 10 Mo. Exportez uniquement la section « config firewall policy » ou le VDOM concerné.`,
        `${file.name} is ${size} MB, above the 10 MB limit. Export only the “config firewall policy” section or the relevant VDOM.`,
      ),
      confirmLabel: tr('Compris', 'OK'),
      cancelLabel: null,
    })
    return
  }
  await loadConfiguration(await file.text(), file.name)
}

document.querySelector<HTMLInputElement>('#file-input')!.addEventListener('change', (event) => {
  void handleFile((event.target as HTMLInputElement).files?.[0])
})
document.querySelector<HTMLButtonElement>('#history-clear')!.addEventListener('click', async () => {
  if (!historyStore || !await askConfirmation({
    eyebrow: tr('Historique local', 'Local history'),
    title: tr('Effacer l’historique ?', 'Clear the history?'),
    message: tr(
      'Les notes et compteurs de tous les audits enregistrés dans ce navigateur seront supprimés. Les configurations elles-mêmes ne sont jamais stockées.',
      'The scores and counters of every audit recorded in this browser will be deleted. Configurations themselves are never stored.',
    ),
    confirmLabel: tr('Effacer l’historique', 'Clear the history'),
    tone: 'danger',
  })) return
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
      `<li>${tr('Règle', 'Rule')} #${escapeHtml(after.id)}${tr(' : ', ': ')}${escapeHtml(changedFields.join(', ') || tr('champs non détaillés', 'fields not detailed'))}</li>`,
    ).join('')
    const counted = (count: number, fr: [string, string], en: [string, string]) => `${count} ${plural(count, fr, en)}`
    summary.innerHTML = `<strong>${tr('Comparaison avec', 'Comparison with')} ${escapeHtml(file.name)}</strong>`
      + `<span>${counted(comparison.added.length, ['ajoutée', 'ajoutées'], ['added', 'added'])}</span>`
      + `<span>${counted(comparison.modified.length, ['modifiée', 'modifiées'], ['modified', 'modified'])}</span>`
      + `<span>${counted(comparison.removed.length, ['supprimée', 'supprimées'], ['removed', 'removed'])}</span>`
      + `${modifications ? `<ul>${modifications}</ul>` : ''}`
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
  ['usage-filter', (value) => { activeUsage = value as UsageBand | 'all' }],
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
    for (const key of ['family', 'category', 'vdom', 'interface', 'source', 'destination', 'service', 'usage']) clearFilter(key)
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
  const meetingOpen = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-meeting-open]')
  if (meetingOpen?.dataset.meetingOpen) {
    setView('meeting')
    openFocus(meetingOpen.dataset.meetingOpen)
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
    document.querySelector<HTMLSpanElement>('#copy-status')!.textContent = tr('Markdown copié', 'Markdown copied')
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

const dropzone = document.querySelector<HTMLButtonElement>('#dropzone')!
// Les boutons « choisir un fichier » (barre latérale, état vide) ouvrent le sélecteur de fichier natif.
document.addEventListener('click', (event) => {
  if ((event.target as HTMLElement).closest('[data-choose-file]')) document.querySelector<HTMLInputElement>('#file-input')!.click()
})
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
  link.download = tr('audit-fortigate.csv', 'fortigate-audit.csv')
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
  downloadText(renderHtmlReport(audit, sourceName), tr('rapport-fortiscope.html', 'fortiscope-report.html'), 'text/html;charset=utf-8')
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})
document.querySelector<HTMLButtonElement>('#cli-export-button')!.addEventListener('click', () => {
  downloadText(serializeRecommendationsCli(audit.findings), tr('remediations-fortigate.cli', 'fortigate-remediations.cli'), 'text/plain;charset=utf-8')
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
})
document.querySelector<HTMLButtonElement>('#ack-export-button')!.addEventListener('click', () => {
  downloadText(serializeAcknowledgements([...acknowledgementMetadata.values()]), tr('acquittements-fortiscope.json', 'fortiscope-acknowledgements.json'), 'application/json;charset=utf-8')
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
      renderImportErrors([tr('Fichier d’acquittements invalide.', 'Invalid acknowledgements file.')])
    }
  })
})

/** Annonce un message aux lecteurs d'écran via la zone `aria-live` (sans déplacer le focus). */
let announceTimer: number | undefined
const announce = (message: string, delay = 0) => {
  window.clearTimeout(announceTimer)
  announceTimer = window.setTimeout(() => {
    const region = document.querySelector<HTMLDivElement>('#live-region')!
    // Vider puis remplir garantit la relecture d'un message identique.
    region.textContent = ''
    window.setTimeout(() => { region.textContent = message }, 50)
  }, delay)
}

const refreshFindingsView = () => {
  if (syncMeeting()) renderMeetingPanel()
  renderOverviewPanel()
  renderFilterChips()
  renderMetrics()
  renderTabs()
  renderFindings()
  if (sourceName && activeView === 'findings') {
    const count = filteredFindings().length
    announce(`${count} ${plural(count, ['constat affiché', 'constats affichés'], ['finding shown', 'findings shown'])}`, 400)
  }
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
    button.textContent = tr('Copié', 'Copied')
    announce(tr('Commande CLI copiée', 'CLI command copied'))
    window.setTimeout(() => { button.textContent = tr('Copier', 'Copy') }, 2000)
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
  if (isTyping(event.target) || !sourceName || activeView !== 'findings') return
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

document.querySelector<HTMLElement>('.view-tabs')!.addEventListener('click', (event) => {
  const tab = (event.target as HTMLElement).closest<HTMLButtonElement>('[data-view]')
  if (tab && !tab.disabled) setView(tab.dataset.view as View)
})
document.querySelector<HTMLElement>('.view-tabs')!.addEventListener('keydown', (event) => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const enabled = views.filter((view) => !document.querySelector<HTMLButtonElement>(`.view-tabs [data-view="${view}"]`)?.disabled)
  const index = enabled.indexOf(activeView)
  const next = event.key === 'Home' ? enabled[0]
    : event.key === 'End' ? enabled[enabled.length - 1]
      : enabled[(index + (event.key === 'ArrowRight' ? 1 : enabled.length - 1)) % enabled.length] ?? activeView
  setView(next)
  document.querySelector<HTMLButtonElement>(`.view-tabs [data-view="${next}"]`)?.focus()
})
window.addEventListener('hashchange', () => {
  const view = viewFromHash()
  if (view) setView(view, false)
})

const showFindingsWith = (apply: () => void) => {
  for (const key of ['family', 'category', 'vdom', 'interface', 'source', 'destination', 'service', 'usage']) clearFilter(key)
  activeSeverity = 'all'
  searchQuery = ''
  document.querySelector<HTMLInputElement>('#finding-search')!.value = ''
  apply()
  renderContextFilters()
  refreshFindingsView()
  setView('findings')
  window.scrollTo({ top: 0 })
}

document.querySelector<HTMLDivElement>('#view-overview')!.addEventListener('click', (event) => {
  const target = event.target as HTMLElement
  const family = target.closest<HTMLButtonElement>('[data-family]')
  const vdom = target.closest<HTMLButtonElement>('[data-vdom]')
  const priority = target.closest<HTMLButtonElement>('[data-priority-id]')
  if (family) showFindingsWith(() => { activeFamily = family.dataset.family as FindingFamily })
  else if (vdom) showFindingsWith(() => { activeVdom = vdom.dataset.vdom ?? 'all' })
  else if (priority) showFindingsWith(() => { selectedFindingId = priority.dataset.priorityId ?? null })
  else if (target.closest('[data-show-findings]')) showFindingsWith(() => {})
})

/* ---------- Mode réunion ---------- */
const meetingPanel = document.querySelector<HTMLDivElement>('#view-meeting')!
const focusDialog = document.querySelector<HTMLDialogElement>('#meeting-focus')!
const minutesDialog = document.querySelector<HTMLDialogElement>('#minutes-dialog')!

const cardContext = (card: MeetingCard): MeetingCardContext => ({ policy: policyForCard(audit, card), findings: findingsForCard(audit, card) })
const boardOrder = () => meetingColumns.flatMap((column) => cardsInColumn(meetingBoard, column)).map((card) => card.policyKey)
const meetingRunning = () => Boolean(meetingBoard.startedAt && !meetingBoard.endedAt)

let meetingSaveTimer: number | undefined
const persistMeeting = (immediate = true) => {
  window.clearTimeout(meetingSaveTimer)
  if (immediate) meetingStore.save(meetingBoard)
  else meetingSaveTimer = window.setTimeout(() => meetingStore.save(meetingBoard), 300)
}

const commitMeeting = (next: MeetingBoard) => {
  meetingBoard = next
  persistMeeting()
  renderMeetingPanel()
  if (activeView === 'findings') renderFindings()
}

/** Aligne le tableau sur les constats ouverts (au chargement et après un acquittement) ; n'enregistre que s'il a changé. */
const syncMeeting = (): boolean => {
  if (!sourceName) return false
  const next = syncBoard(meetingBoard, openFindings(), audit.policies)
  if (next === meetingBoard) return false
  meetingBoard = next
  persistMeeting()
  return true
}

const renderMeetingPanel = () => {
  const tab = document.querySelector<HTMLButtonElement>('#tab-meeting')!
  tab.disabled = !sourceName
  document.querySelector<HTMLSpanElement>('#tab-meeting-count')!.textContent = sourceName && meetingBoard.cards.length ? String(meetingBoard.cards.length) : ''
  document.querySelector<HTMLButtonElement>('#minutes-export-button')!.disabled = !sourceName || !meetingBoard.cards.length
  if (!sourceName) {
    meetingPanel.innerHTML = ''
    return
  }
  meetingPanel.innerHTML = renderMeetingBoard(meetingBoard, cardContext, collapsedGroups)
  renderIcons()
}

const focusCardElement = (key: string) =>
  meetingPanel.querySelector<HTMLElement>(`[data-card-key="${CSS.escape(key)}"]`)?.focus()

const renderFocus = () => {
  const card = meetingBoard.cards.find((candidate) => candidate.policyKey === focusKey)
  if (!card) {
    focusDialog.close()
    return
  }
  const queue = focusQueue.map((key) => meetingBoard.cards.find((candidate) => candidate.policyKey === key)).filter((candidate): candidate is MeetingCard => Boolean(candidate))
  const agendaScroll = focusDialog.querySelector('.focus-agenda')?.scrollTop
  focusDialog.innerHTML = renderMeetingFocus(card, cardContext(card), { queue, running: meetingRunning() }, cardContext)
  renderIcons()
  const agendaList = focusDialog.querySelector<HTMLElement>('.focus-agenda')
  if (agendaList && agendaScroll !== undefined) agendaList.scrollTop = agendaScroll
  focusDialog.querySelector('.agenda-item.current')?.scrollIntoView({ block: 'nearest' })
}

/** L'ordre du jour s'affiche par proposition : la navigation suit le même ordre. */
const proposalOrder = ['delete', 'modify', 'keep', undefined]
const orderByProposal = (keys: string[]) => proposalOrder.flatMap((proposal) =>
  keys.filter((key) => meetingBoard.cards.find((card) => card.policyKey === key)?.proposal === proposal))

const openFocus = (key: string, queue = boardOrder()) => {
  focusQueue = orderByProposal(queue.includes(key) ? queue : [key, ...queue])
  focusKey = key
  renderFocus()
  if (!focusDialog.open) focusDialog.showModal()
  focusDialog.querySelector<HTMLButtonElement>('[data-decide][aria-pressed="true"], [data-decide]')?.focus()
}

const stepFocus = (step: number) => {
  const next = focusQueue[focusQueue.indexOf(focusKey ?? '') + step]
  if (!next) return
  focusKey = next
  renderFocus()
  focusDialog.querySelector<HTMLElement>('.focus-main')?.scrollTo({ top: 0 })
}

const decideFocused = (column: MeetingColumn) => {
  if (!focusKey) return
  const decided = meetingBoard.cards.find((card) => card.policyKey === focusKey)
  if (decided) announce(tr(`Règle ${decided.policyId} : ${meetingColumnLabel(column).toLowerCase()}`, `Rule ${decided.policyId}: ${meetingColumnLabel(column).toLowerCase()}`))
  meetingBoard = moveCard(meetingBoard, focusKey, column)
  persistMeeting()
  const index = focusQueue.indexOf(focusKey)
  if (meetingRunning() && column !== 'discuss' && index < focusQueue.length - 1) stepFocus(1)
  else renderFocus()
  focusDialog.querySelector<HTMLButtonElement>(`[data-decide="${column}"]`)?.focus()
}

const openMinutes = () => {
  document.querySelector<HTMLTextAreaElement>('#minutes-markdown')!.value = renderMinutesMarkdown(meetingBoard, audit)
  document.querySelector<HTMLSpanElement>('#minutes-status')!.textContent = ''
  minutesDialog.showModal()
}

const minutesFileName = (extension: string) => `${tr('compte-rendu-reunion', 'meeting-minutes')}-${meetingBoard.date || tr('sans-date', 'undated')}.${extension}`

meetingPanel.addEventListener('click', (event) => {
  const target = event.target as HTMLElement
  if (target.closest('[data-meeting-start]')) {
    meetingBoard = { ...meetingBoard, startedAt: meetingRunning() ? meetingBoard.startedAt : meetingBoard.startedAt ?? new Date().toISOString(), endedAt: undefined }
    persistMeeting()
    renderMeetingPanel()
    const queue = agenda(meetingBoard).map((card) => card.policyKey)
    const ordered = queue.length ? queue : boardOrder()
    if (ordered[0]) openFocus(ordered[0], ordered)
    return
  }
  if (target.closest('[data-meeting-end]')) {
    commitMeeting({ ...meetingBoard, endedAt: new Date().toISOString() })
    openMinutes()
    return
  }
  const toggle = target.closest<HTMLButtonElement>('[data-toggle-group]')
  if (toggle?.dataset.toggleGroup) {
    const group = toggle.dataset.toggleGroup
    if (!collapsedGroups.delete(group)) collapsedGroups.add(group)
    renderMeetingPanel()
    meetingPanel.querySelector<HTMLButtonElement>(`[data-toggle-group="${group}"]`)?.focus()
    return
  }
  if (target.closest('[data-meeting-sort]')) {
    commitMeeting(sortDiscussByPriority(meetingBoard, audit))
    return
  }
  if (target.closest('[data-meeting-minutes]')) {
    openMinutes()
    return
  }
  if (target.closest('[data-meeting-clear]')) {
    void askConfirmation({
      eyebrow: tr('Réunion de revue', 'Review meeting'),
      title: tr('Réinitialiser le tableau ?', 'Reset the board?'),
      message: tr(
        'Les notes, propositions modifiées, décisions et horaires de séance seront effacés. Le tableau sera reconstruit à partir des constats ouverts ; l’audit lui-même n’est pas modifié.',
        'Notes, changed proposals, decisions and meeting times will be erased. The board will be rebuilt from the open findings; the audit itself is not changed.',
      ),
      confirmLabel: tr('Réinitialiser', 'Reset'),
      tone: 'danger',
    }).then((confirmed) => {
      if (!confirmed) return
      meetingStore.clear(sourceName)
      meetingBoard = addPolicies(createBoard(sourceName), openFindings(), audit.policies)
      persistMeeting()
      renderMeetingPanel()
      if (activeView === 'findings') renderFindings()
    })
    return
  }
  if (target.closest('select, label, input, textarea')) return
  const card = target.closest<HTMLElement>('[data-card-key]')
  if (card?.dataset.cardKey) openFocus(card.dataset.cardKey)
})

meetingPanel.addEventListener('change', (event) => {
  const select = (event.target as HTMLElement).closest<HTMLSelectElement>('[data-move-card]')
  const key = select?.closest<HTMLElement>('[data-card-key]')?.dataset.cardKey
  if (!select || !key) return
  const [column, proposal] = select.value.split(':')
  commitMeeting(column === 'discuss' && proposal
    ? moveToDiscussGroup(meetingBoard, key, proposal === 'none' ? undefined : proposal as MeetingProposal)
    : moveCard(meetingBoard, key, column as MeetingColumn))
  focusCardElement(key)
})

meetingPanel.addEventListener('input', (event) => {
  const input = event.target as HTMLInputElement
  const field = input.dataset.boardField
  if (!field) return
  if (field === 'title') meetingBoard = { ...meetingBoard, title: input.value }
  else if (field === 'date') meetingBoard = { ...meetingBoard, date: input.value }
  else if (field === 'participants') meetingBoard = { ...meetingBoard, participants: input.value.split(',').map((name) => name.trim()).filter(Boolean) }
  persistMeeting(false)
})

meetingPanel.addEventListener('keydown', (event) => {
  const card = event.target as HTMLElement
  const key = card.dataset?.cardKey
  if (!key || event.ctrlKey || event.metaKey || event.altKey) return
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault()
    openFocus(key)
  } else if (/^[1-5]$/.test(event.key)) {
    event.preventDefault()
    const column = meetingColumns[Number(event.key) - 1]
    commitMeeting(moveCard(meetingBoard, key, column))
    focusCardElement(key)
    announce(tr(`Déplacée vers ${meetingColumnLabel(column)}`, `Moved to ${meetingColumnLabel(column)}`))
  } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    const sibling = event.key === 'ArrowDown' ? card.nextElementSibling : card.previousElementSibling
    if (sibling instanceof HTMLElement && sibling.dataset.cardKey) sibling.focus()
  }
})

let draggedKey: string | null = null
const dropIndex = (list: HTMLElement, clientY: number) => {
  const cards = [...list.querySelectorAll<HTMLElement>('[data-card-key]')].filter((card) => card.dataset.cardKey !== draggedKey)
  const index = cards.findIndex((card) => {
    const box = card.getBoundingClientRect()
    return clientY < box.top + box.height / 2
  })
  return index === -1 ? cards.length : index
}
const clearDropTargets = () => meetingPanel.querySelectorAll('.drop-target').forEach((list) => list.classList.remove('drop-target'))

meetingPanel.addEventListener('dragstart', (event) => {
  const card = (event.target as HTMLElement).closest<HTMLElement>('[data-card-key]')
  if (!card || !event.dataTransfer) return
  draggedKey = card.dataset.cardKey ?? null
  event.dataTransfer.effectAllowed = 'move'
  event.dataTransfer.setData('text/plain', draggedKey ?? '')
  card.classList.add('dragging')
})
meetingPanel.addEventListener('dragover', (event) => {
  const list = (event.target as HTMLElement).closest<HTMLElement>('[data-drop-column]')
  if (!list || !draggedKey) return
  event.preventDefault()
  if (event.dataTransfer) event.dataTransfer.dropEffect = 'move'
  if (!list.classList.contains('drop-target')) {
    clearDropTargets()
    list.classList.add('drop-target')
  }
})
meetingPanel.addEventListener('drop', (event) => {
  const list = (event.target as HTMLElement).closest<HTMLElement>('[data-drop-column]')
  if (!list || !draggedKey) return
  event.preventDefault()
  const key = draggedKey
  draggedKey = null
  const proposal = list.dataset.dropProposal
  commitMeeting(proposal
    ? moveToDiscussGroup(meetingBoard, key, proposal === 'none' ? undefined : proposal as MeetingProposal, dropIndex(list, event.clientY))
    : moveCard(meetingBoard, key, list.dataset.dropColumn as MeetingColumn, dropIndex(list, event.clientY)))
})
meetingPanel.addEventListener('dragend', () => {
  draggedKey = null
  clearDropTargets()
  meetingPanel.querySelectorAll('.dragging').forEach((card) => card.classList.remove('dragging'))
})

focusDialog.addEventListener('click', (event) => {
  const target = event.target as HTMLElement
  if (target === focusDialog || target.closest('[data-focus-close]')) {
    focusDialog.close()
    return
  }
  const goto = target.closest<HTMLButtonElement>('[data-focus-goto]')
  if (goto?.dataset.focusGoto) {
    focusKey = goto.dataset.focusGoto
    renderFocus()
    focusDialog.querySelector<HTMLElement>('.focus-main')?.scrollTo({ top: 0 })
    focusDialog.querySelector<HTMLButtonElement>('.agenda-item.current')?.focus()
    return
  }
  const step = target.closest<HTMLButtonElement>('[data-focus-step]')
  if (step) {
    stepFocus(Number(step.dataset.focusStep))
    return
  }
  const decide = target.closest<HTMLButtonElement>('[data-decide]')
  if (decide) {
    decideFocused(decide.dataset.decide as MeetingColumn)
    return
  }
  const copyButton = target.closest<HTMLButtonElement>('[data-copy-cli]')
  if (copyButton) {
    copyCli(copyButton)
    return
  }
})

const updateFocusedField = (element: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, immediate: boolean) => {
  const field = element.dataset.cardField as keyof MeetingCardPatch | undefined
  if (!field || !focusKey) return
  const patch: MeetingCardPatch = field === 'proposal'
    ? { proposal: (element.value || undefined) as MeetingCardPatch['proposal'] }
    : { [field]: element.value }
  meetingBoard = updateCard(meetingBoard, focusKey, patch)
  persistMeeting(immediate)
}
focusDialog.addEventListener('input', (event) => updateFocusedField(event.target as HTMLInputElement, false))
focusDialog.addEventListener('change', (event) => {
  const element = event.target as HTMLInputElement
  updateFocusedField(element, true)
  // La proposition colore le bloc de tête et marque le bouton de décision correspondant.
  if (element.dataset.cardField === 'proposal') {
    focusQueue = orderByProposal(focusQueue)
    renderFocus()
    focusDialog.querySelector<HTMLSelectElement>('[data-card-field="proposal"]')?.focus()
  }
})

focusDialog.addEventListener('keydown', (event) => {
  if (event.ctrlKey || event.metaKey || event.altKey || isTyping(event.target)) return
  const column = decisionKeys()[event.key.toLowerCase()]
  if (column) {
    event.preventDefault()
    decideFocused(column)
  } else if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
    event.preventDefault()
    stepFocus(event.key === 'ArrowRight' ? 1 : -1)
  }
})

focusDialog.addEventListener('close', () => {
  persistMeeting()
  const key = focusKey
  focusKey = null
  renderMeetingPanel()
  if (activeView === 'findings') renderFindings()
  else if (key) focusCardElement(key)
})

document.querySelector<HTMLButtonElement>('#minutes-export-button')!.addEventListener('click', () => {
  document.querySelector<HTMLDetailsElement>('#export-menu')!.open = false
  openMinutes()
})
document.querySelector<HTMLButtonElement>('#close-minutes')!.addEventListener('click', () => minutesDialog.close())
document.querySelector<HTMLButtonElement>('#copy-minutes')!.addEventListener('click', () => {
  const textarea = document.querySelector<HTMLTextAreaElement>('#minutes-markdown')!
  const copy = navigator.clipboard?.writeText(textarea.value) ?? Promise.reject()
  void copy.catch(() => {
    textarea.select()
    document.execCommand('copy')
  }).finally(() => {
    document.querySelector<HTMLSpanElement>('#minutes-status')!.textContent = tr('Compte rendu copié', 'Minutes copied')
  })
})
document.querySelector<HTMLButtonElement>('#download-minutes-md')!.addEventListener('click', () => {
  downloadText(renderMinutesMarkdown(meetingBoard, audit), minutesFileName('md'), 'text/markdown;charset=utf-8')
})
document.querySelector<HTMLButtonElement>('#download-minutes-html')!.addEventListener('click', () => {
  downloadText(renderMinutesHtml(meetingBoard, audit), minutesFileName('html'), 'text/html;charset=utf-8')
})

/* ---------- Langue ---------- */
/** Fichier en attente de réanalyse après un changement de langue (lu puis effacé aussitôt). */
const pendingImportKey = 'fortiscope-pending-import'

document.querySelector<HTMLButtonElement>('#locale-toggle')!.addEventListener('click', async () => {
  // La langue est fixée au chargement : la changer recharge la page. Le fichier analysé est confié à
  // sessionStorage (propre à cet onglet) le temps du rechargement, puis effacé dès sa relecture.
  if (lastImport) {
    try {
      sessionStorage.setItem(pendingImportKey, JSON.stringify(lastImport))
    } catch {
      const proceed = await askConfirmation({
        eyebrow: otherLocale === 'en' ? 'Language' : 'Langue',
        title: otherLocale === 'en' ? 'Re-import the file?' : 'Réimporter le fichier ?',
        message: otherLocale === 'en'
          ? 'This file is too large to be kept while the page reloads. You will need to import it again.'
          : 'Ce fichier est trop volumineux pour être conservé pendant le rechargement. Il faudra l’importer de nouveau.',
        confirmLabel: otherLocale === 'en' ? 'Switch to English' : 'Passer en français',
      })
      if (!proceed) return
    }
  }
  try { localStorage.setItem(localeStorageKey, otherLocale) } catch { /* préférence non enregistrée */ }
  location.reload()
})

renderAll()
setView('findings', false)

const restorePendingImport = () => {
  let pending: { content?: unknown, name?: unknown } | null = null
  try {
    pending = JSON.parse(sessionStorage.getItem(pendingImportKey) ?? 'null')
    sessionStorage.removeItem(pendingImportKey)
  } catch {
    return
  }
  if (pending && typeof pending.content === 'string' && typeof pending.name === 'string') {
    void loadConfiguration(pending.content, pending.name, { restored: true })
  }
}
restorePendingImport()
