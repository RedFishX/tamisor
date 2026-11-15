import type { Finding, FirewallPolicy, Severity } from '../domain/audit'
import {
  boardProgress, cardsInColumn, decisionColumns, discussGroups, maxSeverity, meetingColumnLabels, meetingColumns,
  type MeetingBoard, type MeetingCard, type MeetingColumn, type MeetingProposal,
} from '../domain/meeting'
import { cardLocation } from '../domain/meeting-minutes'
import { formatUsage, usageBand } from '../domain/policy-usage'
import { renderRecommendation } from './recommendation-view'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)

const severityLabels: Record<Severity, string> = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible' }

const categoryLabels: Record<Finding['category'], string> = {
  duplicate: 'Doublon', shadowed: 'Masquée', overlap: 'Chevauchement', permissive: 'Permissive', exposure: 'Exposition',
  unused: 'Inutilisée', indeterminate: 'À valider', temporary: 'Temporaire', governance: 'Gouvernance',
  security: 'Profils de sécurité', inspection: 'Inspection SSL', object: 'Objets', visibility: 'Visibilité',
}

/** Touches de décision en séance, une par colonne d'issue. */
export const decisionKeys: Record<string, MeetingColumn> = { s: 'delete', m: 'modify', c: 'keep', r: 'postpone' }
const keyForColumn = (column: MeetingColumn) => Object.entries(decisionKeys).find(([, value]) => value === column)?.[0].toUpperCase()

const columnHints: Record<MeetingColumn, string> = {
  discuss: 'Préparées avant la séance',
  delete: 'Retrait de la règle',
  modify: 'Règle à resserrer',
  keep: 'Maintenue, avec justification',
  postpone: 'Informations manquantes',
}

export interface MeetingCardContext {
  findings: Finding[]
  policy?: FirewallPolicy
}

export type CardContextResolver = (card: MeetingCard) => MeetingCardContext

const proposalGroupLabels: Record<MeetingProposal | 'none', string> = {
  delete: 'Proposé : supprimer',
  modify: 'Proposé : modifier',
  keep: 'Proposé : conserver',
  none: 'Sans proposition',
}

const moveOptions = (card: MeetingCard): string => {
  const columns = meetingColumns.map((column, index) =>
    `<option value="${column}"${column === card.column && column !== 'discuss' ? ' selected' : ''}>${index + 1} · ${meetingColumnLabels[column]}</option>`,
  ).join('')
  const proposals = (['delete', 'modify', 'keep', 'none'] as const).map((proposal) => {
    const selected = card.column === 'discuss' && (card.proposal ?? 'none') === proposal
    return `<option value="discuss:${proposal}"${selected ? ' selected' : ''}>${proposalGroupLabels[proposal]}</option>`
  }).join('')
  return `<optgroup label="Décision">${columns}</optgroup><optgroup label="À discuter">${proposals}</optgroup>`
}

const renderCard = (card: MeetingCard, context: MeetingCardContext): string => {
  const severity = maxSeverity(context.findings)
  const categories = [...new Set(context.findings.map((finding) => categoryLabels[finding.category]))]
  const location = cardLocation(card, context.policy?.order)
  const usage = formatUsage(context.policy)
  const band = usageBand(context.policy)
  // Sur la carte, seul le compteur : la date de dernière utilisation reste dans l'infobulle et le libellé accessible.
  const hits = context.policy?.hitCount
  const usageShort = hits === undefined ? usage : `${hits.toLocaleString('fr-FR')} hit${hits > 1 ? 's' : ''}`
  const note = (card.column === 'discuss' ? card.prepNote : card.rationale).trim()
  const label = [
    `Règle ${card.policyId} ${card.policyName}`,
    `colonne ${meetingColumnLabels[card.column]}`,
    severity ? `sévérité ${severityLabels[severity].toLowerCase()}` : '',
    usage ?? '',
  ].filter(Boolean).join(', ')
  const summary = [categories.slice(0, 2).join(' · '), categories.length > 2 ? `+${categories.length - 2}` : ''].filter(Boolean).join(' ')
  return `
    <li class="meeting-card ${severity ?? 'none'}${card.orphan ? ' orphan' : ''}" draggable="true" tabindex="0"
      data-card-key="${escapeHtml(card.policyKey)}" aria-label="${escapeHtml(label)}" aria-keyshortcuts="Enter 1 2 3 4 5">
      <span class="meeting-card-top">
        <span class="meeting-card-meta">#${escapeHtml(card.policyId)}${location ? ` · ${escapeHtml(location)}` : ''}</span>
        ${usageShort ? `<span class="meeting-usage ${band}" title="${escapeHtml(usage ?? '')}">${escapeHtml(usageShort)}</span>` : ''}
      </span>
      <strong>${escapeHtml(card.policyName)}</strong>
      ${card.orphan ? '<span class="meeting-card-warning">Absente de la configuration chargée</span>' : ''}
      ${note ? `<p class="meeting-card-note">${escapeHtml(note)}</p>` : ''}
      <span class="meeting-card-footer">
        <small title="${escapeHtml(categories.join(', '))}">${escapeHtml(summary)}</small>
        <label class="meeting-move"><span class="sr-only">Déplacer vers</span><select data-move-card aria-label="Déplacer la règle ${escapeHtml(card.policyId)} vers">${moveOptions(card)}</select></label>
      </span>
    </li>
  `
}

const renderCards = (cards: MeetingCard[], resolve: CardContextResolver, hint: string) =>
  cards.map((card) => renderCard(card, resolve(card))).join('') || `<li class="meeting-drop-hint" aria-hidden="true">${hint}</li>`

const renderDiscussColumn = (board: MeetingBoard, resolve: CardContextResolver, collapsed: ReadonlySet<string>): string => {
  const total = cardsInColumn(board, 'discuss').length
  return `
    <section class="meeting-column discuss" aria-labelledby="meeting-column-discuss">
      <header>
        <h3 id="meeting-column-discuss">${meetingColumnLabels.discuss}</h3>
        <span class="meeting-count">${total}</span>
        <small>Rangées par proposition ; glissez une carte d’un groupe à l’autre.</small>
        ${total > 1 ? '<button class="text-button meeting-sort" type="button" data-meeting-sort title="Proposition, sévérité, puis hit count croissant">Trier par priorité</button>' : ''}
      </header>
      ${discussGroups(board).map(({ proposal, cards }) => {
        const id = proposal ?? 'none'
        const isCollapsed = collapsed.has(id) && cards.length > 0
        return `
          <div class="discuss-group ${id}${cards.length ? '' : ' empty'}${isCollapsed ? ' collapsed' : ''}" data-drop-column="discuss" data-drop-proposal="${id}">
            <h4 id="discuss-group-${id}">
              <button type="button" data-toggle-group="${id}" aria-expanded="${!isCollapsed}" aria-controls="discuss-list-${id}"${cards.length ? '' : ' disabled'}>
                <i data-lucide="chevron-down"></i>${proposalGroupLabels[id]} <span>${cards.length}</span>
              </button>
            </h4>
            <ol class="meeting-cards" id="discuss-list-${id}" aria-labelledby="discuss-group-${id}"${isCollapsed ? ' hidden' : ''}>
              ${renderCards(cards, resolve, 'Déposer ici')}
            </ol>
          </div>
        `
      }).join('')}
    </section>
  `
}

const renderColumn = (board: MeetingBoard, column: MeetingColumn, resolve: CardContextResolver, collapsed: ReadonlySet<string>): string => {
  if (column === 'discuss') return renderDiscussColumn(board, resolve, collapsed)
  const cards = cardsInColumn(board, column)
  return `
    <section class="meeting-column ${column}" aria-labelledby="meeting-column-${column}">
      <header>
        <h3 id="meeting-column-${column}">${meetingColumnLabels[column]}</h3>
        <span class="meeting-count">${cards.length}</span>
        <small>${columnHints[column]}</small>
      </header>
      <ol class="meeting-cards" data-drop-column="${column}" aria-label="${meetingColumnLabels[column]}">
        ${renderCards(cards, resolve, 'Déposer une règle ici')}
      </ol>
    </section>
  `
}

const renderEmpty = (): string => `
  <div class="meeting-empty">
    <p class="overview-label">Ordre du jour</p>
    <h2>Aucune policy à revoir</h2>
    <p>Le tableau reprend automatiquement chaque policy qui a au moins un constat ouvert. Ici, tous les constats sont acquittés ou aucun ne concerne une policy.</p>
  </div>
`

export const renderMeetingBoard = (board: MeetingBoard, resolve: CardContextResolver, collapsed: ReadonlySet<string> = new Set()): string => {
  const progress = boardProgress(board)
  const percent = progress.total ? Math.round((progress.decided / progress.total) * 100) : 0
  const running = Boolean(board.startedAt && !board.endedAt)
  return `
    <section class="meeting-header">
      <div class="meeting-identity">
        <p class="overview-label">${running ? '<span class="meeting-live" aria-hidden="true"></span>Séance en cours' : 'Réunion de revue'}</p>
        <label class="sr-only" for="meeting-title">Titre de la réunion</label>
        <input class="meeting-title" id="meeting-title" data-board-field="title" value="${escapeHtml(board.title)}" autocomplete="off" />
        <div class="meeting-fields">
          <label>Date<input type="date" data-board-field="date" value="${escapeHtml(board.date)}" /></label>
          <label class="meeting-participants">Participants<input data-board-field="participants" value="${escapeHtml(board.participants.join(', '))}" placeholder="Équipe réseau, RSSI, exploitation" autocomplete="off" /></label>
        </div>
      </div>
      <div class="meeting-progress" aria-label="Avancement">
        <strong>${progress.decided}<small>/${progress.total}</small></strong>
        <span>décision${progress.decided > 1 ? 's' : ''} prise${progress.decided > 1 ? 's' : ''}</span>
        <span class="meeting-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="${progress.total}" aria-valuenow="${progress.decided}" aria-label="Policies décidées"><i style="width:${percent}%"></i></span>
      </div>
      <div class="meeting-actions">
        <button class="acknowledge-button" type="button" data-meeting-start${progress.total ? '' : ' disabled'}>
          <i data-lucide="presentation"></i>${running ? 'Reprendre la séance' : board.endedAt ? 'Rouvrir la séance' : 'Démarrer la séance'}
        </button>
        ${running ? '<button class="secondary-button" type="button" data-meeting-end><i data-lucide="square"></i>Clore la séance</button>' : ''}
        <button class="secondary-button" type="button" data-meeting-minutes${progress.total ? '' : ' disabled'}><i data-lucide="file-text"></i>Compte rendu</button>
        <button class="text-button" type="button" data-meeting-clear${progress.total ? '' : ' disabled'}>Réinitialiser le tableau</button>
      </div>
    </section>
    ${progress.total ? `
      <p class="meeting-help">Glissez une carte vers une colonne, ou sélectionnez-la et tapez <kbd>1</kbd> à <kbd>5</kbd>. <kbd>Entrée</kbd> ouvre la fiche.</p>
      <div class="meeting-board">${meetingColumns.map((column) => renderColumn(board, column, resolve, collapsed)).join('')}</div>
    ` : renderEmpty()}
  `
}

const list = (values: string[]) => values.join(', ') || '—'

/** Le flux autorisé, lu de gauche à droite : interfaces, adresses, service. */
const renderFlow = (policy: FirewallPolicy): string => {
  const sources = [...policy.srcaddr, ...(policy.users ?? []), ...(policy.groups ?? [])]
  const extras = [
    policy.logtraffic ? `Journalisation ${policy.logtraffic}` : '',
    policy.nat === 'enable' ? 'NAT activé' : '',
    policy.schedule.length && policy.schedule.join() !== 'always' ? `Horaire ${policy.schedule.join(', ')}` : '',
    policy.comments ? `Commentaire « ${policy.comments} »` : '',
  ].filter(Boolean)
  return `
    <dl class="focus-flow">
      <div><dt>Interfaces</dt><dd>${escapeHtml(list(policy.srcintf))} <b aria-hidden="true">→</b><span class="sr-only">vers</span> ${escapeHtml(list(policy.dstintf))}</dd></div>
      <div><dt>Adresses</dt><dd>${escapeHtml(list(sources))} <b aria-hidden="true">→</b><span class="sr-only">vers</span> ${escapeHtml(list(policy.dstaddr))}</dd></div>
      <div><dt>Service</dt><dd>${escapeHtml(list([...policy.service, ...policy.internetServices]))} · ${escapeHtml(policy.action)}</dd></div>
    </dl>
    ${extras.length ? `<p class="focus-extra">${escapeHtml(extras.join(' · '))}</p>` : ''}
  `
}

export interface FocusPosition {
  /** Policies de la séance, dans l'ordre de passage. */
  queue: MeetingCard[]
  running: boolean
}

const agendaStatus = (card: MeetingCard, current: boolean): { glyph: string, label: string } => {
  if (current) return { glyph: '●', label: 'en cours' }
  if (card.column === 'postpone') return { glyph: '↷', label: 'reportée' }
  if (card.column !== 'discuss') return { glyph: '✓', label: `décidée : ${meetingColumnLabels[card.column].toLowerCase()}` }
  return { glyph: '', label: 'à traiter' }
}

/** Colonne « ordre du jour » : où en est la séance, et accès direct à n'importe quelle policy. */
const renderAgenda = (current: MeetingCard, queue: MeetingCard[], resolve: CardContextResolver): string => {
  const decided = queue.filter((card) => card.column !== 'discuss' && card.column !== 'postpone').length
  const groups = (['delete', 'modify', 'keep', 'none'] as const)
    .map((group) => ({ group, cards: queue.filter((card) => (card.proposal ?? 'none') === group) }))
    .filter(({ cards }) => cards.length)
  return `
    <nav class="focus-agenda" aria-label="Ordre du jour">
      <p class="focus-agenda-title">Ordre du jour <span>${decided}/${queue.length}</span></p>
      ${groups.map(({ group, cards }) => `
        <h4 class="${group}">${proposalGroupLabels[group]}</h4>
        <ol>
          ${cards.map((card) => {
            const isCurrent = card.policyKey === current.policyKey
            const status = agendaStatus(card, isCurrent)
            const hits = resolve(card).policy?.hitCount
            return `<li><button type="button" class="agenda-item ${card.column}${isCurrent ? ' current' : ''}" data-focus-goto="${escapeHtml(card.policyKey)}"
              ${isCurrent ? 'aria-current="step"' : ''} aria-label="${escapeHtml(`Règle ${card.policyId} ${card.policyName}, ${status.label}`)}">
              <span class="agenda-status" aria-hidden="true">${status.glyph}</span>
              <span class="agenda-name"><b>#${escapeHtml(card.policyId)}</b> ${escapeHtml(card.policyName)}</span>
              ${hits === undefined ? '' : `<span class="agenda-hits ${usageBand(resolve(card).policy)}">${escapeHtml(hits >= 10000 ? `${Math.round(hits / 1000)}k` : String(hits))}</span>`}
            </button></li>`
          }).join('')}
        </ol>
      `).join('')}
    </nav>
  `
}

const proposalHeadlines: Record<MeetingProposal | 'none', string> = {
  delete: 'Supprimer la règle',
  modify: 'Modifier la règle',
  keep: 'Conserver en l’état',
  none: 'Aucune proposition',
}

/** Bloc coloré en tête de fiche : ce que la préparation propose, et l'argument d'usage qui le soutient. */
const renderProposal = (card: MeetingCard, context: MeetingCardContext): string => {
  const id = card.proposal ?? 'none'
  const severity = maxSeverity(context.findings)
  const facts = [
    formatUsage(context.policy),
    context.findings.length ? `${context.findings.length} constat${context.findings.length > 1 ? 's' : ''}` : '',
    severity ? `sévérité max. ${severityLabels[severity].toLowerCase()}` : '',
  ].filter(Boolean)
  return `
    <section class="focus-proposal ${id}" aria-label="Proposition préparée">
      <div class="focus-proposal-head">
        <span>Proposition préparée</span>
        <label><span class="sr-only">Changer la proposition</span>
          <select data-card-field="proposal">
            <option value=""${card.proposal ? '' : ' selected'}>Aucune</option>
            ${(['delete', 'modify', 'keep'] as const).map((proposal) => `<option value="${proposal}"${card.proposal === proposal ? ' selected' : ''}>${meetingColumnLabels[proposal]}</option>`).join('')}
          </select>
        </label>
      </div>
      <strong>${proposalHeadlines[id]}</strong>
      ${facts.length ? `<p class="focus-proposal-facts">${escapeHtml(facts.join(' · '))}</p>` : ''}
      <label class="focus-proposal-note"><span class="sr-only">Note de préparation</span><textarea rows="2" data-card-field="prepNote" placeholder="Note de préparation : contexte, demandeur, ticket, trafic observé…">${escapeHtml(card.prepNote)}</textarea></label>
    </section>
  `
}

export const renderMeetingFocus = (card: MeetingCard, context: MeetingCardContext, position: FocusPosition, resolve: CardContextResolver): string => {
  const location = cardLocation(card, context.policy?.order)
  const field = (name: keyof MeetingCard) => `data-card-field="${name}"`
  const index = position.queue.findIndex((candidate) => candidate.policyKey === card.policyKey)
  const total = position.queue.length
  return `
    <header class="focus-top">
      <div>
        <p class="eyebrow">${position.running ? 'Séance' : 'Fiche'} · policy ${index + 1} sur ${total}</p>
        <span class="focus-column ${card.column}">${meetingColumnLabels[card.column]}</span>
      </div>
      <div class="focus-nav">
        <button class="icon-button" type="button" data-focus-step="-1" aria-label="Policy précédente" title="Précédente (←)"${index > 0 ? '' : ' disabled'}><i data-lucide="chevron-left"></i></button>
        <button class="icon-button" type="button" data-focus-step="1" aria-label="Policy suivante" title="Suivante (→)"${index < total - 1 ? '' : ' disabled'}><i data-lucide="chevron-right"></i></button>
        <button class="icon-button" type="button" data-focus-close aria-label="Fermer" title="Fermer (Échap)"><i data-lucide="x"></i></button>
      </div>
    </header>
    <div class="focus-body">
      ${renderAgenda(card, position.queue, resolve)}
      <div class="focus-main">
        <div class="focus-title">
          <h2>${escapeHtml(card.policyName)}</h2>
          <p class="focus-location">Règle #${escapeHtml(card.policyId)}${location ? ` · ${escapeHtml(location)}` : ''}</p>
        </div>
        ${card.orphan ? '<p class="meeting-card-warning">Cette policy n’existe plus dans la configuration chargée.</p>' : ''}
        ${renderProposal(card, context)}
        ${context.policy ? renderFlow(context.policy) : ''}
        <section class="focus-findings">
          <h3>Constats (${context.findings.length})</h3>
          ${context.findings.map((finding) => `
            <details class="focus-finding">
              <summary><span class="severity-badge ${finding.severity}">${severityLabels[finding.severity]}</span><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(categoryLabels[finding.category])}</small></summary>
              <p>${escapeHtml(finding.detail)}</p>
              ${renderRecommendation(finding.recommendation)}
            </details>
          `).join('') || '<p class="overview-note">Aucun constat ouvert sur cette policy.</p>'}
        </section>
      </div>
      <section class="focus-decision" aria-label="Décision">
        <div class="decision-buttons" role="group" aria-label="Décision">
          ${decisionColumns.map((column) => `
            <button type="button" class="decision-button ${column}" data-decide="${column}" aria-pressed="${card.column === column}" aria-keyshortcuts="${keyForColumn(column)}">
              <span>${meetingColumnLabels[column]}${card.proposal === column ? '<small>proposé</small>' : ''}</span><kbd aria-hidden="true">${keyForColumn(column)}</kbd>
            </button>
          `).join('')}
          ${card.column !== 'discuss' ? '<button class="text-button" type="button" data-decide="discuss">Remettre à discuter</button>' : ''}
        </div>
        <div class="decision-fields">
          <label class="dialog-field">Justification<textarea rows="2" ${field('rationale')} placeholder="Pourquoi cette décision ? Ex. : flux ERP encore utilisé, à restreindre à 10.20.4.0/24.">${escapeHtml(card.rationale)}</textarea></label>
          <label class="dialog-field">Échéance<input type="date" ${field('dueDate')} value="${escapeHtml(card.dueDate)}" /></label>
        </div>
      </section>
    </div>
  `
}
