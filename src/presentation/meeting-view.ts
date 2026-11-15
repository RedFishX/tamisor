import type { Finding, FirewallPolicy } from '../domain/audit'
import {
  boardProgress, cardsInColumn, decisionColumns, discussGroups, maxSeverity, meetingColumnLabel, meetingColumns,
  type MeetingBoard, type MeetingCard, type MeetingColumn, type MeetingProposal,
} from '../domain/meeting'
import { cardLocation } from '../domain/meeting-minutes'
import { categoryLabel, colon, severityLabel } from '../domain/labels'
import { formatHits, formatUsage, usageBand } from '../domain/policy-usage'
import { getLocale, plural, tr } from '../i18n'
import { renderRecommendation } from './recommendation-view'

const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)

/**
 * Touches de décision en séance : l'initiale de chaque décision dans la langue courante
 * (Supprimer/Modifier/Conserver/Reporter, Delete/Modify/Keep/Postpone).
 */
export const decisionKeys = (): Record<string, MeetingColumn> => getLocale() === 'en'
  ? { d: 'delete', m: 'modify', k: 'keep', p: 'postpone' }
  : { s: 'delete', m: 'modify', c: 'keep', r: 'postpone' }
const keyForColumn = (column: MeetingColumn) => Object.entries(decisionKeys()).find(([, value]) => value === column)?.[0].toUpperCase()

const columnHint = (column: MeetingColumn): string => ({
  discuss: tr('Préparées avant la séance', 'Prepared before the meeting'),
  delete: tr('Retrait de la règle', 'Rule removal'),
  modify: tr('Règle à resserrer', 'Rule to tighten'),
  keep: tr('Maintenue, avec justification', 'Kept, with a rationale'),
  postpone: tr('Informations manquantes', 'Missing information'),
})[column]

export interface MeetingCardContext {
  findings: Finding[]
  policy?: FirewallPolicy
}

export type CardContextResolver = (card: MeetingCard) => MeetingCardContext

const proposalGroupLabel = (group: MeetingProposal | 'none'): string => ({
  delete: tr('Proposé : supprimer', 'Proposed: delete'),
  modify: tr('Proposé : modifier', 'Proposed: modify'),
  keep: tr('Proposé : conserver', 'Proposed: keep'),
  none: tr('Sans proposition', 'No proposal'),
})[group]

const moveOptions = (card: MeetingCard): string => {
  const columns = meetingColumns.map((column, index) =>
    `<option value="${column}"${column === card.column && column !== 'discuss' ? ' selected' : ''}>${index + 1} · ${meetingColumnLabel(column)}</option>`,
  ).join('')
  const proposals = (['delete', 'modify', 'keep', 'none'] as const).map((proposal) => {
    const selected = card.column === 'discuss' && (card.proposal ?? 'none') === proposal
    return `<option value="discuss:${proposal}"${selected ? ' selected' : ''}>${proposalGroupLabel(proposal)}</option>`
  }).join('')
  return `<optgroup label="${tr('Décision', 'Decision')}">${columns}</optgroup><optgroup label="${meetingColumnLabel('discuss')}">${proposals}</optgroup>`
}

const ruleLabel = (card: MeetingCard) => `${tr('Règle', 'Rule')} ${card.policyId} ${card.policyName}`

const renderCard = (card: MeetingCard, context: MeetingCardContext): string => {
  const severity = maxSeverity(context.findings)
  const categories = [...new Set(context.findings.map((finding) => categoryLabel(finding.category)))]
  const location = cardLocation(card, context.policy?.order)
  const usage = formatUsage(context.policy)
  const band = usageBand(context.policy)
  // Sur la carte, seul le compteur : la date de dernière utilisation reste dans l'infobulle et le libellé accessible.
  const hits = context.policy?.hitCount
  const usageShort = hits === undefined ? usage : formatHits(hits)
  const note = (card.column === 'discuss' ? card.prepNote : card.rationale).trim()
  const label = [
    ruleLabel(card),
    tr(`colonne ${meetingColumnLabel(card.column)}`, `column ${meetingColumnLabel(card.column)}`),
    card.column === 'discuss' ? proposalGroupLabel(card.proposal ?? 'none') : '',
    severity ? tr(`sévérité ${severityLabel(severity).toLowerCase()}`, `${severityLabel(severity).toLowerCase()} severity`) : '',
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
      ${card.orphan ? `<span class="meeting-card-warning">${tr('Absente de la configuration chargée', 'Missing from the loaded configuration')}</span>` : ''}
      ${note ? `<p class="meeting-card-note">${escapeHtml(note)}</p>` : ''}
      <span class="meeting-card-footer">
        <small title="${escapeHtml(categories.join(', '))}">${escapeHtml(summary)}</small>
        <label class="meeting-move"><span class="sr-only">${tr('Déplacer vers', 'Move to')}</span><select data-move-card aria-label="${escapeHtml(tr(`Déplacer la règle ${card.policyId} vers`, `Move rule ${card.policyId} to`))}">${moveOptions(card)}</select></label>
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
        <h3 id="meeting-column-discuss">${meetingColumnLabel('discuss')}</h3>
        <span class="meeting-count" aria-label="${total} ${plural(total, ['policy', 'policies'], ['policy', 'policies'])}">${total}</span>
        <small>${tr('Rangées par proposition ; glissez une carte d’un groupe à l’autre.', 'Grouped by proposal; drag a card from one group to another.')}</small>
        ${total > 1 ? `<button class="text-button meeting-sort" type="button" data-meeting-sort title="${tr('Proposition, hit count croissant, puis sévérité', 'Proposal, ascending hit count, then severity')}">${tr('Trier par priorité', 'Sort by priority')}</button>` : ''}
      </header>
      ${discussGroups(board).map(({ proposal, cards }) => {
        const id = proposal ?? 'none'
        const isCollapsed = collapsed.has(id) && cards.length > 0
        return `
          <div class="discuss-group ${id}${cards.length ? '' : ' empty'}${isCollapsed ? ' collapsed' : ''}" data-drop-column="discuss" data-drop-proposal="${id}">
            <h4 id="discuss-group-${id}">
              <button type="button" data-toggle-group="${id}" aria-expanded="${!isCollapsed}" aria-controls="discuss-list-${id}"${cards.length ? '' : ' disabled'}>
                <i data-lucide="chevron-down"></i>${proposalGroupLabel(id)} <span>${cards.length}</span>
              </button>
            </h4>
            <ol class="meeting-cards" id="discuss-list-${id}" aria-labelledby="discuss-group-${id}"${isCollapsed ? ' hidden' : ''}>
              ${renderCards(cards, resolve, tr('Déposer ici', 'Drop here'))}
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
        <h3 id="meeting-column-${column}">${meetingColumnLabel(column)}</h3>
        <span class="meeting-count" aria-label="${cards.length} ${plural(cards.length, ['policy', 'policies'], ['policy', 'policies'])}">${cards.length}</span>
        <small>${columnHint(column)}</small>
      </header>
      <ol class="meeting-cards" data-drop-column="${column}" aria-labelledby="meeting-column-${column}">
        ${renderCards(cards, resolve, tr('Déposer une règle ici', 'Drop a rule here'))}
      </ol>
    </section>
  `
}

const renderEmpty = (): string => `
  <div class="meeting-empty">
    <p class="overview-label">${tr('Ordre du jour', 'Agenda')}</p>
    <h2>${tr('Aucune policy à revoir', 'No policy to review')}</h2>
    <p>${tr(
      'Le tableau reprend automatiquement chaque policy qui a au moins un constat ouvert. Ici, tous les constats sont acquittés ou aucun ne concerne une policy.',
      'The board automatically lists every policy with at least one open finding. Here, all findings are acknowledged or none concerns a policy.',
    )}</p>
  </div>
`

export const renderMeetingBoard = (board: MeetingBoard, resolve: CardContextResolver, collapsed: ReadonlySet<string> = new Set()): string => {
  const progress = boardProgress(board)
  const percent = progress.total ? Math.round((progress.decided / progress.total) * 100) : 0
  const running = Boolean(board.startedAt && !board.endedAt)
  const decisions = plural(progress.decided, ['décision prise', 'décisions prises'], ['decision made', 'decisions made'])
  return `
    <section class="meeting-header" aria-label="${tr('Réunion de revue', 'Review meeting')}">
      <div class="meeting-identity">
        <p class="overview-label">${running ? `<span class="meeting-live" aria-hidden="true"></span>${tr('Séance en cours', 'Meeting in progress')}` : tr('Réunion de revue', 'Review meeting')}</p>
        <label class="sr-only" for="meeting-title">${tr('Titre de la réunion', 'Meeting title')}</label>
        <input class="meeting-title" id="meeting-title" data-board-field="title" value="${escapeHtml(board.title)}" autocomplete="off" />
        <div class="meeting-fields">
          <label>Date<input type="date" data-board-field="date" value="${escapeHtml(board.date)}" /></label>
          <label class="meeting-participants">Participants<input data-board-field="participants" value="${escapeHtml(board.participants.join(', '))}" placeholder="${tr('Équipe réseau, RSSI, exploitation', 'Network team, CISO, operations')}" autocomplete="off" /></label>
        </div>
      </div>
      <div class="meeting-progress">
        <strong aria-hidden="true">${progress.decided}<small>/${progress.total}</small></strong>
        <span aria-hidden="true">${decisions}</span>
        <span class="meeting-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="${progress.total}" aria-valuenow="${progress.decided}"
          aria-valuetext="${tr(`${progress.decided} sur ${progress.total} policies décidées`, `${progress.decided} of ${progress.total} policies decided`)}" aria-label="${tr('Policies décidées', 'Policies decided')}"><i style="width:${percent}%"></i></span>
      </div>
      <div class="meeting-actions">
        <button class="acknowledge-button" type="button" data-meeting-start${progress.total ? '' : ' disabled'}>
          <i data-lucide="presentation"></i>${running ? tr('Reprendre la séance', 'Resume the meeting') : board.endedAt ? tr('Rouvrir la séance', 'Reopen the meeting') : tr('Démarrer la séance', 'Start the meeting')}
        </button>
        ${running ? `<button class="secondary-button" type="button" data-meeting-end><i data-lucide="square"></i>${tr('Clore la séance', 'End the meeting')}</button>` : ''}
        <button class="secondary-button" type="button" data-meeting-minutes${progress.total ? '' : ' disabled'}><i data-lucide="file-text"></i>${tr('Compte rendu', 'Minutes')}</button>
        <button class="text-button" type="button" data-meeting-clear${progress.total ? '' : ' disabled'}>${tr('Réinitialiser le tableau', 'Reset the board')}</button>
      </div>
    </section>
    ${progress.total ? `
      <p class="meeting-help" id="meeting-help">${tr(
        'Glissez une carte vers une colonne, ou sélectionnez-la et tapez <kbd>1</kbd> à <kbd>5</kbd>. <kbd>Entrée</kbd> ouvre la fiche.',
        'Drag a card to a column, or select it and press <kbd>1</kbd> to <kbd>5</kbd>. <kbd>Enter</kbd> opens the card.',
      )}</p>
      <h2 class="sr-only">${tr('Tableau de réunion', 'Meeting board')}</h2>
      <div class="meeting-board">${meetingColumns.map((column) => renderColumn(board, column, resolve, collapsed)).join('')}</div>
    ` : renderEmpty()}
  `
}

const list = (values: string[]) => values.join(', ') || '—'

/** Le flux autorisé, lu de gauche à droite : interfaces, adresses, service. */
const renderFlow = (policy: FirewallPolicy): string => {
  const sources = [...policy.srcaddr, ...(policy.users ?? []), ...(policy.groups ?? [])]
  const extras = [
    policy.logtraffic ? `${tr('Journalisation', 'Logging')} ${policy.logtraffic}` : '',
    policy.nat === 'enable' ? tr('NAT activé', 'NAT enabled') : '',
    policy.schedule.length && policy.schedule.join() !== 'always' ? `${tr('Horaire', 'Schedule')} ${policy.schedule.join(', ')}` : '',
    policy.comments ? tr(`Commentaire « ${policy.comments} »`, `Comment “${policy.comments}”`) : '',
  ].filter(Boolean)
  const to = `<b aria-hidden="true">→</b><span class="sr-only">${tr('vers', 'to')}</span>`
  return `
    <dl class="focus-flow">
      <div><dt>Interfaces</dt><dd>${escapeHtml(list(policy.srcintf))} ${to} ${escapeHtml(list(policy.dstintf))}</dd></div>
      <div><dt>${tr('Adresses', 'Addresses')}</dt><dd>${escapeHtml(list(sources))} ${to} ${escapeHtml(list(policy.dstaddr))}</dd></div>
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
  if (current) return { glyph: '●', label: tr('en cours', 'current') }
  if (card.column === 'postpone') return { glyph: '↷', label: tr('reportée', 'postponed') }
  if (card.column !== 'discuss') return { glyph: '✓', label: `${tr('décidée', 'decided')}${colon()}${meetingColumnLabel(card.column).toLowerCase()}` }
  return { glyph: '', label: tr('à traiter', 'pending') }
}

/** Colonne « ordre du jour » : où en est la séance, et accès direct à n'importe quelle policy. */
const renderAgenda = (current: MeetingCard, queue: MeetingCard[], resolve: CardContextResolver): string => {
  const decided = queue.filter((card) => card.column !== 'discuss' && card.column !== 'postpone').length
  const groups = (['delete', 'modify', 'keep', 'none'] as const)
    .map((group) => ({ group, cards: queue.filter((card) => (card.proposal ?? 'none') === group) }))
    .filter(({ cards }) => cards.length)
  return `
    <nav class="focus-agenda" aria-label="${tr('Ordre du jour', 'Agenda')}">
      <p class="focus-agenda-title">${tr('Ordre du jour', 'Agenda')} <span>${decided}/${queue.length}</span></p>
      ${groups.map(({ group, cards }) => `
        <h4 class="${group}">${proposalGroupLabel(group)}</h4>
        <ol>
          ${cards.map((card) => {
            const isCurrent = card.policyKey === current.policyKey
            const status = agendaStatus(card, isCurrent)
            const policy = resolve(card).policy
            const hits = policy?.hitCount
            return `<li><button type="button" class="agenda-item ${card.column}${isCurrent ? ' current' : ''}" data-focus-goto="${escapeHtml(card.policyKey)}"
              ${isCurrent ? 'aria-current="step"' : ''} aria-label="${escapeHtml([ruleLabel(card), status.label, hits === undefined ? '' : formatHits(hits)].filter(Boolean).join(', '))}">
              <span class="agenda-status" aria-hidden="true">${status.glyph}</span>
              <span class="agenda-name" aria-hidden="true"><b>#${escapeHtml(card.policyId)}</b> ${escapeHtml(card.policyName)}</span>
              ${hits === undefined ? '' : `<span class="agenda-hits ${usageBand(policy)}" aria-hidden="true">${escapeHtml(hits >= 10000 ? `${Math.round(hits / 1000)}k` : String(hits))}</span>`}
            </button></li>`
          }).join('')}
        </ol>
      `).join('')}
    </nav>
  `
}

const proposalHeadline = (proposal: MeetingProposal | 'none'): string => ({
  delete: tr('Supprimer la règle', 'Delete the rule'),
  modify: tr('Modifier la règle', 'Modify the rule'),
  keep: tr('Conserver en l’état', 'Keep as is'),
  none: tr('Aucune proposition', 'No proposal'),
})[proposal]

/** Bloc coloré en tête de fiche : ce que la préparation propose, et l'argument d'usage qui le soutient. */
const renderProposal = (card: MeetingCard, context: MeetingCardContext): string => {
  const id = card.proposal ?? 'none'
  const severity = maxSeverity(context.findings)
  const count = context.findings.length
  const facts = [
    formatUsage(context.policy),
    count ? `${count} ${plural(count, ['constat', 'constats'], ['finding', 'findings'])}` : '',
    severity ? tr(`sévérité max. ${severityLabel(severity).toLowerCase()}`, `highest severity ${severityLabel(severity).toLowerCase()}`) : '',
  ].filter(Boolean)
  return `
    <section class="focus-proposal ${id}" aria-labelledby="focus-proposal-label">
      <div class="focus-proposal-head">
        <span id="focus-proposal-label">${tr('Proposition préparée', 'Prepared proposal')}</span>
        <label><span class="sr-only">${tr('Changer la proposition', 'Change the proposal')}</span>
          <select data-card-field="proposal">
            <option value=""${card.proposal ? '' : ' selected'}>${tr('Aucune', 'None')}</option>
            ${(['delete', 'modify', 'keep'] as const).map((proposal) => `<option value="${proposal}"${card.proposal === proposal ? ' selected' : ''}>${meetingColumnLabel(proposal)}</option>`).join('')}
          </select>
        </label>
      </div>
      <strong>${proposalHeadline(id)}</strong>
      ${facts.length ? `<p class="focus-proposal-facts">${escapeHtml(facts.join(' · '))}</p>` : ''}
      <label class="focus-proposal-note"><span class="sr-only">${tr('Note de préparation', 'Preparation note')}</span><textarea rows="2" data-card-field="prepNote" placeholder="${tr('Note de préparation : contexte, demandeur, ticket, trafic observé…', 'Preparation note: context, requester, ticket, observed traffic…')}">${escapeHtml(card.prepNote)}</textarea></label>
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
        <p class="eyebrow">${position.running ? tr('Séance', 'Meeting') : tr('Fiche', 'Card')} · ${tr(`policy ${index + 1} sur ${total}`, `policy ${index + 1} of ${total}`)}</p>
        <span class="focus-column ${card.column}">${meetingColumnLabel(card.column)}</span>
      </div>
      <div class="focus-nav">
        <button class="icon-button" type="button" data-focus-step="-1" aria-label="${tr('Policy précédente', 'Previous policy')}" title="${tr('Précédente (←)', 'Previous (←)')}"${index > 0 ? '' : ' disabled'}><i data-lucide="chevron-left"></i></button>
        <button class="icon-button" type="button" data-focus-step="1" aria-label="${tr('Policy suivante', 'Next policy')}" title="${tr('Suivante (→)', 'Next (→)')}"${index < total - 1 ? '' : ' disabled'}><i data-lucide="chevron-right"></i></button>
        <button class="icon-button" type="button" data-focus-close aria-label="${tr('Fermer', 'Close')}" title="${tr('Fermer (Échap)', 'Close (Esc)')}"><i data-lucide="x"></i></button>
      </div>
    </header>
    <div class="focus-body">
      ${renderAgenda(card, position.queue, resolve)}
      <div class="focus-main">
        <div class="focus-title">
          <h2 id="focus-title">${escapeHtml(card.policyName)}</h2>
          <p class="focus-location">${tr('Règle', 'Rule')} #${escapeHtml(card.policyId)}${location ? ` · ${escapeHtml(location)}` : ''}</p>
        </div>
        ${card.orphan ? `<p class="meeting-card-warning">${tr('Cette policy n’existe plus dans la configuration chargée.', 'This policy no longer exists in the loaded configuration.')}</p>` : ''}
        ${renderProposal(card, context)}
        ${context.policy ? renderFlow(context.policy) : ''}
        <section class="focus-findings" aria-labelledby="focus-findings-title">
          <h3 id="focus-findings-title">${tr('Constats', 'Findings')} (${context.findings.length})</h3>
          ${context.findings.map((finding) => `
            <details class="focus-finding">
              <summary><span class="severity-badge ${finding.severity}">${severityLabel(finding.severity)}</span><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(categoryLabel(finding.category))}</small></summary>
              <p>${escapeHtml(finding.detail)}</p>
              ${renderRecommendation(finding.recommendation)}
            </details>
          `).join('') || `<p class="overview-note">${tr('Aucun constat ouvert sur cette policy.', 'No open finding on this policy.')}</p>`}
        </section>
      </div>
      <section class="focus-decision" aria-labelledby="focus-decision-title">
        <h3 class="sr-only" id="focus-decision-title">${tr('Décision', 'Decision')}</h3>
        <div class="decision-buttons" role="group" aria-labelledby="focus-decision-title">
          ${decisionColumns.map((column) => `
            <button type="button" class="decision-button ${column}" data-decide="${column}" aria-pressed="${card.column === column}" aria-keyshortcuts="${keyForColumn(column)}">
              <span>${meetingColumnLabel(column)}${card.proposal === column ? `<small>${tr('proposé', 'proposed')}</small>` : ''}</span><kbd aria-hidden="true">${keyForColumn(column)}</kbd>
            </button>
          `).join('')}
          ${card.column !== 'discuss' ? `<button class="text-button" type="button" data-decide="discuss">${tr('Remettre à discuter', 'Move back to discussion')}</button>` : ''}
        </div>
        <div class="decision-fields">
          <label class="dialog-field">${tr('Justification', 'Rationale')}<textarea rows="2" ${field('rationale')} placeholder="${tr('Pourquoi cette décision ? Ex. : flux ERP encore utilisé, à restreindre à 10.20.4.0/24.', 'Why this decision? E.g. ERP flow still in use, restrict it to 10.20.4.0/24.')}">${escapeHtml(card.rationale)}</textarea></label>
          <label class="dialog-field">${tr('Échéance', 'Due date')}<input type="date" ${field('dueDate')} value="${escapeHtml(card.dueDate)}" /></label>
        </div>
      </section>
    </div>
  `
}
