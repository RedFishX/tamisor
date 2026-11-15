import type { AuditResult, Finding } from './audit'
import { colon, severityLabel } from './labels'
import { formatUsage } from './policy-usage'
import { boardProgress, cardsInColumn, findingsForCard, meetingColumnLabel, policyForCard, type MeetingBoard, type MeetingCard, type MeetingColumn } from './meeting'
import { plural, tr } from '../i18n'

/** Ordre des sections du compte rendu : décisions d'abord, puis ce qui reste ouvert. */
export const minutesSections = (): Array<{ column: MeetingColumn, heading: string }> => [
  { column: 'delete', heading: tr('À supprimer', 'To delete') },
  { column: 'modify', heading: tr('À modifier', 'To modify') },
  { column: 'keep', heading: tr('Conservées', 'Kept') },
  { column: 'postpone', heading: tr('Reportées', 'Postponed') },
  { column: 'discuss', heading: tr('Non traitées', 'Not discussed') },
]

/** Neutralise le HTML brut que certains rendus Markdown interprètent, et aplatit les retours à la ligne. */
const inline = (value: string): string => value.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\s*\n\s*/g, ' ').trim()

const multiline = (value: string): string => value.trim().split(/\r?\n/).map((line) => `  > ${inline(line)}`).join('\n')

export const formatDuration = (startedAt?: string, endedAt?: string): string | undefined => {
  if (!startedAt || !endedAt) return undefined
  const minutes = Math.round((Date.parse(endedAt) - Date.parse(startedAt)) / 60000)
  if (!Number.isFinite(minutes) || minutes < 0) return undefined
  const hours = Math.floor(minutes / 60)
  return hours ? `${hours} h ${String(minutes % 60).padStart(2, '0')}` : `${minutes} min`
}

export const cardLocation = (card: MeetingCard, order?: number): string => [
  card.vdom ? `VDOM ${card.vdom}` : undefined,
  card.family === 'ipv6' ? 'IPv6' : undefined,
  order !== undefined ? `seq ${order}` : undefined,
].filter(Boolean).join(', ')

const findingLine = (finding: Finding): string => `${severityLabel(finding.severity)} · ${inline(finding.title)}`

const renderCard = (card: MeetingCard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const policy = policyForCard(audit, card)
  const findings = findingsForCard(audit, card)
  const location = cardLocation(card, policy?.order)
  const c = colon()
  const lines = [`### ${tr('Règle', 'Rule')} #${inline(card.policyId)} · ${inline(card.policyName)}${location ? ` (${inline(location)})` : ''}`, '']
  if (card.orphan) lines.push(`- **${tr('Attention', 'Warning')}**${c}${tr('policy absente de la configuration chargée.', 'policy missing from the loaded configuration.')}`)
  if (findings.length) lines.push(`- ${tr('Constats', 'Findings')}${c}${findings.map(findingLine).join(tr(' ; ', '; '))}`)
  const usage = formatUsage(policy)
  if (usage) lines.push(`- ${tr('Utilisation', 'Usage')}${c}${inline(usage)}`)
  if (card.proposal) lines.push(`- ${tr('Proposition initiale', 'Initial proposal')}${c}${meetingColumnLabel(card.proposal)}`)
  if (card.rationale.trim()) lines.push(`- ${tr('Justification', 'Rationale')}${c}${inline(card.rationale)}`)
  if (card.dueDate) lines.push(`- ${tr('Échéance', 'Due date')}${c}${card.dueDate}`)
  if (card.prepNote.trim()) lines.push(`- ${tr('Notes de préparation', 'Preparation notes')}${c.trimEnd()}`, multiline(card.prepNote))
  return lines.join('\n')
}

export const renderMinutesMarkdown = (board: MeetingBoard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const progress = boardProgress(board)
  const duration = formatDuration(board.startedAt, board.endedAt)
  const c = colon()
  const { byColumn } = progress
  const header = [
    `# ${inline(board.title)}`,
    '',
    `- Date${c}${board.date}`,
    `- Configuration${c}${inline(board.sourceName)}`,
    `- Participants${c}${board.participants.length ? board.participants.map(inline).join(', ') : tr('non renseignés', 'not specified')}`,
    ...(duration ? [`- ${tr('Durée', 'Duration')}${c}${duration}`] : []),
    '',
    tr(
      `**Synthèse** : ${progress.total} ${plural(progress.total, ['policy inscrite', 'policies inscrites'], ['', ''])} ; ${byColumn.delete} à supprimer, ${byColumn.modify} à modifier, `
        + `${byColumn.keep} ${plural(byColumn.keep, ['conservée', 'conservées'], ['', ''])}, ${byColumn.postpone} ${plural(byColumn.postpone, ['reportée', 'reportées'], ['', ''])}, `
        + `${byColumn.discuss} ${plural(byColumn.discuss, ['non traitée', 'non traitées'], ['', ''])}.`,
      `**Summary**: ${progress.total} ${plural(progress.total, ['', ''], ['policy', 'policies'])} on the agenda; ${byColumn.delete} to delete, ${byColumn.modify} to modify, `
        + `${byColumn.keep} kept, ${byColumn.postpone} postponed, ${byColumn.discuss} not discussed.`,
    ),
  ]
  const sections = minutesSections()
    .map(({ column, heading }) => ({ heading, cards: cardsInColumn(board, column) }))
    .filter(({ cards }) => cards.length)
    .map(({ heading, cards }) => [`## ${heading} (${cards.length})`, '', cards.map((card) => renderCard(card, audit)).join('\n\n')].join('\n'))
  return [header.join('\n'), ...sections].join('\n\n') + '\n'
}
