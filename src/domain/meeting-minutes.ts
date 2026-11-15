import type { AuditResult, Finding, Severity } from './audit'
import { formatUsage } from './policy-usage'
import { boardProgress, cardsInColumn, findingsForCard, meetingColumnLabels, policyForCard, type MeetingBoard, type MeetingCard, type MeetingColumn } from './meeting'

const severityLabels: Record<Severity, string> = { critical: 'Critique', high: 'Élevée', medium: 'Moyenne', low: 'Faible' }

/** Ordre des sections du compte rendu : décisions d'abord, puis ce qui reste ouvert. */
export const minutesSections: Array<{ column: MeetingColumn, heading: string }> = [
  { column: 'delete', heading: 'À supprimer' },
  { column: 'modify', heading: 'À modifier' },
  { column: 'keep', heading: 'Conservées' },
  { column: 'postpone', heading: 'Reportées' },
  { column: 'discuss', heading: 'Non traitées' },
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

const findingLine = (finding: Finding): string => `${severityLabels[finding.severity]} · ${inline(finding.title)}`

const renderCard = (card: MeetingCard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const policy = policyForCard(audit, card)
  const findings = findingsForCard(audit, card)
  const location = cardLocation(card, policy?.order)
  const lines = [`### Règle #${inline(card.policyId)} · ${inline(card.policyName)}${location ? ` (${inline(location)})` : ''}`, '']
  if (card.orphan) lines.push('- **Attention** : policy absente de la configuration chargée.')
  if (findings.length) lines.push(`- Constats : ${findings.map(findingLine).join(' ; ')}`)
  const usage = formatUsage(policy)
  if (usage) lines.push(`- Utilisation : ${inline(usage)}`)
  if (card.proposal) lines.push(`- Proposition initiale : ${meetingColumnLabels[card.proposal]}`)
  if (card.rationale.trim()) lines.push(`- Justification : ${inline(card.rationale)}`)
  if (card.dueDate) lines.push(`- Échéance : ${card.dueDate}`)
  if (card.prepNote.trim()) lines.push('- Notes de préparation :', multiline(card.prepNote))
  return lines.join('\n')
}

export const renderMinutesMarkdown = (board: MeetingBoard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const progress = boardProgress(board)
  const duration = formatDuration(board.startedAt, board.endedAt)
  const header = [
    `# ${inline(board.title)}`,
    '',
    `- Date : ${board.date}`,
    `- Configuration : ${inline(board.sourceName)}`,
    `- Participants : ${board.participants.length ? board.participants.map(inline).join(', ') : 'non renseignés'}`,
    ...(duration ? [`- Durée : ${duration}`] : []),
    '',
    `**Synthèse** : ${progress.total} policy(s) inscrite(s) ; ${progress.byColumn.delete} à supprimer, ${progress.byColumn.modify} à modifier, `
      + `${progress.byColumn.keep} conservée(s), ${progress.byColumn.postpone} reportée(s), ${progress.byColumn.discuss} non traitée(s).`,
  ]
  const sections = minutesSections
    .map(({ column, heading }) => ({ heading, cards: cardsInColumn(board, column) }))
    .filter(({ cards }) => cards.length)
    .map(({ heading, cards }) => [`## ${heading} (${cards.length})`, '', cards.map((card) => renderCard(card, audit)).join('\n\n')].join('\n'))
  return [header.join('\n'), ...sections].join('\n\n') + '\n'
}
