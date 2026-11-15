import type { AuditResult, Finding, FirewallPolicy, Severity } from './audit'
import { tr } from '../i18n'

/** Colonnes du tableau de réunion : une colonne d'entrée et quatre issues possibles. */
export type MeetingColumn = 'discuss' | 'delete' | 'modify' | 'keep' | 'postpone'
export type MeetingProposal = 'delete' | 'modify' | 'keep'

export const meetingColumns: MeetingColumn[] = ['discuss', 'delete', 'modify', 'keep', 'postpone']
export const decisionColumns: MeetingColumn[] = ['delete', 'modify', 'keep', 'postpone']

export const meetingColumnLabel = (column: MeetingColumn): string => ({
  discuss: tr('À discuter', 'To discuss'),
  delete: tr('Supprimer', 'Delete'),
  modify: tr('Modifier', 'Modify'),
  keep: tr('Conserver', 'Keep'),
  postpone: tr('Reporter', 'Postpone'),
})[column]

export interface MeetingCard {
  policyKey: string
  policyId: string
  vdom?: string
  family?: 'ipv4' | 'ipv6'
  policyName: string
  column: MeetingColumn
  proposal?: MeetingProposal
  prepNote: string
  rationale: string
  dueDate: string
  /** Position dans la colonne. */
  order: number
  /** Policy absente de la configuration actuellement chargée (supprimée ou renumérotée). */
  orphan?: boolean
}

export interface MeetingBoard {
  version: 1
  sourceName: string
  title: string
  date: string
  participants: string[]
  cards: MeetingCard[]
  startedAt?: string
  endedAt?: string
}

type PolicyRef = { id?: string, policyId?: string, vdom?: string, family?: 'ipv4' | 'ipv6' }

/** Clé stable d'une policy, identique pour la policy et ses constats ; VDOM et famille IP la distinguent. */
export const policyKey = (reference: PolicyRef): string =>
  `${reference.vdom ?? 'global'}|${reference.family ?? 'ipv4'}|${reference.policyId ?? reference.id ?? ''}`

const today = (): string => new Date().toISOString().slice(0, 10)

export const createBoard = (sourceName: string, date = today()): MeetingBoard => ({
  version: 1,
  sourceName,
  title: tr(`Revue des règles · ${sourceName}`, `Rule review · ${sourceName}`),
  date,
  participants: [],
  cards: [],
})

const deleteCategories: Finding['category'][] = ['shadowed', 'duplicate', 'unused']
const modifyCategories: Finding['category'][] = ['permissive', 'exposure', 'visibility', 'security', 'inspection', 'overlap', 'temporary', 'governance', 'object']

/** Pré-remplit une proposition à partir des constats ; elle reste modifiable. */
export const suggestProposal = (findings: Pick<Finding, 'category'>[]): MeetingProposal | undefined => {
  if (findings.some((finding) => deleteCategories.includes(finding.category))) return 'delete'
  if (findings.some((finding) => modifyCategories.includes(finding.category))) return 'modify'
  return undefined
}

const nextOrder = (board: MeetingBoard, column: MeetingColumn): number =>
  board.cards.filter((card) => card.column === column).reduce((max, card) => Math.max(max, card.order + 1), 0)

/** Les constats « Objets » portent sur des adresses ou services orphelins, pas sur une policy : ils restent hors réunion. */
export const isPolicyFinding = (finding: Pick<Finding, 'category'>): boolean => finding.category !== 'object'

const severityRank: Severity[] = ['critical', 'high', 'medium', 'low']
const proposalRank = (proposal?: MeetingProposal) => proposal ? ['delete', 'modify', 'keep'].indexOf(proposal) : 3

export interface PriorityInput {
  proposal?: MeetingProposal
  severity?: Severity
  hitCount?: number
  order: number
}

/**
 * Ordre de préparation : par proposition (supprimer, modifier, conserver, sans), puis hit count croissant
 * (les règles jamais utilisées d'abord, compteur inconnu en dernier), puis sévérité décroissante, puis séquence.
 */
export const comparePriority = (a: PriorityInput, b: PriorityInput): number =>
  proposalRank(a.proposal) - proposalRank(b.proposal)
  || (a.hitCount ?? Number.POSITIVE_INFINITY) - (b.hitCount ?? Number.POSITIVE_INFINITY)
  || (a.severity ? severityRank.indexOf(a.severity) : 4) - (b.severity ? severityRank.indexOf(b.severity) : 4)
  || a.order - b.order

/** Ajoute une carte par policy distincte, rangée par priorité, en ignorant celles déjà présentes. */
export const addPolicies = (board: MeetingBoard, findings: Finding[], policies: FirewallPolicy[] = []): MeetingBoard => {
  const existing = new Set(board.cards.map((card) => card.policyKey))
  const byPolicy = new Map<string, Finding[]>()
  for (const finding of findings.filter(isPolicyFinding)) {
    const key = policyKey(finding)
    if (existing.has(key)) continue
    byPolicy.set(key, [...(byPolicy.get(key) ?? []), finding])
  }
  let order = nextOrder(board, 'discuss')
  const hitCounts = new Map(policies.map((policy) => [policyKey(policy), policy.hitCount]))
  const priority = ([key, related]: [string, Finding[]]): PriorityInput => ({
    proposal: suggestProposal(related), severity: maxSeverity(related), hitCount: hitCounts.get(key), order: related[0].order,
  })
  const added = [...byPolicy.entries()]
    .sort((a, b) => comparePriority(priority(a), priority(b)))
    .map(([key, related]): MeetingCard => ({
      policyKey: key,
      policyId: related[0].policyId,
      vdom: related[0].vdom,
      family: related[0].family,
      policyName: related[0].policyName,
      column: 'discuss',
      proposal: suggestProposal(related),
      prepNote: '',
      rationale: '',
      dueDate: '',
      order: order++,
    }))
  return added.length ? { ...board, cards: [...board.cards, ...added] } : board
}

export const hasCard = (board: MeetingBoard, key: string): boolean => board.cards.some((card) => card.policyKey === key)

export const cardsInColumn = (board: MeetingBoard, column: MeetingColumn): MeetingCard[] =>
  board.cards.filter((card) => card.column === column).sort((a, b) => a.order - b.order)

const renumber = (cards: MeetingCard[]): MeetingCard[] => cards.map((card, order) => ({ ...card, order }))

export const removeCard = (board: MeetingBoard, key: string): MeetingBoard =>
  ({ ...board, cards: board.cards.filter((card) => card.policyKey !== key) })

/** Déplace une carte vers une colonne, à une position donnée (fin de colonne par défaut). */
export const moveCard = (board: MeetingBoard, key: string, column: MeetingColumn, index?: number): MeetingBoard => {
  const card = board.cards.find((candidate) => candidate.policyKey === key)
  if (!card) return board
  const source = card.column
  const target = cardsInColumn(board, column).filter((candidate) => candidate.policyKey !== key)
  const position = index === undefined ? target.length : Math.min(Math.max(index, 0), target.length)
  target.splice(position, 0, { ...card, column })
  const updated = new Map(renumber(target).map((candidate) => [candidate.policyKey, candidate]))
  if (source !== column) {
    for (const candidate of renumber(cardsInColumn(board, source).filter((other) => other.policyKey !== key))) {
      updated.set(candidate.policyKey, candidate)
    }
  }
  return { ...board, cards: board.cards.map((candidate) => updated.get(candidate.policyKey) ?? candidate) }
}

export type MeetingCardPatch = Partial<Pick<MeetingCard, 'proposal' | 'prepNote' | 'rationale' | 'dueDate'>>

export const updateCard = (board: MeetingBoard, key: string, patch: MeetingCardPatch): MeetingBoard =>
  ({ ...board, cards: board.cards.map((card) => card.policyKey === key ? { ...card, ...patch } : card) })

export interface BoardProgress {
  total: number
  decided: number
  byColumn: Record<MeetingColumn, number>
}

export const boardProgress = (board: MeetingBoard): BoardProgress => {
  const byColumn = Object.fromEntries(meetingColumns.map((column) => [column, 0])) as Record<MeetingColumn, number>
  for (const card of board.cards) byColumn[card.column] += 1
  return { total: board.cards.length, decided: board.cards.length - byColumn.discuss - byColumn.postpone, byColumn }
}

/** Sous-groupes de « À discuter » : la préparation range chaque policy selon la proposition à défendre en séance. */
export const discussGroupOrder: Array<MeetingProposal | undefined> = ['delete', 'modify', 'keep', undefined]

export const discussGroups = (board: MeetingBoard): Array<{ proposal?: MeetingProposal, cards: MeetingCard[] }> => {
  const cards = cardsInColumn(board, 'discuss')
  return discussGroupOrder.map((proposal) => ({ proposal, cards: cards.filter((card) => card.proposal === proposal) }))
}

/** Dépose une carte dans un sous-groupe de « À discuter » : la position est relative au groupe et fixe la proposition. */
export const moveToDiscussGroup = (board: MeetingBoard, key: string, proposal: MeetingProposal | undefined, indexInGroup?: number): MeetingBoard => {
  const withProposal = { ...board, cards: board.cards.map((card) => card.policyKey === key ? { ...card, proposal } : card) }
  const discuss = cardsInColumn(withProposal, 'discuss').filter((card) => card.policyKey !== key)
  const group = discuss.filter((card) => card.proposal === proposal)
  const anchor = indexInGroup === undefined ? undefined : group[indexInGroup]
  const index = anchor ? discuss.indexOf(anchor) : group.length ? discuss.indexOf(group[group.length - 1]) + 1 : discuss.length
  return moveCard(withProposal, key, 'discuss', index)
}

/** Réordonne « À discuter » par priorité (voir `comparePriority`). */
export const sortDiscussByPriority = (board: MeetingBoard, audit: Pick<AuditResult, 'policies' | 'findings'>): MeetingBoard => {
  const priority = (card: MeetingCard): PriorityInput => ({
    proposal: card.proposal,
    severity: maxSeverity(findingsForCard(audit, card)),
    hitCount: policyForCard(audit, card)?.hitCount,
    order: policyForCard(audit, card)?.order ?? Number.MAX_SAFE_INTEGER,
  })
  const sorted = cardsInColumn(board, 'discuss').sort((a, b) => comparePriority(priority(a), priority(b)))
  const orders = new Map(sorted.map((card, order) => [card.policyKey, order]))
  return { ...board, cards: board.cards.map((card) => orders.has(card.policyKey) ? { ...card, order: orders.get(card.policyKey)! } : card) }
}

/** Ordre de passage en séance : « À discuter » groupe par groupe, puis les cartes reportées. */
export const agenda = (board: MeetingBoard): MeetingCard[] => [...discussGroups(board).flatMap((group) => group.cards), ...cardsInColumn(board, 'postpone')]

export const policyForCard = (audit: Pick<AuditResult, 'policies'>, card: MeetingCard): FirewallPolicy | undefined =>
  audit.policies.find((policy) => policyKey(policy) === card.policyKey)

export const findingsForCard = (audit: Pick<AuditResult, 'findings'>, card: MeetingCard): Finding[] =>
  audit.findings.filter((finding) => policyKey(finding) === card.policyKey)

export const maxSeverity = (findings: Pick<Finding, 'severity'>[]): Severity | undefined =>
  severityRank.find((severity) => findings.some((finding) => finding.severity === severity))

const untouched = (card: MeetingCard): boolean => card.column === 'discuss'
  && ![card.prepNote, card.rationale, card.dueDate].some((value) => value.trim())

/**
 * Le tableau reflète les constats ouverts : chaque policy concernée y figure. Une carte encore vierge
 * (À discuter, sans note) disparaît quand sa policy n'a plus de constat ouvert, par exemple après un acquittement.
 */
export const syncBoard = (board: MeetingBoard, openFindings: Finding[], policies: FirewallPolicy[]): MeetingBoard => {
  const openKeys = new Set(openFindings.filter(isPolicyFinding).map(policyKey))
  const stale = board.cards.filter((card) => !openKeys.has(card.policyKey) && untouched(card))
  const pruned = stale.length ? stale.reduce((next, card) => removeCard(next, card.policyKey), board) : board
  return addPolicies(pruned, openFindings, policies)
}

/** Marque les cartes dont la policy n'existe plus dans la configuration chargée ; ne supprime rien. */
export const reconcileBoard = (board: MeetingBoard, audit: Pick<AuditResult, 'policies'>): MeetingBoard => {
  const keys = new Set(audit.policies.map(policyKey))
  return {
    ...board,
    cards: board.cards.map((card) => {
      const policy = audit.policies.find((candidate) => policyKey(candidate) === card.policyKey)
      const orphan = !keys.has(card.policyKey)
      return { ...card, orphan: orphan || undefined, policyName: policy?.name ?? card.policyName }
    }),
  }
}
