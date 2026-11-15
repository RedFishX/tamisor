import { meetingColumns, type MeetingBoard, type MeetingCard } from '../domain/meeting'

/** Stockage clé/valeur minimal (compatible `localStorage`), injecté pour rester testable. */
export interface KeyValueStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export const meetingStorageKey = (sourceName: string): string => `fortiscope-meeting:${sourceName}`

const isString = (value: unknown): value is string => typeof value === 'string'
const optionalString = (value: unknown): boolean => value === undefined || isString(value)

const isCard = (value: unknown): value is MeetingCard => {
  if (!value || typeof value !== 'object') return false
  const card = value as Partial<MeetingCard>
  return isString(card.policyKey) && isString(card.policyId) && isString(card.policyName)
    && meetingColumns.includes(card.column as MeetingCard['column'])
    && (card.proposal === undefined || ['delete', 'modify', 'keep'].includes(card.proposal))
    && isString(card.prepNote) && isString(card.rationale) && isString(card.dueDate) && typeof card.order === 'number'
    && optionalString(card.vdom) && (card.family === undefined || card.family === 'ipv4' || card.family === 'ipv6')
}

export const serializeBoard = (board: MeetingBoard): string => JSON.stringify(board)

/** Relit un tableau ; renvoie `null` si le contenu est absent ou invalide. Les cartes mal formées sont écartées. */
export const parseBoard = (content: string | null): MeetingBoard | null => {
  if (!content) return null
  let parsed: unknown
  try { parsed = JSON.parse(content) } catch { return null }
  if (!parsed || typeof parsed !== 'object') return null
  const board = parsed as Partial<MeetingBoard>
  if (board.version !== 1 || !isString(board.sourceName) || !isString(board.title) || !isString(board.date)
    || !Array.isArray(board.participants) || !Array.isArray(board.cards)) return null
  return {
    version: 1,
    sourceName: board.sourceName,
    title: board.title,
    date: board.date,
    participants: board.participants.filter(isString),
    // Les anciens champs « notes de séance » et « responsable » des tableaux déjà enregistrés sont ignorés.
    cards: board.cards.filter(isCard).map(({ meetingNote: _meetingNote, owner: _owner, ...card }: MeetingCard & { meetingNote?: unknown, owner?: unknown }) => ({ ...card, orphan: undefined })),
    startedAt: isString(board.startedAt) ? board.startedAt : undefined,
    endedAt: isString(board.endedAt) ? board.endedAt : undefined,
  }
}

export interface MeetingStore {
  load(sourceName: string): MeetingBoard | null
  save(board: MeetingBoard): void
  clear(sourceName: string): void
}

export const createMeetingStore = (storage: KeyValueStorage): MeetingStore => ({
  load: (sourceName) => {
    try { return parseBoard(storage.getItem(meetingStorageKey(sourceName))) } catch { return null }
  },
  save: (board) => {
    try { storage.setItem(meetingStorageKey(board.sourceName), serializeBoard(board)) } catch { /* stockage plein ou bloqué */ }
  },
  clear: (sourceName) => {
    try { storage.removeItem(meetingStorageKey(sourceName)) } catch { /* stockage bloqué */ }
  },
})
