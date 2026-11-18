import { describe, expect, it } from 'vitest'
import { meetingFinding as finding } from '../test-fixtures/meeting-fixtures'
import { addPolicies, createBoard } from '../domain/meeting'
import { createMeetingStore, meetingStorageKey, parseBoard, serializeBoard } from './meeting-store'

const memoryStorage = () => {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) },
    values,
  }
}

describe('meeting store', () => {
  it('conserve un tableau par fichier de configuration', () => {
    const storage = memoryStorage()
    const store = createMeetingStore(storage)
    const board = addPolicies(createBoard('fw-siege.conf'), [finding({})])
    store.save(board)
    expect(storage.values.has(meetingStorageKey('fw-siege.conf'))).toBe(true)
    expect(store.load('fw-siege.conf')).toEqual(board)
    expect(store.load('fw-agence.conf')).toBeNull()
    store.clear('fw-siege.conf')
    expect(store.load('fw-siege.conf')).toBeNull()
  })

  it('rejette un contenu invalide et écarte les cartes mal formées', () => {
    expect(parseBoard('{pas du json')).toBeNull()
    expect(parseBoard(JSON.stringify({ version: 2 }))).toBeNull()
    const board = addPolicies(createBoard('fw.conf'), [finding({})])
    const tampered = JSON.parse(serializeBoard(board))
    tampered.cards.push({ policyKey: 'x', column: 'ailleurs' })
    expect(parseBoard(JSON.stringify(tampered))?.cards).toHaveLength(1)
  })

  it('relit un tableau enregistré avant le retrait des notes de séance et du responsable', () => {
    const board = addPolicies(createBoard('fw.conf'), [finding({})])
    const legacy = JSON.parse(serializeBoard(board))
    legacy.cards[0] = { ...legacy.cards[0], meetingNote: 'Validé en CAB', owner: 'Équipe réseau' }
    const card = parseBoard(JSON.stringify(legacy))!.cards[0]
    expect(card).not.toHaveProperty('meetingNote')
    expect(card).not.toHaveProperty('owner')
  })

  it('ne lève pas d’erreur si le stockage est bloqué', () => {
    const store = createMeetingStore({
      getItem: () => { throw new Error('bloqué') },
      setItem: () => { throw new Error('bloqué') },
      removeItem: () => { throw new Error('bloqué') },
    })
    expect(store.load('fw.conf')).toBeNull()
    expect(() => store.save(createBoard('fw.conf'))).not.toThrow()
  })

  describe('clé des cartes', () => {
    const boardWith = (cards: Array<Record<string, unknown>>) => JSON.stringify({
      ...JSON.parse(serializeBoard(createBoard('fw.conf'))),
      cards: cards.map((card, order) => ({ policyName: 'P', column: 'discuss', prepNote: '', rationale: '', dueDate: '', order, ...card })),
    })

    it('laisse intactes les clés ordinaires d’un tableau déjà enregistré', () => {
      const board = parseBoard(boardWith([{ policyKey: 'root|ipv4|10', policyId: '10', vdom: 'root', family: 'ipv4' }]))
      expect(board?.cards[0].policyKey).toBe('root|ipv4|10')
    })

    it('migre l’ancienne clé ambiguë d’un id contenant « | » et recalcule toujours depuis VDOM, famille et id', () => {
      const board = parseBoard(boardWith([
        { policyKey: 'global|ipv4|a|b', policyId: 'a|b' },
        { policyKey: 'clé-inventée', policyId: '5', vdom: 'dmz' },
      ]))
      expect(board?.cards.map((card) => card.policyKey)).toEqual(['global|ipv4|a%7Cb', 'dmz|ipv4|5'])
    })

    it('écarte un doublon de clé après recalcul', () => {
      const board = parseBoard(boardWith([{ policyKey: 'a', policyId: '1' }, { policyKey: 'b', policyId: '1' }]))
      expect(board?.cards).toHaveLength(1)
    })

    it('est idempotent', () => {
      const once = parseBoard(boardWith([{ policyKey: 'x', policyId: 'a|b' }]))!
      expect(parseBoard(serializeBoard(once))).toEqual(once)
    })
  })
})
