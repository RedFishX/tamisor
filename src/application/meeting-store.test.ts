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
})
