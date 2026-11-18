import { describe, expect, it } from 'vitest'
import { meetingFinding as finding, meetingPolicy as policy } from '../test-fixtures/meeting-fixtures'
import {
  addPolicies, agenda, boardProgress, cardsInColumn, comparePriority, createBoard, discussGroups, moveCard, moveToDiscussGroup, policyKey,
  reconcileBoard, removeCard, sortDiscussByPriority, suggestProposal, syncBoard, updateCard,
} from './meeting'

describe('addPolicies', () => {
  it('crée une seule carte par policy, même avec plusieurs constats', () => {
    const board = addPolicies(createBoard('fw.conf'), [
      finding({ category: 'permissive' }),
      finding({ category: 'visibility' }),
      finding({ policyId: '7', policyName: 'DMZ_vers_WAN', order: 2, category: 'unused' }),
    ])
    expect(board.cards).toHaveLength(2)
    expect(board.cards.map((card) => card.policyId)).toEqual(['7', '12'])
    expect(board.cards.map((card) => card.proposal)).toEqual(['delete', 'modify'])
    expect(board.cards.every((card) => card.column === 'discuss')).toBe(true)
  })

  it('distingue la même policy dans deux VDOM ou deux familles IP', () => {
    const board = addPolicies(createBoard('fw.conf'), [
      finding({ vdom: 'root' }),
      finding({ vdom: 'dmz' }),
      finding({ vdom: 'root', family: 'ipv6' }),
    ])
    expect(board.cards).toHaveLength(3)
  })

  it('ignore les constats sur des objets, qui ne sont pas des policies', () => {
    expect(addPolicies(createBoard('fw.conf'), [finding({ category: 'object', policyId: 'object:address:SRV_OLD' })]).cards).toHaveLength(0)
  })

  it('n’ajoute pas deux fois une policy déjà inscrite', () => {
    const once = addPolicies(createBoard('fw.conf'), [finding({})])
    expect(addPolicies(once, [finding({ category: 'security' })])).toBe(once)
  })

  it('aligne la clé d’une policy sur celle de ses constats', () => {
    expect(policyKey(policy({ vdom: 'root' }))).toBe(policyKey(finding({ vdom: 'root' })))
  })
})

describe('suggestProposal', () => {
  it('propose la suppression pour une règle masquée, doublon ou inutilisée', () => {
    expect(suggestProposal([finding({ category: 'permissive' }), finding({ category: 'shadowed' })])).toBe('delete')
  })
  it('propose la modification pour une règle permissive', () => {
    expect(suggestProposal([finding({ category: 'permissive' })])).toBe('modify')
  })
  it('ne propose rien pour un constat à valider', () => {
    expect(suggestProposal([finding({ category: 'indeterminate' })])).toBeUndefined()
  })
})

describe('moveCard', () => {
  const board = addPolicies(createBoard('fw.conf'), [
    finding({ policyId: '1', order: 1 }), finding({ policyId: '2', order: 2 }), finding({ policyId: '3', order: 3 }),
  ])
  const key = (id: string) => board.cards.find((card) => card.policyId === id)!.policyKey

  it('déplace vers une colonne et renumérote la colonne d’origine', () => {
    const moved = moveCard(board, key('1'), 'delete')
    expect(cardsInColumn(moved, 'delete').map((card) => card.policyId)).toEqual(['1'])
    expect(cardsInColumn(moved, 'discuss').map((card) => [card.policyId, card.order])).toEqual([['2', 0], ['3', 1]])
  })

  it('réordonne à l’intérieur d’une colonne', () => {
    const moved = moveCard(board, key('3'), 'discuss', 0)
    expect(cardsInColumn(moved, 'discuss').map((card) => card.policyId)).toEqual(['3', '1', '2'])
  })

  it('compte les décisions sans les cartes reportées', () => {
    const decided = moveCard(moveCard(board, key('1'), 'delete'), key('2'), 'postpone')
    expect(boardProgress(decided)).toMatchObject({ total: 3, decided: 1, byColumn: { delete: 1, postpone: 1, discuss: 1 } })
    expect(agenda(decided).map((card) => card.policyId)).toEqual(['3', '2'])
  })

  it('met à jour et retire une carte', () => {
    const updated = updateCard(board, key('2'), { rationale: 'Flux ERP encore utilisé' })
    expect(updated.cards.find((card) => card.policyId === '2')?.rationale).toBe('Flux ERP encore utilisé')
    expect(removeCard(updated, key('2')).cards).toHaveLength(2)
  })
})

describe('reconcileBoard', () => {
  it('signale les policies disparues sans les retirer', () => {
    const board = addPolicies(createBoard('fw.conf'), [finding({ policyId: '12' }), finding({ policyId: '40' })])
    const reconciled = reconcileBoard(board, { policies: [policy({ id: '12', name: 'LAN_vers_ERP_v2' })] })
    expect(reconciled.cards).toHaveLength(2)
    expect(reconciled.cards.find((card) => card.policyId === '40')?.orphan).toBe(true)
    expect(reconciled.cards.find((card) => card.policyId === '12')).toMatchObject({ orphan: undefined, policyName: 'LAN_vers_ERP_v2' })
  })
})

describe('priorité de préparation', () => {
  it('classe par proposition, hit count croissant (inconnu en dernier) puis sévérité', () => {
    const items = [
      { proposal: 'modify' as const, severity: 'critical' as const, order: 1 },
      { proposal: 'delete' as const, severity: 'low' as const, hitCount: 500, order: 2 },
      { proposal: 'delete' as const, severity: 'low' as const, hitCount: 0, order: 3 },
      { proposal: 'delete' as const, severity: 'low' as const, order: 4 },
      { proposal: 'delete' as const, severity: 'high' as const, hitCount: 9000, order: 5 },
    ]
    expect([...items].sort(comparePriority).map((item) => item.order)).toEqual([3, 2, 5, 4, 1])
  })

  it('range les nouvelles cartes par priorité en tenant compte du hit count', () => {
    const board = addPolicies(createBoard('fw.conf'), [
      finding({ policyId: '1', order: 1, category: 'unused' }),
      finding({ policyId: '2', order: 2, category: 'unused' }),
      finding({ policyId: '3', order: 3, category: 'permissive', severity: 'critical' }),
    ], [policy({ id: '1', hitCount: 40 }), policy({ id: '2', hitCount: 0 }), policy({ id: '3', hitCount: 0 })])
    expect(cardsInColumn(board, 'discuss').map((card) => card.policyId)).toEqual(['2', '1', '3'])
  })

  it('retrie la colonne après un réordonnancement manuel', () => {
    const audit = {
      policies: [policy({ id: '1', order: 1, hitCount: 40 }), policy({ id: '2', order: 2, hitCount: 0 })],
      findings: [finding({ policyId: '1', order: 1, category: 'unused' }), finding({ policyId: '2', order: 2, category: 'unused' })],
    }
    let board = addPolicies(createBoard('fw.conf'), audit.findings, audit.policies)
    board = moveCard(board, board.cards.find((card) => card.policyId === '1')!.policyKey, 'discuss', 0)
    expect(cardsInColumn(sortDiscussByPriority(board, audit), 'discuss').map((card) => card.policyId)).toEqual(['2', '1'])
  })
})

describe('groupes de « À discuter »', () => {
  const board = addPolicies(createBoard('fw.conf'), [
    finding({ policyId: '1', order: 1, category: 'unused' }),
    finding({ policyId: '2', order: 2, category: 'permissive' }),
    finding({ policyId: '3', order: 3, category: 'indeterminate' }),
  ])
  const key = (id: string) => board.cards.find((card) => card.policyId === id)!.policyKey
  const ids = (cards: { policyId: string }[]) => cards.map((card) => card.policyId)

  it('regroupe les cartes par proposition, dans l’ordre de séance', () => {
    expect(discussGroups(board).map((group) => ids(group.cards))).toEqual([['1'], ['2'], [], ['3']])
    expect(ids(agenda(board))).toEqual(['1', '2', '3'])
  })

  it('déposer dans un groupe change la proposition et la position dans le groupe', () => {
    const moved = moveToDiscussGroup(board, key('2'), 'delete', 0)
    expect(discussGroups(moved).map((group) => ids(group.cards))).toEqual([['2', '1'], [], [], ['3']])
    const back = moveToDiscussGroup(moveCard(board, key('3'), 'postpone'), key('3'), undefined)
    expect(back.cards.find((card) => card.policyId === '3')).toMatchObject({ column: 'discuss', proposal: undefined })
  })
})

describe('syncBoard', () => {
  const policies = [policy({ id: '1', order: 1 }), policy({ id: '2', order: 2 })]
  const open = [finding({ policyId: '1', order: 1 }), finding({ policyId: '2', order: 2 }), finding({ policyId: 'object:address:SRV_OLD', category: 'object' })]

  it('remplit le tableau avec chaque policy qui a un constat ouvert, sans les objets', () => {
    expect(syncBoard(createBoard('fw.conf'), open, policies).cards.map((card) => card.policyId)).toEqual(['1', '2'])
  })

  it('renvoie le même tableau quand rien ne change', () => {
    const board = syncBoard(createBoard('fw.conf'), open, policies)
    expect(syncBoard(board, open, policies)).toBe(board)
  })

  it('retire une carte vierge dont les constats sont acquittés, mais garde une carte travaillée', () => {
    let board = syncBoard(createBoard('fw.conf'), open, policies)
    board = updateCard(board, board.cards.find((card) => card.policyId === '2')!.policyKey, { prepNote: 'Demande DSI' })
    expect(syncBoard(board, [], policies).cards.map((card) => card.policyId)).toEqual(['2'])
  })
})
