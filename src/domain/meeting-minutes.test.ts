import { describe, expect, it } from 'vitest'
import { meetingFinding as finding, meetingPolicy as policy } from '../test-fixtures/meeting-fixtures'
import { addPolicies, createBoard, moveCard, updateCard } from './meeting'
import { formatDuration, renderMinutesMarkdown } from './meeting-minutes'

const findings = [
  finding({ policyId: '12', severity: 'critical', title: 'Accès global vers ERP' }),
  finding({ policyId: '7', policyName: 'Ancien_VPN', order: 2, category: 'unused', title: 'Aucun trafic depuis 90 jours' }),
]
const audit = { policies: [policy({ id: '12' }), policy({ id: '7', name: 'Ancien_VPN', order: 2, hitCount: 0, lastUsed: 'Never' })], findings }

const board = () => {
  let next = addPolicies({ ...createBoard('fw-siege.conf', '2026-11-20'), participants: ['Équipe réseau', 'RSSI'] }, findings)
  const key = (id: string) => next.cards.find((card) => card.policyId === id)!.policyKey
  next = moveCard(next, key('7'), 'delete')
  next = updateCard(next, key('7'), { rationale: 'Tunnel décommissionné en septembre', dueDate: '2026-12-01' })
  next = updateCard(next, key('12'), { prepNote: 'Voir ticket <CHG-4812>\navec l’équipe ERP' })
  return next
}

describe('renderMinutesMarkdown', () => {
  it('regroupe les policies par décision, décisions d’abord', () => {
    const markdown = renderMinutesMarkdown(board(), audit)
    expect(markdown).toContain('- Participants : Équipe réseau, RSSI')
    expect(markdown).toContain('2 policies inscrites ; 1 à supprimer, 0 à modifier, 0 conservée, 0 reportée, 1 non traitée.')
    expect(markdown.indexOf('## À supprimer (1)')).toBeLessThan(markdown.indexOf('## Non traitées (1)'))
    expect(markdown).toContain('### Règle #7 · Ancien_VPN (seq 2)')
    expect(markdown).toContain('- Justification : Tunnel décommissionné en septembre')
    expect(markdown).toContain('- Échéance : 2026-12-01')
    expect(markdown).not.toContain('Responsable')
    expect(markdown).toContain('Critique · Accès global vers ERP')
    expect(markdown).toContain('- Utilisation : 0 hit')
  })

  it('neutralise le HTML et conserve les notes sur plusieurs lignes', () => {
    const markdown = renderMinutesMarkdown(board(), audit)
    expect(markdown).toContain('  > Voir ticket &lt;CHG-4812&gt;\n  > avec l’équipe ERP')
    expect(markdown).not.toContain('<CHG-4812>')
  })

  it('omet les sections vides', () => {
    expect(renderMinutesMarkdown(board(), audit)).not.toContain('## Conservées')
  })
})

describe('formatDuration', () => {
  it('formate une durée de séance', () => {
    expect(formatDuration('2026-11-20T09:00:00Z', '2026-11-20T10:25:00Z')).toBe('1 h 25')
    expect(formatDuration('2026-11-20T09:00:00Z', '2026-11-20T09:40:00Z')).toBe('40 min')
    expect(formatDuration('2026-11-20T09:00:00Z')).toBeUndefined()
  })
})
