import { describe, expect, it } from 'vitest'
import { meetingFinding as finding, meetingPolicy as policy } from '../test-fixtures/meeting-fixtures'
import { addPolicies, createBoard, findingsForCard, moveCard, policyForCard } from '../domain/meeting'
import { renderMeetingBoard, renderMeetingFocus } from './meeting-view'
import { renderMinutesHtml } from './meeting-minutes-report'

const findings = [finding({ severity: 'critical', policyName: 'LAN_<ERP>' }), finding({ policyId: '7', order: 2, category: 'shadowed' })]
const audit = { policies: [policy({ id: '12', name: 'LAN_<ERP>', hitCount: 15230 }), policy({ id: '7', order: 2, hitCount: 0 })], findings }
const resolve = (card: Parameters<typeof findingsForCard>[1]) => ({ findings: findingsForCard(audit, card), policy: policyForCard(audit, card) })

describe('renderMeetingBoard', () => {
  it('explique un tableau vide sans proposer d’ajout manuel', () => {
    const html = renderMeetingBoard(createBoard('fw.conf'), resolve)
    expect(html).toContain('Aucune policy à revoir')
    expect(html).not.toContain('data-meeting-add')
    expect(html).not.toContain('meeting-board')
  })

  it('affiche les cinq colonnes, les compteurs et des cartes accessibles', () => {
    let board = addPolicies(createBoard('fw.conf'), findings)
    board = moveCard(board, board.cards[0].policyKey, 'delete')
    const html = renderMeetingBoard(board, resolve)
    for (const label of ['À discuter', 'Supprimer', 'Modifier', 'Conserver', 'Reporter']) expect(html).toContain(`>${label}</h3>`)
    expect(html).toContain('1<small>/2</small>')
    expect(html).toContain('aria-keyshortcuts="Enter 1 2 3 4 5"')
    expect(html).toContain('draggable="true"')
    expect(html).toContain('LAN_&lt;ERP&gt;')
    expect(html).not.toContain('LAN_<ERP>')
  })

  it('range « À discuter » par proposition et affiche le hit count sur la carte', () => {
    const html = renderMeetingBoard(addPolicies(createBoard('fw.conf'), findings), resolve)
    expect(html).toContain('data-drop-proposal="delete"')
    expect(html).toContain('Proposé : supprimer <span>1</span>')
    expect(html).toContain('<span class="meeting-usage never" title="0 hit">0 hit</span>')
    expect(html).toContain('data-meeting-sort')
    expect(html).toContain('<option value="discuss:delete" selected>')
  })
})

describe('renderMeetingFocus', () => {
  const board = () => {
    // #7 (masquée) est proposée à la suppression et déjà décidée ; #12 (permissive) est en cours.
    const initial = addPolicies(createBoard('fw.conf'), findings)
    return moveCard(initial, initial.cards.find((card) => card.policyId === '7')!.policyKey, 'delete')
  }
  const focus = (policyId: string) => {
    const current = board()
    const card = current.cards.find((candidate) => candidate.policyId === policyId)!
    const queue = ['7', '12'].map((id) => current.cards.find((candidate) => candidate.policyId === id)!)
    return renderMeetingFocus(card, resolve(card), { queue, running: true }, resolve)
  }

  it('présente la policy, son flux, ses constats et la barre de décision avec raccourcis', () => {
    const html = focus('12')
    expect(html).toContain('Séance · policy 2 sur 2')
    expect(html).toContain('port1 <b aria-hidden="true">→</b><span class="sr-only">vers</span> port3')
    expect(html).toContain('Plan de remédiation')
    expect(html).toContain('data-decide="delete" aria-pressed="false" aria-keyshortcuts="S"')
    expect(html).toContain('aria-label="Policy suivante" title="Suivante (→)" disabled')
  })

  it('affiche l’ordre du jour par proposition, avec l’état de chaque policy', () => {
    const html = focus('12')
    expect(html).toContain('Ordre du jour <span>1/2</span>')
    expect(html.indexOf('Proposé : supprimer')).toBeLessThan(html.indexOf('Proposé : modifier'))
    expect(html).toMatch(/aria-label="Règle 7 [^"]*, décidée : supprimer, 0 hit"/)
    expect(html).toMatch(/aria-current="step" aria-label="Règle 12 [^"]*, en cours, 15\u202f230 hits"/)
    expect(html).toContain('<span class="agenda-hits never" aria-hidden="true">0</span>')
    expect(html).toContain('<span class="agenda-hits high" aria-hidden="true">15k</span>')
  })

  it('met en tête la proposition préparée, colorée, avec l’argument d’usage', () => {
    const html = focus('7')
    expect(html).toContain('<section class="focus-proposal delete"')
    expect(html).toContain('<strong>Supprimer la règle</strong>')
    expect(html).toContain('0 hit · 1 constat')
    expect(html).toContain('<span>Supprimer<small>proposé</small></span>')
    expect(html.indexOf('focus-proposal')).toBeLessThan(html.indexOf('focus-flow'))
  })
})

describe('renderMinutesHtml', () => {
  it('produit une page imprimable échappée', () => {
    const html = renderMinutesHtml(addPolicies(createBoard('fw.conf'), findings), audit)
    expect(html).toContain('<!doctype html>')
    expect(html).toContain('Non traitées (2)')
    expect(html).toContain('LAN_&lt;ERP&gt;')
  })
})
