import { readFileSync } from 'node:fs'
import { afterEach, describe, expect, it } from 'vitest'
import { setLocale } from '../i18n'
import { addPolicies, createBoard } from '../domain/meeting'
import { meetingFinding, meetingPolicy } from '../test-fixtures/meeting-fixtures'
import { renderExportMenu } from './export-menu'
import { renderMeetingBoard, renderMeetingFocus } from './meeting-view'
import { renderScoreSparkline } from './overview-view'

const mainSource = readFileSync(new URL('./main.ts', import.meta.url), 'utf8')
const styles = readFileSync(new URL('./tokens.css', import.meta.url), 'utf8') + readFileSync(new URL('./style.css', import.meta.url), 'utf8')

afterEach(() => setLocale('fr'))

/**
 * Contrats d'accessibilité vérifiables sans navigateur. L'audit complet (axe-core, clavier, lecteur d'écran)
 * est décrit dans README.md ; ces tests empêchent surtout les régressions sur ce qu'il a corrigé.
 */
describe('structure de la page', () => {
  it('propose un lien d’évitement vers le contenu principal', () => {
    expect(mainSource).toContain('<a class="skip-link" href="#main-content">')
    expect(mainSource).toContain('<main class="content" id="main-content" tabindex="-1">')
  })

  it('déclare la langue du document et une zone d’annonce pour les lecteurs d’écran', () => {
    expect(mainSource).toContain('document.documentElement.lang = getLocale()')
    expect(mainSource).toContain('id="live-region" role="status" aria-live="polite"')
  })

  it('nomme chaque boîte de dialogue par son titre', () => {
    const dialogs = mainSource.match(/<dialog [^>]*>/g) ?? []
    expect(dialogs.length).toBeGreaterThanOrEqual(5)
    for (const dialog of dialogs) expect(dialog).toMatch(/aria-labelledby="[^"]+"/)
  })

  it('utilise de vrais boutons pour choisir un fichier, pas des libellés détournés', () => {
    expect(mainSource).not.toMatch(/<label[^>]*role="button"/)
    expect(mainSource).toContain('<button class="dropzone" id="dropzone" type="button" data-choose-file')
  })

  it('n’annonce pas de menu ARIA sans la navigation au clavier qui va avec', () => {
    expect(renderExportMenu(true)).not.toMatch(/role="menu(item)?"/)
  })
})

describe('contrastes et mouvement', () => {
  it('garde un gris secondaire conforme WCAG AA sur les fonds clairs', () => {
    expect(styles).toMatch(/--muted: #5c6662;/)
  })

  it('coupe les animations quand l’utilisateur réduit les mouvements', () => {
    expect(styles).toMatch(/@media \(prefers-reduced-motion: reduce\)[\s\S]*transition: none !important/)
  })
})

describe('vues rendues', () => {
  const findings = [meetingFinding({ policyId: '7', order: 2, category: 'unused' })]
  const policy = meetingPolicy({ id: '7', order: 2, hitCount: 0 })
  const board = addPolicies(createBoard('fw.conf'), findings)
  const resolve = () => ({ findings, policy })

  it('rend les cartes de réunion utilisables au clavier et décrites aux lecteurs d’écran', () => {
    const html = renderMeetingBoard(board, resolve)
    expect(html).toContain('tabindex="0"')
    expect(html).toContain('aria-keyshortcuts="Enter 1 2 3 4 5"')
    expect(html).toMatch(/aria-label="Règle 7 [^"]+, colonne À discuter, Proposé : supprimer, sévérité moyenne, 0 hit"/)
    expect(html).toContain('role="progressbar"')
    expect(html).toContain('<h2 class="sr-only">Tableau de réunion</h2>')
  })

  it('expose les décisions de séance avec leur raccourci et leur état', () => {
    const html = renderMeetingFocus(board.cards[0], resolve(), { queue: board.cards, running: true }, resolve)
    expect(html).toContain('<h2 id="focus-title">')
    expect(html).toContain('data-decide="delete" aria-pressed="false" aria-keyshortcuts="S"')
    expect(html).toContain('aria-current="step"')
  })

  it('décrit la courbe de la note par un texte alternatif', () => {
    const svg = renderScoreSparkline([
      { id: 'a', sourceName: 'fw.conf', analyzedAt: '2026-10-01T10:00:00Z', score: 48, activePolicies: 10, critical: 0, high: 0, findings: 0 },
      { id: 'b', sourceName: 'fw.conf', analyzedAt: '2026-11-01T10:00:00Z', score: 62, activePolicies: 10, critical: 0, high: 0, findings: 0 },
    ])
    expect(svg).toContain('role="img" aria-label="Note de 48 à 62 sur 2 audits"')
  })
})
