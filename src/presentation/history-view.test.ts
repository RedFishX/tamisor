import { describe, expect, it } from 'vitest'
import type { HistoryEntry } from '../application/audit-history'
import { renderHistory } from './history-view'

const entry = (day: string, score: number, source = 'siege.conf'): HistoryEntry => ({
  id: `${day}-${source}`, sourceName: source, analyzedAt: `${day}T09:00:00.000Z`, score, activePolicies: 40, critical: 2, high: 5, findings: 14,
})

describe('renderHistory', () => {
  it('affiche le plus récent en premier avec son écart de note', () => {
    const html = renderHistory([entry('2026-09-01', 54), entry('2026-10-01', 71), entry('2026-10-01', 10, 'agence.conf')], 'siege.conf')
    expect(html.indexOf('71')).toBeLessThan(html.indexOf('54'))
    expect(html).toContain('+17')
    expect(html).not.toContain('>10<')
  })

  it('gère l’absence d’historique, l’indisponibilité et échappe le contenu', () => {
    expect(renderHistory([], 'siege.conf')).toContain('Aucun audit enregistré')
    expect(renderHistory([], 'siege.conf', true)).toContain('indisponible')
    expect(renderHistory([{ ...entry('2026-10-01', 60), analyzedAt: '<b>' }], 'siege.conf')).not.toContain('<b>')
  })
})
