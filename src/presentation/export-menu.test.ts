import { describe, expect, it } from 'vitest'
import { renderExportMenu } from './export-menu'

describe('renderExportMenu', () => {
  it('regroupe les trois formats sous une seule commande', () => {
    const html = renderExportMenu(true)

    expect(html).toContain('<summary class="secondary-button"')
    expect(html).toContain('Exporter')
    expect(html).toContain('id="export-button"')
    expect(html).toContain('Constats CSV')
    expect(html).toContain('id="html-report-button"')
    expect(html).toContain('Rapport HTML interactif')
    expect(html).toContain('id="cli-export-button"')
    expect(html).toContain('Commandes CLI')
    expect(html).not.toContain('disabled')
  })

  it('désactive chaque format tant qu’aucun audit n’est chargé', () => {
    const html = renderExportMenu(false)
    expect(html.match(/disabled/g)).toHaveLength(8)
  })
})