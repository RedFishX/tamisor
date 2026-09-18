import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const mainSource = readFileSync(new URL('./main.ts', import.meta.url), 'utf8')

describe('interface accessibility contracts', () => {
  it('expose des labels pour les contrôles de recherche et de filtrage', () => {
    expect(mainSource).toContain('aria-label="Filtrer par type"')
    expect(mainSource).toContain('aria-label="Filtrer par VDOM"')
    expect(mainSource).toContain('aria-label="Filtrer par service"')
  })

  it('déclare des boutons explicites et une zone d’alerte import', () => {
    expect(mainSource).toContain('type="button"')
    expect(mainSource).toContain('role="alert"')
    expect(mainSource).toContain('role="status"')
  })
})
