import { describe, expect, it } from 'vitest'
import { generateRealisticConfig } from '../test-fixtures/realistic-config'
import { analyzeConfiguration } from './analyzer'

describe('analyzeConfiguration sur une grosse configuration réaliste', () => {
  it('analyse 5000 policies et leurs objets dans un temps raisonnable', () => {
    const configuration = generateRealisticConfig({ policies: 5000 })
    const start = performance.now()
    const result = analyzeConfiguration(configuration)
    const duration = performance.now() - start

    expect(result.policies).toHaveLength(5000)
    expect(result.stats.activePolicies).toBe(5000)
    expect(result.findings.some((finding) => finding.category === 'permissive')).toBe(true)
    expect(result.findings.some((finding) => finding.category === 'security')).toBe(true)
    expect(result.findings.some((finding) => finding.category === 'object')).toBe(true)
    console.info(`5000 policies analysées en ${Math.round(duration)} ms`)
    expect(duration).toBeLessThan(5_000)
  }, 30_000)

  it('produit un résultat identique pour une même graine', () => {
    const first = analyzeConfiguration(generateRealisticConfig({ policies: 200, seed: 7 }))
    const second = analyzeConfiguration(generateRealisticConfig({ policies: 200, seed: 7 }))
    expect(second.findings.map((finding) => finding.id)).toEqual(first.findings.map((finding) => finding.id))
  })
})
