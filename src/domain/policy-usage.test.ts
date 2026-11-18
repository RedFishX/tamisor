import { describe, expect, it } from 'vitest'
import { formatUsage, usageBand } from './policy-usage'

describe('usageBand', () => {
  it('range les hit counts en tranches', () => {
    expect(usageBand({ hitCount: 0 })).toBe('never')
    expect(usageBand({ hitCount: 99 })).toBe('low')
    expect(usageBand({ hitCount: 100 })).toBe('medium')
    expect(usageBand({ hitCount: 9999 })).toBe('medium')
    expect(usageBand({ hitCount: 10000 })).toBe('high')
  })

  it('reconnaît « Never » sans compteur et signale l’absence de données', () => {
    expect(usageBand({ lastUsed: 'Never' })).toBe('never')
    expect(usageBand({})).toBe('unknown')
    expect(usageBand(undefined)).toBe('unknown')
  })
})

describe('formatUsage', () => {
  it('résume le compteur et la dernière utilisation', () => {
    expect(formatUsage({ hitCount: 12450, lastUsed: '2026-10-02' })).toBe('12 450 hits · dernier 2026-10-02')
    expect(formatUsage({ hitCount: 0, lastUsed: 'Never' })).toBe('0 hit')
    expect(formatUsage({ lastUsed: 'Jamais' })).toBe('jamais utilisée')
    expect(formatUsage({})).toBeUndefined()
  })
})
