import { describe, expect, it } from 'vitest'
import { countLines } from './edition'

describe('countLines', () => {
  it('compte les lignes, avec ou sans saut de ligne final', () => {
    expect(countLines('')).toBe(0)
    expect(countLines('config firewall policy')).toBe(1)
    expect(countLines('a\nb\nc')).toBe(3)
    expect(countLines('a\nb\nc\n')).toBe(3)
    expect(countLines('a\r\nb\r\n')).toBe(2)
    expect(countLines('\n\n')).toBe(2)
  })
})
