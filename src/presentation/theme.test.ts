import { describe, expect, it } from 'vitest'
import { resolveTheme, toggleTheme, type ThemePreference } from './theme'

describe('theme', () => {
  it.each([
    ['light', false, 'light'],
    ['dark', false, 'dark'],
    ['system', true, 'dark'],
    ['system', false, 'light'],
  ] as Array<[ThemePreference, boolean, 'light' | 'dark']>)(
    'résout la préférence %s',
    (preference, systemIsDark, expected) => {
      expect(resolveTheme(preference, systemIsDark)).toBe(expected)
    },
  )

  it('bascule entre les deux thèmes explicites', () => {
    expect(toggleTheme('light')).toBe('dark')
    expect(toggleTheme('dark')).toBe('light')
  })
})