export type ThemePreference = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'

export const resolveTheme = (
  preference: ThemePreference,
  systemIsDark: boolean,
): ResolvedTheme => preference === 'system'
  ? systemIsDark ? 'dark' : 'light'
  : preference

export const toggleTheme = (current: ResolvedTheme): ResolvedTheme =>
  current === 'dark' ? 'light' : 'dark'
