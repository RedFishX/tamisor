import type { FirewallPolicy } from './audit'

/** Tranches de hit count. Seuls les exports CSV/GUI fournissent ces compteurs ; un export CLI donne « unknown ». */
export type UsageBand = 'never' | 'low' | 'medium' | 'high' | 'unknown'

export const usageBands: UsageBand[] = ['never', 'low', 'medium', 'high', 'unknown']

export const usageBandLabels: Record<UsageBand, string> = {
  never: 'Jamais utilisée (0)',
  low: 'Faible (1 à 99)',
  medium: 'Moyenne (100 à 9 999)',
  high: 'Forte (10 000 et plus)',
  unknown: 'Hit count inconnu',
}

type UsageFields = Pick<FirewallPolicy, 'hitCount' | 'lastUsed'>

const neverUsedLabel = /^(never|jamais)$/i

export const usageBand = (policy?: UsageFields): UsageBand => {
  if (!policy) return 'unknown'
  if (policy.hitCount === undefined) return policy.lastUsed && neverUsedLabel.test(policy.lastUsed.trim()) ? 'never' : 'unknown'
  if (policy.hitCount === 0) return 'never'
  if (policy.hitCount < 100) return 'low'
  if (policy.hitCount < 10000) return 'medium'
  return 'high'
}

/** Libellé court pour une carte ou un compte rendu : « 0 hit », « 12 450 hits · 2026-10-02 ». */
export const formatUsage = (policy?: UsageFields): string | undefined => {
  if (!policy || (policy.hitCount === undefined && !policy.lastUsed)) return undefined
  const hits = policy.hitCount === undefined ? undefined : `${policy.hitCount.toLocaleString('fr-FR')} hit${policy.hitCount > 1 ? 's' : ''}`
  const last = policy.lastUsed && !neverUsedLabel.test(policy.lastUsed.trim()) ? `dernier ${policy.lastUsed}` : undefined
  return [hits ?? (policy.lastUsed && neverUsedLabel.test(policy.lastUsed.trim()) ? 'jamais utilisée' : undefined), last].filter(Boolean).join(' · ') || undefined
}
