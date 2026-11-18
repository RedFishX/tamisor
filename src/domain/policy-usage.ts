import type { FirewallPolicy } from './audit'
import { formatNumber, plural, tr } from '../i18n'

/** Tranches de hit count. Seuls les exports CSV/GUI fournissent ces compteurs ; un export CLI donne « unknown ». */
export type UsageBand = 'never' | 'low' | 'medium' | 'high' | 'unknown'

export const usageBands: UsageBand[] = ['never', 'low', 'medium', 'high', 'unknown']

export const usageBandLabel = (band: UsageBand): string => ({
  never: tr('Jamais utilisée (0)', 'Never used (0)'),
  low: tr('Faible (1 à 99)', 'Low (1 to 99)'),
  medium: tr('Moyenne (100 à 9 999)', 'Medium (100 to 9,999)'),
  high: tr('Forte (10 000 et plus)', 'High (10,000 and more)'),
  unknown: tr('Hit count inconnu', 'Hit count unknown'),
})[band]

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

/** Libellé court du nombre de hits : « 0 hit », « 12 450 hits ». */
export const formatHits = (hits: number): string => `${formatNumber(hits)} ${plural(hits, ['hit', 'hits'], ['hit', 'hits'])}`

/** Libellé court pour une carte ou un compte rendu : « 0 hit », « 12 450 hits · dernier 2026-10-02 ». */
export const formatUsage = (policy?: UsageFields): string | undefined => {
  if (!policy || (policy.hitCount === undefined && !policy.lastUsed)) return undefined
  const hits = policy.hitCount === undefined ? undefined : formatHits(policy.hitCount)
  const last = policy.lastUsed && !neverUsedLabel.test(policy.lastUsed.trim()) ? tr(`dernier ${policy.lastUsed}`, `last ${policy.lastUsed}`) : undefined
  return [hits ?? (policy.lastUsed && neverUsedLabel.test(policy.lastUsed.trim()) ? tr('jamais utilisée', 'never used') : undefined), last].filter(Boolean).join(' · ') || undefined
}
