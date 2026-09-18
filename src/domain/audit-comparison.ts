import type { FirewallPolicy } from './audit'

export interface PolicyComparison {
  added: FirewallPolicy[]
  removed: FirewallPolicy[]
  modified: Array<{ before: FirewallPolicy, after: FirewallPolicy, changedFields: string[] }>
}

const policyKey = (policy: FirewallPolicy): string =>
  `${policy.vdom ?? 'global'}:${policy.family ?? 'ipv4'}:${policy.id}`

const comparablePolicy = ({ order: _order, ...policy }: FirewallPolicy): string =>
  JSON.stringify(policy)

const changedFields = (before: FirewallPolicy, after: FirewallPolicy): string[] =>
  Object.keys({ ...before, ...after }).filter((key) => key !== 'order' && JSON.stringify(before[key as keyof FirewallPolicy]) !== JSON.stringify(after[key as keyof FirewallPolicy]))

export const comparePolicies = (before: FirewallPolicy[], after: FirewallPolicy[]): PolicyComparison => {
  const beforeByKey = new Map(before.map((policy) => [policyKey(policy), policy]))
  const afterByKey = new Map(after.map((policy) => [policyKey(policy), policy]))
  const added = after.filter((policy) => !beforeByKey.has(policyKey(policy)))
  const removed = before.filter((policy) => !afterByKey.has(policyKey(policy)))
  const modified = after.flatMap((policy) => {
    const previous = beforeByKey.get(policyKey(policy))
    return previous && comparablePolicy(previous) !== comparablePolicy(policy)
      ? [{ before: previous, after: policy, changedFields: changedFields(previous, policy) }]
      : []
  })
  return { added, removed, modified }
}
