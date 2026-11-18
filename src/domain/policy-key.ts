/**
 * Identité d'une policy : VDOM, famille IP et identifiant. Une seule définition pour la réunion (clé des cartes,
 * enregistrée dans le navigateur), la comparaison de deux audits et le score.
 *
 * Les trois parties sont jointes par « | » après avoir échappé « % » et « | » dans chacune : la clé est injective
 * (deux policies distinctes n'ont jamais la même clé, même si un VDOM ou un id contient « | »). Pour les valeurs
 * ordinaires (sans « % » ni « | »), la clé est identique à l'ancien format `vdom|famille|id`, donc les comptes rendus
 * déjà enregistrés restent valides sans migration.
 */
export type PolicyRef = { id?: string, policyId?: string, vdom?: string, family?: 'ipv4' | 'ipv6' }

const escapePart = (value: string): string => value.replace(/%/g, '%25').replace(/\|/g, '%7C')

export const policyKey = (reference: PolicyRef): string =>
  [reference.vdom ?? 'global', reference.family ?? 'ipv4', reference.policyId ?? reference.id ?? ''].map(escapePart).join('|')
