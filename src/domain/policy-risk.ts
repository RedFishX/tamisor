import type { FirewallPolicy } from './audit'

export type ElementRiskLevel = 'low' | 'medium' | 'high'

export interface PolicyElementRisk {
  key: 'interfaces' | 'sources' | 'destinations' | 'services' | 'schedule' | 'action' | 'nat' | 'security' | 'logging'
  label: string
  level: ElementRiskLevel
  value: string
  reason: string
}

const joined = (values: string[]): string => values.join(', ') || 'Non défini'
const containsAny = (values: string[], universal: string[]): boolean =>
  values.some((value) => universal.includes(value.toLowerCase()))

export const assessPolicyElements = (policy: FirewallPolicy): PolicyElementRisk[] => {
  const universalAddresses = ['all', 'all_ipv4', 'all_ipv6']
  const anyInterface = containsAny([...policy.srcintf, ...policy.dstintf], ['any'])
  const allSources = containsAny(policy.srcaddr, universalAddresses)
  const allDestinations = containsAny(policy.dstaddr, universalAddresses)
  const allServices = containsAny(policy.service, ['all'])
  const always = containsAny(policy.schedule, ['always'])
  const usesNat = policy.nat === 'enable' || policy.ipPools.length > 0 || policy.destinationVips.length > 0

  return [
    {
      key: 'interfaces', label: 'Interfaces', level: anyInterface ? 'high' : 'low',
      value: `${joined(policy.srcintf)} → ${joined(policy.dstintf)}`,
      reason: anyInterface ? 'Une interface « any » étend la règle à plusieurs chemins réseau.' : 'Les interfaces d’entrée et de sortie sont explicites.',
    },
    {
      key: 'sources', label: 'Sources', level: allSources ? 'high' : 'low', value: joined(policy.srcaddr),
      reason: allSources ? 'La règle accepte toutes les sources au lieu d’un périmètre identifié.' : 'Les sources sont limitées à des objets nommés.',
    },
    {
      key: 'destinations', label: 'Destinations', level: allDestinations ? 'high' : 'low', value: joined(policy.dstaddr),
      reason: allDestinations ? 'La règle autorise toutes les destinations.' : 'Les destinations sont limitées à des objets nommés.',
    },
    {
      key: 'services', label: 'Services', level: allServices || (!policy.service.length && !policy.internetServices.length) ? 'high' : 'low',
      value: joined(policy.internetServices.length ? policy.internetServices : policy.service),
      reason: allServices ? 'ALL autorise tous les services et ports.' : !policy.service.length && !policy.internetServices.length ? 'Aucun service explicite n’a été identifié.' : 'Les services autorisés sont explicitement définis.',
    },
    {
      key: 'schedule', label: 'Horaire', level: always ? 'medium' : 'low', value: joined(policy.schedule),
      reason: always ? 'La règle est active en permanence, y compris hors des périodes utiles.' : 'La règle est limitée par un horaire nommé.',
    },
    {
      key: 'action', label: 'Action', level: 'low', value: policy.action,
      reason: policy.action === 'accept' ? 'Le risque dépend des critères autorisés détaillés ci-dessus.' : 'La règle bloque le trafic correspondant.',
    },
    {
      key: 'nat', label: 'NAT et publication', level: policy.destinationVips.length && allSources ? 'high' : usesNat ? 'medium' : 'low',
      value: policy.destinationVips.length ? `VIP : ${joined(policy.destinationVips)}` : policy.ipPools.length ? `IP pool : ${joined(policy.ipPools)}` : policy.nat,
      reason: policy.destinationVips.length && allSources ? 'Une ressource publiée est accessible depuis toutes les sources.' : usesNat ? 'Une traduction d’adresse est appliquée et doit être validée.' : 'Aucune publication ou IP pool n’est associée.',
    },
    {
      key: 'security', label: 'Profils de sécurité', level: policy.utmStatus === 'enable' ? 'low' : 'medium',
      value: policy.utmStatus === 'enable' ? 'Activés' : 'Désactivés',
      reason: policy.utmStatus === 'enable' ? 'Des profils de sécurité sont appliqués au trafic.' : 'Le trafic autorisé ne bénéficie pas de profils de sécurité.',
    },
    {
      key: 'logging', label: 'Journalisation', level: policy.logtraffic === 'disable' ? 'high' : 'low',
      value: policy.logtraffic === 'disable' ? 'Désactivée' : policy.logtraffic,
      reason: policy.logtraffic === 'disable' ? 'L’usage de la règle ne peut pas être contrôlé dans les journaux.' : 'Les sessions correspondantes sont journalisées.',
    },
  ]
}
