import type { FirewallPolicy } from './audit'
import { tr } from '../i18n'

export type ElementRiskLevel = 'low' | 'medium' | 'high'

export interface PolicyElementRisk {
  key: 'interfaces' | 'sources' | 'destinations' | 'services' | 'schedule' | 'action' | 'nat' | 'security' | 'logging'
  label: string
  level: ElementRiskLevel
  value: string
  reason: string
}

const joined = (values: string[]): string => values.join(', ') || tr('Non défini', 'Not set')
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
      reason: anyInterface
        ? tr('Une interface « any » étend la règle à plusieurs chemins réseau.', 'An “any” interface extends the rule to several network paths.')
        : tr('Les interfaces d’entrée et de sortie sont explicites.', 'Incoming and outgoing interfaces are explicit.'),
    },
    {
      key: 'sources', label: 'Sources', level: allSources ? 'high' : 'low', value: joined(policy.srcaddr),
      reason: allSources
        ? tr('La règle accepte toutes les sources au lieu d’un périmètre identifié.', 'The rule accepts every source instead of an identified scope.')
        : tr('Les sources sont limitées à des objets nommés.', 'Sources are limited to named objects.'),
    },
    {
      key: 'destinations', label: 'Destinations', level: allDestinations ? 'high' : 'low', value: joined(policy.dstaddr),
      reason: allDestinations
        ? tr('La règle autorise toutes les destinations.', 'The rule allows every destination.')
        : tr('Les destinations sont limitées à des objets nommés.', 'Destinations are limited to named objects.'),
    },
    {
      key: 'services', label: 'Services', level: allServices || (!policy.service.length && !policy.internetServices.length) ? 'high' : 'low',
      value: joined(policy.internetServices.length ? policy.internetServices : policy.service),
      reason: allServices
        ? tr('ALL autorise tous les services et ports.', 'ALL allows every service and port.')
        : !policy.service.length && !policy.internetServices.length
          ? tr('Aucun service explicite n’a été identifié.', 'No explicit service was found.')
          : tr('Les services autorisés sont explicitement définis.', 'Allowed services are explicitly defined.'),
    },
    {
      key: 'schedule', label: tr('Horaire', 'Schedule'), level: always ? 'medium' : 'low', value: joined(policy.schedule),
      reason: always
        ? tr('La règle est active en permanence, y compris hors des périodes utiles.', 'The rule is always active, including outside the periods it is needed.')
        : tr('La règle est limitée par un horaire nommé.', 'The rule is limited by a named schedule.'),
    },
    {
      key: 'action', label: 'Action', level: 'low', value: policy.action,
      reason: policy.action === 'accept'
        ? tr('Le risque dépend des critères autorisés détaillés ci-dessus.', 'The risk depends on the allowed criteria listed above.')
        : tr('La règle bloque le trafic correspondant.', 'The rule blocks matching traffic.'),
    },
    {
      key: 'nat', label: tr('NAT et publication', 'NAT and publishing'), level: policy.destinationVips.length && allSources ? 'high' : usesNat ? 'medium' : 'low',
      value: policy.destinationVips.length
        ? tr(`VIP : ${joined(policy.destinationVips)}`, `VIP: ${joined(policy.destinationVips)}`)
        : policy.ipPools.length ? tr(`IP pool : ${joined(policy.ipPools)}`, `IP pool: ${joined(policy.ipPools)}`) : policy.nat,
      reason: policy.destinationVips.length && allSources
        ? tr('Une ressource publiée est accessible depuis toutes les sources.', 'A published resource is reachable from every source.')
        : usesNat
          ? tr('Une traduction d’adresse est appliquée et doit être validée.', 'Address translation is applied and must be validated.')
          : tr('Aucune publication ou IP pool n’est associée.', 'No published service or IP pool is attached.'),
    },
    {
      key: 'security', label: tr('Profils de sécurité', 'Security profiles'), level: policy.utmStatus === 'enable' ? 'low' : 'medium',
      value: policy.utmStatus === 'enable' ? tr('Activés', 'Enabled') : tr('Désactivés', 'Disabled'),
      reason: policy.utmStatus === 'enable'
        ? tr('Des profils de sécurité sont appliqués au trafic.', 'Security profiles are applied to the traffic.')
        : tr('Le trafic autorisé ne bénéficie pas de profils de sécurité.', 'Allowed traffic is not covered by security profiles.'),
    },
    {
      key: 'logging', label: tr('Journalisation', 'Logging'), level: policy.logtraffic === 'disable' ? 'high' : 'low',
      value: policy.logtraffic === 'disable' ? tr('Désactivée', 'Disabled') : policy.logtraffic,
      reason: policy.logtraffic === 'disable'
        ? tr('L’usage de la règle ne peut pas être contrôlé dans les journaux.', 'The rule’s use cannot be checked in the logs.')
        : tr('Les sessions correspondantes sont journalisées.', 'Matching sessions are logged.'),
    },
  ]
}
