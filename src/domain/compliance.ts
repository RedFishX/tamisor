import type { Finding } from './audit'
import { tr } from '../i18n'

export type ComplianceFramework = 'PCI-DSS v4.0' | 'ANSSI'

export interface ComplianceReference {
  framework: ComplianceFramework
  control: string
  title: string
}

const pci = (control: string, title: string): ComplianceReference => ({ framework: 'PCI-DSS v4.0', control, title })
const anssi = (title: string): ComplianceReference => ({
  framework: 'ANSSI',
  control: tr('Guide de filtrage réseau d’un pare-feu', 'Firewall network filtering guide'),
  title,
})

/**
 * Correspondance indicative entre catégories de constats et exigences de référentiels.
 * Elle aide à préparer un échange d'audit ; elle ne remplace pas l'évaluation d'un référentiel.
 * Construite à l'appel pour suivre la langue courante.
 */
const referencesByCategory = (): Record<Finding['category'], ComplianceReference[]> => {
  const leastPrivilege = [
    pci('1.2.5', tr('Services, protocoles et ports autorisés identifiés, approuvés et justifiés', 'All services, protocols and ports allowed are identified, approved and have a defined business need')),
    anssi(tr('Autoriser explicitement le strict nécessaire, tout le reste est interdit', 'Explicitly allow only what is strictly necessary; everything else is denied')),
  ]
  const periodicReview = [
    pci('1.2.7', tr('Revue des configurations des contrôles de sécurité réseau au moins tous les six mois', 'Configurations of network security controls are reviewed at least once every six months')),
    anssi(tr('Revoir périodiquement les règles et supprimer celles qui sont obsolètes', 'Review rules periodically and remove obsolete ones')),
  ]
  const changeControl = pci('1.2.2', tr('Changements de configuration approuvés et gérés par le processus de contrôle des changements', 'Changes to network connections and configurations are approved and managed through change control'))
  const intrusionDetection = pci('11.5.1', tr('Techniques de détection ou de prévention d’intrusion en place', 'Intrusion-detection and/or intrusion-prevention techniques are in place'))
  return {
    permissive: leastPrivilege,
    exposure: [
      pci('1.4.2', tr('Trafic entrant depuis les réseaux non fiables limité aux composants publics autorisés', 'Inbound traffic from untrusted networks is restricted to authorised publicly accessible components')),
      ...leastPrivilege,
    ],
    shadowed: periodicReview,
    overlap: periodicReview,
    duplicate: periodicReview,
    unused: periodicReview,
    object: periodicReview,
    indeterminate: periodicReview,
    temporary: [
      changeControl,
      anssi(tr('Limiter la durée des règles temporaires et les supprimer à échéance', 'Limit how long temporary rules last and remove them when they expire')),
    ],
    governance: [
      changeControl,
      anssi(tr('Documenter chaque règle : objet, demandeur et responsable', 'Document every rule: purpose, requester and owner')),
    ],
    visibility: [
      pci('10.2.1', tr('Journaux d’audit activés et actifs pour tous les composants du système', 'Audit logs are enabled and active for all system components')),
      anssi(tr('Journaliser les flux autorisés pour permettre l’analyse a posteriori', 'Log allowed flows so they can be analysed afterwards')),
    ],
    security: [intrusionDetection],
    inspection: [intrusionDetection],
  }
}

export const complianceReferences = (finding: Pick<Finding, 'category'>): ComplianceReference[] =>
  referencesByCategory()[finding.category] ?? []

export const formatComplianceReference = (reference: ComplianceReference): string =>
  `${reference.framework} ${reference.control}${tr(' : ', ': ')}${reference.title}`
