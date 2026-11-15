import type { Finding } from './audit'
import { tr } from '../i18n'

export type ComplianceFramework = 'PCI-DSS v4.0' | 'CIS FortiGate' | 'ANSSI'

export interface ComplianceReference {
  framework: ComplianceFramework
  control: string
  title: string
}

const pci = (control: string, title: string): ComplianceReference => ({ framework: 'PCI-DSS v4.0', control, title })
const cis = (title: string): ComplianceReference => ({ framework: 'CIS FortiGate', control: 'Policy and Objects', title })
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
    cis(tr('Restreindre sources, destinations et services de chaque policy', 'Restrict the sources, destinations and services of every policy')),
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
      cis(tr('Documenter chaque policy (nom, commentaire, responsable)', 'Document every policy (name, comment, owner)')),
    ],
    visibility: [
      pci('10.2.1', tr('Journaux d’audit activés et actifs pour tous les composants du système', 'Audit logs are enabled and active for all system components')),
      cis(tr('Activer la journalisation des policies', 'Enable policy logging')),
      anssi(tr('Journaliser les flux autorisés pour permettre l’analyse a posteriori', 'Log allowed flows so they can be analysed afterwards')),
    ],
    security: [
      intrusionDetection,
      cis(tr('Appliquer des profils de sécurité aux flux autorisés', 'Apply security profiles to allowed flows')),
    ],
    inspection: [
      intrusionDetection,
      cis(tr('Inspecter le trafic chiffré lorsque le contexte le permet', 'Inspect encrypted traffic where the context allows')),
    ],
  }
}

export const complianceReferences = (finding: Pick<Finding, 'category'>): ComplianceReference[] =>
  referencesByCategory()[finding.category] ?? []

export const formatComplianceReference = (reference: ComplianceReference): string =>
  `${reference.framework} ${reference.control}${tr(' : ', ': ')}${reference.title}`
