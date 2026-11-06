import type { Finding } from './audit'

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
  control: 'Guide de filtrage réseau d’un pare-feu',
  title,
})

const leastPrivilege = [
  pci('1.2.5', 'Services, protocoles et ports autorisés identifiés, approuvés et justifiés'),
  cis('Restreindre sources, destinations et services de chaque policy'),
  anssi('Autoriser explicitement le strict nécessaire, tout le reste est interdit'),
]
const periodicReview = [
  pci('1.2.7', 'Revue des configurations des contrôles de sécurité réseau au moins tous les six mois'),
  anssi('Revoir périodiquement les règles et supprimer celles qui sont obsolètes'),
]

/**
 * Correspondance indicative entre catégories de constats et exigences de référentiels.
 * Elle aide à préparer un échange d'audit ; elle ne remplace pas l'évaluation d'un référentiel.
 */
const referencesByCategory: Record<Finding['category'], ComplianceReference[]> = {
  permissive: leastPrivilege,
  exposure: [
    pci('1.4.2', 'Trafic entrant depuis les réseaux non fiables limité aux composants publics autorisés'),
    ...leastPrivilege,
  ],
  shadowed: periodicReview,
  overlap: periodicReview,
  duplicate: periodicReview,
  unused: periodicReview,
  object: periodicReview,
  indeterminate: periodicReview,
  temporary: [
    pci('1.2.2', 'Changements de configuration approuvés et gérés par le processus de contrôle des changements'),
    anssi('Limiter la durée des règles temporaires et les supprimer à échéance'),
  ],
  governance: [
    pci('1.2.2', 'Changements de configuration approuvés et gérés par le processus de contrôle des changements'),
    cis('Documenter chaque policy (nom, commentaire, responsable)'),
  ],
  visibility: [
    pci('10.2.1', 'Journaux d’audit activés et actifs pour tous les composants du système'),
    cis('Activer la journalisation des policies'),
    anssi('Journaliser les flux autorisés pour permettre l’analyse a posteriori'),
  ],
  security: [
    pci('11.5.1', 'Techniques de détection ou de prévention d’intrusion en place'),
    cis('Appliquer des profils de sécurité aux flux autorisés'),
  ],
  inspection: [
    pci('11.5.1', 'Techniques de détection ou de prévention d’intrusion en place'),
    cis('Inspecter le trafic chiffré lorsque le contexte le permet'),
  ],
}

export const complianceReferences = (finding: Pick<Finding, 'category'>): ComplianceReference[] =>
  referencesByCategory[finding.category] ?? []

export const formatComplianceReference = (reference: ComplianceReference): string =>
  `${reference.framework} ${reference.control} : ${reference.title}`
