import type { Finding, Severity } from './audit'
import { tr } from '../i18n'

/** Libellés partagés par l'interface, les exports et le compte rendu, dans la langue courante. */
export const severityLabel = (severity: Severity): string => ({
  critical: tr('Critique', 'Critical'),
  high: tr('Élevée', 'High'),
  medium: tr('Moyenne', 'Medium'),
  low: tr('Faible', 'Low'),
})[severity]

export const categoryLabel = (category: Finding['category']): string => ({
  duplicate: tr('Doublon', 'Duplicate'),
  shadowed: tr('Masquée', 'Shadowed'),
  overlap: tr('Chevauchement', 'Overlap'),
  permissive: tr('Permissive', 'Permissive'),
  exposure: tr('Exposition', 'Exposure'),
  visibility: tr('Visibilité', 'Visibility'),
  unused: tr('Inutilisée', 'Unused'),
  indeterminate: tr('À valider', 'To validate'),
  temporary: tr('Temporaire', 'Temporary'),
  governance: tr('Gouvernance', 'Governance'),
  security: tr('Profils de sécurité', 'Security profiles'),
  inspection: tr('Inspection SSL', 'SSL inspection'),
  object: tr('Objets', 'Objects'),
})[category]

/** Libellés longs du filtre « Type de constat ». */
export const categoryFilterLabel = (category: Finding['category']): string => ({
  permissive: tr('Règles permissives', 'Permissive rules'),
  shadowed: tr('Règles masquées', 'Shadowed rules'),
  overlap: tr('Chevauchements partiels', 'Partial overlaps'),
  duplicate: tr('Règles dupliquées', 'Duplicate rules'),
  exposure: tr('VIP exposées', 'Exposed VIPs'),
  visibility: tr('Visibilité', 'Visibility'),
  unused: tr('Règles inutilisées', 'Unused rules'),
  indeterminate: tr('À valider', 'To validate'),
  temporary: tr('Règles temporaires', 'Temporary rules'),
  governance: tr('Gouvernance', 'Governance'),
  security: tr('Profils de sécurité', 'Security profiles'),
  inspection: tr('Inspection SSL', 'SSL inspection'),
  object: tr('Objets', 'Objects'),
})[category]

export const findingCategories: Finding['category'][] = [
  'permissive', 'shadowed', 'overlap', 'duplicate', 'exposure', 'visibility', 'unused',
  'indeterminate', 'temporary', 'governance', 'security', 'inspection', 'object',
]

/** Séparateur entre un libellé et sa valeur : « Libellé : valeur » en français, « Label: value » en anglais. */
export const colon = (): string => tr(' : ', ': ')
