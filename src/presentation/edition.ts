/**
 * Points d'extension de l'interface. Une distribution (hébergement, démo, édition interne) peut enregistrer
 * une édition AVANT de charger `main.ts` pour limiter l'import, verrouiller des fonctions ou afficher un bandeau :
 *
 *   import { registerEdition } from '…/src/presentation/edition'
 *   registerEdition({ … })
 *   import '…/src/presentation/main'
 *
 * Sans édition enregistrée, l'application fonctionne sans aucune restriction (édition open source).
 */

import type { AuditResult, Finding } from '../domain/audit'

export interface DialogOptions {
  eyebrow: string
  title: string
  message: string
  confirmLabel: string
  /** `null` : simple information, sans bouton d'annulation. */
  cancelLabel?: string | null
  tone?: 'danger' | 'neutral'
}

/** Services de l'interface mis à disposition de l'édition. */
export interface EditionUi {
  /** Boîte de dialogue aux couleurs de l'application ; résout `true` si l'utilisateur confirme. */
  confirm(options: DialogOptions): Promise<boolean>
  /** Redessine le bandeau (après un changement d'état propre à l'édition). */
  refreshBanner(): void
}

/** Audit affiché, mis à disposition des actions de l'édition (lecture seule). */
export interface AuditContext {
  audit: AuditResult
  sourceName: string
  /** Constat acquitté dans ce navigateur pour ce fichier source. */
  isAcknowledged(sourceName: string, finding: Finding): boolean
  /** Analyse un autre fichier avec le même moteur (Web Worker), sans l'afficher ni l'ajouter à l'historique. */
  analyze(file: File): Promise<{ audit: AuditResult, importErrors: string[] }>
}

/** Entrée ajoutée au menu « Exporter », après les formats intégrés. Verrouillable par `lockedFeatures`. */
export interface EditionAction {
  /** Identifiant DOM du bouton. */
  id: string
  label: string
  hint: string
  run(context: AuditContext, ui: EditionUi): void | Promise<void>
}

export interface Edition {
  /** Identifiants DOM des boutons verrouillés : visibles, marqués de `lockedBadge`, leur action est remplacée par `onLockedFeature`. */
  lockedFeatures?: readonly string[]
  lockedBadge?: string
  /** Texte lu par les lecteurs d'écran sur un bouton verrouillé. */
  lockedDescription?: string
  onLockedFeature?(featureId: string, ui: EditionUi): void
  /** Remplace la mention de taille sous la zone de dépôt. */
  fileTypesHint?(): string
  /** Avant la lecture du fichier. `false` : import abandonné. */
  beforeImport?(file: { name: string, size: number }, ui: EditionUi): boolean | Promise<boolean>
  /** Fichier lu en mémoire, avant l'analyse. `false` : import abandonné. */
  beforeAnalysis?(source: { name: string, lines: number }, ui: EditionUi): boolean | Promise<boolean>
  /** Après l'analyse, avant l'affichage. `false` : résultat écarté. `restored` : réanalyse après changement de langue. */
  acceptAnalysis?(analysis: { name: string, policies: number, restored: boolean }, ui: EditionUi): boolean | Promise<boolean>
  /** Actions supplémentaires du menu « Exporter ». */
  exportActions?: readonly EditionAction[]
  /** Bandeau au-dessus des vues (HTML de confiance, produit par l'édition). */
  banner?: { label: string, render(): string }
}

let current: Edition = {}

export const registerEdition = (edition: Edition): void => { current = edition }
export const getEdition = (): Edition => current
export const isLocked = (featureId: string): boolean => current.lockedFeatures?.includes(featureId) ?? false

/** Nombre de lignes d'un texte (une dernière ligne sans saut de ligne compte). */
export const countLines = (text: string): number => {
  if (!text) return 0
  let lines = 1
  for (let index = text.indexOf('\n'); index !== -1; index = text.indexOf('\n', index + 1)) lines += 1
  return text.endsWith('\n') ? lines - 1 : lines
}
