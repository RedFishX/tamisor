import { tr } from '../i18n'

/** Verrouillage optionnel décidé par l'édition (voir `edition.ts`) : attributs et badge par bouton. */
export interface ExportMenuLock {
  isLocked(id: string): boolean
  badge(id: string): string
}

/** Entrée supplémentaire fournie par l'édition (libellés de confiance, échappés ici quand même). */
export interface ExtraExport { id: string, label: string, hint: string }

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`)

export const renderExportMenu = (auditReady: boolean, lock?: ExportMenuLock, extras: readonly ExtraExport[] = []): string => {
  const disabled = auditReady ? '' : ' disabled'
  const locked = (id: string) => lock?.isLocked(id) ? ' data-locked="true" aria-describedby="locked-feature-hint"' : ''
  const badge = (id: string) => lock?.badge(id) ?? ''
  return `
    <details class="export-menu" id="export-menu">
      <summary class="secondary-button" aria-label="${tr('Ouvrir les formats d’export', 'Open export formats')}">
        <i data-lucide="download"></i> ${tr('Exporter', 'Export')} <i data-lucide="chevron-down" class="menu-chevron"></i>
      </summary>
      <div class="export-options">
        <button id="export-button" type="button"${disabled}${locked('export-button')}>
          <i data-lucide="table-properties"></i><span><strong>${tr('Constats CSV', 'Findings CSV')}</strong><small>${tr('Analyse tabulaire exploitable', 'Spreadsheet-ready analysis')}</small></span>${badge('export-button')}
        </button>
        <button id="html-report-button" type="button"${disabled}${locked('html-report-button')}>
          <i data-lucide="file-text"></i><span><strong>${tr('Rapport HTML interactif', 'Interactive HTML report')}</strong><small>${tr('Consultation, filtres et impression', 'Browse, filter and print')}</small></span>${badge('html-report-button')}
        </button>
        <button id="cli-export-button" type="button"${disabled}${locked('cli-export-button')}>
          <i data-lucide="square-terminal"></i><span><strong>${tr('Commandes CLI', 'CLI commands')}</strong><small>${tr('Remédiations à adapter', 'Remediations to adapt')}</small></span>${badge('cli-export-button')}
        </button>
        <button id="sarif-export-button" type="button"${disabled}${locked('sarif-export-button')}>
          <i data-lucide="file-code"></i><span><strong>${tr('Rapport SARIF', 'SARIF report')}</strong><small>${tr('Code scanning et outils de CI', 'Code scanning and CI tools')}</small></span>${badge('sarif-export-button')}
        </button>
        <button id="json-export-button" type="button"${disabled}${locked('json-export-button')}>
          <i data-lucide="braces"></i><span><strong>${tr('Rapport JSON', 'JSON report')}</strong><small>${tr('Constats structurés, réutilisables', 'Structured, reusable findings')}</small></span>${badge('json-export-button')}
        </button>
        <button id="ack-export-button" type="button"${disabled}${locked('ack-export-button')}>
          <i data-lucide="download"></i><span><strong>${tr('Acquittements JSON', 'Acknowledgements JSON')}</strong><small>${tr('Partager l’état de revue', 'Share the review state')}</small></span>${badge('ack-export-button')}
        </button>
        <button id="ack-import-button" type="button"${disabled}${locked('ack-import-button')}>
          <i data-lucide="upload"></i><span><strong>${tr('Importer les acquittements', 'Import acknowledgements')}</strong><small>${tr('Restaurer un état partagé', 'Restore a shared state')}</small></span>${badge('ack-import-button')}
        </button>
        <button id="minutes-export-button" type="button"${disabled}${locked('minutes-export-button')}>
          <i data-lucide="presentation"></i><span><strong>${tr('Compte rendu de réunion', 'Meeting minutes')}</strong><small>${tr('Décisions par policy', 'Decisions per policy')}</small></span>${badge('minutes-export-button')}
        </button>
        ${extras.map((extra) => `<button id="${escapeHtml(extra.id)}" type="button" data-edition-export${disabled}${locked(extra.id)}>
          <i data-lucide="file-text"></i><span><strong>${escapeHtml(extra.label)}</strong><small>${escapeHtml(extra.hint)}</small></span>${badge(extra.id)}
        </button>`).join('')}
      </div>
    </details>
  `
}
