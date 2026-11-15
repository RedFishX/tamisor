import { tr } from '../i18n'

export const renderExportMenu = (auditReady: boolean): string => {
  const disabled = auditReady ? '' : ' disabled'
  return `
    <details class="export-menu" id="export-menu">
      <summary class="secondary-button" aria-label="${tr('Ouvrir les formats d’export', 'Open export formats')}">
        <i data-lucide="download"></i> ${tr('Exporter', 'Export')} <i data-lucide="chevron-down" class="menu-chevron"></i>
      </summary>
      <div class="export-options">
        <button id="export-button" type="button"${disabled}>
          <i data-lucide="table-properties"></i><span><strong>${tr('Constats CSV', 'Findings CSV')}</strong><small>${tr('Analyse tabulaire exploitable', 'Spreadsheet-ready analysis')}</small></span>
        </button>
        <button id="html-report-button" type="button"${disabled}>
          <i data-lucide="file-text"></i><span><strong>${tr('Rapport HTML interactif', 'Interactive HTML report')}</strong><small>${tr('Consultation, filtres et impression', 'Browse, filter and print')}</small></span>
        </button>
        <button id="cli-export-button" type="button"${disabled}>
          <i data-lucide="square-terminal"></i><span><strong>${tr('Commandes CLI', 'CLI commands')}</strong><small>${tr('Remédiations à adapter', 'Remediations to adapt')}</small></span>
        </button>
        <button id="ack-export-button" type="button"${disabled}>
          <i data-lucide="download"></i><span><strong>${tr('Acquittements JSON', 'Acknowledgements JSON')}</strong><small>${tr('Partager l’état de revue', 'Share the review state')}</small></span>
        </button>
        <button id="ack-import-button" type="button"${disabled}>
          <i data-lucide="upload"></i><span><strong>${tr('Importer les acquittements', 'Import acknowledgements')}</strong><small>${tr('Restaurer un état partagé', 'Restore a shared state')}</small></span>
        </button>
        <button id="minutes-export-button" type="button"${disabled}>
          <i data-lucide="presentation"></i><span><strong>${tr('Compte rendu de réunion', 'Meeting minutes')}</strong><small>${tr('Décisions par policy', 'Decisions per policy')}</small></span>
        </button>
      </div>
    </details>
  `
}
