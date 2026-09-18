export const renderExportMenu = (auditReady: boolean): string => {
  const disabled = auditReady ? '' : ' disabled'
  return `
    <details class="export-menu" id="export-menu">
      <summary class="secondary-button" aria-label="Ouvrir les formats d’export">
        <i data-lucide="download"></i> Exporter <i data-lucide="chevron-down" class="menu-chevron"></i>
      </summary>
      <div class="export-options" role="menu">
        <button id="export-button" type="button" role="menuitem"${disabled}>
          <i data-lucide="table-properties"></i><span><strong>Constats CSV</strong><small>Analyse tabulaire exploitable</small></span>
        </button>
        <button id="html-report-button" type="button" role="menuitem"${disabled}>
          <i data-lucide="file-text"></i><span><strong>Rapport HTML interactif</strong><small>Consultation, filtres et impression</small></span>
        </button>
        <button id="cli-export-button" type="button" role="menuitem"${disabled}>
          <i data-lucide="square-terminal"></i><span><strong>Commandes CLI</strong><small>Remédiations à adapter</small></span>
        </button>
        <button id="ack-export-button" type="button" role="menuitem"${disabled}>
          <i data-lucide="download"></i><span><strong>Acquittements JSON</strong><small>Partager l’état de revue</small></span>
        </button>
        <button id="ack-import-button" type="button" role="menuitem"${disabled}>
          <i data-lucide="upload"></i><span><strong>Importer les acquittements</strong><small>Restaurer un état partagé</small></span>
        </button>
      </div>
    </details>
  `
}
