import { analyzeImportedConfiguration } from '../infrastructure/configuration-import'
import { plural, setLocale, tr, type Locale } from '../i18n'

interface AuditRequest {
  content: string
  fileName: string
  /** Langue des constats produits : le worker n'a pas accès à la préférence enregistrée. */
  locale: Locale
}

self.onmessage = (event: MessageEvent<AuditRequest>) => {
  setLocale(event.data.locale)
  self.postMessage({ type: 'progress', message: tr('Import du fichier…', 'Importing the file…') })
  const result = analyzeImportedConfiguration(event.data.content, event.data.fileName)
  const editCount = (event.data.content.match(/^\s*edit\s+/gm) ?? []).length
  const objectCount = event.data.fileName.toLowerCase().endsWith('.csv') ? 0 : Math.max(0, editCount - result.policies.length)
  const policies = result.policies.length
  self.postMessage({
    type: 'progress',
    message: tr(
      `${policies} ${plural(policies, ['policy', 'policies'], ['', ''])} et ${objectCount} ${plural(objectCount, ['objet traité', 'objets traités'], ['', ''])}`,
      `${policies} ${plural(policies, ['', ''], ['policy', 'policies'])} and ${objectCount} ${plural(objectCount, ['', ''], ['object', 'objects'])} processed`,
    ),
  })
  self.postMessage({ type: 'result', result })
}
