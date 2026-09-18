import { analyzeImportedConfiguration } from '../infrastructure/configuration-import'

interface AuditRequest {
  content: string
  fileName: string
}

self.onmessage = (event: MessageEvent<AuditRequest>) => {
  self.postMessage({ type: 'progress', message: 'Import du fichier...' })
  const result = analyzeImportedConfiguration(event.data.content, event.data.fileName)
  const editCount = (event.data.content.match(/^\s*edit\s+/gm) ?? []).length
  const objectCount = event.data.fileName.toLowerCase().endsWith('.csv') ? 0 : Math.max(0, editCount - result.policies.length)
  self.postMessage({ type: 'progress', message: `${result.policies.length} policy(s) et ${objectCount} objet(s) traité(s)` })
  self.postMessage({ type: 'result', result })
}
