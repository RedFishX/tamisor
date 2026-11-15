/**
 * Commande `fortiscope` : audite un export FortiGate dans un pipeline de CI et produit des rapports JSON et SARIF.
 *
 *   node fortiscope.mjs firewall.conf --sarif fortiscope.sarif --json fortiscope.json --fail-on high
 *
 * Codes de sortie : 0 = seuil respecté, 1 = constats bloquants, 2 = erreur d'utilisation ou d'import.
 * Toute l'analyse est locale, comme dans l'application : aucun appel réseau.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'
import process from 'node:process'
import { parseArgs } from 'node:util'
import packageJson from '../../package.json'
import { isLocale, setLocale, tr } from '../i18n'
import { analyzeImportedConfiguration } from '../infrastructure/configuration-import'
import { createConfigLocator } from '../infrastructure/config-locations'
import { parseAcknowledgements } from '../application/finding-acknowledgement'
import {
  buildJsonReport, buildSarifReport, evaluateGate, classifyFindings, parseBaselineIds, renderTextSummary, severityOrder,
  type FailOn, type ReportContext,
} from '../application/ci-report'

const help = (): string => tr(`Usage : fortiscope <fichier.conf|.txt|.csv> [options]

Options :
  --sarif <fichier>             Écrit un rapport SARIF 2.1.0 (« - » pour la sortie standard)
  --json <fichier>              Écrit un rapport JSON FortiScope (« - » pour la sortie standard)
  --fail-on <sévérité>          critical | high | medium | low | none (défaut : high)
  --acknowledgements <fichier>  Acquittements JSON exportés depuis l'application : ces constats ne bloquent pas
  --baseline <fichier>          Rapport JSON de la branche cible : seuls les nouveaux constats bloquent
  --source-uri <chemin>         Chemin du fichier dans le dépôt, repris dans les rapports (défaut : l'argument)
  --lang <fr|en>                Langue des constats (défaut : fr)
  -h, --help                    Affiche cette aide
  -v, --version                 Affiche la version

Codes de sortie : 0 seuil respecté, 1 constats bloquants, 2 erreur d'utilisation ou d'import.`,
`Usage: fortiscope <file.conf|.txt|.csv> [options]

Options:
  --sarif <file>                Write a SARIF 2.1.0 report ("-" for standard output)
  --json <file>                 Write a FortiScope JSON report ("-" for standard output)
  --fail-on <severity>          critical | high | medium | low | none (default: high)
  --acknowledgements <file>     Acknowledgements JSON exported from the app: these findings do not block
  --baseline <file>             JSON report of the target branch: only new findings block
  --source-uri <path>           Path of the file in the repository, used in the reports (default: the argument)
  --lang <fr|en>                Language of the findings (default: fr)
  -h, --help                    Show this help
  -v, --version                 Show the version

Exit codes: 0 threshold met, 1 blocking findings, 2 usage or import error.`)

class UsageError extends Error {}

const write = (target: string, content: string) => {
  if (target === '-') process.stdout.write(`${content}\n`)
  else writeFileSync(target, `${content}\n`, 'utf8')
}

export const run = (argv: string[]): number => {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      sarif: { type: 'string' },
      json: { type: 'string' },
      'fail-on': { type: 'string', default: 'high' },
      acknowledgements: { type: 'string' },
      baseline: { type: 'string' },
      'source-uri': { type: 'string' },
      lang: { type: 'string', default: 'fr' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  })
  if (!isLocale(values.lang)) throw new UsageError(`--lang: fr | en (${values.lang})`)
  setLocale(values.lang)
  if (values.help) {
    process.stdout.write(`${help()}\n`)
    return 0
  }
  if (values.version) {
    process.stdout.write(`${packageJson.version}\n`)
    return 0
  }
  const failOn = values['fail-on'] as FailOn
  if (failOn !== 'none' && !severityOrder.includes(failOn)) throw new UsageError(`--fail-on: critical | high | medium | low | none (${failOn})`)
  if (positionals.length !== 1) throw new UsageError(tr('Indiquez un seul fichier de configuration à auditer.', 'Give exactly one configuration file to audit.'))

  const path = positionals[0]
  const content = readFileSync(path, 'utf8')
  const audit = analyzeImportedConfiguration(content, basename(path))
  if (audit.importErrors.length) {
    process.stderr.write(`${tr('Import impossible', 'Import failed')}${tr(' : ', ': ')}${audit.importErrors.join(' ')}\n`)
    return 2
  }
  if (!audit.policies.length) {
    process.stderr.write(`${tr('Aucune policy trouvée dans', 'No policy found in')} ${path}\n`)
    return 2
  }

  let baselineIds: Set<string> | undefined
  if (values.baseline) {
    // Premier passage (pas encore de rapport sur la branche cible) : on continue sans référence.
    if (existsSync(values.baseline)) baselineIds = parseBaselineIds(readFileSync(values.baseline, 'utf8'))
    else process.stderr.write(`${tr('Référence introuvable, analyse sans référence :', 'Baseline not found, running without it:')} ${values.baseline}\n`)
  }

  const context: ReportContext = {
    audit,
    sourceUri: (values['source-uri'] ?? path).replace(/\\/g, '/').replace(/^\.\//, ''),
    toolVersion: packageJson.version,
    locate: createConfigLocator(content, path),
    acknowledgements: values.acknowledgements ? parseAcknowledgements(readFileSync(values.acknowledgements, 'utf8')) : [],
    baselineIds,
    failOn,
  }
  if (values.sarif) write(values.sarif, JSON.stringify(buildSarifReport(context), null, 2))
  if (values.json) write(values.json, JSON.stringify(buildJsonReport(context), null, 2))
  // Le résumé va sur la sortie d'erreur quand un rapport est écrit sur la sortie standard.
  const summaryStream = values.sarif === '-' || values.json === '-' ? process.stderr : process.stdout
  summaryStream.write(`${renderTextSummary(context)}\n`)
  return evaluateGate(classifyFindings(context), failOn).passed ? 0 : 1
}

const isEntryPoint = typeof process.argv[1] === 'string' && /fortiscope\.(m?js|ts)$/.test(process.argv[1])
if (isEntryPoint) {
  try {
    process.exitCode = run(process.argv.slice(2))
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    process.stderr.write(`fortiscope: ${message}\n${error instanceof UsageError || (error as { code?: string }).code?.startsWith('ERR_PARSE_ARGS') ? `\n${help()}\n` : ''}`)
    process.exitCode = 2
  }
}
