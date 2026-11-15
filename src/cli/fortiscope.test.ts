import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { setLocale } from '../i18n'
import { run } from './fortiscope'

const fixture = new URL('../../test/multi-vdom-ipv6.conf', import.meta.url).pathname
let directory: string
let stdout: string

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'fortiscope-cli-'))
  stdout = ''
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => { stdout += String(chunk); return true })
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
})

afterEach(() => {
  vi.restoreAllMocks()
  rmSync(directory, { recursive: true, force: true })
  setLocale('fr')
})

describe('commande fortiscope', () => {
  it('écrit les rapports et échoue (code 1) quand des constats dépassent le seuil', () => {
    const sarif = join(directory, 'fortiscope.sarif')
    const json = join(directory, 'fortiscope.json')
    expect(run([fixture, '--sarif', sarif, '--json', json, '--source-uri', 'campus/fw.conf'])).toBe(1)
    expect(JSON.parse(readFileSync(sarif, 'utf8')).runs[0].results.length).toBeGreaterThan(0)
    expect(JSON.parse(readFileSync(json, 'utf8')).source.file).toBe('campus/fw.conf')
    expect(stdout).toContain('Seuil « high » dépassé')
  })

  it('réussit (code 0) quand le seuil est désactivé ou que tout est déjà connu', () => {
    expect(run([fixture, '--fail-on', 'none'])).toBe(0)
    const baseline = join(directory, 'baseline.json')
    run([fixture, '--json', baseline, '--fail-on', 'none'])
    expect(run([fixture, '--baseline', baseline])).toBe(0)
  })

  it('continue sans référence au premier passage', () => {
    expect(run([fixture, '--baseline', join(directory, 'absente.json'), '--fail-on', 'none'])).toBe(0)
  })

  it('produit les constats en anglais avec --lang en', () => {
    const json = join(directory, 'report.json')
    run([fixture, '--json', json, '--lang', 'en', '--fail-on', 'none'])
    const report = JSON.parse(readFileSync(json, 'utf8'))
    expect(report.locale).toBe('en')
    expect(report.findings.map((item: { title: string }) => item.title)).toContain('Highly permissive rule')
  })

  it('signale une erreur d’import (code 2)', () => {
    const csv = join(directory, 'export.csv')
    writeFileSync(csv, 'Name;Comment\nweb;ok\n')
    expect(run([csv])).toBe(2)
  })

  it('refuse un seuil inconnu', () => {
    expect(() => run([fixture, '--fail-on', 'urgent'])).toThrow('--fail-on')
  })
})
