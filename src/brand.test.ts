import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { LEGACY_STORAGE_PREFIXES, STORAGE_PREFIX } from './brand'
import { localeStorageKey } from './i18n'

const bootScript = readFileSync(new URL('../public/boot.js', import.meta.url), 'utf8')

const memoryStorage = (entries: Record<string, string>) => {
  const values = new Map(Object.entries(entries))
  return {
    values,
    get length() { return values.size },
    key: (index: number) => [...values.keys()][index] ?? null,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value) },
    removeItem: (key: string) => { values.delete(key) },
  }
}

const runBoot = (storage: ReturnType<typeof memoryStorage>, prefersDark = false) => {
  const document = { documentElement: { dataset: {} as Record<string, string> } }
  new Function('localStorage', 'document', 'matchMedia', bootScript)(storage, document, () => ({ matches: prefersDark }))
  return document.documentElement.dataset
}

describe('identité et migration du stockage', () => {
  it('public/boot.js utilise les mêmes préfixes que src/brand.ts', () => {
    expect(bootScript).toContain(`var prefix = '${STORAGE_PREFIX}'`)
    for (const legacy of LEGACY_STORAGE_PREFIXES) expect(bootScript).toContain(`'${legacy}'`)
    expect(localeStorageKey).toBe(`${STORAGE_PREFIX}locale`)
  })

  it('recopie les anciennes clés sans écraser les nouvelles, puis applique le thème migré', () => {
    const storage = memoryStorage({
      'fortiscope-theme': 'dark',
      'fortiscope-acknowledged': '["a"]',
      'fortiscope-meeting:fw.conf': '{}',
      'shadowline-acknowledged': '["b"]',
      'shadowline-locale': 'en',
      'tamisor-locale': 'fr',
      'autre-cle': 'x',
    })
    expect(runBoot(storage).theme).toBe('dark')
    expect(Object.fromEntries(storage.values)).toEqual({
      'tamisor-theme': 'dark',
      'tamisor-acknowledged': '["b"]',
      'tamisor-meeting:fw.conf': '{}',
      'tamisor-locale': 'fr',
      'autre-cle': 'x',
    })
  })

  it('suit le thème du système sans préférence enregistrée', () => {
    expect(runBoot(memoryStorage({}), true).theme).toBe('dark')
    expect(runBoot(memoryStorage({}), false).theme).toBe('light')
  })
})
