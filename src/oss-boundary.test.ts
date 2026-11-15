import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'

// Le code publié (src/) ne doit dépendre d'aucun fichier hors de src/ autre que package.json :
// il doit compiler seul, une fois publié sans le reste du dépôt.
const root = new URL('.', import.meta.url).pathname
const files = (directory: string): string[] => readdirSync(directory).flatMap((name) => {
  const path = join(directory, name)
  return statSync(path).isDirectory() ? files(path) : /\.(ts|css)$/.test(name) ? [path] : []
})

describe('frontière du code publié', () => {
  it('n’importe rien en dehors de src/ (hors package.json)', () => {
    const offenders = files(root).flatMap((file) => [...readFileSync(file, 'utf8').matchAll(/(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)]
      .map((match) => relative(root, join(file, '..', match[1])))
      .filter((target) => target.startsWith('..') && !target.endsWith('package.json'))
      .map((target) => `${relative(root, file)} -> ${target}`))
    expect(offenders).toEqual([])
  })
})
