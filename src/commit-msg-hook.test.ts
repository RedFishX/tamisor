import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Le hook .githooks/commit-msg refuse tout message qui ne suit pas Conventional Commits.
const hook = new URL('../.githooks/commit-msg', import.meta.url).pathname
const directory = mkdtempSync(join(tmpdir(), 'commit-msg-'))

const run = (message: string) => {
  const file = join(directory, 'COMMIT_EDITMSG')
  writeFileSync(file, message)
  return spawnSync('sh', [hook, file], { encoding: 'utf8' })
}

describe('hook commit-msg', () => {
  it.each([
    'feat(ui): add search and pill filters\n',
    'fix: expire malformed review dates\n',
    'build(deps): update vite to 8.3.8\n\nCorps libre.\n',
    'feat(api)!: drop the legacy login route\n',
    'chore(release): 0.1.0\n',
    'Merge branch main into feature\n',
    'Revert "feat: add x"\n',
    'fixup! fix(ci): expire malformed review dates\n',
    '# commentaire de l’éditeur\nfix(ci): ignore les lignes de commentaire\n',
  ])('accepte %j', (message) => {
    expect(run(message).status).toBe(0)
  })

  it.each([
    'Update the CI\n',
    'feat:\n',
    'feat: \n',
    'Feat: capital type\n',
    'feature(ui): wrong type\n',
    'feat(UI): uppercase scope\n',
    'feat(ui) add the colon\n',
    `fix: ${'x'.repeat(100)}\n`,
    '\n',
  ])('refuse %j', (message) => {
    const result = run(message)
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('Conventional Commits')
  })
})
