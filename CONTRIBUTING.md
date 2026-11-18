# Contributing to Tamisor

Thank you for your interest. Reports of false positives or false negatives are particularly useful: attach an
**anonymised** configuration excerpt (addresses, names, passwords, keys and certificates removed).

## Before opening a pull request

```bash
npm install
npm test
npm run build   # strict typecheck + application + CI command
```

- Every visible text is a `tr('français', 'English')` pair (`src/i18n.ts`); no `tr()` call at module level in
  code loaded by the worker (`analyzer.ts`, `csv-policy-parser.ts`).
- Finding identifiers do not depend on the language, and the JSON format / SARIF fingerprints are a contract for
  CI users: do not change them without discussion.
- WCAG 2.2 AA accessibility: a keyboard path for every interaction, announcements through `announce()`.
- Add a test for every new or modified detection rule.

## Commit messages

Messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/): `type(scope): description`,
in English, imperative mood, 100 characters at most on the first line, no trailing period.

| Type | For |
|---|---|
| `feat` | a user-visible feature |
| `fix` | a fix (behaviour, security) |
| `docs` | documentation only |
| `style` | formatting, with no effect on behaviour |
| `refactor` | a rewrite with no change in behaviour |
| `perf` | a performance improvement |
| `test` | tests only |
| `build` | the build, dependencies, Docker images |
| `ci` | continuous integration workflows and examples |
| `chore` | everything else (version, housekeeping) |

The scope is optional (`ui`, `api`, `ci`, `docker`, `meeting`, `cli`…). A `!` before the colon flags a breaking
change (`feat(cli)!: …`). Examples: `fix(ci): expire malformed review dates`,
`build(deps): update vite to 8.3.8`.

A hook checks the format before each commit; to enable it in your copy: `npm run hooks:install`.

## Contributor agreement (CLA)

Tamisor is published under AGPL-3.0 and may also be offered under a commercial license. To keep that possible,
each contributor accepts the [CLA](CLA.md) once, at the time of their first pull request (an automatic comment
explains how). You keep the copyright on your contributions.
