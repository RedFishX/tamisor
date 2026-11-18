import { afterEach, describe, expect, it } from 'vitest'
import { formatNumber, getLocale, plural, resolveLocale, setLocale, tr } from './i18n'
import { analyzeConfiguration } from './domain/analyzer'
import { complianceReferences } from './domain/compliance'
import { severityLabel } from './domain/labels'
import { assessPolicyElements } from './domain/policy-risk'
import { addPolicies, createBoard, moveCard } from './domain/meeting'
import { renderMinutesMarkdown } from './domain/meeting-minutes'
import { renderMeetingBoard, renderMeetingFocus, decisionKeys } from './presentation/meeting-view'
import { renderOverview } from './presentation/overview-view'
import { renderHtmlReport } from './presentation/audit-report'
import { meetingFinding, meetingPolicy } from './test-fixtures/meeting-fixtures'

const configuration = `
config firewall policy
    edit 10
        set name "Internet access"
        set srcintf "lan"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set schedule "always"
        set service "ALL"
        set logtraffic disable
    next
end
`

afterEach(() => setLocale('fr'))

describe('resolveLocale', () => {
  it('respecte la préférence enregistrée, sinon la langue du navigateur', () => {
    expect(resolveLocale('en', 'fr-FR')).toBe('en')
    expect(resolveLocale(null, 'fr-CA')).toBe('fr')
    expect(resolveLocale(null, 'de-DE')).toBe('en')
    expect(resolveLocale('xx', undefined)).toBe('en')
  })
})

describe('tr et plural', () => {
  it('choisit le texte de la langue courante', () => {
    expect(getLocale()).toBe('fr')
    expect(tr('Constats', 'Findings')).toBe('Constats')
    setLocale('en')
    expect(tr('Constats', 'Findings')).toBe('Findings')
  })

  it('applique les règles d’accord de chaque langue', () => {
    expect(plural(0, ['constat', 'constats'], ['finding', 'findings'])).toBe('constat')
    expect(plural(2, ['constat', 'constats'], ['finding', 'findings'])).toBe('constats')
    setLocale('en')
    expect(plural(0, ['constat', 'constats'], ['finding', 'findings'])).toBe('findings')
    expect(plural(1, ['constat', 'constats'], ['finding', 'findings'])).toBe('finding')
  })

  it('formate les nombres selon la langue', () => {
    expect(formatNumber(12450)).toBe('12 450')
    setLocale('en')
    expect(formatNumber(12450)).toBe('12,450')
  })
})

describe('version anglaise', () => {
  it('produit les constats de l’analyse en anglais', () => {
    setLocale('en')
    const findings = analyzeConfiguration(configuration).findings
    const titles = findings.map((finding) => finding.title)
    expect(titles).toContain('Highly permissive rule')
    expect(titles).toContain('Logging disabled')
    const permissive = findings.find((finding) => finding.category === 'permissive')!
    expect(permissive.recommendation.summary).toBe('Apply the principle of least privilege to every match criterion of the policy.')
    expect(permissive.recommendation.cli).toContain('set srcaddr "<approved-source-group>"')
    expect(JSON.stringify(findings)).not.toMatch(/[éèàç]/)
  })

  it('garde des identifiants de constats indépendants de la langue', () => {
    const french = analyzeConfiguration(configuration).findings.map((finding) => finding.id)
    setLocale('en')
    expect(analyzeConfiguration(configuration).findings.map((finding) => finding.id)).toEqual(french)
  })

  it('traduit libellés, conformité et risque par élément', () => {
    setLocale('en')
    expect(severityLabel('high')).toBe('High')
    expect(complianceReferences({ category: 'visibility' })[0].title).toBe('Audit logs are enabled and active for all system components')
    expect(assessPolicyElements(meetingPolicy({ logtraffic: 'disable' })).find((element) => element.key === 'logging')?.value).toBe('Disabled')
  })

  it('rend la réunion et le compte rendu en anglais, avec les raccourcis anglais', () => {
    setLocale('en')
    const findings = [meetingFinding({ policyId: '7', order: 2, category: 'unused', title: 'Rule probably unused' })]
    const audit = { policies: [meetingPolicy({ id: '7', order: 2, hitCount: 0 })], findings }
    const board = addPolicies(createBoard('fw.conf', '2026-11-20'), findings)
    const card = board.cards[0]
    const resolve = () => ({ findings, policy: audit.policies[0] })
    const html = renderMeetingBoard(board, resolve) + renderMeetingFocus(card, resolve(), { queue: [card], running: true }, resolve)
    expect(html).toContain('Proposed: delete')
    expect(html).toContain('Start the meeting')
    expect(html).toContain('data-decide="keep" aria-pressed="false" aria-keyshortcuts="K"')
    // Les données de la fixture (recommandation) restent en français : on vérifie seulement les libellés d'interface.
    for (const french of ['À discuter', 'Proposé', 'Démarrer', 'Ordre du jour', 'Justification', 'Échéance', 'Règle']) expect(html).not.toContain(french)
    expect(decisionKeys()).toEqual({ d: 'delete', m: 'modify', k: 'keep', p: 'postpone' })
    const markdown = renderMinutesMarkdown(moveCard(board, card.policyKey, 'delete'), audit)
    expect(markdown).toContain('# Rule review · fw.conf')
    expect(markdown).toContain('## To delete (1)')
    expect(markdown).toContain('- Usage: 0 hits')
    expect(markdown).toContain('**Summary**: 1 policy on the agenda; 1 to delete')
  })

  it('rend la vue d’ensemble et le rapport HTML en anglais', () => {
    setLocale('en')
    const overview = renderOverview({
      score: 62, tone: 'warning', criticalCount: 0, history: [], families: [], vdoms: [], priorities: [], openFindings: 3,
    })
    expect(overview).toContain('Configuration score')
    expect(overview).toContain('See all 3 findings')
    const report = renderHtmlReport(analyzeConfiguration(configuration), 'fw.conf')
    expect(report).toContain('<html lang="en">')
    expect(report).toContain('Audit report')
    expect(report).toContain('Highly permissive rule')
  })
})
