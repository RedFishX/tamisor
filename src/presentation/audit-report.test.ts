import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { analyzeConfiguration } from '../domain/analyzer'
import { createExecutiveSummary, renderHtmlReport, serializeRecommendationsCli } from './audit-report'

const audit = analyzeConfiguration(`config firewall policy
edit 1
set name "Global"
set srcintf "lan"
set dstintf "wan"
set srcaddr "all"
set dstaddr "all"
set action accept
set service "ALL"
next
end`)

describe('audit reports', () => {
  it('produit un résumé exécutif chiffré', () => {
    expect(createExecutiveSummary(audit)).toContain('1 politique active')
    expect(createExecutiveSummary(audit)).toContain('1 alerte critique')
  })

  it('génère un rapport HTML autonome et imprimable', () => {
    const html = renderHtmlReport(audit, 'site.conf')
    expect(html).toContain('<!doctype html>')
    expect(html).toContain('@media print')
    expect(html).toContain('site.conf')
    expect(html).toContain('Règle très permissive')
    expect(html).toContain('--green: #146c53')
    expect(html).toContain('class="brand-mark"')
    expect(html).toContain('Forti<span>Scope</span>')
    expect(html).toContain('data-severity="critical"')
    expect(html).toContain('data-category="permissive"')
    expect(html).toContain('id="report-search"')
    expect(html).toContain('id="severity-filter"')
    expect(html).toContain('id="category-filter"')
    expect(html).toContain('<details class="finding')
    expect(html).toContain('addEventListener')
    expect(html).toContain('.finding.severity-critical>summary{background:var(--red-soft)')
    expect(html).toContain('.finding-body{background:var(--surface)')
    expect(html).toContain('.finding>summary{color:var(--ink)')
    expect(html).toContain('.finding-body{background:var(--surface);color:var(--ink)')
    expect(html).toContain('.badge{background:var(--surface)!important;color:var(--ink)!important')
    expect(html).toContain('font:16px/1.65')
    expect(html).toContain('.finding-title strong{font-size:16px')
    expect(html).toContain('<strong class="policy-title">Global</strong>')
    expect(html).toContain('Règle #1 · Règle très permissive · Permissive')
    expect(html).toContain('button class="metric critical" data-metric="critical"')
    expect(html).toContain('button class="metric warning" data-metric="permissive"')
    expect(html).toContain('button class="metric shadowed" data-metric="shadowed"')
    expect(html).toContain('.metric.critical::before{background:var(--red)')
    expect(html).toContain('.metric.critical strong{color:var(--red)')
    expect(html).toContain("document.querySelectorAll('[data-metric]')")
    expect(html).toContain("button.classList.toggle('active'")
    expect(html).not.toMatch(/https?:\/\/(?:fonts\.googleapis|fonts\.gstatic)/)
  })

  it('regroupe les recommandations CLI disponibles', () => {
    const cli = serializeRecommendationsCli(audit.findings)
    expect(cli).toContain('# Règle 1 - Global')
    expect(cli).toContain('config firewall policy')
  })

  describe('CSP du rapport HTML autonome', () => {
    const html = renderHtmlReport(audit, 'site</script><img src=x onerror=alert(1)>.conf')
    const script = html.match(/<script>([\s\S]*?)<\/script>/)![1]

    it('autorise le seul script du fichier, par son empreinte', () => {
      const hash = `sha256-${createHash('sha256').update(script).digest('base64')}`
      const csp = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)![1]
      // Si ce test échoue après une modification du script, remplacer REPORT_SCRIPT_SHA256 par la valeur « hash » ci-dessus.
      expect(csp).toContain(`script-src '${hash}'`)
      expect(csp).toContain("default-src 'none'")
      expect(csp).not.toMatch(/unsafe-eval|unsafe-hashes|script-src[^;]*unsafe-inline|https?:/)
      expect(html.indexOf('Content-Security-Policy')).toBeLessThan(html.indexOf('<style>'))
    })

    it('n’a aucun gestionnaire d’événement en attribut ni autre script exécutable', () => {
      expect(html).not.toMatch(/<[^>]*\son[a-z]+\s*=/i)
      expect(html.match(/<script/g)).toHaveLength(2)
      expect(html).toContain('<script type="application/json" id="report-config">')
    })

    it('garde la langue hors du script : le bloc JSON est valide et ne peut pas fermer sa balise', () => {
      const json = html.match(/<script type="application\/json" id="report-config">([\s\S]*?)<\/script>/)![1]
      expect(json).not.toContain('<')
      expect(JSON.parse(json)).toMatchObject({ shownLabel: [expect.any(String), expect.any(String)], isEnglish: expect.any(Boolean) })
    })

    it('est une source JavaScript valide', () => {
      expect(() => new Function(script)).not.toThrow()
    })
  })
})
