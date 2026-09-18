import { describe, expect, it } from 'vitest'
import type { Finding, Recommendation } from '../domain/audit'
import { renderRecommendation, serializeFindingsCsv } from './recommendation-view'

describe('renderRecommendation', () => {
  it('affiche le plan d’action, le CLI et la référence Fortinet en échappant le contenu', () => {
    const recommendation: Recommendation = {
      summary: 'Restreindre <all>',
      actions: ['Créer les objets nécessaires.', 'Tester avec Policy Match.'],
      cli: 'config firewall policy\n    edit 10\nend',
      reference: {
        title: 'Fortinet - Firewall policy',
        url: 'https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/656084/firewall-policy',
      },
    }

    const html = renderRecommendation(recommendation)

    expect(html).toContain('Restreindre &lt;all&gt;')
    expect(html).toContain('<li>Créer les objets nécessaires.</li>')
    expect(html).toContain('<code>config firewall policy')
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noreferrer noopener"')
    expect(html).toContain(recommendation.reference.url)
  })

  it('inclut les actions, le CLI et la source dans l’export CSV', () => {
    const finding = {
      id: 'permissive-10',
      policyId: '10',
      policyName: 'Accès global',
      order: 1,
      severity: 'critical',
      category: 'permissive',
      title: 'Règle très permissive',
      detail: 'Périmètre trop large.',
      evidence: ['Source: all'],
      recommendation: {
        summary: 'Appliquer le moindre privilège.',
        actions: ['Limiter les sources.', 'Limiter les services.'],
        cli: 'edit 10\nset srcaddr "LAN"',
        reference: { title: 'Fortinet - Firewall policy', url: 'https://docs.fortinet.com/policy' },
      },
    } satisfies Finding

    const csv = serializeFindingsCsv([finding])

    expect(csv).toContain('recommandation;actions;cli;reference')
    expect(csv).toContain('Appliquer le moindre privilège.')
    expect(csv).toContain('Limiter les sources. | Limiter les services.')
    expect(csv).toContain('https://docs.fortinet.com/policy')
  })
})