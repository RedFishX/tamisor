import type { Finding, FirewallPolicy } from '../domain/audit'
import { complianceReferences, formatComplianceReference } from '../domain/compliance'
import { tr } from '../i18n'

const values = (items: string[]): string => items.join(', ') || tr('Non défini', 'Not set')

export const generatePolicyMarkdown = (
  policy: FirewallPolicy,
  findings: Finding[],
  sourceName: string,
): string => {
  const statistics = [
    policy.hitCount !== undefined ? `| ${tr('Correspondances', 'Hits')} | ${policy.hitCount} |` : '',
    policy.lastUsed ? `| ${tr('Dernière utilisation', 'Last used')} | ${policy.lastUsed} |` : '',
  ].filter(Boolean).join('\n')
  const findingsDocumentation = findings.length
    ? findings.map((finding) => `### ${finding.title}\n\n${finding.detail}\n\n**${tr('Recommandation :', 'Recommendation:')}** ${finding.recommendation.summary}\n\n${finding.recommendation.actions.map((action) => `- ${action}`).join('\n')}\n\n**${tr('Référentiels (indicatif) :', 'Frameworks (indicative):')}**\n\n${complianceReferences(finding).map((reference) => `- ${formatComplianceReference(reference)}`).join('\n')}`).join('\n\n')
    : tr('Aucun constat détecté pour cette policy.', 'No finding detected for this policy.')

  const c = tr(' :', ':')
  return `# ${policy.name}

**Source${c}** ${sourceName}  
**Policy${c}** #${policy.id}  
**VDOM${c}** ${policy.vdom ?? 'global'}  
**${tr('Famille', 'Family')}${c}** ${(policy.family ?? 'ipv4').toUpperCase()}

## ${tr('Rôle de la policy', 'Policy purpose')}

${tr(
    `Du réseau **${values(policy.srcaddr)}** vers **${values(policy.dstaddr)}**, via **${values(policy.service)}**, pendant **${values(policy.schedule)}**. Action appliquée : **${policy.action}**.`,
    `From **${values(policy.srcaddr)}** to **${values(policy.dstaddr)}**, using **${values(policy.service)}**, during **${values(policy.schedule)}**. Action applied: **${policy.action}**.`,
  )}

## ${tr('Critères de correspondance', 'Match criteria')}

| ${tr('Critère', 'Criterion')} | ${tr('Valeur', 'Value')} |
| --- | --- |
| Interfaces | ${values(policy.srcintf)} → ${values(policy.dstintf)} |
| ${tr('Adresses', 'Addresses')} | ${values(policy.srcaddr)} → ${values(policy.dstaddr)} |
| Services | ${values(policy.service)} |
| ${tr('Horaire', 'Schedule')} | ${values(policy.schedule)} |
| ${tr('Journalisation', 'Logging')} | ${policy.logtraffic} |
| ${tr('Profils de sécurité', 'Security profiles')} | ${policy.utmStatus} |
${statistics}
${policy.comments ? `\n## ${tr('Contexte', 'Context')}\n\n${policy.comments}\n` : ''}
## ${tr('Constats d’audit', 'Audit findings')}

${findingsDocumentation}
`
}
