import type { Finding, FirewallPolicy } from '../domain/audit'

const values = (items: string[]): string => items.join(', ') || 'Non défini'

export const generatePolicyMarkdown = (
  policy: FirewallPolicy,
  findings: Finding[],
  sourceName: string,
): string => {
  const statistics = [
    policy.hitCount !== undefined ? `| Correspondances | ${policy.hitCount} |` : '',
    policy.lastUsed ? `| Dernière utilisation | ${policy.lastUsed} |` : '',
  ].filter(Boolean).join('\n')
  const findingsDocumentation = findings.length
    ? findings.map((finding) => `### ${finding.title}\n\n${finding.detail}\n\n**Recommandation :** ${finding.recommendation.summary}\n\n${finding.recommendation.actions.map((action) => `- ${action}`).join('\n')}`).join('\n\n')
    : 'Aucun constat détecté pour cette policy.'

  return `# ${policy.name}

**Source :** ${sourceName}  
**Policy :** #${policy.id}  
**VDOM :** ${policy.vdom ?? 'global'}  
**Famille :** ${(policy.family ?? 'ipv4').toUpperCase()}

## Rôle de la policy

Du réseau **${values(policy.srcaddr)}** vers **${values(policy.dstaddr)}**, via **${values(policy.service)}**, pendant **${values(policy.schedule)}**. Action appliquée : **${policy.action}**.

## Critères de correspondance

| Critère | Valeur |
| --- | --- |
| Interfaces | ${values(policy.srcintf)} → ${values(policy.dstintf)} |
| Adresses | ${values(policy.srcaddr)} → ${values(policy.dstaddr)} |
| Services | ${values(policy.service)} |
| Horaire | ${values(policy.schedule)} |
| Journalisation | ${policy.logtraffic} |
| Profils de sécurité | ${policy.utmStatus} |
${statistics}
${policy.comments ? `\n## Contexte\n\n${policy.comments}\n` : ''}
## Constats d’audit

${findingsDocumentation}
`
}
