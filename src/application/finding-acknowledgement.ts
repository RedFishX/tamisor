import type { Finding } from '../domain/audit'

export const acknowledgementKey = (sourceName: string, finding: Finding): string =>
  `${sourceName}:${finding.id}`

export const filterAcknowledgedFindings = (
  findings: Finding[],
  acknowledged: Set<string>,
  sourceName: string,
  showAcknowledged: boolean,
): Finding[] => showAcknowledged
  ? findings
  : findings.filter((finding) => !acknowledged.has(acknowledgementKey(sourceName, finding)))


export interface AcknowledgementRecord {
  key: string
  justification: string
  reviewDate: string
  acknowledgedAt: string
}
export const toggleAcknowledgement = (acknowledged: Set<string>, key: string): Set<string> => {
  const next = new Set(acknowledged)
  if (next.has(key)) next.delete(key)
  else next.add(key)
  return next
}

export const serializeAcknowledgements = (records: AcknowledgementRecord[]): string =>
  JSON.stringify({ version: 1, acknowledgements: records }, null, 2)

export const parseAcknowledgements = (content: string): AcknowledgementRecord[] => {
  const parsed: unknown = JSON.parse(content)
  if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as { acknowledgements?: unknown }).acknowledgements)) {
    throw new Error('Format d’acquittements invalide')
  }
  return (parsed as { acknowledgements: unknown[] }).acknowledgements.filter((record): record is AcknowledgementRecord => {
    if (!record || typeof record !== 'object') return false
    const candidate = record as Partial<AcknowledgementRecord>
    return typeof candidate.key === 'string' && typeof candidate.justification === 'string' && typeof candidate.reviewDate === 'string' && typeof candidate.acknowledgedAt === 'string'
  })
}
