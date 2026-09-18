import { describe, expect, it } from 'vitest'
import type { Finding } from '../domain/audit'
import { acknowledgementKey, filterAcknowledgedFindings, toggleAcknowledgement } from './finding-acknowledgement'
import { parseAcknowledgements, serializeAcknowledgements } from './finding-acknowledgement'

const finding = { id: 'ipv4-shadowed-2' } as Finding

describe('finding acknowledgement', () => {
  it('isole un acquittement par fichier et identifiant', () => {
    expect(acknowledgementKey('site-a.conf', finding)).toBe('site-a.conf:ipv4-shadowed-2')
  })

  it('masque les constats acquittés sauf demande explicite', () => {
    const acknowledged = new Set([acknowledgementKey('site-a.conf', finding)])
    expect(filterAcknowledgedFindings([finding], acknowledged, 'site-a.conf', false)).toEqual([])
    expect(filterAcknowledgedFindings([finding], acknowledged, 'site-a.conf', true)).toEqual([finding])
  })

  it('permet d’acquitter puis de restaurer un constat', () => {
    const key = acknowledgementKey('site-a.conf', finding)
    expect(toggleAcknowledgement(new Set(), key)).toEqual(new Set([key]))
    expect(toggleAcknowledgement(new Set([key]), key)).toEqual(new Set())
  })

  it('sérialise et recharge les acquittements avec leur revue', () => {
    const records = [{ key: 'audit:finding', justification: 'Exception validée', reviewDate: '2026-12-01', acknowledgedAt: '2026-09-15T10:00:00.000Z' }]
    expect(parseAcknowledgements(serializeAcknowledgements(records))).toEqual(records)
  })
})