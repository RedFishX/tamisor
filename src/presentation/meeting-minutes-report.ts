import type { AuditResult } from '../domain/audit'
import { boardProgress, cardsInColumn, findingsForCard, meetingColumnLabel, policyForCard, type MeetingBoard, type MeetingCard } from '../domain/meeting'
import { formatUsage } from '../domain/policy-usage'
import { cardLocation, formatDuration, minutesSections } from '../domain/meeting-minutes'
import { severityLabel } from '../domain/labels'
import { getLocale, tr } from '../i18n'

const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character] ?? character)

const paragraph = (value: string) => escapeHtml(value.trim()).replace(/\r?\n/g, '<br>')

const renderCard = (card: MeetingCard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const policy = policyForCard(audit, card)
  const findings = findingsForCard(audit, card)
  const location = cardLocation(card, policy?.order)
  const rows: Array<[string, string]> = []
  const usage = formatUsage(policy)
  if (usage) rows.push([tr('Utilisation', 'Usage'), escapeHtml(usage)])
  if (card.proposal) rows.push([tr('Proposition initiale', 'Initial proposal'), escapeHtml(meetingColumnLabel(card.proposal))])
  if (card.rationale.trim()) rows.push([tr('Justification', 'Rationale'), paragraph(card.rationale)])
  if (card.dueDate) rows.push([tr('Échéance', 'Due date'), escapeHtml(card.dueDate)])
  if (card.prepNote.trim()) rows.push([tr('Notes de préparation', 'Preparation notes'), paragraph(card.prepNote)])
  return `<article class="card">
    <h3>${tr('Règle', 'Rule')} #${escapeHtml(card.policyId)} · ${escapeHtml(card.policyName)}${location ? ` <small>${escapeHtml(location)}</small>` : ''}</h3>
    ${card.orphan ? `<p class="warning">${tr('Policy absente de la configuration chargée.', 'Policy missing from the loaded configuration.')}</p>` : ''}
    ${findings.length ? `<ul class="findings">${findings.map((finding) => `<li><span class="badge ${finding.severity}">${severityLabel(finding.severity)}</span>${escapeHtml(finding.title)}</li>`).join('')}</ul>` : ''}
    ${rows.length ? `<dl>${rows.map(([label, value]) => `<dt>${label}</dt><dd>${value}</dd>`).join('')}</dl>` : ''}
  </article>`
}

export const renderMinutesHtml = (board: MeetingBoard, audit: Pick<AuditResult, 'policies' | 'findings'>): string => {
  const progress = boardProgress(board)
  const duration = formatDuration(board.startedAt, board.endedAt)
  const sections = minutesSections()
  return `<!doctype html>
<html lang="${getLocale()}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(board.title)}</title>
<style>
:root{--ink:#17201d;--muted:#646e6a;--paper:#f6f7f4;--surface:#fff;--line:#dfe3df;--green:#146c53;--red:#b83232;--red-soft:#fae7e4;--amber:#955808;--amber-soft:#fff0d2;--blue:#2e609b;--blue-soft:#e8f0fa;--count:#e6eae5}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 "Plus Jakarta Sans","Segoe UI",system-ui,sans-serif}
main{width:min(920px,calc(100% - 32px));margin:40px auto 72px}.eyebrow{margin:0 0 6px;color:var(--green);font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}
h1{margin:0 0 14px;font-size:30px;line-height:1.2}.meta{margin:0 0 24px;padding:0;display:flex;flex-wrap:wrap;gap:6px 24px;list-style:none;color:var(--muted);font-size:13px}.meta strong{color:var(--ink)}
.counts{display:grid;grid-template-columns:repeat(5,1fr);margin:0 0 36px;border-top:2px solid var(--ink)}.counts div{padding:12px 0}.counts span{display:block;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.counts strong{font:600 26px "Azeret Mono",Consolas,monospace}
h2{margin:36px 0 10px;padding-bottom:8px;border-bottom:1px solid var(--line);font-size:18px}.card{padding:16px 0;border-bottom:1px solid var(--line);break-inside:avoid}.card h3{margin:0 0 8px;font-size:15px}.card h3 small{color:var(--muted);font-weight:500}
.findings{margin:0 0 10px;padding:0;list-style:none;font-size:13px}.findings li{margin:3px 0;display:flex;gap:8px;align-items:center}.badge{padding:1px 6px;border-radius:3px;font-size:10px;font-weight:800;text-transform:uppercase}.critical{background:var(--red-soft);color:var(--red)}.high{background:var(--amber-soft);color:var(--amber)}.medium{background:var(--blue-soft);color:var(--blue)}.low{background:var(--count);color:var(--muted)}
dl{margin:0;display:grid;grid-template-columns:190px 1fr;gap:4px 16px;font-size:13px}dt{color:var(--muted);font-weight:700}dd{margin:0}.warning{margin:0 0 8px;color:var(--red);font-size:13px;font-weight:700}
button{position:fixed;top:16px;right:16px;padding:8px 14px;border:1px solid var(--line);border-radius:5px;background:var(--surface);font:inherit;font-weight:700;cursor:pointer}
@media(max-width:640px){.counts{grid-template-columns:repeat(3,1fr)}dl{grid-template-columns:1fr}button{position:static;margin:16px}}
@media print{body{background:#fff}button{display:none}main{width:100%;margin:0}}
</style></head><body><button type="button" onclick="window.print()">${tr('Imprimer', 'Print')}</button><main>
<p class="eyebrow">${tr('Compte rendu de réunion', 'Meeting minutes')}</p><h1>${escapeHtml(board.title)}</h1>
<ul class="meta"><li>Date <strong>${escapeHtml(board.date)}</strong></li><li>Configuration <strong>${escapeHtml(board.sourceName)}</strong></li><li>Participants <strong>${escapeHtml(board.participants.join(', ') || tr('non renseignés', 'not specified'))}</strong></li>${duration ? `<li>${tr('Durée', 'Duration')} <strong>${duration}</strong></li>` : ''}</ul>
<section class="counts">${sections.map(({ column, heading }) => `<div><span>${heading}</span><strong>${progress.byColumn[column]}</strong></div>`).join('')}</section>
${sections.map(({ column, heading }) => ({ heading, cards: cardsInColumn(board, column) })).filter(({ cards }) => cards.length)
    .map(({ heading, cards }) => `<h2>${heading} (${cards.length})</h2>${cards.map((card) => renderCard(card, audit)).join('')}`).join('')}
</main></body></html>`
}
