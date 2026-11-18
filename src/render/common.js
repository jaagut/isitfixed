// Markup shared by the sidebar, the home page and the case page. Functions
// return HTML strings; every dynamic value is escaped here.
import { PRODUCTS, VENDORS, summary } from '../data.js';
import { rowStatus, shortName } from '../rows.js';
import { esc, icons } from '../util.js';

export const STATUS_ORDER = ['affected', 'fix_available', 'inconclusive', 'unaffected', 'unknown'];
export const labels = {
  affected: 'Affected',
  inconclusive: 'Inconclusive',
  unknown: 'No data',
  fixed: 'Fix published',
  fix_available: 'Fix available',
  unaffected: 'Not affected',
};
export const statusSymbols = { affected: '!', fix_available: '↑', inconclusive: '?', unaffected: '✓', unknown: '–' };
export const badge = (s, label = labels[s]) => `<span class="status ${s}"><span class="dot"></span>${label}</span>`;

export const selected = (c) => PRODUCTS.filter((p) => c.products.includes(p.id));
export const sum = (record, cvss) => summary(record, cvss || '3.1');

export function statusCounts(c, products) {
  const counts = Object.fromEntries(STATUS_ORDER.map((s) => [s, 0]));
  for (const p of products) counts[rowStatus(c, p)]++;
  return counts;
}
export function caseStatus(c) {
  if (!c.record && !c.vendorData) return 'unknown';
  const counts = statusCounts(c, selected(c));
  return STATUS_ORDER.find((s) => counts[s]) || 'unknown';
}
export function statusDescription(c) {
  const counts = statusCounts(c, selected(c));
  return (
    STATUS_ORDER.filter((s) => counts[s])
      .map((s) => `${counts[s]} ${labels[s].toLowerCase()}`)
      .join(', ') || 'No OS versions selected'
  );
}
// Thin bar with one segment per OS version, in status order. Segment widths are
// applied from data-flex after rendering (no inline styles under the CSP).
export function statusBar(c) {
  const products = selected(c);
  if (!products.length) return '';
  const rows = products.map((p) => ({ product: p, status: rowStatus(c, p) }));
  const segments = STATUS_ORDER.map((s) => {
    const count = rows.filter(({ status }) => status === s).length;
    return count ? `<span class="${s}" data-flex="${count}"></span>` : '';
  }).join('');
  const breakdown = rows
    .map(
      ({ product, status }) =>
        `<span class="status-chip ${status}">${logo(product.family)}<span>${esc(shortName(product))}</span><span class="visually-hidden"> — ${labels[status]}</span></span>`,
    )
    .join('');
  return `<span class="status-meter"><span class="status-total" aria-label="${rows.length} selected OS version${rows.length === 1 ? '' : 's'}">${rows.length} ${rows.length === 1 ? 'OS' : 'OSs'}</span><span class="status-track"><span class="status-breakdown">${breakdown}</span><span class="status-bar" aria-hidden="true">${segments}</span></span></span>`;
}
export function cvssChip(s) {
  if (s.score == null) return '';
  const severity = esc(s.severity.toLowerCase());
  return `<span class="cvss ${severity}" title="CVSS ${esc(s.cvssVersion)} · ${severity}">${esc(s.score.toFixed(1))}</span>`;
}

// Share, archive and delete; used by the sidebar and the home page.
const iconButton = (attrs, label, icon) =>
  `<button type="button" ${attrs} aria-label="${label}" title="${label}">${icon}</button>`;
export function caseActions(c) {
  const archived = Boolean(c.archived),
    verb = archived ? 'Unarchive' : 'Archive';
  return [
    '<span class="case-actions">',
    iconButton(`data-share="${c.id}"`, `Share ${c.id}`, icons.share),
    iconButton(`data-archive="${c.id}"`, `${verb} ${c.id}`, archived ? icons.unarchive : icons.archive),
    iconButton(`class="delete-case" data-delete="${c.id}"`, `Delete ${c.id}`, icons.trash),
    '</span>',
  ].join('');
}

export const logo = (family) =>
  `<img class="vendor-logo logo-${family}" src="/assets/logos/${VENDORS.find((v) => v.id === family)?.logo || family}.svg" alt="" width="28" height="28">`;
