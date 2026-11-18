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
// One bar segment per status: its OS logos (one per version) on a tint of the segment colour,
// directly above the coloured strip. One tooltip for the whole tint names the status and versions.
function statusSegment(status, products) {
  const versions = products.map(shortName);
  const discs = products.map((p) => `<span class="stack-logo">${logo(p.family)}</span>`);
  const label = esc(`${labels[status]}: ${versions.join(', ')}`);
  return [
    `<span class="status-seg ${status}" data-flex="${products.length}" role="img" aria-label="${label}">`,
    `<span class="seg-logos" data-tip="${esc(`${labels[status]} · ${versions.join(', ')}`)}">${discs.join('')}</span>`,
    '<span class="seg-fill"></span>',
    '</span>',
  ].join('');
}
// Status bar for a case: one segment per status in STATUS_ORDER, proportional to its OS versions,
// with one slot (and logo) per version. "No data" is left out unless nothing else is known.
// Segment sizes come from data-flex after rendering (no inline styles under the CSP).
export function statusBar(c, { showChecked = false } = {}) {
  const products = selected(c);
  if (!products.length) return '';
  const groups = Object.fromEntries(STATUS_ORDER.map((status) => [status, []]));
  for (const product of products) groups[rowStatus(c, product)].push(product);
  let shown = STATUS_ORDER.filter((s) => groups[s].length);
  if (shown.length > 1) shown = shown.filter((s) => s !== 'unknown');
  const checked = showChecked
    ? `<small class="status-checked" data-checked-at="${Number(c.apiChecked || c.checked) || 0}"></small>`
    : '';
  const segments = shown.map((s) => statusSegment(s, groups[s])).join('');
  return `<span class="status-meter"><span class="status-bar">${segments}</span>${checked}</span>`;
}
export function cvssChip(s) {
  if (s.score == null) return '';
  const severity = esc(s.severity.toLowerCase());
  return `<span class="cvss ${severity}" title="CVSS ${esc(s.cvssVersion)} · ${severity}">${esc(s.score.toFixed(1))}</span>`;
}

// Case actions sit alongside the case-opening button.
const iconButton = (attrs, label, icon) =>
  `<button type="button" ${attrs} aria-label="${label}" title="${label}">${icon}</button>`;
export function archiveCaseAction(c) {
  return iconButton(
    `class="archive-case-action" data-archive="${c.id}"`,
    `${c.archived ? 'Unarchive' : 'Archive'} ${c.id}`,
    c.archived ? icons.unarchive : icons.archive,
  );
}
export function caseActions(c) {
  return [
    '<span class="case-actions">',
    iconButton(`data-share="${c.id}"`, `Share ${c.id}`, icons.share),
    archiveCaseAction(c),
    iconButton(`class="delete-case" data-delete="${c.id}"`, `Delete ${c.id}`, icons.trash),
    '</span>',
  ].join('');
}

export const logo = (family) =>
  `<img class="vendor-logo logo-${family}" src="/assets/logos/${VENDORS.find((v) => v.id === family)?.logo || family}.svg" alt="" width="28" height="28">`;
