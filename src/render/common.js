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
// One status of the breakdown: a pill tinted in the status colour with the status symbol and
// one logo per OS version (versions as tooltips). The status name is the pill's label.
function statusGroup(status, products) {
  const versions = products.map(shortName);
  const discs = products.map(
    (p, i) => `<span class="stack-logo" data-tip="${esc(versions[i])}">${logo(p.family)}</span>`,
  );
  const label = esc(`${labels[status]}: ${versions.join(', ')}`);
  return [
    `<span class="status-group ${status}" role="img" aria-label="${label}" data-tip="${esc(labels[status])}">`,
    `<span class="case-status ${status}" aria-hidden="true">${statusSymbols[status]}</span>`,
    discs.join(''),
    '</span>',
  ].join('');
}
// Thin bar with one segment per OS version, in status order; hovering the card reveals one line
// above it with each status and its OS logos in the same order. Segment widths are applied from
// data-flex after rendering (no inline styles under the CSP).
export function statusBar(c, { showChecked = false } = {}) {
  const products = selected(c);
  if (!products.length) return '';
  const groups = Object.fromEntries(STATUS_ORDER.map((status) => [status, []]));
  for (const product of products) groups[rowStatus(c, product)].push(product);
  const populated = STATUS_ORDER.filter((status) => groups[status].length);
  const segments = populated.map((s) => `<span class="${s}" data-flex="${groups[s].length}"></span>`).join('');
  const breakdown = populated.map((s) => statusGroup(s, groups[s])).join('');
  const checked = showChecked
    ? `<small class="status-checked" data-checked-at="${Number(c.apiChecked || c.checked) || 0}"></small>`
    : '';
  const total = `${products.length} OS ${products.length === 1 ? 'version' : 'versions'}`;
  return [
    '<span class="status-meter">',
    `<span class="status-breakdown"><span class="status-groups">${breakdown}</span>${checked}</span>`,
    `<span class="status-total">${total}</span>`,
    `<span class="status-bar" aria-hidden="true">${segments}</span>`,
    '</span>',
  ].join('');
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
