// Workspace search combines saved case text with evidence for the selected OS versions.
import { PRODUCTS, VENDORS } from './data.js';
import { labels, STATUS_ORDER } from './render/common.js';
import { rowStatus, shortName } from './rows.js';
import { caseSearchText } from './state.js';

const normalize = (s) => s.toLowerCase().replace(/[\s_.-]+/g, '');
const option = (field, id, label, group, aliases = []) => ({
  field,
  id,
  label,
  group,
  names: [id, label, ...aliases].filter(Boolean).map(normalize),
});
const families = VENDORS.map((v) => ({
  ...option('os', v.id, v.name, 'OS family', [v.vendor]),
  // "RHEL", "Debian", "SLES"…: the first word of the family's version names.
  short: PRODUCTS.find((p) => p.family === v.id)?.name.split(' ')[0] || v.name,
}));
const versions = PRODUCTS.map((p) => ({
  ...option('version', p.id, p.name, 'OS version', [p.code, p.version, p.version.split(' ')[0]]),
  short: shortName(p),
}));
const statuses = STATUS_ORDER.map((s) =>
  option('status', s === 'fix_available' ? 'fixed' : s, labels[s], 'Status', [s]),
);
const options = [...families, ...versions, ...statuses];
const tokens = (query) => query.match(/(?:[^\s"]+|"[^"]*(?:"|$))+/g) || [];
const fieldToken = /^(os|version|status):(.*)$/i;
const same = (entry, value) => entry.names.includes(normalize(value));

// The OS family and version qualifiers form one picker group; values in a group are alternatives.
const GROUPS = { os: ['os', 'version'], status: ['status'] };
const groupOf = (field) => (field === 'status' ? 'status' : 'os');

// Replaces the positive filters of a picker group (none: clears it). Typed exclusions stay intact.
export function replaceSearchFilter(query, group, value = '') {
  const fields = GROUPS[group];
  const remaining = tokens(query).filter((word) => !fields.includes(word.match(fieldToken)?.[1].toLowerCase()));
  if (value) remaining.push(value);
  return remaining.join(' ');
}

// Adds a picker value to the query, or removes it when it is already there.
export function toggleSearchFilter(query, token) {
  const [field, id] = token.split(':');
  if (!selectedSearchFilter(query, field, id)) return [...tokens(query), token].join(' ');
  const matches = (word) => {
    const match = word.match(fieldToken);
    if (match?.[1].toLowerCase() !== field) return false;
    return options.some((o) => o.field === field && o.id === id && same(o, match[2].replaceAll('"', '')));
  };
  return tokens(query)
    .filter((word) => !matches(word))
    .join(' ');
}

export function selectedSearchFilter(query, field, id) {
  return tokens(query).some((word) => {
    const match = word.match(fieldToken);
    if (match?.[1].toLowerCase() !== field) return false;
    return options.some((o) => o.field === field && o.id === id && same(o, match[2].replaceAll('"', '')));
  });
}

// Short label of a picker group's positive filters ("RHEL 9", "Affected +1"), or ''.
export function searchFilterLabel(query, group) {
  const labels = [];
  for (const word of tokens(query)) {
    const match = word.match(fieldToken);
    const field = match?.[1].toLowerCase();
    if (!GROUPS[group].includes(field)) continue;
    const found = options.find((o) => o.field === field && same(o, match[2].replaceAll('"', '')));
    if (found) labels.push(found.short || found.label);
  }
  return labels.length > 1 ? `${labels[0]} +${labels.length - 1}` : labels[0] || '';
}

// A selected OS version must match every filter group; values within a group are alternatives
// (version:rhel8 version:rhel9 matches either).
export function matchesCase(c, query) {
  const words = tokens(query);
  if (!words.length) return true;
  const products = PRODUCTS.filter((p) => c.products?.includes(p.id));
  const rowFilters = {};
  let text;
  for (const word of words) {
    const negative = word.startsWith('-') && word.length > 1;
    const term = (negative ? word.slice(1) : word).replaceAll('"', '').toLowerCase();
    const field = term.match(fieldToken);
    if (!field) {
      text ??= [
        caseSearchText(c),
        c.savedTitle,
        c.searchText,
        ...Object.keys(c.vendorData?.evidence || {}),
        ...Object.keys(c.vendorData?.sources || {}),
        ...products.map((p) => [p.id, p.name, p.family, p.vendor, p.code].join(' ')),
      ]
        .join(' ')
        .toLowerCase();
      if (text.includes(term) === negative) return false;
      continue;
    }
    const [, key, value] = field;
    const ids = new Set(options.filter((o) => o.field === key && same(o, value)).map((o) => o.id));
    const matches = (p) => {
      if (key === 'os') return ids.has(p.family);
      if (key === 'version') return ids.has(p.id);
      const status = rowStatus(c, p);
      return ids.has(status === 'fix_available' ? 'fixed' : status);
    };
    if (negative) {
      if (products.some(matches)) return false;
    } else (rowFilters[groupOf(key)] ??= []).push(matches);
  }
  const groups = Object.values(rowFilters);
  return !groups.length || products.some((p) => groups.every((group) => group.some((filter) => filter(p))));
}

// Use with a stable descending sort after matching, so equally relevant cases keep their activity order.
export function searchRelevance(c, query) {
  const id = c.id.toLowerCase();
  const title = (c.record?.containers?.cna?.title || c.savedTitle || '').toLowerCase();
  let score = 0;
  for (const word of tokens(query)) {
    if (word.startsWith('-') || fieldToken.test(word)) continue;
    const term = word.replaceAll('"', '').toLowerCase();
    if (term === id) score += 10;
    else if (id.includes(term)) score += 4;
    else if (title.includes(term)) score += 2;
  }
  return score;
}
