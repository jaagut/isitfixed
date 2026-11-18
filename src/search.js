// Workspace search combines saved case text with evidence for the selected OS versions.
import { PRODUCTS, VENDORS } from './data.js';
import { labels, STATUS_ORDER } from './render/common.js';
import { rowStatus } from './rows.js';
import { caseSearchText } from './state.js';

const normalize = (s) => s.toLowerCase().replace(/[\s_.-]+/g, '');
const option = (field, id, label, group, aliases = []) => ({
  field,
  id,
  label,
  group,
  names: [id, label, ...aliases].filter(Boolean).map(normalize),
});
const families = VENDORS.map((v) => option('os', v.id, v.name, 'OS family', [v.vendor]));
const versions = PRODUCTS.map((p) =>
  option('version', p.id, p.name, 'OS version', [p.code, p.version, p.version.split(' ')[0]]),
);
const statuses = STATUS_ORDER.map((s) =>
  option('status', s === 'fix_available' ? 'fixed' : s, labels[s], 'Status', [s]),
);
const options = [...families, ...versions, ...statuses];
const tokens = (query) => query.match(/(?:[^\s"]+|"[^"]*(?:"|$))+/g) || [];
const fieldToken = /^(os|version|status):(.*)$/i;
const same = (entry, value) => entry.names.includes(normalize(value));

// Positive row filters must all match the same selected OS version.
export function matchesCase(c, query) {
  const words = tokens(query);
  if (!words.length) return true;
  const products = PRODUCTS.filter((p) => c.products?.includes(p.id));
  const rowFilters = [];
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
    } else rowFilters.push(matches);
  }
  return !rowFilters.length || products.some((p) => rowFilters.every((filter) => filter(p)));
}

export function searchSuggestions(query) {
  const words = tokens(query);
  const active = /\s$/.test(query) ? '' : words.at(-1) || '';
  const prefix = query.slice(0, query.length - active.length);
  const negative = active.startsWith('-') ? '-' : '';
  const term = active.slice(negative.length).replaceAll('"', '');
  const field = term.match(fieldToken);
  const needle = normalize(field ? field[2] : term);
  const candidates = options
    .filter((o) => !field || o.field === field[1].toLowerCase())
    .map((o) => ({
      ...o,
      score: !needle || o.names.includes(needle) ? 0 : o.names.some((n) => n.startsWith(needle)) ? 1 : 2,
    }))
    .filter((o) => o.names.some((n) => n.includes(needle)))
    .sort((a, b) => a.score - b.score);
  // On focus show a representative set from each group; typing a qualifier exposes all its options.
  const results = !term ? [families, versions, statuses].flatMap((group) => group.slice(0, 3)) : candidates;
  return results.map(({ label, group, field, id }) => ({
    label,
    group,
    value: prefix + negative + field + ':' + id + ' ',
  }));
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
