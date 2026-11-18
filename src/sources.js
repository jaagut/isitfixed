// Source cards for a case: one per selected vendor family, the CVE record and,
// with TMDS enabled, the agent inventory and the Kernel Support Package list.
// Pure: returns data for the Sources section and the case status line.
import { VENDORS } from './data.js';
import { HOUR } from './util.js';
import { kernelFamilies } from './tmds.js';

export const STALE_AFTER = 2 * HOUR;
export const SOURCE_STATES = {
  ok: 'OK',
  stale: 'Stale',
  error: 'Error',
  paused: 'Paused',
  'not-published': 'Not published',
  'no-data': 'No data',
  'cve-record': 'Via CVE record',
  loading: 'Loading',
};

// API error texts are short and sanitized; keep them to one readable sentence anyway.
const sentence = (text) => {
  const s = String(text).replace(/\s+/g, ' ').trim().slice(0, 300);
  return /[.!?]$/.test(s) ? s : `${s}.`;
};
const card = (id, name, extra) => ({
  id,
  name,
  state: 'ok',
  checked: null,
  updated: null,
  url: null,
  urlLabel: 'Source data',
  warnings: [],
  notes: [],
  advisories: [],
  excludedImages: 0,
  retryAfter: null,
  ...extra,
});
const isStale = (checked, now) => Boolean(checked) && now - checked > STALE_AFTER;
const STALE_WARNING = 'Last checked more than 2 hours ago.';

function vendorCard(family, s, now) {
  const vendor = VENDORS.find((v) => v.id === family);
  const base = card(family, vendor?.name || family, {
    checked: s?.checked || null,
    updated: s?.sourceUpdated || null,
    url: s?.url || null,
    urlLabel: 'Vendor data',
    advisories: Array.isArray(s?.advisories) ? s.advisories : [],
    excludedImages: s?.excludedImages || 0,
  });
  if (family === 'windows')
    return {
      ...base,
      state: 'cve-record',
      notes: ['Microsoft fixes come from the CVE record (CNA statement) or an imported CSAF file.'],
    };
  if (!s) return { ...base, state: 'no-data', notes: ['No snapshot yet.'] };
  const paused = Number(s.retryAfter) > now;
  if (paused) base.retryAfter = Number(s.retryAfter);
  if (s.error) {
    base.state = paused ? 'paused' : 'error';
    // The server's "next attempt after HH:MM UTC" is shown in local time from retryAfter instead.
    const text = paused ? s.error.replace(/[;,.]?\s*next attempt after \d{1,2}:\d{2}(?: UTC)?\.?/i, '') : s.error;
    base.warnings.push(`${sentence(text)} Showing saved evidence if available.`);
  } else if (paused) {
    base.state = 'paused';
    base.warnings.push('Temporarily paused after repeated failures.');
  } else if (s.notPublished) {
    base.state = 'not-published';
    base.notes.push(`${sentence(s.notPublished)} Check the vendor page.`);
  } else if (isStale(s.checked, now)) {
    base.state = 'stale';
    base.warnings.push(STALE_WARNING);
  }
  return base;
}

function recordCard(c, now) {
  const base = card('cve', 'CVE record', {
    checked: c.checked || null,
    updated: c.record?.cveMetadata?.dateUpdated || null,
    url: `https://cveawg.mitre.org/api/cve/${c.id}`,
    urlLabel: 'Record data',
  });
  if (!c.record) return { ...base, state: 'no-data', notes: ['Not fetched yet.'] };
  if (isStale(c.checked, now)) return { ...base, state: 'stale', warnings: [STALE_WARNING] };
  return base;
}

function inventoryCards(families, products, { data, error }, now) {
  const linux = products.filter((p) => kernelFamilies.includes(p.family));
  const agent = card('tmds-agent', 'TMDS Agent inventory', { urlLabel: 'Download center feed' });
  const ksp = card('tmds-ksp', 'TMDS Kernel Support Packages', { urlLabel: 'Kernel list' });
  if (!data) {
    const state = error ? 'error' : 'loading';
    const warnings = error ? [sentence(error)] : [];
    return [
      { ...agent, state, warnings },
      { ...ksp, state, warnings: [...warnings] },
    ];
  }
  const builds = linux.reduce((n, p) => n + (data.products?.[p.id]?.length || 0), 0);
  agent.checked = data.checked ?? data.attempted ?? null;
  agent.url = data.source || null;
  agent.notes.push(
    linux.length
      ? `${builds} bundled agent build${builds === 1 ? '' : 's'} for the selected OS versions.`
      : 'No selected OS version has a TMDS agent stream.',
  );
  if (data.error) {
    agent.state = 'error';
    agent.warnings.push(`${sentence(data.error)} Showing the last inventory.`);
  } else if (!agent.checked) agent.state = 'no-data';
  else if (isStale(agent.checked, now)) {
    agent.state = 'stale';
    agent.warnings.push(STALE_WARNING);
  }
  const k = data.ksp;
  if (!k) return [agent, { ...ksp, state: 'no-data', notes: ['Not provided by this server.'] }];
  const packages = linux.reduce((n, p) => n + (k.products?.[p.id]?.length || 0), 0);
  Object.assign(ksp, {
    checked: k.checked ?? k.attempted ?? null,
    updated: k.pageUpdated || null,
    url: k.source || null,
  });
  ksp.notes.push(
    linux.length
      ? `${packages} package${packages === 1 ? '' : 's'} for the selected OS versions.`
      : 'No selected OS version has a Kernel Support Package.',
  );
  if (k.error) {
    ksp.state = 'error';
    ksp.warnings.push(`${sentence(k.error)} Showing the last list.`);
  } else if (!ksp.checked) ksp.state = 'no-data';
  else if (isStale(ksp.checked, now)) {
    ksp.state = 'stale';
    ksp.warnings.push(STALE_WARNING);
  }
  return [agent, ksp];
}

/**
 * @param c case
 * @param products selected products (PRODUCTS entries), in display order
 * @param options.tmds whether TMDS is enabled; options.inventory {data, error} of /api/tmds
 */
export function sourceCards(
  c,
  products,
  { tmds = false, inventory = { data: null, error: null }, now = Date.now() } = {},
) {
  const families = [...new Set(products.map((p) => p.family))];
  const cards = [recordCard(c, now), ...families.map((f) => vendorCard(f, c.vendorData?.sources?.[f], now))];
  if (tmds) cards.push(...inventoryCards(families, products, inventory, now));
  return cards;
}

// "Sources checked <time> · <n> sources · <k> warnings".
export function sourceSummary(cards) {
  const times = cards.map((c) => c.checked).filter((t) => typeof t === 'number');
  return {
    checked: times.length ? Math.max(...times) : null,
    count: cards.length,
    warnings: cards.reduce((n, c) => n + c.warnings.length, 0),
  };
}
