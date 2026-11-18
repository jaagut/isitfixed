// Browser workspace state: defaults, validation of saved state and backups, migrations.
import { CVSS_VERSIONS, migrateProducts, validId } from './data.js';
import { validTheme } from './cases.js';

export const STORAGE_KEY = 'cve-desk-v1';
// Bump to show the first-visit disclaimer again after its text changes.
export const DISCLAIMER_VERSION = '2026-11';

export const defaultState = () => ({
  version: 1,
  cases: [],
  products: ['rhel9', 'rhel10', 'debian12'],
  auto: true,
  activity: [],
  theme: 'system',
  tmds: true,
});

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Throws for anything that is not a CVE Desk workspace; repairs optional fields.
export function validateState(s) {
  if (
    s?.version !== 1 ||
    !Array.isArray(s.cases) ||
    !Array.isArray(s.products) ||
    !Array.isArray(s.activity) ||
    s.cases.length > 1000
  )
    throw Error('Invalid workspace backup.');
  const ids = new Set();
  for (const c of s.cases) {
    if (
      !validId(c.id) ||
      ids.has(c.id) ||
      !Array.isArray(c.products) ||
      typeof c.notes !== 'string' ||
      (c.archived !== undefined && typeof c.archived !== 'number') ||
      (c.record && c.record.cveMetadata?.cveId !== c.id)
    )
      throw Error('Invalid case in backup.');
    ids.add(c.id);
    c.products = migrateProducts(c.products);
    // Older saves have no action baseline: the next evaluation sets one silently.
    if (c.actionBaseline !== undefined && !isObject(c.actionBaseline?.rows)) delete c.actionBaseline;
  }
  if (s.cvss !== undefined && !CVSS_VERSIONS.includes(s.cvss)) delete s.cvss;
  s.theme = validTheme(s.theme);
  s.tmds = s.tmds !== false;
  s.auto = s.auto !== false;
  if (s.disclaimerAccepted !== undefined && typeof s.disclaimerAccepted !== 'string') delete s.disclaimerAccepted;
  s.products = migrateProducts(s.products);
  return s;
}

export function loadState(storage) {
  try {
    const saved = storage.getItem(STORAGE_KEY);
    if (saved) return validateState(JSON.parse(saved));
  } catch {
    /* Unreadable or invalid saved state: start with the default workspace. */
  }
  return defaultState();
}
