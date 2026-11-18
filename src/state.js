// Browser workspace state: defaults, validation of saved state and backups, migrations.
import { CVSS_VERSIONS, migrateProducts, validId } from './data.js';
import { validTheme } from './cases.js';

// Keep the original keys so the rebrand preserves existing workspaces and preferences.
export const STORAGE_KEY = 'cve-desk-v1';
// The appearance has its own key so the early theme script does not parse the workspace.
export const THEME_KEY = 'cve-desk-theme';
// A saved workspace that cannot be read is kept under this prefix plus a timestamp (at most one).
export const RECOVERY_PREFIX = `${STORAGE_KEY}-recovery-`;
// Bump to show the first-visit disclaimer again after its text changes.
export const DISCLAIMER_VERSION = '2026-11-18';
// Open cases are watched by the server (MAX_WATCHES_PER_WORKSPACE); archived ones are not.
export const MAX_OPEN_CASES = 200;
export const MAX_CASES = 1000;

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
const isTime = (v) => typeof v === 'number' && Number.isFinite(v);
const strings = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
const TIMES = ['created', 'updatedAt', 'apiChecked', 'attempted'];

// One vendor evidence entry as the API returns it; anything else is dropped.
function evidenceEntry(e) {
  if (!isObject(e) || typeof e.status !== 'string') return null;
  const out = { ...e, status: e.status };
  for (const k of ['fix', 'affected', 'unaffected', 'mitigation', 'links']) out[k] = strings(e[k]);
  for (const k of ['name', 'source', 'note']) if (out[k] !== undefined && typeof out[k] !== 'string') delete out[k];
  return out;
}
function vendorData(v, id) {
  if (!isObject(v) || v.id !== id) return undefined;
  const evidence = {};
  for (const [product, list] of Object.entries(isObject(v.evidence) ? v.evidence : {}))
    if (Array.isArray(list)) evidence[product] = list.map(evidenceEntry).filter(Boolean);
  const sources = Object.fromEntries(
    Object.entries(isObject(v.sources) ? v.sources : {}).filter(([, s]) => isObject(s)),
  );
  return { ...v, evidence, sources };
}
// Action baseline row (see changes.js); an invalid row is dropped and adopted again silently.
function baselineRow(r) {
  if (!isObject(r) || typeof r.status !== 'string' || !Array.isArray(r.fixes) || !Array.isArray(r.mitigations))
    return null;
  const row = { status: r.status, fixes: strings(r.fixes), mitigations: strings(r.mitigations) };
  const t = r.tmds;
  if (isObject(t) && typeof t.agent === 'string' && typeof t.ksp === 'string') {
    row.tmds = { agent: t.agent, ksp: t.ksp };
    if (isObject(t.cells))
      row.tmds.cells = Object.fromEntries(
        Object.entries(t.cells).filter(
          ([, c]) => Array.isArray(c) && c.length === 2 && c.every((s) => typeof s === 'string'),
        ),
      );
  }
  return row;
}
function actionBaseline(b) {
  if (!isObject(b) || !isObject(b.rows)) return undefined;
  const rows = {};
  for (const [id, r] of Object.entries(b.rows)) {
    const row = baselineRow(r);
    if (row) rows[id] = row;
  }
  const next = { rows };
  if (typeof b.rejected === 'boolean') next.rejected = b.rejected;
  return next;
}
// Repairs one case; returns null for a case that cannot be kept.
function sanitizeCase(c) {
  if (!isObject(c) || typeof c.id !== 'string' || !validId(c.id)) return null;
  c.products = migrateProducts(strings(c.products));
  if (typeof c.notes !== 'string') c.notes = '';
  if (c.archived !== undefined && !isTime(c.archived)) delete c.archived;
  for (const k of TIMES) if (c[k] !== undefined && !isTime(c[k])) delete c[k];
  if (c.hasUpdate !== undefined) c.hasUpdate = c.hasUpdate === true;
  if (c.record !== undefined && (!isObject(c.record) || c.record.cveMetadata?.cveId !== c.id)) {
    delete c.record;
    delete c.checked;
  }
  if (c.vendorData !== undefined) {
    const v = vendorData(c.vendorData, c.id);
    if (v) c.vendorData = v;
    else delete c.vendorData;
  }
  if (c.vex !== undefined && !isObject(c.vex)) delete c.vex;
  if (c.cache !== undefined && !isObject(c.cache)) delete c.cache;
  if (c.error !== undefined && typeof c.error !== 'string') delete c.error;
  if (c.changedRows !== undefined) {
    const r = c.changedRows;
    if (isObject(r) && isTime(r.at)) c.changedRows = { ids: strings(r.ids), at: r.at };
    else delete c.changedRows;
  }
  // Older saves have no action baseline: the next evaluation sets one silently.
  if (c.actionBaseline !== undefined) {
    const b = actionBaseline(c.actionBaseline);
    if (b) c.actionBaseline = b;
    else delete c.actionBaseline;
  }
  return c;
}
const activityEntry = (a) =>
  isObject(a) && typeof a.id === 'string' && typeof a.text === 'string' && isTime(a.time)
    ? { id: a.id, text: a.text, time: a.time, unread: a.unread === true }
    : null;

// Open cases beyond the watch limit are archived, least recently active first.
function capOpenCases(s, now) {
  const open = s.cases.filter((c) => !c.archived);
  if (open.length <= MAX_OPEN_CASES) return 0;
  const latest = (c) => Math.max(c.updatedAt || 0, c.created || 0);
  const excess = [...open].sort((a, b) => latest(a) - latest(b)).slice(0, open.length - MAX_OPEN_CASES);
  for (const c of excess) c.archived = now;
  return excess.length;
}

/**
 * Validates and repairs a workspace (saved state or backup) in place.
 * Throws only for something that is not a Is It Fixed workspace or exceeds MAX_CASES;
 * invalid cases, activity entries, baselines and vendor snapshots are dropped.
 * @param report optional object that receives {droppedCases, archivedCases}
 */
export function validateState(s, report = {}, now = Date.now()) {
  if (!isObject(s) || s.version !== 1 || !Array.isArray(s.cases)) throw Error('Invalid workspace backup.');
  if (s.cases.length > MAX_CASES)
    throw Error(`The workspace has ${s.cases.length} cases; Is It Fixed keeps at most ${MAX_CASES}.`);
  const ids = new Set(),
    cases = [];
  for (const raw of s.cases) {
    const c = sanitizeCase(raw);
    if (!c || ids.has(c.id)) continue;
    ids.add(c.id);
    cases.push(c);
  }
  report.droppedCases = s.cases.length - cases.length;
  s.cases = cases;
  report.archivedCases = capOpenCases(s, now);
  s.activity = (Array.isArray(s.activity) ? s.activity : []).map(activityEntry).filter(Boolean).slice(0, 100);
  s.products = Array.isArray(s.products) ? migrateProducts(strings(s.products)) : defaultState().products;
  if (s.cvss !== undefined && !CVSS_VERSIONS.includes(s.cvss)) delete s.cvss;
  if (s.osOrder !== undefined) {
    if (Array.isArray(s.osOrder)) s.osOrder = strings(s.osOrder);
    else delete s.osOrder;
  }
  if (s.sidebarWidth !== undefined && !isTime(s.sidebarWidth)) delete s.sidebarWidth;
  s.theme = validTheme(s.theme);
  s.tmds = s.tmds !== false;
  s.auto = s.auto !== false;
  if (s.disclaimerAccepted !== undefined && typeof s.disclaimerAccepted !== 'string') delete s.disclaimerAccepted;
  return s;
}

// Cheap check before saving: everything validateState would reject outright.
export function saveable(s) {
  if (!isObject(s) || s.version !== 1 || !Array.isArray(s.cases) || s.cases.length > MAX_CASES) return false;
  const ids = new Set();
  for (const c of s.cases) {
    if (!isObject(c) || typeof c.id !== 'string' || !validId(c.id) || ids.has(c.id)) return false;
    ids.add(c.id);
  }
  return s.cases.filter((c) => !c.archived).length <= MAX_OPEN_CASES;
}

function recoveryKeys(storage) {
  const keys = [];
  for (let i = 0; i < (storage.length || 0); i++) {
    const k = storage.key(i);
    if (k?.startsWith(RECOVERY_PREFIX)) keys.push(k);
  }
  return keys;
}
export const recoveryKey = (storage) => recoveryKeys(storage).sort().at(-1) || null;

// Keeps an unreadable saved workspace under a recovery key (replacing an older copy).
// Returns the key, or null when it could not be kept anywhere but its original place.
function keepForRecovery(storage, raw, now) {
  const key = `${RECOVERY_PREFIX}${now}`;
  for (const k of recoveryKeys(storage)) storage.removeItem(k);
  try {
    storage.setItem(key, raw);
    return key;
  } catch {
    // Not enough space for a copy: move it instead.
  }
  try {
    storage.removeItem(STORAGE_KEY);
    storage.setItem(key, raw);
    return key;
  } catch {
    try {
      storage.setItem(STORAGE_KEY, raw);
    } catch {
      /* Nothing more to do: the caller must not overwrite it. */
    }
    return null;
  }
}

/**
 * Loads the saved workspace.
 * @returns {{state, report, recovery: string|null, locked: boolean, raw?: string}} `recovery` is the key
 *   under which an unreadable saved workspace was kept; `locked` means it could not be moved aside (saving
 *   would overwrite it), and `raw` then holds it for an export.
 */
export function loadWorkspace(storage, now = Date.now()) {
  const report = {};
  let raw;
  try {
    raw = storage.getItem(STORAGE_KEY);
  } catch {
    return { state: defaultState(), report, recovery: null, locked: false };
  }
  if (!raw) return { state: defaultState(), report, recovery: null, locked: false };
  try {
    return { state: validateState(JSON.parse(raw), report, now), report, recovery: null, locked: false };
  } catch {
    const recovery = keepForRecovery(storage, raw, now);
    return { state: defaultState(), report, recovery, locked: !recovery, raw: recovery ? undefined : raw };
  }
}
export const loadState = (storage) => loadWorkspace(storage).state;

const list = (v) => (Array.isArray(v) ? v : []);

// Search includes package names and descriptions: the CNA title often names neither.
export function caseSearchText(c) {
  const cna = c.record?.containers?.cna;
  return [
    c.id,
    c.notes,
    c.savedTitle,
    c.searchText,
    cna?.title,
    ...list(cna?.descriptions).map((d) => d?.value),
    ...list(cna?.affected).flatMap((a) => [a?.vendor, a?.product, a?.packageName]),
    ...Object.values(c.vendorData?.evidence || {}).flatMap((entries) =>
      list(entries).flatMap((e) => [e?.name, e?.note, ...list(e?.fix)]),
    ),
  ]
    .filter((v) => typeof v === 'string')
    .join(' ')
    .toLowerCase();
}

const pick = (value, keys) =>
  Object.fromEntries(keys.filter((key) => value?.[key] !== undefined).map((key) => [key, value[key]]));
function compactRecord(record) {
  const cna = record?.containers?.cna;
  if (!cna) return record;
  return {
    cveMetadata: record.cveMetadata,
    containers: {
      cna: {
        ...pick(cna, ['title', 'descriptions', 'metrics', 'problemTypes', 'providerMetadata']),
        ...(Array.isArray(cna.affected)
          ? {
              affected: cna.affected.map((a) =>
                pick(a, ['vendor', 'product', 'packageName', 'defaultStatus', 'versions']),
              ),
            }
          : {}),
      },
      ...(Array.isArray(record.containers.adp) ? { adp: record.containers.adp.map((a) => pick(a, ['metrics'])) } : {}),
    },
  };
}

// localStorage commonly allows about 5 MiB, counting UTF-16 strings. Leave room for
// preferences, watch identity and other origin keys; failure still preserves the old save.
export const WORKSPACE_CHAR_BUDGET = 2_000_000;
export function persistWorkspace(storage, state, budget = WORKSPACE_CHAR_BUDGET) {
  if (!saveable(state)) return { saved: false, reason: 'invalid' };
  const cases = state.cases.map((c) => ({
    ...c,
    ...(c.record ? { record: compactRecord(c.record) } : {}),
  }));
  const snapshot = { ...state, cases };
  const candidates = cases
    .filter((c) => c.record || c.vendorData)
    .sort(
      (a, b) =>
        Boolean(b.archived) - Boolean(a.archived) || (a.updatedAt || a.created || 0) - (b.updatedAt || b.created || 0),
    );
  let evictedSnapshots = 0;
  const evict = (c) => {
    // Keep enough metadata for sidebar search when a disposable snapshot is omitted.
    c.savedTitle = c.record?.containers?.cna?.title || c.savedTitle;
    // Bound derived search metadata, never user-authored notes.
    c.searchText = caseSearchText(c).slice(0, 16000);
    for (const key of ['record', 'vendorData', 'apiChecked', 'checked', 'cache']) delete c[key];
    evictedSnapshots++;
  };
  let raw = JSON.stringify(snapshot);
  if (raw.length > budget) {
    let estimate = raw.length;
    while (estimate > budget && candidates.length) {
      const c = candidates.shift(),
        before = JSON.stringify(c).length;
      evict(c);
      estimate -= before - JSON.stringify(c).length;
    }
    raw = JSON.stringify(snapshot);
  }
  while (true) {
    if (raw.length > budget) return { saved: false, reason: 'full', evictedSnapshots };
    try {
      storage.setItem(STORAGE_KEY, raw);
      return { saved: true, compacted: true, evictedSnapshots };
    } catch {
      // Actual quotas can be smaller (or another origin key can occupy space).
      // Retry with fewer caches, but never delete the previous workspace to make room.
      if (!candidates.length) return { saved: false, reason: 'unavailable', evictedSnapshots };
      const count = Math.ceil(candidates.length / 2);
      for (const c of candidates.splice(0, count)) evict(c);
      raw = JSON.stringify(snapshot);
    }
  }
}
