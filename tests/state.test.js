import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateState,
  loadState,
  loadWorkspace,
  saveable,
  recoveryKey,
  defaultState,
  STORAGE_KEY,
  RECOVERY_PREFIX,
  DISCLAIMER_VERSION,
  MAX_OPEN_CASES,
} from '../src/state.js';

const storage = (value) => ({ getItem: (k) => (k === STORAGE_KEY ? value : null) });
// localStorage stand-in with an optional quota in characters.
function memoryStorage(entries = {}, quota = Infinity) {
  const map = new Map(Object.entries(entries));
  const used = () => [...map].reduce((n, [k, v]) => n + k.length + v.length, 0);
  return {
    map,
    get length() {
      return map.size;
    },
    key: (i) => [...map.keys()][i] ?? null,
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem(k, v) {
      const before = map.get(k);
      map.set(k, String(v));
      if (used() > quota) {
        if (before === undefined) map.delete(k);
        else map.set(k, before);
        throw Error('QuotaExceededError');
      }
    },
    removeItem: (k) => map.delete(k),
  };
}
const kase = (n, extra = {}) => ({ id: `CVE-2026-${String(n).padStart(4, '0')}`, products: [], notes: '', ...extra });

test('old saves migrate: TMDS on, no baseline, no disclaimer acknowledgement', () => {
  const old = {
    version: 1,
    products: ['rhel9', 'debian11'],
    auto: true,
    activity: [],
    cases: [{ id: 'CVE-2024-1086', products: ['rhel9', 'windows'], notes: '' }],
  };
  const s = validateState(old);
  assert.equal(s.tmds, true);
  assert.equal(s.theme, 'system');
  assert.deepEqual(s.products, ['rhel9']);
  assert.deepEqual(s.cases[0].products, ['rhel9', 'windows10', 'windows11', 'server2022', 'server2025']);
  assert.equal(s.cases[0].actionBaseline, undefined);
  assert.notEqual(s.disclaimerAccepted, DISCLAIMER_VERSION);
});

test('invalid optional fields are repaired; invalid workspaces are rejected', () => {
  const s = validateState({
    ...defaultState(),
    tmds: false,
    disclaimerAccepted: 42,
    cases: [{ id: 'CVE-2024-1086', products: [], notes: '', actionBaseline: { rows: 'x' } }],
  });
  assert.equal(s.tmds, false);
  assert.equal(s.disclaimerAccepted, undefined);
  assert.equal(s.cases[0].actionBaseline, undefined);
  assert.throws(() => validateState({ version: 2 }), /Invalid workspace/);
  assert.throws(() => validateState(null), /Invalid workspace/);
  const report = {};
  const dropped = validateState(
    { ...defaultState(), cases: [{ id: 'CVE-1', products: [], notes: '' }, kase(1), kase(1), 'x', kase(2)] },
    report,
  );
  assert.deepEqual(
    dropped.cases.map((c) => c.id),
    ['CVE-2026-0001', 'CVE-2026-0002'],
  );
  assert.equal(report.droppedCases, 3);
  assert.equal(
    validateState({ ...defaultState(), cases: [kase(1, { id: `CVE-2026-${'1'.repeat(30)}` })] }).cases.length,
    0,
  );
});

test('nested data is sanitized instead of throwing (activity, baselines, vendor snapshots)', () => {
  const s = validateState({
    version: 1,
    products: 'rhel9',
    activity: [
      { id: 'CVE-2026-0001', text: 'x', time: 1, unread: 1 },
      null,
      { id: 1 },
      { id: 'a', text: 'b', time: 'now' },
    ],
    cases: [
      kase(1, {
        products: ['rhel9', 7],
        notes: 5,
        archived: 'yes',
        created: 'today',
        record: { cveMetadata: { cveId: 'CVE-2026-9999' } },
        checked: 5,
        vendorData: {
          id: 'CVE-2026-0001',
          evidence: {
            rhel9: [{ status: 'fixed', fix: ['kernel-1-1.el9', 3], links: 'x' }, 'bad', { fix: [] }],
            x: 'y',
          },
          sources: { rhel: { checked: 1 }, bad: 'x' },
        },
        actionBaseline: {
          rows: {
            rhel9: {
              status: 'affected',
              fixes: [],
              mitigations: [],
              tmds: { agent: 'pending', ksp: 'nodata', cells: { a: ['x', 'y'], b: 'z' } },
            },
            rhel10: { status: 'affected' },
            debian12: null,
          },
          rejected: 'no',
        },
        changedRows: { ids: 'rhel9' },
      }),
      kase(2, { vendorData: { id: 'CVE-2026-0003', evidence: {} } }),
    ],
  });
  assert.deepEqual(s.activity, [{ id: 'CVE-2026-0001', text: 'x', time: 1, unread: false }]);
  assert.deepEqual(s.products, defaultState().products);
  const [c, d] = s.cases;
  assert.deepEqual(c.products, ['rhel9']);
  assert.equal(c.notes, '');
  assert.equal(c.archived, undefined);
  assert.equal(c.created, undefined);
  assert.equal(c.record, undefined, 'a record of another CVE is dropped');
  assert.equal(c.checked, undefined);
  assert.deepEqual(c.vendorData.evidence, {
    rhel9: [{ status: 'fixed', fix: ['kernel-1-1.el9'], affected: [], unaffected: [], mitigation: [], links: [] }],
  });
  assert.deepEqual(Object.keys(c.vendorData.sources), ['rhel']);
  assert.deepEqual(c.actionBaseline, {
    rows: {
      rhel9: {
        status: 'affected',
        fixes: [],
        mitigations: [],
        tmds: { agent: 'pending', ksp: 'nodata', cells: { a: ['x', 'y'] } },
      },
    },
  });
  assert.equal(c.changedRows, undefined);
  assert.equal(d.vendorData, undefined, 'a snapshot of another CVE is dropped');
});

test('limits: more than 1000 cases is rejected; open cases beyond 200 are archived', () => {
  const many = (n, extra) => Array.from({ length: n }, (_, i) => kase(i + 1, extra));
  assert.throws(() => validateState({ ...defaultState(), cases: many(1001) }), /at most 1000/);
  const report = {};
  const s = validateState({ ...defaultState(), cases: many(250).map((c, i) => ({ ...c, updatedAt: i })) }, report, 42);
  assert.equal(report.archivedCases, 50);
  assert.equal(s.cases.filter((c) => !c.archived).length, MAX_OPEN_CASES);
  assert.equal(s.cases[0].archived, 42, 'the least recently updated cases are archived');
  assert.equal(s.cases[249].archived, undefined);
  assert.ok(saveable(s));
  assert.ok(!saveable({ ...s, cases: [...s.cases, kase(1)] }), 'duplicate id');
  assert.ok(!saveable({ ...s, cases: [...s.cases, kase(999)] }), 'one open case too many');
  assert.ok(!saveable({ ...defaultState(), cases: many(1001, { archived: 1 }) }));
});

test('loading falls back to defaults for missing or broken storage', () => {
  assert.deepEqual(loadState(storage(null)), defaultState());
  assert.deepEqual(loadState(storage('{broken')), defaultState());
  const throwing = {
    getItem() {
      throw Error('SecurityError');
    },
  };
  assert.deepEqual(loadState(throwing), defaultState());
  assert.equal(loadState(storage(JSON.stringify({ ...defaultState(), tmds: false }))).tmds, false);
});

test('an unreadable saved workspace is kept under one recovery key instead of being overwritten', () => {
  const broken = JSON.stringify({ ...defaultState(), cases: Array.from({ length: 1001 }, (_, i) => kase(i + 1)) });
  const store = memoryStorage({ [STORAGE_KEY]: broken, [`${RECOVERY_PREFIX}1`]: 'older' });
  const r = loadWorkspace(store, 5);
  assert.deepEqual(r.state, defaultState());
  assert.equal(r.recovery, `${RECOVERY_PREFIX}5`);
  assert.equal(r.locked, false);
  assert.equal(store.getItem(r.recovery), broken);
  assert.equal(store.getItem(`${RECOVERY_PREFIX}1`), null, 'at most one recovery copy');
  assert.equal(recoveryKey(store), r.recovery);
  // Not enough room for a copy: it is moved instead.
  const tight = memoryStorage({ [STORAGE_KEY]: '{broken' }, 40);
  const moved = loadWorkspace(tight, 6);
  assert.equal(tight.getItem(moved.recovery), '{broken');
  assert.equal(tight.getItem(STORAGE_KEY), null);
  // No room at all: the original stays where it is and the app must not save over it.
  const full = memoryStorage({ [STORAGE_KEY]: '{broken' }, 20);
  const locked = loadWorkspace(full, 7);
  assert.equal(locked.locked, true);
  assert.equal(locked.raw, '{broken');
  assert.equal(full.getItem(STORAGE_KEY), '{broken');
});

test('persistence drops unused record payload while preserving assessments and in-memory export', async () => {
  const { persistWorkspace } = await import('../src/state.js');
  const s = defaultState();
  const c = kase(1, {
    record: {
      cveMetadata: { cveId: 'CVE-2026-0001' },
      containers: {
        cna: {
          title: 'PHP problem',
          references: [{ url: 'x'.repeat(100000) }],
          affected: [
            {
              vendor: 'Vendor',
              product: 'PHP',
              versions: [{ version: '1', status: 'affected' }],
              unused: 'x'.repeat(10000),
            },
          ],
          metrics: [{ cvssV3_1: { baseScore: 9 } }],
        },
      },
    },
  });
  s.cases.push(c);
  const before = JSON.stringify(s),
    store = memoryStorage();
  assert.equal(persistWorkspace(store, s).saved, true);
  const saved = loadState(store);
  assert.deepEqual(saved.cases[0].record.containers.cna.affected[0].versions, [{ version: '1', status: 'affected' }]);
  assert.equal(saved.cases[0].record.containers.cna.references, undefined);
  assert.equal(JSON.stringify(s), before);
});

test('quota fallback preserves user data and baseline, omits oldest archived snapshots, and retains package search', async () => {
  const { persistWorkspace, caseSearchText } = await import('../src/state.js');
  const s = defaultState();
  s.cases.push(
    kase(1, {
      archived: 1,
      notes: 'keep my note',
      products: ['debian13'],
      actionBaseline: { rows: {} },
      record: {
        cveMetadata: { cveId: 'CVE-2026-0001' },
        containers: {
          cna: {
            title: 'A vulnerability',
            affected: [{ product: 'php', versions: [{ version: 'x'.repeat(15000), status: 'affected' }] }],
          },
        },
      },
    }),
  );
  const store = memoryStorage({}, 3000);
  const result = persistWorkspace(store, s);
  assert.equal(result.saved, true);
  assert.equal(result.evictedSnapshots, 1);
  const saved = loadState(store).cases[0];
  assert.equal(saved.record, undefined);
  assert.equal(saved.notes, 'keep my note');
  assert.deepEqual(saved.products, ['debian13']);
  assert.deepEqual(saved.actionBaseline, { rows: {} });
  assert.ok(caseSearchText(saved).includes('php'));
  assert.ok(s.cases[0].record);
});

test('unavailable storage does not replace the prior save or throw', async () => {
  const { persistWorkspace } = await import('../src/state.js');
  const store = memoryStorage({ [STORAGE_KEY]: 'old' }, 100);
  const s = defaultState();
  s.cases.push(kase(1, { notes: 'x'.repeat(200) }));
  assert.equal(persistWorkspace(store, s).saved, false);
  assert.equal(store.getItem(STORAGE_KEY), 'old');
});

test('persistence never discards an imported VEX document to satisfy quota', async () => {
  const { persistWorkspace } = await import('../src/state.js');
  const s = defaultState();
  s.cases.push(kase(1, { vex: { document: { title: 'imported', data: 'x'.repeat(5000) } } }));
  const store = memoryStorage({ [STORAGE_KEY]: 'prior save' }, 1000);
  assert.equal(persistWorkspace(store, s).saved, false);
  assert.equal(store.getItem(STORAGE_KEY), 'prior save');
  assert.equal(s.cases[0].vex.document.title, 'imported');
});
