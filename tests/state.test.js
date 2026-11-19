import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateState,
  saveable,
  defaultState,
  DISCLAIMER_VERSION,
  MAX_OPEN_CASES,
  caseSearchText,
  followDefaults,
} from '../src/state.js';
import { loadWorkspace, saveWorkspace, loadTheme, saveTheme, createStore, requestPersistence } from '../src/storage.js';
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

function store(initial) {
  const map = new Map(initial === undefined ? [] : [['workspace', initial]]);
  return {
    map,
    get: async (k) => structuredClone(map.get(k)),
    put: async (entries) => {
      for (const [key, value] of entries) map.set(key, structuredClone(value));
    },
  };
}
test('IndexedDB workspace roundtrip retains large evidence and snapshots the call immediately', async () => {
  const db = store(),
    s = defaultState();
  s.cases.push(
    kase(1, {
      notes: 'private',
      record: {
        cveMetadata: { cveId: 'CVE-2026-0001' },
        containers: { cna: { title: 'Title', descriptions: [{ value: 'x'.repeat(3000000) }] } },
      },
    }),
  );
  const write = saveWorkspace(s, db);
  s.cases[0].notes = 'later';
  assert.equal((await write).saved, true);
  const loaded = await loadWorkspace(db);
  assert.equal(loaded.state.cases[0].notes, 'private');
  assert.equal(loaded.state.cases[0].record.containers.cna.descriptions[0].value.length, 3000000);
});
test('unreadable current workspace is locked without deleting or overwriting it', async () => {
  const raw = { version: 77, cases: [] },
    db = store(raw);
  const loaded = await loadWorkspace(db);
  assert.equal(loaded.locked, true);
  assert.deepEqual(loaded.raw, raw);
  assert.deepEqual(db.map.get('workspace'), raw);
});
test('storage unavailable and quota failures are reported without destroying last save', async () => {
  const db = store(defaultState()),
    before = structuredClone(db.map);
  db.put = async () => {
    throw Object.assign(Error('full'), { name: 'QuotaExceededError' });
  };
  assert.deepEqual(await saveWorkspace(defaultState(), db), { saved: false, reason: 'full' });
  assert.deepEqual(db.map, before);
  const unavailable = {
    get: async () => {
      throw Error('disabled');
    },
  };
  assert.equal((await loadWorkspace(unavailable)).error, 'disabled');
  assert.deepEqual((await loadWorkspace(store())).state, defaultState());
  await assert.rejects(() => createStore(null).get('workspace'), /unavailable/);
});
test('theme preference shares browser database and unknown values follow system', async () => {
  const db = store();
  assert.equal(await loadTheme(db), 'system');
  await saveTheme('dark', db);
  assert.equal(await loadTheme(db), 'dark');
  await saveWorkspace({ ...defaultState(), theme: 'light' }, db);
  assert.equal(await loadTheme(db), 'light');
});
test('removed imported VEX is discarded from restore and saves', async () => {
  const s = { ...defaultState(), cases: [kase(1, { vex: { private: true } })] },
    db = store();
  await saveWorkspace(s, db);
  assert.equal(db.map.get('workspace').cases[0].vex, undefined);
  assert.equal(validateState(structuredClone(s)).cases[0].vex, undefined);
  assert.ok(s.cases[0].vex);
});
test('case search includes descriptions and affected package names in archived cases', () => {
  const c = kase(1, {
    archived: 1,
    record: {
      containers: {
        cna: {
          title: 'A generic title',
          affected: [{ packageName: 'php' }],
          descriptions: [{ value: 'Another keyword' }],
        },
      },
    },
  });
  assert.ok(caseSearchText(c).includes('php'));
  assert.ok(caseSearchText(c).includes('keyword'));
});

test('overlapping workspace saves commit in call order and a failed save does not block later writes', async () => {
  const db = store(),
    commits = [];
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  db.put = async (entries) => {
    const state = entries.find(([key]) => key === 'workspace')[1];
    if (state.theme === 'dark') await gate;
    commits.push(state.theme);
  };
  const first = saveWorkspace({ ...defaultState(), theme: 'dark' }, db);
  const second = saveWorkspace({ ...defaultState(), theme: 'light' }, db);
  await Promise.resolve();
  assert.deepEqual(commits, []);
  release();
  await Promise.all([first, second]);
  assert.deepEqual(commits, ['dark', 'light']);
  db.put = async () => {
    throw Error('unavailable');
  };
  assert.equal((await saveWorkspace(defaultState(), db)).saved, false);
  db.put = async () => {};
  assert.equal((await saveWorkspace(defaultState(), db)).saved, true);
});

test('cases with an untouched OS selection follow the defaults; customized ones keep theirs', () => {
  const s = validateState({
    version: 1,
    products: ['rhel9', 'debian12'],
    activity: [],
    cases: [
      { id: 'CVE-2026-0001', products: ['debian12', 'rhel9'], notes: '' },
      { id: 'CVE-2026-0002', products: ['rhel9'], notes: '' },
      { id: 'CVE-2026-0003', products: ['rhel9', 'debian12'], notes: '', customProducts: true },
    ],
  });
  assert.deepEqual(
    s.cases.map((c) => c.customProducts),
    [false, true, true],
  );
  s.products = ['rhel10', 'ubuntu2404'];
  const changed = followDefaults(s);
  assert.deepEqual(
    changed.map((c) => c.id),
    ['CVE-2026-0001'],
  );
  assert.deepEqual(s.cases[0].products, ['rhel10', 'ubuntu2404']);
  assert.deepEqual(s.cases[1].products, ['rhel9']);
  assert.deepEqual(followDefaults(s), []);
});
test('persistent storage is requested only when not yet granted and failures are tolerated', async () => {
  let asked = 0;
  const storage = (persisted, grant) => ({
    persisted: async () => persisted,
    persist: async () => {
      asked++;
      return grant;
    },
  });
  assert.equal(await requestPersistence(storage(true, false)), true);
  assert.equal(asked, 0, 'already persisted: no request');
  assert.equal(await requestPersistence(storage(false, true)), true);
  assert.equal(await requestPersistence(storage(false, false)), false);
  assert.equal(asked, 2);
  assert.equal(await requestPersistence(undefined), false);
  assert.equal(await requestPersistence({}), false);
  assert.equal(
    await requestPersistence({
      persist: async () => {
        throw Error('denied');
      },
    }),
    false,
  );
});
