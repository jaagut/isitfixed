import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateState, loadState, defaultState, STORAGE_KEY, DISCLAIMER_VERSION } from '../src/state.js';

const storage = (value) => ({ getItem: (k) => (k === STORAGE_KEY ? value : null) });

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
  assert.throws(
    () => validateState({ ...defaultState(), cases: [{ id: 'CVE-1', products: [], notes: '' }] }),
    /Invalid case/,
  );
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
