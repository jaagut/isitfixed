import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRODUCTS } from '../src/data.js';
import { caseActionState, diffActions, withoutTmds, describeChanges, hashText, tmdsState } from '../src/changes.js';

const ID = 'CVE-2026-1234';
const product = (id) => PRODUCTS.find((p) => p.id === id);
const entry = (name, status, fix = [], extra = {}) => ({
  name,
  status,
  fix,
  affected: [],
  unaffected: [],
  mitigation: [],
  links: [],
  source: 'Red Hat VEX',
  ...extra,
});
// A case snapshot as stored in the browser, with vendor evidence per OS version.
function snapshot(evidence, { rejected = false, sources, ...extra } = {}) {
  return {
    id: ID,
    products: Object.keys(evidence),
    record: { cveMetadata: { cveId: ID, state: rejected ? 'REJECTED' : 'PUBLISHED' } },
    vendorData: {
      id: ID,
      evidence,
      sources: sources || { rhel: { checked: 1 }, debian: { checked: 1 }, ubuntu: { checked: 1 } },
    },
    ...extra,
  };
}
const RHEL9 = [product('rhel9')];
function evaluate(baseline, c, products = RHEL9, inventory = null) {
  const { fingerprint, info } = caseActionState(c, products, inventory);
  return diffActions(baseline, fingerprint, info);
}

test('the first computation sets the baseline silently (old saves without a baseline)', () => {
  const { baseline, changes } = evaluate(undefined, snapshot({ rhel9: [entry('kernel', 'affected')] }));
  assert.deepEqual(changes, []);
  assert.equal(baseline.rows.rhel9.status, 'affected');
  assert.equal(baseline.rejected, false);
});

test('a published fix is reported with its build; unrelated metadata changes are not', () => {
  const before = snapshot({ rhel9: [entry('kernel', 'affected', [], { note: 'Under investigation' })] });
  const { baseline } = evaluate(undefined, before);
  // Source timestamps, notes and advisory links change: not actionable.
  const touched = snapshot(
    { rhel9: [entry('kernel', 'affected', [], { note: 'Triage updated', links: ['https://x.test/RHSA-1'] })] },
    { sources: { rhel: { checked: 99, sourceUpdated: '2026-11-18T10:00:00Z' } } },
  );
  assert.deepEqual(evaluate(baseline, touched).changes, []);
  const fixed = snapshot({
    rhel9: [
      entry('kernel-0:5.14.0-427.13.1.el9_4.x86_64', 'fixed', [
        'kernel-0:5.14.0-427.13.1.el9_4.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)',
        'kernel-core-0:5.14.0-427.13.1.el9_4.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)',
      ]),
    ],
  });
  const result = evaluate(baseline, fixed);
  assert.deepEqual(result.changes, [{ id: 'rhel9', text: 'RHEL 9: fix available (kernel-5.14.0-427.13.1.el9_4)' }]);
  assert.deepEqual(result.baseline.rows.rhel9.fixes, ['5.14.0-427.13.1.el9_4']);
  // Same state again: nothing new.
  assert.deepEqual(evaluate(result.baseline, fixed).changes, []);
});

test('status changes, new builds and mitigations are described per OS version', () => {
  const debian = [product('debian12')];
  const one = snapshot({ debian12: [entry('linux', 'fixed', ['linux 6.1.76-1'], { source: 'Debian tracker' })] });
  const { baseline } = evaluate(undefined, one, debian);
  const two = snapshot({
    debian12: [
      entry('linux', 'fixed', ['linux 6.1.76-1', 'linux 6.1.80-1'], {
        source: 'Debian tracker',
        mitigation: ['Disable   the module.'],
      }),
    ],
  });
  const r = evaluate(baseline, two, debian);
  assert.deepEqual(
    r.changes.map((c) => c.text),
    ['Debian 12: new fixed build (linux 6.1.80-1)', 'Debian 12: mitigation published'],
  );
  // Whitespace-only edits of the mitigation are not a change; real edits are.
  const reworded = snapshot({
    debian12: [
      entry('linux', 'fixed', ['linux 6.1.76-1', 'linux 6.1.80-1'], {
        source: 'Debian tracker',
        mitigation: ['Disable the module.\n'],
      }),
    ],
  });
  assert.deepEqual(evaluate(r.baseline, reworded, debian).changes, []);
  const affected = snapshot({ debian12: [entry('linux', 'affected', [], { source: 'Debian tracker' })] });
  assert.deepEqual(
    evaluate(r.baseline, affected, debian).changes.map((c) => c.text),
    ['Debian 12: status changed to Affected', 'Debian 12: mitigation withdrawn'],
  );
});

test('a rejected CVE is reported once', () => {
  const { baseline } = evaluate(undefined, snapshot({ rhel9: [entry('kernel', 'affected')] }));
  const r = evaluate(baseline, snapshot({ rhel9: [entry('kernel', 'affected')] }, { rejected: true }));
  assert.deepEqual(r.changes, [{ id: null, text: 'CVE rejected' }]);
  assert.equal(r.baseline.rejected, true);
});

test('new OS selections and rows without fetched sources are adopted silently', () => {
  const { baseline } = evaluate(undefined, snapshot({ rhel9: [entry('kernel', 'affected')] }));
  // The user adds Debian 12, but its source has not been fetched yet.
  const pending = snapshot(
    { rhel9: [entry('kernel', 'affected')], debian12: [] },
    { sources: { rhel: { checked: 1 } } },
  );
  const both = [product('rhel9'), product('debian12')];
  const r1 = evaluate(baseline, pending, both);
  assert.deepEqual(r1.changes, []);
  assert.ok(!('debian12' in r1.baseline.rows));
  // Debian arrives with a fix: still the user's own action, no notification.
  const fetched = snapshot({
    rhel9: [entry('kernel', 'affected')],
    debian12: [entry('linux', 'fixed', ['linux 6.1.76-1'])],
  });
  const r2 = evaluate(r1.baseline, fetched, both);
  assert.deepEqual(r2.changes, []);
  assert.equal(r2.baseline.rows.debian12.status, 'fix_available');
  // A temporarily failing source keeps the previous baseline instead of reporting "No data".
  const failing = snapshot(
    { rhel9: [entry('kernel', 'affected')], debian12: [] },
    { sources: { rhel: { checked: 1 }, debian: { error: 'Vendor source unavailable' } } },
  );
  const r3 = evaluate(r2.baseline, failing, both);
  assert.deepEqual(r3.changes, []);
  assert.equal(r3.baseline.rows.debian12.status, 'fix_available');
  // Removing an OS version drops it from the baseline.
  assert.ok(!('debian12' in evaluate(r3.baseline, fetched, RHEL9).baseline.rows));
});

const kernelCase = () =>
  snapshot({
    rhel9: [
      entry('kernel', 'fixed', [
        'kernel-0:5.14.0-741.20.1.el9_9.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)',
      ]),
    ],
  });
const inventory = (kspKernels, agentKernels = ['5_14_0_687_70_1_el9_8_x86_64']) => ({
  enabled: true,
  checked: 1,
  products: { rhel9: [{ release: '20.0.3-31610', architecture: 'x86_64', kernels: agentKernels }] },
  ksp: {
    products: {
      rhel9: [
        {
          architecture: 'x86_64',
          release: '20.0.3-36500',
          filename: 'KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip',
          kernels: kspKernels,
        },
      ],
    },
  },
});

test('TMDS support is reported when the KSP or the bundled agent starts supporting a fix', () => {
  const c = kernelCase();
  const before = evaluate(undefined, c, RHEL9, inventory([['5.14.0-687.64.1.el9_8.x86_64', 'default', null, false]]));
  assert.deepEqual(before.baseline.rows.rhel9.tmds, {
    agent: 'pending',
    ksp: 'pending',
    cells: { 'el9_9/x86_64': ['pending', 'pending'] },
  });
  const ksp = inventory([['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false]]);
  const r = evaluate(before.baseline, c, RHEL9, ksp);
  assert.deepEqual(r.changes, [{ id: 'rhel9', text: 'RHEL 9: KSP support released (KSP 20.0.3-36500)' }]);
  const agent = inventory(
    [['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false]],
    ['5_14_0_741_20_1_el9_9_x86_64'],
  );
  assert.deepEqual(
    evaluate(r.baseline, c, RHEL9, agent).changes.map((x) => x.text),
    ['RHEL 9: TMDS Agent support released (Agent 20.0.3-31610)'],
  );
});

test('TMDS: loading keeps the old state, turning it on or off re-baselines silently', () => {
  const c = kernelCase();
  const on = evaluate(undefined, c, RHEL9, inventory([]));
  // Inventory not loaded yet: TMDS fields are carried over, nothing is reported.
  const loading = evaluate(on.baseline, c, RHEL9, null);
  assert.deepEqual(loading.changes, []);
  assert.ok(loading.baseline.rows.rhel9.tmds);
  // Turning TMDS off strips its state; turning it on again adopts the current state silently.
  const off = withoutTmds(loading.baseline);
  assert.ok(!off.rows.rhel9.tmds);
  const supported = inventory([['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false]]);
  const again = evaluate(off, c, RHEL9, supported);
  assert.deepEqual(again.changes, []);
  assert.equal(again.baseline.rows.rhel9.tmds.ksp, 'supported');
});

test('TMDS: nodata or an unchecked inventory is "not evaluated", never a change', () => {
  const c = kernelCase();
  const supported = inventory([['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false]]);
  // The server has not completed a check yet: TMDS is not evaluated at all.
  const unchecked = evaluate(undefined, c, RHEL9, { ...supported, checked: null });
  assert.equal(unchecked.baseline.rows.rhel9.tmds, undefined);
  // KSP list without data for this OS: nodata → supported later is adopted silently.
  const empty = { ...supported, ksp: { checked: 1, products: {} } };
  const nodata = evaluate(undefined, c, RHEL9, empty);
  assert.equal(nodata.baseline.rows.rhel9.tmds.ksp, 'nodata');
  assert.deepEqual(evaluate(nodata.baseline, c, RHEL9, supported).changes, []);
  // Supported, then the KSP data is missing for a while: the supported state is kept, nothing is reported.
  const on = evaluate(undefined, c, RHEL9, supported);
  const gap = evaluate(on.baseline, c, RHEL9, empty);
  assert.deepEqual(gap.changes, []);
  assert.equal(gap.baseline.rows.rhel9.tmds.ksp, 'supported');
  assert.deepEqual(evaluate(gap.baseline, c, RHEL9, supported).changes, []);
});

test('TMDS: turning it on adopts its state but still reports a status change', () => {
  const before = evaluate(undefined, snapshot({ rhel9: [entry('kernel', 'affected')] }));
  const r = evaluate(before.baseline, kernelCase(), RHEL9, inventory([]));
  assert.deepEqual(
    r.changes.map((x) => x.text),
    ['RHEL 9: fix available (kernel-5.14.0-741.20.1.el9_9)'],
  );
  assert.ok(r.baseline.rows.rhel9.tmds);
});

test('TMDS regressions: silent unless supported support is no longer listed', () => {
  const c = kernelCase();
  const pending = inventory([['5.14.0-687.64.1.el9_8.x86_64', 'default', null, false]]);
  const supported = inventory([['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', false]]);
  const delta = inventory([['5.14.0-741.22.1.el9_9.x86_64', 'default', '20.0.3-36500', true]]);
  const p = evaluate(undefined, c, RHEL9, pending);
  // pending → unknown: worse, but never supported: silent and baselined.
  const unknown = evaluate(p.baseline, c, RHEL9, inventory([]));
  assert.deepEqual(unknown.changes, []);
  assert.equal(unknown.baseline.rows.rhel9.tmds.ksp, 'unknown');
  const s = evaluate(unknown.baseline, c, RHEL9, supported);
  assert.deepEqual(
    s.changes.map((x) => x.text),
    ['RHEL 9: KSP support released (KSP 20.0.3-36500)'],
  );
  // supported → Δ only: reported once as no longer listed.
  const d = evaluate(s.baseline, c, RHEL9, delta);
  assert.deepEqual(
    d.changes.map((x) => x.text),
    ['RHEL 9: TMDS support no longer listed'],
  );
  assert.deepEqual(evaluate(d.baseline, c, RHEL9, delta).changes, []);
  // A new fixed build that is not supported yet: the fix change says it all.
  const newer = snapshot({
    rhel9: [
      entry('kernel', 'fixed', [
        'kernel-0:5.14.0-741.30.1.el9_9.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)',
      ]),
    ],
  });
  const fixed = evaluate(s.baseline, newer, RHEL9, supported);
  assert.deepEqual(
    fixed.changes.map((x) => x.text),
    ['RHEL 9: new fixed build (kernel-5.14.0-741.30.1.el9_9)'],
  );
});

test('TMDS: a kernel branch or architecture becoming supported is reported while the total stays partial', () => {
  const c = snapshot({
    rhel9: [
      entry('kernel', 'fixed', [
        'kernel-0:5.14.0-741.20.1.el9_9.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)',
        'kernel-0:5.14.0-427.90.1.el9_4.x86_64 as a component of Red Hat Enterprise Linux BaseOS EUS (v. 9.4)',
        'kernel-0:5.14.0-570.60.1.el9_6.x86_64 as a component of Red Hat Enterprise Linux BaseOS EUS (v. 9.6)',
      ]),
    ],
  });
  const kernels = (...k) => k.map((x) => [x, 'default', '20.0.3-36500', false]);
  const one = inventory(
    kernels('5.14.0-741.22.1.el9_9.x86_64', '5.14.0-427.80.1.el9_4.x86_64', '5.14.0-570.50.1.el9_6.x86_64'),
  );
  const two = inventory(
    kernels('5.14.0-741.22.1.el9_9.x86_64', '5.14.0-427.90.1.el9_4.x86_64', '5.14.0-570.50.1.el9_6.x86_64'),
  );
  const r1 = evaluate(undefined, c, RHEL9, one);
  assert.equal(r1.baseline.rows.rhel9.tmds.ksp, 'partial');
  const r2 = evaluate(r1.baseline, c, RHEL9, two);
  assert.equal(r2.baseline.rows.rhel9.tmds.ksp, 'partial');
  assert.deepEqual(
    r2.changes.map((x) => x.text),
    ['RHEL 9: KSP support released for 5.14.0-427.90.1.el9_4 (x86_64)'],
  );
  // Old baselines without per-branch state adopt it silently.
  const legacy = structuredClone(r1.baseline);
  delete legacy.rows.rhel9.tmds.cells;
  assert.deepEqual(evaluate(legacy, c, RHEL9, two).changes, []);
});

test('helpers', () => {
  assert.equal(hashText('abc'), hashText('abc'));
  assert.notEqual(hashText('abc'), hashText('abd'));
  assert.deepEqual(tmdsState(null), { agent: 'none', ksp: 'none' });
  assert.deepEqual(
    tmdsState({ status: 'partial', agent: { status: 'pending' }, ksp: { status: 'partial', partial: true } }),
    { agent: 'pending', ksp: 'delta', cells: {} },
  );
  const changes = ['a', 'b', 'c', 'd', 'e'].map((text) => ({ id: 'x', text }));
  assert.equal(describeChanges(changes), 'a; b; c; +2 more');
  assert.equal(describeChanges(changes.slice(0, 1)), 'a');
});

test('per-cell KSP delta improvements retain their feature restriction in notifications', () => {
  const row = {
    status: 'fix_available',
    fixes: [],
    mitigations: [],
    tmds: {
      agent: 'pending',
      ksp: 'partial',
      cells: { 'el9/x86_64': ['pending', 'pending'], 'el9/aarch64': ['pending', 'supported'] },
    },
  };
  const old = { rows: { rhel9: row } };
  const cur = structuredClone(old);
  cur.rows.rhel9.tmds.cells['el9/x86_64'][1] = 'delta';
  assert.deepEqual(
    diffActions(old, cur).changes.map((x) => x.text),
    ['rhel9: KSP Δ support (WRS/FW/IPS only) released for el9 (x86_64)'],
  );
});
