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
  assert.deepEqual(before.baseline.rows.rhel9.tmds, { agent: 'pending', ksp: 'pending' });
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
  // A worse TMDS state alone is not actionable.
  assert.deepEqual(evaluate(again.baseline, c, RHEL9, inventory([])).changes, []);
});

test('helpers', () => {
  assert.equal(hashText('abc'), hashText('abc'));
  assert.notEqual(hashText('abc'), hashText('abd'));
  assert.deepEqual(tmdsState(null), { agent: 'none', ksp: 'none' });
  assert.deepEqual(
    tmdsState({ status: 'partial', agent: { status: 'pending' }, ksp: { status: 'partial', partial: true } }),
    {
      agent: 'pending',
      ksp: 'delta',
    },
  );
  const changes = ['a', 'b', 'c', 'd', 'e'].map((text) => ({ id: 'x', text }));
  assert.equal(describeChanges(changes), 'a; b; c; +2 more');
  assert.equal(describeChanges(changes.slice(0, 1)), 'a');
});
