// Actionable changes. Each case keeps a baseline "action fingerprint" of its
// selected OS versions; after every case refresh and every TMDS inventory
// refresh the fingerprint is recomputed and compared. Only these changes are
// reported (activity entry, New marker, notification, row highlight):
//   - row status (Affected, Fix available, Not affected, ...)
//   - the set of fixed builds
//   - whether mitigations exist, and their text
//   - TMDS bundled-agent and KSP support (only while TMDS is enabled): when it
//     improves overall or for one kernel branch and architecture, and when a
//     fix that was supported is no longer listed; other regressions are silent
//   - the CVE being rejected (or un-rejected)
// Source timestamps, advisories, notes and other metadata are not part of it.
// Rows the baseline does not know yet (new OS selections, or TMDS turned on)
// are adopted silently; rows whose source has not been fetched yet keep their
// previous baseline, and so does TMDS while the inventory has no data ("nodata"
// is "not evaluated", never a change). Pure: no DOM, storage or time.
import { groupFixes } from './data.js';
import { rowAssessment, rowReady, shortName } from './rows.js';
import { kernelSupport, productInventory, isKernelFix, kernelFamilies } from './tmds.js';

// Short, stable digest so long mitigation texts do not bloat saved state (FNV-1a, 32 bit).
export function hashText(text) {
  let h = 0x811c9dc5;
  for (const ch of text) h = Math.imul(h ^ ch.codePointAt(0), 0x01000193) >>> 0;
  return h.toString(36);
}
const normalize = (text) => text.replace(/\s+/g, ' ').trim().toLowerCase();

const STATUS_LABELS = {
  affected: 'Affected',
  fix_available: 'Fix available',
  inconclusive: 'Inconclusive',
  unaffected: 'Not affected',
  unknown: 'No data',
};

// TMDS state of a row: "none" without kernel fixes; Δ-only KSP support is "delta".
// `cells` keeps the state per kernel branch and architecture ("el9_4/x86_64": [agent, ksp]).
export function tmdsState(t) {
  if (!t || t.status === 'none') return { agent: 'none', ksp: 'none' };
  const cells = {};
  for (const b of t.branches || [])
    for (const c of b.cells)
      cells[`${b.branch}/${c.arch}`] = [
        c.agent.status,
        c.ksp.status === 'partial' && c.ksp.partial ? 'delta' : c.ksp.status,
      ];
  return {
    agent: t.agent.status,
    ksp: t.ksp.status === 'partial' && t.ksp.partial ? 'delta' : t.ksp.status,
    cells,
  };
}
// Better is higher; "nodata" means not evaluated and is never compared.
const TMDS_RANK = { none: 0, unknown: 1, pending: 2, delta: 3, partial: 4, supported: 5 };
const improved = (old, cur) => old !== 'nodata' && cur !== 'nodata' && TMDS_RANK[cur] > TMDS_RANK[old];
// TMDS evaluated now but without data for a part: keep that part's previous state.
function mergeTmds(old, cur) {
  if (!cur) return old;
  if (!old) return cur;
  const keep = (o, c) => (c === 'nodata' && o ? o : c);
  const next = { agent: keep(old.agent, cur.agent), ksp: keep(old.ksp, cur.ksp) };
  if (cur.cells) {
    next.cells = {};
    for (const [key, [agent, ksp]] of Object.entries(cur.cells)) {
      const prev = old.cells?.[key];
      next.cells[key] = [keep(prev?.[0], agent), keep(prev?.[1], ksp)];
    }
  }
  return next;
}
// The inventory counts as evaluated once the server has completed a check.
const evaluated = (inventory) => Boolean(inventory && (inventory.checked || inventory.ksp?.checked));

export function rowFingerprint(row, tmds) {
  const fp = {
    status: row.status,
    fixes: [...new Set(groupFixes(row.fixes).map((g) => g.version || g.packages[0]))].sort(),
    mitigations: [...new Set(row.mitigations.map((m) => hashText(normalize(m.text))))].sort(),
  };
  if (tmds) fp.tmds = tmds;
  return fp;
}

/**
 * Current action fingerprint of a case plus the details used to describe changes.
 * @param products selected products (PRODUCTS entries)
 * @param inventory the /api/tmds payload when TMDS is enabled and loaded; otherwise null
 */
export function caseActionState(c, products, inventory = null) {
  const rows = {},
    info = {};
  const tmdsOn = evaluated(inventory);
  for (const p of products) {
    if (!rowReady(c, p)) {
      rows[p.id] = null;
      continue;
    }
    const row = rowAssessment(c, p),
      groups = groupFixes(row.fixes);
    let tmds = null,
      t = null;
    if (tmdsOn && kernelFamilies.includes(p.family)) {
      const kernels = row.fixes.filter(isKernelFix);
      t = kernels.length ? kernelSupport(p.family, kernels, productInventory(inventory, p.id)) : null;
      tmds = tmdsState(t);
    }
    rows[p.id] = rowFingerprint(row, tmds);
    info[p.id] = {
      name: shortName(p),
      builds: groups.map((g) => [g.version || g.packages[0], g.packages[0]]),
      agentRelease: t?.agent.release || null,
      kspRelease: t ? t.ksp.release || t.ksp.current : null,
      // Fix label per kernel branch, for per-branch messages.
      branches: Object.fromEntries((t?.branches || []).map((b) => [b.branch, b.fix])),
    };
  }
  const fingerprint = { rows };
  if (c.record) fingerprint.rejected = c.record.cveMetadata?.state === 'REJECTED';
  return { fingerprint, info };
}

const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// TMDS: improvements are "released"; losing full support is reported unless a new fix explains it
// ("not yet supported" after a new fixed build is implied by that change). Other regressions are silent.
function tmdsChanges(old, cur, info) {
  const name = info.name,
    out = [],
    o = old.tmds,
    t = cur.tmds;
  const agentRelease = info.agentRelease ? ` (Agent ${info.agentRelease})` : '',
    kspRelease = info.kspRelease ? ` (KSP ${info.kspRelease})` : '';
  const agentImproved = improved(o.agent, t.agent),
    kspImproved = improved(o.ksp, t.ksp);
  if (agentImproved) {
    if (t.agent === 'supported') out.push(`${name}: TMDS Agent support released${agentRelease}`);
    else if (t.agent === 'partial') out.push(`${name}: TMDS Agent now partly supports the fix`);
  }
  if (kspImproved) {
    if (t.ksp === 'supported') out.push(`${name}: KSP support released${kspRelease}`);
    else if (t.ksp === 'partial') out.push(`${name}: KSP now partly supports the fix${kspRelease}`);
    else if (t.ksp === 'delta') out.push(`${name}: KSP Δ support (WRS/FW/IPS only) released${kspRelease}`);
  }
  // A kernel branch or architecture that became supported while the overall state did not change.
  if (o.cells && t.cells) {
    const better = (i) =>
      Object.entries(t.cells).filter(([key, s]) => {
        const prev = o.cells[key];
        return prev && ['supported', 'delta'].includes(s[i]) && improved(prev[i], s[i]);
      });
    const describe = (cells) => {
      const [key] = cells[0],
        [branch, arch] = key.split('/'),
        label = info.branches?.[branch] || branch;
      return `${label} (${arch})${cells.length > 1 ? ` +${cells.length - 1} more` : ''}`;
    };
    const agentCells = agentImproved ? [] : better(0),
      kspCells = kspImproved ? [] : better(1);
    if (agentCells.length) out.push(`${name}: TMDS Agent support released for ${describe(agentCells)}`);
    const fullCells = kspCells.filter(([, states]) => states[1] === 'supported'),
      deltaCells = kspCells.filter(([, states]) => states[1] === 'delta');
    if (fullCells.length) out.push(`${name}: KSP support released for ${describe(fullCells)}`);
    if (deltaCells.length) out.push(`${name}: KSP Δ support (WRS/FW/IPS only) released for ${describe(deltaCells)}`);
  }
  const lost = (k) => o[k] === 'supported' && t[k] !== 'nodata' && t[k] !== 'supported';
  if ((lost('agent') || lost('ksp')) && same(old.fixes, cur.fixes)) out.push(`${name}: TMDS support no longer listed`);
  return out;
}
function rowChanges(old, cur, info) {
  const name = info.name,
    out = [];
  const label = (key) => info.builds.find(([k]) => k === key)?.[1] || key;
  const firstNew = info.builds.map(([k]) => k).find((k) => !old.fixes.includes(k));
  if (old.status !== cur.status) {
    if (cur.status === 'fix_available') {
      const build = firstNew || info.builds[0]?.[0];
      out.push(`${name}: fix available${build ? ` (${label(build)})` : ''}`);
    } else out.push(`${name}: status changed to ${STATUS_LABELS[cur.status] || cur.status}`);
  }
  const added = cur.fixes.filter((f) => !old.fixes.includes(f));
  if (added.length && !(cur.status === 'fix_available' && old.status !== cur.status)) {
    const more = added.length > 1 ? ` +${added.length - 1} more` : '';
    out.push(`${name}: new fixed build (${label(firstNew || added[0])})${more}`);
  } else if (!added.length && !same(old.fixes, cur.fixes) && cur.fixes.length) {
    out.push(`${name}: fixed build list changed`);
  }
  if (!same(old.mitigations, cur.mitigations)) {
    if (!old.mitigations.length) out.push(`${name}: mitigation published`);
    else if (!cur.mitigations.length) out.push(`${name}: mitigation withdrawn`);
    else out.push(`${name}: mitigation updated`);
  }
  if (old.tmds && cur.tmds) out.push(...tmdsChanges(old, cur, info));
  return out;
}

/**
 * Compares the stored baseline with the current fingerprint.
 * @returns {{baseline: object, changes: {id: string|null, text: string}[]}} the next baseline to store
 */
export function diffActions(baseline, current, info = {}) {
  if (!baseline?.rows) return { baseline: current, changes: [] };
  const rows = {},
    changes = [];
  for (const [id, row] of Object.entries(current.rows)) {
    const old = baseline.rows[id];
    if (!row) {
      if (old) rows[id] = old; // Source not fetched yet: keep the previous baseline.
      continue;
    }
    if (!old) {
      rows[id] = row; // New selection: adopt silently.
      continue;
    }
    // TMDS not evaluated right now (inventory loading, without data or disabled): keep the old TMDS state.
    const tmds = mergeTmds(old.tmds, row.tmds);
    const next = tmds ? { ...row, tmds } : row;
    rows[id] = next;
    // TMDS just turned on for this row: adopt its state silently, but still compare everything else.
    const before = next.tmds && !old.tmds ? { ...old, tmds: next.tmds } : old;
    for (const text of rowChanges(before, next, info[id] || { name: id, builds: [] })) changes.push({ id, text });
  }
  const next = { rows };
  const rejected = current.rejected ?? baseline.rejected;
  if (rejected !== undefined) next.rejected = rejected;
  if (baseline.rejected !== undefined && current.rejected !== undefined && baseline.rejected !== current.rejected)
    changes.unshift({ id: null, text: current.rejected ? 'CVE rejected' : 'CVE no longer rejected' });
  return { baseline: next, changes };
}

// Turning TMDS off forgets its state, so turning it back on later re-baselines silently.
export function withoutTmds(baseline) {
  if (!baseline?.rows) return baseline;
  const rows = Object.fromEntries(
    Object.entries(baseline.rows).map(([id, row]) => {
      const rest = { ...row };
      delete rest.tmds;
      return [id, rest];
    }),
  );
  return { ...baseline, rows };
}

// One activity line: up to three changes, then a count.
export function describeChanges(changes, limit = 3) {
  const texts = changes.map((c) => c.text);
  const more = texts.length > limit ? `; +${texts.length - limit} more` : '';
  return texts.slice(0, limit).join('; ') + more;
}
