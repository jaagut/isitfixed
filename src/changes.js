// Actionable changes. Each case keeps a baseline "action fingerprint" of its
// selected OS versions; after every case refresh and every TMDS inventory
// refresh the fingerprint is recomputed and compared. Only these changes are
// reported (activity entry, New marker, notification, row highlight):
//   - row status (Affected, Fix available, Not affected, ...)
//   - the set of fixed builds
//   - whether mitigations exist, and their text
//   - TMDS bundled-agent and KSP support (only while TMDS is enabled), when it improves
//   - the CVE being rejected (or un-rejected)
// Source timestamps, advisories, notes and other metadata are not part of it.
// Rows the baseline does not know yet (new OS selections, or TMDS turned on)
// are adopted silently; rows whose source has not been fetched yet keep their
// previous baseline. Pure: no DOM, storage or time.
import { groupFixes } from './data.js';
import { rowAssessment, rowReady, shortName } from './rows.js';
import { kernelSupport, productInventory, isKernelFix } from './tmds.js';

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
export function tmdsState(t) {
  if (!t || t.status === 'none') return { agent: 'none', ksp: 'none' };
  return { agent: t.agent.status, ksp: t.ksp.status === 'partial' && t.ksp.partial ? 'delta' : t.ksp.status };
}

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
  for (const p of products) {
    if (!rowReady(c, p)) {
      rows[p.id] = null;
      continue;
    }
    const row = rowAssessment(c, p),
      groups = groupFixes(row.fixes);
    let tmds = null,
      t = null;
    if (inventory) {
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
    };
  }
  const fingerprint = { rows };
  if (c.record) fingerprint.rejected = c.record.cveMetadata?.state === 'REJECTED';
  return { fingerprint, info };
}

const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
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
  // TMDS: only improvements are actionable ("not yet" after a new fix is implied by the fix change).
  if (old.tmds && cur.tmds) {
    if (old.tmds.agent !== cur.tmds.agent) {
      if (cur.tmds.agent === 'supported')
        out.push(`${name}: TMDS Agent support released${info.agentRelease ? ` (Agent ${info.agentRelease})` : ''}`);
      else if (cur.tmds.agent === 'partial') out.push(`${name}: TMDS Agent now partly supports the fix`);
    }
    if (old.tmds.ksp !== cur.tmds.ksp) {
      const release = info.kspRelease ? ` (KSP ${info.kspRelease})` : '';
      if (cur.tmds.ksp === 'supported') out.push(`${name}: KSP support released${release}`);
      else if (cur.tmds.ksp === 'partial') out.push(`${name}: KSP now partly supports the fix${release}`);
      else if (cur.tmds.ksp === 'delta') out.push(`${name}: KSP Δ support (WRS/FW/IPS only) released${release}`);
    }
  }
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
    // TMDS not evaluated right now (inventory loading or disabled on the server): keep the old TMDS state.
    const next = !row.tmds && old.tmds ? { ...row, tmds: old.tmds } : row;
    rows[id] = next;
    if (next.tmds && !old.tmds) continue; // TMDS just turned on for this row: adopt silently.
    for (const text of rowChanges(old, next, info[id] || { name: id, builds: [] })) changes.push({ id, text });
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
