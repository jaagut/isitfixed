// Per-OS-version facts derived from a case: status, fixed builds, mitigations
// (with the sources that carried them) and advisories. Pure; used by the case
// page and by the actionable-change fingerprint.
import { assess, assessmentStatus, splitPackage } from './data.js';

export const FEED_FAMILIES = new Set(['rhel', 'sles', 'debian', 'ubuntu', 'alpine']);
export const CNA_SOURCE = 'CNA statement';

// Kernel and runtime packages first; debug, devel and doc builds last.
const fixRank = (f) => {
  const n = splitPackage(f).name;
  const kind = /^(?:kernel|kernel-default|linux)$/.test(n) ? 0 : /^(?:kernel|linux)-/.test(n) ? 1 : 2;
  return kind + (/-(?:debug|debuginfo|debugsource|devel|doc|headers|source)\b/.test(n) ? 3 : 0);
};
export const shortFix = (f) =>
  f
    .replace(/ as (?:a )?component of .*/, '')
    .replace(/-0:/g, '-')
    .replace(/\.(?:aarch64|x86_64|ppc64le|s390x|src|noarch|i686|armv7hl)$/, '');
export const rowFixes = (a) =>
  [...new Set(a.evidence.flatMap((e) => e.fix).map(shortFix))].sort(
    (x, y) => fixRank(x) - fixRank(y) || splitPackage(x).name.length - splitPackage(y).name.length,
  );
// Drops shell-prompt prefixes ("root> ") some vendors put in front of commands.
export const cleanMitigation = (m) =>
  String(m)
    .replace(/^[\w.-]+>\s*/gm, '')
    .trim();

export function rowAssessment(c, p) {
  const a = assess(c.record || { cveMetadata: { cveId: c.id } }, p, c.vex, c.vendorData);
  const s = assessmentStatus(a);
  const mitigations = new Map();
  for (const e of a.evidence)
    for (const m of e.mitigation || []) {
      const text = cleanMitigation(m);
      if (!text) continue;
      if (!mitigations.has(text)) mitigations.set(text, new Set());
      mitigations.get(text).add(e.source || CNA_SOURCE);
    }
  return {
    assessment: a,
    // "Inconclusive": evidence exists, but none of it establishes a status.
    status: s === 'unknown' && a.evidence.length ? 'inconclusive' : s,
    fixes: rowFixes(a),
    mitigations: [...mitigations].map(([text, sources]) => ({ text, sources: [...sources] })),
    advisories: [...new Set(a.evidence.flatMap((e) => e.links || []))],
    sources: [...new Set(a.evidence.map((e) => e.source || CNA_SOURCE))],
    // Short vendor notes (Debian triage, Microsoft scope); skip VEX build boilerplate.
    notes: [...new Set(a.evidence.map((e) => e.note).filter((n) => n && !/^Recommended (?:patched )?build/.test(n)))],
  };
}

// A row is comparable over time once its vendor feed (or, for CNA-only
// families, the CVE record) has been fetched at least once.
export function rowReady(c, p) {
  if (FEED_FAMILIES.has(p.family)) {
    const s = c.vendorData?.sources?.[p.family];
    return Boolean(s?.checked || c.vendorData?.evidence?.[p.id]?.length);
  }
  return Boolean(c.record || c.vex);
}

// "Ubuntu 24.04 LTS" → "Ubuntu 24.04", "Debian 12 · Bookworm" → "Debian 12".
export const shortName = (p) => p.name.replace(/ LTS$/, '').replace(/ · .*$/, '');

// Display status only (cheaper than rowAssessment): used for counts and sidebar icons.
export function rowStatus(c, p) {
  const a = assess(c.record || { cveMetadata: { cveId: c.id } }, p, c.vex, c.vendorData);
  const s = assessmentStatus(a);
  return s === 'unknown' && a.evidence.length ? 'inconclusive' : s;
}
