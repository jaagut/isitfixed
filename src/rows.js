// Per-OS-version facts derived from a case: status, fixed builds, mitigations
// (with the sources that carried them) and advisories. Pure; used by the case
// page and by the actionable-change fingerprint.
import { assess, assessmentStatus, splitPackage, suseAdvisories, vendorName } from './data.js';

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
    // The architecture ends the NEVRA, also before a module stream suffix (" (nodejs:24)").
    .replace(/\.(?:aarch64|x86_64|ppc64le|s390x|src|noarch|i686|armv7hl)(?= \(|$)/, '');
// Short package name of an evidence entry: "lemon as a component of RHEL 8" → "lemon",
// "SUSE Linux Enterprise Server 15 SP4-TERADATA:sqlite3" → "sqlite3", "nodejs (nodejs:22) …" → "nodejs:22".
export function packageLabel(name) {
  const s = shortFix(String(name || '')).replace(/^SUSE [^:]*:/, '');
  const stream = s.match(/^\S+ \(([^()\s]+)\)$/);
  if (stream) return stream[1];
  // Only a real version ends the name ("libsqlite3-0-32bit" and "libopenssl-1_0_0-devel" are names).
  const parts = splitPackage(s);
  return /\d\.\d/.test(parts.version) ? parts.name : s;
}
// Vendor notes saying an affected component will stay unfixed (won't fix, end of life, out of support).
export const NO_FIX_NOTE =
  /will not fix|won't fix|no fix (?:is )?planned|end of (?:life|standard support|kernel support|support)|out of support|not covered by .*security support/i;
const NOT_A_NOTE = /^Recommended (?:patched )?build/; // VEX build boilerplate
// "a, b, c +2": at most `max` names.
export const listNames = (names, max = 3) =>
  `${names.slice(0, max).join(', ')}${names.length > max ? ` +${names.length - max}` : ''}`;
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
  const a = assess(c.record || { cveMetadata: { cveId: c.id } }, p, c.vendorData);
  const s = assessmentStatus(a);
  const mitigations = new Map();
  for (const e of a.evidence)
    for (const m of e.mitigation || []) {
      const text = cleanMitigation(m);
      if (!text) continue;
      if (!mitigations.has(text)) mitigations.set(text, new Set());
      mitigations.get(text).add(e.source || CNA_SOURCE);
    }
  // "Inconclusive": evidence exists, but none of it establishes a status.
  const status = s === 'unknown' && a.evidence.length ? 'inconclusive' : s;
  return {
    assessment: a,
    status,
    fixes: rowFixes(a),
    mitigations: [...mitigations].map(([text, sources]) => ({ text, sources: [...sources] })),
    advisories: [...new Set(a.evidence.flatMap((e) => e.links || []))],
    // CVE-wide advisories from the vendor document (SUSE): not specific to this version.
    documentAdvisories: p.family === 'sles' ? suseAdvisories(c.vendorData?.sources?.sles?.advisories) : [],
    sources: [...new Set(a.evidence.map((e) => e.source || CNA_SOURCE))],
    notes: rowNotes(p, a.evidence),
    stillAffected: stillAffected(p, a),
    explanation: explanation(c, p, a, status),
  };
}

// Short vendor notes (Debian/Ubuntu triage, CSAF no-fix reasons, Microsoft scope), each text once.
// With several packages a note names them, notes of affected or undecided entries come first, and
// notes of unaffected packages are left out (Ubuntu kernel rows list dozens of them).
function rowNotes(p, evidence) {
  const named = p.family !== 'windows' && new Set(evidence.map((e) => packageLabel(e.name))).size > 1;
  const notes = new Map();
  for (const e of evidence) {
    const text = typeof e.note === 'string' ? e.note.trim() : '';
    if (!text || NOT_A_NOTE.test(text) || (named && e.status === 'unaffected')) continue;
    const rank = e.status === 'affected' || e.status === 'unknown' ? 0 : 1;
    const note = notes.get(text) || { rank, packages: new Set() };
    note.rank = Math.min(note.rank, rank);
    note.packages.add(packageLabel(e.name));
    notes.set(text, note);
  }
  return [...notes]
    .sort(([, x], [, y]) => x.rank - y.rank)
    .map(([text, n]) => (named ? `${listNames([...n.packages])}: ${text}` : text));
}

// Affected packages without a fix on a row that has a fix. Windows ranges are per build (the fixed
// build is the answer), and entries the vendor will not fix are explained by their own notes.
function stillAffected(p, a) {
  if (p.family === 'windows' || !a.fixAvailable || a.status !== 'affected') return [];
  const open = a.evidence.filter((e) => e.status === 'affected' && !e.fix?.length && !NO_FIX_NOTE.test(e.note || ''));
  return [...new Set(open.map((e) => packageLabel(e.name)))];
}

// Why a row is Inconclusive or has no data, naming who has not decided.
function explanation(c, p, a, status) {
  const vendor = vendorName(p);
  if (status === 'inconclusive') {
    // A vendor note on an undecided entry ("Not yet triaged by Ubuntu") already says it.
    if (a.evidence.some((e) => e.status === 'unknown' && e.note && !NOT_A_NOTE.test(e.note))) return '';
    if (p.family !== 'windows' && a.evidence.every((e) => !e.source)) return 'The CVE record leaves the status open';
    return p.family === 'ubuntu' ? 'Ubuntu has not assessed this yet' : `${vendor} has not determined the status yet`;
  }
  if (status !== 'unknown' || a.evidence.length || !FEED_FAMILIES.has(p.family)) return '';
  const s = c.vendorData?.sources?.[p.family];
  if (!s) return '';
  if (s.error) return 'Source unavailable; see Sources';
  if (s.notPublished) return `${vendor} has not published this CVE yet`;
  if (!s.checked) return '';
  if (p.family === 'alpine') return 'Alpine lists only fixed packages; no fix recorded';
  return `Not listed by ${vendor} for this version`;
}

// A row is comparable over time once its vendor feed (or, for CNA-only
// families, the CVE record) has been fetched at least once.
export function rowReady(c, p) {
  if (FEED_FAMILIES.has(p.family)) {
    const s = c.vendorData?.sources?.[p.family];
    return Boolean(s?.checked || c.vendorData?.evidence?.[p.id]?.length);
  }
  return Boolean(c.record);
}

// "Ubuntu 24.04 LTS" → "Ubuntu 24.04", "Debian 12 · Bookworm" → "Debian 12".
export const shortName = (p) => p.name.replace(/ LTS$/, '').replace(/ · .*$/, '');

// Display status only (cheaper than rowAssessment): used for counts and sidebar icons.
export function rowStatus(c, p) {
  const a = assess(c.record || { cveMetadata: { cveId: c.id } }, p, c.vendorData);
  const s = assessmentStatus(a);
  return s === 'unknown' && a.evidence.length ? 'inconclusive' : s;
}
