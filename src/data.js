export const VENDORS = [
  { id: 'rhel', name: 'Red Hat Enterprise Linux', vendor: 'Red Hat', logo: 'redhat' },
  { id: 'debian', name: 'Debian', vendor: 'Debian', logo: 'debian' },
  { id: 'sles', name: 'SUSE Linux Enterprise', vendor: 'SUSE', logo: 'suse' },
  { id: 'windows', name: 'Windows', vendor: 'Microsoft', logo: 'windows' },
  { id: 'ubuntu', name: 'Ubuntu', vendor: 'Canonical', logo: 'ubuntu' },
  { id: 'alpine', name: 'Alpine Linux', vendor: 'Alpine', logo: 'alpinelinux' },
];
const DEFENDER = /malware protection engine|microsoft defender|antimalware platform/i;
export const PRODUCTS = [
  ...[8, 9, 10].map((v) => ({
    id: `rhel${v}`,
    family: 'rhel',
    name: `RHEL ${v}`,
    version: String(v),
    vendor: 'Red Hat',
    match: new RegExp(`\\bred hat enterprise linux(?: ${v}\\b|[^()]*\\(v\\. ${v}\\))`, 'i'),
  })),
  ...[
    [12, 'Bookworm'],
    [13, 'Trixie'],
  ].map(([v, code]) => ({
    id: `debian${v}`,
    family: 'debian',
    name: `Debian ${v} · ${code}`,
    version: `${v} · ${code}`,
    code: code.toLowerCase(),
    vendor: 'Debian',
    match: new RegExp(`\\bdebian.*(?:${code}|${v}\\b)`, 'i'),
  })),
  ...[15, 16].map((v) => ({
    id: `sles${v}`,
    family: 'sles',
    name: `SLES ${v}`,
    version: String(v),
    vendor: 'SUSE',
    match: new RegExp(`\\b(?:suse linux enterprise server|sles) ${v}\\b`, 'i'),
  })),
  ...[
    ['windows10', '10'],
    ['windows11', '11'],
    ['server2022', 'Server 2022'],
    ['server2025', 'Server 2025'],
  ].map(([id, v]) => ({
    id,
    family: 'windows',
    name: `Windows ${v}`,
    version: v,
    vendor: 'Microsoft',
    match: new RegExp(`\\bwindows ${v}\\b`, 'i'),
  })),
  ...[
    ['2004', '20.04', 'focal'],
    ['2204', '22.04', 'jammy'],
    ['2404', '24.04', 'noble'],
    ['2604', '26.04', 'resolute'],
  ].map(([id, v, code]) => ({
    id: `ubuntu${id}`,
    family: 'ubuntu',
    name: `Ubuntu ${v} LTS`,
    version: `${v} LTS`,
    code,
    vendor: 'Canonical',
    match: new RegExp(`\\bubuntu.*(?:${v.replace('.', '\\.')}|${code})`, 'i'),
  })),
  ...['3.20', '3.21', '3.22', '3.23', '3.24'].map((v) => ({
    id: `alpine${v.replace('.', '')}`,
    family: 'alpine',
    name: `Alpine ${v}`,
    version: v,
    vendor: 'Alpine',
    match: new RegExp(`\\balpine.*${v.replace('.', '\\.')}\\b`, 'i'),
  })),
];
export function migrateProducts(ids) {
  return [
    ...new Set(
      ids.flatMap((id) =>
        id === 'windows'
          ? ['windows10', 'windows11', 'server2022', 'server2025']
          : PRODUCTS.some((p) => p.id === id)
            ? [id]
            : [],
      ),
    ),
  ];
}
export const validId = (id) => /^CVE-\d{4}-\d{4,}$/.test(id);
export function vendorURL(product, id) {
  if (product.vendor === 'Red Hat') return `https://access.redhat.com/security/cve/${id}`;
  if (product.vendor === 'Debian') return `https://security-tracker.debian.org/tracker/${id}`;
  if (product.vendor === 'SUSE') return `https://www.suse.com/security/cve/${id}.html`;
  if (product.vendor === 'Microsoft') return `https://msrc.microsoft.com/update-guide/vulnerability/${id}`;
  if (product.family === 'ubuntu') return `https://ubuntu.com/security/${id}`;
  if (product.family === 'alpine') return `https://security.alpinelinux.org/vuln/${id}`;
  return `https://www.cve.org/CVERecord?id=${id}`;
}
// Records without a CNA title use the description's first sentence, kept short.
function shortTitle(text) {
  const sentence = text
    .trim()
    .split(/(?<=[.!?])\s/)[0]
    .replace(/[.!?]$/, '');
  return sentence.length > 90
    ? `${sentence.slice(0, sentence.lastIndexOf(' ', 87) > 40 ? sentence.lastIndexOf(' ', 87) : 87)}…`
    : sentence;
}
export const CVSS_VERSIONS = ['3.1', '4.0', '3.0', '2.0'];
const CVSS_KEYS = { '4.0': 'cvssV4_0', 3.1: 'cvssV3_1', '3.0': 'cvssV3_0', '2.0': 'cvssV2_0' };
const severityOf = (score) =>
  score == null
    ? 'Unrated'
    : score >= 9
      ? 'CRITICAL'
      : score >= 7
        ? 'HIGH'
        : score >= 4
          ? 'MEDIUM'
          : score > 0
            ? 'LOW'
            : 'NONE';
// Uses the preferred CVSS version and falls back to the others (3.1, 3.0, 4.0, 2.0).
export function summary(record, preferred = '3.1') {
  const cna = record?.containers?.cna || {};
  const containers = [cna, ...(record?.containers?.adp || [])];
  const metrics = containers.flatMap((c) => c.metrics || []);
  let metric, cvssVersion;
  for (const v of [...new Set([preferred, '3.1', '3.0', '4.0', '2.0'])]) {
    metric = metrics.map((m) => m[CVSS_KEYS[v]]).find(Boolean);
    if (metric) {
      cvssVersion = v;
      break;
    }
  }
  if (metric && !metric.baseSeverity) metric = { ...metric, baseSeverity: severityOf(metric.baseScore) };
  const description = cna.descriptions?.find((d) => d.lang?.startsWith('en'))?.value;
  const rejected = record?.cveMetadata?.state === 'REJECTED';
  return {
    title: cna.title || (rejected ? 'Rejected CVE' : description ? shortTitle(description) : 'Awaiting source data'),
    description: description || 'No English description published.',
    score: metric?.baseScore,
    severity: metric?.baseSeverity || 'Unrated',
    cvssVersion,
    vector: metric?.vectorString || '',
    published: record?.cveMetadata?.datePublished,
    updated: record?.cveMetadata?.dateUpdated,
    category:
      cna.problemTypes?.flatMap((p) => p.descriptions || []).find((d) => d.lang === 'en')?.description ||
      'Category not published',
    rejected,
  };
}
function range(v) {
  const upper = v.lessThan ? ` to < ${v.lessThan}` : v.lessThanOrEqual ? ` to ≤ ${v.lessThanOrEqual}` : '';
  const changes = v.changes?.length
    ? ` (status changes: ${v.changes.map((c) => `${c.at}: ${c.status}`).join(', ')})`
    : '';
  return `${v.version || 'Unspecified'}${upper}${changes}`;
}
export function assess(record, product, vex, vendorData) {
  const cna = record?.containers?.cna;
  // Microsoft records list every affected product, and each range ends at the
  // first fixed build ("lessThan"), published on the day the update ships.
  const microsoft = cna?.providerMetadata?.shortName === 'microsoft' && product.family === 'windows';
  let entries = (cna?.affected || []).filter((a) => product.match.test(a.product || a.packageName || ''));
  let note = '';
  if (microsoft && !entries.length) {
    // Defender ships with every supported Windows release but updates separately.
    entries = (cna.affected || []).filter((a) => DEFENDER.test(a.product || ''));
    if (entries.length)
      note = 'Microsoft Defender component on this Windows version; it updates separately from Windows.';
  }
  let evidence = entries.map((a) => {
    const versions = a.versions || [];
    const affected = versions.filter((v) => v.status === 'affected');
    const unaffected = versions.filter((v) => v.status === 'unaffected');
    // Other vendors' unaffected ranges are not necessarily fixes; never infer a fixed release.
    const status =
      affected.length || a.defaultStatus === 'affected'
        ? 'affected'
        : versions.some((v) => v.status === 'unknown')
          ? 'unknown'
          : a.defaultStatus === 'unaffected' && !versions.length
            ? 'unaffected'
            : 'unknown';
    const fix = microsoft ? affected.filter((v) => v.lessThan).map((v) => `${a.product} ${v.lessThan}`) : [];
    return {
      name: a.packageName || a.product,
      status,
      affected: affected.map(range),
      unaffected: unaffected.map(range),
      fix,
      mitigation: [],
      ...(note ? { note } : {}),
    };
  });
  if (microsoft && !evidence.length && cna.affected?.length)
    evidence = [
      {
        name: product.name,
        status: 'unaffected',
        affected: [],
        unaffected: [],
        fix: [],
        mitigation: [],
        note: `Not listed by Microsoft. Affected products: ${[...new Set(cna.affected.map((a) => a.product))].slice(0, 4).join(', ')}.`,
      },
    ];
  const vendorEvidence = vendorData?.evidence?.[product.id];
  if (vendorEvidence?.length) evidence = vendorEvidence;
  if (vex) evidence = [...evidence, ...assessVex(vex, record?.cveMetadata?.cveId, product)];
  const status = evidence.some((e) => e.status === 'affected')
    ? 'affected'
    : evidence.some((e) => e.status === 'unknown')
      ? 'unknown'
      : evidence.some((e) => e.status === 'fixed')
        ? 'fixed'
        : evidence.length
          ? 'unaffected'
          : 'unknown';
  return { status, evidence, fixAvailable: evidence.some((e) => e.status === 'fixed' || e.fix.length > 0) };
}
// Presentation highlights the available action without changing the underlying
// affected-component evidence or claiming that a patch has been installed.
export const assessmentStatus = (assessment) => (assessment.fixAvailable ? 'fix_available' : assessment.status);
export function assessVex(doc, id, product, source = 'Imported VEX') {
  const names = new Map(),
    shortNames = new Map();
  const groups = new Map((doc.product_tree?.product_groups || []).map((g) => [g.group_id, g.product_ids || []]));
  function walk(branches, path = []) {
    for (const b of branches || []) {
      const next = [...path, b.name || ''];
      if (b.product) {
        names.set(b.product.product_id, [...next, b.product.name || ''].join(' '));
        shortNames.set(b.product.product_id, b.product.name || b.name);
      }
      walk(b.branches, next);
    }
  }
  walk(doc.product_tree?.branches);
  for (const p of doc.product_tree?.full_product_names || []) {
    names.set(p.product_id, p.name);
    shortNames.set(p.product_id, p.name);
  }
  for (const r of doc.product_tree?.relationships || [])
    names.set(
      r.full_product_name.product_id,
      `${names.get(r.product_reference) || ''} ${names.get(r.relates_to_product_reference) || ''} ${r.full_product_name.name}`,
    );
  const v = doc.vulnerabilities?.find((v) => v.cve?.toUpperCase() === id);
  if (!v) return [];
  const result = [];
  for (const [key, reportedStatus] of [
    ['known_affected', 'affected'],
    ['known_not_affected', 'unaffected'],
    ['fixed', 'fixed'],
    ['recommended', 'recommended'],
    ['under_investigation', 'unknown'],
  ]) {
    for (const pid of v.product_status?.[key] || []) {
      const name = names.get(pid) || pid.replaceAll('_', ' ');
      if (!product.match.test(name)) continue;
      const rem = (v.remediations || []).filter(
        (r) =>
          (!r.product_ids?.length && !r.group_ids?.length) ||
          r.product_ids?.includes(pid) ||
          r.group_ids?.some((g) => groups.get(g)?.includes(pid)),
      );
      const status =
        reportedStatus === 'recommended'
          ? rem.some((r) => r.category === 'vendor_fix')
            ? 'fixed'
            : 'unknown'
          : reportedStatus;
      const short =
        shortNames.get(pid) ||
        doc.product_tree?.relationships?.find((r) => r.full_product_name.product_id === pid)?.full_product_name.name ||
        name;
      result.push({
        name: short,
        status,
        affected: status === 'affected' ? [short] : [],
        unaffected: [],
        fix: status === 'fixed' ? [short] : rem.filter((r) => r.category === 'vendor_fix').map((r) => r.details),
        mitigation: rem.filter((r) => ['mitigation', 'workaround'].includes(r.category)).map((r) => r.details),
        source,
        links: rem.filter((r) => r.category === 'vendor_fix' && r.url).map((r) => r.url),
        ...(reportedStatus === 'recommended'
          ? {
              note:
                status === 'fixed'
                  ? 'Recommended patched build; vendor-fix remediation published.'
                  : 'Recommended build; no explicit vendor-fix remediation published.',
            }
          : {}),
      });
    }
  }
  return result;
}
// TMDS Agent support: compare vendor kernel fixes with kernels bundled in the
// Deep Security Agent package. Package versions and kernel release names use
// different schemes per vendor, so each parser maps both to {branch, build}.
// A bundled kernel supports the fix when it is the same branch and build >= fix.
const ARCH = /_(?:x86_64|amd64|aarch64|arm64|ppc64le|s390x)$/;
const nums = (s) => String(s).split(/[._]/).filter(Boolean).map(Number);
const dots = (s) => s.replace(/_/g, '.');
const ubuntuFlavor = (pkg, abi) => (abi >= 1000 ? pkg.replace(/^linux-?/, '').split('-')[0] : '');
const KERNELS = {
  rhel: {
    fix: (f) => {
      const m = f.match(/^kernel(?:-[a-z][a-z0-9_]*)*-(\d+\.\d+\.\d+)-(\d+(?:\.\d+)*)\.el(\d+(?:_\d+)?)$/);
      return m && { branch: `el${m[3]}`, build: nums(`${m[1]}.${m[2]}`), label: `${m[1]}-${m[2]}.el${m[3]}` };
    },
    vfs: (k) => {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d+(?:_\d+)*)_el(\d+(?:_\d+)?)$/);
      return (
        m && { branch: `el${m[3]}`, build: nums(`${m[1]}_${m[2]}`), label: `${dots(m[1])}-${dots(m[2])}.el${m[3]}` }
      );
    },
  },
  sles: {
    // kernel-default-5.14.21-150500.55.195.1 runs as 5.14.21-150500.55.195-default.
    fix: (f) => {
      const m = f.match(/^kernel-([a-z0-9]+)(?:-[a-z]+)*-(\d+\.\d+\.\d+)-(\d{6})((?:\.\d+)+)$/);
      if (!m) return null;
      const flavor = ['azure', 'rt'].includes(m[1]) ? m[1] : 'default',
        build = nums(m[4]).slice(0, -1);
      return {
        branch: `${m[2]}-${m[3]} ${flavor}`,
        build,
        label: `${m[2]}-${m[3]}.${build.join('.')}-${flavor}`,
        optional: flavor !== 'default',
      };
    },
    vfs: (k) => {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d{6})_(\d+(?:_\d+)*)_([a-z][a-z0-9]*)$/);
      return (
        m && {
          branch: `${dots(m[1])}-${m[2]} ${m[4]}`,
          build: nums(m[3]),
          label: `${dots(m[1])}-${m[2]}.${dots(m[3])}-${m[4]}`,
        }
      );
    },
  },
  ubuntu: {
    // linux 5.15.0-130.140 runs as 5.15.0-130-generic; cloud kernels use ABI >= 1000.
    fix: (f) => {
      const m = f.match(/^(linux(?:-[a-z0-9.-]+)?) (\d+\.\d+\.\d+)-(\d+)\.\d+/);
      if (!m) return null;
      const flavor = ubuntuFlavor(m[1], +m[3]);
      return {
        branch: `${m[2]} ${flavor}`,
        build: [+m[3]],
        label: `${m[2]}-${m[3]}${flavor ? `-${flavor}` : ''}`,
        optional: Boolean(flavor),
      };
    },
    vfs: (k) => {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d+)_([a-z][a-z0-9_]*)$/);
      if (!m) return null;
      const flavor = +m[2] >= 1000 ? m[3].split('_')[0] : '';
      return {
        branch: `${dots(m[1])} ${flavor}`,
        build: [+m[2]],
        label: `${dots(m[1])}-${m[2]}-${m[3].replace(/_/g, '-')}`,
      };
    },
  },
  debian: {
    // Only the 6.12+ scheme (6.12.113+deb13-amd64) carries the upstream version.
    fix: (f) => {
      const m = f.match(/^linux(?:-\d+\.\d+)? (\d+)\.(\d+)\.(\d+)-/);
      return m && { branch: `${m[1]}.${m[2]}`, build: [+m[3]], label: `${m[1]}.${m[2]}.${m[3]}` };
    },
    vfs: (k) => {
      const m = k.match(/^(\d+)_(\d+)_(\d+)\+deb\d+/);
      return (
        m && {
          branch: `${m[1]}.${m[2]}`,
          build: [+m[3]],
          label: k
            .replace(ARCH, '')
            .replace(/_(?=\d)/g, '.')
            .replace(/_/g, '-'),
        }
      );
    },
  },
};
const compareBuild = (a, b) => {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? -1) - (b[i] ?? -1);
    if (d) return d;
  }
  return 0;
};
export const isKernelFix = (f) => /^(?:kernel|linux)(?:-[a-z0-9_.]+)*[- ](?:0:)?\d+\.\d+\.\d+/.test(f);
export function tmdsSupport(family, fixes, releases = []) {
  const parse = KERNELS[family];
  const bundled = releases.flatMap((r) => r.kernels.map((k) => ({ ...(parse?.vfs(k) || {}), raw: k, release: r })));
  if (!parse) return { status: 'unknown', branches: [] };
  const wanted = new Map();
  for (const f of fixes) {
    const k = parse.fix(f);
    if (k && (!wanted.has(k.branch) || compareBuild(k.build, wanted.get(k.branch).build) < 0)) wanted.set(k.branch, k);
  }
  const branches = [...wanted.values()].map((fix) => {
    const same = bundled.filter((b) => b.branch === fix.branch).sort((a, b) => compareBuild(a.build, b.build));
    const ok = same.filter((b) => compareBuild(b.build, fix.build) >= 0);
    const pick = ok[0] || same.at(-1);
    const arches = pick
      ? [...new Set(same.filter((b) => b.label === pick.label).map((b) => b.release.architecture))]
      : [];
    return {
      fix: fix.label,
      optional: fix.optional,
      status: ok.length ? 'supported' : same.length ? 'pending' : 'unknown',
      kernel: pick?.label,
      exact: pick ? compareBuild(pick.build, fix.build) === 0 : false,
      arches,
      release: pick?.release,
    };
  });
  // Extra flavours TMDS does not bundle at all (raspi, rt, ibm…) are left out.
  // For main kernels, unknown counts against "supported": no match is not proof of support.
  const shown = branches.filter((b) => !(b.optional && b.status === 'unknown'));
  if (!shown.length) return { status: branches.length ? 'none' : 'unknown', branches: [] };
  const status = shown.every((b) => b.status === 'unknown')
    ? 'unknown'
    : shown.every((b) => b.status === 'supported')
      ? 'supported'
      : shown.some((b) => b.status === 'supported')
        ? 'partial'
        : 'pending';
  return { status, branches: shown };
}
// Accept any text that contains a CVE ID, such as an advisory URL; IDs are case-insensitive.
export function extractCveIds(text) {
  return [...new Set([...String(text).matchAll(/cve[-_](\d{4})[-_](\d{4,})/gi)].map((m) => `CVE-${m[1]}-${m[2]}`))];
}
// Split "name version" (Debian/Ubuntu/Alpine), RPM "name-version-release" or "Windows product build".
export function splitPackage(f) {
  const m = f.match(/^(\S+) (\S+)$/) || f.match(/^(.+?)-(\d[^-\s]*-[^-\s]+)$/) || f.match(/^(.+) (\d+(?:\.\d+){2,})$/);
  return m ? { name: m[1], version: m[2] } : { name: f, version: '' };
}
// Group fixed packages that share a build (kernel, kernel-64k, kernel-core…).
// The group's main package is the first one in the given ranking order.
export function groupFixes(fixes) {
  const groups = new Map();
  for (const f of fixes) {
    const { name, version } = splitPackage(f),
      key = version || f;
    if (!groups.has(key)) groups.set(key, { version, main: name, packages: [] });
    groups.get(key).packages.push(f);
  }
  return [...groups.values()];
}
