// Trend Micro Deep Security (TMDS) kernel support for vendor kernel fixes.
//
// Vendors publish fixed kernel *package* versions; Trend Micro lists kernel
// *release* names (`uname -r`) in two places:
//   - Plugin-VFS descriptors bundled in each Deep Security Agent 20 LTS package
//     (5_14_0_427_13_1_el9_4_x86_64), and
//   - the Kernel Support Package (KSP) page (5.14.0-427.13.1.el9_4.x86_64).
// Each family parser maps all three forms to {branch, build}. A listed kernel
// supports a fix when it is in the same branch (kernel stream + flavour) and
// its build is the same or newer. This is package/catalog evidence only: it
// says nothing about an installed agent or a runtime certification.

const ARCH = /[._](?:x86_64|amd64|aarch64|arm64|ppc64le|s390x)$/;
const ARCH_ORDER = ['x86_64', 'aarch64', 'ppc64le', 's390x'];
const nums = (s) => String(s).split(/[._]/).filter(Boolean).map(Number);
const dots = (s) => s.replace(/_/g, '.');

export function compareBuild(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? -1) - (b[i] ?? -1);
    if (d) return d;
  }
  return 0;
}
// Trend Micro release strings such as 20.0.3-36500.
export const compareRelease = (a, b) =>
  compareBuild(String(a).split(/[.-]/).map(Number), String(b).split(/[.-]/).map(Number));
const newestRelease = (list) => list.reduce((a, b) => (!a || compareRelease(b, a) > 0 ? b : a), null);

// Ubuntu: an ABI >= 1000 marks a cloud/OEM kernel whose flavour comes from the
// source package (linux-aws-6.5 → aws, linux-aws-fips → aws-fips). Below 1000
// it is the main kernel (linux, linux-hwe-6.8, linux-lowlatency); only FIPS
// builds share the ABI under their own flavour.
function ubuntuFixFlavor(pkg, abi) {
  const name = pkg.replace(/^linux-?/, '').replace(/-\d+\.\d+$/, '');
  if (abi >= 1000) return name;
  return name === 'fips' ? 'fips' : '';
}
const ubuntuKernelFlavor = (abi, suffix) => (abi >= 1000 || suffix !== 'generic' ? suffix : '');
function ubuntuKernel(release) {
  const m = release.match(/^(\d+\.\d+\.\d+)-(\d+)-([a-z0-9][a-z0-9-]*)$/);
  if (!m) return null;
  const flavor = ubuntuKernelFlavor(+m[2], m[3]);
  return { branch: `${m[1]} ${flavor}`, build: [+m[2]], label: release, series: flavor, rank: [...nums(m[1]), +m[2]] };
}

// Debian: the security tracker's fixed version for a release covers every later
// version of that source package in the release. Kernels named after their
// upstream version carry the release tag: 6.12.38+deb13-amd64 (trixie `linux`),
// 6.12.90+deb12.1-cloud-amd64 (bookworm `linux-6.12`), 6.10.11+bpo-amd64
// (backports, not covered by the release's tracker entry). trixie-backports
// kernels also carry +deb13 (6.16.3+deb13-amd64), so a branch is the upstream
// series (`linux 6.12`): a 6.16 kernel says nothing about a 6.12 fix. A respin of
// the same upstream version (+deb13.1, +deb13+1) is a fourth build component.
// Bookworm's main `linux` uses ABI names (6.1.0-9-amd64) that do not reveal the
// package version, so those kernels cannot be compared.
// Upstream series of each release's main `linux` source package.
const DEBIAN_LINUX = { 12: [6, 1], 13: [6, 12] };
// Fixed in a later Debian revision than the first upload of that upstream version:
// listed kernels of the same upstream version may or may not include it.
const LATER_REVISION = 1e9;
function debianKernel(release) {
  const m = release.match(/^(\d+)\.(\d+)\.(\d+)\+(?:deb(\d+)(?:[.+](\d+))?|(bpo))-(cloud-)?(?:amd64|arm64)$/);
  if (!m) return null;
  const branch = `${m[6] ? 'bpo' : 'linux'} ${m[1]}.${m[2]}${m[7] ? ' cloud' : ''}`;
  return {
    branch,
    build: [+m[1], +m[2], +m[3], +(m[5] || 0)],
    label: release,
    series: branch,
    release: m[4] ? +m[4] : null,
  };
}

// SUSE kernel flavours other than default (each its own kernel package and uname suffix).
const SLES_FLAVORS = [
  'azure',
  'rt',
  'preempt',
  '64kb',
  'zfcpdump',
  'kvmsmall',
  'debug',
  'vanilla',
  'coco',
  'lpae',
  'pae',
];
// RHEL variant kernels built from the same source (uname suffix +rt, +64k, +debug); kernel-core,
// -modules, -devel, -tools… belong to the standard kernel.
const RHEL_VARIANTS = ['rt', '64k', 'debug', 'zfcpdump'];
const rhelBranch = (stream, variant) => `el${stream}${variant ? ` ${variant}` : ''}`;

const KERNELS = {
  rhel: {
    // kernel-5.14.0-427.13.1.el9_4 runs as 5.14.0-427.13.1.el9_4.x86_64; EUS streams (el9_4) stay separate.
    // kernel-rt-…, kernel-64k-… and kernel-debug-… are variants that only kernels of that variant support.
    fix(f) {
      const m = f.match(/^kernel((?:-\d*[a-z][a-z0-9_]*)*)-(\d+\.\d+\.\d+)-(\d+(?:\.\d+)*)\.el(\d+)(_\d+)?$/);
      if (!m) return null;
      const variant = m[1].split('-').find((s) => RHEL_VARIANTS.includes(s)) || '';
      return {
        branch: rhelBranch(`${m[4]}${m[5] || ''}`, variant),
        build: nums(`${m[2]}.${m[3]}`),
        label: `${m[2]}-${m[3]}.el${m[4]}${m[5] || ''}${variant ? `+${variant}` : ''}`,
        optional: Boolean(variant),
        series: rhelBranch(m[4], variant),
      };
    },
    vfs(k) {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d+(?:_\d+)*)_el(\d+)(_\d+)?$/);
      return (
        m && {
          branch: `el${m[3]}${m[4] || ''}`,
          build: nums(`${m[1]}_${m[2]}`),
          label: `${dots(m[1])}-${dots(m[2])}.el${m[3]}${m[4] || ''}`,
          series: `el${m[3]}`,
        }
      );
    },
    // Cloud kernels (….el9_2.cloud.0.3) are a separate flavour that RHEL kernel fixes do not cover.
    // Variant kernels carry a suffix after the architecture: 5.14.0-427.13.1.el9_4.x86_64+rt.
    ksp(k) {
      const [base, variant = ''] = k.split('+');
      const m = base.replace(ARCH, '').match(/^(\d+\.\d+\.\d+)-(\d+(?:\.\d+)*)\.el(\d+)(_\d+)?(\.cloud(?:\.\d+)*)?$/);
      if (!m || (variant && !RHEL_VARIANTS.includes(variant))) return null;
      const cloud = m[5] ? ' cloud' : '';
      return {
        branch: `${rhelBranch(`${m[3]}${m[4] || ''}`, variant)}${cloud}`,
        build: nums(`${m[1]}.${m[2]}`),
        label: k,
        series: `${rhelBranch(m[3], variant)}${cloud}`,
      };
    },
  },
  sles: {
    // kernel-default-5.14.21-150500.55.195.1 runs as 5.14.21-150500.55.195-default (rebuild counter dropped).
    fix(f) {
      const m = f.match(/^kernel((?:-[a-z0-9]+)+)-(\d+\.\d+\.\d+)-(\d{6})((?:\.\d+)+)$/);
      if (!m) return null;
      const parts = nums(m[4]);
      // kernel-default-base carries a second release (….55.44.1.150500.6.19.5); its kernel build matches kernel-default.
      if (parts.length > 3) return null;
      // kernel-azure, kernel-devel-azure, kernel-preempt and kernel-source-rt belong to their flavour (a
      // separate kernel that only kernels of that flavour can support); kernel-source, -syms, -docs to default.
      const flavor = m[1].split('-').find((s) => SLES_FLAVORS.includes(s)) || 'default',
        build = parts.slice(0, -1);
      return {
        branch: `${m[2]}-${m[3]} ${flavor}`,
        build,
        label: `${m[2]}-${m[3]}.${build.join('.')}-${flavor}`,
        optional: flavor !== 'default',
        series: flavor,
        rank: [...nums(m[2]), +m[3], ...build],
      };
    },
    vfs(k) {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d{6})_(\d+(?:_\d+)*)_(\d*[a-z][a-z0-9]*)$/);
      return (
        m && {
          branch: `${dots(m[1])}-${m[2]} ${m[4]}`,
          build: nums(m[3]),
          label: `${dots(m[1])}-${m[2]}.${dots(m[3])}-${m[4]}`,
          series: m[4],
          rank: [...nums(m[1]), +m[2], ...nums(m[3])],
        }
      );
    },
    // 6.4.0-150700.53.31-default; SLES 15 GA names without a 6-digit release (4.12.14-25.13-default) are skipped.
    ksp(k) {
      const m = k.match(/^(\d+\.\d+\.\d+)-(\d{6})\.(\d+(?:\.\d+)*)-(\d*[a-z][a-z0-9]*)$/);
      return (
        m && {
          branch: `${m[1]}-${m[2]} ${m[4]}`,
          build: nums(m[3]),
          label: k,
          series: m[4],
          rank: [...nums(m[1]), +m[2], ...nums(m[3])],
        }
      );
    },
  },
  ubuntu: {
    // linux 5.15.0-130.140 runs as 5.15.0-130-generic; linux-aws 5.15.0-1070.76 as 5.15.0-1070-aws.
    fix(f) {
      const m = f.match(/^(linux(?:-[a-z0-9.-]+)?) (\d+\.\d+\.\d+)-(\d+)\.\d+/);
      if (!m) return null;
      const flavor = ubuntuFixFlavor(m[1], +m[3]);
      return {
        branch: `${m[2]} ${flavor}`,
        build: [+m[3]],
        label: `${m[2]}-${m[3]}-${flavor || 'generic'}`,
        optional: Boolean(flavor),
        series: flavor,
        rank: [...nums(m[2]), +m[3]],
      };
    },
    vfs: (k) => {
      const m = k.replace(ARCH, '').match(/^(\d+_\d+_\d+)_(\d+)_([a-z][a-z0-9_]*)$/);
      return m && ubuntuKernel(`${dots(m[1])}-${m[2]}-${m[3].replace(/_/g, '-')}`);
    },
    ksp: ubuntuKernel,
  },
  debian: {
    // linux 6.12.113-1 (or linux-6.12 6.12.113-1~deb12u1): branch is the upstream series of the source package.
    fix(f) {
      const m = f.match(/^(linux(?:-\d+\.\d+)?) (\d+)\.(\d+)\.(\d+)-(\d[\w.+~]*)/);
      if (!m) return null;
      const branch = `linux ${m[2]}.${m[3]}`,
        later = !/^1(?:~deb\d+u1)?$/.test(m[5]);
      return {
        branch,
        build: [+m[2], +m[3], +m[4], later ? LATER_REVISION : 0],
        label: `${m[1]} ${m[2]}.${m[3]}.${m[4]}-${m[5]}`,
        series: branch,
        pkg: m[1],
        upstream: 3,
        later,
      };
    },
    // A `linux` fix from before the release (linux 6.6.15-1 for trixie) covers every
    // kernel of the release's main series; the release tag of the listed kernels tells which.
    adjust(fix, kernels) {
      const tags = new Set(kernels.map((k) => k.release).filter(Boolean)),
        main = tags.size === 1 ? DEBIAN_LINUX[[...tags][0]] : null;
      if (fix.pkg !== 'linux' || !main || compareBuild(fix.build.slice(0, 2), main) >= 0) return fix;
      const branch = `linux ${main.join('.')}`;
      return { ...fix, branch, series: branch, build: [0], later: false };
    },
    // 6_12_113+deb13_cloud_amd64 → 6.12.113+deb13-cloud-amd64; ABI names (6_1_0_44_amd64) stay unparsed.
    vfs: (k) => debianKernel(k.replace(/_(?=\d)/g, '.').replace(/_/g, '-')),
    ksp: debianKernel,
  },
};

export const isKernelFix = (f) => /^(?:kernel|linux)(?:-[a-z0-9_.]+)*[- ](?:0:)?\d+\.\d+\.\d+/.test(f);
export const kernelFamilies = Object.keys(KERNELS);

const byRank = (a, b) => compareBuild(a.rank || a.build, b.rank || b.build);
// Kernels of the fix's branch, ordered by build; without any, the newest kernel of
// the same series when the fix is from a newer minor stream or service pack.
function candidates(fix, parsed) {
  const same = parsed.filter((k) => k.branch === fix.branch).sort((a, b) => compareBuild(a.build, b.build));
  const series = parsed
    .filter((k) => k.series === fix.series)
    .sort(byRank)
    .at(-1);
  // Only a stream newer than everything listed is "not yet"; an older, unlisted stream stays unknown.
  const newest = same.at(-1) || (series && byRank(fix, series) > 0 ? series : undefined);
  const ok = same.filter((k) => compareBuild(k.build, fix.build) >= 0);
  // Fixed in a later package revision of an upstream version that is listed: no way to tell.
  const upstream = (k) => k.build.slice(0, fix.upstream);
  const unsure =
    fix.later && !ok.length ? same.filter((k) => compareBuild(upstream(k), upstream(fix)) === 0).at(-1) : undefined;
  return { ok, newest, unsure };
}

// Bundled agent: the earliest agent release (of this architecture) that bundles
// a kernel >= the fix in the same branch.
function agentCell(fix, releases) {
  if (!releases.length) return { status: 'nodata' };
  let best = null,
    newest = null;
  for (const r of releases) {
    const c = candidates(fix, r.parsed);
    if (c.ok.length && (!best || compareRelease(r.release, best.release.release) < 0))
      best = { release: r, kernel: c.ok[0] };
    if (c.newest && (!newest || byRank(c.newest, newest.kernel) > 0)) newest = { release: r, kernel: c.newest };
  }
  if (best)
    return {
      status: 'supported',
      release: best.release,
      kernel: best.kernel.label,
      exact: compareBuild(best.kernel.build, fix.build) === 0,
    };
  const latest = releases.reduce((a, b) => (compareRelease(b.release, a.release) > 0 ? b : a));
  const unsure = releases.map((r) => candidates(fix, r.parsed).unsure).find(Boolean);
  if (unsure) return { status: 'unknown', release: latest, kernel: unsure.label, revision: true };
  if (newest) return { status: 'pending', release: latest, kernel: newest.kernel.label };
  return { status: 'unknown', release: latest };
}

// Kernel Support Package: does the current KSP list a kernel >= the fix? The
// minimum KSP needed is the smallest `since` among qualifying kernels; a null
// `since` means the kernel was listed when the server first saw this package,
// so only "current KSP or earlier" is known. Δ cells only cover WRS/FW/IPS.
function kspCell(fix, entry) {
  if (!entry) return { status: 'nodata' };
  const c = candidates(fix, entry.parsed);
  const full = c.ok.filter((k) => !k.partial),
    use = full.length ? full : c.ok;
  if (use.length) {
    const since = use.map((k) => k.since),
      known = since.every(Boolean);
    return {
      status: full.length ? 'supported' : 'partial',
      partial: !full.length,
      entry,
      kernel: use[0].label,
      exact: compareBuild(use[0].build, fix.build) === 0,
      since: known ? since.sort(compareRelease)[0] : null,
    };
  }
  if (c.unsure) return { status: 'unknown', entry, kernel: c.unsure.label, revision: true };
  if (c.newest) return { status: 'pending', entry, kernel: c.newest.label };
  return { status: 'unknown', entry };
}

// Combines statuses of several cells: all supported, some, none yet, or nothing to compare.
export function combineStatus(statuses) {
  const s = statuses.filter((x) => x !== 'nodata');
  if (!s.length) return 'nodata';
  if (s.every((x) => x === 'supported')) return 'supported';
  if (s.some((x) => x === 'supported' || x === 'partial')) return 'partial';
  if (s.some((x) => x === 'pending')) return 'pending';
  return 'unknown';
}
// A (branch, architecture) cell is covered when the agent or the KSP supports it.
function cellStatus(cell) {
  if (cell.agent.status === 'supported' || cell.ksp.status === 'supported') return 'supported';
  if (cell.ksp.status === 'partial') return 'partial';
  if (cell.agent.status === 'pending' || cell.ksp.status === 'pending') return 'pending';
  return cell.agent.status === 'nodata' && cell.ksp.status === 'nodata' ? 'nodata' : 'unknown';
}
const comparable = (cell) =>
  ['supported', 'partial', 'pending'].some((s) => [cell.agent.status, cell.ksp.status].includes(s));

/**
 * Support of one OS version's kernel fixes by the bundled agent and the KSP.
 * @param family vendor family (rhel, sles, ubuntu, debian)
 * @param fixes fixed package strings (non-kernel entries are ignored)
 * @param inventory {releases: agent releases for this OS, ksp: KSP entries for this OS (one per architecture)}
 * Status is computed for x86_64 when Trend Micro lists it, otherwise for every listed architecture;
 * each branch keeps one cell per architecture for details.
 */
export function kernelSupport(family, fixes, { releases = [], ksp = [] } = {}) {
  const parser = KERNELS[family];
  const empty = { status: 'unknown', branches: [], arches: [], agent: { status: 'nodata' }, ksp: { status: 'nodata' } };
  if (!parser) return empty;
  const agents = releases.map((r) => ({
    ...r,
    parsed: (r.kernels || []).map((k) => parser.vfs(String(k))).filter(Boolean),
  }));
  const packages = ksp.map((e) => ({
    ...e,
    parsed: (e.kernels || [])
      .map(([release, , since, partial]) => {
        const k = parser.ksp(String(release));
        return k && { ...k, since: since || null, partial: Boolean(partial) };
      })
      .filter(Boolean),
  }));
  const listed = [...agents, ...packages].flatMap((x) => x.parsed);
  const wanted = new Map();
  for (const f of fixes) {
    let k = parser.fix(f);
    if (k && parser.adjust) k = parser.adjust(k, listed);
    if (k && (!wanted.has(k.branch) || compareBuild(k.build, wanted.get(k.branch).build) < 0)) wanted.set(k.branch, k);
  }
  const arches = [...new Set([...agents, ...packages].map((x) => x.architecture))].sort(
    (a, b) => (ARCH_ORDER.indexOf(a) + 1 || 99) - (ARCH_ORDER.indexOf(b) + 1 || 99),
  );
  const primary = arches.includes('x86_64') ? ['x86_64'] : arches;
  const branches = [...wanted.values()].map((fix) => {
    const cells = arches.map((arch) => ({
      arch,
      agent: agentCell(
        fix,
        agents.filter((r) => r.architecture === arch),
      ),
      ksp: kspCell(
        fix,
        packages.find((e) => e.architecture === arch),
      ),
    }));
    const main = cells.filter((c) => primary.includes(c.arch));
    return {
      fix: fix.label,
      branch: fix.branch,
      optional: Boolean(fix.optional),
      cells,
      agent: combineStatus(main.map((c) => c.agent.status)),
      ksp: combineStatus(main.map((c) => c.ksp.status)),
      status: combineStatus(main.map(cellStatus)),
      comparable: cells.some(comparable),
    };
  });
  // Flavours Trend Micro does not list at all (raspi, kvm, rt…) are left out.
  // For main kernels, no match is not proof of support: they stay as "unknown".
  const shown = branches.filter((b) => !b.optional || b.comparable);
  if (!shown.length) return { ...empty, status: branches.length ? 'none' : 'unknown', arches };
  const main = shown.flatMap((b) => b.cells.filter((c) => primary.includes(c.arch)));
  const agentStatus = combineStatus(shown.map((b) => b.agent));
  const kspStatus = combineStatus(shown.map((b) => b.ksp));
  const kspCells = main.filter((c) => ['supported', 'partial'].includes(c.ksp.status));
  const status = combineStatus(shown.map((b) => b.status));
  return {
    status: status === 'nodata' ? 'unknown' : status,
    branches: shown,
    arches,
    primary,
    agent: {
      status: agentStatus,
      // The agent release needed for every branch: the newest of the per-branch earliest releases.
      release:
        agentStatus === 'supported'
          ? newestRelease(main.filter((c) => c.agent.status === 'supported').map((c) => c.agent.release.release))
          : null,
    },
    ksp: {
      status: kspStatus,
      // The KSP needed for every branch: the newest of the per-branch minimums.
      release: kspCells.every((c) => c.ksp.since) ? newestRelease(kspCells.map((c) => c.ksp.since)) : null,
      current: newestRelease(main.map((c) => c.ksp.entry?.release).filter(Boolean)),
      partial: kspCells.length > 0 && kspCells.every((c) => c.ksp.partial),
    },
  };
}

// Closed summary of the TMDS fact, e.g. "KSP 20.0.3-36500 · Agent not yet".
export function supportSummary(t) {
  const ksp = {
    supported: `KSP ${t.ksp.release || t.ksp.current}`,
    partial: t.ksp.partial ? `KSP Δ ${t.ksp.release || t.ksp.current}` : 'KSP partly',
    pending: 'KSP not yet',
    unknown: 'KSP unverified',
    nodata: 'KSP no data',
  }[t.ksp.status];
  const agent = {
    supported: `Agent ${t.agent.release}`,
    partial: 'Agent partly',
    pending: 'Agent not yet',
    unknown: 'Agent unverified',
    nodata: 'Agent no data',
  }[t.agent.status];
  return `${ksp} · ${agent}`;
}

// Selects the inventory for one OS version from the /api/tmds payload.
export function productInventory(inventory, productId) {
  return {
    releases: inventory?.products?.[productId] || [],
    ksp: inventory?.ksp?.products?.[productId] || [],
  };
}
// KSP package name without architecture and extension: KernelSupport-RedHat_EL9-20.0.3-36500.
export const kspName = (entry) =>
  String(entry?.filename || `KSP ${entry?.release || ''}`)
    .replace(/\.zip$/i, '')
    .replace(ARCH, '');
