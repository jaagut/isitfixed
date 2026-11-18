import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderCase } from '../src/render/case.js';
import { renderHome } from '../src/render/home.js';
import { DEFAULT_CONFIG } from '../src/api.js';
import { defaultState } from '../src/state.js';

const ID = 'CVE-2024-1086';
const NOW = Date.parse('2026-11-18T15:00:00Z');
const kernel = 'kernel-0:5.14.0-427.13.1.el9_4.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)';
const c = {
  id: ID,
  products: ['rhel9', 'windows11'],
  notes: '',
  checked: NOW,
  record: {
    cveMetadata: { cveId: ID, state: 'PUBLISHED' },
    containers: {
      cna: {
        title: 'Use-after-free in nf_tables',
        affected: [{ product: 'Windows 11', defaultStatus: 'unaffected' }],
      },
    },
  },
  vendorData: {
    id: ID,
    evidence: {
      rhel9: [
        {
          name: 'kernel',
          status: 'fixed',
          fix: [kernel],
          affected: [],
          unaffected: [],
          mitigation: ['Blacklist the nf_tables module.'],
          links: [
            'https://access.redhat.com/errata/RHSA-2024:2394',
            'https://access.redhat.com/errata/RHSA-2024:3138',
            'https://access.redhat.com/errata/RHSA-2024:3306',
          ],
          source: 'Red Hat VEX',
        },
      ],
    },
    sources: {
      rhel: { url: 'https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-1086.json', checked: NOW },
    },
  },
};
const inventory = {
  data: {
    products: {
      rhel9: [
        {
          release: '20.0.3-31610',
          architecture: 'x86_64',
          kernels: ['5_14_0_427_13_1_el9_4_x86_64'],
          download: 'https://files.trendmicro.com/agent.zip',
        },
      ],
    },
    checked: NOW,
    ksp: {
      products: {
        rhel9: [
          {
            architecture: 'x86_64',
            release: '20.0.3-36500',
            filename: 'KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip',
            download:
              'https://files.trendmicro.com/products/deepsecurity/en/20.0/KernelSupport-RedHat_EL9-20.0.3-36500.x86_64.zip',
            kernels: [['5.14.0-427.13.1.el9_4.x86_64', 'default', '20.0.3-36000', false]],
          },
        ],
      },
      notes: ['To use KSP 20.0.1 or later, DSM 20.0.883+ and DSA 20.0.0-8453+ are required.'],
      checked: NOW,
    },
  },
  error: null,
};
const ctx = (extra = {}) => ({
  state: { ...defaultState(), cases: [c] },
  config: DEFAULT_CONFIG,
  inventory,
  tmdsOn: true,
  busy: new Set(),
  chooserOpen: false,
  groupOverride: new Map(),
  now: NOW,
  ...extra,
});

test('case page: no inline styles or handlers (CSP), root-absolute logos', () => {
  const html = renderCase(c, ctx()) + renderHome(ctx(), null);
  assert.doesNotMatch(html, /\sstyle=/);
  assert.doesNotMatch(html, /\son[a-z]+=/);
  assert.doesNotMatch(html, /<script/);
  assert.match(html, /src="\/assets\/logos\/redhat\.svg"/);
});

test('header: refresh only when the server allows it; status line links to Sources', () => {
  assert.doesNotMatch(renderCase(c, ctx()), /id="refresh"/);
  assert.match(renderCase(c, ctx({ config: { ...DEFAULT_CONFIG, manualRefresh: true } })), /id="refresh"/);
  const html = renderCase(c, ctx());
  assert.match(html, /href="#case-sources"[^>]*>.*Sources checked/);
  assert.match(html, /<details class="sources-section" id="case-sources" data-detail="sources">/);
  assert.doesNotMatch(html, /re-checks watched cases/);
  assert.match(html, /id="delete-case"[^>]*data-delete="CVE-/);
  assert.doesNotMatch(html, /class="freshness"/);
});

test('version shows its status and advisories without redundant vendor links; mitigations retain sources', () => {
  const html = renderCase(c, ctx());
  assert.doesNotMatch(html, /fact-label">Advisor/);
  assert.match(html, /Advisories: <a [^>]*>RHSA-2024:2394 ↗<\/a>, <a [^>]*>RHSA-2024:3138 ↗<\/a>/);
  assert.match(
    html,
    /<details class="advisory-list"[^>]*><summary aria-label="Show 1 more advisory">\+1<\/summary><div><a [^>]*>RHSA-2024:3306 ↗<\/a><\/div><\/details>/,
  );
  assert.doesNotMatch(html, /All 3 advisories|class="table-head"|class="assessment-source"/);
  assert.match(html, /class="product-name"><strong>[^<]+<\/strong><div class="assessment"><span class="status /);
  const version = html.match(/class="product-name">([\s\S]*?)<div class="fix-summary">/)[1];
  assert.doesNotMatch(version, /Red Hat VEX ↗|>Red Hat ↗<\/a>|Source:/);
  assert.match(html, /TMDS Kernel Support Packages/);
  assert.match(html, /Vendor data/);
  assert.match(html, /class="when-open">1 mitigation<\/span>/);
  assert.match(html, /class="when-closed"><span class="fact-text">Blacklist the nf_tables module/);
  assert.match(
    html,
    /Blacklist the nf_tables module\.<\/p><p class="fact-source">Source: <a href="https:\/\/access\.redhat\.com\/errata\/RHSA-2024:2394"/,
  );
});

test('TMDS fact with KSP and agent details; everything TMDS disappears when off', () => {
  const on = renderCase(c, ctx());
  assert.match(on, /KSP 20\.0\.3-36000 · Agent 20\.0\.3-31610/);
  assert.match(on, /KernelSupport-RedHat_EL9-20\.0\.3-36500 ↗<\/a> — supports it since KSP 20\.0\.3-36000/);
  assert.match(on, /Agent 20\.0\.3-31610 or later ↗/);
  assert.match(on, /DSM 20\.0\.883\+/);
  assert.match(on, /not a runtime certification/);
  assert.match(on, /Kernel Support Packages<\/h3>/);
  const off = renderCase(c, ctx({ tmdsOn: false }));
  assert.doesNotMatch(off, /tmds|TMDS|Kernel Support/);
  assert.doesNotMatch(renderHome(ctx({ tmdsOn: false }), null), /Deep Security/);
  assert.match(renderHome(ctx(), null), /Trend Micro Deep Security/);
});

test('hostile or odd vendor data cannot break the case page', () => {
  const odd = structuredClone(c);
  odd.vendorData.evidence.rhel9[0].links = ['https://access.redhat.com/errata/RHSA-%E0%A4%A', 'https://x.test/a%2Fb'];
  odd.vendorData.sources.rhel.excludedImages = '"><img src=x onerror=alert(1)>';
  const html = renderCase(odd, ctx());
  assert.match(html, />RHSA-%E0%A4%A ↗</, 'malformed percent-encoding is shown as published');
  assert.match(html, />a\/b ↗</);
  assert.doesNotMatch(html, /<img src=x|onerror=/);
  odd.vendorData.sources.rhel.excludedImages = 3;
  assert.match(renderCase(odd, ctx()), /3 public-cloud image entries not counted/);
});

test('TMDS: no line for families without kernel matching; Debian respins are not verifiable', () => {
  const alpine = {
    ...structuredClone(c),
    products: ['alpine322'],
    vendorData: {
      id: ID,
      evidence: { alpine322: [{ name: 'linux-lts', status: 'fixed', fix: ['linux-lts 6.12.1-r0'], source: 'Alpine' }] },
      sources: { alpine: { checked: NOW } },
    },
  };
  assert.doesNotMatch(renderCase(alpine, ctx()), /fact-label">TMDS/);
  assert.doesNotMatch(renderCase(alpine, ctx({ inventory: { data: null, error: null } })), /Checking inventory/);
  const debian = {
    ...structuredClone(c),
    products: ['debian13'],
    vendorData: {
      id: ID,
      evidence: { debian13: [{ name: 'linux', status: 'fixed', fix: ['linux 6.12.90-2'], source: 'Debian' }] },
      sources: { debian: { checked: NOW } },
    },
  };
  const data = {
    checked: NOW,
    products: {},
    ksp: {
      checked: NOW,
      products: {
        debian13: [
          {
            architecture: 'x86_64',
            release: '20.0.3-36500',
            kernels: [['6.12.90+deb13-amd64', 'default', null, false]],
          },
        ],
      },
    },
  };
  const html = renderCase(debian, ctx({ inventory: { data, error: null } }));
  assert.match(html, /KSP unverified/);
  assert.match(html, /Lists <code>6\.12\.90\+deb13-amd64<\/code> of the same upstream version/);
});

test('home: every visitor sees what Is It Fixed is for', () => {
  const tagline = /Check whether a vulnerability is fixed for the OS versions you run/;
  assert.match(renderHome(ctx({ state: defaultState() }), null), tagline);
  assert.match(renderHome(ctx(), null), tagline);
});

test('each row links the vendor CVE page with its advisories', () => {
  const html = renderCase(c, ctx());
  const rhel = html.match(/data-row="rhel9">[\s\S]*?<div class="fix-summary">/)[0];
  assert.match(
    rhel,
    /<\/details><a href="https:\/\/access\.redhat\.com\/security\/cve\/CVE-2024-1086" [^>]*>Red Hat CVE page ↗<\/a><\/div>/,
  );
  const windows = html.match(/data-row="windows11">[\s\S]*?<div class="fix-summary">/)[0];
  assert.match(
    windows,
    /<div class="row-advisories"><a href="https:\/\/msrc\.microsoft\.com\/update-guide\/vulnerability\/CVE-2024-1086" [^>]*>Microsoft CVE page ↗<\/a><\/div>/,
  );
});

const ubuntuCase = (evidence, sources = { ubuntu: { checked: NOW } }) => ({
  ...structuredClone(c),
  products: ['ubuntu2404'],
  vendorData: { id: ID, evidence: { ubuntu2404: evidence }, sources },
});
const ubuntuEntry = (name, status, extra = {}) => ({
  name,
  status,
  affected: [],
  unaffected: [],
  fix: [],
  mitigation: [],
  links: [],
  source: 'Ubuntu security tracker',
  ...extra,
});
const rowHTML = (html, id) => html.match(new RegExp(`data-row="${id}">[\\s\\S]*?<div class="fix-summary">`))[0];

test('mitigations cite Red Hat VEX advisories only; other vendors cite their CVE page', () => {
  const html = renderCase(
    ubuntuCase([
      ubuntuEntry('openssh', 'fixed', {
        fix: ['openssh 1:9.6p1-3ubuntu13.3'],
        links: ['https://ubuntu.com/security/notices/USN-6859-1'],
        mitigation: ['Set LoginGraceTime to 0.'],
      }),
    ]),
    ctx(),
  );
  assert.match(
    html,
    /Set LoginGraceTime to 0\.<\/p><p class="fact-source">Source: <a href="https:\/\/ubuntu\.com\/security\/CVE-2024-1086" [^>]*>Ubuntu CVE page ↗<\/a><\/p>/,
  );
  assert.match(rowHTML(html, 'ubuntu2404'), />USN-6859-1 ↗<\/a>/, 'the USN stays a row advisory');
});

test('row explanations: who has not decided, what is still affected, why there is no data', () => {
  const triage = renderCase(
    ubuntuCase([ubuntuEntry('sqlite3', 'unknown', { note: 'Not yet triaged by Ubuntu' })]),
    ctx(),
  );
  // The vendor's own note says who has not decided; no second, generic line.
  assert.match(rowHTML(triage, 'ubuntu2404'), /Inconclusive<\/span><small>Not yet triaged by Ubuntu<\/small>/);
  assert.doesNotMatch(triage, /Ubuntu has not assessed this yet/);
  assert.doesNotMatch(triage, /Available evidence does not establish status/);
  const partial = renderCase(
    ubuntuCase([
      ubuntuEntry('linux', 'fixed', { fix: ['linux 6.8.0-100.100'] }),
      ubuntuEntry('linux-azure', 'affected', { note: 'Fix pending in 6.8.0-1052.55; not yet released' }),
      ubuntuEntry('linux-hwe-6.11', 'affected', { note: 'Ubuntu will not fix this: end of life' }),
    ]),
    ctx(),
  );
  const row = rowHTML(partial, 'ubuntu2404');
  assert.match(row, /<small>Still affected: linux-azure<\/small>/);
  assert.match(row, /<small>linux-azure: Fix pending in 6\.8\.0-1052\.55; not yet released<\/small>/);
  assert.match(row, /<small>linux-hwe-6\.11: Ubuntu will not fix this: end of life<\/small>/);
  assert.doesNotMatch(partial, /Older builds/);
  // Windows: the fixed build is the answer; nothing is listed as still affected.
  assert.doesNotMatch(rowHTML(renderCase(c, ctx()), 'windows11'), /Still affected/);
  const missing = renderCase(
    ubuntuCase([], { ubuntu: { checked: NOW, notPublished: 'Ubuntu has not published a tracker entry.' } }),
    ctx(),
  );
  assert.match(rowHTML(missing, 'ubuntu2404'), /No data<\/span><small>Ubuntu has not published this CVE yet<\/small>/);
});

test('notes: first two shown, the rest unfold; vendor text is escaped', () => {
  const notes = ['<b>one</b>', 'two', 'three', 'four'];
  const html = renderCase(ubuntuCase(notes.map((n, i) => ubuntuEntry(`pkg${i}`, 'affected', { note: n }))), ctx());
  const row = rowHTML(html, 'ubuntu2404');
  assert.match(row, /<small>pkg0: &lt;b&gt;one&lt;\/b&gt;<\/small><small>pkg1: two<\/small>/);
  assert.match(
    row,
    /<details class="advisory-list" data-detail="ubuntu2404:notes"><summary aria-label="Show 2 more notes">\+2 more<\/summary><div><span>pkg2: three<\/span><span>pkg3: four<\/span><\/div><\/details>/,
  );
  assert.doesNotMatch(row, /<b>one/);
});

test('SLES rows and the SUSE source card list SUSE-SU updates, not Liberty Linux RHSA advisories', () => {
  const suse = (n) => ({
    url: `https://www.suse.com/support/update/announcement/2026/suse-su-2026000${n}-1/`,
    label: `SUSE-SU-2026:000${n}-1`,
  });
  const sles = {
    ...structuredClone(c),
    products: ['sles15'],
    vendorData: {
      id: ID,
      evidence: {
        sles15: [
          {
            name: 'kernel-default-5.14.21-150500.55.49.1 as component of SUSE Linux Enterprise Server 15 SP5',
            status: 'fixed',
            fix: ['kernel-default-5.14.21-150500.55.49.1 as component of SUSE Linux Enterprise Server 15 SP5'],
            affected: [],
            unaffected: [],
            mitigation: [],
            links: [],
            source: 'SUSE CSAF',
          },
        ],
      },
      sources: {
        sles: {
          checked: NOW,
          url: 'https://ftp.suse.com/pub/projects/security/csaf-vex/2024/cve-2024-1086.json',
          advisories: [
            { url: 'https://access.redhat.com/errata/RHSA-2026:93412', label: 'RHSA-2026:93412' },
            suse(1),
            suse(2),
            suse(3),
            { url: 'javascript:alert(1)', label: 'SUSE-SU-2026:0004-1' },
          ],
        },
      },
    },
  };
  const html = renderCase(sles, ctx());
  const row = rowHTML(html, 'sles15');
  assert.match(
    row,
    /SUSE advisories \(all products\): <a [^>]*>SUSE-SU-2026:0001-1 ↗<\/a>, <a [^>]*>SUSE-SU-2026:0002-1 ↗<\/a>/,
  );
  assert.match(row, /aria-label="Show 1 more advisory">\+1<\/summary><div><a [^>]*>SUSE-SU-2026:0003-1 ↗<\/a><\/div>/);
  assert.match(
    row,
    /<\/details><a href="https:\/\/www\.suse\.com\/security\/cve\/CVE-2024-1086\.html" [^>]*>SUSE CVE page ↗<\/a><\/div>/,
  );
  assert.doesNotMatch(row, /RHSA|javascript:/);
  const card = html.match(/<article class="source-card[^"]*"><header><h3>SUSE[\s\S]*?<\/article>/)[0];
  assert.match(card, /SUSE security updates in source document \(4\)/);
  assert.match(card, /Not listed \(not SUSE Linux Enterprise updates\): 1 RHSA advisory for SUSE Liberty Linux\./);
  assert.doesNotMatch(card, />RHSA-2026:93412/);
  assert.doesNotMatch(card, /href="javascript/);
});
