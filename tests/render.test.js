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
