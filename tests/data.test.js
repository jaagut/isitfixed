import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assess, assessVex, PRODUCTS, summary, validId, migrateProducts } from '../src/data.js';
const p = PRODUCTS.find((p) => p.id === 'rhel9');
const record = (affected) => ({ cveMetadata: { cveId: 'CVE-2024-3094' }, containers: { cna: { affected } } });
test('missing product is unknown and RHEL major versions stay separate', () => {
  assert.equal(
    assess(record([{ product: 'Red Hat Enterprise Linux 10', defaultStatus: 'unaffected' }]), p).status,
    'unknown',
  );
});
test('explicit unaffected statement is preserved', () => {
  assert.equal(
    assess(record([{ product: 'Red Hat Enterprise Linux 9', defaultStatus: 'unaffected' }]), p).status,
    'unaffected',
  );
});
test('unaffected versions are not inferred to be fixes', () => {
  const a = assess(
    record([
      {
        product: 'Red Hat Enterprise Linux 9',
        versions: [
          { version: '1', lessThan: '2', status: 'affected' },
          { version: '2', status: 'unaffected' },
        ],
      },
    ]),
    p,
  );
  assert.equal(a.status, 'affected');
  assert.deepEqual(a.evidence[0].fix, []);
  assert.deepEqual(a.evidence[0].affected, ['1 to < 2']);
});
test('VEX relationships inherit context; remediations stay product-scoped', () => {
  const vex = {
    product_tree: {
      branches: [{ name: 'Red Hat Enterprise Linux 9', product: { product_id: 'platform', name: 'kernel' } }],
      full_product_names: [{ product_id: 'pkg', name: 'kernel-1.2.3' }],
      relationships: [
        {
          product_reference: 'pkg',
          relates_to_product_reference: 'platform',
          full_product_name: { product_id: 'combined', name: 'fixed kernel' },
        },
      ],
    },
    vulnerabilities: [
      {
        cve: 'CVE-2024-3094',
        product_status: { fixed: ['combined'] },
        remediations: [
          { category: 'mitigation', product_ids: ['combined'], details: 'Disable feature' },
          { category: 'mitigation', product_ids: ['other'], details: 'Unrelated' },
        ],
      },
    ],
  };
  const evidence = assessVex(vex, 'CVE-2024-3094', p);
  const a = { status: evidence[0].status, evidence };
  assert.equal(a.status, 'fixed');
  assert.deepEqual(a.evidence[0].mitigation, ['Disable feature']);
  assert.equal(a.evidence[0].fix.length, 1);
  assert.deepEqual(assessVex(vex, 'CVE-2025-1234', p), []);
});
test('missing metrics and identifiers', () => {
  assert.equal(summary(null).score, undefined);
  assert.equal(validId('CVE-2024-3094'), true);
  assert.equal(validId('CVE-2024-<script>'), false);
});

test('records without a CNA title use a short description sentence, not the record state', () => {
  const record = {
    cveMetadata: { cveId: 'CVE-2025-32463', state: 'PUBLISHED' },
    containers: {
      cna: {
        descriptions: [
          {
            lang: 'en',
            value:
              'Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option. More text.',
          },
        ],
      },
    },
  };
  const { title } = summary(record);
  assert.notEqual(title, 'PUBLISHED');
  assert.ok(title.startsWith('Sudo before 1.9.17p1') && title.length <= 91, title);
  assert.equal(summary({ cveMetadata: { state: 'REJECTED' }, containers: { cna: {} } }).title, 'Rejected CVE');
  assert.equal(summary(undefined).title, 'Awaiting source data');
});

test('end-of-life Debian 11 is not offered and is dropped from saved selections', () => {
  assert.ok(!PRODUCTS.some((p) => p.id === 'debian11'));
  assert.deepEqual(migrateProducts(['debian11', 'debian12']), ['debian12']);
});
import { extractCveIds, groupFixes } from '../src/data.js';
test('CVE IDs are found in any text, case-insensitively', () => {
  assert.deepEqual(extractCveIds('https://access.redhat.com/security/cve/cve-2024-1086'), ['CVE-2024-1086']);
  assert.deepEqual(extractCveIds('see CVE_2023_4863 and cve-2024-1086, CVE-2023-4863'), [
    'CVE-2023-4863',
    'CVE-2024-1086',
  ]);
  assert.deepEqual(extractCveIds('no id here'), []);
});
test('fixed packages are grouped by build', () => {
  const g = groupFixes(['kernel-5.14.0-687.64.1.el9_8', 'kernel-64k-5.14.0-687.64.1.el9_8', 'linux 6.12.113-1']);
  assert.deepEqual(
    g.map((x) => [x.main, x.version, x.packages.length]),
    [
      ['kernel', '5.14.0-687.64.1.el9_8', 2],
      ['linux', '6.12.113-1', 1],
    ],
  );
});
test('Microsoft ranges end at the fixed build; Defender applies to Windows; unlisted Windows is not affected', () => {
  const win = PRODUCTS.find((p) => p.id === 'windows11');
  const ms = (affected) => ({
    cveMetadata: { cveId: 'CVE-2024-21338' },
    containers: { cna: { providerMetadata: { shortName: 'microsoft' }, affected } },
  });
  const a = assess(
    ms([
      {
        product: 'Windows 11 Version 23H2',
        versions: [{ version: '10.0.22631.0', lessThan: '10.0.22631.3155', status: 'affected', versionType: 'custom' }],
      },
    ]),
    win,
  );
  assert.deepEqual(a.evidence[0].fix, ['Windows 11 Version 23H2 10.0.22631.3155']);
  assert.equal(a.fixAvailable, true);
  const d = assess(
    ms([
      {
        product: 'Microsoft Malware Protection Engine',
        versions: [{ version: '1.1.0.0', lessThan: '1.1.26060.3008', status: 'affected' }],
      },
    ]),
    win,
  );
  assert.equal(d.fixAvailable, true);
  assert.match(d.evidence[0].note, /Defender/);
  assert.equal(
    assess(
      ms([
        {
          product: 'Microsoft Outlook 2016',
          versions: [{ version: '16.0.0', lessThan: '16.0.5456', status: 'affected' }],
        },
      ]),
      win,
    ).status,
    'unaffected',
  );
  // Other CNAs: ranges are not treated as fixes.
  assert.deepEqual(
    assess(record([{ product: 'Windows 11', versions: [{ version: '1', lessThan: '2', status: 'affected' }] }]), win)
      .evidence[0].fix,
    [],
  );
});
test('CVSS uses the preferred version and falls back', () => {
  const r = {
    cveMetadata: { cveId: 'CVE-2024-1', datePublished: '2024-01-02T00:00:00' },
    containers: {
      cna: {
        metrics: [
          { cvssV4_0: { baseScore: 9.3, baseSeverity: 'CRITICAL' } },
          { cvssV3_1: { baseScore: 7.8, baseSeverity: 'HIGH' } },
        ],
      },
      adp: [{ metrics: [{ cvssV2_0: { baseScore: 5 } }] }],
    },
  };
  assert.deepEqual([summary(r).score, summary(r).cvssVersion], [7.8, '3.1']);
  assert.deepEqual([summary(r, '4.0').score, summary(r, '4.0').cvssVersion], [9.3, '4.0']);
  assert.deepEqual([summary(r, '2.0').score, summary(r, '2.0').severity], [5, 'MEDIUM']);
  assert.equal(summary(r).published, '2024-01-02T00:00:00');
});
