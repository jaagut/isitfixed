import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PRODUCTS } from '../src/data.js';
import { rowAssessment, shortFix, packageLabel, listNames } from '../src/rows.js';

const ID = 'CVE-2026-0001';
const product = (id) => PRODUCTS.find((p) => p.id === id);
const entry = (name, status, extra = {}) => ({
  name,
  status,
  affected: status === 'affected' ? [name] : [],
  unaffected: [],
  fix: [],
  mitigation: [],
  links: [],
  source: 'Vendor feed',
  ...extra,
});
const row = (id, evidence, source = { checked: 1 }, record = null) =>
  rowAssessment(
    {
      id: ID,
      record,
      vendorData: { evidence: { [id]: evidence }, sources: { [product(id).family]: source } },
    },
    product(id),
  );

test('shortFix drops the architecture, also before a module stream', () => {
  assert.equal(
    shortFix('nodejs-1:24.22.1-2.module+el8.10.0+25293+7b33a103.x86_64 (nodejs:24)'),
    'nodejs-1:24.22.1-2.module+el8.10.0+25293+7b33a103 (nodejs:24)',
  );
  assert.equal(
    shortFix('kernel-0:5.14.0-427.13.1.el9_4.x86_64 as a component of Red Hat Enterprise Linux BaseOS (v. 9)'),
    'kernel-5.14.0-427.13.1.el9_4',
  );
  assert.equal(shortFix('openssl 3.0.17-1~deb12u3'), 'openssl 3.0.17-1~deb12u3');
});

test('package labels: component suffixes, SUSE product prefixes, module streams and versions', () => {
  assert.equal(packageLabel('lemon as a component of Red Hat Enterprise Linux 8'), 'lemon');
  assert.equal(packageLabel('mingw-sqlite.src as a component of Red Hat Enterprise Linux 8'), 'mingw-sqlite');
  assert.equal(packageLabel('nodejs (nodejs:22) as a component of Red Hat Enterprise Linux 9'), 'nodejs:22');
  assert.equal(packageLabel('SUSE Linux Enterprise Server 15 SP4-TERADATA:libsqlite3-0-32bit'), 'libsqlite3-0-32bit');
  assert.equal(
    packageLabel('libopenssl-1_0_0-devel as component of SUSE Linux Enterprise Server 15 SP1'),
    'libopenssl-1_0_0-devel',
  );
  assert.equal(
    packageLabel('kernel-64kb-5.14.21-150400.24.108.1 as component of SUSE Linux Enterprise Server 15'),
    'kernel-64kb',
  );
  assert.equal(packageLabel('linux-aws-5.11'), 'linux-aws-5.11');
  assert.equal(listNames(['a', 'b', 'c', 'd', 'e']), 'a, b, c +2');
  assert.equal(listNames(['a']), 'a');
});

test('still affected: open entries of a fixed row, without won’t-fix entries; never on Windows', () => {
  const r = row('rhel9', [
    entry('nodejs (nodejs:22) as a component of Red Hat Enterprise Linux 9', 'affected'),
    entry('nodejs (nodejs:22) as a component of Red Hat Enterprise Linux 9', 'affected'),
    entry('sqlite as a component of Red Hat Enterprise Linux 9', 'affected', { note: 'Will not fix' }),
    entry('lemon as a component of Red Hat Enterprise Linux 9', 'affected', { note: 'Out of support scope' }),
    entry('nodejs-1:24.22.1-5.module+el9.8.0+25292+33251f3b.x86_64 (nodejs:24)', 'fixed', {
      fix: ['nodejs-1:24.22.1-5.module+el9.8.0+25292+33251f3b.x86_64 (nodejs:24)'],
    }),
  ]);
  assert.equal(r.status, 'fix_available');
  assert.deepEqual(r.stillAffected, ['nodejs:22']);
  const ubuntu = row('ubuntu2404', [
    entry('linux', 'fixed', { fix: ['linux 6.8.0-100.100'] }),
    entry('linux-hwe-6.11', 'affected', { note: 'Ubuntu will not fix this: end of life, was needed' }),
    entry('linux-azure', 'affected', { note: 'Fix pending in 6.8.0-1052.55; not yet released' }),
  ]);
  assert.deepEqual(ubuntu.stillAffected, ['linux-azure']);
  const debian = row('debian12', [
    entry('linux', 'fixed', { fix: ['linux 6.1.1-1'] }),
    entry('linux-5.10', 'affected', { note: 'Not covered by Debian security support in this release' }),
  ]);
  assert.deepEqual(debian.stillAffected, []);
  const windows = rowAssessment(
    {
      id: ID,
      record: {
        cveMetadata: { cveId: ID },
        containers: {
          cna: {
            providerMetadata: { shortName: 'microsoft' },
            affected: [
              {
                product: 'Windows 11 Version 24H2 for x64-based Systems',
                versions: [{ version: '10.0.0', lessThan: '10.0.26100.4061', status: 'affected' }],
              },
            ],
          },
        },
      },
    },
    product('windows11'),
  );
  assert.equal(windows.status, 'fix_available');
  assert.deepEqual(windows.stillAffected, []);
});

test('notes: named per package, grouped, deduplicated, affected and undecided first', () => {
  const r = row('ubuntu2204', [
    entry('edk2', 'unaffected', { note: 'Not affected: code not compiled' }),
    entry('sqlite3', 'unknown', { note: 'Not yet triaged by Ubuntu' }),
    entry('sqlite', 'unknown', { note: 'Not yet triaged by Ubuntu' }),
    entry('nodejs', 'affected', { note: 'Vulnerable; no fix released yet' }),
    entry('openssl', 'fixed', { fix: ['openssl 3.0.2-0ubuntu1.20'] }),
  ]);
  // Notes of unaffected packages are left out on rows with several packages.
  assert.deepEqual(r.notes, ['sqlite3, sqlite: Not yet triaged by Ubuntu', 'nodejs: Vulnerable; no fix released yet']);
  // One package: the note stands alone; VEX build boilerplate is not a note.
  const single = row('debian13', [
    entry('sqlite3', 'affected', {
      note: 'No security advisory planned (Minor issue); may be fixed in a point release',
    }),
  ]);
  assert.deepEqual(single.notes, ['No security advisory planned (Minor issue); may be fixed in a point release']);
  const suse = row('sles16', [
    entry('kernel-default-6.12.0-160000.5.1 as component of SUSE Linux Enterprise Server 16.0', 'fixed', {
      fix: ['kernel-default-6.12.0-160000.5.1 as component of SUSE Linux Enterprise Server 16.0'],
      note: 'Recommended patched build; vendor-fix remediation published.',
    }),
  ]);
  assert.deepEqual(suse.notes, []);
});

test('explanations name who has not decided and why a row has no data', () => {
  // The vendor note already explains an undecided entry, so the generic line is not added.
  const triage = row('ubuntu2404', [entry('sqlite3', 'unknown', { note: 'Not yet triaged by Ubuntu' })]);
  assert.equal(triage.status, 'inconclusive');
  assert.equal(triage.explanation, '');
  assert.equal(row('ubuntu2404', [entry('sqlite3', 'unknown')]).explanation, 'Ubuntu has not assessed this yet');
  assert.equal(
    row('rhel9', [entry('sqlite', 'unknown', { source: 'Red Hat VEX' })]).explanation,
    'Red Hat has not determined the status yet',
  );
  assert.equal(
    row('rhel9', [], { checked: 1, notPublished: 'Red Hat has not published a document for this CVE yet.' })
      .explanation,
    'Red Hat has not published this CVE yet',
  );
  assert.equal(row('rhel10', []).explanation, 'Not listed by Red Hat for this version');
  assert.equal(row('debian12', []).explanation, 'Not listed by Debian for this version');
  assert.equal(row('alpine322', []).explanation, 'Alpine lists only fixed packages; no fix recorded');
  assert.equal(
    row('sles15', [], { checked: 1, error: 'Vendor source unavailable' }).explanation,
    'Source unavailable; see Sources',
  );
  assert.equal(row('ubuntu2404', [], null).explanation, '', 'nothing fetched yet');
  assert.equal(row('rhel9', [entry('kernel', 'fixed', { fix: ['kernel-1.0-1.el9'] })]).explanation, '');
  assert.equal(
    row('rhel9', [entry('sqlite', 'unknown', { source: undefined })]).explanation,
    'The CVE record leaves the status open',
  );
});

test('SLES rows carry SUSE-SU document advisories only', () => {
  const r = row('sles15', [entry('kernel-default', 'affected')], {
    checked: 1,
    advisories: [
      { url: 'https://access.redhat.com/errata/RHSA-2026:93412', label: 'RHSA-2026:93412' },
      {
        url: 'https://www.suse.com/support/update/announcement/2026/suse-su-20265085-1/',
        label: 'SUSE-SU-2026:5085-1',
      },
      {
        url: 'https://www.suse.com/support/update/announcement/2026/suse-su-20265085-1/',
        label: 'SUSE-SU-2026:5085-1',
      },
      { url: 'https://www.suse.com/support/kb/doc/?id=000000', label: 'TID-CVE-2026-0001' },
    ],
  });
  assert.deepEqual(
    r.documentAdvisories.map((a) => a.label),
    ['SUSE-SU-2026:5085-1'],
  );
  assert.deepEqual(
    row('rhel9', [], { checked: 1, advisories: [{ url: 'https://x.test', label: 'SUSE-SU-1' }] }).documentAdvisories,
    [],
  );
});
