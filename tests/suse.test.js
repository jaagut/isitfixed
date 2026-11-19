import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseSuse, suseURL, suseMetadata } from '../src/feeds.js';
import { assess, assessmentStatus, PRODUCTS } from '../src/data.js';
const id = 'CVE-2026-98432';
const fixture = JSON.parse(await readFile(new URL('./fixtures/suse-cve-2026-98432.json', import.meta.url)));
test('SUSE uses year directories, with pre-2023 CVEs in its initial 2023 partition', () => {
  assert.equal(suseURL(id), 'https://ftp.suse.com/pub/projects/security/csaf-vex/2026/cve-2026-98432.json');
  assert.equal(
    suseURL('CVE-2021-44228'),
    'https://ftp.suse.com/pub/projects/security/csaf-vex/2023/cve-2021-44228.json',
  );
});
test('real SUSE CSAF separates major versions and preserves service-pack context', () => {
  const evidence = parseSuse(fixture, id);
  assert.equal(evidence.sles15.length, 2);
  assert.ok(evidence.sles15.some((e) => e.status === 'affected' && e.name.includes('15 SP7')));
  assert.ok(
    evidence.sles15.some(
      (e) =>
        e.status === 'fixed' &&
        e.fix.some((f) => f.includes('5.14.21-150400.24.246.1')) &&
        e.name.includes('15 SP4-LTSS'),
    ),
  );
  assert.equal(evidence.sles16.length, 1);
  assert.ok(evidence.sles16[0].fix[0].includes('6.12.0-160000.40.1'));
  assert.ok(!evidence.sles15.some((e) => e.name.includes('High Availability')));
  const assessment = assess(
    { cveMetadata: { cveId: id } },
    PRODUCTS.find((p) => p.id === 'sles15'),
    { evidence },
  );
  assert.equal(assessment.status, 'affected');
  assert.equal(assessmentStatus(assessment), 'fix_available');
});
test('recommended alone cannot establish a fix; group-scoped remediations stay scoped', () => {
  const doc = structuredClone(fixture),
    v = doc.vulnerabilities[0];
  v.remediations = [];
  assert.ok(parseSuse(doc, id).sles16.every((e) => e.status === 'unknown' && e.fix.length === 0));
  const pid = v.product_status.recommended.find((p) => p.includes('Server 16.0'));
  doc.product_tree.product_groups = [{ group_id: 'patched', product_ids: [pid] }];
  v.remediations = [{ category: 'vendor_fix', group_ids: ['patched'], details: 'Install the vendor update.' }];
  assert.equal(parseSuse(doc, id).sles16[0].status, 'fixed');
  assert.ok(
    parseSuse(doc, id)
      .sles15.filter((e) => e.status !== 'affected')
      .every((e) => e.status === 'unknown' && e.fix.length === 0),
  );
});
test('source-wide advisory references are preserved separately from product fixes', () => {
  const metadata = suseMetadata(fixture);
  assert.ok(metadata.sourceUpdated);
  assert.ok(metadata.advisories.length);
  assert.ok(metadata.advisories[0].url.startsWith('https://www.suse.com/'));
  assert.deepEqual(parseSuse(fixture, id).sles16[0].links, []);
});
test('wrong CVE or malformed source is rejected instead of becoming safe', () => {
  assert.throws(() => parseSuse(fixture, 'CVE-2026-1111'), /mismatched CVE/);
  assert.throws(() => parseSuse({}, id), /Invalid SUSE/);
});
