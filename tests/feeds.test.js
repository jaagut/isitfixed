import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { PRODUCTS, migrateProducts, assess, assessmentStatus } from '../src/data.js';
import { parseUbuntu, parseAlpine, parseDebian } from '../src/feeds.js';
test('old selections drop runtimes and migrate Windows to explicit versions', () => {
  assert.deepEqual(migrateProducts(['rhel9', 'python', 'php', 'debian12']), ['rhel9', 'debian12']);
  assert.deepEqual(migrateProducts(['windows']), ['windows10', 'windows11', 'server2022', 'server2025']);
  assert.ok(PRODUCTS.some((p) => p.family === 'ubuntu'));
  assert.ok(PRODUCTS.some((p) => p.family === 'alpine'));
});
test('Ubuntu pending versions are not labeled published fixes', () => {
  const p = PRODUCTS.find((p) => p.id === 'ubuntu2404');
  const entries = parseUbuntu(
    {
      packages: [
        {
          name: 'linux',
          statuses: [
            { release_codename: 'noble', status: 'pending', description: '6.8.0-149' },
            { release_codename: 'jammy', status: 'released', description: '5.15.0-203' },
          ],
        },
      ],
    },
    p,
  );
  assert.equal(entries.length, 1);
  assert.equal(entries[0].status, 'affected');
  assert.deepEqual(entries[0].fix, []);
  assert.match(entries[0].note, /pending/);
});
test('Alpine fix-only feed cannot establish unaffected status from absence', () => {
  const d = { packages: [{ pkg: { name: 'linux-lts', secfixes: { '6.12.1-r0': ['CVE-2026-1234'] } } }] };
  assert.deepEqual(parseAlpine(d, 'CVE-2026-98432'), []);
  assert.equal(parseAlpine(d, 'CVE-2026-1234')[0].status, 'fixed');
});
test('Debian distinguishes fixes from explicit not-affected (version 0)', () => {
  const p = PRODUCTS.find((p) => p.id === 'debian12');
  const entries = parseDebian(
    {
      linux: { 'CVE-2026-1234': { releases: { bookworm: { status: 'resolved', fixed_version: '6.1.2' } } } },
      other: { 'CVE-2026-1234': { releases: { bookworm: { status: 'resolved', fixed_version: '0' } } } },
    },
    'CVE-2026-1234',
    p,
  );
  assert.equal(entries[0].status, 'fixed');
  assert.equal(entries[1].status, 'unaffected');
  assert.deepEqual(entries[1].fix, []);
});
test('real vendor snapshot includes reported RHEL 9 fix and advisory', async () => {
  const snapshot = JSON.parse(await readFile(new URL('./fixtures/vendor-CVE-2026-98432.json', import.meta.url)));
  assert.ok(
    snapshot.evidence.rhel9.some(
      (e) =>
        e.fix.some((v) => v.includes('5.14.0-687.64.1.el9_8')) &&
        e.links.includes('https://access.redhat.com/errata/RHSA-2026:93412'),
    ),
  );
  assert.ok(!snapshot.evidence.rhel10.some((e) => e.fix.some((v) => v.includes('5.14.0-687.64.1.el9_8'))));
  const rhel = assess(
    { cveMetadata: { cveId: snapshot.id } },
    PRODUCTS.find((p) => p.id === 'rhel9'),
    null,
    snapshot,
  );
  assert.equal(rhel.status, 'affected');
  assert.equal(assessmentStatus(rhel), 'fix_available');
  assert.equal(assessmentStatus({ status: 'affected', fixAvailable: false }), 'affected');
  assert.equal(
    assess(
      { cveMetadata: { cveId: snapshot.id } },
      PRODUCTS.find((p) => p.id === 'alpine322'),
      null,
      snapshot,
    ).status,
    'unknown',
  );
});
