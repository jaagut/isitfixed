import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchCase, syncWatches, ping, connection, onConnectionChange } from '../src/api.js';
test('case refresh uses only the API, including selected vendor families and force flag', async () => {
  const original = globalThis.fetch,
    calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ url, options });
      return Response.json({ id: 'CVE-2026-98432', vendorData: { id: 'CVE-2026-98432' } });
    };
    await fetchCase('CVE-2026-98432', ['sles15', 'rhel9', 'sles16', 'windows11'], true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/api/cves/CVE-2026-98432?families=rhel%2Csles&refresh=true');
  } finally {
    globalThis.fetch = original;
  }
});
test('watch sync sends case IDs and vendor choices without private notes or snapshots', async () => {
  const original = globalThis.fetch;
  let sent;
  try {
    globalThis.fetch = async (url, options) => {
      sent = { url, options };
      return Response.json({ watched: 1 });
    };
    await syncWatches([
      { id: 'CVE-2026-98432', products: ['rhel9'], notes: 'Private incident notes', record: { secret: 'internal' } },
    ]);
    assert.equal(sent.options.method, 'PUT');
    assert.deepEqual(JSON.parse(sent.options.body), { cases: [{ id: 'CVE-2026-98432', families: ['rhel'] }] });
  } finally {
    globalThis.fetch = original;
  }
});
test('API failures and wrong CVE IDs are errors, without vendor proxy fallback', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response('backend offline', { status: 503 });
    await assert.rejects(() => fetchCase('CVE-2026-98432', []), /HTTP 503/);
    globalThis.fetch = async () => Response.json({ id: 'CVE-2026-1111', vendorData: { id: 'CVE-2026-1111' } });
    await assert.rejects(() => fetchCase('CVE-2026-98432', []), /mismatched/);
  } finally {
    globalThis.fetch = original;
  }
});
test('progressive case results decode across chunk boundaries', async () => {
  const { streamCase } = await import('../src/api.js');
  const original = globalThis.fetch;
  try {
    const first = { id: 'CVE-2026-98432', vendorData: { id: 'CVE-2026-98432', sources: {} } };
    const last = { ...first, record: { cveMetadata: { cveId: first.id } } };
    const text = JSON.stringify(first) + '\n' + JSON.stringify(last) + '\n',
      encoder = new TextEncoder();
    globalThis.fetch = async () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(encoder.encode(text.slice(0, 20)));
            c.enqueue(encoder.encode(text.slice(20)));
            c.close();
          },
        }),
      );
    const areas = [];
    const result = await streamCase(first.id, [], false, (data) => areas.push(data));
    assert.equal(areas.length, 2);
    assert.deepEqual(result, last);
  } finally {
    globalThis.fetch = original;
  }
});

test('server config: defaults when unavailable, strict types, https-only source link', async () => {
  const { fetchConfig, normalizeConfig, DEFAULT_CONFIG } = await import('../src/api.js');
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      throw TypeError('offline');
    };
    assert.deepEqual(await fetchConfig(), { ...DEFAULT_CONFIG, legal: { imprint: false, privacy: false } });
    globalThis.fetch = async (url) => {
      assert.equal(url, '/api/config');
      return Response.json({
        version: '1.1.0',
        commit: '3077a07c0ffee3077a07c0ffee3077a07c0ffee0',
        manualRefresh: true,
        tmds: false,
        legal: { imprint: true, privacy: 'yes' },
        sourceUrl: 'https://github.com/jaagut/isitfixed',
        retentionDays: 10,
      });
    };
    assert.deepEqual(await fetchConfig(), {
      version: '1.1.0',
      commit: '3077a07c0ffee3077a07c0ffee3077a07c0ffee0',
      manualRefresh: true,
      tmds: false,
      legal: { imprint: true, privacy: false },
      sourceUrl: 'https://github.com/jaagut/isitfixed',
      retentionDays: 10,
    });
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(normalizeConfig({ sourceUrl: 'javascript:alert(1)' }).sourceUrl, null);
  assert.equal(normalizeConfig({ manualRefresh: 'true' }).manualRefresh, false);
  assert.equal(normalizeConfig({ commit: '<b>' }).commit, null);
  assert.equal(normalizeConfig({}).tmds, true);
});

test('API errors use the detail text; 429 says when to retry', async () => {
  const { streamCase } = await import('../src/api.js');
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      Response.json({ detail: 'Manual refresh is disabled on this server.' }, { status: 403 });
    await assert.rejects(() => streamCase('CVE-2026-98432', [], true, () => {}), /Manual refresh is disabled/);
    globalThis.fetch = async () =>
      Response.json({ detail: 'Too many lookups.' }, { status: 429, headers: { 'Retry-After': '120' } });
    await assert.rejects(() => fetchCase('CVE-2026-98432', []), /Too many lookups\. Try again in 2 min\./);
  } finally {
    globalThis.fetch = original;
  }
});

test('the connection state counts any answer below 500 as contact, and 5xx or network errors as failures', async () => {
  const original = globalThis.fetch;
  const seen = [];
  onConnectionChange((c) => seen.push(c.lastFailure > c.lastOk ? 'offline' : 'online'));
  try {
    for (const [answer, expected] of [
      [() => Response.json({ status: 'ok' }), 'online'],
      [() => new Response('{}', { status: 503 }), 'offline'],
      [() => new Response('{}', { status: 429 }), 'online'],
      [() => Promise.reject(new TypeError('Failed to fetch')), 'offline'],
    ]) {
      globalThis.fetch = async () => answer();
      await ping();
      assert.equal(seen.at(-1), expected);
      // Same-millisecond answers must still order correctly in the next round.
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.ok(connection.lastOk > 0 && connection.lastFailure > 0);
  } finally {
    globalThis.fetch = original;
  }
});
