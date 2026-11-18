import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { THEMES, validTheme } from '../src/cases.js';

test('theme setting accepts system, light and dark and falls back to system', () => {
  assert.deepEqual(THEMES, ['system', 'light', 'dark']);
  for (const theme of THEMES) assert.equal(validTheme(theme), theme);
  for (const theme of [undefined, null, '', 'Dark', 'sepia', 1, {}]) assert.equal(validTheme(theme), 'system');
});

// src/theme.js runs before the app module to avoid a flash of the wrong theme.
const script = await readFile(new URL('../src/theme.js', import.meta.url), 'utf8');
function runThemeScript(saved, { throws = false } = {}) {
  const documentElement = { dataset: {} };
  const localStorage = {
    getItem(key) {
      if (throws) throw new Error('SecurityError');
      return key === 'cve-desk-v1' ? saved : null;
    },
  };
  runInNewContext(script, { document: { documentElement }, localStorage, JSON });
  return documentElement.dataset.theme;
}

test('early theme script applies only a saved light or dark theme', () => {
  assert.equal(runThemeScript(JSON.stringify({ theme: 'dark' })), 'dark');
  assert.equal(runThemeScript(JSON.stringify({ theme: 'light' })), 'light');
  assert.equal(runThemeScript(JSON.stringify({ theme: 'system' })), undefined);
  assert.equal(runThemeScript(JSON.stringify({ theme: '"><script>' })), undefined);
  assert.equal(runThemeScript(JSON.stringify({ version: 1 })), undefined);
  assert.equal(runThemeScript(null), undefined);
  assert.equal(runThemeScript('{not json'), undefined);
  assert.equal(runThemeScript('', { throws: true }), undefined);
});
