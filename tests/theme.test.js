import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { THEMES, validTheme } from '../src/cases.js';

test('theme accepts system, light and dark', () => {
  assert.deepEqual(THEMES, ['system', 'light', 'dark']);
  for (const theme of THEMES) assert.equal(validTheme(theme), theme);
  for (const theme of [undefined, null, '', 'Dark', 'sepia', 1, {}]) assert.equal(validTheme(theme), 'system');
});
const script = (await readFile(new URL('../src/theme.js', import.meta.url), 'utf8')).replace(/^import .*;$/m, '');
async function applied(theme, changed) {
  const documentElement = { dataset: {} };
  runInNewContext(script, { document: { documentElement }, loadTheme: () => Promise.resolve(theme) });
  if (changed) documentElement.dataset.theme = changed;
  await Promise.resolve();
  return documentElement.dataset.theme;
}
test('theme applies saved IndexedDB preference without overwriting a newer app choice', async () => {
  assert.equal(await applied('dark'), 'dark');
  assert.equal(await applied('light'), 'light');
  assert.equal(await applied('system'), undefined);
  assert.equal(await applied('dark', 'light'), 'light');
});
