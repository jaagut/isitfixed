// Production frontend build: minified, content-hashed bundles in dist/ (served by the backend via FRONTEND_DIR).
/* global console */
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'dist');
const bundles = [
  { reference: '/src/app.js', entry: 'src/app.js', name: 'app', format: 'esm' },
  { reference: '/src/theme.js', entry: 'src/theme.js', name: 'theme', format: 'iife' },
  { reference: '/style.css', entry: 'style.css', name: 'style' },
];

await rm(out, { recursive: true, force: true });
await mkdir(path.join(out, 'static'), { recursive: true });

const manifest = {};
for (const bundle of bundles) {
  const result = await build({
    entryPoints: [path.join(root, bundle.entry)],
    bundle: true,
    minify: true,
    target: 'es2022',
    ...(bundle.format ? { format: bundle.format } : {}),
    external: ['/assets/*'],
    legalComments: 'none',
    charset: 'utf8',
    write: false,
    logLevel: 'warning',
  });
  const [file] = result.outputFiles;
  const hash = createHash('sha256').update(file.contents).digest('hex').slice(0, 12);
  const name = `${bundle.name}-${hash}${path.extname(bundle.entry)}`;
  await writeFile(path.join(out, 'static', name), file.contents);
  manifest[bundle.reference] = `/static/${name}`;
}

// Point index.html's three local references at the hashed files; fail loudly if one is missing.
let html = await readFile(path.join(root, 'index.html'), 'utf8');
for (const [reference, hashed] of Object.entries(manifest)) {
  const pattern = new RegExp(`(\\s(?:href|src)=["'])(?:\\.?/)?${reference.slice(1).replace('.', '\\.')}(["'])`, 'g');
  const matches = html.match(pattern)?.length ?? 0;
  if (matches !== 1) throw new Error(`index.html must reference ${reference} exactly once (found ${matches})`);
  html = html.replace(pattern, `$1${hashed}$2`);
}
await writeFile(path.join(out, 'index.html'), html);
await cp(path.join(root, 'assets'), path.join(out, 'assets'), { recursive: true });
await writeFile(path.join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(Object.values(manifest).join('\n'));
