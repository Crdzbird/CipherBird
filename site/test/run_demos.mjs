import { createRequire } from 'node:module';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { Engine } from '../js/engine.js';
import { demoContext, defaultInputs } from '../js/context.js';

const here = dirname(fileURLToPath(import.meta.url));
const site = join(here, '..');
const repo = join(site, '..');
const engineDir = process.env.CIPHERBIRD_ENGINE_DIR || join(repo, 'bridge/bindings/cipherbird/assets');
const only = process.argv.slice(2);

const require = createRequire(import.meta.url);
const factory = require(join(engineDir, 'cipherbird.js'));
const module = await factory({ wasmBinary: readFileSync(join(engineDir, 'cipherbird.wasm')) });
const abi = JSON.parse(readFileSync(join(site, 'js/abi.json'), 'utf8'));
const engine = new Engine(module, abi);

const exported = new Set(Object.keys(module).filter((k) => k.startsWith('_cbw_cipherbird_')).map((k) => k.slice(5)));
const declared = new Set(abi.functions.map((f) => f.name));
const drift = [...exported].filter((n) => !declared.has(n)).concat([...declared].filter((n) => !exported.has(n)));
if (drift.length) {
  console.error(`abi.json and the engine disagree: ${drift.join(', ')}`);
  process.exit(1);
}

const reached = new Set();
const call = engine.call.bind(engine);
engine.call = (name, ...args) => {
  reached.add(name);
  return call(name, ...args);
};
const cb = demoContext(engine);

const chapterDir = join(site, 'js/chapters');
const files = readdirSync(chapterDir).filter((f) => f.endsWith('.js') && f !== 'index.js').sort();
let failed = 0;
let demos = 0;
let checks = 0;
for (const file of files) {
  const chapter = (await import(pathToFileURL(join(chapterDir, file)).href)).default;
  if (only.length && !only.includes(chapter.id)) continue;
  console.log(`\n${chapter.title}`);
  for (const demo of chapter.demos) {
    demos++;
    const start = performance.now();
    let rows;
    try {
      rows = await demo.run(cb, defaultInputs(demo));
    } catch (error) {
      failed++;
      console.log(`  FAIL ${demo.id}: threw ${error && error.stack ? error.stack : error}`);
      continue;
    }
    const bad = rows.filter((r) => r.kind === 'check' && !r.ok);
    checks += rows.filter((r) => r.kind === 'check').length;
    const ascii = JSON.stringify(rows.filter((r) => r.kind !== 'bytes' && r.kind !== 'image' && r.kind !== 'file')
      .map((r) => [r.label, r.note, r.kind === 'table' ? r.head : null]));
    if (/[^\x00-\x7f]/.test(ascii + demo.title + demo.statement)) {
      failed++;
      console.log(`  FAIL ${demo.id}: non-ASCII text`);
    }
    if (bad.length) {
      failed++;
      for (const r of bad) console.log(`  FAIL ${demo.id}: ${r.label} -> ${r.value}`);
    } else {
      console.log(`  ok   ${demo.id} (${rows.length} rows, ${(performance.now() - start).toFixed(0)} ms)`);
    }
  }
}

const skip = (n) => /_free$/.test(n) || n === 'init';
const all = abi.functions.map((f) => f.name.replace(/^cipherbird_/, '')).filter((n) => !skip(n));
const missing = all.filter((n) => !reached.has(n));
console.log(`\n${demos} demos, ${checks} checks, ${failed} failed`);
console.log(`ABI reached by the demos: ${all.length - missing.length} of ${all.length}`);
if (process.env.SHOW_MISSING) console.log(`not reached: ${missing.join(' ')}`);
if (existsSync(join(site, 'js/chapters/index.js')) && !only.length) {
  const listed = (await import(pathToFileURL(join(chapterDir, 'index.js')).href)).default.map((c) => c.id);
  const ids = [];
  for (const file of files) ids.push((await import(pathToFileURL(join(chapterDir, file)).href)).default.id);
  const unlisted = ids.filter((id) => !listed.includes(id));
  if (unlisted.length) {
    failed++;
    console.log(`chapters missing from index.js: ${unlisted.join(', ')}`);
  }
}
process.exit(failed ? 1 : 0);
