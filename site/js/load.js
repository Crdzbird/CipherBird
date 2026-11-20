import { Engine } from './engine.js';
import { demoContext } from './context.js';

const base = new URL('../engine/', import.meta.url);
let pending = null;

function loadScript(src, integrity) {
  return new Promise((resolve, reject) => {
    const tag = document.createElement('script');
    tag.src = src;
    tag.integrity = integrity;
    tag.crossOrigin = 'anonymous';
    tag.onload = resolve;
    tag.onerror = () => reject(new Error('the engine script did not load or failed its integrity check'));
    document.head.append(tag);
  });
}

async function start() {
  const began = performance.now();
  const integrity = await (await fetch(new URL('integrity.json', base))).json();
  const abi = await (await fetch(new URL('./abi.json', import.meta.url))).json();
  await loadScript(new URL('cipherbird.js', base).href, integrity.engine);
  const response = await fetch(new URL('cipherbird.wasm', base), { integrity: integrity.wasm });
  const wasm = new Uint8Array(await response.arrayBuffer());
  const module = await self.createCipherBird({ wasmBinary: wasm });
  const engine = new Engine(module, abi);
  return {
    engine,
    cb: demoContext(engine),
    wasm,
    integrity,
    loadMs: performance.now() - began,
  };
}

/** Loads the engine once per page, verified against its attested digests. */
export function loadEngine() {
  if (!pending) pending = start();
  return pending;
}
