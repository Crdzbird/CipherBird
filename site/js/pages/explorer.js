import { loadEngine } from '../load.js';
import { el, renderRow } from '../ui/render.js';
import { groupFunctions } from '../areas.js';
import { argPlan, Out, EngineError } from '../engine.js';
import { fromHex, utf8 } from '../bytes.js';
import { row } from '../kit.js';

const ready = loadEngine();
const list = document.getElementById('fn-list');
const main = document.getElementById('fn-main');
const search = document.getElementById('search');
const slots = [];
let abi = null;
let current = null;

const CHAINS = [
  { title: 'Sign and verify', text: 'A fresh Ed25519 key signs a release note, and the signature checks out.', steps: [
    ['ed25519_keygen', []],
    ['ed25519_sign', ['release 1.3.0', '#1.secret_key']],
    ['ed25519_verify', ['release 1.3.0', '#2', '#1.public_key']],
  ] },
  { title: 'Agree on a post-quantum key', text: 'X-Wing encapsulates to a public key; the holder of the secret key recovers the same secret.', steps: [
    ['xwing_keygen', []],
    ['xwing_encapsulate', ['#1.public_key']],
    ['xwing_decapsulate', ['#2.ciphertext', '#1.secret_key']],
  ] },
  { title: 'Hash in pieces', text: 'An incremental BLAKE3 handle takes two pieces and matches the one-shot digest.', steps: [
    ['blake3_hasher_create', ['']],
    ['blake3_hasher_update', ['#1', 'hello ']],
    ['blake3_hasher_update', ['#1', 'world']],
    ['blake3_hasher_finalize', ['#1', '32']],
    ['blake3', ['hello world', '32']],
  ] },
  { title: 'Watch a forgery fail', text: 'XChaCha20-Poly1305 seals with one context and refuses to open under another.', steps: [
    ['sym_keygen', []],
    ['xchacha20_encrypt', ['meet at dawn', '#1', 'thread 7']],
    ['xchacha20_decrypt', ['#2', '#1', 'thread 8']],
  ] },
];

const KIND_HELP = {
  bytes: 'bytes and their length',
  fixedBytes: 'bytes of a fixed size',
  byteList: 'a list of byte strings, one per line',
  u64List: 'a list of integers, comma separated',
  u16List: 'a list of integers, comma separated',
  textList: 'a list of strings, one per line',
  text: 'a string; leave empty for NULL',
  int: 'an integer',
  u64: 'a 64-bit integer',
  f64: 'a number',
  handle: 'a handle from an earlier call',
  structIn: 'a struct from an earlier call',
  outBytes: 'output capacity in bytes',
  outText: 'output capacity in bytes',
  outScalar: 'written by the engine',
  outBuffer: 'written by the engine',
};

function resolve(text) {
  const match = /^\$(\d+)(?:\.(\w+))?$/.exec(text.trim());
  if (!match) return undefined;
  const slot = slots[Number(match[1]) - 1];
  if (!slot) throw new Error(`no result ${text.trim()} yet`);
  return match[2] ? slot.value[match[2]] : slot.value;
}

function parseBytes(text, format) {
  const ref = resolve(text);
  if (ref !== undefined) return ref instanceof Uint8Array ? ref : utf8.encode(String(ref));
  if (text === '') return null;
  return format === 'hex' ? fromHex(text) : utf8.encode(text);
}

function argControl(step) {
  const id = `arg-${step.name}`;
  const label = el('label', { for: id }, el('code', {}, step.name));
  const kind = el('span', { class: 'kind' }, KIND_HELP[step.type] || step.type);
  let control;
  let format = null;
  if (step.type === 'outScalar' || step.type === 'outBuffer') {
    control = el('span', { class: 'kind' }, 'shown with the result');
  } else if (['bytes', 'fixedBytes', 'byteList'].includes(step.type)) {
    control = el('textarea', { id, rows: step.type === 'byteList' ? 4 : 2, placeholder: 'text, hex, or $1 for an earlier result' });
    format = el('select', { 'aria-label': `${step.name} format` }, el('option', { value: 'text' }, 'as text'), el('option', { value: 'hex' }, 'as hex'));
  } else if (step.type === 'textList') {
    control = el('textarea', { id, rows: 3 });
  } else {
    const placeholder = step.type === 'handle' || step.type === 'structIn' ? '$1' : step.type.startsWith('out') ? '4096' : '';
    control = el('input', { id, type: 'text', placeholder, autocomplete: 'off', spellcheck: 'false' });
  }
  const read = () => {
    const raw = control.value ?? '';
    switch (step.type) {
      case 'bytes':
      case 'fixedBytes':
        return parseBytes(raw, format.value);
      case 'byteList':
        return raw.split('\n').filter((l) => l !== '').map((l) => parseBytes(l, format.value));
      case 'u64List':
      case 'u16List':
        return raw.split(',').map((s) => s.trim()).filter(Boolean).map(Number);
      case 'textList':
        return raw.split('\n').filter((l) => l !== '');
      case 'text':
        return raw === '' ? null : (resolve(raw) ?? raw);
      case 'outBytes':
        return Out.bytes(Number(raw) || 4096);
      case 'outText':
        return Out.text(Number(raw) || 4096);
      case 'outScalar':
        return Out.scalar();
      case 'outBuffer':
        return Out.buffer();
      case 'handle':
      case 'structIn': {
        const ref = resolve(raw);
        return ref !== undefined ? ref : Number(raw) || 0;
      }
      case 'u64':
        return raw === '' ? 0 : BigInt(raw);
      default:
        return raw === '' ? 0 : Number(raw);
    }
  };
  const set = (value) => {
    if ('value' in control) control.value = value;
    if (format) format.value = 'text';
  };
  const box = el('div', {}, control, format ? el('div', { class: 'as' }, format) : null);
  return { node: el('div', { class: 'arg' }, el('div', {}, label, el('div', {}, kind)), box), read, set, step };
}

function signature(fn) {
  const params = fn.params.map((p) => `    ${p.ctype} ${p.name}`).join(',\n');
  return `${fn.ret} ${fn.name}(${params ? `\n${params}\n` : 'void'})`;
}

function valueRows(label, value) {
  if (value instanceof Uint8Array) {
    const rows = [row.bytes(label, value)];
    const text = utf8.decode(value);
    if (value.length && /^[\x20-\x7e\n\r\t]+$/.test(text)) rows.push(row.text(`${label} as text`, text));
    return rows;
  }
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => valueRows(`${label}.${k}`, v));
  }
  return [row.text(label, value === undefined ? 'nothing' : String(value))];
}

async function call(fn, controls, output) {
  const { engine } = await ready;
  const short = fn.name.replace(/^cipherbird_/, '');
  try {
    const args = controls.map((c) => c.read());
    const start = performance.now();
    const value = engine.call(short, ...args);
    const ms = performance.now() - start;
    slots.push({ name: short, value });
    const n = slots.length;
    const rows = [row.text(`Result $${n}`, `${short} returned in ${ms.toFixed(2)} ms`), ...valueRows(`$${n}`, value)];
    controls.forEach((c, i) => {
      if (args[i] instanceof Out) rows.push(...valueRows(c.step.name, args[i].value));
    });
    output.replaceChildren(...rows.map(renderRow));
    renderSlots();
  } catch (error) {
    const text = error instanceof EngineError ? `The engine refused: ${error.message}` : String(error.message || error);
    output.replaceChildren(renderRow(row.check('Error', false, text)));
    slots.push({ name: `${short} (refused)`, value: null });
    renderSlots();
  }
}

async function runChain(chain) {
  const base = slots.length;
  for (const [short, values] of chain.steps) {
    const view = show(short);
    values.forEach((v, i) => view.controls[i].set(v.replace(/#(\d+)/g, (m, k) => `$${base + Number(k)}`)));
    await new Promise((resolve) => setTimeout(resolve, 450));
    await call(view.fn, view.controls, view.output);
    await new Promise((resolve) => setTimeout(resolve, 650));
  }
}

function renderSlots() {
  const host = document.getElementById('slots');
  if (!host) return;
  host.replaceChildren(el('span', {}, slots.length ? 'Earlier results:' : 'Results you get are kept here as $1, $2 and so on.'),
    ...slots.map((s, i) => el('button', { type: 'button', title: s.name, onclick: () => navigator.clipboard?.writeText(`$${i + 1}`) }, `$${i + 1} ${s.name}`)));
}

function show(short) {
  const fn = abi.functions.find((f) => f.name === `cipherbird_${short}`) || abi.functions.find((f) => f.name === 'cipherbird_sha256');
  current = fn.name;
  for (const b of list.querySelectorAll('button')) b.setAttribute('aria-current', String(b.dataset.fn === fn.name));
  const plan = argPlan(fn).filter((s) => !s.hidden);
  const controls = plan.map(argControl);
  const output = el('ol', { class: 'ui-rows', 'aria-live': 'polite' });
  const isFree = /_free$/.test(fn.name);
  main.replaceChildren(
    el('h2', {}, fn.name.replace(/^cipherbird_/, '')),
    el('p', { class: 'ui-note' }, fn.doc || 'No description in the header.'),
    el('div', { class: 'signature' }, el('pre', {}, el('code', {}, signature(fn)))),
    ...(isFree ? [el('p', {}, 'The page frees every buffer and string the engine returns, so this function is called for you. Handles are freed by their own _free function with a handle from an earlier call.')] : []),
    controls.length ? el('div', { class: 'args' }, controls.map((c) => c.node)) : el('p', { class: 'ui-note' }, 'This function takes no arguments.'),
    el('div', { class: 'ui-bar' }, el('button', { class: 'ui-run', type: 'button', onclick: () => call(fn, controls, output) }, `Call ${fn.name}`)),
    output,
    el('div', { class: 'slots', id: 'slots' }),
    el('section', { 'aria-label': 'Examples' }, el('h3', { class: 'ui-field-label' }, 'Or run a short chain of calls'),
      el('div', { class: 'chains' }, CHAINS.map((chain) => el('button', { type: 'button', onclick: () => runChain(chain) },
        el('strong', {}, chain.title), chain.text, el('br'), el('code', {}, chain.steps.map(([f]) => f).join(', ')))))));
  renderSlots();
  if (location.hash.slice(1) !== fn.name.replace(/^cipherbird_/, '')) history.replaceState(null, '', `#${fn.name.replace(/^cipherbird_/, '')}`);
  return { fn, controls, output };
}

function renderList(filter = '') {
  const needle = filter.trim().toLowerCase();
  list.replaceChildren();
  for (const group of groupFunctions(abi)) {
    const fns = group.fns.filter((f) => !needle || f.short.includes(needle) || f.doc.toLowerCase().includes(needle));
    if (!fns.length) continue;
    list.append(el('li', { class: 'group' }, `${group.title} (${fns.length})`));
    for (const fn of fns) {
      list.append(el('li', {}, el('button', { type: 'button', 'data-fn': fn.name, 'aria-current': String(fn.name === current), onclick: () => show(fn.short) }, fn.short)));
    }
  }
}

async function start() {
  abi = await (await fetch(new URL('../abi.json', import.meta.url))).json();
  renderList();
  show(location.hash.slice(1) || 'sha256');
  search.addEventListener('input', () => renderList(search.value));
  addEventListener('hashchange', () => {
    if (`cipherbird_${location.hash.slice(1)}` !== current) show(location.hash.slice(1));
  });
  try {
    const { cb, loadMs } = await ready;
    document.getElementById('engine-status').textContent = `Engine ${cb.call('version')} verified and loaded in ${loadMs.toFixed(0)} ms. Byte arguments take text, hex, or an earlier result such as $1 or $1.public_key.`;
  } catch (error) {
    document.getElementById('engine-status').textContent = `The engine did not start: ${error.message}`;
  }
}

start();
