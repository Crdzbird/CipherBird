import { loadEngine } from '../load.js';
import { hex, base64, utf8, flipBit, preview } from '../bytes.js';
import { el, renderDemo, runWhenSeen } from '../ui/render.js';
import { groupFunctions } from '../areas.js';
import { EngineError } from '../engine.js';
import chapters from '../chapters/index.js';
import { enterOnScroll } from '../ui/motion.js';

const ready = loadEngine();
const $ = (id) => document.getElementById(id);

function setText(id, text) {
  $(id).textContent = text;
}

async function selfCheck() {
  try {
    const { engine, cb, wasm, integrity, loadMs } = await ready;
    setText('sc-version', `version ${cb.call('version')}`);
    setText('sc-size', `${wasm.length.toLocaleString('en-US')} bytes`);
    setText('sc-attested', integrity.wasm.replace(/^sha384-/, ''));
    $('sc-integrity').replaceChildren(el('span', { class: 'badge' }, 'matches, checked before start'));
    setText('sc-functions', `${engine.abi.functions.length} exported through the C ABI`);
    const page = new Uint8Array(await (await fetch(location.href, { cache: 'force-cache' })).arrayBuffer());
    const hashAll = () => {
      const start = performance.now();
      const digest = cb.call('blake3', wasm, 32);
      const pageDigest = cb.call('sha256', page);
      const ms = performance.now() - start;
      setText('sc-blake3', hex(digest));
      setText('sc-page', hex(pageDigest));
      return ms;
    };
    const first = hashAll();
    setText('sc-time', `Loaded in ${loadMs.toFixed(0)} ms, hashed ${(wasm.length / 1e6).toFixed(1)} MB in ${first.toFixed(1)} ms`);
    $('sc-again').addEventListener('click', () => {
      setText('sc-time', `Hashed again in ${hashAll().toFixed(1)} ms`);
    });
  } catch (error) {
    $('sc-integrity').replaceChildren(el('span', { class: 'badge is-bad' }, 'failed'));
    setText('sc-time', String(error.message || error));
  }
}

function answerRow(label, value, code = false) {
  return el('li', {}, el('span', {}, label), code ? el('code', {}, value) : el('span', {}, value));
}

async function showcase() {
  const input = $('type-line');
  const answer = $('answer');
  const { cb } = await ready;
  const tier = 0;
  const recipient = cb.call('sealed_generate_recipient', tier);
  const sender = cb.call('sealed_generate_sender', tier);
  const aad = utf8.encode('cipherbird.site/showcase');
  const purpose = utf8.encode('message');
  let timer = null;
  const update = () => {
    const message = input.value;
    const start = performance.now();
    const envelope = cb.call('sealed_seal', tier, message, recipient.public_key, sender.secret_key, aad, purpose);
    const sealMs = performance.now() - start;
    const opened = utf8.decode(cb.call('sealed_open', tier, envelope, recipient.secret_key, recipient.public_key, sender.public_key, aad, purpose));
    let refusal = 'accepted';
    try {
      cb.call('sealed_open', tier, flipBit(envelope, -1), recipient.secret_key, recipient.public_key, sender.public_key, aad, purpose);
    } catch (error) {
      refusal = error instanceof EngineError ? `refused: ${error.message}` : String(error);
    }
    answer.replaceChildren(
      answerRow('BLAKE3', hex(cb.call('blake3', message, 32)), true),
      answerRow('Sealed envelope', `${envelope.length.toLocaleString('en-US')} bytes, ${preview(envelope, 10)}`),
      answerRow('Protected by', 'X25519 with sntrup761 for the key, Ed25519 with ML-DSA-65 for the signature'),
      answerRow('Recipient opens', opened || '(empty)'),
      answerRow('One bit flipped in flight', refusal),
      answerRow('Time', `sealed in ${sealMs.toFixed(1)} ms`),
    );
  };
  update();
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(update, 120);
  });
  document.querySelectorAll('.examples button').forEach((button) => {
    button.addEventListener('click', () => {
      input.value = button.textContent;
      update();
      input.focus();
    });
  });
}

const CELLS = [
  { chapter: 'threshold', demo: 'frost-sign', title: 'Two of three can sign', text: 'FROST splits one Ed25519 key into shares. Any two holders sign together, and the result is an ordinary signature.' },
  { chapter: 'bbs', demo: 'disclosure', title: 'Prove two facts, hide three', text: 'A BBS credential signs five attributes. The holder reveals two, and each proof is unlinkable to the last.' },
  { chapter: 'oprf-opaque', demo: 'opaque-login', title: 'Log in without a password', text: 'OPAQUE agrees a session key from a password the server never receives, not even at registration.' },
  { chapter: 'channels', demo: 'noise-handshake', title: 'Agree on a private channel', text: 'A Noise XX handshake between two parties in this page: three messages, one shared hash, mutual keys.' },
  { chapter: 'post-quantum', demo: 'sizes', title: 'Post-quantum, measured', text: 'Key, ciphertext and signature sizes of ML-KEM, ML-DSA, SLH-DSA, X-Wing and the hybrids, measured just now.' },
  { chapter: 'stego', demo: 'hide', title: 'A message inside a picture', text: 'Steganography hides an encrypted payload in an image, and only the right key finds it again.' },
];

function features() {
  const byId = new Map(chapters.map((c) => [c.id, c]));
  const nodes = [];
  CELLS.forEach((cell, i) => {
    const chapter = byId.get(cell.chapter);
    const demo = chapter && (chapter.demos.find((d) => d.id === cell.demo) || chapter.demos[0]);
    if (!demo) return;
    const fragment = renderDemo(demo, ready, { compact: true });
    nodes.push(fragment);
    const row = Math.floor(i / 3);
    const flipped = (i % 2 === 1) !== (row % 2 === 1);
    $('cells').append(el('article', { class: `cell${flipped ? ' is-flipped' : ''}` },
      el('div', { class: 'cell-text' }, el('h3', {}, cell.title), el('p', {}, cell.text),
        el('a', { href: `tour.html#${chapter.id}` }, 'Open it in the tour')),
      el('div', { class: 'fragment' }, fragment)));
  });
  runWhenSeen(nodes);
}

async function how() {
  const { cb } = await ready;
  const message = 'meet at dawn';
  const digest = cb.call('blake3', message, 32);
  $('how-1').append(el('ol', { class: 'ui-rows' },
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, 'r.buf, 32 bytes'), el('code', { class: 'ui-hex' }, hex(digest)))));
  const key = cb.call('random_bytes', 32);
  const aad = utf8.encode('thread 7');
  const box = cb.call('committing_encrypt', message, key, aad);
  const boxText = base64(box);
  $('how-2').append(el('ol', { class: 'ui-rows' },
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, `box, ${box.length} bytes before base64`), el('code', { class: 'ui-hex' }, boxText)),
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, 'key.hex'), el('code', { class: 'ui-hex' }, hex(key)))));
  const opened = utf8.decode(cb.call('committing_decrypt', box, key, aad));
  const refuse = (fn) => {
    try {
      fn();
      return 'accepted';
    } catch (error) {
      return `refused: ${error.message}`;
    }
  };
  const forged = refuse(() => cb.call('committing_decrypt', flipBit(box, 40), key, aad));
  const otherKey = refuse(() => cb.call('committing_decrypt', box, cb.call('random_bytes', 32), aad));
  const otherThread = refuse(() => cb.call('committing_decrypt', box, key, utf8.encode('thread 8')));
  $('how-3').append(el('ol', { class: 'ui-rows' },
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, 'decryptText(box)'), el('span', { class: 'ui-value' }, `'${opened}'`)),
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, 'One bit of the box flipped'), el('span', { class: 'ui-value' }, forged)),
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, 'Another key'), el('span', { class: 'ui-value' }, otherKey)),
    el('li', { class: 'ui-row' }, el('span', { class: 'ui-label' }, "aad: 'thread 8'"), el('span', { class: 'ui-value' }, otherThread))));
}

async function catalogue() {
  const abi = await (await fetch(new URL('../abi.json', import.meta.url))).json();
  const groups = groupFunctions(abi);
  const tabs = $('tabs');
  const bands = $('bands');
  const show = (group) => {
    for (const b of tabs.children) b.setAttribute('aria-selected', String(b.dataset.id === group.id));
    bands.replaceChildren(...group.fns.map((fn) => el('li', {},
      el('code', {}, fn.short),
      el('span', { class: 'doc' }, fn.doc ? (fn.doc.length > 150 ? `${fn.doc.slice(0, 147)}...` : fn.doc) : 'Frees what the engine allocated.'),
      el('a', { href: `explorer.html#${fn.short}` }, 'Call it'))));
  };
  for (const group of groups) {
    tabs.append(el('button', { type: 'button', role: 'tab', 'data-id': group.id, onclick: () => show(group) },
      group.title, el('span', {}, `${group.fns.length} functions`)));
  }
  show(groups[0]);
}

const FAQ = [
  ['Is this the real library?', 'Yes. The page loads cipherbird.wasm, the same engine the Flutter and Dart packages ship for the web, built by CI and checked against its recorded SHA-384 digest before it starts.'],
  ['Does anything leave my browser?', 'No. There is no server behind this site. Keys, messages and pictures stay in this tab and are gone when you close it.'],
  ['Which parts are post-quantum?', 'ML-KEM, ML-DSA and SLH-DSA from FIPS 203, 204 and 205, sntrup761, X-Wing, and hybrids that pair each with X25519 or Ed25519, so a break of either half alone is not enough.'],
  ['Which languages can call it?', 'C and C++ directly, and bindings for Dart and Flutter, Go, Swift, Java, Kotlin, Python, Ruby, Rust, .NET and JavaScript, all over the same C ABI.'],
  ['Can I use it in production?', 'Read SECURITY.md and the assessment notes in the repository first. The engine wraps vetted implementations such as libsodium, liboqs, OpenSSL and blst rather than writing its own primitives.'],
  ['What does not run here?', 'Anything that needs the operating system: hardware keys, the OpenSSL FIPS provider and P-256 are not in the browser build. The tour says so wherever it applies.'],
  ['Why is the engine 3 MB?', 'It carries libsodium, liboqs, OpenSSL libcrypto, blst, BLAKE3 and secp256k1, so every scheme on this site works offline once it has loaded.'],
];

function faq() {
  const list = $('faq');
  const pane = $('faq-pane');
  const buttons = [];
  const select = (index) => {
    buttons.forEach((b, i) => {
      b.setAttribute('aria-expanded', String(i === index));
      b.nextElementSibling.hidden = i !== index;
    });
    pane.classList.add('is-swapping');
    setTimeout(() => {
      pane.textContent = FAQ[index][1];
      pane.classList.remove('is-swapping');
    }, 150);
  };
  FAQ.forEach(([q, a], i) => {
    const button = el('button', { type: 'button', 'aria-expanded': 'false', onclick: () => select(i), onmouseenter: () => {
      if (matchMedia('(hover: hover)').matches) select(i);
    }, onfocus: () => select(i) }, q);
    buttons.push(button);
    list.append(el('li', {}, button, el('p', { class: 'inline-answer', hidden: true }, a)));
  });
  pane.textContent = FAQ[0][1];
  select(0);
}

selfCheck();
showcase();
features();
how();
catalogue();
faq();
enterOnScroll();
