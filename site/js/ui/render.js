import { hex } from '../bytes.js';
import { EngineError } from '../engine.js';

/** Creates an element with attributes and children. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function byteCount(n) {
  return `${n.toLocaleString('en-US')} byte${n === 1 ? '' : 's'}`;
}

function copyButton(text) {
  const button = el('button', { class: 'ui-copy', type: 'button', text: 'Copy' });
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copied';
    } catch {
      button.textContent = 'Select and copy';
    }
    setTimeout(() => { button.textContent = 'Copy'; }, 1400);
  });
  return button;
}

function bytesValue(bytes) {
  const full = hex(bytes);
  const limit = 96;
  if (full.length <= limit) return el('code', { class: 'ui-hex' }, full);
  const code = el('code', { class: 'ui-hex' }, `${full.slice(0, limit)}...`);
  const more = el('button', { class: 'ui-more', type: 'button', text: 'Show all' });
  more.addEventListener('click', () => {
    const open = more.textContent === 'Show all';
    code.textContent = open ? full : `${full.slice(0, limit)}...`;
    more.textContent = open ? 'Show less' : 'Show all';
  });
  return el('span', { class: 'ui-hexwrap' }, code, more);
}

/** One output row as a list item. */
export function renderRow(r) {
  const label = el('span', { class: 'ui-label' }, r.label);
  const note = r.note ? el('span', { class: 'ui-note' }, r.note) : null;
  switch (r.kind) {
    case 'bytes':
      return el('li', { class: 'ui-row', 'data-ui': '' }, el('div', { class: 'ui-head' }, label,
        el('span', { class: 'ui-meta' }, byteCount(r.value.length)), copyButton(hex(r.value))),
      bytesValue(r.value), note);
    case 'check':
      return el('li', { class: `ui-row ui-check ${r.ok ? 'is-ok' : 'is-bad'}`, 'data-ui': '' },
        el('div', { class: 'ui-head' }, el('span', { class: 'ui-dot', 'aria-hidden': 'true' }), label,
          el('span', { class: 'ui-verdict' }, r.ok ? 'holds' : 'does not hold')),
        r.value ? el('span', { class: 'ui-value' }, r.value) : null, note);
    case 'table':
      return el('li', { class: 'ui-row ui-tablerow', 'data-ui': '' }, label,
        el('div', { class: 'ui-tablewrap' }, el('table', { class: 'ui-table' },
          el('thead', {}, el('tr', {}, r.head.map((h) => el('th', { scope: 'col' }, h)))),
          el('tbody', {}, r.body.map((cells) => el('tr', {}, cells.map((c) => el('td', {}, String(c)))))))), note);
    case 'image': {
      const url = URL.createObjectURL(new Blob([r.value], { type: r.mime }));
      return el('li', { class: 'ui-row', 'data-ui': '' }, label,
        el('img', { class: 'ui-image', src: url, alt: r.label, loading: 'lazy' }), note);
    }
    case 'file': {
      const url = URL.createObjectURL(new Blob([r.value], { type: r.mime || 'application/octet-stream' }));
      return el('li', { class: 'ui-row', 'data-ui': '' }, el('div', { class: 'ui-head' }, label,
        el('span', { class: 'ui-meta' }, byteCount(r.value.length))),
      el('a', { class: 'ui-download', href: url, download: r.name }, `Download ${r.name}`), note);
    }
    default:
      return el('li', { class: 'ui-row', 'data-ui': '' }, el('div', { class: 'ui-head' }, label),
        el('span', { class: 'ui-value' }, r.value), note);
  }
}

function inputField(input, values, onChange) {
  const id = `in-${Math.random().toString(36).slice(2, 9)}`;
  const label = el('label', { for: id, class: 'ui-field-label' }, input.label);
  let control;
  if (input.kind === 'textarea') {
    control = el('textarea', { id, rows: 3 }, input.value ?? '');
    control.addEventListener('input', () => onChange(input.name, control.value));
  } else if (input.kind === 'select') {
    control = el('select', { id }, input.options.map((o) => {
      const [value, text] = Array.isArray(o) ? o : [o, o];
      return el('option', { value, selected: String(value) === String(input.value) }, text);
    }));
    control.addEventListener('change', () => onChange(input.name, control.value));
  } else if (input.kind === 'toggle') {
    control = el('input', { id, type: 'checkbox', checked: Boolean(input.value) });
    control.addEventListener('change', () => onChange(input.name, control.checked));
    return el('div', { class: 'ui-field ui-toggle', 'data-ui': '' }, control, label);
  } else if (input.kind === 'file') {
    control = el('input', { id, type: 'file', accept: input.accept || '' });
    control.addEventListener('change', async () => {
      const file = control.files[0];
      onChange(input.name, file ? { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) } : undefined);
    });
  } else if (input.kind === 'number') {
    control = el('input', { id, type: 'number', value: input.value, min: input.min, max: input.max, step: input.step || 1 });
    control.addEventListener('input', () => onChange(input.name, Number(control.value)));
  } else {
    control = el('input', { id, type: 'text', value: input.value ?? '', spellcheck: 'false', autocomplete: 'off' });
    control.addEventListener('input', () => onChange(input.name, control.value));
  }
  values[input.name] = input.value;
  return el('div', { class: 'ui-field', 'data-ui': '' }, label, control, input.hint ? el('span', { class: 'ui-note' }, input.hint) : null);
}

/** Renders a working demo: its inputs, a run button and its live output. */
export function renderDemo(demo, ready, { compact = false } = {}) {
  const values = {};
  const output = el('ol', { class: 'ui-rows', 'aria-live': 'polite' });
  const status = el('span', { class: 'ui-status' }, 'Waiting for the engine');
  let timer = null;
  let ran = false;

  async function run() {
    ran = true;
    status.textContent = 'Running';
    root.classList.add('is-running');
    await new Promise((resolve) => setTimeout(resolve, 16));
    const { cb } = await ready;
    const start = performance.now();
    try {
      const rows = await demo.run(cb, { ...values });
      output.replaceChildren(...rows.map(renderRow));
      const failed = rows.filter((r) => r.kind === 'check' && !r.ok).length;
      const checks = rows.filter((r) => r.kind === 'check').length;
      status.textContent = `${(performance.now() - start).toFixed(0)} ms${checks ? `, ${checks - failed} of ${checks} checks hold` : ''}`;
    } catch (error) {
      const message = error instanceof EngineError ? `The engine refused: ${error.message}` : String(error && error.message ? error.message : error);
      output.replaceChildren(el('li', { class: 'ui-row ui-check is-bad', 'data-ui': '' }, el('div', { class: 'ui-head' },
        el('span', { class: 'ui-dot', 'aria-hidden': 'true' }), el('span', { class: 'ui-label' }, 'Error')),
      el('span', { class: 'ui-value' }, message)));
      status.textContent = 'Stopped with an error';
    } finally {
      root.classList.remove('is-running');
    }
  }

  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(run, 350);
  };
  const fields = (demo.inputs || []).map((input) => inputField(input, values, (name, value) => {
    values[name] = value;
    schedule();
  }));
  const button = el('button', { class: 'ui-run', type: 'button', onclick: run }, 'Run again');
  const root = el('div', { class: `ui-demo${compact ? ' is-compact' : ''}` },
    fields.length ? el('div', { class: 'ui-fields' }, fields) : null,
    el('div', { class: 'ui-bar' }, button, status),
    output);
  root.run = () => (ran ? Promise.resolve() : run());
  return root;
}

/** Runs each demo the first time it scrolls near the viewport. */
export function runWhenSeen(nodes) {
  if (!('IntersectionObserver' in self)) {
    nodes.forEach((n) => n.run());
    return;
  }
  const seen = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        seen.unobserve(entry.target);
        entry.target.run();
      }
    }
  }, { rootMargin: '400px 0px' });
  nodes.forEach((n) => seen.observe(n));
}
