import { loadEngine } from '../load.js';
import { el, renderDemo, runWhenSeen } from '../ui/render.js';
import { enterOnScroll } from '../ui/motion.js';
import chapters from '../chapters/index.js';

const engineReady = loadEngine();
const status = document.getElementById('status');
const totals = { runs: 0, checks: 0, held: 0 };

const FIGURES = {
  sealed: {
    src: 'assets/siege-of-paris-1870-1871-pigeon-post.jpg', width: 1600, height: 788,
    alt: 'Both faces of a bronze medal from 1871 for the pigeon post of the siege of Paris: a seated figure releasing a pigeon, and a pigeon flying over a wreath.',
    caption: 'The medal France struck in 1871 for the pigeon post of the siege of Paris.',
  },
};

function recorder(cb, chips, seen) {
  return {
    ...cb,
    call(name, ...args) {
      if (!seen.has(name)) {
        seen.add(name);
        chips.append(el('code', {}, name));
      }
      return cb.call(name, ...args);
    },
  };
}

function countRows(rows) {
  totals.runs++;
  for (const r of rows) {
    if (r.kind !== 'check') continue;
    totals.checks++;
    if (r.ok) totals.held++;
  }
}

function demoBlock(chapter, demo) {
  const chips = el('div', { class: 'fns', 'aria-label': 'Engine functions this demo calls' });
  const seen = new Set();
  const ready = engineReady.then((loaded) => ({ ...loaded, cb: recorder(loaded.cb, chips, seen) }));
  const counted = {
    ...demo,
    async run(cb, input) {
      const rows = await demo.run(cb, input);
      countRows(rows);
      updateStatus();
      return rows;
    },
  };
  const fragment = renderDemo(counted, ready);
  const block = el('article', { class: 'demo', id: `${chapter.id}-${demo.id}` },
    el('div', { class: 'demo-text' }, el('h3', {}, demo.title), el('p', {}, demo.statement), chips),
    fragment);
  return { block, fragment };
}

let loadMs = 0;
function updateStatus() {
  const run = `${totals.runs} demos run, ${totals.held} of ${totals.checks} checks hold`;
  status.textContent = `Engine verified and loaded in ${loadMs.toFixed(0)} ms. ${run}.`;
}

async function runInBackground(fragments) {
  for (const fragment of fragments) {
    await new Promise((resolve) => setTimeout(resolve, 40));
    await fragment.run();
  }
}

function build() {
  const nav = document.getElementById('chapter-nav');
  const host = document.getElementById('chapters');
  const fragments = [];
  for (const chapter of chapters) {
    nav.append(el('li', {}, el('a', { href: `#${chapter.id}`, 'data-id': chapter.id }, chapter.title)));
    const figure = FIGURES[chapter.id];
    const head = el('header', { class: 'chapter-head' },
      el('h2', {}, chapter.title),
      el('p', {}, chapter.lead),
      figure ? el('figure', { class: 'frame-crop' },
        el('img', { src: figure.src, width: figure.width, height: figure.height, alt: figure.alt, loading: 'lazy' }),
        el('figcaption', { class: 'caption' }, figure.caption)) : null);
    const section = el('section', { class: 'chapter', id: chapter.id, 'aria-label': chapter.title }, head);
    for (const demo of chapter.demos) {
      const { block, fragment } = demoBlock(chapter, demo);
      section.append(block);
      fragments.push(fragment);
    }
    host.append(section);
  }
  runWhenSeen(fragments);
  engineReady.then(() => runInBackground(fragments), () => {});
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
}

build();
enterOnScroll();
engineReady.then((loaded) => {
  loadMs = loaded.loadMs;
  updateStatus();
}, (error) => {
  status.textContent = `The engine did not start: ${error.message}`;
});
