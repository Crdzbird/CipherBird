import { EngineError } from './engine.js';
import { toBytes } from './bytes.js';

/** Output rows a demo returns; the page renders them and the test runner checks them. */
export const row = {
  /** Bytes shown as hex with their length. */
  bytes: (label, value, note) => ({ kind: 'bytes', label, value: toBytes(value), note }),
  /** Plain text or a number. */
  text: (label, value, note) => ({ kind: 'text', label, value: String(value), note }),
  /** An outcome the library promises; `ok` must be true for the demo to pass. */
  check: (label, ok, value, note) => ({ kind: 'check', label, ok: Boolean(ok), value: String(value ?? ''), note }),
  /** A small table: `head` is a list of column titles, `body` a list of rows. */
  table: (label, head, body, note) => ({ kind: 'table', label, head, body, note }),
  /** A picture the engine produced or read, as encoded bytes with a MIME type. */
  image: (label, value, mime, note) => ({ kind: 'image', label, value: toBytes(value), mime, note }),
  /** A file the visitor can download. */
  file: (label, value, name, mime, note) => ({ kind: 'file', label, value: toBytes(value), name, mime, note }),
};

/** Runs `fn` and reports whether the engine refused it, with the engine's message. */
export function refuses(fn) {
  try {
    const value = fn();
    if (value === false || value === 0) return { refused: true, message: 'returned false' };
    return { refused: false, message: 'accepted', value };
  } catch (error) {
    if (error instanceof EngineError) return { refused: true, message: error.message };
    throw error;
  }
}

/** A check row for an operation that must be refused. */
export function mustRefuse(label, fn, note) {
  const outcome = refuses(fn);
  return row.check(label, outcome.refused, outcome.refused ? `refused: ${outcome.message}` : 'accepted', note);
}

/** Number of differing bits between two equal-length byte strings. */
export function bitDistance(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  let n = 0;
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    let v = x[i] ^ y[i];
    while (v) {
      n += v & 1;
      v >>= 1;
    }
  }
  return n;
}

/** Milliseconds taken by `fn`, with its result. */
export function timed(fn) {
  const start = performance.now();
  const value = fn();
  return { value, ms: performance.now() - start };
}
