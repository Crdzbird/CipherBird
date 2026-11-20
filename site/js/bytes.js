const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

/** UTF-8 encode and decode. */
export const utf8 = {
  encode: (text) => encoder.encode(text),
  decode: (bytes) => decoder.decode(bytes),
};

/** Bytes from a Uint8Array, an ArrayBuffer, an array of numbers or a UTF-8 string. */
export function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return Uint8Array.from(value);
  if (typeof value === 'string') return encoder.encode(value);
  throw new TypeError('expected bytes or a string');
}

/** Lower-case hex of bytes. */
export function hex(bytes) {
  return Array.from(toBytes(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Bytes from hex; whitespace is ignored. */
export function fromHex(text) {
  const clean = text.replace(/\s+/g, '');
  if (clean.length % 2 || /[^0-9a-f]/i.test(clean)) throw new TypeError('not hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/** Standard base64 of bytes. */
export function base64(bytes) {
  let s = '';
  for (const b of toBytes(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

/** Bytes joined end to end. */
export function concat(...parts) {
  const list = parts.map(toBytes);
  const out = new Uint8Array(list.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of list) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** A copy of bytes with one bit flipped at byte `index` (from the end when negative). */
export function flipBit(bytes, index = -1, bit = 0) {
  const copy = Uint8Array.from(toBytes(bytes));
  const at = index < 0 ? copy.length + index : index;
  copy[at] ^= 1 << bit;
  return copy;
}

/** True when two byte strings are equal. */
export function same(a, b) {
  const x = toBytes(a);
  const y = toBytes(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** A short hex preview: the first and last bytes with the length. */
export function preview(bytes, keep = 12) {
  const h = hex(bytes);
  if (h.length <= keep * 4) return h;
  return `${h.slice(0, keep * 2)}...${h.slice(-keep)}`;
}
