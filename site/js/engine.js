import { utf8, toBytes } from './bytes.js';

/** Thrown when the engine reports an error; message is the engine's text. */
export class EngineError extends Error {
  constructor(fn, message) {
    super(message || 'failed');
    this.name = 'EngineError';
    this.fn = fn;
  }
}

/** An output slot passed in place of a pointer the engine writes to. */
export class Out {
  constructor(kind, capacity) {
    this.kind = kind;
    this.capacity = capacity;
    this.value = undefined;
  }

  /** Room for up to `capacity` bytes; `value` becomes the written bytes. */
  static bytes(capacity) {
    return new Out('bytes', capacity);
  }

  /** Room for an ASCII string of up to `capacity` bytes. */
  static text(capacity) {
    return new Out('text', capacity);
  }

  /** A single scalar (int, size_t or uint8_t) written by the engine. */
  static scalar() {
    return new Out('scalar', 8);
  }

  /** A CryptoBuffer the engine allocates; `value` becomes its bytes. */
  static buffer() {
    return new Out('buffer', 8);
  }
}

const isLenName = (name) => /len$/.test(name);
const PTR_ARRAY = 'const uint8_t* const*';

/** Groups a C parameter list into the arguments a JavaScript caller passes. */
export function argPlan(fn) {
  const plan = [];
  const params = fn.params;
  for (let i = 0; i < params.length; i++) {
    const p = params[i];
    const next = params[i + 1];
    const t = p.ctype;
    if (t === 'const uint8_t*' && next && next.ctype === 'size_t' && isLenName(next.name)) {
      plan.push({ type: 'bytes', name: p.name, params: [i, i + 1] });
      i++;
    } else if (t === PTR_ARRAY && next && next.ctype === 'const size_t*') {
      const counted = params[i + 2] && params[i + 2].ctype === 'size_t';
      plan.push({ type: 'byteList', name: p.name, params: counted ? [i, i + 1, i + 2] : [i, i + 1] });
      i += counted ? 2 : 1;
    } else if (t === 'const uint64_t*' && next && next.ctype === 'size_t') {
      plan.push({ type: 'u64List', name: p.name, params: [i, i + 1] });
      i++;
    } else if (t === 'const uint16_t*') {
      plan.push({ type: 'u16List', name: p.name, params: [i] });
    } else if (t === 'const char**' && next && next.ctype === 'size_t') {
      plan.push({ type: 'textList', name: p.name, params: [i, i + 1] });
      i++;
    } else if (t === 'char**') {
      plan.push({ type: 'error', name: p.name, params: [i], hidden: true });
    } else if ((t === 'uint8_t*' || t === 'char*') && next && next.ctype === 'size_t') {
      const lenOut = params[i + 2] && params[i + 2].ctype === 'size_t*';
      plan.push({ type: t === 'char*' ? 'outText' : 'outBytes', name: p.name,
        params: lenOut ? [i, i + 1, i + 2] : [i, i + 1] });
      i += lenOut ? 2 : 1;
    } else if (t === 'uint8_t*' || t === 'int*' || t === 'size_t*') {
      plan.push({ type: 'outScalar', name: p.name, params: [i] });
    } else if (t === 'CryptoBuffer*') {
      plan.push({ type: 'outBuffer', name: p.name, params: [i] });
    } else if (t === 'const uint8_t*') {
      plan.push({ type: 'fixedBytes', name: p.name, params: [i] });
    } else if (t === 'const char*') {
      plan.push({ type: 'text', name: p.name, params: [i] });
    } else if (/^const Crypto\w+\*$/.test(t)) {
      plan.push({ type: 'structIn', struct: t.slice(6, -1), name: p.name, params: [i] });
    } else if (p.kind === 'u64') {
      plan.push({ type: 'u64', name: p.name, params: [i] });
    } else if (p.kind === 'f64') {
      plan.push({ type: 'f64', name: p.name, params: [i] });
    } else if (p.kind === 'ptr') {
      plan.push({ type: 'handle', name: p.name, ctype: t, params: [i] });
    } else {
      plan.push({ type: 'int', name: p.name, ctype: t, params: [i] });
    }
  }
  return plan;
}

/** The loaded engine: `call` reaches every C ABI function by its short name. */
export class Engine {
  constructor(module, abi) {
    this.module = module;
    this.abi = abi;
    this.fns = new Map(abi.functions.map((f) => [f.name.replace(/^cipherbird_/, ''), f]));
    this.plans = new Map();
    this.calls = 0;
    if (module._cbw_cipherbird_init() !== 0) {
      throw new EngineError('init', 'engine init failed');
    }
  }

  get heap() {
    return this.module.HEAPU8;
  }

  u32(ptr) {
    return new DataView(this.heap.buffer).getUint32(ptr, true);
  }

  cString(ptr) {
    if (!ptr) return null;
    const heap = this.heap;
    let end = ptr;
    while (heap[end]) end++;
    return utf8.decode(heap.subarray(ptr, end));
  }

  /** The argument plan of a function, for documentation and the explorer. */
  plan(short) {
    if (!this.plans.has(short)) {
      const fn = this.fns.get(short);
      if (!fn) throw new EngineError(short, 'no such function');
      this.plans.set(short, argPlan(fn));
    }
    return this.plans.get(short);
  }

  /** Calls cipherbird_<short> with JavaScript values; see argPlan for shapes. */
  call(short, ...args) {
    const fn = this.fns.get(short);
    if (!fn) throw new EngineError(short, 'no such function');
    const plan = this.plan(short);
    const mem = new Scratch(this);
    try {
      const raw = new Array(fn.params.length);
      const after = [];
      let next = 0;
      for (const step of plan) {
        const value = step.hidden ? undefined : args[next++];
        this.place(step, value, raw, mem, after, fn);
      }
      const words = [];
      let retSlot = 0;
      if (fn.retKind === 'struct') {
        retSlot = mem.alloc(this.abi.structs[fn.ret].size);
        words.push(retSlot);
      } else if (fn.retKind === 'u64') {
        retSlot = mem.alloc(8);
        words.push(retSlot);
      }
      fn.params.forEach((p, i) => {
        if (p.kind === 'u64') {
          const big = BigInt(raw[i] ?? 0);
          words.push(Number(big & 0xffffffffn), Number(big >> 32n));
        } else {
          words.push(raw[i] ?? 0);
        }
      });
      this.calls++;
      const result = this.module['_cbw_' + fn.name](...words);
      let value;
      if (fn.retKind === 'struct') value = this.readStruct(fn.ret, retSlot, true);
      else if (fn.retKind === 'u64') value = Number(BigInt(this.u32(retSlot)) | (BigInt(this.u32(retSlot + 4)) << 32n));
      else if (fn.ret === 'const char*') value = this.cString(result);
      else if (fn.retKind === 'ptr') value = result >>> 0;
      else if (fn.retKind === 'i32') value = /size_t|uint/.test(fn.ret) ? result >>> 0 : result;
      for (const finish of after) finish(value);
      return unwrap(short, fn, value);
    } finally {
      mem.release();
    }
  }

  place(step, value, raw, mem, after, fn) {
    const [a, b, c] = step.params;
    switch (step.type) {
      case 'bytes': {
        const bytes = value == null ? null : toBytes(value);
        raw[a] = bytes ? mem.bytes(bytes) : 0;
        raw[b] = bytes ? bytes.length : 0;
        break;
      }
      case 'fixedBytes':
        raw[a] = value == null ? 0 : mem.bytes(toBytes(value));
        break;
      case 'text':
        raw[a] = value == null ? 0 : mem.bytes(utf8.encode(String(value) + '\0'));
        break;
      case 'byteList': {
        const list = (value || []).map(toBytes);
        const ptrs = mem.alloc(Math.max(4, list.length * 4));
        const lens = mem.alloc(Math.max(4, list.length * 4));
        list.forEach((bytes, k) => {
          const p = mem.bytes(bytes);
          const dv = new DataView(this.heap.buffer);
          dv.setUint32(ptrs + k * 4, p, true);
          dv.setUint32(lens + k * 4, bytes.length, true);
        });
        raw[a] = ptrs;
        raw[b] = lens;
        if (c !== undefined) raw[c] = list.length;
        else this.shareCount(fn, step, list.length, raw);
        break;
      }
      case 'u64List': {
        const list = value || [];
        const ptr = mem.alloc(Math.max(8, list.length * 8));
        const dv = new DataView(this.heap.buffer);
        list.forEach((n, k) => dv.setBigUint64(ptr + k * 8, BigInt(n), true));
        raw[a] = ptr;
        raw[b] = list.length;
        break;
      }
      case 'u16List': {
        const list = value || [];
        const ptr = mem.alloc(Math.max(2, list.length * 2));
        const dv = new DataView(this.heap.buffer);
        list.forEach((n, k) => dv.setUint16(ptr + k * 2, n, true));
        raw[a] = ptr;
        break;
      }
      case 'textList': {
        const list = value || [];
        const ptr = mem.alloc(Math.max(4, list.length * 4));
        list.forEach((s, k) => {
          const p = mem.bytes(utf8.encode(String(s) + '\0'));
          new DataView(this.heap.buffer).setUint32(ptr + k * 4, p, true);
        });
        raw[a] = ptr;
        raw[b] = list.length;
        break;
      }
      case 'error': {
        const slot = mem.alloc(4);
        raw[a] = slot;
        after.push(() => {
          const ptr = this.u32(slot);
          if (ptr) {
            const message = this.cString(ptr);
            this.module._cbw_cipherbird_str_free(ptr);
            throw new EngineError(fn.name.replace(/^cipherbird_/, ''), message);
          }
        });
        break;
      }
      case 'outBytes':
      case 'outText': {
        const out = value instanceof Out ? value : Out.bytes(Number(value) || 0);
        const ptr = mem.alloc(Math.max(1, out.capacity));
        raw[a] = ptr;
        raw[b] = out.capacity;
        const lenSlot = c !== undefined ? mem.alloc(4) : 0;
        if (c !== undefined) raw[c] = lenSlot;
        after.push((ret) => {
          const exact = /len$/.test(fn.params[b].name);
          const n = c !== undefined ? this.u32(lenSlot)
            : exact ? out.capacity : Math.min(out.capacity, Number(ret) || 0);
          const bytes = this.heap.slice(ptr, ptr + n);
          out.value = step.type === 'outText' ? utf8.decode(bytes).replace(/\0+$/, '') : bytes;
        });
        break;
      }
      case 'outScalar': {
        const out = value instanceof Out ? value : Out.scalar();
        const slot = mem.alloc(8);
        raw[a] = slot;
        const width = fn.params[a].ctype === 'uint8_t*' ? 1 : 4;
        after.push(() => {
          out.value = width === 1 ? this.heap[slot] : this.u32(slot);
        });
        break;
      }
      case 'outBuffer': {
        const out = value instanceof Out ? value : Out.buffer();
        const slot = mem.alloc(8);
        raw[a] = slot;
        after.push(() => {
          out.value = this.takeBuffer(slot);
        });
        break;
      }
      case 'structIn':
        raw[a] = this.writeStruct(step.struct, value || {}, mem);
        break;
      default:
        raw[a] = value == null ? 0 : value;
    }
  }

  shareCount(fn, step, length, raw) {
    const after = fn.params.findIndex((p, i) => i > step.params[1] && p.ctype === 'size_t' && /count/.test(p.name));
    if (after >= 0) raw[after] = length;
  }

  takeBuffer(ptr) {
    const data = this.u32(ptr);
    const len = this.u32(ptr + 4);
    const bytes = data ? this.heap.slice(data, data + len) : new Uint8Array(0);
    if (data) this.module._cbw_cipherbird_buffer_free(ptr);
    return bytes;
  }

  readStruct(name, ptr, owned) {
    const struct = this.abi.structs[name];
    const out = {};
    const dv = () => new DataView(this.heap.buffer);
    for (const f of struct.fields) {
      const at = ptr + f.offset;
      if (f.ctype === 'CryptoBuffer') {
        out[f.name] = owned ? this.takeBuffer(at) : this.heap.slice(this.u32(at), this.u32(at) + this.u32(at + 4));
      } else if (f.ctype === 'char*') {
        const p = this.u32(at);
        out[f.name] = this.cString(p);
        if (p && owned) this.module._cbw_cipherbird_str_free(p);
      } else if (f.count) {
        out[f.name] = this.heap.slice(at, at + f.size);
      } else if (f.ctype === 'double') {
        out[f.name] = dv().getFloat64(at, true);
      } else if (f.ctype === 'uint64_t') {
        out[f.name] = Number(dv().getBigUint64(at, true));
      } else if (f.size === 1) {
        out[f.name] = this.heap[at];
      } else {
        out[f.name] = f.ctype === 'int' ? dv().getInt32(at, true) : this.u32(at);
      }
    }
    return out;
  }

  writeStruct(name, value, mem) {
    const struct = this.abi.structs[name];
    const ptr = mem.alloc(struct.size);
    for (const f of struct.fields) {
      const at = ptr + f.offset;
      if (f.ctype === 'CryptoBuffer' && value[f.name] != null) {
        const bytes = toBytes(value[f.name]);
        const data = mem.bytes(bytes);
        const dv = new DataView(this.heap.buffer);
        dv.setUint32(at, data, true);
        dv.setUint32(at + 4, bytes.length, true);
      }
    }
    return ptr;
  }

  /** Writes a file into the engine's in-memory file system. */
  writeFile(path, bytes) {
    const dir = path.slice(0, path.lastIndexOf('/'));
    if (dir) this.module.FS.mkdirTree(dir);
    this.module.FS.writeFile(path, toBytes(bytes));
    return path;
  }

  /** Reads a file back from the engine's in-memory file system. */
  readFile(path) {
    return this.module.FS.readFile(path);
  }
}

function unwrap(short, fn, value) {
  if (fn.retKind !== 'struct') return value;
  if (value && typeof value.error === 'string') {
    throw new EngineError(short, value.error);
  }
  if (fn.ret === 'CryptoBufferResult') return value.buf;
  if (fn.ret === 'CryptoResult') return value.ok === 1;
  if (value && 'error' in value) delete value.error;
  return value;
}

class Scratch {
  constructor(engine) {
    this.engine = engine;
    this.blocks = [];
  }

  alloc(size) {
    const ptr = this.engine.module._malloc(Math.max(1, size));
    this.engine.heap.fill(0, ptr, ptr + size);
    this.blocks.push([ptr, size]);
    return ptr;
  }

  bytes(bytes) {
    const ptr = this.alloc(bytes.length);
    this.engine.heap.set(bytes, ptr);
    return ptr;
  }

  release() {
    for (const [ptr, size] of this.blocks) {
      this.engine.heap.fill(0, ptr, ptr + size);
      this.engine.module._free(ptr);
    }
    this.blocks = [];
  }
}
