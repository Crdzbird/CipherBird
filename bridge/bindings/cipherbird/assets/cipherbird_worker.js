// Web worker hosting its own copy of the engine for CipherBird jobs. The
// Dart side fetches cipherbird.js and this file with their integrity
// digests, joins them into one blob (so createCipherBird is in scope and
// nothing is imported by URL) and sends the verified .wasm bytes in the
// first message {op: 'init', args: {wasm}}. Messages: {id, op, args};
// replies: {id, result} or {id, error}.
'use strict';

var resolveEngine;
var enginePromise = new Promise(function (resolve) { resolveEngine = resolve; });

function initEngine(args) {
  var bytes = args.wasm;
  var options = {
    instantiateWasm: function (imports, onInstance) {
      WebAssembly.instantiate(bytes, imports).then(function (result) { onInstance(result.instance); });
      return {};
    }
  };
  resolveEngine(createCipherBird(options).then(function (module) {
    if (module._cbw_cryptolib_init() !== 0) {
      throw new Error('cipherbird: engine init failed');
    }
    return module;
  }));
  return enginePromise.then(function () { return true; });
}

// Scratch allocations and their sizes, so release() can wipe them.
var scratch = new Map();

function cString(module, text) {
  var bytes = new TextEncoder().encode(text);
  var ptr = module._malloc(bytes.length + 1);
  module.HEAPU8.set(bytes, ptr);
  module.HEAPU8[ptr + bytes.length] = 0;
  bytes.fill(0);
  scratch.set(ptr, bytes.length + 1);
  return ptr;
}

function cBytes(module, bytes) {
  var view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  var size = view.length === 0 ? 1 : view.length;
  var ptr = module._malloc(size);
  module.HEAPU8.set(view, ptr);
  scratch.set(ptr, size);
  return ptr;
}

// Overwrites a scratch block with zeros, then frees it.
function release(module, ptr) {
  var size = scratch.get(ptr);
  if (size) {
    module.HEAPU8.fill(0, ptr, ptr + size);
    scratch.delete(ptr);
  }
  module._free(ptr);
}

function readCString(module, ptr) {
  var end = ptr;
  while (module.HEAPU8[end] !== 0) { end++; }
  return new TextDecoder().decode(module.HEAPU8.subarray(ptr, end));
}

// Drains a CryptoBufferResult written at out: {data@0, len@4, error@8}.
function takeBuffer(module, out) {
  var data = module.HEAPU32[out >> 2];
  var len = module.HEAPU32[(out + 4) >> 2];
  var error = module.HEAPU32[(out + 8) >> 2];
  if (error !== 0) {
    var message = readCString(module, error);
    module._cbw_cryptolib_str_free(error);
    throw new Error(message);
  }
  var copy = new Uint8Array(len);
  copy.set(module.HEAPU8.subarray(data, data + len));
  module._cbw_cryptolib_buffer_free(out);
  return copy;
}

function split64(value) {
  return [value % 4294967296, Math.floor(value / 4294967296)];
}

// Scratch files for the generic call: written to the worker's in-memory
// file system before the call and removed after it.
var fileCounter = 0;
function fsPath(module, ext) {
  if (fileCounter === 0) { try { module.FS.mkdir('/w'); } catch (e) {} }
  return '/w/' + (fileCounter++) + '.' + ext;
}

// Drains a CryptoKeyPair written at out: {public_key{data,len}@0, secret_key{data,len}@8}.
function takeKeyPair(module, out) {
  var pk = module.HEAPU32[out >> 2], pkLen = module.HEAPU32[(out + 4) >> 2];
  var sk = module.HEAPU32[(out + 8) >> 2], skLen = module.HEAPU32[(out + 12) >> 2];
  if (pk === 0 || sk === 0) { module._cbw_cryptolib_keypair_free(out); throw new Error('key generation failed'); }
  var pkCopy = new Uint8Array(pkLen); pkCopy.set(module.HEAPU8.subarray(pk, pk + pkLen));
  var skCopy = new Uint8Array(skLen); skCopy.set(module.HEAPU8.subarray(sk, sk + skLen));
  module._cbw_cryptolib_keypair_free(out);
  return { pk: pkCopy, sk: skCopy };
}

// Drains a CryptoResult written at out: {ok@0, error@4}.
function takeResult(module, out) {
  var error = module.HEAPU32[(out + 4) >> 2];
  if (error !== 0) {
    var message = readCString(module, error);
    module._cbw_cryptolib_str_free(error);
    throw new Error(message);
  }
  return module.HEAPU32[out >> 2] !== 0;
}

// One engine entry point by symbol. args: [{k: 'bytes'|'str'|'i32'|'u64'|'f64'|'file'|'out', v, ext}];
// ret: 'buffer'|'keypair'|'result'|'int'|'void'. Files written for 'out' come back as bytes.
function genericCall(module, a) {
  var fn = module['_cbw_' + a.symbol];
  if (!fn) { throw new Error('cipherbird: no engine entry point ' + a.symbol); }
  var scratchPtrs = [], paths = [], outPaths = [], argv = [];
  var outSize = { buffer: 12, keypair: 16, result: 8 }[a.ret] || 0;
  var out = outSize ? module._malloc(outSize) : 0;
  if (out) { argv.push(out); }
  try {
    (a.args || []).forEach(function (arg) {
      if (arg.k === 'bytes') {
        var view = arg.v instanceof Uint8Array ? arg.v : new Uint8Array(arg.v);
        var p = cBytes(module, view); scratchPtrs.push(p); argv.push(p, view.length);
      } else if (arg.k === 'str') {
        var sp = cString(module, arg.v); scratchPtrs.push(sp); argv.push(sp);
      } else if (arg.k === 'u64') {
        var pair = split64(arg.v); argv.push(pair[0], pair[1]);
      } else if (arg.k === 'file') {
        var path = fsPath(module, arg.ext);
        module.FS.writeFile(path, arg.v instanceof Uint8Array ? arg.v : new Uint8Array(arg.v));
        paths.push(path); var pp = cString(module, path); scratchPtrs.push(pp); argv.push(pp);
      } else if (arg.k === 'out') {
        var op = fsPath(module, arg.ext);
        paths.push(op); outPaths.push(op); var opp = cString(module, op); scratchPtrs.push(opp); argv.push(opp);
      } else {
        argv.push(arg.v);
      }
    });
    var raw = fn.apply(null, argv);
    var value;
    if (a.ret === 'buffer') { value = takeBuffer(module, out); }
    else if (a.ret === 'keypair') { value = takeKeyPair(module, out); }
    else if (a.ret === 'result') { value = takeResult(module, out); }
    else if (a.ret === 'int') { value = raw; }
    else { value = null; }
    var files = outPaths.map(function (p) {
      var bytes = module.FS.readFile(p); var copy = new Uint8Array(bytes.length); copy.set(bytes); return copy;
    });
    return { value: value, files: files };
  } finally {
    if (out) { module._free(out); }
    scratchPtrs.forEach(function (p) { release(module, p); });
    paths.forEach(function (p) { try { module.FS.unlink(p); } catch (e) {} });
  }
}

var ops = {
  ready: function () { return true; },
  call: genericCall,
  argon2id_derive: function (module, a) {
    var password = cString(module, a.password);
    var salt = cBytes(module, a.salt);
    var out = module._malloc(12);
    var ops64 = split64(a.ops);
    try {
      module._cbw_cryptolib_argon2id_derive(out, password, salt, a.salt.length, a.keyLen, ops64[0], ops64[1], a.mem);
      return takeBuffer(module, out);
    } finally {
      module._free(out); release(module, salt); release(module, password);
    }
  },
  argon2id_hash_str: function (module, a) {
    var password = cString(module, a.password);
    var out = module._malloc(12);
    var ops64 = split64(a.ops);
    try {
      module._cbw_cryptolib_argon2id_hash_str(out, password, ops64[0], ops64[1], a.mem);
      var bytes = takeBuffer(module, out);
      var end = bytes.indexOf(0);
      return new TextDecoder().decode(end < 0 ? bytes : bytes.subarray(0, end));
    } finally {
      module._free(out); release(module, password);
    }
  },
  argon2id_verify_str: function (module, a) {
    var password = cString(module, a.password);
    var phc = cString(module, a.phc);
    try {
      return module._cbw_cryptolib_argon2id_verify_str(password, phc) === 1;
    } finally {
      release(module, phc); release(module, password);
    }
  }
};

self.onmessage = function (event) {
  var message = event.data;
  var job = message.op === 'init'
    ? Promise.resolve().then(function () { return initEngine(message.args || {}); })
    : enginePromise.then(function (module) {
        var handler = ops[message.op];
        if (!handler) { throw new Error('cipherbird: unknown worker op ' + message.op); }
        return handler(module, message.args || {});
      });
  job.then(function (result) {
    self.postMessage({ id: message.id, result: result });
  }, function (error) {
    self.postMessage({ id: message.id, error: String(error && error.message ? error.message : error) });
  });
};
