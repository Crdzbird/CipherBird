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

var ops = {
  ready: function () { return true; },
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
