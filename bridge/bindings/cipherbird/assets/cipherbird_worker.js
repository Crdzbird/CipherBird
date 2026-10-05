// Web worker hosting its own copy of the engine for CipherBird jobs.
// Spawned by the Dart side through a blob that sets self.cipherbirdBase to
// the directory holding cipherbird.js and cipherbird.wasm, then imports this
// file. Messages: {id, op, args}; replies: {id, result} or {id, error}.
'use strict';

var base = self.cipherbirdBase || '';
importScripts(base + 'cipherbird.js');

var enginePromise = createCipherBird({ locateFile: function (file) { return base + file; } })
  .then(function (module) {
    if (module._cbw_cryptolib_init() !== 0) {
      throw new Error('cipherbird: engine init failed');
    }
    return module;
  });

function cString(module, text) {
  var bytes = new TextEncoder().encode(text);
  var ptr = module._malloc(bytes.length + 1);
  module.HEAPU8.set(bytes, ptr);
  module.HEAPU8[ptr + bytes.length] = 0;
  return ptr;
}

function cBytes(module, bytes) {
  var view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  var ptr = module._malloc(view.length === 0 ? 1 : view.length);
  module.HEAPU8.set(view, ptr);
  return ptr;
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
      module._free(out); module._free(salt); module._free(password);
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
      module._free(out); module._free(password);
    }
  },
  argon2id_verify_str: function (module, a) {
    var password = cString(module, a.password);
    var phc = cString(module, a.phc);
    try {
      return module._cbw_cryptolib_argon2id_verify_str(password, phc) === 1;
    } finally {
      module._free(phc); module._free(password);
    }
  }
};

self.onmessage = function (event) {
  var message = event.data;
  enginePromise.then(function (module) {
    var handler = ops[message.op];
    if (!handler) { throw new Error('cipherbird: unknown worker op ' + message.op); }
    return handler(module, message.args || {});
  }).then(function (result) {
    self.postMessage({ id: message.id, result: result });
  }, function (error) {
    self.postMessage({ id: message.id, error: String(error && error.message ? error.message : error) });
  });
};
