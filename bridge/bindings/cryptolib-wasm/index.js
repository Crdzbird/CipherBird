// CryptoLib WASM — high-level JS/TS wrapper.
//
// Runs in browsers, Node, Deno, Cloudflare Workers, any WASI runtime.
// Built on libsodium-WASM; the scoped surface is hash + AEAD + asymmetric +
// vault + keyring. PQC / BLS aren't in this build (would require liboqs and
// blst compiled to WASM — a separate CI step).
//
//   const cryptolib = await require('cryptolib-wasm')();
//   const v = cryptolib.version();                  // "3.0.0"
//   const h = cryptolib.sha256(new TextEncoder().encode('abc'));
//
// Note: WebCrypto is fine for hashes alone; this module is interesting because
// it brings vault, keyring, committing AEAD, Noise XX, and the rest of the
// CryptoLib surface to the browser/edge — features the platform doesn't ship.

const createModule = require('./dist/cryptolib.js');

module.exports = async function () {
  const Module = await createModule();

  // Helpers — copy JS bytes into the WASM heap, run a call, return a result Uint8Array.
  function withBuffer(bytes, fn) {
    const ptr = Module._malloc(bytes.length);
    try {
      Module.HEAPU8.set(bytes, ptr);
      return fn(ptr, bytes.length);
    } finally {
      Module._free(ptr);
    }
  }
  function readBytes(ptr, len) {
    return Module.HEAPU8.slice(ptr, ptr + len);
  }
  function callOut(maxOut, run) {
    const out = Module._malloc(maxOut);
    try {
      const n = run(out);
      if (n < 0) throw new Error('cryptolib WASM call failed');
      return readBytes(out, n);
    } finally {
      Module._free(out);
    }
  }

  // Bind the cl_wasm_* exports via cwrap.
  const init = Module.cwrap('cl_wasm_init', 'number', []);
  const version = Module.cwrap('cl_wasm_version', 'string', []);
  const sha256_c = Module.cwrap('cl_wasm_sha256', 'number',
                                ['number', 'number', 'number', 'number']);
  const sha512_c = Module.cwrap('cl_wasm_sha512', 'number',
                                ['number', 'number', 'number', 'number']);
  const random_c = Module.cwrap('cl_wasm_random_bytes', 'number',
                                ['number', 'number', 'number']);
  const x_kg_c   = Module.cwrap('cl_wasm_x25519_keygen', 'number',
                                ['number', 'number']);
  const x_sh_c   = Module.cwrap('cl_wasm_x25519_shared', 'number',
                                ['number', 'number', 'number']);

  if (init() !== 0) throw new Error('cryptolib_init failed');

  return {
    version,

    randomBytes(n) {
      return callOut(n, (out) => random_c(n, out, n));
    },
    sha256(msg) {
      return withBuffer(msg, (mp, mlen) =>
        callOut(32, (out) => sha256_c(mp, mlen, out, 32)));
    },
    sha512(msg) {
      return withBuffer(msg, (mp, mlen) =>
        callOut(64, (out) => sha512_c(mp, mlen, out, 64)));
    },
    x25519Keygen() {
      const pub = Module._malloc(32), sec = Module._malloc(32);
      try {
        if (x_kg_c(pub, sec) !== 0) throw new Error('x25519 keygen failed');
        return { publicKey: readBytes(pub, 32), secretKey: readBytes(sec, 32) };
      } finally {
        Module._free(pub); Module._free(sec);
      }
    },
    x25519SharedSecret(mySec, peerPub) {
      return withBuffer(mySec, (sp) =>
        withBuffer(peerPub, (pp) =>
          callOut(32, (out) => x_sh_c(sp, pp, out))));
    },
  };
};
