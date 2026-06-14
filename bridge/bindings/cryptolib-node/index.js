// CryptoLib for Node.js — koffi FFI bindings.
//
// The native library is bundled in this package under prebuilds/<platform>-<arch>/
// and loaded automatically; consumers never provide a path:
//
//   const crypto = require('cryptolib');
//   crypto.init();
//   crypto.sha256(Buffer.from('abc')).toString('hex');
//
// NOTE for publishing: the bundled binary must be self-contained (statically
// link libsodium / liboqs / blst / OpenSSL) so it runs without those libs
// installed on the consumer's machine. See PUBLISHING.md.

'use strict';
const path = require('node:path');
const koffi = require('koffi');

// ── Resolve the bundled native library for this platform/arch ────────────────
function resolveLibPath() {
  if (process.env.CRYPTOLIB_DYLIB) return process.env.CRYPTOLIB_DYLIB; // dev override
  const ext = process.platform === 'darwin' ? 'dylib'
            : process.platform === 'win32' ? 'dll'
            : 'so';
  const triple = `${process.platform}-${process.arch}`;
  return path.join(__dirname, 'prebuilds', triple, `libcryptolib_c.${ext}`);
}

// ── Lazy native binding ──────────────────────────────────────────────────────
// The native library is loaded on FIRST USE (or warmed early via preload()),
// never at require() time — so importing this module is cheap and never blocks
// the event loop. All public methods are synchronous; the first one to run
// triggers the (memoized) load. No `await` is ever required to call crypto.
let _native = null;
function ensureLoaded() {
  if (_native) return _native;
  const lib = koffi.load(resolveLibPath());

  // Structs (registered once, on first load).
  const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
  const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoPacket', { ciphertext: CryptoBuffer, signature: CryptoBuffer, kdf_salt: CryptoBuffer });
  koffi.struct('CryptoKeyPair', { public_key: CryptoBuffer, secret_key: CryptoBuffer });
  koffi.struct('CryptoAsymBundle', { box_public: CryptoBuffer, box_secret: CryptoBuffer, sign_public: CryptoBuffer, sign_secret: CryptoBuffer });
  koffi.struct('CryptoKemEncapsResult', { ciphertext: CryptoBuffer, shared_secret: CryptoBuffer });

  const f = (sig) => lib.func(sig);
  _native = {
  init: f('int cryptolib_init()'), version: f('const char *cryptolib_version()'),
  random: f('CryptoBufferResult cryptolib_random_bytes(size_t)'),
  sha256: f('CryptoBufferResult cryptolib_sha256(uint8_t*, size_t)'),
  sha512: f('CryptoBufferResult cryptolib_sha512(uint8_t*, size_t)'),
  blake2b: f('CryptoBufferResult cryptolib_blake2b(uint8_t*, size_t, uint8_t*, size_t)'),
  blake3: f('CryptoBufferResult cryptolib_blake3(uint8_t*, size_t, size_t)'),
  hmac256: f('CryptoBufferResult cryptolib_hmac_sha256(uint8_t*, size_t, uint8_t*, size_t)'),
  hmac256v: f('int cryptolib_hmac_sha256_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  hkdf: f('CryptoBufferResult cryptolib_hkdf_derive(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, size_t)'),
  argonHash: f('CryptoBufferResult cryptolib_argon2id_hash_str(const char*, uint64_t, size_t)'),
  argonVerify: f('int cryptolib_argon2id_verify_str(const char*, const char*)'),
  symKeygen: f('CryptoBufferResult cryptolib_sym_keygen()'),
  xEnc: f('CryptoBufferResult cryptolib_xchacha20_encrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  xDec: f('CryptoBufferResult cryptolib_xchacha20_decrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  aesAvail: f('int cryptolib_aes256gcm_available()'),
  aesEnc: f('CryptoBufferResult cryptolib_aes256gcm_encrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  aesDec: f('CryptoBufferResult cryptolib_aes256gcm_decrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  edKeygen: f('CryptoKeyPair cryptolib_ed25519_keygen()'),
  edSign: f('CryptoBufferResult cryptolib_ed25519_sign(uint8_t*, size_t, uint8_t*, size_t)'),
  edVerify: f('int cryptolib_ed25519_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  xKeygen: f('CryptoKeyPair cryptolib_x25519_keygen()'),
  xShared: f('CryptoBufferResult cryptolib_x25519_shared_secret(uint8_t*, size_t, uint8_t*, size_t)'),
  boxKeygen: f('CryptoKeyPair cryptolib_box_keygen()'),
  boxEnc: f('CryptoBufferResult cryptolib_box_encrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  boxDec: f('CryptoBufferResult cryptolib_box_decrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  sealEnc: f('CryptoBufferResult cryptolib_sealedbox_encrypt(uint8_t*, size_t, uint8_t*, size_t)'),
  sealDec: f('CryptoBufferResult cryptolib_sealedbox_decrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  vCreate: f('void *cryptolib_vault_create(uint8_t*, size_t, int)'),
  vSeal: f('CryptoPacket cryptolib_vault_seal(void*, uint8_t*, size_t, const char*, _Out_ char**)'),
  vOpen: f('CryptoBufferResult cryptolib_vault_open(void*, CryptoPacket*, const char*)'),
  vFree: f('void cryptolib_vault_free(void*)'),
  kemKeygen: f('CryptoKeyPair cryptolib_ml_kem_keygen(int)'),
  kemEncaps: f('CryptoKemEncapsResult cryptolib_ml_kem_encapsulate(uint8_t*, size_t, int, _Out_ char**)'),
  kemDecaps: f('CryptoBufferResult cryptolib_ml_kem_decapsulate(uint8_t*, size_t, uint8_t*, size_t, int)'),
  hyKeygen: f('CryptoKeyPair cryptolib_hybrid_kem_keygen()'),
  hyEncaps: f('CryptoKemEncapsResult cryptolib_hybrid_kem_encapsulate(uint8_t*, size_t, _Out_ char**)'),
  hyDecaps: f('CryptoBufferResult cryptolib_hybrid_kem_decapsulate(uint8_t*, size_t, uint8_t*, size_t)'),
  dsaKeygen: f('CryptoKeyPair cryptolib_ml_dsa_keygen(int)'),
  dsaSign: f('CryptoBufferResult cryptolib_ml_dsa_sign(uint8_t*, size_t, uint8_t*, size_t, int)'),
  dsaVerify: f('int cryptolib_ml_dsa_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, int)'),
  blsKeygen: f('CryptoKeyPair cryptolib_bls_keygen()'),
  blsSign: f('CryptoBufferResult cryptolib_bls_sign(uint8_t*, size_t, uint8_t*, size_t)'),
  blsVerify: f('int cryptolib_bls_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  krCreate: f('void *cryptolib_keyring_create()'),
  krAddDev: f('int cryptolib_keyring_add_device_slot(void*, uint8_t*, size_t)'),
  krAddPw: f('int cryptolib_keyring_add_passphrase_slot(void*, const char*, int)'),
  krCount: f('size_t cryptolib_keyring_slot_count(void*)'),
  krSer: f('CryptoBufferResult cryptolib_keyring_serialise(void*)'),
  krDeser: f('void *cryptolib_keyring_deserialise(uint8_t*, size_t, _Out_ char**)'),
  krUnlockDev: f('CryptoBufferResult cryptolib_keyring_unlock_with_device(void*, uint8_t*, size_t)'),
  krUnlockPw: f('CryptoBufferResult cryptolib_keyring_unlock_with_passphrase(void*, const char*)'),
  krFree: f('void cryptolib_keyring_free(void*)'),
  bufFree: f('void cryptolib_buffer_free(CryptoBuffer*)'),
  pktFree: f('void cryptolib_packet_free(CryptoPacket*)'),
  kpFree: f('void cryptolib_keypair_free(CryptoKeyPair*)'),
  kemFree: f('void cryptolib_kem_encaps_free(CryptoKemEncapsResult*)'),
  strFree: f('void cryptolib_str_free(void*)'),
  };
  return _native;
}

// Proxy so existing `fn.xxx` call sites stay unchanged but trigger the lazy load
// on first property access.
const fn = new Proxy({}, { get: (_t, prop) => ensureLoaded()[prop] });

// ── Helpers ──────────────────────────────────────────────────────────────────
const b = (cb) => (!cb.data || Number(cb.len) === 0) ? Buffer.alloc(0)
  : Buffer.from(koffi.decode(cb.data, 'uint8_t', Number(cb.len)));
function consume(r) {
  if ((!r.buf.data || Number(r.buf.len) === 0) && r.error) {
    const m = koffi.decode(r.error, 'char *'); fn.strFree(r.error); throw new Error(m);
  }
  const out = b(r.buf); fn.bufFree(r.buf); return out;
}
function kp(k) { const pub = b(k.public_key), sec = b(k.secret_key); fn.kpFree(k); return { publicKey: pub, secretKey: sec }; }
const u8 = (x) => Buffer.isBuffer(x) ? x : Buffer.from(x);

// Internal: synchronously load + initialize the native lib. Used by the worker
// in preload() and reachable from the main thread for the lazy fallback.
function _warm() {
  const a = ensureLoaded();
  if (a.init() !== 0) throw new Error('cryptolib init failed');
  a.version();
  return true;
}

// Optionally warm the native binding OFF the main thread.
//
// Spawns a short-lived worker_thread that loads the shared library and runs the
// one-time libsodium init. dlopen mapping and libsodium init are process-global,
// so this warms the path for the main thread's later lazy load — the first
// synchronous crypto call then pays no load cost. Returns a Promise<boolean>
// you may ignore (fire-and-forget) or await; the crypto API never requires
// awaiting it. Falls back to a same-thread warm if workers are unavailable.
function preload() {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    let Worker;
    try { ({ Worker } = require('node:worker_threads')); }
    catch { try { _warm(); } catch { /* ignore */ } return done(true); }
    try {
      const code = `
        const { workerData, parentPort } = require('node:worker_threads');
        try { require(workerData.modulePath)._warm(); parentPort.postMessage({ ok: true }); }
        catch (e) { parentPort.postMessage({ ok: false, error: String(e) }); }`;
      const w = new Worker(code, { eval: true, workerData: { modulePath: __filename } });
      w.once('message', (m) => { w.terminate(); done(!!(m && m.ok)); });
      w.once('error', () => done(false));
      w.once('exit', (c) => done(c === 0));
    } catch { done(false); }
  });
}

// ── Public API ───────────────────────────────────────────────────────────────
module.exports = {
  preload,
  _warm,
  init() { if (fn.init() !== 0) throw new Error('cryptolib init failed'); },
  version: () => fn.version(),
  randomBytes: (n) => consume(fn.random(n)),

  sha256: (m) => consume(fn.sha256(u8(m), u8(m).length)),
  sha512: (m) => consume(fn.sha512(u8(m), u8(m).length)),
  blake2b: (m, key = null) => consume(fn.blake2b(u8(m), u8(m).length, key ? u8(key) : null, key ? u8(key).length : 0)),
  blake3: (m, len = 32) => consume(fn.blake3(u8(m), u8(m).length, len)),
  hmacSha256: (m, key) => consume(fn.hmac256(u8(m), u8(m).length, u8(key), u8(key).length)),
  hmacSha256Verify: (m, mac, key) => fn.hmac256v(u8(m), u8(m).length, u8(mac), u8(mac).length, u8(key), u8(key).length) === 1,
  argon2idHashStr: (pw, ops = 2, mem = 67108864) => consume(fn.argonHash(pw, ops, mem)).toString('latin1').replace(/\0+$/, ''),
  argon2idVerifyStr: (pw, phc) => fn.argonVerify(pw, phc) === 1,

  symKeygen: () => consume(fn.symKeygen()),
  xchacha20Encrypt: (pt, key, aad = null) => consume(fn.xEnc(u8(pt), u8(pt).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  xchacha20Decrypt: (ct, key, aad = null) => consume(fn.xDec(u8(ct), u8(ct).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  aes256gcmAvailable: () => fn.aesAvail() === 1,

  ed25519Keygen: () => kp(fn.edKeygen()),
  ed25519Sign: (m, sk) => consume(fn.edSign(u8(m), u8(m).length, u8(sk), u8(sk).length)),
  ed25519Verify: (m, sig, pk) => fn.edVerify(u8(m), u8(m).length, u8(sig), u8(sig).length, u8(pk), u8(pk).length) === 1,
  x25519Keygen: () => kp(fn.xKeygen()),
  x25519SharedSecret: (sk, pk) => consume(fn.xShared(u8(sk), u8(sk).length, u8(pk), u8(pk).length)),

  // Post-quantum
  mlKemKeygen: (level = 1) => kp(fn.kemKeygen(level)),
  mlKemEncapsulate(pk, level = 1) {
    const e = [null]; const r = fn.kemEncaps(u8(pk), u8(pk).length, level, e);
    const ss = b(r.shared_secret), ct = b(r.ciphertext); fn.kemFree(r);
    if (e[0]) { const m = koffi.decode(e[0], 'char *'); fn.strFree(e[0]); throw new Error(m); }
    return { ciphertext: ct, sharedSecret: ss };
  },
  mlKemDecapsulate: (ct, sk, level = 1) => consume(fn.kemDecaps(u8(ct), u8(ct).length, u8(sk), u8(sk).length, level)),

  // Hybrid X25519 + ML-KEM-768
  hybridKemKeygen: () => kp(fn.hyKeygen()),
  hybridKemEncapsulate(pk) {
    const e = [null]; const r = fn.hyEncaps(u8(pk), u8(pk).length, e);
    const ss = b(r.shared_secret), ct = b(r.ciphertext); fn.kemFree(r);
    if (e[0]) { const m = koffi.decode(e[0], 'char *'); fn.strFree(e[0]); throw new Error(m); }
    return { ciphertext: ct, sharedSecret: ss };
  },
  hybridKemDecapsulate: (ct, sk) => consume(fn.hyDecaps(u8(ct), u8(ct).length, u8(sk), u8(sk).length)),

  blsKeygen: () => kp(fn.blsKeygen()),
  blsSign: (m, sk) => consume(fn.blsSign(u8(m), u8(m).length, u8(sk), u8(sk).length)),
  blsVerify: (m, sig, pk) => fn.blsVerify(u8(m), u8(m).length, u8(sig), u8(sig).length, u8(pk), u8(pk).length) === 1,

  // Keyring
  keyringCreate: () => fn.krCreate(),
  keyringAddDeviceSlot: (kr, factor) => fn.krAddDev(kr, u8(factor), u8(factor).length) === 0,
  keyringAddPassphraseSlot: (kr, pw, kdf = 0) => fn.krAddPw(kr, pw, kdf) === 0,
  keyringSlotCount: (kr) => Number(fn.krCount(kr)),
  keyringSerialise: (kr) => consume(fn.krSer(kr)),
  keyringDeserialise(blob) { const e = [null]; const kr = fn.krDeser(u8(blob), u8(blob).length, e); if (e[0]) { const m = koffi.decode(e[0], 'char *'); fn.strFree(e[0]); throw new Error(m); } return kr; },
  keyringUnlockWithDevice: (kr, factor) => consume(fn.krUnlockDev(kr, u8(factor), u8(factor).length)),
  keyringUnlockWithPassphrase: (kr, pw) => consume(fn.krUnlockPw(kr, pw)),
  keyringFree: (kr) => fn.krFree(kr),

  // Escape hatch for advanced/raw use.
  _fn: fn,
};
