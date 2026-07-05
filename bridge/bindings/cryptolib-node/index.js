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
  koffi.struct('CryptoDerivedKeys', { symmetric_key: CryptoBuffer, vault_master_key: CryptoBuffer, signing_seed: CryptoBuffer, box_seed: CryptoBuffer, stream_key: CryptoBuffer, raw_entropy: CryptoBuffer });
  koffi.struct('CryptoEntropyInfo', { path: 'void *', file_size: 'uint64_t', chunks_read: 'uint64_t', entropy_bits: 'double' });
  koffi.struct('CryptoResult', { ok: 'int', error: 'void *' });

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
  bundleFree: f('void cryptolib_bundle_free(CryptoAsymBundle*)'),
  derivedFree: f('void cryptolib_derived_keys_free(CryptoDerivedKeys*)'),
  entInfoFree: f('void cryptolib_entropy_info_free(CryptoEntropyInfo*)'),

  // Hash / KDF
  blake3Keyed: f('CryptoBufferResult cryptolib_blake3_keyed(uint8_t*, size_t, uint8_t*, size_t, size_t)'),
  blake3Derive: f('CryptoBufferResult cryptolib_blake3_derive_key(const char*, uint8_t*, size_t, size_t)'),
  hmac512: f('CryptoBufferResult cryptolib_hmac_sha512(uint8_t*, size_t, uint8_t*, size_t)'),
  hmac512v: f('int cryptolib_hmac_sha512_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  hkdfExtract: f('CryptoBufferResult cryptolib_hkdf_extract(uint8_t*, size_t, uint8_t*, size_t)'),
  hkdfExpand: f('CryptoBufferResult cryptolib_hkdf_expand(uint8_t*, size_t, uint8_t*, size_t, size_t)'),
  argonDerive: f('CryptoBufferResult cryptolib_argon2id_derive(const char*, uint8_t*, size_t, size_t, uint64_t, size_t)'),

  // Symmetric — committing AEAD + streaming
  cmtEnc: f('CryptoBufferResult cryptolib_committing_encrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  cmtDec: f('CryptoBufferResult cryptolib_committing_decrypt(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  streamEncCreate: f('void *cryptolib_stream_enc_create(uint8_t*)'),
  streamEncHeader: f('CryptoBufferResult cryptolib_stream_enc_header(void*)'),
  streamEncPush: f('CryptoBufferResult cryptolib_stream_enc_push(void*, uint8_t*, size_t, uint8_t)'),
  streamEncFree: f('void cryptolib_stream_enc_free(void*)'),
  streamDecCreate: f('void *cryptolib_stream_dec_create(uint8_t*, uint8_t*)'),
  streamDecPull: f('CryptoBufferResult cryptolib_stream_dec_pull(void*, uint8_t*, size_t, _Out_ uint8_t*)'),
  streamDecFree: f('void cryptolib_stream_dec_free(void*)'),

  // Asymmetric extras
  edKeygenSeed: f('CryptoKeyPair cryptolib_ed25519_keygen_from_seed(uint8_t*, size_t)'),
  secureEqual: f('int cryptolib_secure_equal(uint8_t*, size_t, uint8_t*, size_t)'),

  // Post-quantum — SLH-DSA + hybrid signatures
  slhKeygen: f('CryptoKeyPair cryptolib_slh_dsa_keygen(int, int)'),
  slhSign: f('CryptoBufferResult cryptolib_slh_dsa_sign(uint8_t*, size_t, uint8_t*, size_t, int, int)'),
  slhVerify: f('int cryptolib_slh_dsa_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, int, int)'),
  hsKeygen: f('CryptoKeyPair cryptolib_hybrid_sig_keygen()'),
  hsSign: f('CryptoBufferResult cryptolib_hybrid_sig_sign(uint8_t*, size_t, uint8_t*, size_t)'),
  hsVerify: f('int cryptolib_hybrid_sig_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),

  // BLS extras
  blsKeygenIkm: f('CryptoKeyPair cryptolib_bls_keygen_from_ikm(uint8_t*, size_t)'),
  blsAgg: f('CryptoBufferResult cryptolib_bls_aggregate(const uint8_t**, size_t*, size_t)'),
  blsAggVerify: f('int cryptolib_bls_aggregate_verify(const uint8_t**, size_t*, const uint8_t**, size_t*, size_t, uint8_t*, size_t)'),

  // Vault + packet serialisation
  vFromEntropy: f('void *cryptolib_vault_from_entropy(void*, int)'),
  vPubKey: f('CryptoBufferResult cryptolib_vault_public_key(void*)'),
  vSealBoost: f('CryptoPacket cryptolib_vault_seal_boosted(void*, uint8_t*, size_t, const char*, void*, _Out_ char**)'),
  vOpenBoost: f('CryptoBufferResult cryptolib_vault_open_boosted(void*, CryptoPacket*, const char*, void*)'),
  pktSer: f('CryptoBufferResult cryptolib_packet_serialise(CryptoPacket*)'),
  pktDeser: f('CryptoPacket cryptolib_packet_deserialise(uint8_t*, size_t, _Out_ char**)'),

  // Asymmetric vault
  asymBundleGen: f('CryptoAsymBundle cryptolib_asym_bundle_generate()'),
  asymVSeal: f('CryptoPacket cryptolib_asym_vault_seal(CryptoAsymBundle*, uint8_t*, size_t, uint8_t*, size_t, const char*, _Out_ char**)'),
  asymVOpen: f('CryptoBufferResult cryptolib_asym_vault_open(CryptoPacket*, CryptoAsymBundle*, uint8_t*, size_t, const char*)'),

  // Keyring extra
  krRemove: f('int cryptolib_keyring_remove_slot(void*, size_t)'),

  // Media entropy
  entFromFile: f('void *cryptolib_entropy_from_file(const char*, _Out_ char**)'),
  entFromFileDet: f('void *cryptolib_entropy_from_file_deterministic(const char*, _Out_ char**)'),
  entFromFiles: f('void *cryptolib_entropy_from_files(const char**, size_t, _Out_ char**)'),
  entFromFilesDet: f('void *cryptolib_entropy_from_files_deterministic(const char**, size_t, _Out_ char**)'),
  entDeriveAll: f('CryptoDerivedKeys cryptolib_entropy_derive_all(void*)'),
  entSymKey: f('CryptoBufferResult cryptolib_entropy_symmetric_key(void*)'),
  entRaw: f('CryptoBufferResult cryptolib_entropy_raw(void*)'),
  entBoost: f('CryptoBufferResult cryptolib_entropy_boost(void*)'),
  entInfo: f('CryptoEntropyInfo cryptolib_entropy_info(void*)'),
  entRefresh: f('void cryptolib_entropy_refresh(void*)'),
  entAsymBundle: f('CryptoAsymBundle cryptolib_entropy_asym_bundle(void*, _Out_ char**)'),
  entFree: f('void cryptolib_entropy_free(void*)'),
  keyFromFile: f('CryptoBufferResult cryptolib_key_from_file(const char*)'),
  sealFromFile: f('CryptoPacket cryptolib_seal_from_file(const char*, const char*, const char*, _Out_ char**)'),
  openFromFile: f('CryptoBufferResult cryptolib_open_from_file(const char*, CryptoPacket*, const char*)'),

  // EVM / Bitcoin interop
  keccak: f('CryptoBufferResult cryptolib_keccak256(uint8_t*, size_t)'),
  ripemd: f('CryptoBufferResult cryptolib_ripemd160(uint8_t*, size_t)'),
  secpKeygen: f('CryptoKeyPair cryptolib_secp256k1_keygen()'),
  secpPub: f('CryptoBufferResult cryptolib_secp256k1_pubkey(uint8_t*, size_t, int)'),
  secpSign: f('CryptoBufferResult cryptolib_secp256k1_sign(uint8_t*, uint8_t*, size_t)'),
  secpVerify: f('int cryptolib_secp256k1_verify(uint8_t*, uint8_t*, size_t, uint8_t*, size_t)'),
  secpRecover: f('CryptoBufferResult cryptolib_secp256k1_recover(uint8_t*, uint8_t*)'),

  // Steganography
  stegoEmbed: f('CryptoResult cryptolib_stego_embed(const char*, uint8_t*, size_t, const char*)'),
  stegoExtract: f('CryptoBufferResult cryptolib_stego_extract(const char*)'),
  stegoCapacity: f('size_t cryptolib_stego_capacity(const char*)'),

  // MolecularVault
  molSeal: f('CryptoBufferResult cryptolib_molecular_seal(uint8_t*, size_t, const char*, uint8_t*, size_t, uint64_t, size_t)'),
  molOpen: f('CryptoBufferResult cryptolib_molecular_open(uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  molSealKey: f('CryptoBufferResult cryptolib_molecular_seal_with_key(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  molOpenKey: f('CryptoBufferResult cryptolib_molecular_open_with_key(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
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

// Throw if a `_Out_ char**` error slot was populated.
function outErr(e) { if (e[0]) { const m = koffi.decode(e[0], 'char *'); fn.strFree(e[0]); throw new Error(m); } }

// CryptoAsymBundle ↔ JS { boxPublic, boxSecret, signPublic, signSecret }.
function bundle(bd) {
  const out = { boxPublic: b(bd.box_public), boxSecret: b(bd.box_secret), signPublic: b(bd.sign_public), signSecret: b(bd.sign_secret) };
  fn.bundleFree(bd); return out;
}
function bundleToC(x) {
  return { box_public: { data: u8(x.boxPublic), len: x.boxPublic.length }, box_secret: { data: u8(x.boxSecret), len: x.boxSecret.length }, sign_public: { data: u8(x.signPublic), len: x.signPublic.length }, sign_secret: { data: u8(x.signSecret), len: x.signSecret.length } };
}
// CryptoDerivedKeys → JS { symmetricKey, ... , rawEntropy }.
function derived(dk) {
  const out = { symmetricKey: b(dk.symmetric_key), vaultMasterKey: b(dk.vault_master_key), signingSeed: b(dk.signing_seed), boxSeed: b(dk.box_seed), streamKey: b(dk.stream_key), rawEntropy: b(dk.raw_entropy) };
  fn.derivedFree(dk); return out;
}
// CryptoPacket ↔ JS { ciphertext, signature, kdfSalt }.
function pktFrom(p) { const out = { ciphertext: b(p.ciphertext), signature: b(p.signature), kdfSalt: b(p.kdf_salt) }; fn.pktFree(p); return out; }
function pktTo(p) { return { ciphertext: { data: u8(p.ciphertext), len: p.ciphertext.length }, signature: { data: u8(p.signature), len: p.signature.length }, kdf_salt: { data: u8(p.kdfSalt), len: p.kdfSalt.length } }; }

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
  keyringRemoveSlot: (kr, index) => fn.krRemove(kr, index) === 1,
  keyringFree: (kr) => fn.krFree(kr),

  // ── Hash / KDF extras ──
  blake3Keyed: (m, key, len = 32) => consume(fn.blake3Keyed(u8(m), u8(m).length, u8(key), u8(key).length, len)),
  blake3DeriveKey: (ctx, ikm, len = 32) => consume(fn.blake3Derive(ctx, u8(ikm), u8(ikm).length, len)),
  hmacSha512: (m, key) => consume(fn.hmac512(u8(m), u8(m).length, u8(key), u8(key).length)),
  hmacSha512Verify: (m, mac, key) => fn.hmac512v(u8(m), u8(m).length, u8(mac), u8(mac).length, u8(key), u8(key).length) === 1,
  hkdfExtract: (ikm, salt = null) => consume(fn.hkdfExtract(salt ? u8(salt) : null, salt ? u8(salt).length : 0, u8(ikm), u8(ikm).length)),
  hkdfExpand: (prk, info = null, len = 32) => consume(fn.hkdfExpand(u8(prk), u8(prk).length, info ? u8(info) : null, info ? u8(info).length : 0, len)),
  argon2idDerive: (pw, salt, keyLen = 32, ops = 2, mem = 67108864) => consume(fn.argonDerive(pw, u8(salt), u8(salt).length, keyLen, ops, mem)),

  // ── Committing AEAD + streaming ──
  committingEncrypt: (pt, key, aad = null) => consume(fn.cmtEnc(u8(pt), u8(pt).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  committingDecrypt: (ct, key, aad = null) => consume(fn.cmtDec(u8(ct), u8(ct).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  streamEncryptorCreate: (key) => fn.streamEncCreate(u8(key)),
  streamEncHeader: (h) => consume(fn.streamEncHeader(h)),
  streamEncPush: (h, pt, tag = 0) => consume(fn.streamEncPush(h, u8(pt), u8(pt).length, tag)),
  streamEncFree: (h) => fn.streamEncFree(h),
  streamDecryptorCreate: (key, hdr) => fn.streamDecCreate(u8(key), u8(hdr)),
  streamDecPull(h, ct) { const tag = Buffer.alloc(1); const out = consume(fn.streamDecPull(h, u8(ct), u8(ct).length, tag)); return { plaintext: out, tag: tag[0] }; },
  streamDecFree: (h) => fn.streamDecFree(h),

  // ── Asymmetric extras ──
  ed25519KeygenFromSeed: (seed) => kp(fn.edKeygenSeed(u8(seed), u8(seed).length)),
  secureEqual: (a, c) => fn.secureEqual(u8(a), u8(a).length, u8(c), u8(c).length) === 1,

  // ── Post-quantum: SLH-DSA (level 0/1/2 = 128/192/256; hashFamily 0=SHA2,1=SHAKE) + hybrid sig ──
  slhDsaKeygen: (level = 0, hashFamily = 0) => kp(fn.slhKeygen(level, hashFamily)),
  slhDsaSign: (m, sk, level = 0, hashFamily = 0) => consume(fn.slhSign(u8(m), u8(m).length, u8(sk), u8(sk).length, level, hashFamily)),
  slhDsaVerify: (m, sig, pk, level = 0, hashFamily = 0) => fn.slhVerify(u8(m), u8(m).length, u8(sig), u8(sig).length, u8(pk), u8(pk).length, level, hashFamily) === 1,
  hybridSigKeygen: () => kp(fn.hsKeygen()),
  hybridSigSign: (m, sk) => consume(fn.hsSign(u8(m), u8(m).length, u8(sk), u8(sk).length)),
  hybridSigVerify: (m, sig, pk) => fn.hsVerify(u8(m), u8(m).length, u8(sig), u8(sig).length, u8(pk), u8(pk).length) === 1,

  // ── BLS extras ──
  blsKeygenFromIkm: (ikm) => kp(fn.blsKeygenIkm(u8(ikm), u8(ikm).length)),
  blsAggregate(sigs) { const arr = sigs.map(u8); return consume(fn.blsAgg(arr, arr.map((s) => s.length), arr.length)); },
  blsAggregateVerify(msgs, pks, agg) { const m = msgs.map(u8), p = pks.map(u8); return fn.blsAggVerify(m, m.map((x) => x.length), p, p.map((x) => x.length), m.length, u8(agg), u8(agg).length) === 1; },

  // ── Vault + packet serialisation ──
  vaultCreate: (masterKey, kdf = 0) => fn.vCreate(u8(masterKey), u8(masterKey).length, kdf),
  vaultFromEntropy: (h, kdf = 0) => fn.vFromEntropy(h, kdf),
  vaultPublicKey: (v) => consume(fn.vPubKey(v)),
  vaultSeal(v, pt, aad = '') { const e = [null]; const p = fn.vSeal(v, u8(pt), u8(pt).length, aad, e); outErr(e); return pktFrom(p); },
  vaultOpen: (v, pkt, aad = '') => consume(fn.vOpen(v, pktTo(pkt), aad)),
  vaultSealBoosted(v, pt, aad, boost) { const e = [null]; const p = fn.vSealBoost(v, u8(pt), u8(pt).length, aad, boost, e); outErr(e); return pktFrom(p); },
  vaultOpenBoosted: (v, pkt, aad, boost) => consume(fn.vOpenBoost(v, pktTo(pkt), aad, boost)),
  vaultFree: (v) => fn.vFree(v),
  packetSerialise: (pkt) => consume(fn.pktSer(pktTo(pkt))),
  packetDeserialise(data) { const e = [null]; const p = fn.pktDeser(u8(data), u8(data).length, e); outErr(e); return pktFrom(p); },

  // ── Asymmetric vault ──
  asymBundleGenerate: () => bundle(fn.asymBundleGen()),
  asymVaultSeal(sender, recipientBoxPub, pt, aad = '') { const e = [null]; const p = fn.asymVSeal(bundleToC(sender), u8(recipientBoxPub), u8(recipientBoxPub).length, u8(pt), u8(pt).length, aad, e); outErr(e); return pktFrom(p); },
  asymVaultOpen: (pkt, recipient, senderSignPub, aad = '') => consume(fn.asymVOpen(pktTo(pkt), bundleToC(recipient), u8(senderSignPub), u8(senderSignPub).length, aad)),

  // ── Media entropy ──
  entropyFromFile(p) { const e = [null]; const h = fn.entFromFile(p, e); outErr(e); return h; },
  entropyFromFileDeterministic(p) { const e = [null]; const h = fn.entFromFileDet(p, e); outErr(e); return h; },
  entropyFromFiles(paths) { const e = [null]; const h = fn.entFromFiles(paths, paths.length, e); outErr(e); return h; },
  entropyFromFilesDeterministic(paths) { const e = [null]; const h = fn.entFromFilesDet(paths, paths.length, e); outErr(e); return h; },
  entropyDeriveAll: (h) => derived(fn.entDeriveAll(h)),
  entropySymmetricKey: (h) => consume(fn.entSymKey(h)),
  entropyRaw: (h) => consume(fn.entRaw(h)),
  entropyBoost: (h) => consume(fn.entBoost(h)),
  entropyInfo(h) { const i = fn.entInfo(h); const out = { path: i.path ? koffi.decode(i.path, 'char *') : '', fileSize: Number(i.file_size), chunksRead: Number(i.chunks_read), entropyBits: i.entropy_bits }; fn.entInfoFree(i); return out; },
  entropyRefresh: (h) => fn.entRefresh(h),
  entropyAsymBundle(h) { const e = [null]; const bd = fn.entAsymBundle(h, e); outErr(e); return bundle(bd); },
  entropyFree: (h) => fn.entFree(h),
  keyFromFile: (p) => consume(fn.keyFromFile(p)),
  sealFromFile(p, plaintext, aad = '') { const e = [null]; const pkt = fn.sealFromFile(p, plaintext, aad, e); outErr(e); return pktFrom(pkt); },
  openFromFile: (p, pkt, aad = '') => consume(fn.openFromFile(p, pktTo(pkt), aad)),

  // ── EVM / Bitcoin interop ──
  keccak256: (m) => consume(fn.keccak(u8(m), u8(m).length)),
  ripemd160: (m) => consume(fn.ripemd(u8(m), u8(m).length)),
  secp256k1Keygen: () => kp(fn.secpKeygen()),
  secp256k1Pubkey: (sk, compressed = false) => consume(fn.secpPub(u8(sk), u8(sk).length, compressed ? 1 : 0)),
  secp256k1Sign: (digest32, sk) => consume(fn.secpSign(u8(digest32), u8(sk), u8(sk).length)),
  secp256k1Verify: (digest32, sig, pk) => fn.secpVerify(u8(digest32), u8(sig), u8(sig).length, u8(pk), u8(pk).length) === 1,
  secp256k1Recover: (digest32, sig65) => consume(fn.secpRecover(u8(digest32), u8(sig65))),

  // ── Steganography ──
  stegoEmbed(coverPath, payload, outputPath) { const r = fn.stegoEmbed(coverPath, u8(payload), u8(payload).length, outputPath); if (r.ok !== 1) { const m = r.error ? koffi.decode(r.error, 'char *') : 'stego embed failed'; if (r.error) fn.strFree(r.error); throw new Error(m); } },
  stegoExtract: (stegoPath) => consume(fn.stegoExtract(stegoPath)),
  stegoCapacity: (coverPath) => Number(fn.stegoCapacity(coverPath)),

  // ── MolecularVault — max-assurance layered encryption ──
  molecularSeal: (pt, passphrase, aad = null, ops = 0, mem = 0) => consume(fn.molSeal(u8(pt), u8(pt).length, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0, ops, mem)),
  molecularOpen: (env, passphrase, aad = null) => consume(fn.molOpen(u8(env), u8(env).length, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  molecularSealWithKey: (pt, masterKey, aad = null) => consume(fn.molSealKey(u8(pt), u8(pt).length, u8(masterKey), u8(masterKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  molecularOpenWithKey: (env, masterKey, aad = null) => consume(fn.molOpenKey(u8(env), u8(env).length, u8(masterKey), u8(masterKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),

  // Escape hatch for advanced/raw use.
  _fn: fn,
};
