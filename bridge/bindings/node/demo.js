// CipherBird Node.js demo via koffi (https://koffi.dev).
//
// This is the JavaScript native-call path: usable directly from Node/Electron,
// and the same approach a React Native TurboModule (C++) or a Node addon would
// wrap. (Browser React cannot load a .dylib — it would need a WASM build.)
//
// Run (see Makefile target `node`):
//   npm install
//   node demo.js <path-to-libcipherbird_c.dylib>

const koffi = require('koffi');

const libPath = process.argv[2] || 'build/release/libcipherbird_c.dylib';
const lib = koffi.load(libPath);

// ── C struct definitions ─────────────────────────────────────────────────────
const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
// error kept as a raw pointer (not auto-decoded to a JS string) so we can free
// the *original* C allocation with cipherbird_str_free rather than a koffi temp.
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const CryptoPacket = koffi.struct('CryptoPacket', {
  ciphertext: CryptoBuffer, signature: CryptoBuffer, kdf_salt: CryptoBuffer,
});

// ── Function bindings ────────────────────────────────────────────────────────
const cipherbird_init = lib.func('int cipherbird_init()');
const cipherbird_version = lib.func('const char *cipherbird_version()');
const cipherbird_random_bytes = lib.func('CryptoBufferResult cipherbird_random_bytes(size_t n)');
const cipherbird_sha256 = lib.func('CryptoBufferResult cipherbird_sha256(uint8_t *msg, size_t len)');
const cipherbird_vault_create = lib.func('void *cipherbird_vault_create(uint8_t *key, size_t len, int kdf)');
const cipherbird_vault_seal = lib.func('CryptoPacket cipherbird_vault_seal(void *v, uint8_t *pt, size_t len, const char *aad, _Out_ char **err)');
const cipherbird_vault_open = lib.func('CryptoBufferResult cipherbird_vault_open(void *v, CryptoPacket *pkt, const char *aad)');
const cipherbird_buffer_free = lib.func('void cipherbird_buffer_free(CryptoBuffer *buf)');
const cipherbird_packet_free = lib.func('void cipherbird_packet_free(CryptoPacket *p)');
const cipherbird_vault_free = lib.func('void cipherbird_vault_free(void *v)');
const cipherbird_str_free = lib.func('void cipherbird_str_free(void *s)');

// Keyring (envelope / key-slots)
const cipherbird_keyring_create = lib.func('void *cipherbird_keyring_create()');
const cipherbird_keyring_add_device_slot = lib.func('int cipherbird_keyring_add_device_slot(void *kr, uint8_t *fk, size_t len)');
const cipherbird_keyring_add_passphrase_slot = lib.func('int cipherbird_keyring_add_passphrase_slot(void *kr, const char *pw, int kdf)');
const cipherbird_keyring_slot_count = lib.func('size_t cipherbird_keyring_slot_count(void *kr)');
const cipherbird_keyring_serialise = lib.func('CryptoBufferResult cipherbird_keyring_serialise(void *kr)');
const cipherbird_keyring_deserialise = lib.func('void *cipherbird_keyring_deserialise(uint8_t *blob, size_t len, _Out_ char **err)');
const cipherbird_keyring_unlock_with_device = lib.func('CryptoBufferResult cipherbird_keyring_unlock_with_device(void *kr, uint8_t *fk, size_t len)');
const cipherbird_keyring_unlock_with_passphrase = lib.func('CryptoBufferResult cipherbird_keyring_unlock_with_passphrase(void *kr, const char *pw)');
const cipherbird_keyring_free = lib.func('void cipherbird_keyring_free(void *kr)');

// Keypair struct (public/secret CryptoBuffers) for the signature keygens.
const CryptoKeyPair = koffi.struct('CryptoKeyPair', { public_key: CryptoBuffer, secret_key: CryptoBuffer });
const cipherbird_keypair_free = lib.func('void cipherbird_keypair_free(CryptoKeyPair *kp)');

// ── Newly exposed feature functions ──
const cipherbird_committing_encrypt = lib.func('CryptoBufferResult cipherbird_committing_encrypt(uint8_t *pt, size_t ptl, uint8_t *key, size_t kl, uint8_t *aad, size_t al)');
const cipherbird_committing_decrypt = lib.func('CryptoBufferResult cipherbird_committing_decrypt(uint8_t *ct, size_t ctl, uint8_t *key, size_t kl, uint8_t *aad, size_t al)');
const cipherbird_hmac_sha256 = lib.func('CryptoBufferResult cipherbird_hmac_sha256(uint8_t *msg, size_t ml, uint8_t *key, size_t kl)');
const cipherbird_hmac_sha256_verify = lib.func('int cipherbird_hmac_sha256_verify(uint8_t *msg, size_t ml, uint8_t *mac, size_t macl, uint8_t *key, size_t kl)');
const cipherbird_hkdf_extract = lib.func('CryptoBufferResult cipherbird_hkdf_extract(uint8_t *salt, size_t sl, uint8_t *ikm, size_t il)');
const cipherbird_hkdf_expand = lib.func('CryptoBufferResult cipherbird_hkdf_expand(uint8_t *prk, size_t pl, uint8_t *info, size_t il, size_t outlen)');
const cipherbird_hkdf_derive = lib.func('CryptoBufferResult cipherbird_hkdf_derive(uint8_t *ikm, size_t il, uint8_t *salt, size_t sl, uint8_t *info, size_t infl, size_t outlen)');
const cipherbird_hybrid_sig_keygen = lib.func('CryptoKeyPair cipherbird_hybrid_sig_keygen()');
const cipherbird_hybrid_sig_sign = lib.func('CryptoBufferResult cipherbird_hybrid_sig_sign(uint8_t *msg, size_t ml, uint8_t *sk, size_t skl)');
const cipherbird_hybrid_sig_verify = lib.func('int cipherbird_hybrid_sig_verify(uint8_t *msg, size_t ml, uint8_t *sig, size_t sigl, uint8_t *pk, size_t pkl)');
const cipherbird_bls_keygen_from_ikm = lib.func('CryptoKeyPair cipherbird_bls_keygen_from_ikm(uint8_t *ikm, size_t il)');

// Copy a returned CryptoBufferResult into a Node Buffer and free the C memory.
function consume(res) {
  if (!res.buf.data || Number(res.buf.len) === 0) {
    if (res.error) {
      console.error('error:', koffi.decode(res.error, 'char *'));
      cipherbird_str_free(res.error);
    }
    return Buffer.alloc(0);
  }
  const n = Number(res.buf.len);
  const bytes = Buffer.from(koffi.decode(res.buf.data, 'uint8_t', n));
  cipherbird_buffer_free(res.buf);
  return bytes;
}

const hex = (b) => b.toString('hex');

// Copy a returned CryptoKeyPair into { pub, sec } Buffers and free the C memory.
function consumeKeypair(kp) {
  const pub = Buffer.from(koffi.decode(kp.public_key.data, 'uint8_t', Number(kp.public_key.len)));
  const sec = Buffer.from(koffi.decode(kp.secret_key.data, 'uint8_t', Number(kp.secret_key.len)));
  cipherbird_keypair_free(kp);
  return { pub, sec };
}

if (cipherbird_init() !== 0) throw new Error('init failed');
console.log('CipherBird version:', cipherbird_version());

console.log('random(32): ', hex(consume(cipherbird_random_bytes(32))));
console.log('sha256(abc):', hex(consume(cipherbird_sha256(Buffer.from('abc'), 3))));

const key = consume(cipherbird_random_bytes(32));
const vault = cipherbird_vault_create(key, key.length, 0);
if (!vault) throw new Error('vault_create failed');

const pt = Buffer.from('hello from node');
const errOut = [null];
const packet = cipherbird_vault_seal(vault, pt, pt.length, 'ctx', errOut);
if (errOut[0]) throw new Error('seal: ' + errOut[0]);

const opened = consume(cipherbird_vault_open(vault, packet, 'ctx'));
console.log('vault roundtrip: "%s"', opened.toString());

// Wrong AAD must fail.
const bad = cipherbird_vault_open(vault, packet, 'wrong');
if (bad.buf.data) throw new Error('wrong AAD should not decrypt');
if (bad.error) cipherbird_str_free(bad.error);

cipherbird_packet_free(packet);
cipherbird_vault_free(vault);

// Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
const factor = consume(cipherbird_random_bytes(32)); // stands in for a hardware key
const kr = cipherbird_keyring_create();
cipherbird_keyring_add_device_slot(kr, factor, factor.length);
cipherbird_keyring_add_passphrase_slot(kr, 'cross-device pass', 0);
const blob = consume(cipherbird_keyring_serialise(kr));
const krErr = [null];
const kr2 = cipherbird_keyring_deserialise(blob, blob.length, krErr);
if (krErr[0]) throw new Error('keyring deserialise failed');
const mDev = consume(cipherbird_keyring_unlock_with_device(kr2, factor, factor.length));
const mPass = consume(cipherbird_keyring_unlock_with_passphrase(kr2, 'cross-device pass'));
console.log('keyring slots:', Number(cipherbird_keyring_slot_count(kr)),
            '· device==passphrase master:', Buffer.compare(mDev, mPass) === 0);
cipherbird_keyring_free(kr);
cipherbird_keyring_free(kr2);

// ── Newly exposed feature functions ──
// Committing AEAD (UtC): wrong key must fail.
const caKey = consume(cipherbird_random_bytes(32));
const caAad = Buffer.from('ctx');
const caCt = consume(cipherbird_committing_encrypt(Buffer.from('commit me'), 9, caKey, caKey.length, caAad, caAad.length));
const caDec = consume(cipherbird_committing_decrypt(caCt, caCt.length, caKey, caKey.length, caAad, caAad.length));
const caBad = cipherbird_committing_decrypt(caCt, caCt.length, consume(cipherbird_random_bytes(32)), 32, caAad, caAad.length);
const caReject = !caBad.buf.data;
if (caBad.error) cipherbird_str_free(caBad.error);
console.log('committing AEAD: roundtrip="%s" reject-wrong-key=%s', caDec.toString(), caReject);

// HKDF-SHA256 + HMAC-SHA256.
const ikm = consume(cipherbird_random_bytes(32));
const salt = Buffer.from('salt'), info = Buffer.from('app');
const prk = consume(cipherbird_hkdf_extract(salt, salt.length, ikm, ikm.length));
const okm = consume(cipherbird_hkdf_expand(prk, prk.length, info, info.length, 42));
const okm1 = consume(cipherbird_hkdf_derive(ikm, ikm.length, salt, salt.length, info, info.length, 42));
const macMsg = Buffer.from('mac me');
const mac256 = consume(cipherbird_hmac_sha256(macMsg, macMsg.length, ikm, ikm.length));
const macOk = cipherbird_hmac_sha256_verify(macMsg, macMsg.length, mac256, mac256.length, ikm, ikm.length) === 1;
console.log('hkdf len=%d consistent=%s · hmac256 verify=%s', okm.length, Buffer.compare(okm, okm1) === 0, macOk);

// Hybrid signature (Ed25519 + ML-DSA-65).
const hkp = consumeKeypair(cipherbird_hybrid_sig_keygen());
const sMsg = Buffer.from('sign me');
const hsig = consume(cipherbird_hybrid_sig_sign(sMsg, sMsg.length, hkp.sec, hkp.sec.length));
const hsigOk = cipherbird_hybrid_sig_verify(sMsg, sMsg.length, hsig, hsig.length, hkp.pub, hkp.pub.length) === 1;
console.log('hybrid sig: len=%d verify=%s', hsig.length, hsigOk);

// BLS deterministic keygen from IKM.
const blsIkm = consume(cipherbird_random_bytes(32));
const d1 = consumeKeypair(cipherbird_bls_keygen_from_ikm(blsIkm, blsIkm.length));
const d2 = consumeKeypair(cipherbird_bls_keygen_from_ikm(blsIkm, blsIkm.length));
console.log('bls keygen-from-ikm deterministic:', Buffer.compare(d1.pub, d2.pub) === 0);

console.log('Node demo OK');
