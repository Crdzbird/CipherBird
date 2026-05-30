// CryptoLib Node.js — FULL showcase of every capability family via koffi.
//
// Run (see Makefile target `node-showcase`):
//   npm install && node showcase.js <path-to-libcryptolib_c.dylib>

const koffi = require('koffi');
const lib = koffi.load(process.argv[2] || 'build/release/libcryptolib_c.dylib');

// ── Structs ───────────────────────────────────────────────────────────────────
const CryptoBuffer = koffi.struct('CryptoBuffer', { data: 'void *', len: 'size_t' });
const CryptoBufferResult = koffi.struct('CryptoBufferResult', { buf: CryptoBuffer, error: 'void *' });
const CryptoPacket = koffi.struct('CryptoPacket', { ciphertext: CryptoBuffer, signature: CryptoBuffer, kdf_salt: CryptoBuffer });
const CryptoKeyPair = koffi.struct('CryptoKeyPair', { public_key: CryptoBuffer, secret_key: CryptoBuffer });
const CryptoAsymBundle = koffi.struct('CryptoAsymBundle', { box_public: CryptoBuffer, box_secret: CryptoBuffer, sign_public: CryptoBuffer, sign_secret: CryptoBuffer });
const CryptoKemEncapsResult = koffi.struct('CryptoKemEncapsResult', { ciphertext: CryptoBuffer, shared_secret: CryptoBuffer });

const f = (sig) => lib.func(sig);
const fn = {
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
  bundleGen: f('CryptoAsymBundle cryptolib_asym_bundle_generate()'),
  avSeal: f('CryptoPacket cryptolib_asym_vault_seal(CryptoAsymBundle*, uint8_t*, size_t, uint8_t*, size_t, const char*, _Out_ char**)'),
  avOpen: f('CryptoBufferResult cryptolib_asym_vault_open(CryptoPacket*, CryptoAsymBundle*, uint8_t*, size_t, const char*)'),
  kemKeygen: f('CryptoKeyPair cryptolib_ml_kem_keygen(int)'),
  kemEncaps: f('CryptoKemEncapsResult cryptolib_ml_kem_encapsulate(uint8_t*, size_t, int, _Out_ char**)'),
  kemDecaps: f('CryptoBufferResult cryptolib_ml_kem_decapsulate(uint8_t*, size_t, uint8_t*, size_t, int)'),
  hyKeygen: f('CryptoKeyPair cryptolib_hybrid_kem_keygen()'),
  hyEncaps: f('CryptoKemEncapsResult cryptolib_hybrid_kem_encapsulate(uint8_t*, size_t, _Out_ char**)'),
  hyDecaps: f('CryptoBufferResult cryptolib_hybrid_kem_decapsulate(uint8_t*, size_t, uint8_t*, size_t)'),
  dsaKeygen: f('CryptoKeyPair cryptolib_ml_dsa_keygen(int)'),
  dsaSign: f('CryptoBufferResult cryptolib_ml_dsa_sign(uint8_t*, size_t, uint8_t*, size_t, int)'),
  dsaVerify: f('int cryptolib_ml_dsa_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, int)'),
  slhKeygen: f('CryptoKeyPair cryptolib_slh_dsa_keygen(int, int)'),
  slhSign: f('CryptoBufferResult cryptolib_slh_dsa_sign(uint8_t*, size_t, uint8_t*, size_t, int, int)'),
  slhVerify: f('int cryptolib_slh_dsa_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, int, int)'),
  blsKeygen: f('CryptoKeyPair cryptolib_bls_keygen()'),
  blsSign: f('CryptoBufferResult cryptolib_bls_sign(uint8_t*, size_t, uint8_t*, size_t)'),
  blsVerify: f('int cryptolib_bls_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  blsAgg: f('CryptoBufferResult cryptolib_bls_aggregate(void**, size_t*, size_t)'),
  blsAggVerify: f('int cryptolib_bls_aggregate_verify(void**, size_t*, void**, size_t*, size_t, uint8_t*, size_t)'),
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
  bundleFree: f('void cryptolib_bundle_free(CryptoAsymBundle*)'),
  kemFree: f('void cryptolib_kem_encaps_free(CryptoKemEncapsResult*)'),
  strFree: f('void cryptolib_str_free(void*)'),
};

const b = (cb) => (!cb.data || Number(cb.len) === 0) ? Buffer.alloc(0)
  : Buffer.from(koffi.decode(cb.data, 'uint8_t', Number(cb.len)));
function consume(r) { const out = b(r.buf); fn.bufFree(r.buf); return out; }
function kp(k) { const pub = b(k.public_key), sec = b(k.secret_key); fn.kpFree(k); return { pub, sec }; }
const eq = (x, y) => Buffer.compare(x, y) === 0;
let pass = 0, fail = 0;
const ck = (label, ok) => { console.log(`  ${ok ? '✓' : '✗'} ${label}`); ok ? pass++ : fail++; };

if (fn.init() !== 0) throw new Error('init failed');
console.log(`CryptoLib ${fn.version()} — Node full showcase\n`);
const abc = Buffer.from('abc'), msg = Buffer.from('secret payload');

console.log('HASHING');
ck('SHA-256(abc) KAT', consume(fn.sha256(abc, 3)).toString('hex') === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
ck('SHA-512', consume(fn.sha512(abc, 3)).length === 64);
ck('BLAKE2b', consume(fn.blake2b(abc, 3, null, 0)).length === 64);
ck('BLAKE3', consume(fn.blake3(abc, 3, 32)).length === 32);
const hk = consume(fn.symKeygen());
const mac = consume(fn.hmac256(abc, 3, hk, hk.length));
ck('HMAC-SHA256 verify', fn.hmac256v(abc, 3, mac, mac.length, hk, hk.length) === 1);
ck('HKDF derive', consume(fn.hkdf(hk, hk.length, null, 0, null, 0, 32)).length === 32);
const phc = consume(fn.argonHash('hunter2', 2, 67108864)).toString('latin1').replace(/\0+$/, '');
ck('Argon2id PHC verify', fn.argonVerify('hunter2', phc) === 1);

console.log('\nSYMMETRIC');
const sk = consume(fn.symKeygen());
const xct = consume(fn.xEnc(msg, msg.length, sk, sk.length, null, 0));
ck('XChaCha20 round-trip', eq(consume(fn.xDec(xct, xct.length, sk, sk.length, null, 0)), msg));
if (fn.aesAvail() === 1) {
  const act = consume(fn.aesEnc(msg, msg.length, sk, sk.length, null, 0));
  ck('AES-256-GCM round-trip', eq(consume(fn.aesDec(act, act.length, sk, sk.length, null, 0)), msg));
} else console.log('    AES-256-GCM unavailable');

console.log('\nASYMMETRIC');
const ed = kp(fn.edKeygen());
const sig = consume(fn.edSign(abc, 3, ed.sec, ed.sec.length));
ck('Ed25519 sign/verify', fn.edVerify(abc, 3, sig, sig.length, ed.pub, ed.pub.length) === 1);
const xa = kp(fn.xKeygen()), xb = kp(fn.xKeygen());
ck('X25519 ECDH', eq(consume(fn.xShared(xa.sec, xa.sec.length, xb.pub, xb.pub.length)),
                     consume(fn.xShared(xb.sec, xb.sec.length, xa.pub, xa.pub.length))));
const r = kp(fn.boxKeygen()), s = kp(fn.boxKeygen());
const bct = consume(fn.boxEnc(msg, msg.length, r.pub, r.pub.length, s.sec, s.sec.length));
ck('Box round-trip', eq(consume(fn.boxDec(bct, bct.length, s.pub, s.pub.length, r.sec, r.sec.length)), msg));
const sct = consume(fn.sealEnc(msg, msg.length, r.pub, r.pub.length));
ck('SealedBox round-trip', eq(consume(fn.sealDec(sct, sct.length, r.pub, r.pub.length, r.sec, r.sec.length)), msg));

console.log('\nVAULTS');
const vk = consume(fn.random(32));
const vault = fn.vCreate(vk, vk.length, 0);
const e1 = [null];
const pkt = fn.vSeal(vault, msg, msg.length, 'ctx', e1);
ck('SecureVault round-trip', eq(consume(fn.vOpen(vault, pkt, 'ctx')), msg));
fn.pktFree(pkt); fn.vFree(vault);
const alice = fn.bundleGen(), bob = fn.bundleGen();
const bobBoxPub = b(bob.box_public), aliceSignPub = b(alice.sign_public);
const e2 = [null];
const apkt = fn.avSeal(alice, bobBoxPub, bobBoxPub.length, msg, msg.length, 'ctx', e2);
ck('AsymmetricVault round-trip', eq(consume(fn.avOpen(apkt, bob, aliceSignPub, aliceSignPub.length, 'ctx')), msg));
fn.pktFree(apkt); fn.bundleFree(alice); fn.bundleFree(bob);

console.log('\nPOST-QUANTUM');
const kem = kp(fn.kemKeygen(1));
const e3 = [null];
const enc = fn.kemEncaps(kem.pub, kem.pub.length, 1, e3);
const ssE = b(enc.shared_secret), kemCt = b(enc.ciphertext);
ck('ML-KEM-768 encaps/decaps', eq(ssE, consume(fn.kemDecaps(kemCt, kemCt.length, kem.sec, kem.sec.length, 1))));
fn.kemFree(enc);
const hkp = kp(fn.hyKeygen());
const eh = [null];
const henc = fn.hyEncaps(hkp.pub, hkp.pub.length, eh);
const hssE = b(henc.shared_secret), hct = b(henc.ciphertext);
ck('Hybrid X25519+ML-KEM-768 encaps/decaps',
   eq(hssE, consume(fn.hyDecaps(hct, hct.length, hkp.sec, hkp.sec.length))) && hssE.length === 32);
fn.kemFree(henc);
const dsa = kp(fn.dsaKeygen(1));
const dsig = consume(fn.dsaSign(abc, 3, dsa.sec, dsa.sec.length, 1));
ck('ML-DSA-65 sign/verify', fn.dsaVerify(abc, 3, dsig, dsig.length, dsa.pub, dsa.pub.length, 1) === 1);
const slh = kp(fn.slhKeygen(1, 0));
const ssig = consume(fn.slhSign(abc, 3, slh.sec, slh.sec.length, 1, 0));
ck('SLH-DSA-128f sign/verify', fn.slhVerify(abc, 3, ssig, ssig.length, slh.pub, slh.pub.length, 1, 0) === 1);

console.log('\nBLS12-381');
const m1 = Buffer.from('msg-one'), m2 = Buffer.from('msg-two');
const b1 = kp(fn.blsKeygen()), b2 = kp(fn.blsKeygen());
const sig1 = consume(fn.blsSign(m1, m1.length, b1.sec, b1.sec.length));
const sig2 = consume(fn.blsSign(m2, m2.length, b2.sec, b2.sec.length));
ck('BLS sign/verify', fn.blsVerify(m1, m1.length, sig1, sig1.length, b1.pub, b1.pub.length) === 1);
const agg = consume(fn.blsAgg([sig1, sig2], [BigInt(sig1.length), BigInt(sig2.length)], 2));
ck('BLS aggregate-verify (distinct msgs)',
   fn.blsAggVerify([m1, m2], [BigInt(m1.length), BigInt(m2.length)],
                   [b1.pub, b2.pub], [BigInt(b1.pub.length), BigInt(b2.pub.length)], 2, agg, agg.length) === 1);

console.log('\nKEYRING');
const factor = consume(fn.random(32));
const kr = fn.krCreate();
fn.krAddDev(kr, factor, factor.length);
fn.krAddPw(kr, 'cross-device pass', 0);
const blob = consume(fn.krSer(kr));
const e4 = [null];
const kr2 = fn.krDeser(blob, blob.length, e4);
const mDev = consume(fn.krUnlockDev(kr2, factor, factor.length));
const mPass = consume(fn.krUnlockPw(kr2, 'cross-device pass'));
ck(`Keyring device==passphrase master (${Number(fn.krCount(kr))} slots)`, eq(mDev, mPass) && mDev.length === 32);
fn.krFree(kr); fn.krFree(kr2);

console.log(`\nNode showcase ${fail === 0 ? 'OK' : 'FAILED'} (${pass} passed, ${fail} failed)`);
process.exit(fail === 0 ? 0 : 1);
