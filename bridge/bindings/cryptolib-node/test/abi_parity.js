/*
 * Every group the Dart packages expose and the Node binding gained for
 * 1.3.0: X-Wing, Suite v2, Session v2, live entropy, the calibrated health
 * report, the entropy policy, keyring hardware slots, the FIPS profile
 * surface, box and sealed box, ML-DSA, the chunked SecretStream helpers and
 * HPKE with a chosen KEM. Also checks that every function in the C header
 * is declared by index.js when the header is reachable (a repository checkout).
 *
 * CIPHERBIRD_LIBRARY=<path> node test/abi_parity.js
 */
'use strict';
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const B = (s) => Buffer.from(s);

ok('header parity: every CRYPTO_API symbol is declared', () => {
  const header = path.join(__dirname, '..', '..', '..', 'cryptolib_c.h');
  if (!fs.existsSync(header)) { console.log('      (header not present, skipped)'); return; }
  const src = fs.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
  const declared = new Set(src.match(/cryptolib_[a-z0-9_]+\(/g).map((m) => m.slice(0, -1)));
  const abi = [...fs.readFileSync(header, 'utf8').matchAll(/^CRYPTO_API[^(]*?\b(cryptolib_[a-z0-9_]+)\s*\(/gm)].map((m) => m[1]);
  const missing = abi.filter((s) => !declared.has(s));
  assert.deepStrictEqual(missing, [], `missing from index.js: ${missing.join(', ')}`);
  assert.ok(abi.length >= 327, `header lists ${abi.length} functions`);
});

ok('X-Wing round trip and seed expansion', () => {
  const bob = c.xwingKeygen();
  assert.strictEqual(bob.publicKey.length, 1216);
  assert.strictEqual(bob.secretKey.length, 32);
  const { ciphertext, sharedSecret } = c.xwingEncapsulate(bob.publicKey);
  assert.strictEqual(ciphertext.length, 1120);
  assert.ok(c.xwingDecapsulate(ciphertext, bob.secretKey).equals(sharedSecret));
  assert.ok(c.xwingKeypairFromSeed(bob.secretKey).publicKey.equals(bob.publicKey));
  assert.throws(() => c.XWing.encapsulate(Buffer.alloc(5)), /cipherbird|X-Wing|key/i);
});

ok('Suite v2 binds the recipient and the aad', () => {
  const bob = c.xwingKeygen(), carol = c.xwingKeygen(), alice = c.hybridSigKeygen();
  const env = c.suite2Seal(B('wire 100 EUR'), bob.publicKey, alice.secretKey, B('ctx'));
  assert.strictEqual(c.suite2SuiteOf(env), c.Suite2Id.xWingSig);
  assert.strictEqual(c.suite2SuiteOf(B('nope')), 0);
  assert.strictEqual(c.suite2Open(env, bob.secretKey, bob.publicKey, alice.publicKey, B('ctx')).toString(), 'wire 100 EUR');
  assert.throws(() => c.suite2Open(env, bob.secretKey, carol.publicKey, alice.publicKey, B('ctx')));
  assert.throws(() => c.suite2Open(env, bob.secretKey, bob.publicKey, alice.publicKey));
});

ok('Session v2 authenticates both ends', () => {
  const alice = c.hybridSigKeygen(), bob = c.hybridSigKeygen(), mallory = c.hybridSigKeygen();
  const prekey = c.Session2.generatePrekey(bob.secretKey);
  assert.strictEqual(c.Session2.verifyPrekey(prekey.publicKey, bob.publicKey).length, 1216);
  assert.throws(() => c.Session2.verifyPrekey(prekey.publicKey, mallory.publicKey));
  const a = c.Session2.initiate(prekey.publicKey, bob.publicKey, alice.publicKey, alice.secretKey);
  const hs = a.handshake();
  assert.ok(c.Session2.claimedInitiator(hs).equals(alice.publicKey));
  assert.throws(() => c.Session2.accept(hs, prekey.publicKey, prekey.secretKey, bob.publicKey, bob.secretKey, mallory.publicKey));
  const bs = c.acceptSession2(hs, prekey.publicKey, prekey.secretKey, bob.publicKey, bob.secretKey, alice.publicKey);
  assert.strictEqual(bs.decrypt(a.encrypt(B('hello'))).toString(), 'hello');
  assert.strictEqual(a.decrypt(bs.encrypt(B('reply'), B('aad')), B('aad')).toString(), 'reply');
  assert.throws(() => a.decrypt(bs.encrypt(B('x'), B('aad'))));
  a.close(); bs.close(); bs.close();
});

ok('live entropy fails closed, credits noise, rejects a blank chunk with a reason', () => {
  const live = c.liveEntropy();
  try {
    assert.throws(() => live.generate(32), /not ready/);
    const blank = live.feed(Buffer.alloc(4096));
    assert.strictEqual(blank.accepted, false);
    assert.strictEqual(blank.rctCutoff, 31);
    assert.match(blank.reason, /mixed in but not credited/);
    const noise = c.randomBytes(8192); noise[0] = 0xA5;
    const good = live.feed(noise, 1);
    assert.ok(good.accepted && good.ready && good.creditedBits > 256);
    assert.ok(!live.generate(32).equals(live.generate(32)));
    const st = live.status();
    assert.strictEqual(st.chunksFed, 2);
    assert.strictEqual(st.chunksAccepted, 1);
    assert.strictEqual(st.reseeds, 1);
    assert.strictEqual(st.lastReason, '');
  } finally { live.close(); live.close(); }
  const perm = c.Rng.live({ minBitsPerByte: 0, requireRct: false, minCreditedBits: 64 });
  try {
    const pb = perm.feed(Buffer.alloc(4096));
    assert.ok(pb.accepted && pb.creditedBits === 0 && !pb.ready);
    assert.ok(perm.feed(c.randomBytes(2048)).ready);
    assert.strictEqual(perm.generate(16).length, 16);
  } finally { perm.close(); }
});

ok('health report v2 carries the cutoffs and a summary; the policy refuses a flat file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cb_health_'));
  try {
    const noisy = path.join(dir, 'noise.bin'); fs.writeFileSync(noisy, c.randomBytes(65536));
    const h = c.assessFileHealth(noisy);
    assert.strictEqual(h.rctCutoff, 31);
    assert.strictEqual(h.sampleBytes, 65536);
    assert.strictEqual(h.floorBitsPerByte, 1.0);
    assert.match(h.summary, /cutoff 31/);
    assert.ok(h.healthy && h.mcvBitsPerByte > 0 && h.aptWindow === 512);
    assert.strictEqual(c.assessFileHealth(noisy, 1 << 20, 7.9).rctCutoff, 5);
    const eh = c.entropyFromFileWithPolicy(noisy, { deterministic: true });
    assert.strictEqual(c.entropySymmetricKey(eh).length, 32);
    c.entropyFree(eh);
    const flat = path.join(dir, 'flat.bin'); fs.writeFileSync(flat, Buffer.alloc(4096));
    assert.throws(() => c.entropyFromFileWithPolicy(flat), /policy floor|repetition/);
    c.entropyFree(c.entropyFromFileWithPolicy(flat, { minBitsPerByte: 0, requireRct: false }));
    assert.throws(() => c.entropyFromFile(path.join(dir, 'missing.bin')), /not found/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

ok('keyring hardware slots round trip through a wrapped factor', () => {
  const kr = c.keyringCreate();
  const factor = c.randomBytes(32);
  c.keyringAddDeviceSlot(kr, factor);
  const hwFactor = c.keyringAddHardwareSlot(kr, B('enclave-key-1'));
  assert.strictEqual(hwFactor.length, 32);
  assert.strictEqual(c.keyringSlotType(kr, 0), c.KeyringSlotType.device);
  assert.strictEqual(c.keyringSlotType(kr, 1), c.KeyringSlotType.hardware);
  assert.strictEqual(c.keyringSlotType(kr, 9), -1);
  const wrapped = c.xchacha20Encrypt(hwFactor, factor);
  assert.ok(c.keyringSetHardwareBlob(kr, 1, wrapped));
  const kr2 = c.keyringDeserialise(c.keyringSerialise(kr));
  const slot = c.keyringHardwareSlot(kr2, 1);
  assert.strictEqual(slot.keyId.toString(), 'enclave-key-1');
  assert.ok(slot.blob.equals(wrapped));
  assert.throws(() => c.keyringHardwareSlot(kr2, 0), /not a hardware slot/);
  const master = c.keyringUnlockWithHardware(kr2, 1, c.xchacha20Decrypt(slot.blob, factor));
  assert.ok(master.equals(c.keyringUnlockWithDevice(kr2, factor)));
  c.keyringFree(kr); c.keyringFree(kr2);
});

ok('the fips layer is bound and absent outside the fips profile', () => {
  assert.strictEqual(c.Fips.available(), false);
  assert.strictEqual(c.fipsStatus().loaded, false);
  assert.throws(() => c.fipsDigest(c.FipsHash.Sha256, B('abc')));
  assert.throws(() => c.Fips.envelopeCreate());
  assert.throws(() => c.Fips.random(16));
  assert.throws(() => c.Fips.init());
});

ok('box, sealed box and ML-DSA', () => {
  const bk = c.boxKeygen(), bk2 = c.boxKeygen();
  assert.strictEqual(c.boxDecrypt(c.boxEncrypt(B('box'), bk2.publicKey, bk.secretKey), bk.publicKey, bk2.secretKey).toString(), 'box');
  assert.strictEqual(c.sealedboxDecrypt(c.sealedboxEncrypt(B('sealed'), bk.publicKey), bk.publicKey, bk.secretKey).toString(), 'sealed');
  const d = c.mlDsaKeygen();
  const sig = c.mlDsaSign(B('m'), d.secretKey);
  assert.ok(c.mlDsaVerify(B('m'), sig, d.publicKey));
  assert.ok(!c.mlDsaVerify(B('x'), sig, d.publicKey));
  const d44 = c.mlDsaKeygen(0);
  assert.ok(c.mlDsaVerify(B('m'), c.mlDsaSign(B('m'), d44.secretKey, 0), d44.publicKey, 0));
});

ok('chunked SecretStream helpers', () => {
  const key = c.symKeygen();
  const se = c.streamEncrypt(key, [B('a'), B('bb'), B('ccc')]);
  assert.strictEqual(se.chunks.length, 3);
  assert.deepStrictEqual(c.streamDecrypt(key, se.header, se.chunks).map(String), ['a', 'bb', 'ccc']);
  assert.throws(() => c.streamDecrypt(c.symKeygen(), se.header, se.chunks));
});

ok('HPKE with X-Wing and ML-KEM-768', () => {
  for (const kem of [c.Hpke.Kem.XWing, c.Hpke.Kem.MlKem768, c.Hpke.Kem.DhkemX25519]) {
    assert.ok(c.Hpke.kemAvailable(kem));
    const bob = c.Hpke.keygenKem(kem);
    const s = c.Hpke.setupSKem(kem, c.Hpke.Kdf.Sha256, c.Hpke.Aead.ChaCha20Poly1305, c.Hpke.Mode.Base, bob.publicKey, B('info'));
    const ct = s.context.seal(B('pq hpke'), B('aad')); s.context.close();
    const r = c.Hpke.setupRKem(kem, c.Hpke.Kdf.Sha256, c.Hpke.Aead.ChaCha20Poly1305, c.Hpke.Mode.Base, s.enc, bob.secretKey, B('info'));
    assert.strictEqual(r.open(ct, B('aad')).toString(), 'pq hpke'); r.close();
    assert.ok(c.Hpke.deriveKeyPairKem(kem, c.randomBytes(64)).publicKey.length > 0);
  }
  assert.throws(() => c.Hpke.setupSKem(c.Hpke.Kem.XWing, c.Hpke.Kdf.Sha256, c.Hpke.Aead.ChaCha20Poly1305, c.Hpke.Mode.Base, Buffer.alloc(3), B('i')));
});

console.log(`\ncipherbird abi parity: OK (${pass} passed)`);
