/*
 * The domain namespaces reach the same engine as the flat API and carry
 * every member the Dart facades expose.
 *
 * CIPHERBIRD_LIBRARY=<path> node test/namespaces.js
 */
'use strict';
const assert = require('node:assert');
const c = require('..');

let pass = 0;
const ok = (label, f) => { f(); pass++; console.log(`  ok  ${label}`); };
const B = (s) => Buffer.from(s);

const EXPECTED = {
  hash: ['blake3Hasher', 'blake2b', 'sha256', 'sha512', 'hmacSha512', 'hmacSha512Verify', 'argon2idHashStr', 'argon2idVerifyStr',
    'argon2idDerive', 'blake3', 'blake3Keyed', 'blake3DeriveKey', 'hmacSha256', 'hmacSha256Verify', 'hkdfExtract', 'hkdfExpand', 'hkdfDerive',
    'argon2idHashStrBytes', 'argon2idVerifyStrBytes', 'argon2idDeriveBytes'],
  aead: ['symKeygen', 'xchacha20Encrypt', 'xchacha20Decrypt', 'aes256gcmEncrypt', 'aes256gcmDecrypt', 'aes256gcmAvailable',
    'streamEncrypt', 'streamDecrypt', 'committingEncrypt', 'committingDecrypt'],
  asym: ['ed25519Keygen', 'ed25519KeygenFromSeed', 'ed25519Sign', 'ed25519Verify', 'x25519Keygen', 'x25519SharedSecret',
    'boxKeygen', 'boxEncrypt', 'boxDecrypt', 'sealedboxEncrypt', 'sealedboxDecrypt'],
  bls: ['keygen', 'sign', 'verify', 'keygenFromIkm', 'aggregate', 'aggregateVerify'],
  vault: ['vaultCreate', 'vaultFromEntropy', 'vaultSeal', 'vaultSealBoosted', 'vaultOpen', 'vaultOpenBoosted', 'vaultPublicKey',
    'packetSerialise', 'packetDeserialise', 'vaultFree', 'asymBundleGenerate', 'asymVaultSeal', 'asymVaultOpen',
    'molecularSeal', 'molecularOpen', 'molecularSealWithKey', 'molecularOpenWithKey'],
  keyring: ['create', 'addDeviceSlot', 'addPassphraseSlot', 'addPassphraseSlotBytes', 'slotCount', 'serialise', 'deserialise',
    'unlockWithDevice', 'unlockWithPassphrase', 'unlockWithPassphraseBytes', 'free', 'removeSlot',
    'addHardwareSlot', 'setHardwareBlob', 'slotType', 'hardwareSlot', 'unlockWithHardware'],
  entropy: ['fromFile', 'fromFileDeterministic', 'fromFiles', 'fromFilesDeterministic', 'deriveAll', 'symmetricKey', 'raw', 'boost',
    'info', 'asymBundle', 'refresh', 'free', 'keyFromFile', 'sealFromFile', 'openFromFile', 'assessFileHealth',
    'fromFileWithPolicy', 'fromBytes', 'keyFromBytes', 'sealWithBytes', 'openWithBytes', 'assessHealthOf'],
  stego: ['embed', 'extract', 'capacity', 'embedKeyed', 'extractKeyed', 'embedEncrypted', 'extractDecrypt', 'inspect', 'detectHidden',
    'contentDigest', 'embedBytes', 'extractBytes', 'capacityOf', 'inspectBytes', 'detectHiddenBytes', 'contentDigestOf',
    'embedKeyedBytes', 'extractKeyedBytes', 'embedEncryptedBytes', 'extractDecryptBytes'],
  composed: ['fecEncode', 'fecDecode', 'physicalSeal', 'physicalOpen', 'imageFactorSeal', 'imageFactorOpen', 'hpkeStegoSeal', 'hpkeStegoOpen',
    'physicalSealBytes', 'physicalOpenBytes', 'imageFactorSealBytes', 'imageFactorOpenBytes', 'hpkeStegoSealBytes', 'hpkeStegoOpenBytes'],
  chain: ['keccak256', 'ripemd160', 'secp256k1Keygen', 'secp256k1Pubkey', 'secp256k1Sign', 'secp256k1Verify', 'secp256k1Recover'],
  suite: ['sealPq', 'sealPqSntrup', 'openPq', 'sealSignedPq', 'sealSignedPqSntrup', 'openSignedPq', 'sealWithFile', 'openWithFile',
    'sealWithKeyringDevice', 'openWithKeyringDevice', 'sealWithKeyringPassphrase', 'openWithKeyringPassphrase', 'evmAddress',
    'sealThreshold', 'openThreshold'],
  sealed: ['newIdentity', 'inspect', 'addressedTo', 'seal', 'open', 'sealerBegin', 'openerBegin'],
  session: ['generateSessionPrekey', 'initiateSession', 'acceptSession', 'generateSession2Prekey', 'verifySession2Prekey',
    'claimedSession2Initiator', 'initiateSession2', 'acceptSession2'],
  frost: ['keygen', 'commit', 'commitWithNonces', 'sign', 'aggregate', 'verify', 'verifyShare'],
  hpke: ['keygen', 'deriveKeyPair', 'setupS', 'setupR', 'sealBase', 'openBase', 'kemAvailable', 'keygenKem', 'deriveKeyPairKem', 'setupSKem', 'setupRKem'],
  ecvrf: ['keygen', 'publicKey', 'prove', 'proofToHash', 'verify'],
  bbs: ['keygen', 'skToPk', 'sign', 'verify', 'proofGen', 'proofVerify', 'commitWithNym', 'blindSignWithNym', 'finalizeNymSecrets',
    'calculatePseudonym', 'proofGenWithPseudonym', 'proofVerifyWithPseudonym', 'blindCommit', 'blindSign', 'verifyBlindSign',
    'hashToScalar', 'randomScalar'],
  oprf: ['deriveKeyPair', 'blind', 'blindWithScalar', 'blindEvaluate', 'finalize', 'evaluate'],
  opaque: ['registrationRequest', 'registrationResponse', 'finalizeRequest', 'clientInit', 'serverRespond', 'clientFinish', 'serverFinish'],
  rng: ['bytes', 'drbg', 'fortuna', 'live'],
  pq: ['mlKem', 'mlDsa', 'slhDsa', 'hybridKem', 'hybridSig', 'sntrup', 'xwing'],
  channel: ['create'],
  fips: ['available', 'init', 'status', 'digest', 'hmac', 'hmacVerify', 'hkdf', 'pbkdf2', 'random', 'aesGcmEncrypt', 'aesGcmDecrypt',
    'p256Keygen', 'p256Ecdh', 'p256Sign', 'p256Verify', 'p256PublicKey', 'hpkeP256Seal', 'hpkeP256Open', 'envelopeCreate', 'envelopeDeserialise'],
  easy: ['symmetricKey', 'symmetricKeyFromPassphrase', 'signingKey', 'kemKeyPair', 'identity', 'randomBytes', 'randomHex', 'token',
    'hashPassword', 'verifyPassword', 'sha256Hex', 'symmetricKeyFromPassphraseAsync', 'hashPasswordAsync', 'verifyPasswordAsync'],
};

ok('every namespace carries the members the Dart facades expose', () => {
  for (const [ns, members] of Object.entries(EXPECTED)) {
    assert.ok(c[ns], `namespace ${ns}`);
    const missing = members.filter((m) => c[ns][m] === undefined);
    assert.deepStrictEqual(missing, [], `${ns} is missing ${missing.join(', ')}`);
  }
});

ok('hash, aead and asym namespaces', () => {
  assert.strictEqual(c.hash.sha256(B('abc')).toString('hex'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.strictEqual(c.hash.blake3(B('x'), { outLen: 64 }).length, 64);
  assert.ok(c.hash.hmacSha256Verify(B('m'), c.hash.hmacSha256(B('m'), B('k'.repeat(32))), B('k'.repeat(32))));
  assert.strictEqual(c.hash.hkdfDerive(B('ikm'), { info: B('i'), outLen: 16 }).length, 16);
  const key = c.aead.symKeygen();
  assert.strictEqual(c.aead.committingDecrypt(c.aead.committingEncrypt(B('p'), key, B('a')), key, B('a')).toString(), 'p');
  const se = c.aead.streamEncrypt(key, [B('1'), B('2')]);
  assert.deepStrictEqual(c.aead.streamDecrypt(key, se.header, se.chunks).map(String), ['1', '2']);
  const ed = c.asym.ed25519Keygen();
  assert.ok(c.asym.ed25519Verify(B('m'), c.asym.ed25519Sign(B('m'), ed.secretKey), ed.publicKey));
  const a = c.asym.x25519Keygen(), b = c.asym.x25519Keygen();
  assert.ok(c.asym.x25519SharedSecret(a.secretKey, b.publicKey).equals(c.asym.x25519SharedSecret(b.secretKey, a.publicKey)));
});

ok('vault, keyring, chain and suite namespaces', () => {
  const v = c.vault.vaultCreate(c.randomBytes(32));
  const pkt = c.vault.vaultSeal(v, B('vaulted'), 'aad');
  assert.strictEqual(c.vault.vaultOpen(v, c.vault.packetDeserialise(c.vault.packetSerialise(pkt)), 'aad').toString(), 'vaulted');
  c.vault.vaultFree(v);
  const env = c.vault.molecularSealWithKey(B('m'), c.randomBytes(32).fill(7), { aad: B('x') });
  assert.strictEqual(c.vault.molecularOpenWithKey(env, Buffer.alloc(32, 7), { aad: B('x') }).toString(), 'm');
  const kr = c.keyring.create();
  const factor = c.randomBytes(32);
  c.keyring.addDeviceSlot(kr, factor);
  assert.strictEqual(c.keyring.slotCount(kr), 1);
  assert.strictEqual(c.keyring.slotType(kr, 0), c.KeyringSlotType.device);
  assert.strictEqual(c.keyring.unlockWithDevice(kr, factor).length, 32);
  c.keyring.free(kr);
  const s = c.chain.secp256k1Keygen();
  const digest = c.chain.keccak256(B('tx'));
  const sig = c.chain.secp256k1Sign(digest, s.secretKey);
  assert.ok(c.chain.secp256k1Verify(digest, sig.subarray(0, 64), s.publicKey));
  assert.ok(c.chain.secp256k1Recover(digest, sig).equals(s.publicKey));
  assert.strictEqual(c.chain.evmAddress(s.publicKey).length, 20);
  const bob = c.pq.hybridKem.keygen();
  assert.strictEqual(c.suite.openPq(c.suite.sealPq(B('pq'), bob.publicKey, { aad: B('a') }), bob.secretKey, { aad: B('a') }).toString(), 'pq');
  const xw = c.pq.xwing.keygen(), signer = c.pq.hybridSig.keygen();
  const env2 = c.suite.seal2(B('v2'), xw.publicKey, signer.secretKey);
  assert.strictEqual(c.suite.suiteOf(env2), c.Suite2Id.xWingSig);
  assert.strictEqual(c.suite.open2(env2, xw.secretKey, xw.publicKey, signer.publicKey).toString(), 'v2');
  const thr = c.suite.sealThreshold(B('t'), 3, 2);
  assert.strictEqual(c.suite.openThreshold(thr.envelope, thr.shares.slice(1)).toString(), 't');
});

ok('sealed, session, channel and pq namespaces', () => {
  const alice = c.sealed.newIdentity(), bob = c.sealed.newIdentity();
  const env = c.sealed.seal(c.SealedTier.Flagship, B('sealed'), bob.recipientPublic, alice.senderSecret, { aad: B('a') });
  assert.ok(c.sealed.addressedTo(env, bob.recipientPublic));
  assert.strictEqual(c.sealed.inspect(env).streaming, false);
  assert.strictEqual(c.sealed.open(c.SealedTier.Flagship, env, bob.recipientSecret, bob.recipientPublic, alice.senderPublic, { aad: B('a') }).toString(), 'sealed');
  const sealer = c.sealed.sealerBegin(c.SealedTier.Flagship, bob.recipientPublic, alice.senderSecret);
  const preamble = sealer.preamble();
  const c1 = sealer.push(B('chunk'));
  const fin = sealer.finalize();
  sealer.close();
  const opener = c.sealed.openerBegin(c.SealedTier.Flagship, preamble, bob.recipientSecret, bob.recipientPublic, alice.senderPublic);
  assert.strictEqual(opener.pull(c1).plaintext.toString(), 'chunk');
  opener.pull(fin.ciphertext);
  assert.ok(opener.finalize(fin.trailer));
  opener.close();
  const pre = c.session.generateSessionPrekey();
  const init = c.session.initiateSession(pre.publicKey);
  const resp = c.session.acceptSession(init.handshake(), pre.publicKey, pre.secretKey);
  assert.strictEqual(resp.decrypt(init.encrypt(B('s1'))).toString(), 's1');
  init.close(); resp.close();
  const ka = c.asym.x25519Keygen(), kb = c.asym.x25519Keygen();
  const na = c.channel.create({ initiator: true, staticPublic: ka.publicKey, staticSecret: ka.secretKey });
  const nb = c.channel.create({ initiator: false, staticPublic: kb.publicKey, staticSecret: kb.secretKey });
  nb.readMessage(na.writeMessage()); na.readMessage(nb.writeMessage()); nb.readMessage(na.writeMessage());
  na.split(); nb.split();
  assert.strictEqual(nb.decrypt(na.encrypt(B('noise'))).toString(), 'noise');
  na.close(); nb.close();
  const d = c.pq.mlDsa.keygen(2);
  assert.ok(c.pq.mlDsa.verify(B('m'), c.pq.mlDsa.sign(B('m'), d.secretKey, 2), d.publicKey, 2));
  const k = c.pq.mlKem.keygen(0);
  const e = c.pq.mlKem.encapsulate(k.publicKey, 0);
  assert.ok(c.pq.mlKem.decapsulate(e.ciphertext, k.secretKey, 0).equals(e.sharedSecret));
  const sn = c.pq.sntrup.keygen();
  const en = c.pq.sntrup.encapsulate(sn.publicKey);
  assert.ok(c.pq.sntrup.decapsulate(en.ciphertext, sn.secretKey).equals(en.sharedSecret));
  assert.strictEqual(c.rng.bytes(8).length, 8);
  assert.strictEqual(c.fips.available(), false);
});

console.log(`\ncipherbird namespaces: OK (${pass} passed)`);
