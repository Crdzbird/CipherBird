/*
 * Domain-grouped entry points, the same namespaces the Dart packages expose
 * on CipherBird: cipherbird.hash, cipherbird.aead, cipherbird.asym and so on.
 * Every method delegates to the flat API, so the two spellings are
 * interchangeable; the namespaces exist so a call site reads by domain.
 */
'use strict';

module.exports = (api) => {
  const hash = {
    blake3Hasher: ({ key = null } = {}) => api.blake3Hasher(key),
    blake2b: (msg, key = null) => api.blake2b(msg, key),
    sha256: (msg) => api.sha256(msg),
    sha512: (msg) => api.sha512(msg),
    hmacSha512: (msg, key) => api.hmacSha512(msg, key),
    hmacSha512Verify: (msg, mac, key) => api.hmacSha512Verify(msg, mac, key),
    argon2idHashStr: (password, { ops = 2, mem = 67108864 } = {}) => api.argon2idHashStr(password, ops, mem),
    argon2idVerifyStr: (password, phc) => api.argon2idVerifyStr(password, phc),
    argon2idDerive: (password, salt, { keyLen = 32, ops = 2, mem = 67108864 } = {}) => api.argon2idDerive(password, salt, keyLen, ops, mem),
    argon2idHashStrBytes: (password, { ops = 2, mem = 67108864 } = {}) => api.argon2idHashStr(password, ops, mem),
    argon2idVerifyStrBytes: (password, phc) => api.argon2idVerifyStr(password, phc),
    argon2idDeriveBytes: (password, salt, { keyLen = 32, ops = 2, mem = 67108864 } = {}) => api.argon2idDerive(password, salt, keyLen, ops, mem),
    blake3: (msg, { outLen = 32 } = {}) => api.blake3(msg, outLen),
    blake3Keyed: (msg, key, { outLen = 32 } = {}) => api.blake3Keyed(msg, key, outLen),
    blake3DeriveKey: (context, ikm, { outLen = 32 } = {}) => api.blake3DeriveKey(context, ikm, outLen),
    hmacSha256: (msg, key) => api.hmacSha256(msg, key),
    hmacSha256Verify: (msg, mac, key) => api.hmacSha256Verify(msg, mac, key),
    hkdfExtract: (ikm, { salt = null } = {}) => api.hkdfExtract(ikm, salt),
    hkdfExpand: (prk, { info = null, outLen = 32 } = {}) => api.hkdfExpand(prk, info, outLen),
    hkdfDerive: (ikm, opts = {}) => api.hkdfDerive(ikm, opts),
    keccak256: (msg) => api.keccak256(msg),
    ripemd160: (msg) => api.ripemd160(msg),
    secureEqual: (a, b) => api.secureEqual(a, b),
    blake2bKeyed: (msg, key = null, { outLen = 32 } = {}) => api.blake2bKeyed(msg, key, outLen),
    blake2bKeyedInto: (out, msg, key = null) => api.blake2bKeyedInto(out, msg, key),
  };

  const aead = {
    symKeygen: () => api.symKeygen(),
    xchacha20Encrypt: (pt, key, aad = null) => api.xchacha20Encrypt(pt, key, aad),
    xchacha20Decrypt: (ct, key, aad = null) => api.xchacha20Decrypt(ct, key, aad),
    aes256gcmEncrypt: (pt, key, aad = null) => api.aes256gcmEncrypt(pt, key, aad),
    aes256gcmDecrypt: (ct, key, aad = null) => api.aes256gcmDecrypt(ct, key, aad),
    aes256gcmAvailable: () => api.aes256gcmAvailable(),
    streamEncrypt: (key, chunks) => api.streamEncrypt(key, chunks),
    streamDecrypt: (key, header, chunks) => api.streamDecrypt(key, header, chunks),
    committingEncrypt: (pt, key, aad = null) => api.committingEncrypt(pt, key, aad),
    committingDecrypt: (ct, key, aad = null) => api.committingDecrypt(ct, key, aad),
  };

  const asym = {
    ed25519Keygen: () => api.ed25519Keygen(),
    ed25519KeygenFromSeed: (seed) => api.ed25519KeygenFromSeed(seed),
    ed25519Sign: (msg, sk) => api.ed25519Sign(msg, sk),
    ed25519Verify: (msg, sig, pk) => api.ed25519Verify(msg, sig, pk),
    x25519Keygen: () => api.x25519Keygen(),
    x25519SharedSecret: (sk, pk) => api.x25519SharedSecret(sk, pk),
    boxKeygen: () => api.boxKeygen(),
    boxEncrypt: (pt, recipientPub, senderSec) => api.boxEncrypt(pt, recipientPub, senderSec),
    boxDecrypt: (ct, senderPub, recipientSec) => api.boxDecrypt(ct, senderPub, recipientSec),
    sealedboxEncrypt: (pt, recipientPub) => api.sealedboxEncrypt(pt, recipientPub),
    sealedboxDecrypt: (ct, recipientPub, recipientSec) => api.sealedboxDecrypt(ct, recipientPub, recipientSec),
  };

  const bls = {
    keygen: () => api.blsKeygen(),
    sign: (msg, sk) => api.blsSign(msg, sk),
    verify: (msg, sig, pk) => api.blsVerify(msg, sig, pk),
    keygenFromIkm: (ikm) => api.blsKeygenFromIkm(ikm),
    aggregate: (sigs) => api.blsAggregate(sigs),
    aggregateVerify: (msgs, pks, agg) => api.blsAggregateVerify(msgs, pks, agg),
  };

  const vault = {
    vaultCreate: (masterKey, { kdfPreset = 0 } = {}) => api.vaultCreate(masterKey, kdfPreset),
    vaultFromEntropy: (entropy, { kdf = 0 } = {}) => api.vaultFromEntropy(entropy, kdf),
    vaultSeal: (v, pt, aad = '') => api.vaultSeal(v, pt, aad),
    vaultSealBoosted: (v, pt, aad, boost) => api.vaultSealBoosted(v, pt, aad, boost),
    vaultOpen: (v, pkt, aad = '') => api.vaultOpen(v, pkt, aad),
    vaultOpenBoosted: (v, pkt, aad, boost) => api.vaultOpenBoosted(v, pkt, aad, boost),
    vaultPublicKey: (v) => api.vaultPublicKey(v),
    packetSerialise: (pkt) => api.packetSerialise(pkt),
    packetDeserialise: (data) => api.packetDeserialise(data),
    vaultFree: (v) => api.vaultFree(v),
    asymBundleGenerate: () => api.asymBundleGenerate(),
    asymVaultSeal: (sender, recipientBoxPub, pt, aad = '') => api.asymVaultSeal(sender, recipientBoxPub, pt, aad),
    asymVaultOpen: (pkt, recipient, senderSignPub, aad = '') => api.asymVaultOpen(pkt, recipient, senderSignPub, aad),
    molecularSeal: (pt, passphrase, { aad = null, ops = 0, mem = 0 } = {}) => api.molecularSeal(pt, passphrase, aad, ops, mem),
    molecularOpen: (env, passphrase, { aad = null } = {}) => api.molecularOpen(env, passphrase, aad),
    molecularSealWithKey: (pt, masterKey, { aad = null } = {}) => api.molecularSealWithKey(pt, masterKey, aad),
    molecularOpenWithKey: (env, masterKey, { aad = null } = {}) => api.molecularOpenWithKey(env, masterKey, aad),
  };

  const keyring = {
    create: () => api.keyringCreate(),
    addDeviceSlot: (kr, factor) => api.keyringAddDeviceSlot(kr, factor),
    addPassphraseSlot: (kr, passphrase, kdf = 0) => api.keyringAddPassphraseSlot(kr, passphrase, kdf),
    addPassphraseSlotBytes: (kr, passphrase, kdf = 0) => api.keyringAddPassphraseSlot(kr, passphrase, kdf),
    slotCount: (kr) => api.keyringSlotCount(kr),
    serialise: (kr) => api.keyringSerialise(kr),
    deserialise: (blob) => api.keyringDeserialise(blob),
    unlockWithDevice: (kr, factor) => api.keyringUnlockWithDevice(kr, factor),
    unlockWithPassphrase: (kr, passphrase) => api.keyringUnlockWithPassphrase(kr, passphrase),
    unlockWithPassphraseBytes: (kr, passphrase) => api.keyringUnlockWithPassphrase(kr, passphrase),
    free: (kr) => api.keyringFree(kr),
    removeSlot: (kr, index) => api.keyringRemoveSlot(kr, index),
    addHardwareSlot: (kr, keyId) => api.keyringAddHardwareSlot(kr, keyId),
    setHardwareBlob: (kr, index, blob) => api.keyringSetHardwareBlob(kr, index, blob),
    slotType: (kr, index) => api.keyringSlotType(kr, index),
    hardwareSlot: (kr, index) => api.keyringHardwareSlot(kr, index),
    unlockWithHardware: (kr, index, factor) => api.keyringUnlockWithHardware(kr, index, factor),
  };

  const entropy = {
    fromFile: (p) => api.entropyFromFile(p),
    fromFileDeterministic: (p) => api.entropyFromFileDeterministic(p),
    fromFiles: (paths) => api.entropyFromFiles(paths),
    fromFilesDeterministic: (paths) => api.entropyFromFilesDeterministic(paths),
    fromFileWithPolicy: (p, opts = {}) => api.entropyFromFileWithPolicy(p, opts),
    fromBytes: (bytes, opts = {}) => api.entropyFromBytes(bytes, opts),
    deriveAll: (h) => api.entropyDeriveAll(h),
    symmetricKey: (h) => api.entropySymmetricKey(h),
    raw: (h) => api.entropyRaw(h),
    boost: (h) => api.entropyBoost(h),
    info: (h) => api.entropyInfo(h),
    asymBundle: (h) => api.entropyAsymBundle(h),
    refresh: (h) => api.entropyRefresh(h),
    free: (h) => api.entropyFree(h),
    keyFromFile: (p) => api.keyFromFile(p),
    keyFromBytes: (bytes) => api.keyFromBytes(bytes),
    sealFromFile: (p, plaintext, aad = '') => api.sealFromFile(p, plaintext, aad),
    openFromFile: (p, pkt, aad = '') => api.openFromFile(p, pkt, aad),
    sealWithBytes: (bytes, plaintext, aad = '') => api.sealWithBytes(bytes, plaintext, aad),
    openWithBytes: (bytes, pkt, aad = '') => api.openWithBytes(bytes, pkt, aad),
    assessFileHealth: (p, { maxBytes = 1 << 20, floorBitsPerByte = 1.0 } = {}) => api.assessFileHealth(p, maxBytes, floorBitsPerByte),
    assessHealthOf: (bytes, { maxBytes = 1 << 20, floorBitsPerByte = 1.0 } = {}) => api.assessHealthOf(bytes, maxBytes, floorBitsPerByte),
  };

  const stego = {
    embed: (coverPath, payload, outputPath) => api.stegoEmbed(coverPath, payload, outputPath),
    extract: (stegoPath) => api.stegoExtract(stegoPath),
    capacity: (coverPath) => api.stegoCapacity(coverPath),
    embedKeyed: (coverPath, payload, outputPath, key) => api.StegoAdvanced.embedKeyed(coverPath, payload, outputPath, key),
    extractKeyed: (stegoPath, key) => api.StegoAdvanced.extractKeyed(stegoPath, key),
    embedEncrypted: (coverPath, plaintext, outputPath, masterKey) => api.StegoAdvanced.embedEncrypted(coverPath, plaintext, outputPath, masterKey),
    extractDecrypt: (stegoPath, masterKey) => api.StegoAdvanced.extractDecrypt(stegoPath, masterKey),
    inspect: (p) => api.StegoAdvanced.inspect(p),
    detectHidden: (p) => api.StegoAdvanced.detectHidden(p),
    contentDigest: (p) => api.StegoAdvanced.contentDigest(p),
    embedBytes: (cover, format, payload) => api.stegoEmbedBytes(cover, format, payload),
    extractBytes: (stego, format) => api.stegoExtractBytes(stego, format),
    capacityOf: (cover, format) => api.stegoCapacityOf(cover, format),
    inspectBytes: (bytes, format) => api.stegoInspectBytes(bytes, format),
    detectHiddenBytes: (bytes, format) => api.stegoDetectHiddenBytes(bytes, format),
    contentDigestOf: (bytes, format) => api.stegoContentDigestOf(bytes, format),
    embedKeyedBytes: (cover, format, payload, key) => api.stegoEmbedKeyedBytes(cover, format, payload, key),
    extractKeyedBytes: (stego, format, key) => api.stegoExtractKeyedBytes(stego, format, key),
    embedEncryptedBytes: (cover, format, plaintext, masterKey) => api.stegoEmbedEncryptedBytes(cover, format, plaintext, masterKey),
    extractDecryptBytes: (stego, format, masterKey) => api.stegoExtractDecryptBytes(stego, format, masterKey),
  };

  const composed = {
    fecEncode: (data, scheme) => api.Composed.fecEncode(data, scheme),
    fecDecode: (data, scheme, originalLength) => api.Composed.fecDecode(data, scheme, originalLength),
    physicalSeal: (o) => api.Composed.physicalSeal(o),
    physicalOpen: (o) => api.Composed.physicalOpen(o),
    imageFactorSeal: (o) => api.Composed.imageFactorSeal(o),
    imageFactorOpen: (o) => api.Composed.imageFactorOpen(o),
    hpkeStegoSeal: (o) => api.Composed.hpkeStegoSeal(o),
    hpkeStegoOpen: (o) => api.Composed.hpkeStegoOpen(o),
    physicalSealBytes: (o) => api.physicalSealBytes(o),
    physicalOpenBytes: (o) => api.physicalOpenBytes(o),
    imageFactorSealBytes: (o) => api.imageFactorSealBytes(o),
    imageFactorOpenBytes: (o) => api.imageFactorOpenBytes(o),
    hpkeStegoSealBytes: (o) => api.hpkeStegoSealBytes(o),
    hpkeStegoOpenBytes: (o) => api.hpkeStegoOpenBytes(o),
  };

  const chain = {
    keccak256: (msg) => api.keccak256(msg),
    ripemd160: (msg) => api.ripemd160(msg),
    secp256k1Keygen: () => api.secp256k1Keygen(),
    secp256k1Pubkey: (sk, { compressed = false } = {}) => api.secp256k1Pubkey(sk, compressed),
    secp256k1Sign: (digest, sk) => api.secp256k1Sign(digest, sk),
    secp256k1Verify: (digest, sig, pk) => api.secp256k1Verify(digest, sig, pk),
    secp256k1Recover: (digest, sig65) => api.secp256k1Recover(digest, sig65),
    evmAddress: (pk) => api.suiteEvmAddress(pk),
  };

  const suite = {
    sealPq: (pt, pk, { aad = null } = {}) => api.suiteSealPq(pt, pk, aad),
    sealPqSntrup: (pt, pk, { aad = null } = {}) => api.suiteSealPqSntrup(pt, pk, aad),
    openPq: (env, sk, { aad = null } = {}) => api.suiteOpenPq(env, sk, aad),
    sealSignedPq: (pt, pk, signerSk, { aad = null } = {}) => api.suiteSealSignedPq(pt, pk, signerSk, aad),
    sealSignedPqSntrup: (pt, pk, signerSk, { aad = null } = {}) => api.suiteSealSignedPqSntrup(pt, pk, signerSk, aad),
    openSignedPq: (env, sk, signerPk, { aad = null } = {}) => api.suiteOpenSignedPq(env, sk, signerPk, aad),
    sealWithFile: (pt, p, { aad = null } = {}) => api.suiteSealWithFile(pt, p, aad),
    openWithFile: (env, p, { aad = null } = {}) => api.suiteOpenWithFile(env, p, aad),
    sealWithKeyringDevice: (pt, kr, factor, { aad = null } = {}) => api.suiteSealWithKeyringDevice(pt, kr, factor, aad),
    openWithKeyringDevice: (env, kr, factor, { aad = null } = {}) => api.suiteOpenWithKeyringDevice(env, kr, factor, aad),
    sealWithKeyringPassphrase: (pt, kr, pw, { aad = null } = {}) => api.suiteSealWithKeyringPassphrase(pt, kr, pw, aad),
    openWithKeyringPassphrase: (env, kr, pw, { aad = null } = {}) => api.suiteOpenWithKeyringPassphrase(env, kr, pw, aad),
    evmAddress: (pk) => api.suiteEvmAddress(pk),
    sealThreshold: (pt, n, k, { aad = null } = {}) => api.suiteSealThreshold(pt, n, k, aad),
    openThreshold: (env, shares, { aad = null } = {}) => api.suiteOpenThreshold(env, shares, aad),
    seal2: (pt, recipientKemPublic, signerSigSecret, { aad = null, suite: id = api.Suite2Id.xWingSig } = {}) =>
      api.suite2Seal(pt, recipientKemPublic, signerSigSecret, aad, id),
    open2: (env, recipientKemSecret, recipientKemPublic, signerSigPublic, { aad = null } = {}) =>
      api.suite2Open(env, recipientKemSecret, recipientKemPublic, signerSigPublic, aad),
    suiteOf: (env) => api.suite2SuiteOf(env),
  };

  const sealed = {
    newIdentity: (tier = api.SealedTier.Flagship) => api.Identity.generate(tier),
    inspect: (env) => api.sealedInspect(env),
    addressedTo: (env, recipientPublic) => api.sealedAddressedTo(env, recipientPublic),
    seal: (tier, pt, recipientPublic, senderSecret, opts = null) =>
      new api.Identity(tier, null, null, null, senderSecret).seal(pt, recipientPublic, opts),
    open: (tier, env, recipientSecret, recipientPublic, senderPublic, opts = null) =>
      new api.Identity(tier, recipientPublic, recipientSecret, null, null).open(env, senderPublic, opts),
    sealerBegin: (tier, recipientPublic, senderSecret, opts = null) =>
      new api.Identity(tier, null, null, null, senderSecret).newStreamSealer(recipientPublic, opts),
    openerBegin: (tier, preamble, recipientSecret, recipientPublic, senderPublic, opts = null) =>
      new api.Identity(tier, recipientPublic, recipientSecret, null, null).newStreamOpener(preamble, senderPublic, opts),
  };

  const session = {
    generateSessionPrekey: () => api.Session.generatePrekey(),
    initiateSession: (responderPrekeyPublic) => api.Session.initiate(responderPrekeyPublic),
    acceptSession: (handshake, prekeyPublic, prekeySecret) => api.Session.accept(handshake, prekeyPublic, prekeySecret),
    generateSession2Prekey: (responderSigSecret) => api.Session2.generatePrekey(responderSigSecret),
    verifySession2Prekey: (bundle, responderSigPublic) => api.Session2.verifyPrekey(bundle, responderSigPublic),
    claimedSession2Initiator: (handshake) => api.Session2.claimedInitiator(handshake),
    initiateSession2: (...a) => api.Session2.initiate(...a),
    acceptSession2: (...a) => api.Session2.accept(...a),
  };

  const pq = {
    mlKem: {
      keygen: (level = 1) => api.mlKemKeygen(level),
      encapsulate: (pk, level = 1) => api.mlKemEncapsulate(pk, level),
      decapsulate: (ct, sk, level = 1) => api.mlKemDecapsulate(ct, sk, level),
    },
    mlDsa: {
      keygen: (level = 1) => api.mlDsaKeygen(level),
      sign: (msg, sk, level = 1) => api.mlDsaSign(msg, sk, level),
      verify: (msg, sig, pk, level = 1) => api.mlDsaVerify(msg, sig, pk, level),
    },
    slhDsa: {
      keygen: (level = 0, hash = 0) => api.slhDsaKeygen(level, hash),
      sign: (msg, sk, level = 0, hash = 0) => api.slhDsaSign(msg, sk, level, hash),
      verify: (msg, sig, pk, level = 0, hash = 0) => api.slhDsaVerify(msg, sig, pk, level, hash),
    },
    hybridKem: {
      keygen: () => api.hybridKemKeygen(),
      encapsulate: (pk) => api.hybridKemEncapsulate(pk),
      decapsulate: (ct, sk) => api.hybridKemDecapsulate(ct, sk),
    },
    hybridSig: {
      keygen: () => api.hybridSigKeygen(),
      sign: (msg, sk) => api.hybridSigSign(msg, sk),
      verify: (msg, sig, pk) => api.hybridSigVerify(msg, sig, pk),
    },
    sntrup: {
      keygen: () => api.sntrupX25519Keygen(),
      encapsulate: (pk) => api.sntrupX25519Encapsulate(pk),
      decapsulate: (ct, sk) => api.sntrupX25519Decapsulate(ct, sk),
    },
    xwing: api.XWing,
  };

  const tokens = {
    paseto: api.Paseto,
    cb1: api.Cb1,
    v4LocalEncrypt: (...a) => api.Paseto.v4LocalEncrypt(...a),
    v4LocalDecrypt: (...a) => api.Paseto.v4LocalDecrypt(...a),
    cb1LocalEncrypt: (...a) => api.Cb1.localEncrypt(...a),
    cb1LocalDecrypt: (...a) => api.Cb1.localDecrypt(...a),
    cb1PublicSign: (...a) => api.Cb1.publicSign(...a),
    cb1PublicVerify: (...a) => api.Cb1.publicVerify(...a),
  };

  const channel = {
    create: ({ initiator, staticPublic, staticSecret, prologue = null }) => api.noise(initiator, staticPublic, staticSecret, prologue),
  };

  return {
    hash, aead, asym, bls, vault, keyring, entropy, stego, composed, chain, suite, sealed, session, pq, channel, tokens,
    frost: api.Frost, hpke: api.Hpke, ecvrf: api.Ecvrf, bbs: api.Bbs, oprf: api.Oprf, opaque: api.Opaque, rng: api.Rng, fips: api.Fips,
  };
};
