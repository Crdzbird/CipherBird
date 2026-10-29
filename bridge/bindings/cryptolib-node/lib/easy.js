/*
 * Easy mode: keys with the safe defaults built in, the same classes the Dart
 * packages offer. SymmetricKey encrypts with the key-committing AEAD and
 * stretches passphrases with Argon2id at a SecurityProfile cost; SigningKey
 * and VerifyKey are Ed25519 or the post-quantum hybrid; KemKeyPair is the
 * X25519 + ML-KEM-768 hybrid with one-call public-key encryption. The
 * byte layouts and HKDF labels match the Dart packages exactly, so a blob
 * made here opens there.
 */
'use strict';

const KEM_INFO = Buffer.from('cryptolib/easy/kem/v1');

const toHex = (b) => Buffer.from(b).toString('hex');
const fromHex = (s) => {
  const t = s.startsWith('0x') ? s.slice(2) : s;
  if (t.length % 2 !== 0 || /[^0-9a-fA-F]/.test(t)) throw new TypeError('cipherbird: not a hex string');
  return Buffer.from(t, 'hex');
};
const toBase64 = (b) => Buffer.from(b).toString('base64');
const fromBase64 = (s) => Buffer.from(s, 'base64');
const toBase64Url = (b) => Buffer.from(b).toString('base64url');
const fromBase64Url = (s) => Buffer.from(s, 'base64url');
const utf8Bytes = (s) => Buffer.from(String(s), 'utf8');
const utf8Text = (b) => Buffer.from(b).toString('utf8');

module.exports = (api) => {
  const u8 = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(x));
  const algoOf = (a) => {
    if (a === 'ed25519' || a === api.SignatureAlgorithm.ed25519) return api.SignatureAlgorithm.ed25519;
    if (a === 'hybrid' || a === api.SignatureAlgorithm.hybrid) return api.SignatureAlgorithm.hybrid;
    throw new TypeError('cipherbird: pick a real signature algorithm (ed25519 or hybrid)');
  };
  const cost = (profile) => api.SecurityProfile.params(profile);

  /** A 32-byte symmetric key with the safe choices built in. */
  class SymmetricKey {
    constructor(key) { this._secret = api.Secret.take(u8(key)); }
    /** A fresh random key. */
    static generate() { return new SymmetricKey(api.randomBytes(32)); }
    /** Wrap existing 32-byte key material; copies the bytes. */
    static fromBytes(key) {
      const k = u8(key);
      if (k.length !== 32) throw new RangeError(`cipherbird: a key is exactly 32 bytes, got ${k.length}`);
      return new SymmetricKey(Buffer.from(k));
    }
    static fromHex(hex) { return SymmetricKey.fromBytes(fromHex(hex)); }
    static fromBase64(b64) { return SymmetricKey.fromBytes(fromBase64(b64)); }
    /**
     * Stretch a passphrase (string or bytes) with Argon2id. `salt` must be at
     * least 16 random bytes stored next to the ciphertext; cost comes from
     * `profile` unless `ops` and `memoryBytes` override it.
     */
    static fromPassphrase(passphrase, { salt, profile = api.SecurityProfile.balanced, ops, memoryBytes } = {}) {
      if (!salt || u8(salt).length < 16) throw new RangeError('cipherbird: use at least 16 bytes of salt');
      const p = cost(profile);
      return new SymmetricKey(api.argon2idDerive(passphrase, salt, 32, ops ?? p.argon2Ops, memoryBytes ?? p.argon2Memory));
    }
    static fromPassphraseBytes(passphrase, opts) { return SymmetricKey.fromPassphrase(passphrase, opts); }
    get _key() { return this._secret.bytes; }
    /** A copy of the raw key bytes; wipe it when done. */
    get bytes() { return Buffer.from(this._key); }
    get hex() { return toHex(this._key); }
    get base64() { return toBase64(this._key); }
    /** An independent sub-key for `purpose` (HKDF); different purposes never collide. */
    derive(purpose) { return new SymmetricKey(api.hkdfDerive(this._key, { info: utf8Bytes(purpose), outLen: 32 })); }
    /** Encrypt with the key-committing AEAD; `aad` is authenticated, not encrypted. */
    encrypt(plaintext, { aad = null } = {}) { return api.committingEncrypt(plaintext, this._key, aad); }
    /** Decrypt; throws if the key, the data or `aad` do not match. */
    decrypt(ciphertext, { aad = null } = {}) { return api.committingDecrypt(ciphertext, this._key, aad); }
    /** Encrypt a string; returns base64 you can store or send as text. */
    encryptText(text, { aad = null } = {}) { return toBase64(this.encrypt(utf8Bytes(text), { aad: aad == null ? null : utf8Bytes(aad) })); }
    decryptText(b64, { aad = null } = {}) { return utf8Text(this.decrypt(fromBase64(b64), { aad: aad == null ? null : utf8Bytes(aad) })); }
    /** Use this key as a Recipe key source: recipe().withKeySource(key.asKeySource). */
    get asKeySource() { return new api.RawKeySource(this._key); }
    /** Zero the key bytes. The object is unusable afterwards. */
    destroy() { this._secret.wipe(); }
    get isDestroyed() { return this._secret.wiped; }
  }

  /** The public half of a SigningKey. */
  class VerifyKey {
    constructor(publicKey, algorithm) { this.publicKey = Buffer.from(u8(publicKey)); this.algorithm = algoOf(algorithm); }
    static fromBytes(publicKey, { algorithm = 'ed25519' } = {}) { return new VerifyKey(publicKey, algorithm); }
    static fromHex(hex, { algorithm = 'ed25519' } = {}) { return new VerifyKey(fromHex(hex), algorithm); }
    verify(message, signature) {
      return this.algorithm === api.SignatureAlgorithm.hybrid
        ? api.hybridSigVerify(message, signature, this.publicKey)
        : api.ed25519Verify(message, signature, this.publicKey);
    }
    /** Verify a string against a base64 signature from SigningKey.signText. */
    verifyText(message, signatureBase64) { return this.verify(utf8Bytes(message), fromBase64(signatureBase64)); }
    /** Plug into a Recipe: recipe.verifiedWith(key.scheme). */
    get scheme() {
      return this.algorithm === api.SignatureAlgorithm.hybrid
        ? new api.HybridSignature({ publicKey: this.publicKey }) : new api.Ed25519Signature({ publicKey: this.publicKey });
    }
  }

  /** A signing key pair: Ed25519 by default, or the post-quantum hybrid (Ed25519 + ML-DSA-65). */
  class SigningKey {
    constructor(algorithm, pair) { this.algorithm = algoOf(algorithm); this._pair = pair; }
    static generate({ algorithm = 'ed25519' } = {}) {
      const a = algoOf(algorithm);
      return new SigningKey(a, a === api.SignatureAlgorithm.hybrid ? api.hybridSigKeygen() : api.ed25519Keygen());
    }
    /** Wrap existing key bytes (loaded from secure storage). */
    static fromBytes({ secretKey, publicKey, algorithm = 'ed25519' }) {
      return new SigningKey(algorithm, { publicKey: Buffer.from(u8(publicKey)), secretKey: Buffer.from(u8(secretKey)) });
    }
    get publicKey() { return this._pair.publicKey; }
    get secretKey() { return this._pair.secretKey; }
    /** The verification half, safe to hand to anyone. */
    get verifyKey() { return new VerifyKey(this.publicKey, this.algorithm); }
    sign(message) {
      return this.algorithm === api.SignatureAlgorithm.hybrid ? api.hybridSigSign(message, this.secretKey) : api.ed25519Sign(message, this.secretKey);
    }
    /** Sign a string; returns the signature as base64. */
    signText(message) { return toBase64(this.sign(utf8Bytes(message))); }
    verify(message, signature) { return this.verifyKey.verify(message, signature); }
    /** Plug into a Recipe: recipe.signedWith(key.scheme). */
    get scheme() {
      const keys = { secretKey: this.secretKey, publicKey: this.publicKey };
      return this.algorithm === api.SignatureAlgorithm.hybrid ? new api.HybridSignature(keys) : new api.Ed25519Signature(keys);
    }
    /** Zero the secret key. */
    destroy() { api.wipe(this._pair.secretKey); }
  }

  /** A hybrid X25519 + ML-KEM-768 key pair with one-call public-key encryption. */
  class KemKeyPair {
    constructor(pair) { this._pair = pair; }
    static generate() { return new KemKeyPair(api.hybridKemKeygen()); }
    static fromBytes({ publicKey, secretKey }) {
      return new KemKeyPair({ publicKey: Buffer.from(u8(publicKey)), secretKey: Buffer.from(u8(secretKey)) });
    }
    /** Sender side: agree on a key with the owner of `recipientPublicKey`. Returns { ciphertext, key }. */
    static encapsulate(recipientPublicKey) {
      const { ciphertext, sharedSecret } = api.hybridKemEncapsulate(recipientPublicKey);
      const key = new SymmetricKey(api.hkdfDerive(sharedSecret, { info: KEM_INFO, outLen: 32 }));
      api.wipe(sharedSecret);
      return { ciphertext, key };
    }
    /** A self-contained blob only the owner of `recipientPublicKey` can open: len(4 BE) | KEM ciphertext | committing AEAD body. */
    static encryptFor(recipientPublicKey, plaintext, { aad = null } = {}) {
      const { ciphertext, key } = KemKeyPair.encapsulate(recipientPublicKey);
      try {
        const body = key.encrypt(plaintext, { aad });
        const len = Buffer.alloc(4); len.writeUInt32BE(ciphertext.length, 0);
        return Buffer.concat([len, ciphertext, body]);
      } finally { key.destroy(); }
    }
    static encryptTextFor(recipientPublicKey, text, { aad = null } = {}) {
      return toBase64(KemKeyPair.encryptFor(recipientPublicKey, utf8Bytes(text), { aad: aad == null ? null : utf8Bytes(aad) }));
    }
    get publicKey() { return this._pair.publicKey; }
    get secretKey() { return this._pair.secretKey; }
    /** Recipient side: recover the key agreed in KemKeyPair.encapsulate. */
    decapsulate(ciphertext) {
      const ss = api.hybridKemDecapsulate(ciphertext, this.secretKey);
      const key = new SymmetricKey(api.hkdfDerive(ss, { info: KEM_INFO, outLen: 32 }));
      api.wipe(ss);
      return key;
    }
    /** Open a blob made by KemKeyPair.encryptFor for this key pair. */
    decrypt(blob, { aad = null } = {}) {
      const b = u8(blob);
      if (b.length < 4) throw new RangeError('cipherbird: malformed blob');
      const n = b.readUInt32BE(0);
      if (b.length < 4 + n) throw new RangeError('cipherbird: malformed blob');
      const key = this.decapsulate(b.subarray(4, 4 + n));
      try { return key.decrypt(b.subarray(4 + n), { aad }); } finally { key.destroy(); }
    }
    decryptText(b64, { aad = null } = {}) { return utf8Text(this.decrypt(fromBase64(b64), { aad: aad == null ? null : utf8Bytes(aad) })); }
    /** Zero the secret key. The object cannot decapsulate afterwards. */
    destroy() { api.wipe(this._pair.secretKey); }
  }

  const phcString = (raw) => { const end = raw.indexOf(0); return (end < 0 ? raw : raw.subarray(0, end)).toString('utf8'); };

  /** The easy-mode entry points, reachable as cipherbird.easy. */
  const easy = {
    symmetricKey: () => SymmetricKey.generate(),
    symmetricKeyFromPassphrase: (passphrase, opts) => SymmetricKey.fromPassphrase(passphrase, opts),
    symmetricKeyFromPassphraseBytes: (passphrase, opts) => SymmetricKey.fromPassphrase(passphrase, opts),
    signingKey: ({ algorithm = 'ed25519' } = {}) => SigningKey.generate({ algorithm }),
    kemKeyPair: () => KemKeyPair.generate(),
    /** A fresh sealed-messaging Identity (Flagship by default, Fortress for the strongest tier). */
    identity: (tier = api.SealedTier.Flagship) => api.Identity.generate(tier),
    randomBytes: (n) => api.randomBytes(n),
    randomHex: (n) => toHex(api.randomBytes(n)),
    /** An opaque URL-safe random token (session ids, nonces); `bytes` of entropy. */
    token: (bytes = 32) => toBase64Url(api.randomBytes(bytes)),
    /** Hash a password for storage (Argon2id, PHC string); check it later with verifyPassword. */
    hashPassword(password, { profile = api.SecurityProfile.balanced } = {}) {
      const p = cost(profile);
      return phcString(Buffer.from(api.argon2idHashStr(password, p.argon2Ops, p.argon2Memory), 'latin1'));
    },
    hashPasswordBytes(password, opts) { return easy.hashPassword(password, opts); },
    verifyPassword: (password, phc) => api.argon2idVerifyStr(password, phc),
    verifyPasswordBytes: (password, phc) => api.argon2idVerifyStr(password, phc),
    /** SHA-256 of a string, as hex. For anything security-sensitive prefer SigningKey or a MAC. */
    sha256Hex: (text) => toHex(api.sha256(utf8Bytes(text))),
    /** SymmetricKey.fromPassphrase on the worker thread. */
    async symmetricKeyFromPassphraseAsync(passphrase, { salt, profile = api.SecurityProfile.balanced, ops, memoryBytes } = {}) {
      if (!salt || u8(salt).length < 16) throw new RangeError('cipherbird: use at least 16 bytes of salt');
      const p = cost(profile);
      const key = await api.async.argon2idDerive(passphrase, salt, 32, ops ?? p.argon2Ops, memoryBytes ?? p.argon2Memory);
      return new SymmetricKey(key);
    },
    /** hashPassword on the worker thread. */
    async hashPasswordAsync(password, { profile = api.SecurityProfile.balanced } = {}) {
      const p = cost(profile);
      return phcString(Buffer.from(await api.async.argon2idHashStr(password, p.argon2Ops, p.argon2Memory), 'latin1'));
    },
    /** verifyPassword on the worker thread. */
    verifyPasswordAsync: (password, phc) => api.async.argon2idVerifyStr(password, phc),
  };

  return {
    SymmetricKey, SigningKey, VerifyKey, KemKeyPair, SecretBytes: api.Secret, easy,
    toHex, fromHex, toBase64, fromBase64, toBase64Url, fromBase64Url, utf8Bytes, utf8Text,
    /** Compare in constant time; use it for tags, MACs and tokens. */
    constantTimeEquals: (a, b) => api.secureEqual(a, b),
  };
};
