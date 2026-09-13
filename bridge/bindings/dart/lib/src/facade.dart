part of '../cryptolib_ffi.dart';

// ── Grouped API ──────────────────────────────────────────────────────────────
// The full surface is ~250 operations. Reaching them all from one flat object
// makes autocomplete useless, so each domain is also reachable through a named
// group: `lib.pq.mlKem.keygen(...)`, `lib.stego.detectHidden(...)`.
//
// These are zero-cost `extension type` views over the same CryptoLib instance —
// no allocation, no indirection. The flat methods remain available, so both
// styles work and neither is deprecated.

/// Hashes, MACs, password hashing and HKDF.
extension type HashApi(CryptoLib _l) {
  /// Incremental BLAKE3; pass a 32-byte [key] for keyed (MAC) mode.
  Blake3Hasher blake3Hasher({Uint8List? key}) => _l.blake3Hasher(key: key);

  /// BLAKE2b-512 hash. key may be empty for unkeyed.
  Uint8List blake2b(Uint8List msg, [Uint8List? key]) => _l.blake2b(msg, key);

  /// SHA-256 hash.
  Uint8List sha256(Uint8List msg) => _l.sha256(msg);

  /// SHA-512 hash.
  Uint8List sha512(Uint8List msg) => _l.sha512(msg);

  /// BLAKE3 hash. [outLen] is the extendable output length in bytes
  /// (defaults to 32). Pass a larger value to use BLAKE3 as an XOF.
  Uint8List blake3(Uint8List msg, {int outLen = 32}) => _l.blake3(msg, outLen: outLen);

  /// BLAKE3 keyed MAC. [key] must be exactly 32 bytes. [outLen] defaults to 32.
  Uint8List blake3Keyed(Uint8List msg, Uint8List key, {int outLen = 32}) => _l.blake3Keyed(msg, key, outLen: outLen);

  /// BLAKE3 key derivation. [context] is a hard-coded, application-unique
  /// domain-separation string; [ikm] is the input key material. [outLen]
  /// defaults to 32.
  Uint8List blake3DeriveKey(String context, Uint8List ikm, {int outLen = 32}) => _l.blake3DeriveKey(context, ikm, outLen: outLen);

  /// HMAC-SHA256. [key] should be >= 32 bytes. Returns a 32-byte tag.
  Uint8List hmacSha256(Uint8List msg, Uint8List key) => _l.hmacSha256(msg, key);

  /// Verify an HMAC-SHA256 tag in constant time. Returns true if valid.
  bool hmacSha256Verify(Uint8List msg, Uint8List mac, Uint8List key) => _l.hmacSha256Verify(msg, mac, key);

  /// HKDF-SHA256 extract: PRK = HMAC(salt, IKM). Pass an empty [salt] for the
  /// all-zero default. Returns a 32-byte pseudorandom key.
  Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) => _l.hkdfExtract(ikm, salt: salt);

  /// HKDF-SHA256 expand: derive [outLen] bytes of output key material from a
  /// pseudorandom key [prk] and optional [info] context.
  Uint8List hkdfExpand(Uint8List prk, {Uint8List? info, int outLen = 32}) => _l.hkdfExpand(prk, info: info, outLen: outLen);

  /// HKDF-SHA256 one-shot (extract + expand): derive [outLen] bytes from [ikm]
  /// with optional [salt] and [info].
  Uint8List hkdfDerive(Uint8List ikm,
      {Uint8List? salt, Uint8List? info, int outLen = 32}) => _l.hkdfDerive(ikm, salt: salt, info: info, outLen: outLen);

  /// HMAC-SHA512.
  Uint8List hmacSha512(Uint8List msg, Uint8List key) => _l.hmacSha512(msg, key);

  /// HMAC-SHA512 verify. Returns true if valid.
  bool hmacSha512Verify(Uint8List msg, Uint8List mac, Uint8List key) => _l.hmacSha512Verify(msg, mac, key);

  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(String password, {int ops = 2, int mem = 67108864}) => _l.argon2idHashStr(password, ops: ops, mem: mem);

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) => _l.argon2idVerifyStr(password, phcStr);

  /// Derive a key from password + salt.
  Uint8List argon2idDerive(String password, Uint8List salt,
      {int keyLen = 32, int ops = 2, int mem = 67108864}) => _l.argon2idDerive(password, salt, keyLen: keyLen, ops: ops, mem: mem);

}

/// Authenticated symmetric encryption, incl. committing and streaming modes.
extension type AeadApi(CryptoLib _l) {
  /// Generate a 32-byte random symmetric key.
  Uint8List symKeygen() => _l.symKeygen();

  /// XChaCha20-Poly1305 encrypt.
  Uint8List xchacha20Encrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) => _l.xchacha20Encrypt(plaintext, key, aad);

  /// XChaCha20-Poly1305 decrypt.
  Uint8List xchacha20Decrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) => _l.xchacha20Decrypt(ciphertext, key, aad);

  /// AES-256-GCM encrypt.
  Uint8List aes256gcmEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) => _l.aes256gcmEncrypt(plaintext, key, aad);

  /// AES-256-GCM decrypt.
  Uint8List aes256gcmDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) => _l.aes256gcmDecrypt(ciphertext, key, aad);

  /// Check if AES-256-GCM is available on this CPU.
  bool aes256gcmAvailable() => _l.aes256gcmAvailable();

  /// Committing AEAD encrypt. Unlike a plain AEAD, the ciphertext binds the
  /// exact key, so it cannot be opened under a second key (no invisible
  /// salamander / partitioning-oracle attack). [key] is 32 bytes.
  Uint8List committingEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) => _l.committingEncrypt(plaintext, key, aad);

  /// Committing AEAD decrypt. Throws if the key/AAD don't match or the
  /// commitment check fails. [key] is 32 bytes.
  Uint8List committingDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) => _l.committingDecrypt(ciphertext, key, aad);

  /// Streaming encrypt: encrypt chunks of data with ordering.
  /// Returns (header, encryptedChunks).
  (Uint8List header, List<Uint8List> chunks) streamEncrypt(Uint8List key, List<Uint8List> plaintextChunks) => _l.streamEncrypt(key, plaintextChunks);

  /// Streaming decrypt: decrypt chunks of data.
  List<Uint8List> streamDecrypt(Uint8List key, Uint8List header, List<Uint8List> ciphertextChunks) => _l.streamDecrypt(key, header, ciphertextChunks);

}

/// X25519 key exchange, Ed25519 signing, boxes and sealed boxes.
extension type AsymApi(CryptoLib _l) {
  /// Generate an Ed25519 signing keypair.
  KeyPairResult ed25519Keygen() => _l.ed25519Keygen();

  /// Generate Ed25519 keypair from a 32-byte seed (deterministic).
  KeyPairResult ed25519KeygenFromSeed(Uint8List seed) => _l.ed25519KeygenFromSeed(seed);

  /// Sign a message. Returns 64-byte detached signature.
  Uint8List ed25519Sign(Uint8List msg, Uint8List secretKey) => _l.ed25519Sign(msg, secretKey);

  /// Verify a detached signature. Returns true if valid.
  bool ed25519Verify(Uint8List msg, Uint8List sig, Uint8List publicKey) => _l.ed25519Verify(msg, sig, publicKey);

  /// Generate an X25519 key agreement keypair.
  KeyPairResult x25519Keygen() => _l.x25519Keygen();

  /// Compute X25519 shared secret (32 bytes).
  Uint8List x25519SharedSecret(Uint8List ourSecret, Uint8List theirPublic) => _l.x25519SharedSecret(ourSecret, theirPublic);

  /// Generate a Box keypair (X25519).
  KeyPairResult boxKeygen() => _l.boxKeygen();

  /// Box encrypt: sender to recipient authenticated encryption.
  Uint8List boxEncrypt(Uint8List plaintext, Uint8List recipientPub, Uint8List senderSec) => _l.boxEncrypt(plaintext, recipientPub, senderSec);

  /// Box decrypt.
  Uint8List boxDecrypt(Uint8List ciphertext, Uint8List senderPub, Uint8List recipientSec) => _l.boxDecrypt(ciphertext, senderPub, recipientSec);

  /// SealedBox encrypt (anonymous sender).
  Uint8List sealedboxEncrypt(Uint8List plaintext, Uint8List recipientPub) => _l.sealedboxEncrypt(plaintext, recipientPub);

  /// SealedBox decrypt.
  Uint8List sealedboxDecrypt(Uint8List ciphertext, Uint8List recipientPub, Uint8List recipientSec) => _l.sealedboxDecrypt(ciphertext, recipientPub, recipientSec);

}

/// BLS12-381 signing, verification and aggregation.
extension type BlsApi(CryptoLib _l) {
  KeyPairResult keygen() => _l.blsKeygen();

  /// Deterministic BLS keygen from input key material. [ikm] must be >= 32
  /// bytes (per IRTF draft-irtf-cfrg-bls-signature KeyGen). Same IKM → same key.
  KeyPairResult keygenFromIkm(Uint8List ikm) => _l.blsKeygenFromIkm(ikm);

  Uint8List sign(Uint8List msg, Uint8List secretKey) => _l.blsSign(msg, secretKey);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey) => _l.blsVerify(msg, sig, publicKey);

  /// Aggregate N BLS signatures (each a 96-byte compressed G2 point) into a
  /// single 96-byte signature. Throws if [sigs] is empty.
  Uint8List aggregate(List<Uint8List> sigs) => _l.blsAggregate(sigs);

  /// Verify an aggregate signature over N (message, public key) pairs in a
  /// single operation. [messages] and [publicKeys] must be the same length and
  /// positionally correspond. Returns true iff every signature is valid.
  bool aggregateVerify(List<Uint8List> messages, List<Uint8List> publicKeys, Uint8List aggSig) => _l.blsAggregateVerify(messages, publicKeys, aggSig);

}

/// Layered vaults: Vault, asymmetric Vault and MolecularVault.
extension type VaultApi(CryptoLib _l) {
  /// Create a vault from a 32-byte master key.
  Pointer<Void> vaultCreate(Uint8List masterKey, {KdfPreset kdfPreset = KdfPreset.interactive}) => _l.vaultCreate(masterKey, kdfPreset: kdfPreset);

  /// Create a vault from an entropy handle.
  Pointer<Void> vaultFromEntropy(Pointer<Void> entropy, {KdfPreset kdf = KdfPreset.interactive}) => _l.vaultFromEntropy(entropy, kdf: kdf);

  /// Seal plaintext through the vault pipeline.
  Packet vaultSeal(Pointer<Void> vault, Uint8List plaintext, String aad) => _l.vaultSeal(vault, plaintext, aad);

  /// Seal with entropy boost (two-factor).
  Packet vaultSealBoosted(Pointer<Void> vault, Uint8List plaintext, String aad, Pointer<Void> boost) => _l.vaultSealBoosted(vault, plaintext, aad, boost);

  /// Open a vault packet.
  Uint8List vaultOpen(Pointer<Void> vault, Packet pkt, String aad) => _l.vaultOpen(vault, pkt, aad);

  /// Open with entropy boost.
  Uint8List vaultOpenBoosted(Pointer<Void> vault, Packet pkt, String aad, Pointer<Void> boost) => _l.vaultOpenBoosted(vault, pkt, aad, boost);

  /// Get the vault's Ed25519 public key.
  Uint8List vaultPublicKey(Pointer<Void> vault) => _l.vaultPublicKey(vault);

  /// Serialise a packet to flat bytes.
  Uint8List packetSerialise(Packet pkt) => _l.packetSerialise(pkt);

  /// Deserialise flat bytes to a packet.
  Packet packetDeserialise(Uint8List data) => _l.packetDeserialise(data);

  /// Free a vault handle.
  void vaultFree(Pointer<Void> vault) => _l.vaultFree(vault);

  /// Generate a full asymmetric key bundle (X25519 + Ed25519).
  AsymBundleResult asymBundleGenerate() => _l.asymBundleGenerate();

  /// Asymmetric vault seal: sender encrypts for recipient with signature.
  Packet asymVaultSeal(AsymBundleResult sender, Uint8List recipientBoxPub, Uint8List plaintext, String aad) => _l.asymVaultSeal(sender, recipientBoxPub, plaintext, aad);

  /// Asymmetric vault open: recipient decrypts and verifies.
  Uint8List asymVaultOpen(Packet pkt, AsymBundleResult recipient, Uint8List senderSignPub, String aad) => _l.asymVaultOpen(pkt, recipient, senderSignPub, aad);

  /// Seal [plaintext] under a [passphrase]. [ops]/[mem] are Argon2id work
  /// factors; pass 0 for either to use the library's SENSITIVE preset. Raise
  /// [mem] toward 1<<30 (1 GiB) to make password guessing far costlier.
  Uint8List molecularSeal(Uint8List plaintext, String passphrase,
      {Uint8List? aad, int ops = 0, int mem = 0}) => _l.molecularSeal(plaintext, passphrase, aad: aad, ops: ops, mem: mem);

  /// Open a passphrase-sealed envelope. Wrong passphrase/AAD or tampering throws.
  Uint8List molecularOpen(Uint8List envelope, String passphrase, {Uint8List? aad}) => _l.molecularOpen(envelope, passphrase, aad: aad);

  /// Seal under a 32-byte full-entropy master key (e.g. from the hybrid KEM).
  Uint8List molecularSealWithKey(Uint8List plaintext, Uint8List masterKey,
      {Uint8List? aad}) => _l.molecularSealWithKey(plaintext, masterKey, aad: aad);

  /// Open a raw-key-sealed envelope.
  Uint8List molecularOpenWithKey(Uint8List envelope, Uint8List masterKey,
      {Uint8List? aad}) => _l.molecularOpenWithKey(envelope, masterKey, aad: aad);

}

/// Envelope encryption with revocable device and passphrase slots.
extension type KeyringApi(CryptoLib _l) {
  /// New keyring with a fresh random master key.
  Pointer<Void> create() => _l.keyringCreate();

  /// Wrap the master key under a >=32-byte hardware factor key.
  bool addDeviceSlot(Pointer<Void> kr, Uint8List factor) => _l.keyringAddDeviceSlot(kr, factor);

  /// Wrap the master key under an Argon2id passphrase. kdf: 0=interactive, 1=sensitive.
  bool addPassphraseSlot(Pointer<Void> kr, String passphrase, KdfPreset kdf) => _l.keyringAddPassphraseSlot(kr, passphrase, kdf);

  /// Number of slots.
  int slotCount(Pointer<Void> kr) => _l.keyringSlotCount(kr);

  /// Remove (revoke) the slot at [index]. Returns true on success, false if the
  /// index is out of range.
  bool removeSlot(Pointer<Void> kr, int index) => _l.keyringRemoveSlot(kr, index);

  /// Serialise the envelope blob (no plaintext key).
  Uint8List serialise(Pointer<Void> kr) => _l.keyringSerialise(kr);

  /// Parse an envelope blob into a (locked) keyring handle (nullptr on error).
  Pointer<Void> deserialise(Uint8List blob) => _l.keyringDeserialise(blob);

  /// Recover the master key with a device factor key.
  Uint8List unlockWithDevice(Pointer<Void> kr, Uint8List factor) => _l.keyringUnlockWithDevice(kr, factor);

  /// Recover the master key with a passphrase.
  Uint8List unlockWithPassphrase(Pointer<Void> kr, String passphrase) => _l.keyringUnlockWithPassphrase(kr, passphrase);

  /// Free a keyring handle.
  void free(Pointer<Void> kr) => _l.keyringFree(kr);

}

/// Media-derived entropy and entropy-source health.
extension type EntropyApi(CryptoLib _l) {
  /// Harvest entropy from a file (LavaRand mode).
  Pointer<Void> fromFile(String path) => _l.entropyFromFile(path);

  /// Harvest entropy from a file (deterministic mode).
  Pointer<Void> fromFileDeterministic(String path) => _l.entropyFromFileDeterministic(path);

  /// Harvest entropy from multiple files (LavaRand mode).
  Pointer<Void> fromFiles(List<String> paths) => _l.entropyFromFiles(paths);

  /// Harvest entropy from multiple files (deterministic mode).
  Pointer<Void> fromFilesDeterministic(List<String> paths) => _l.entropyFromFilesDeterministic(paths);

  /// Derive all 6 domain-separated keys at once.
  DerivedKeysResult deriveAll(Pointer<Void> handle) => _l.entropyDeriveAll(handle);

  /// Derive a 32-byte symmetric key from an entropy handle.
  Uint8List symmetricKey(Pointer<Void> handle) => _l.entropySymmetricKey(handle);

  /// Get the 64-byte raw mixed entropy.
  Uint8List raw(Pointer<Void> handle) => _l.entropyRaw(handle);

  /// Get the 32-byte entropy boost key.
  Uint8List boost(Pointer<Void> handle) => _l.entropyBoost(handle);

  /// Get entropy info.
  EntropyInfoResult info(Pointer<Void> handle) => _l.entropyInfo(handle);

  /// Get a full asymmetric bundle from entropy.
  AsymBundleResult asymBundle(Pointer<Void> handle) => _l.entropyAsymBundle(handle);

  /// Refresh system entropy in-place.
  void refresh(Pointer<Void> handle) => _l.entropyRefresh(handle);

  /// Free an entropy handle.
  void free(Pointer<Void> handle) => _l.entropyFree(handle);

  /// One-liner: get a 32-byte key from any file.
  Uint8List keyFromFile(String path) => _l.keyFromFile(path);

  /// One-liner: encrypt plaintext using a file as the key.
  Packet sealFromFile(String path, String plaintext, String aad) => _l.sealFromFile(path, plaintext, aad);

  /// One-liner: decrypt a packet using a file as the key.
  Uint8List openFromFile(String path, Packet pkt, String aad) => _l.openFromFile(path, pkt, aad);

  /// Assess a media file against the SP 800-90B health tests. [maxBytes] caps the
  /// sample size (0 = default 1 MiB). Use before trusting a file as a key source.
  HealthReport assessFileHealth(String path, [int maxBytes = 0]) => _l.assessFileHealth(path, maxBytes);

}

/// Steganographic embedding, extraction and carrier diagnostics.
extension type StegoApi(CryptoLib _l) {
  /// Embed raw bytes into a media file.
  void embed(String coverPath, Uint8List payload, String outputPath) => _l.stegoEmbed(coverPath, payload, outputPath);

  /// Extract raw bytes from a stego media file.
  Uint8List extract(String stegoPath) => _l.stegoExtract(stegoPath);

  /// Get the steganographic capacity of a cover file (in bytes).
  int capacity(String coverPath) => _l.stegoCapacity(coverPath);

  /// Embed with key-derived whitening (and, for .ppm, block permutation) so no
  /// 'CSTG' signature survives. The same key must be used to [stegoExtractKeyed].
  void embedKeyed(String coverPath, Uint8List payload, String outputPath, Uint8List key) => _l.stegoEmbedKeyed(coverPath, payload, outputPath, key);

  /// Extract a keyed-embedded payload. A wrong key fails fast.
  Uint8List extractKeyed(String stegoPath, Uint8List key) => _l.stegoExtractKeyed(stegoPath, key);

  /// AEAD-seal [plaintext] under a key derived from [masterKey], then hide the
  /// ciphertext (always-encrypt: no cleartext in the carrier). .ppm carrier.
  void embedEncrypted(String coverPath, Uint8List plaintext, String outputPath, Uint8List masterKey) => _l.stegoEmbedEncrypted(coverPath, plaintext, outputPath, masterKey);

  /// Extract and AEAD-open a carrier written by [stegoEmbedEncrypted]. Wrong key
  /// or tampering throws.
  Uint8List extractDecrypt(String stegoPath, Uint8List masterKey) => _l.stegoExtractDecrypt(stegoPath, masterKey);

  /// Inspect a media file's structural validity and whether its content matches
  /// its extension.
  StegoFileInspection inspect(String path) => _l.stegoInspect(path);

  /// 32-byte BLAKE2b of the whole file. Store it and recompute later to detect
  /// ANY change (reference-based tamper detection).
  Uint8List contentDigest(String path) => _l.stegoContentDigest(path);

  /// Heuristic hidden-data probe. See [StegoHiddenDataReport.note] for the
  /// limits — this is an indicator, not proof.
  StegoHiddenDataReport detectHidden(String path) => _l.stegoDetectHidden(path);

}

/// Carriers that combine encryption with concealment, plus FEC.
extension type ComposedApi(CryptoLib _l) {
  /// Two-factor "the photo is the key" seal: [keyMediaPath] is conditioned into
  /// AEAD + stego keys; [plaintext] (binding [aad]) is sealed and hidden in a
  /// SEPARATE [coverPath], written to [outputPath]. Both files are required to open.
  void physicalSeal(String keyMediaPath, Uint8List plaintext, Uint8List aad,
      String coverPath, String outputPath) => _l.physicalSeal(keyMediaPath, plaintext, aad, coverPath, outputPath);

  /// Recover a [physicalSeal] message: reconstruct keys from [keyMediaPath],
  /// extract from [stegoPath], and AEAD-open under [aad].
  Uint8List physicalOpen(String keyMediaPath, Uint8List aad, String stegoPath) => _l.physicalOpen(keyMediaPath, aad, stegoPath);

  /// Forward error correction encode. scheme: 0=None, 1=Repetition-3,
  /// 2=Repetition-5, 3=Hamming(7,4). Trades capacity for bit-error recovery.
  Uint8List fecEncode(Uint8List data, FecScheme scheme) => _l.fecEncode(data, scheme);

  /// Forward error correction decode: recover [originalLen] bytes from [data],
  /// correcting within the scheme's capability. Throws if [data] is too short.
  Uint8List fecDecode(Uint8List data, FecScheme scheme, int originalLen) => _l.fecDecode(data, scheme, originalLen);

  /// Seal [plaintext] (binding [aad]) under OPRF([oprfSecretSeed], the reference
  /// image), hiding the ciphertext in [coverPath] → [outputPath]. Two factors to
  /// open: the OPRF secret AND the exact reference image.
  void imageFactorSeal(Uint8List oprfSecretSeed, String referenceImagePath,
      Uint8List plaintext, Uint8List aad, String coverPath, String outputPath) => _l.imageFactorSeal(oprfSecretSeed, referenceImagePath, plaintext, aad, coverPath, outputPath);

  /// Recover an [imageFactorSeal] message.
  Uint8List imageFactorOpen(Uint8List oprfSecretSeed, String referenceImagePath,
      Uint8List aad, String stegoPath) => _l.imageFactorOpen(oprfSecretSeed, referenceImagePath, aad, stegoPath);

  /// Seal [plaintext] to recipient public key [pkR], hiding the ciphertext in
  /// [coverPath] → [outputPath]. Returns the PUBLIC KEM encapsulation `enc`.
  Uint8List hpkeStegoSeal(Uint8List pkR, Uint8List plaintext, Uint8List aad,
      Uint8List info, String coverPath, String outputPath) => _l.hpkeStegoSeal(pkR, plaintext, aad, info, coverPath, outputPath);

  /// Recover an [hpkeStegoSeal] message with recipient secret [skR] and `enc`.
  Uint8List hpkeStegoOpen(Uint8List skR, Uint8List enc, Uint8List aad,
      Uint8List info, String stegoPath) => _l.hpkeStegoOpen(skR, enc, aad, info, stegoPath);

}

/// EVM and Bitcoin interop primitives.
extension type ChainApi(CryptoLib _l) {
  /// Keccak-256 (ORIGINAL padding, Ethereum). 32-byte digest. NOT SHA3-256.
  /// Used for tx hashing, contract-address derivation, ABI selectors, EIP-55.
  Uint8List keccak256(Uint8List msg) => _l.keccak256(msg);

  /// RIPEMD-160. 20-byte digest. Bitcoin HASH160(x) = ripemd160(sha256(x)).
  Uint8List ripemd160(Uint8List msg) => _l.ripemd160(msg);

  /// secp256k1 keypair: secretKey(32) + publicKey(65 uncompressed, 0x04‖X‖Y).
  KeyPairResult secp256k1Keygen() => _l.secp256k1Keygen();

  /// Derive the public key from a 32-byte secret key.
  /// [compressed] true → 33 bytes (0x02/0x03‖X), false → 65 bytes (0x04‖X‖Y).
  Uint8List secp256k1Pubkey(Uint8List secretKey, {bool compressed = false}) => _l.secp256k1Pubkey(secretKey, compressed: compressed);

  /// Sign a 32-byte [digest] (RFC6979 deterministic, low-S). Returns 65 bytes:
  /// r(32)‖s(32)‖recovery_id(1). The caller hashes first (Ethereum:
  /// keccak256(rlp(tx)); Bitcoin: sha256(sha256(preimage))).
  Uint8List secp256k1Sign(Uint8List digest, Uint8List secretKey) => _l.secp256k1Sign(digest, secretKey);

  /// Verify a 64-byte [sig] (r‖s) over a 32-byte [digest]. [publicKey] is 33 or
  /// 65 bytes. Low-S enforced (EIP-2 / BIP-62). Returns true if valid.
  bool secp256k1Verify(Uint8List digest, Uint8List sig, Uint8List publicKey) => _l.secp256k1Verify(digest, sig, publicKey);

  /// Recover the 65-byte uncompressed public key from a 32-byte [digest] and a
  /// 65-byte recoverable [sig65] (r‖s‖recovery_id). Ethereum's ecrecover.
  Uint8List secp256k1Recover(Uint8List digest, Uint8List sig65) => _l.secp256k1Recover(digest, sig65);

}

/// One-call composed recipes (PQ seal, threshold, file-keyed, keyring-backed).
extension type SuiteApi(CryptoLib _l) {
  /// Post-quantum message: encapsulate to [recipientKemPublic] and seal under
  /// the shared secret. Secure while EITHER X25519 or ML-KEM-768 holds.
  Uint8List sealPq(Uint8List plaintext, Uint8List recipientKemPublic,
          {Uint8List? aad}) => _l.suiteSealPq(plaintext, recipientKemPublic, aad: aad);

  /// Like [suiteSealPq] but with the X25519+sntrup761 hybrid KEM (a different
  /// lattice family). [suiteOpenPq] auto-detects the KEM from the envelope.
  Uint8List sealPqSntrup(Uint8List plaintext, Uint8List recipientKemPublic,
          {Uint8List? aad}) => _l.suiteSealPqSntrup(plaintext, recipientKemPublic, aad: aad);

  /// Open a [suiteSealPq]/[suiteSealPqSntrup] envelope with the recipient's
  /// hybrid-KEM secret key (KEM chosen from the envelope's suite id).
  Uint8List openPq(Uint8List envelope, Uint8List recipientKemSecret,
          {Uint8List? aad}) => _l.suiteOpenPq(envelope, recipientKemSecret, aad: aad);

  /// Flagship: post-quantum confidentiality (hybrid KEM) + post-quantum
  /// authenticity (Ed25519+ML-DSA-65). [suiteOpenSignedPq] returns plaintext
  /// only if the signature verifies.
  Uint8List sealSignedPq(Uint8List plaintext, Uint8List recipientKemPublic,
          Uint8List signerSigSecret, {Uint8List? aad}) => _l.suiteSealSignedPq(plaintext, recipientKemPublic, signerSigSecret, aad: aad);

  /// Flagship with the X25519+sntrup761 hybrid KEM.
  Uint8List sealSignedPqSntrup(Uint8List plaintext, Uint8List recipientKemPublic,
          Uint8List signerSigSecret, {Uint8List? aad}) => _l.suiteSealSignedPqSntrup(plaintext, recipientKemPublic, signerSigSecret, aad: aad);

  /// Decrypt then verify; a signature mismatch throws and yields no plaintext.
  Uint8List openSignedPq(Uint8List envelope, Uint8List recipientKemSecret,
          Uint8List signerSigPublic, {Uint8List? aad}) => _l.suiteOpenSignedPq(envelope, recipientKemSecret, signerSigPublic, aad: aad);

  /// File-as-key: deterministic media entropy from [path] derives the master.
  Uint8List sealWithFile(Uint8List plaintext, String path, {Uint8List? aad}) => _l.suiteSealWithFile(plaintext, path, aad: aad);

  /// Re-derive from the same file and open the envelope.
  Uint8List openWithFile(Uint8List envelope, String path, {Uint8List? aad}) => _l.suiteOpenWithFile(envelope, path, aad: aad);

  /// Keyring-guarded: a device-factor unlock provides the MolecularVault master.
  Uint8List sealWithKeyringDevice(Uint8List plaintext, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) => _l.suiteSealWithKeyringDevice(plaintext, keyring, factorKey, aad: aad);

  Uint8List openWithKeyringDevice(Uint8List envelope, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) => _l.suiteOpenWithKeyringDevice(envelope, keyring, factorKey, aad: aad);

  /// Keyring-guarded via a passphrase slot.
  Uint8List sealWithKeyringPassphrase(Uint8List plaintext,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) => _l.suiteSealWithKeyringPassphrase(plaintext, keyring, passphrase, aad: aad);

  Uint8List openWithKeyringPassphrase(Uint8List envelope,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) => _l.suiteOpenWithKeyringPassphrase(envelope, keyring, passphrase, aad: aad);

  /// EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  Uint8List evmAddress(Uint8List secp256k1PublicKey) => _l.suiteEvmAddress(secp256k1PublicKey);

  /// Threshold (k-of-n): seal under a fresh master, split it into [n] Shamir
  /// shares of which any [k] reconstruct it. Returns the envelope and the [n]
  /// individual share records; distribute the shares, keep the envelope
  /// anywhere. Open with [suiteOpenThreshold] using any `k` of the shares.
  (Uint8List envelope, List<Uint8List> shares) sealThreshold(Uint8List plaintext, int n, int k, {Uint8List? aad}) => _l.suiteSealThreshold(plaintext, n, k, aad: aad);

  /// Reconstruct the master from any k of the shares and open the envelope.
  Uint8List openThreshold(Uint8List envelope, List<Uint8List> shares,
      {Uint8List? aad}) => _l.suiteOpenThreshold(envelope, shares, aad: aad);

}

/// Flagship / Fortress sealed messaging.
extension type SealedApi(CryptoLib _l) {
  /// Generate a party's recipient (KEM) + sender (signature) keypairs.
  Identity identity(SealedTier tier) => _l.newIdentity(tier);

  /// Read an envelope's public header without any key. Null if unrecognizable.
  SealedInfo? inspect(Uint8List envelope) => _l.sealedInspect(envelope);

  /// Whether the envelope is addressed to recipientPublic (fingerprint match).
  bool addressedTo(Uint8List envelope, Uint8List recipientPublic) => _l.sealedAddressedTo(envelope, recipientPublic);

  Uint8List seal(SealedTier tier, Uint8List pt, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? aad, Uint8List? purpose}) => _l.sealedSeal(tier, pt, recipientPublic, senderSecret, aad: aad, purpose: purpose);

  Uint8List open(SealedTier tier, Uint8List envelope, Uint8List recipientSecret,
      Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? aad, Uint8List? purpose}) => _l.sealedOpen(tier, envelope, recipientSecret, recipientPublic, senderPublic, aad: aad, purpose: purpose);

  SealedStreamSealer sealerBegin(SealedTier tier, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? purpose}) => _l.sealedSealerBegin(tier, recipientPublic, senderSecret, purpose: purpose);

  SealedStreamOpener openerBegin(SealedTier tier, Uint8List preamble,
      Uint8List recipientSecret, Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? purpose}) => _l.sealedOpenerBegin(tier, preamble, recipientSecret, recipientPublic, senderPublic, purpose: purpose);

}

/// Forward-secret ratcheting sessions.
extension type SessionApi(CryptoLib _l) {
  /// Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey.
  KeyPairResult generateSessionPrekey() => _l.generateSessionPrekey();

  /// Initiator: start a session to the responder's prekey public key.
  Session initiateSession(Uint8List responderPrekeyPublic) => _l.initiateSession(responderPrekeyPublic);

  /// Responder: accept a handshake with your prekey (public + secret).
  Session acceptSession(Uint8List handshake, Uint8List prekeyPublic, Uint8List prekeySecret) => _l.acceptSession(handshake, prekeyPublic, prekeySecret);

}

/// FROST t-of-n threshold signatures.
extension type FrostApi(CryptoLib _l) {
  /// Trusted-dealer split: any [t] of [n] shares can sign. Share i (0-based) has
  /// FROST identifier i+1. Output verifies with standard Ed25519 verification.
  FrostKeyGen keygen(int n, int t) => _l.frostKeygen(n, t);

  /// Round 1: fresh random nonce pair + public commitment for a share. Keep the
  /// returned nonces secret; publish the commitment.
  (FrostNonces, FrostCommitment) commit(Uint8List shareSecret, int identifier) => _l.frostCommit(shareSecret, identifier);

  /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
  (FrostNonces, FrostCommitment) commitWithNonces(int identifier, Uint8List hiding, Uint8List binding) => _l.frostCommitWithNonces(identifier, hiding, binding);

  /// Round 2: this participant's 32-byte signature share. [commitments] is the
  /// full round-1 set from every participating signer (including self).
  Uint8List sign(int identifier, Uint8List shareSecret, Uint8List groupPublicKey,
      FrostNonces nonces, Uint8List msg, List<FrostCommitment> commitments) => _l.frostSign(identifier, shareSecret, groupPublicKey, nonces, msg, commitments);

  /// Aggregate signature shares into one 64-byte Ed25519 signature.
  Uint8List aggregate(Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments, List<Uint8List> sigShares) => _l.frostAggregate(groupPublicKey, msg, commitments, sigShares);

  /// Verify an aggregate signature with standard Ed25519.
  bool verify(Uint8List msg, Uint8List sig, Uint8List groupPublicKey) => _l.frostVerify(msg, sig, groupPublicKey);

  /// Verify one participant's signature share against its public share.
  bool verifyShare(int identifier, Uint8List publicShare, Uint8List sigShare,
      FrostCommitment commitment, Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments) => _l.frostVerifyShare(identifier, publicShare, sigShare, commitment, groupPublicKey, msg, commitments);

}

/// HPKE (RFC 9180) hybrid public-key encryption.
extension type HpkeApi(CryptoLib _l) {
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult keygen() => _l.hpkeKeygen();

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult deriveKeyPair(Uint8List ikm) => _l.hpkeDeriveKeyPair(ikm);

  /// Sender key schedule (any mode). Returns the KEM encapsulation + context.
  HpkeSender setupS(HpkeKdf kdf, HpkeAead aead, HpkeMode mode, Uint8List recipientPublic, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderSecret}) => _l.hpkeSetupS(kdf, aead, mode, recipientPublic, info, psk: psk, pskId: pskId, senderSecret: senderSecret);

  /// Receiver key schedule (any mode). Returns the established context.
  HpkeContext setupR(HpkeKdf kdf, HpkeAead aead, HpkeMode mode, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderPublic}) => _l.hpkeSetupR(kdf, aead, mode, enc, recipientSecret, info, psk: psk, pskId: pskId, senderPublic: senderPublic);

  /// Single-shot base-mode encryption → (enc, ciphertext).
  (Uint8List, Uint8List) sealBase(HpkeKdf kdf, HpkeAead aead, Uint8List recipientPublic, Uint8List info,
      Uint8List plaintext, {Uint8List? aad}) => _l.hpkeSealBase(kdf, aead, recipientPublic, info, plaintext, aad: aad);

  /// Single-shot base-mode decryption.
  Uint8List openBase(HpkeKdf kdf, HpkeAead aead, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      Uint8List ciphertext, {Uint8List? aad}) => _l.hpkeOpenBase(kdf, aead, enc, recipientSecret, info, ciphertext, aad: aad);

}

/// ECVRF (RFC 9381) verifiable random function.
extension type EcvrfApi(CryptoLib _l) {
  /// ECVRF key pair (pk 32 B, sk = 32-byte seed).
  KeyPairResult keygen() => _l.ecvrfKeygen();

  /// Derive the public key Y = x·B from a 32-byte secret seed.
  Uint8List publicKey(Uint8List secretKey) => _l.ecvrfPublicKey(secretKey);

  /// Prove: returns the 80-byte proof for (sk, alpha).
  Uint8List prove(Uint8List secretKey, Uint8List alpha) => _l.ecvrfProve(secretKey, alpha);

  /// proof_to_hash: returns the 64-byte VRF output beta for a proof.
  Uint8List proofToHash(Uint8List proof) => _l.ecvrfProofToHash(proof);

  /// Verify: returns the 64-byte beta on success; throws if the proof is invalid.
  Uint8List verify(Uint8List publicKey, Uint8List alpha, Uint8List proof) => _l.ecvrfVerify(publicKey, alpha, proof);

}

/// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
extension type BbsApi(CryptoLib _l) {
  /// KeyGen from key material (>= 32 B) + optional key info. Throws on failure.
  KeyPairResult keygen(Uint8List keyMaterial, {Uint8List? keyInfo}) => _l.bbsKeygen(keyMaterial, keyInfo: keyInfo);

  /// Derive the 96-byte public key from a 32-byte secret key.
  Uint8List skToPk(Uint8List secretKey) => _l.bbsSkToPk(secretKey);

  /// Sign a vector of messages → 80-byte signature.
  Uint8List sign(Uint8List secretKey, Uint8List publicKey, Uint8List header, List<Uint8List> messages) => _l.bbsSign(secretKey, publicKey, header, messages);

  /// Verify a signature over a vector of messages.
  bool verify(Uint8List publicKey, Uint8List signature, Uint8List header, List<Uint8List> messages) => _l.bbsVerify(publicKey, signature, header, messages);

  /// Derive a selective-disclosure proof. `messages` is the FULL signed vector;
  /// `disclosedIndexes` (0-based) selects which to reveal.
  Uint8List proofGen(Uint8List publicKey, Uint8List signature, Uint8List header, Uint8List ph,
      List<Uint8List> messages, List<int> disclosedIndexes) => _l.bbsProofGen(publicKey, signature, header, ph, messages, disclosedIndexes);

  /// Verify a selective-disclosure proof against the revealed messages.
  bool proofVerify(Uint8List publicKey, Uint8List proof, Uint8List header, Uint8List ph,
      List<Uint8List> disclosedMessages, List<int> disclosedIndexes) => _l.bbsProofVerify(publicKey, proof, header, ph, disclosedMessages, disclosedIndexes);

  /// Commit to [committedMessages] plus [proverNyms] (secret scalars the issuer
  /// must not learn). Returns (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) commitWithNym(List<Uint8List> committedMessages, List<Uint8List> proverNyms) => _l.bbsCommitWithNym(committedMessages, proverNyms);

  /// Blind-sign over the commitment + signer [messages], folding
  /// [signerNymEntropy] into the last nym slot. Returns an 80-byte signature.
  Uint8List blindSignWithNym(Uint8List secretKey, Uint8List publicKey, Uint8List commitmentWithProof,
      Uint8List header, List<Uint8List> messages, Uint8List signerNymEntropy, int lengthNymVector) => _l.bbsBlindSignWithNym(secretKey, publicKey, commitmentWithProof, header, messages, signerNymEntropy, lengthNymVector);

  /// Finalize nym_secrets = [proverNyms] with the last element +=
  /// [signerNymEntropy]. Returns concatenated 32-byte scalars.
  Uint8List finalizeNymSecrets(List<Uint8List> proverNyms, Uint8List signerNymEntropy) => _l.bbsFinalizeNymSecrets(proverNyms, signerNymEntropy);

  /// Derive the deterministic pseudonym (48-byte compressed G1 point) for a
  /// context from the [nymSecrets].
  Uint8List calculatePseudonym(Uint8List contextId, List<Uint8List> nymSecrets) => _l.bbsCalculatePseudonym(contextId, nymSecrets);

  /// Generate a pseudonym-bound selective-disclosure proof. Returns
  /// (proof, pseudonym). Disclosed index lists are 0-based into the signer and
  /// committed message vectors respectively.
  (Uint8List, Uint8List) proofGenWithPseudonym(Uint8List publicKey, Uint8List signature, Uint8List header,
      Uint8List ph, Uint8List contextId, List<Uint8List> signerMessages, List<Uint8List> committedMessages,
      Uint8List secretProverBlind, List<Uint8List> nymSecrets,
      List<int> disclosedSignerIndexes, List<int> disclosedCommittedIndexes) => _l.bbsProofGenWithPseudonym(publicKey, signature, header, ph, contextId, signerMessages, committedMessages, secretProverBlind, nymSecrets, disclosedSignerIndexes, disclosedCommittedIndexes);

  /// Verify a pseudonym-bound proof. [disclosedMessages]/[disclosedIndexes] are
  /// the COMBINED signer+committed disclosures (committed index j passed as j+L+1).
  bool proofVerifyWithPseudonym(Uint8List publicKey, Uint8List proof, Uint8List header, Uint8List ph,
      Uint8List contextId, Uint8List pseudonym, int L, int lengthNymVector,
      List<Uint8List> disclosedMessages, List<int> disclosedIndexes) => _l.bbsProofVerifyWithPseudonym(publicKey, proof, header, ph, contextId, pseudonym, L, lengthNymVector, disclosedMessages, disclosedIndexes);

  /// Commit to [committedMessages] (which the signer never learns). Returns
  /// (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) blindCommit(List<Uint8List> committedMessages) => _l.bbsBlindCommit(committedMessages);

  /// Blind-sign over the commitment + signer [messages] → 80-byte signature.
  Uint8List blindSign(Uint8List secretKey, Uint8List publicKey, Uint8List commitmentWithProof,
      Uint8List header, List<Uint8List> messages) => _l.bbsBlindSign(secretKey, publicKey, commitmentWithProof, header, messages);

  /// Verify a blind signature over [messages] + [committedMessages] using the
  /// [secretProverBlind] kept from [bbsBlindCommit].
  bool verifyBlindSign(Uint8List publicKey, Uint8List signature, Uint8List header,
      List<Uint8List> messages, List<Uint8List> committedMessages, Uint8List secretProverBlind) => _l.bbsVerifyBlindSign(publicKey, signature, header, messages, committedMessages, secretProverBlind);

  /// Deterministically map (msg, dst) to a canonical scalar in [0, r) — the BBS
  /// hash_to_scalar primitive. Use for a stable per-holder nym seed:
  /// nymSeed = bbsHashToScalar(memberSecret, dst).
  Uint8List hashToScalar(Uint8List msg, Uint8List dst) => _l.bbsHashToScalar(msg, dst);

  /// A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE).
  Uint8List randomScalar() => _l.bbsRandomScalar();

}

/// Oblivious pseudorandom function (RFC 9497).
extension type OprfApi(CryptoLib _l) {
  /// Derive an OPRF key pair from a seed (+ optional info). Throws on failure.
  KeyPairResult deriveKeyPair(Uint8List seed, {Uint8List? info}) => _l.oprfDeriveKeyPair(seed, info: info);

  /// Client: blind an input with a fresh random scalar.
  OprfBlindResult blind(Uint8List input) => _l.oprfBlind(input);

  /// Deterministic blind with a caller-supplied scalar (test vectors).
  OprfBlindResult blindWithScalar(Uint8List input, Uint8List blind) => _l.oprfBlindWithScalar(input, blind);

  /// Server: evaluate a blinded element under the secret key.
  Uint8List blindEvaluate(Uint8List secretKey, Uint8List blindedElement) => _l.oprfBlindEvaluate(secretKey, blindedElement);

  /// Client: unblind the evaluated element → 64-byte PRF output.
  Uint8List finalize(Uint8List input, Uint8List blind, Uint8List evaluatedElement) => _l.oprfFinalize(input, blind, evaluatedElement);

  /// Server one-shot: compute the PRF output directly from the key + input.
  Uint8List evaluate(Uint8List secretKey, Uint8List input) => _l.oprfEvaluate(secretKey, input);

}

/// OPAQUE password-authenticated key exchange.
extension type OpaqueApi(CryptoLib _l) {
  /// Client registration step 1: blind the password → {blind, request}.
  OprfBlindResult registrationRequest(Uint8List password) => _l.opaqueRegistrationRequest(password);

  /// Server registration step: → 64-byte registration response.
  Uint8List registrationResponse(Uint8List request, Uint8List serverPublicKey,
      Uint8List credentialIdentifier, Uint8List oprfSeed) => _l.opaqueRegistrationResponse(request, serverPublicKey, credentialIdentifier, oprfSeed);

  /// Client registration step 2: → {record, exportKey}.
  OpaqueRecord finalizeRequest(Uint8List password, Uint8List blind, Uint8List response,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) => _l.opaqueFinalizeRequest(password, blind, response, serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Client login step 1: → {ke1, clientState}.
  OpaqueKe1 clientInit(Uint8List password) => _l.opaqueClientInit(password);

  /// Server login step 1: → {ke2, serverState}.
  OpaqueKe2 serverRespond(Uint8List context, Uint8List serverPrivateKey, Uint8List serverPublicKey,
      Uint8List record, Uint8List credentialIdentifier, Uint8List oprfSeed, Uint8List ke1,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) => _l.opaqueServerRespond(context, serverPrivateKey, serverPublicKey, record, credentialIdentifier, oprfSeed, ke1, serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Client login step 2: authenticate server → {ke3, sessionKey, exportKey}.
  /// Throws on a wrong password / server authentication failure.
  OpaqueKe3 clientFinish(Uint8List clientState, Uint8List ke2, Uint8List context,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) => _l.opaqueClientFinish(clientState, ke2, context, serverIdentity: serverIdentity, clientIdentity: clientIdentity);

  /// Server login step 2: verify KE3 → the session key (throws on failure).
  Uint8List serverFinish(Uint8List serverState, Uint8List ke3) => _l.opaqueServerFinish(serverState, ke3);

}

/// Random bytes and explicitly-seeded generators.
extension type RngApi(CryptoLib _l) {
  /// Generate n cryptographically secure random bytes.
  Uint8List bytes(int n) => _l.randomBytes(n);

  /// Instantiate an HMAC-DRBG from entropy (>= 32 bytes) + optional nonce +
  /// personalization. Call [Drbg.close] when done.
  Drbg drbg(Uint8List entropy, [Uint8List? nonce, Uint8List? personalization]) => _l.drbgInstantiate(entropy, nonce, personalization);

  /// Create a new (unseeded) Fortuna pool. Call [Fortuna.close] when done.
  Fortuna fortuna() => _l.fortunaNew();

}

/// ML-KEM (FIPS 203) key encapsulation.
extension type PqMlKemApi(CryptoLib _l) {
  KeyPairResult keygen(MlKemLevel level) => _l.mlKemKeygen(level);

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey, MlKemLevel level) => _l.mlKemEncapsulate(publicKey, level);

  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey, MlKemLevel level) => _l.mlKemDecapsulate(ciphertext, secretKey, level);

}

/// ML-DSA (FIPS 204) signatures.
extension type PqMlDsaApi(CryptoLib _l) {
  KeyPairResult keygen(MlDsaLevel level) => _l.mlDsaKeygen(level);

  Uint8List sign(Uint8List msg, Uint8List secretKey, MlDsaLevel level) => _l.mlDsaSign(msg, secretKey, level);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey, MlDsaLevel level) => _l.mlDsaVerify(msg, sig, publicKey, level);

}

/// SLH-DSA (FIPS 205) hash-based signatures.
extension type PqSlhDsaApi(CryptoLib _l) {
  KeyPairResult keygen(SlhDsaLevel level, SlhDsaHash hash) => _l.slhDsaKeygen(level, hash);

  Uint8List sign(Uint8List msg, Uint8List secretKey, SlhDsaLevel level, SlhDsaHash hash) => _l.slhDsaSign(msg, secretKey, level, hash);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey, SlhDsaLevel level, SlhDsaHash hash) => _l.slhDsaVerify(msg, sig, publicKey, level, hash);

}

/// X25519 + ML-KEM-768 hybrid KEM.
extension type PqHybridKemApi(CryptoLib _l) {
  KeyPairResult keygen() => _l.hybridKemKeygen();

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey) => _l.hybridKemEncapsulate(publicKey);

  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) => _l.hybridKemDecapsulate(ciphertext, secretKey);

}

/// Ed25519 + ML-DSA-65 hybrid signatures.
extension type PqHybridSigApi(CryptoLib _l) {
  KeyPairResult keygen() => _l.hybridSigKeygen();

  Uint8List sign(Uint8List msg, Uint8List secretKey) => _l.hybridSigSign(msg, secretKey);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey) => _l.hybridSigVerify(msg, sig, publicKey);

}

/// X25519 + sntrup761 hybrid KEM (a second lattice family).
extension type PqSntrupApi(CryptoLib _l) {
  KeyPairResult keygen() => _l.sntrupX25519Keygen();

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey) => _l.sntrupX25519Encapsulate(publicKey);

  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) => _l.sntrupX25519Decapsulate(ciphertext, secretKey);

}

/// Post-quantum algorithms, grouped by scheme.
extension type PqApi(CryptoLib _l) {
  /// ML-KEM (FIPS 203) key encapsulation.
  PqMlKemApi get mlKem => PqMlKemApi(_l);

  /// ML-DSA (FIPS 204) signatures.
  PqMlDsaApi get mlDsa => PqMlDsaApi(_l);

  /// SLH-DSA (FIPS 205) hash-based signatures.
  PqSlhDsaApi get slhDsa => PqSlhDsaApi(_l);

  /// X25519 + ML-KEM-768 hybrid KEM.
  PqHybridKemApi get hybridKem => PqHybridKemApi(_l);

  /// Ed25519 + ML-DSA-65 hybrid signatures.
  PqHybridSigApi get hybridSig => PqHybridSigApi(_l);

  /// X25519 + sntrup761 hybrid KEM (a second lattice family).
  PqSntrupApi get sntrup => PqSntrupApi(_l);

}

/// Noise XX secure channel (Noise_XX_25519_ChaChaPoly_SHA256).
extension type NoiseApi(CryptoLib _l) {
  /// Create a Noise XX state from this side's X25519 keypair. Both sides must
  /// use the same [prologue].
  NoiseXX create({required bool initiator, required Uint8List staticPublic,
      required Uint8List staticSecret, Uint8List? prologue}) =>
      _l.noise(initiator: initiator, staticPublic: staticPublic, staticSecret: staticSecret, prologue: prologue);
}

/// Domain-grouped entry points into the full CryptoLib surface.
extension CryptoLibNamespaces on CryptoLib {
  /// Hashes, MACs, password hashing and HKDF.
  HashApi get hash => HashApi(this);

  /// Authenticated symmetric encryption, incl. committing and streaming modes.
  AeadApi get aead => AeadApi(this);

  /// X25519 key exchange, Ed25519 signing, boxes and sealed boxes.
  AsymApi get asym => AsymApi(this);

  /// BLS12-381 signing, verification and aggregation.
  BlsApi get bls => BlsApi(this);

  /// Layered vaults: Vault, asymmetric Vault and MolecularVault.
  VaultApi get vault => VaultApi(this);

  /// Envelope encryption with revocable device and passphrase slots.
  KeyringApi get keyring => KeyringApi(this);

  /// Media-derived entropy and entropy-source health.
  EntropyApi get entropy => EntropyApi(this);

  /// Steganographic embedding, extraction and carrier diagnostics.
  StegoApi get stego => StegoApi(this);

  /// Carriers that combine encryption with concealment, plus FEC.
  ComposedApi get composed => ComposedApi(this);

  /// EVM and Bitcoin interop primitives.
  ChainApi get chain => ChainApi(this);

  /// One-call composed recipes (PQ seal, threshold, file-keyed, keyring-backed).
  SuiteApi get suite => SuiteApi(this);

  /// Flagship / Fortress sealed messaging.
  SealedApi get sealed => SealedApi(this);

  /// Forward-secret ratcheting sessions.
  SessionApi get session => SessionApi(this);

  /// FROST t-of-n threshold signatures.
  FrostApi get frost => FrostApi(this);

  /// HPKE (RFC 9180) hybrid public-key encryption.
  HpkeApi get hpke => HpkeApi(this);

  /// ECVRF (RFC 9381) verifiable random function.
  EcvrfApi get ecvrf => EcvrfApi(this);

  /// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
  BbsApi get bbs => BbsApi(this);

  /// Oblivious pseudorandom function (RFC 9497).
  OprfApi get oprf => OprfApi(this);

  /// OPAQUE password-authenticated key exchange.
  OpaqueApi get opaque => OpaqueApi(this);

  /// Random bytes and explicitly-seeded generators.
  RngApi get rng => RngApi(this);

  /// Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA and hybrids).
  PqApi get pq => PqApi(this);

  /// Noise XX secure channel.
  NoiseApi get channel => NoiseApi(this);
}
