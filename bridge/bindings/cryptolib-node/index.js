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
  koffi.struct('CryptoFileInspection', { parses: 'int', format: 'uint8', ext_matches: 'int', width: 'uint64_t', height: 'uint64_t', file_size: 'uint64_t', detail: 'void *', error: 'void *' });
  koffi.struct('CryptoHiddenDataReport', { cryptolib_payload: 'int', lsb_chi_square: 'double', lsb_embedding_likelihood: 'double', samples_analysed: 'uint64_t', note: 'void *', error: 'void *' });
  koffi.struct('CryptoHealthReport', { min_entropy_per_byte: 'double', longest_run: 'uint64_t', max_window_count: 'uint64_t', rct_passed: 'int', apt_passed: 'int', error: 'void *' });
  koffi.struct('CryptoSealedInfo', { ok: 'uint8', version: 'uint8', suite: 'uint8', streaming: 'uint8', fingerprint: koffi.array('uint8', 16), kem_ciphertext_len: 'size_t' });
  koffi.struct('CryptoFrostKeyGen', { group_public_key: CryptoBuffer, secret_shares: CryptoBuffer, public_shares: CryptoBuffer, count: 'size_t', error: 'void *' });
  koffi.struct('CryptoFrostCommit', { hiding_nonce: CryptoBuffer, binding_nonce: CryptoBuffer, hiding_commit: CryptoBuffer, binding_commit: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoOprfBlind', { blind: CryptoBuffer, blinded_element: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoOpaqueRecord', { record: CryptoBuffer, export_key: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoOpaqueKe1', { ke1: CryptoBuffer, client_state: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoOpaqueKe2', { ke2: CryptoBuffer, server_state: CryptoBuffer, error: 'void *' });
  koffi.struct('CryptoOpaqueKe3', { ke3: CryptoBuffer, session_key: CryptoBuffer, export_key: CryptoBuffer, error: 'void *' });

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
  snKeygen: f('CryptoKeyPair cryptolib_sntrup_x25519_keygen()'),
  snEncaps: f('CryptoKemEncapsResult cryptolib_sntrup_x25519_encapsulate(uint8_t*, size_t, _Out_ char**)'),
  snDecaps: f('CryptoBufferResult cryptolib_sntrup_x25519_decapsulate(uint8_t*, size_t, uint8_t*, size_t)'),
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

  // Suite — one-call advanced combinations
  suiteSealPq: f('CryptoBufferResult cryptolib_suite_seal_pq(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteSealPqSntrup: f('CryptoBufferResult cryptolib_suite_seal_pq_sntrup(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteOpenPq: f('CryptoBufferResult cryptolib_suite_open_pq(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteSealSignedPq: f('CryptoBufferResult cryptolib_suite_seal_signed_pq(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteSealSignedPqSntrup: f('CryptoBufferResult cryptolib_suite_seal_signed_pq_sntrup(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteOpenSignedPq: f('CryptoBufferResult cryptolib_suite_open_signed_pq(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteSealWithFile: f('CryptoBufferResult cryptolib_suite_seal_with_file(uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  suiteOpenWithFile: f('CryptoBufferResult cryptolib_suite_open_with_file(uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  suiteSealKrDev: f('CryptoBufferResult cryptolib_suite_seal_with_keyring_device(uint8_t*, size_t, void*, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteOpenKrDev: f('CryptoBufferResult cryptolib_suite_open_with_keyring_device(uint8_t*, size_t, void*, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteSealKrPw: f('CryptoBufferResult cryptolib_suite_seal_with_keyring_passphrase(uint8_t*, size_t, void*, const char*, uint8_t*, size_t)'),
  suiteOpenKrPw: f('CryptoBufferResult cryptolib_suite_open_with_keyring_passphrase(uint8_t*, size_t, void*, const char*, uint8_t*, size_t)'),
  suiteSealThr: f('CryptoBufferResult cryptolib_suite_seal_threshold(uint8_t*, size_t, uint8_t, uint8_t, uint8_t*, size_t, _Out_ CryptoBuffer*)'),
  // Flagship/Fortress sealed messaging (tier 0=Flagship, 1=Fortress).
  sealedGenRecip: f('CryptoKeyPair cryptolib_sealed_generate_recipient(int)'),
  sealedGenSender: f('CryptoKeyPair cryptolib_sealed_generate_sender(int)'),
  sealedSeal: f('CryptoBufferResult cryptolib_sealed_seal(int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  sealedOpen: f('CryptoBufferResult cryptolib_sealed_open(int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  sealedInspect: f('CryptoSealedInfo cryptolib_sealed_inspect(uint8_t*, size_t)'),
  sealedAddr: f('int cryptolib_sealed_addressed_to(uint8_t*, size_t, uint8_t*, size_t)'),
  sealedSealerBegin: f('void *cryptolib_sealed_sealer_begin(int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)'),
  sealedSealerPreamble: f('CryptoBufferResult cryptolib_sealed_sealer_preamble(void *)'),
  sealedSealerPush: f('CryptoBufferResult cryptolib_sealed_sealer_push(void *, uint8_t*, size_t)'),
  sealedSealerFinalize: f('CryptoBufferResult cryptolib_sealed_sealer_finalize(void *, uint8_t*, size_t, _Out_ CryptoBuffer*)'),
  sealedSealerFree: f('void cryptolib_sealed_sealer_free(void *)'),
  sealedOpenerBegin: f('void *cryptolib_sealed_opener_begin(int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)'),
  sealedOpenerPull: f('CryptoBufferResult cryptolib_sealed_opener_pull(void *, uint8_t*, size_t, _Out_ int*)'),
  sealedOpenerFinalize: f('CryptoBufferResult cryptolib_sealed_opener_finalize(void *, uint8_t*, size_t)'),
  sealedOpenerFree: f('void cryptolib_sealed_opener_free(void *)'),
  // Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet).
  sessGenPrekey: f('CryptoKeyPair cryptolib_session_generate_prekey()'),
  sessInitiate: f('void *cryptolib_session_initiate(uint8_t*, size_t, _Out_ char**)'),
  sessHandshake: f('CryptoBufferResult cryptolib_session_handshake(void *)'),
  sessAccept: f('void *cryptolib_session_accept(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)'),
  sessEncrypt: f('CryptoBufferResult cryptolib_session_encrypt(void *, uint8_t*, size_t, uint8_t*, size_t)'),
  sessDecrypt: f('CryptoBufferResult cryptolib_session_decrypt(void *, uint8_t*, size_t, uint8_t*, size_t)'),
  sessFree: f('void cryptolib_session_free(void *)'),

  // FROST(Ed25519, SHA-512) — RFC 9591 threshold signatures.
  frostKeygen: f('CryptoFrostKeyGen cryptolib_frost_keygen(uint16_t, uint16_t)'),
  frostKgFree: f('void cryptolib_frost_keygen_free(CryptoFrostKeyGen*)'),
  frostCommit: f('CryptoFrostCommit cryptolib_frost_commit(uint8_t*, size_t, uint16_t)'),
  frostCommitNonces: f('CryptoFrostCommit cryptolib_frost_commit_with_nonces(uint16_t, uint8_t*, size_t, uint8_t*, size_t)'),
  frostCommitFree: f('void cryptolib_frost_commit_free(CryptoFrostCommit*)'),
  frostSign: f('CryptoBufferResult cryptolib_frost_sign(uint16_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint16_t*, uint8_t*, uint8_t*, size_t)'),
  frostAggregate: f('CryptoBufferResult cryptolib_frost_aggregate(uint8_t*, size_t, uint8_t*, size_t, uint16_t*, uint8_t*, uint8_t*, size_t, uint8_t*)'),
  frostVerify: f('int cryptolib_frost_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  frostVerifyShare: f('int cryptolib_frost_verify_share(uint16_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint16_t*, uint8_t*, uint8_t*, size_t)'),

  // HPKE (RFC 9180) — DHKEM(X25519, HKDF-SHA256).
  hpkeKeygen: f('CryptoKeyPair cryptolib_hpke_keygen()'),
  hpkeDerive: f('CryptoKeyPair cryptolib_hpke_derive_keypair(uint8_t*, size_t)'),
  hpkeSetupS: f('void* cryptolib_hpke_setup_s(int, int, int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ CryptoBuffer*, _Out_ char**)'),
  hpkeSetupR: f('void* cryptolib_hpke_setup_r(int, int, int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)'),
  hpkeSeal: f('CryptoBufferResult cryptolib_hpke_seal(void*, uint8_t*, size_t, uint8_t*, size_t)'),
  hpkeOpen: f('CryptoBufferResult cryptolib_hpke_open(void*, uint8_t*, size_t, uint8_t*, size_t)'),
  hpkeExport: f('CryptoBufferResult cryptolib_hpke_export(void*, uint8_t*, size_t, size_t)'),
  hpkeCtxFree: f('void cryptolib_hpke_context_free(void*)'),

  // ECVRF (RFC 9381) — verifiable random function.
  ecvrfKeygen: f('CryptoKeyPair cryptolib_ecvrf_keygen()'),
  ecvrfPubkey: f('CryptoBufferResult cryptolib_ecvrf_public_key(uint8_t*, size_t)'),
  ecvrfProve: f('CryptoBufferResult cryptolib_ecvrf_prove(uint8_t*, size_t, uint8_t*, size_t)'),
  ecvrfProofToHash: f('CryptoBufferResult cryptolib_ecvrf_proof_to_hash(uint8_t*, size_t)'),
  ecvrfVerify: f('CryptoBufferResult cryptolib_ecvrf_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),

  // OPRF (RFC 9497) — oblivious pseudorandom function.
  oprfDerive: f('CryptoKeyPair cryptolib_oprf_derive_keypair(uint8_t*, size_t, uint8_t*, size_t)'),
  oprfBlind: f('CryptoOprfBlind cryptolib_oprf_blind(uint8_t*, size_t)'),
  oprfBlindScalar: f('CryptoOprfBlind cryptolib_oprf_blind_with_scalar(uint8_t*, size_t, uint8_t*, size_t)'),
  oprfBlindFree: f('void cryptolib_oprf_blind_free(CryptoOprfBlind*)'),
  oprfBlindEval: f('CryptoBufferResult cryptolib_oprf_blind_evaluate(uint8_t*, size_t, uint8_t*, size_t)'),
  oprfFinalize: f('CryptoBufferResult cryptolib_oprf_finalize(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  oprfEvaluate: f('CryptoBufferResult cryptolib_oprf_evaluate(uint8_t*, size_t, uint8_t*, size_t)'),

  // OPAQUE aPAKE (OPAQUE-3DH, ristretto255-SHA-512).
  opaqueRegRequest: f('CryptoOprfBlind cryptolib_opaque_registration_request(uint8_t*, size_t)'),
  opaqueRegResponse: f('CryptoBufferResult cryptolib_opaque_registration_response(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  opaqueFinalize: f('CryptoOpaqueRecord cryptolib_opaque_finalize_request(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  opaqueRecordFree: f('void cryptolib_opaque_record_free(CryptoOpaqueRecord*)'),
  opaqueClientInit: f('CryptoOpaqueKe1 cryptolib_opaque_client_init(uint8_t*, size_t)'),
  opaqueKe1Free: f('void cryptolib_opaque_ke1_free(CryptoOpaqueKe1*)'),
  opaqueServerRespond: f('CryptoOpaqueKe2 cryptolib_opaque_server_respond(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  opaqueKe2Free: f('void cryptolib_opaque_ke2_free(CryptoOpaqueKe2*)'),
  opaqueClientFinish: f('CryptoOpaqueKe3 cryptolib_opaque_client_finish(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  opaqueKe3Free: f('void cryptolib_opaque_ke3_free(CryptoOpaqueKe3*)'),
  opaqueServerFinish: f('CryptoBufferResult cryptolib_opaque_server_finish(uint8_t*, size_t, uint8_t*, size_t)'),

  // BBS signatures + selective disclosure (BLS12-381-SHA-256).
  bbsKeygen: f('CryptoKeyPair cryptolib_bbs_keygen(uint8_t*, size_t, uint8_t*, size_t)'),
  bbsSkToPk: f('CryptoBufferResult cryptolib_bbs_sk_to_pk(uint8_t*, size_t)'),
  bbsSign: f('CryptoBufferResult cryptolib_bbs_sign(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t)'),
  bbsVerify: f('int cryptolib_bbs_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t)'),
  bbsProofGen: f('CryptoBufferResult cryptolib_bbs_proof_gen(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, uint64_t*, size_t)'),
  bbsProofVerify: f('int cryptolib_bbs_proof_verify(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, uint64_t*, size_t)'),
  // BBS per-verifier pseudonyms + blind issuance (draft -per-verifier-linkability-02).
  bbsCommitWithNym: f('CryptoBufferResult cryptolib_bbs_commit_with_nym(const uint8_t**, size_t*, size_t, const uint8_t**, size_t*, size_t, _Out_ CryptoBuffer*)'),
  bbsBlindSignWithNym: f('CryptoBufferResult cryptolib_bbs_blind_sign_with_nym(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, uint8_t*, size_t, uint64_t)'),
  bbsFinalizeNymSecrets: f('CryptoBufferResult cryptolib_bbs_finalize_nym_secrets(const uint8_t**, size_t*, size_t, uint8_t*, size_t)'),
  bbsCalculatePseudonym: f('CryptoBufferResult cryptolib_bbs_calculate_pseudonym(uint8_t*, size_t, const uint8_t**, size_t*, size_t)'),
  bbsProofGenWithPseudonym: f('CryptoBufferResult cryptolib_bbs_proof_gen_with_pseudonym(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, const uint8_t**, size_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, uint64_t*, size_t, uint64_t*, size_t, _Out_ CryptoBuffer*)'),
  bbsProofVerifyWithPseudonym: f('int cryptolib_bbs_proof_verify_with_pseudonym(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint64_t, uint64_t, const uint8_t**, size_t*, size_t, uint64_t*, size_t)'),
  // Standalone blind issuance (draft-irtf-cfrg-bbs-blind-signatures-02, no pseudonyms).
  bbsBlindCommit: f('CryptoBufferResult cryptolib_bbs_blind_commit(const uint8_t**, size_t*, size_t, _Out_ CryptoBuffer*)'),
  bbsBlindSign: f('CryptoBufferResult cryptolib_bbs_blind_sign(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t)'),
  bbsVerifyBlindSign: f('int cryptolib_bbs_verify_blind_sign(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const uint8_t**, size_t*, size_t, const uint8_t**, size_t*, size_t, uint8_t*, size_t)'),
  bbsHashToScalar: f('CryptoBufferResult cryptolib_bbs_hash_to_scalar(uint8_t*, size_t, uint8_t*, size_t)'),
  // Incremental BLAKE3 + Noise XX.
  b3Create: f('void *cryptolib_blake3_hasher_create(uint8_t*, size_t)'),
  b3Update: f('int cryptolib_blake3_hasher_update(void*, uint8_t*, size_t)'),
  b3Finalize: f('CryptoBufferResult cryptolib_blake3_hasher_finalize(void*, size_t)'),
  b3Free: f('void cryptolib_blake3_hasher_free(void*)'),
  noiseCreate: f('void *cryptolib_noise_create(int, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  noiseWrite: f('CryptoBufferResult cryptolib_noise_write_message(void*, uint8_t*, size_t)'),
  noiseRead: f('CryptoBufferResult cryptolib_noise_read_message(void*, uint8_t*, size_t)'),
  noiseFinished: f('int cryptolib_noise_handshake_finished(void*)'),
  noiseHash: f('CryptoBufferResult cryptolib_noise_handshake_hash(void*)'),
  noiseRemote: f('CryptoBufferResult cryptolib_noise_remote_static(void*)'),
  noiseSplit: f('int cryptolib_noise_split(void*)'),
  noiseEnc: f('CryptoBufferResult cryptolib_noise_encrypt(void*, uint8_t*, size_t, uint8_t*, size_t)'),
  noiseDec: f('CryptoBufferResult cryptolib_noise_decrypt(void*, uint8_t*, size_t, uint8_t*, size_t)'),
  noiseDecAt: f('CryptoBufferResult cryptolib_noise_decrypt_at(void*, uint64_t, uint8_t*, size_t, uint8_t*, size_t)'),
  noiseFree: f('void cryptolib_noise_free(void*)'),
  // Stateful RNGs, advanced steganography, composed carriers and FEC.
  drbgInstantiate: f('void *cryptolib_drbg_instantiate(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, _Out_ char**)'),
  drbgGenerate: f('CryptoBufferResult cryptolib_drbg_generate(void*, size_t, uint8_t*, size_t)'),
  drbgReseed: f('CryptoResult cryptolib_drbg_reseed(void*, uint8_t*, size_t, uint8_t*, size_t)'),
  drbgFree: f('void cryptolib_drbg_free(void*)'),
  fortunaNew: f('void *cryptolib_fortuna_new()'),
  fortunaAdd: f('void cryptolib_fortuna_add_entropy(void*, uint8_t, uint8_t*, size_t)'),
  fortunaGen: f('CryptoBufferResult cryptolib_fortuna_generate(void*, size_t)'),
  fortunaReseed: f('void cryptolib_fortuna_reseed(void*)'),
  fortunaCount: f('uint64_t cryptolib_fortuna_reseed_count(void*)'),
  fortunaFree: f('void cryptolib_fortuna_free(void*)'),
  stegoEmbedKeyed: f('CryptoResult cryptolib_stego_embed_keyed(const char*, uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  stegoExtractKeyed: f('CryptoBufferResult cryptolib_stego_extract_keyed(const char*, uint8_t*, size_t)'),
  stegoEmbedEncrypted: f('CryptoResult cryptolib_stego_embed_encrypted(const char*, uint8_t*, size_t, const char*, uint8_t*, size_t)'),
  stegoExtractDecrypt: f('CryptoBufferResult cryptolib_stego_extract_decrypt(const char*, uint8_t*, size_t)'),
  stegoInspect: f('CryptoFileInspection cryptolib_stego_inspect(const char*)'),
  stegoDetectHidden: f('CryptoHiddenDataReport cryptolib_stego_detect_hidden(const char*)'),
  stegoContentDigest: f('CryptoBufferResult cryptolib_stego_content_digest(const char*)'),
  assessFileHealth: f('CryptoHealthReport cryptolib_entropy_assess_file_health(const char*, size_t)'),
  fecEncode: f('CryptoBufferResult cryptolib_fec_encode(uint8_t*, size_t, int)'),
  fecDecode: f('CryptoBufferResult cryptolib_fec_decode(uint8_t*, size_t, int, size_t)'),
  physicalSeal: f('CryptoResult cryptolib_physical_seal(const char*, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)'),
  physicalOpen: f('CryptoBufferResult cryptolib_physical_open(const char*, uint8_t*, size_t, const char*)'),
  imageFactorSeal: f('CryptoResult cryptolib_image_factor_seal(uint8_t*, size_t, const char*, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)'),
  imageFactorOpen: f('CryptoBufferResult cryptolib_image_factor_open(uint8_t*, size_t, const char*, uint8_t*, size_t, const char*)'),
  hpkeStegoSeal: f('CryptoBufferResult cryptolib_hpke_stego_seal(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const char*, const char*)'),
  hpkeStegoOpen: f('CryptoBufferResult cryptolib_hpke_stego_open(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t, const char*)'),
  bbsRandomScalar: f('CryptoBufferResult cryptolib_bbs_random_scalar()'),
  suiteOpenThr: f('CryptoBufferResult cryptolib_suite_open_threshold(uint8_t*, size_t, uint8_t*, size_t, uint8_t*, size_t)'),
  suiteEvmAddr: f('CryptoBufferResult cryptolib_suite_evm_address(uint8_t*, size_t)'),
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
    const m = koffi.decode(r.error, 'char', -1); fn.strFree(r.error); throw new Error(m);
  }
  const out = b(r.buf); fn.bufFree(r.buf); return out;
}
function kp(k) { const pub = b(k.public_key), sec = b(k.secret_key); fn.kpFree(k); return { publicKey: pub, secretKey: sec }; }
const u8 = (x) => Buffer.isBuffer(x) ? x : Buffer.from(x);
// Parse [index(1)|ylen(4 LE)|y] records into individual distributable share records.
function splitShareRecords(blob) {
  const out = [];
  for (let off = 0; off + 5 <= blob.length;) {
    const yl = blob.readUInt32LE(off + 1);
    const end = off + 5 + yl;
    if (end > blob.length) break;
    out.push(blob.subarray(off, end));
    off = end;
  }
  return out;
}

// Throw if a `_Out_ char**` error slot was populated.
function outErr(e) { if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); } }

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
// ═══ Flagship / Fortress — state-of-the-art sealed messaging ═══════════════════
// Two assurance tiers of one construction (encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first). A self-contained,
// drop-in messaging layer.
const SealedTier = Object.freeze({ Flagship: 0, Fortress: 1 });

const _optA = (o) => (o && o.aad ? u8(o.aad) : null);
const _optAL = (o) => (o && o.aad ? u8(o.aad).length : 0);
const _optP = (o) => (o && o.purpose ? u8(o.purpose) : null);
const _optPL = (o) => (o && o.purpose ? u8(o.purpose).length : 0);

// StreamSealer — encrypt a stream: preamble() once, push() each chunk,
// finalize() for the last chunk + signed trailer; close() when done.
class SealedStreamSealer {
  constructor(handle) { this._h = handle; }
  preamble() { return consume(fn.sealedSealerPreamble(this._h)); }
  push(chunk) { return consume(fn.sealedSealerPush(this._h, u8(chunk), u8(chunk).length)); }
  finalize(last = null) {
    const outTrailer = {};
    const ciphertext = consume(fn.sealedSealerFinalize(this._h, last ? u8(last) : null, last ? u8(last).length : 0, outTrailer));
    const trailer = (outTrailer.data && Number(outTrailer.len) > 0)
      ? Buffer.from(koffi.decode(outTrailer.data, 'uint8_t', Number(outTrailer.len))) : Buffer.alloc(0);
    fn.bufFree(outTrailer);
    return { ciphertext, trailer };
  }
  close() { if (this._h) { fn.sealedSealerFree(this._h); this._h = null; } }
}

// StreamOpener — decrypt a stream: pull() each chunk ({plaintext, final}), then
// finalize(trailer) to verify the sender signature over the whole stream.
class SealedStreamOpener {
  constructor(handle) { this._h = handle; }
  pull(ct) {
    const outFinal = [0];
    const plaintext = consume(fn.sealedOpenerPull(this._h, u8(ct), u8(ct).length, outFinal));
    return { plaintext, final: outFinal[0] === 1 };
  }
  finalize(trailer) { consume(fn.sealedOpenerFinalize(this._h, u8(trailer), u8(trailer).length)); return true; }
  close() { if (this._h) { fn.sealedOpenerFree(this._h); this._h = null; } }
}

// Identity — the config/setup handle. Bundles a party's recipient (KEM) keypair
// for receiving and sender (signature) keypair for signing. Publish the publics,
// keep the secrets.
class Identity {
  constructor(tier, recipientPublic, recipientSecret, senderPublic, senderSecret) {
    this.tier = tier;
    this.recipientPublic = recipientPublic; this.recipientSecret = recipientSecret;
    this.senderPublic = senderPublic; this.senderSecret = senderSecret;
  }
  static generate(tier = SealedTier.Flagship) {
    const r = kp(fn.sealedGenRecip(tier));
    const s = kp(fn.sealedGenSender(tier));
    return new Identity(tier, r.publicKey, r.secretKey, s.publicKey, s.secretKey);
  }
  seal(plaintext, recipientPublic, opts = null) {
    return consume(fn.sealedSeal(this.tier, u8(plaintext), u8(plaintext).length,
      u8(recipientPublic), u8(recipientPublic).length, u8(this.senderSecret), u8(this.senderSecret).length,
      _optA(opts), _optAL(opts), _optP(opts), _optPL(opts)));
  }
  open(envelope, senderPublic, opts = null) {
    return consume(fn.sealedOpen(this.tier, u8(envelope), u8(envelope).length,
      u8(this.recipientSecret), u8(this.recipientSecret).length,
      u8(this.recipientPublic), u8(this.recipientPublic).length,
      u8(senderPublic), u8(senderPublic).length,
      _optA(opts), _optAL(opts), _optP(opts), _optPL(opts)));
  }
  newStreamSealer(recipientPublic, opts = null) {
    const e = [null];
    const h = fn.sealedSealerBegin(this.tier, u8(recipientPublic), u8(recipientPublic).length,
      u8(this.senderSecret), u8(this.senderSecret).length, _optP(opts), _optPL(opts), e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: stream sealer begin failed');
    return new SealedStreamSealer(h);
  }
  newStreamOpener(preamble, senderPublic, opts = null) {
    const e = [null];
    const h = fn.sealedOpenerBegin(this.tier, u8(preamble), u8(preamble).length,
      u8(this.recipientSecret), u8(this.recipientSecret).length,
      u8(this.recipientPublic), u8(this.recipientPublic).length,
      u8(senderPublic), u8(senderPublic).length, _optP(opts), _optPL(opts), e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: stream opener begin failed');
    return new SealedStreamOpener(h);
  }
}

// ═══ Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet) ═══════════
// A live channel with forward secrecy + post-compromise security, all PQ.
class Session {
  constructor(handle) { this._h = handle; }

  /** Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey. */
  static generatePrekey() { return kp(fn.sessGenPrekey()); }

  /** Initiator: start a session to the responder's prekey public key. */
  static initiate(responderPrekeyPublic) {
    const e = [null];
    const h = fn.sessInitiate(u8(responderPrekeyPublic), u8(responderPrekeyPublic).length, e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: session initiate failed');
    return new Session(h);
  }

  /** The handshake message to send to the responder (Session.accept). */
  handshake() { return consume(fn.sessHandshake(this._h)); }

  /** Responder: accept a handshake with your prekey (public + secret). */
  static accept(handshake, prekeyPublic, prekeySecret) {
    const e = [null];
    const h = fn.sessAccept(u8(handshake), u8(handshake).length,
      u8(prekeyPublic), u8(prekeyPublic).length, u8(prekeySecret), u8(prekeySecret).length, e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: session accept failed');
    return new Session(h);
  }

  encrypt(plaintext, aad = null) {
    return consume(fn.sessEncrypt(this._h, u8(plaintext), u8(plaintext).length,
      aad ? u8(aad) : null, aad ? u8(aad).length : 0));
  }
  decrypt(message, aad = null) {
    return consume(fn.sessDecrypt(this._h, u8(message), u8(message).length,
      aad ? u8(aad) : null, aad ? u8(aad).length : 0));
  }
  close() { if (this._h) { fn.sessFree(this._h); this._h = null; } }
}

// ═══ FROST(Ed25519, SHA-512) — t-of-n threshold signatures (RFC 9591) ══════════
// t of n parties jointly produce ONE ordinary Ed25519 signature; no single party
// can sign, any t can, and the result verifies with plain Ed25519 against the
// group public key. Commitments/nonces are plain {hiding, binding} byte objects.
//
//   const kg = Frost.keygen(5, 3);                 // any 3-of-5 sign
//   const r0 = Frost.commit(kg.secretShares[0], 1);
//   const r1 = Frost.commit(kg.secretShares[1], 2);
//   const r3 = Frost.commit(kg.secretShares[3], 4);
//   const cs = [r0.commitment, r1.commitment, r3.commitment];
//   const s0 = Frost.sign(1, kg.secretShares[0], kg.groupPublicKey, r0.nonces, msg, cs);
//   const s1 = Frost.sign(2, kg.secretShares[1], kg.groupPublicKey, r1.nonces, msg, cs);
//   const s3 = Frost.sign(4, kg.secretShares[3], kg.groupPublicKey, r3.nonces, msg, cs);
//   const sig = Frost.aggregate(kg.groupPublicKey, msg, cs, [s0, s1, s3]);
//   Frost.verify(msg, sig, kg.groupPublicKey);     // → true (standard Ed25519)
function frostCommitOut(c, identifier) {
  if (c.error) { const m = koffi.decode(c.error, 'char', -1); fn.frostCommitFree(c); throw new Error(m); }
  const nonces = { hiding: b(c.hiding_nonce), binding: b(c.binding_nonce) };
  const commitment = { identifier, hiding: b(c.hiding_commit), binding: b(c.binding_commit) };
  fn.frostCommitFree(c);
  return { nonces, commitment };
}
// Flatten commitments into the three parallel wire arrays.
function frostBufs(cs) {
  return {
    ids: cs.map((c) => c.identifier),
    hid: Buffer.concat(cs.map((c) => u8(c.hiding))),
    bnd: Buffer.concat(cs.map((c) => u8(c.binding))),
  };
}
const Frost = {
  /** Trusted-dealer split: any t of n shares can sign. Share i has identifier i+1. */
  keygen(n, t) {
    const kg = fn.frostKeygen(n, t);
    if (kg.error) { const m = koffi.decode(kg.error, 'char', -1); fn.frostKgFree(kg); throw new Error(m); }
    const count = Number(kg.count);
    const groupPublicKey = b(kg.group_public_key);
    const secs = b(kg.secret_shares), pubs = b(kg.public_shares);
    fn.frostKgFree(kg);
    const secretShares = [], publicShares = [];
    for (let i = 0; i < count; i++) {
      secretShares.push(secs.subarray(i * 32, i * 32 + 32));
      publicShares.push(pubs.subarray(i * 32, i * 32 + 32));
    }
    return { groupPublicKey, secretShares, publicShares };
  },
  /** Round 1: fresh random {nonces, commitment} for a share. Keep nonces secret. */
  commit(shareSecret, identifier) {
    return frostCommitOut(fn.frostCommit(u8(shareSecret), u8(shareSecret).length, identifier), identifier);
  },
  /** Deterministic round-1 commit from caller nonces (test vectors). */
  commitWithNonces(identifier, hiding, binding) {
    return frostCommitOut(fn.frostCommitNonces(identifier, u8(hiding), u8(hiding).length, u8(binding), u8(binding).length), identifier);
  },
  /** Round 2: this participant's 32-byte signature share. */
  sign(identifier, shareSecret, groupPublicKey, nonces, msg, commitments) {
    const { ids, hid, bnd } = frostBufs(commitments);
    return consume(fn.frostSign(identifier, u8(shareSecret), u8(shareSecret).length,
      u8(groupPublicKey), u8(groupPublicKey).length,
      u8(nonces.hiding), u8(nonces.hiding).length,
      u8(nonces.binding), u8(nonces.binding).length,
      u8(msg), u8(msg).length, ids, hid, bnd, commitments.length));
  },
  /** Aggregate shares → one 64-byte Ed25519 signature. */
  aggregate(groupPublicKey, msg, commitments, sigShares) {
    const { ids, hid, bnd } = frostBufs(commitments);
    const flat = Buffer.concat(sigShares.map(u8));
    return consume(fn.frostAggregate(u8(groupPublicKey), u8(groupPublicKey).length,
      u8(msg), u8(msg).length, ids, hid, bnd, commitments.length, flat));
  },
  /** Verify an aggregate signature (standard Ed25519). */
  verify(msg, sig, groupPublicKey) {
    return fn.frostVerify(u8(msg), u8(msg).length, u8(sig), u8(sig).length, u8(groupPublicKey), u8(groupPublicKey).length) === 1;
  },
  /** Verify one participant's signature share against its public share. */
  verifyShare(identifier, publicShare, sigShare, commitment, groupPublicKey, msg, commitments) {
    const { ids, hid, bnd } = frostBufs(commitments);
    return fn.frostVerifyShare(identifier, u8(publicShare), u8(publicShare).length,
      u8(sigShare), u8(sigShare).length,
      u8(commitment.hiding), u8(commitment.hiding).length,
      u8(commitment.binding), u8(commitment.binding).length,
      u8(groupPublicKey), u8(groupPublicKey).length,
      u8(msg), u8(msg).length, ids, hid, bnd, commitments.length) === 1;
  },
};

// ═══ HPKE — Hybrid Public Key Encryption (RFC 9180) ════════════════════════════
// The wire-standard hybrid PKE used by TLS ECH, MLS, Oblivious HTTP. KEM is
// DHKEM(X25519, HKDF-SHA256); an envelope sealed here opens in any conformant
// HPKE implementation.
const HpkeKdf = { Sha256: 1, Sha512: 3 };
const HpkeAead = { Aes128Gcm: 1, Aes256Gcm: 2, ChaCha20Poly1305: 3, ExportOnly: 0xFFFF };
const HpkeMode = { Base: 0, Psk: 1, Auth: 2, AuthPsk: 3 };
const olen = (x) => (x ? u8(x).length : 0);
const optr = (x) => (x ? u8(x) : null);

/** An established one-directional HPKE context. close() when done. */
class HpkeContext {
  constructor(handle) { this._h = handle; }
  seal(plaintext, aad = null) { return consume(fn.hpkeSeal(this._h, optr(aad), olen(aad), u8(plaintext), u8(plaintext).length)); }
  open(ciphertext, aad = null) { return consume(fn.hpkeOpen(this._h, optr(aad), olen(aad), u8(ciphertext), u8(ciphertext).length)); }
  export(exporterContext, length) { return consume(fn.hpkeExport(this._h, optr(exporterContext), olen(exporterContext), length)); }
  close() { if (this._h) { fn.hpkeCtxFree(this._h); this._h = null; } }
}

const Hpke = {
  Kdf: HpkeKdf, Aead: HpkeAead, Mode: HpkeMode,
  keygen() { return kp(fn.hpkeKeygen()); },
  deriveKeyPair(ikm) { return kp(fn.hpkeDerive(u8(ikm), u8(ikm).length)); },
  /** Sender key schedule. opts: { psk, pskId, skS } as needed by the mode. */
  setupS(kdf, aead, mode, recipientPublic, info, opts = {}) {
    const encBox = [{}]; const e = [null];
    const h = fn.hpkeSetupS(kdf, aead, mode, u8(recipientPublic), u8(recipientPublic).length,
      u8(info), u8(info).length, optr(opts.psk), olen(opts.psk), optr(opts.pskId), olen(opts.pskId),
      optr(opts.skS), olen(opts.skS), encBox, e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: hpke setup_s failed');
    const enc = b(encBox[0]); fn.bufFree(encBox[0]);
    return { enc, context: new HpkeContext(h) };
  },
  /** Receiver key schedule. opts: { psk, pskId, pkS } as needed by the mode. */
  setupR(kdf, aead, mode, enc, recipientSecret, info, opts = {}) {
    const e = [null];
    const h = fn.hpkeSetupR(kdf, aead, mode, u8(enc), u8(enc).length,
      u8(recipientSecret), u8(recipientSecret).length, u8(info), u8(info).length,
      optr(opts.psk), olen(opts.psk), optr(opts.pskId), olen(opts.pskId), optr(opts.pkS), olen(opts.pkS), e);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    if (!h) throw new Error('cryptolib: hpke setup_r failed');
    return new HpkeContext(h);
  },
  /** Single-shot base-mode encryption → { enc, ct }. */
  sealBase(kdf, aead, recipientPublic, info, plaintext, aad = null) {
    const s = Hpke.setupS(kdf, aead, HpkeMode.Base, recipientPublic, info);
    try { return { enc: s.enc, ct: s.context.seal(plaintext, aad) }; } finally { s.context.close(); }
  },
  /** Single-shot base-mode decryption. */
  openBase(kdf, aead, enc, recipientSecret, info, ciphertext, aad = null) {
    const r = Hpke.setupR(kdf, aead, HpkeMode.Base, enc, recipientSecret, info);
    try { return r.open(ciphertext, aad); } finally { r.close(); }
  },
};

// ═══ ECVRF — Verifiable Random Function (RFC 9381) ═════════════════════════════
// A public-key PRF: prove(sk, alpha) yields a unique 64-byte output plus a proof
// anyone can verify with the public key. verify throws on an invalid proof.
const Ecvrf = {
  keygen() { return kp(fn.ecvrfKeygen()); },
  publicKey(secretKey) { return consume(fn.ecvrfPubkey(u8(secretKey), u8(secretKey).length)); },
  prove(secretKey, alpha) { return consume(fn.ecvrfProve(u8(secretKey), u8(secretKey).length, u8(alpha), u8(alpha).length)); },
  proofToHash(proof) { return consume(fn.ecvrfProofToHash(u8(proof), u8(proof).length)); },
  /** Returns the 64-byte beta on success; throws if the proof is invalid. */
  verify(publicKey, alpha, proof) {
    return consume(fn.ecvrfVerify(u8(publicKey), u8(publicKey).length, u8(alpha), u8(alpha).length, u8(proof), u8(proof).length));
  },
};

// ═══ BBS — multi-message signatures + selective disclosure (BLS12-381) ═════════
// Sign a vector of messages; derive a proof revealing only a chosen subset while
// proving a valid signature covers all of them (anonymous credentials).
const Bbs = {
  keygen(keyMaterial, keyInfo = null) {
    const k = kp(fn.bbsKeygen(u8(keyMaterial), u8(keyMaterial).length, keyInfo ? u8(keyInfo) : null, keyInfo ? u8(keyInfo).length : 0));
    if (k.publicKey.length === 0) throw new Error('cryptolib: bbs keygen failed (key material must be >= 32 bytes)');
    return k;
  },
  skToPk(secretKey) { return consume(fn.bbsSkToPk(u8(secretKey), u8(secretKey).length)); },
  sign(secretKey, publicKey, header, messages) {
    const m = messages.map(u8);
    return consume(fn.bbsSign(u8(secretKey), u8(secretKey).length, u8(publicKey), u8(publicKey).length,
      u8(header), u8(header).length, m, m.map((x) => x.length), m.length));
  },
  verify(publicKey, signature, header, messages) {
    const m = messages.map(u8);
    return fn.bbsVerify(u8(publicKey), u8(publicKey).length, u8(signature), u8(signature).length,
      u8(header), u8(header).length, m, m.map((x) => x.length), m.length) === 1;
  },
  proofGen(publicKey, signature, header, ph, messages, disclosedIndexes) {
    const m = messages.map(u8);
    return consume(fn.bbsProofGen(u8(publicKey), u8(publicKey).length, u8(signature), u8(signature).length,
      u8(header), u8(header).length, u8(ph), u8(ph).length, m, m.map((x) => x.length), m.length,
      disclosedIndexes, disclosedIndexes.length));
  },
  proofVerify(publicKey, proof, header, ph, disclosedMessages, disclosedIndexes) {
    const m = disclosedMessages.map(u8);
    return fn.bbsProofVerify(u8(publicKey), u8(publicKey).length, u8(proof), u8(proof).length,
      u8(header), u8(header).length, u8(ph), u8(ph).length, m, m.map((x) => x.length), m.length,
      disclosedIndexes, disclosedIndexes.length) === 1;
  },

  // ── Per-verifier pseudonyms + blind issuance (draft -per-verifier-linkability-02).
  // The pseudonym ciphersuite is applied internally. Scalar inputs (proverNyms,
  // nymSecrets, secretProverBlind, signerNymEntropy) are 32-byte big-endian.

  /** Commit committedMessages + proverNyms → { commitmentWithProof, secretProverBlind }. */
  commitWithNym(committedMessages, proverNyms) {
    const cm = committedMessages.map(u8); const pm = proverNyms.map(u8);
    const outBlind = {};
    const cwp = consume(fn.bbsCommitWithNym(cm, cm.map((x) => x.length), cm.length,
      pm, pm.map((x) => x.length), pm.length, outBlind));
    const secretProverBlind = b(outBlind); fn.bufFree(outBlind);
    return { commitmentWithProof: cwp, secretProverBlind };
  },
  /** Blind-sign over the commitment + signer messages → 80-byte signature. */
  blindSignWithNym(secretKey, publicKey, commitmentWithProof, header, messages, signerNymEntropy, lengthNymVector) {
    const m = messages.map(u8);
    return consume(fn.bbsBlindSignWithNym(u8(secretKey), u8(secretKey).length, u8(publicKey), u8(publicKey).length,
      u8(commitmentWithProof), u8(commitmentWithProof).length, u8(header), u8(header).length,
      m, m.map((x) => x.length), m.length, u8(signerNymEntropy), u8(signerNymEntropy).length, lengthNymVector));
  },
  /** nym_secrets = proverNyms with the last element += signerNymEntropy (concatenated 32-byte scalars). */
  finalizeNymSecrets(proverNyms, signerNymEntropy) {
    const pm = proverNyms.map(u8);
    return consume(fn.bbsFinalizeNymSecrets(pm, pm.map((x) => x.length), pm.length,
      u8(signerNymEntropy), u8(signerNymEntropy).length));
  },
  /** Deterministic pseudonym (48-byte compressed G1 point) for a context. */
  calculatePseudonym(contextId, nymSecrets) {
    const nm = nymSecrets.map(u8);
    return consume(fn.bbsCalculatePseudonym(u8(contextId), u8(contextId).length, nm, nm.map((x) => x.length), nm.length));
  },
  /** Pseudonym-bound selective-disclosure proof → { proof, pseudonym }. */
  proofGenWithPseudonym(publicKey, signature, header, ph, contextId, signerMessages, committedMessages,
    secretProverBlind, nymSecrets, disclosedSignerIndexes, disclosedCommittedIndexes) {
    const sm = signerMessages.map(u8); const cm = committedMessages.map(u8); const nm = nymSecrets.map(u8);
    const outNym = {};
    const proof = consume(fn.bbsProofGenWithPseudonym(u8(publicKey), u8(publicKey).length,
      u8(signature), u8(signature).length, u8(header), u8(header).length, u8(ph), u8(ph).length,
      u8(contextId), u8(contextId).length, sm, sm.map((x) => x.length), sm.length,
      cm, cm.map((x) => x.length), cm.length, u8(secretProverBlind), u8(secretProverBlind).length,
      nm, nm.map((x) => x.length), nm.length,
      disclosedSignerIndexes, disclosedSignerIndexes.length,
      disclosedCommittedIndexes, disclosedCommittedIndexes.length, outNym));
    const pseudonym = b(outNym); fn.bufFree(outNym);
    return { proof, pseudonym };
  },
  /** Verify a pseudonym-bound proof. disclosedMessages/disclosedIndexes are the
   *  COMBINED signer+committed disclosures (committed index j passed as j+L+1). */
  proofVerifyWithPseudonym(publicKey, proof, header, ph, contextId, pseudonym, L, lengthNymVector,
    disclosedMessages, disclosedIndexes) {
    const m = disclosedMessages.map(u8);
    return fn.bbsProofVerifyWithPseudonym(u8(publicKey), u8(publicKey).length, u8(proof), u8(proof).length,
      u8(header), u8(header).length, u8(ph), u8(ph).length, u8(contextId), u8(contextId).length,
      u8(pseudonym), u8(pseudonym).length, L, lengthNymVector,
      m, m.map((x) => x.length), m.length, disclosedIndexes, disclosedIndexes.length) === 1;
  },

  // ── Standalone blind issuance (draft-irtf-cfrg-bbs-blind-signatures-02, no
  // pseudonyms). secretProverBlind is a 32-byte big-endian scalar.

  /** Commit committedMessages → { commitmentWithProof, secretProverBlind }. */
  blindCommit(committedMessages) {
    const cm = committedMessages.map(u8);
    const outBlind = {};
    const cwp = consume(fn.bbsBlindCommit(cm, cm.map((x) => x.length), cm.length, outBlind));
    const secretProverBlind = b(outBlind); fn.bufFree(outBlind);
    return { commitmentWithProof: cwp, secretProverBlind };
  },
  /** Blind-sign over the commitment + signer messages → 80-byte signature. */
  blindSign(secretKey, publicKey, commitmentWithProof, header, messages) {
    const m = messages.map(u8);
    return consume(fn.bbsBlindSign(u8(secretKey), u8(secretKey).length, u8(publicKey), u8(publicKey).length,
      u8(commitmentWithProof), u8(commitmentWithProof).length, u8(header), u8(header).length,
      m, m.map((x) => x.length), m.length));
  },
  /** Verify a blind signature over messages + committedMessages using secretProverBlind. */
  verifyBlindSign(publicKey, signature, header, messages, committedMessages, secretProverBlind) {
    const m = messages.map(u8); const cm = committedMessages.map(u8);
    return fn.bbsVerifyBlindSign(u8(publicKey), u8(publicKey).length, u8(signature), u8(signature).length,
      u8(header), u8(header).length, m, m.map((x) => x.length), m.length,
      cm, cm.map((x) => x.length), cm.length, u8(secretProverBlind), u8(secretProverBlind).length) === 1;
  },

  // ── Canonical scalar helpers (issue #5). Both return a 32-byte big-endian
  // value strictly < r, ready to feed the pseudonym / blind-issuance API.

  /** Deterministically map (msg, dst) → canonical scalar in [0, r). Use for a
   *  stable per-holder nym seed: nymSeed = hashToScalar(memberSecret, dst). */
  hashToScalar(msg, dst) {
    return consume(fn.bbsHashToScalar(u8(msg), u8(msg).length, u8(dst), u8(dst).length));
  },
  /** A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE). */
  randomScalar() { return consume(fn.bbsRandomScalar()); },
};

// ═══ OPRF — Oblivious Pseudorandom Function (RFC 9497) ═════════════════════════
// Client blinds its input; server evaluates under its key without seeing it;
// client unblinds to the PRF output. Privacy Pass, PSI, password hardening.
const Oprf = {
  deriveKeyPair(seed, info = null) {
    const k = kp(fn.oprfDerive(u8(seed), u8(seed).length, info ? u8(info) : null, info ? u8(info).length : 0));
    if (k.publicKey.length === 0) throw new Error('cryptolib: oprf derive_keypair failed');
    return k;
  },
  blind(input) {
    const r = fn.oprfBlind(u8(input), u8(input).length);
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.oprfBlindFree(r); throw new Error(m); }
    const out = { blind: b(r.blind), blindedElement: b(r.blinded_element) };
    fn.oprfBlindFree(r);
    return out;
  },
  blindWithScalar(input, blindScalar) {
    const r = fn.oprfBlindScalar(u8(input), u8(input).length, u8(blindScalar), u8(blindScalar).length);
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.oprfBlindFree(r); throw new Error(m); }
    const out = { blind: b(r.blind), blindedElement: b(r.blinded_element) };
    fn.oprfBlindFree(r);
    return out;
  },
  blindEvaluate(secretKey, blindedElement) {
    return consume(fn.oprfBlindEval(u8(secretKey), u8(secretKey).length, u8(blindedElement), u8(blindedElement).length));
  },
  finalize(input, blindScalar, evaluatedElement) {
    return consume(fn.oprfFinalize(u8(input), u8(input).length, u8(blindScalar), u8(blindScalar).length, u8(evaluatedElement), u8(evaluatedElement).length));
  },
  evaluate(secretKey, input) {
    return consume(fn.oprfEvaluate(u8(secretKey), u8(secretKey).length, u8(input), u8(input).length));
  },
};

// ═══ OPAQUE — asymmetric PAKE (OPAQUE-3DH, ristretto255-SHA-512) ═══════════════
// Client and server agree on a session key from a password that never leaves the
// client and is never stored server-side. Registration, then a 3DH login.
const Opaque = {
  registrationRequest(password) {
    const r = fn.opaqueRegRequest(u8(password), u8(password).length);
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.oprfBlindFree(r); throw new Error(m); }
    const out = { blind: b(r.blind), request: b(r.blinded_element) };
    fn.oprfBlindFree(r);
    return out;
  },
  registrationResponse(request, serverPublicKey, credentialIdentifier, oprfSeed) {
    return consume(fn.opaqueRegResponse(u8(request), u8(request).length, u8(serverPublicKey), u8(serverPublicKey).length,
      u8(credentialIdentifier), u8(credentialIdentifier).length, u8(oprfSeed), u8(oprfSeed).length));
  },
  finalizeRequest(password, blind, response, serverIdentity = null, clientIdentity = null) {
    const r = fn.opaqueFinalize(u8(password), u8(password).length, u8(blind), u8(blind).length,
      u8(response), u8(response).length, optr(serverIdentity), olen(serverIdentity), optr(clientIdentity), olen(clientIdentity));
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.opaqueRecordFree(r); throw new Error(m); }
    const out = { record: b(r.record), exportKey: b(r.export_key) };
    fn.opaqueRecordFree(r);
    return out;
  },
  clientInit(password) {
    const r = fn.opaqueClientInit(u8(password), u8(password).length);
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.opaqueKe1Free(r); throw new Error(m); }
    const out = { ke1: b(r.ke1), clientState: b(r.client_state) };
    fn.opaqueKe1Free(r);
    return out;
  },
  serverRespond(context, serverPrivateKey, serverPublicKey, record, credentialIdentifier, oprfSeed, ke1, serverIdentity = null, clientIdentity = null) {
    const r = fn.opaqueServerRespond(u8(context), u8(context).length, u8(serverPrivateKey), u8(serverPrivateKey).length,
      u8(serverPublicKey), u8(serverPublicKey).length, u8(record), u8(record).length,
      u8(credentialIdentifier), u8(credentialIdentifier).length, u8(oprfSeed), u8(oprfSeed).length, u8(ke1), u8(ke1).length,
      optr(serverIdentity), olen(serverIdentity), optr(clientIdentity), olen(clientIdentity));
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.opaqueKe2Free(r); throw new Error(m); }
    const out = { ke2: b(r.ke2), serverState: b(r.server_state) };
    fn.opaqueKe2Free(r);
    return out;
  },
  /** Authenticates the server; throws on a wrong password / server auth failure. */
  clientFinish(clientState, ke2, context, serverIdentity = null, clientIdentity = null) {
    const r = fn.opaqueClientFinish(u8(clientState), u8(clientState).length, u8(ke2), u8(ke2).length,
      u8(context), u8(context).length, optr(serverIdentity), olen(serverIdentity), optr(clientIdentity), olen(clientIdentity));
    if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.opaqueKe3Free(r); throw new Error(m); }
    const out = { ke3: b(r.ke3), sessionKey: b(r.session_key), exportKey: b(r.export_key) };
    fn.opaqueKe3Free(r);
    return out;
  },
  serverFinish(serverState, ke3) {
    return consume(fn.opaqueServerFinish(u8(serverState), u8(serverState).length, u8(ke3), u8(ke3).length));
  },
};

// Public envelope metadata (no secrets).
function sealedInspect(envelope) {
  const i = fn.sealedInspect(u8(envelope), u8(envelope).length);
  if (!i.ok) throw new Error('cryptolib: unrecognizable sealed envelope');
  return {
    version: i.version, suite: i.suite, streaming: i.streaming === 1,
    fingerprint: Buffer.from(i.fingerprint), kemCiphertextLen: Number(i.kem_ciphertext_len),
  };
}
function sealedAddressedTo(envelope, recipientPublic) {
  return fn.sealedAddr(u8(envelope), u8(envelope).length, u8(recipientPublic), u8(recipientPublic).length) === 1;
}


// ═══ Stateful RNGs, advanced steganography, composed carriers, FEC ════════════

/** HMAC-DRBG (NIST SP 800-90A). Deterministic for a given seed. close() when done. */
class Drbg {
  constructor(handle) { this._h = handle; }
  /** Generate `n` (<= 65536) bytes, optionally mixing in `additional` for this call. */
  generate(n, additional = null) { return consume(fn.drbgGenerate(this._h, n, optr(additional), olen(additional))); }
  /** Reseed with fresh entropy plus optional additional input. */
  reseed(entropy, additional = null) {
    const r = fn.drbgReseed(this._h, u8(entropy), u8(entropy).length, optr(additional), olen(additional));
    if (r.ok !== 1) { const m = r.error ? koffi.decode(r.error, 'char', -1) : 'drbg reseed failed'; if (r.error) fn.strFree(r.error); throw new Error(m); }
  }
  /** Release the native handle. Idempotent. */
  close() { if (this._h) { fn.drbgFree(this._h); this._h = null; } }
}

/** Fortuna-style entropy pool: accumulates events and heals after compromise. */
class Fortuna {
  constructor(handle) { this._h = handle; }
  /** Add an entropy event from logical source `sourceId` (0..255). Distinct sources must use distinct ids. */
  addEntropy(sourceId, data) { fn.fortunaAdd(this._h, sourceId, u8(data), u8(data).length); }
  /** Generate `n` bytes. Throws until the pool has reseeded at least once. */
  generate(n) { return consume(fn.fortunaGen(this._h, n)); }
  /** Force a reseed now. */
  reseed() { fn.fortunaReseed(this._h); }
  /** Reseed count; 0 means never seeded. */
  reseedCount() { return Number(fn.fortunaCount(this._h)); }
  /** Release the native handle. Idempotent. */
  close() { if (this._h) { fn.fortunaFree(this._h); this._h = null; } }
}

const Rng = {
  /** Cryptographically-secure bytes straight from the OS CSPRNG — the right default. */
  bytes: (n) => consume(fn.random(n)),
  /** Instantiate an HMAC-DRBG from a caller-supplied seed. */
  drbg(entropy, { nonce = null, personalization = null } = {}) {
    const e = [null];
    const h = fn.drbgInstantiate(u8(entropy), u8(entropy).length, optr(nonce), olen(nonce),
                                 optr(personalization), olen(personalization), e);
    outErr(e);
    if (!h) throw new Error('cryptolib: drbg instantiate failed');
    return new Drbg(h);
  },
  /** Create a new, unseeded Fortuna pool. */
  fortuna() {
    const h = fn.fortunaNew();
    if (!h) throw new Error('cryptolib: fortuna alloc failed');
    return new Fortuna(h);
  },
};

/** Media formats reported by StegoAdvanced.inspect(). */
const MediaFormat = {
  0: 'ppmImage', 1: 'wavAudio', 2: 'crvfVideo', 3: 'bmpImage', 4: 'pngImage', 5: 'flacAudio',
  6: 'aviVideo', 7: 'gifImage', 8: 'jpegImage', 9: 'mp3Audio', 10: 'mp4Video', 255: 'unknown',
};

function checkOk(r, what) {
  if (r.ok !== 1) { const m = r.error ? koffi.decode(r.error, 'char', -1) : what; if (r.error) fn.strFree(r.error); throw new Error(m); }
}
function takeStr(ptr) { if (!ptr) return ''; const v = koffi.decode(ptr, 'char', -1); fn.strFree(ptr); return v; }
function throwIfErr(r) { if (r.error) { const m = koffi.decode(r.error, 'char', -1); fn.strFree(r.error); throw new Error(m); } }

const StegoAdvanced = {
  /** Embed under a key: placement is permuted, so without the key the bits cannot be located. */
  embedKeyed(coverPath, payload, outputPath, key) {
    checkOk(fn.stegoEmbedKeyed(coverPath, u8(payload), u8(payload).length, outputPath, u8(key), u8(key).length), 'stego embed_keyed failed');
  },
  /** Extract a keyed payload. Throws on the wrong key. */
  extractKeyed: (stegoPath, key) => consume(fn.stegoExtractKeyed(stegoPath, u8(key), u8(key).length)),
  /** AEAD-encrypt then hide — the one to reach for by default. */
  embedEncrypted(coverPath, plaintext, outputPath, masterKey) {
    checkOk(fn.stegoEmbedEncrypted(coverPath, u8(plaintext), u8(plaintext).length, outputPath, u8(masterKey), u8(masterKey).length), 'stego embed_encrypted failed');
  },
  /** Extract and decrypt. Fails closed on a wrong key or tampered carrier. */
  extractDecrypt: (stegoPath, masterKey) => consume(fn.stegoExtractDecrypt(stegoPath, u8(masterKey), u8(masterKey).length)),
  /** Structural validity and true format (not the extension). */
  inspect(path) {
    const r = fn.stegoInspect(path);
    throwIfErr(r);
    return { parses: r.parses === 1, format: MediaFormat[r.format] ?? 'unknown', extensionMatches: r.ext_matches === 1,
             width: Number(r.width), height: Number(r.height), fileSize: Number(r.file_size), detail: takeStr(r.detail) };
  },
  /** Heuristic hidden-data probe. cryptolibPayload true is conclusive; the statistics never prove absence. */
  detectHidden(path) {
    const r = fn.stegoDetectHidden(path);
    throwIfErr(r);
    return { cryptolibPayload: r.cryptolib_payload === 1, lsbChiSquare: r.lsb_chi_square,
             lsbEmbeddingLikelihood: r.lsb_embedding_likelihood, samplesAnalysed: Number(r.samples_analysed), note: takeStr(r.note) };
  },
  /** Digest of decoded content rather than file bytes — stable across re-encoding. */
  contentDigest: (path) => consume(fn.stegoContentDigest(path)),
};

/** SP 800-90B style health assessment of a file's entropy. */
function assessFileHealth(path, maxBytes = 1 << 20) {
  const r = fn.assessFileHealth(path, maxBytes);
  throwIfErr(r);
  return { minEntropyPerByte: r.min_entropy_per_byte, longestRun: Number(r.longest_run),
           maxWindowCount: Number(r.max_window_count), rctPassed: r.rct_passed === 1, aptPassed: r.apt_passed === 1,
           get healthy() { return this.rctPassed && this.aptPassed; } };
}

/** Forward error correction schemes. */
const FecScheme = { none: 0, repetition3: 1, repetition5: 2, hamming74: 3 };

const Composed = {
  /** FEC-encode before embedding when the carrier may be degraded in transit. */
  fecEncode: (data, scheme) => consume(fn.fecEncode(u8(data), u8(data).length, scheme)),
  /** FEC-decode, recovering `originalLength` bytes. */
  fecDecode: (data, scheme, originalLength) => consume(fn.fecDecode(u8(data), u8(data).length, scheme, originalLength)),
  /** Seal under a key derived from a key-media file, hidden in a separate cover. Both files are needed to open. */
  physicalSeal({ keyMediaPath, plaintext, coverPath, outputPath, aad = null }) {
    checkOk(fn.physicalSeal(keyMediaPath, u8(plaintext), u8(plaintext).length, optr(aad), olen(aad), coverPath, outputPath), 'physical seal failed');
  },
  /** Recover a physicalSeal message. */
  physicalOpen: ({ keyMediaPath, stegoPath, aad = null }) => consume(fn.physicalOpen(keyMediaPath, optr(aad), olen(aad), stegoPath)),
  /** Two factors: the OPRF secret (know) AND the exact reference image (have). */
  imageFactorSeal({ oprfSecretSeed, referenceImagePath, plaintext, coverPath, outputPath, aad = null }) {
    checkOk(fn.imageFactorSeal(u8(oprfSecretSeed), u8(oprfSecretSeed).length, referenceImagePath,
            u8(plaintext), u8(plaintext).length, optr(aad), olen(aad), coverPath, outputPath), 'image factor seal failed');
  },
  /** Recover an imageFactorSeal message. */
  imageFactorOpen: ({ oprfSecretSeed, referenceImagePath, stegoPath, aad = null }) =>
    consume(fn.imageFactorOpen(u8(oprfSecretSeed), u8(oprfSecretSeed).length, referenceImagePath, optr(aad), olen(aad), stegoPath)),
  /** Seal to an HPKE public key and hide it. Returns `enc` — transmit it alongside the carrier. */
  hpkeStegoSeal: ({ recipientPublic, plaintext, coverPath, outputPath, aad = null, info = null }) =>
    consume(fn.hpkeStegoSeal(u8(recipientPublic), u8(recipientPublic).length, u8(plaintext), u8(plaintext).length,
            optr(aad), olen(aad), optr(info), olen(info), coverPath, outputPath)),
  /** Open an hpkeStegoSeal carrier with the recipient secret and the `enc` value. */
  hpkeStegoOpen: ({ recipientSecret, enc, stegoPath, aad = null, info = null }) =>
    consume(fn.hpkeStegoOpen(u8(recipientSecret), u8(recipientSecret).length, u8(enc), u8(enc).length,
            optr(aad), olen(aad), optr(info), olen(info), stegoPath)),
};


// ═══ Security profiles and composable recipes ═════════════════════════════════
//
// SecurityProfile sets every algorithm parameter consistently, so "use the
// strongest thing available" is one word rather than a dozen constants.
//
// Recipe stacks the library's protections in combination: derive a key, cascade
// several AEADs, sign, add error correction, hide the result in a carrier.
//
// Composition only — every step is an existing, vetted operation. What the
// recipe adds is the plumbing that is easy to get wrong by hand: every layer is
// keyed by HKDF under a distinct info string so no key is reused, the header
// describing the recipe is authenticated as AAD by every layer, the order
// (sign → encrypt → correct → conceal) is fixed, and everything fails closed.
//
// The envelope is a library-native format, and is identical across every
// CryptoLib binding: an envelope sealed here opens in Dart, Go or Swift.

/** One AEAD layer in a Recipe cascade. */
const ProtectionLayer = { xchacha20Poly1305: 1, aes256Gcm: 2, committing: 3, molecular: 4 };

// Pinned wire names: part of the format (they feed each layer's HKDF info
// string), so they must never drift from the other bindings.
const LAYER_WIRE_NAME = { 1: 'xchacha20Poly1305', 2: 'aes256Gcm', 3: 'committing', 4: 'molecular' };

/** Origin authentication for a Recipe. */
const SignatureAlgorithm = { none: 0, ed25519: 1, hybrid: 2 };

const KEY_SOURCE = { raw: 0, passphrase: 1, keyFile: 2 };
const KEY_SOURCE_NAME = { 0: 'raw', 1: 'passphrase', 2: 'keyFile' };

/** Coherent algorithm parameter sets, from ordinary to maximal. */
const SecurityProfile = {
  balanced: 'balanced',
  high: 'high',
  maximum: 'maximum',
  /** Every parameter for a profile, moving together so they cannot be mismatched. */
  params(profile) {
    switch (profile) {
      case 'maximum': return {
        mlKemLevel: 2, mlDsaLevel: 2, slhDsaLevel: 4, slhDsaHash: 1,
        sealedTier: SealedTier.Fortress, kdfPreset: 1, argon2Ops: 4, argon2Memory: 512 * 1024 * 1024,
        cascade: [ProtectionLayer.xchacha20Poly1305, ProtectionLayer.aes256Gcm, ProtectionLayer.committing],
      };
      case 'high': return {
        mlKemLevel: 1, mlDsaLevel: 1, slhDsaLevel: 3, slhDsaHash: 0,
        sealedTier: SealedTier.Flagship, kdfPreset: 1, argon2Ops: 3, argon2Memory: 256 * 1024 * 1024,
        cascade: [ProtectionLayer.xchacha20Poly1305, ProtectionLayer.aes256Gcm],
      };
      default: return {
        mlKemLevel: 1, mlDsaLevel: 1, slhDsaLevel: 1, slhDsaHash: 0,
        sealedTier: SealedTier.Flagship, kdfPreset: 0, argon2Ops: 2, argon2Memory: 64 * 1024 * 1024,
        cascade: [ProtectionLayer.xchacha20Poly1305],
      };
    }
  },
};

const RECIPE_MAGIC = Buffer.from('CLRC');
const FEC_MAGIC = Buffer.from('CLFC');
const RECIPE_VERSION = 1;
const RECIPE_SALT_LEN = 16;

/**
 * A composable protection pipeline. Describe what you want once, then seal and
 * open with the same recipe; the envelope carries its own descriptor.
 *
 *   const r = cryptolib.recipe('maximum')
 *       .withPassphrase('correct horse battery staple')
 *       .signedBy(id.secretKey, cryptolib.SignatureAlgorithm.hybrid)
 *       .verifiedBy(id.publicKey);
 *   const env = r.seal(secret);
 */
class Recipe {
  constructor(api, profile = SecurityProfile.balanced) {
    this._api = api;
    this.profile = profile;
    const p = SecurityProfile.params(profile);
    this._layers = [...p.cascade];
    this._argonOps = p.argon2Ops;
    this._argonMem = p.argon2Memory;
    this._source = KEY_SOURCE.raw;
    this._rawKey = null; this._passphrase = null; this._keyFilePath = null;
    this._signAlgo = SignatureAlgorithm.none; this._signSecret = null; this._signPublic = null;
    this._fec = FecScheme.none;
  }

  /** Derive the root key from a passphrase with Argon2id. */
  withPassphrase(passphrase) { this._source = KEY_SOURCE.passphrase; this._passphrase = passphrase; return this; }

  /** Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token). */
  withKey(key) {
    const k = u8(key);
    if (k.length !== 32) throw new Error(`cryptolib: root key must be exactly 32 bytes, got ${k.length}`);
    this._source = KEY_SOURCE.raw; this._rawKey = Buffer.from(k); return this;
  }

  /**
   * Derive the root key deterministically from a media file — "the file is the key".
   * Uses the reproducible entropy path; keyFromFile mixes in fresh system entropy
   * and so could never reopen its own envelope.
   */
  withKeyFile(path) { this._source = KEY_SOURCE.keyFile; this._keyFilePath = path; return this; }

  /** Replace the cascade with exactly these layers, innermost first. */
  withLayers(layers) {
    if (!layers || layers.length === 0) throw new Error('cryptolib: a recipe needs at least one layer');
    this._layers = [...layers]; return this;
  }

  /** Append one more layer on the outside of the cascade. */
  addLayer(layer) { this._layers.push(layer); return this; }

  /** Override the Argon2id cost. Only meaningful with withPassphrase. */
  argon2Cost({ ops, memoryBytes } = {}) {
    if (ops !== undefined) this._argonOps = ops;
    if (memoryBytes !== undefined) this._argonMem = memoryBytes;
    return this;
  }

  /** Sign the plaintext before encryption, so the signature stays confidential. */
  signedBy(secretKey, algorithm = SignatureAlgorithm.ed25519) {
    if (algorithm === SignatureAlgorithm.none) throw new Error('cryptolib: signedBy needs a real algorithm');
    this._signAlgo = algorithm; this._signSecret = Buffer.from(u8(secretKey)); return this;
  }

  /** The public key open() must verify against. Required whenever the envelope is signed. */
  verifiedBy(publicKey) { this._signPublic = Buffer.from(u8(publicKey)); return this; }

  /** Apply forward error correction to the finished envelope. */
  withFec(scheme) { this._fec = scheme; return this; }

  /** Human-readable summary — useful in logs and review. */
  describe() {
    const layers = this._layers.map((l) => LAYER_WIRE_NAME[l]).join(' → ');
    const sig = Object.keys(SignatureAlgorithm).find((k) => SignatureAlgorithm[k] === this._signAlgo);
    let out = `Recipe(${this.profile})\n  key      : ${KEY_SOURCE_NAME[this._source]}\n`
            + `  layers   : ${layers}\n  signature: ${sig}\n  fec      : ${this._fec}\n`;
    if (this._source === KEY_SOURCE.passphrase) {
      out += `  argon2id : ops=${this._argonOps}, mem=${Math.floor(this._argonMem / (1024 * 1024))}MiB\n`;
    }
    return out;
  }

  /** Protect `plaintext` and return the envelope. */
  seal(plaintext) {
    const salt = this._api.randomBytes(RECIPE_SALT_LEN);
    const header = this._buildHeader(salt);
    const root = this._rootKey(salt, this._argonOps, this._argonMem);

    let body = u8(plaintext);
    if (this._signAlgo !== SignatureAlgorithm.none) {
      if (!this._signSecret) throw new Error('cryptolib: signing requested without a secret key');
      const sig = this._signAlgo === SignatureAlgorithm.ed25519
        ? this._api.ed25519Sign(body, this._signSecret)
        : this._api.hybridSigSign(body, this._signSecret);
      body = prefixLengthed(sig, body);
    }
    this._layers.forEach((layer, i) => { body = this._applyLayer(layer, i, root, salt, header, body, true); });

    const envelope = Buffer.concat([header, body]);
    return this._fec === FecScheme.none ? envelope : this._wrapFec(envelope);
  }

  /** Recover the plaintext. Throws on a wrong key, an altered byte, or a bad signature. */
  open(envelope) {
    const inner = this._unwrapFec(u8(envelope));
    const h = this._parseHeader(inner);
    const root = this._rootKey(h.salt, h.ops, h.memory);

    let body = inner.subarray(h.header.length);
    for (let i = h.layers.length - 1; i >= 0; i--) {
      body = this._applyLayer(h.layers[i], i, root, h.salt, h.header, body, false);
    }
    if (h.signAlgo === SignatureAlgorithm.none) return body;

    const [sig, plaintext] = splitLengthed(body);
    if (!this._signPublic) {
      throw new Error('cryptolib: envelope is signed but no public key was supplied — '
                    + 'call verifiedBy() so the signature is actually checked');
    }
    const ok = h.signAlgo === SignatureAlgorithm.ed25519
      ? this._api.ed25519Verify(plaintext, sig, this._signPublic)
      : this._api.hybridSigVerify(plaintext, sig, this._signPublic);
    if (!ok) throw new Error('cryptolib: signature verification failed');
    return plaintext;
  }

  /** Seal and hide the envelope inside a carrier. Defence-in-depth, not the boundary. */
  sealIntoCarrier(plaintext, { coverPath, outputPath }) {
    this._api.stegoEmbed(coverPath, this.seal(plaintext), outputPath);
  }

  /** Extract and open an envelope written by sealIntoCarrier. */
  openFromCarrier(stegoPath) { return this.open(this._api.stegoExtract(stegoPath)); }

  // ── internals ──────────────────────────────────────────────────────────────

  _rootKey(salt, ops, mem) {
    switch (this._source) {
      case KEY_SOURCE.passphrase:
        if (this._passphrase == null) throw new Error('cryptolib: no passphrase set');
        return this._api.argon2idDerive(this._passphrase, salt, 32, ops, mem);
      case KEY_SOURCE.keyFile: {
        const h = this._api.entropyFromFileDeterministic(this._keyFilePath);
        try { return this._api.entropySymmetricKey(h); } finally { this._api.entropyFree(h); }
      }
      default:
        if (!this._rawKey) throw new Error('cryptolib: no key set — call withKey/withPassphrase/withKeyFile');
        return this._rawKey;
    }
  }

  _layerKey(root, salt, index, layer) {
    const info = Buffer.from(`cryptolib/recipe/v1/layer${index}/${LAYER_WIRE_NAME[layer]}`);
    return this._api.hkdfDerive(root, { salt, info, outLen: 32 });
  }

  _applyLayer(layer, index, root, salt, header, data, seal) {
    const key = this._layerKey(root, salt, index, layer);
    const a = this._api;
    switch (layer) {
      case ProtectionLayer.xchacha20Poly1305: return seal ? a.xchacha20Encrypt(data, key, header) : a.xchacha20Decrypt(data, key, header);
      case ProtectionLayer.aes256Gcm:         return seal ? a.aes256gcmEncrypt(data, key, header) : a.aes256gcmDecrypt(data, key, header);
      case ProtectionLayer.committing:        return seal ? a.committingEncrypt(data, key, header) : a.committingDecrypt(data, key, header);
      case ProtectionLayer.molecular:         return seal ? a.molecularSealWithKey(data, key, header) : a.molecularOpenWithKey(data, key, header);
      default: throw new Error(`cryptolib: unknown protection layer ${layer}`);
    }
  }

  _buildHeader(salt) {
    const head = Buffer.from([...RECIPE_MAGIC, RECIPE_VERSION, this._source, this._signAlgo, this._layers.length, ...this._layers]);
    const costs = Buffer.alloc(8);
    costs.writeUInt32BE(this._argonOps, 0);
    costs.writeUInt32BE(this._argonMem, 4);
    return Buffer.concat([head, u8(salt), costs]);
  }

  _parseHeader(env) {
    if (env.length < 8 + RECIPE_SALT_LEN + 8) throw new Error('cryptolib: envelope too short');
    if (!env.subarray(0, 4).equals(RECIPE_MAGIC)) throw new Error('cryptolib: not a CryptoRecipe envelope');
    if (env[4] !== RECIPE_VERSION) throw new Error(`cryptolib: unsupported envelope version ${env[4]}`);
    const source = env[5];
    if (source !== this._source) {
      throw new Error(`cryptolib: envelope was sealed with the ${KEY_SOURCE_NAME[source]} key source, `
                    + `but this recipe is configured for ${KEY_SOURCE_NAME[this._source]}`);
    }
    const signAlgo = env[6];
    const layerCount = env[7];
    const headerLen = 8 + layerCount + RECIPE_SALT_LEN + 8;
    if (env.length < headerLen) throw new Error('cryptolib: truncated envelope header');
    const layers = [];
    for (let i = 0; i < layerCount; i++) {
      const id = env[8 + i];
      if (!LAYER_WIRE_NAME[id]) throw new Error(`cryptolib: unknown protection layer id ${id}`);
      layers.push(id);
    }
    const salt = Buffer.from(env.subarray(8 + layerCount, 8 + layerCount + RECIPE_SALT_LEN));
    const costs = env.subarray(8 + layerCount + RECIPE_SALT_LEN, headerLen);
    return { header: Buffer.from(env.subarray(0, headerLen)), layers, salt, signAlgo,
             ops: costs.readUInt32BE(0), memory: costs.readUInt32BE(4) };
  }

  _wrapFec(envelope) {
    const encoded = this._api.Composed.fecEncode(envelope, this._fec);
    const head = Buffer.alloc(9);
    FEC_MAGIC.copy(head, 0);
    head[4] = this._fec;
    head.writeUInt32BE(envelope.length, 5);
    return Buffer.concat([head, encoded]);
  }

  _unwrapFec(data) {
    if (data.length < 9 || !data.subarray(0, 4).equals(FEC_MAGIC)) return data;
    const scheme = data[4];
    const originalLen = data.readUInt32BE(5);
    return this._api.Composed.fecDecode(data.subarray(9), scheme, originalLen);
  }
}

function prefixLengthed(prefix, rest) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(u8(prefix).length, 0);
  return Buffer.concat([len, u8(prefix), u8(rest)]);
}

function splitLengthed(data) {
  if (data.length < 4) throw new Error('cryptolib: malformed signed payload');
  const n = data.readUInt32BE(0);
  if (data.length < 4 + n) throw new Error('cryptolib: malformed signed payload');
  return [Buffer.from(data.subarray(4, 4 + n)), Buffer.from(data.subarray(4 + n))];
}


// ═══ Incremental BLAKE3 + Noise XX secure channel ════════════════════════════

/** Incremental BLAKE3. Digest equals blake3() over the concatenation. Not thread-safe. close() when done. */
class Blake3Hasher {
  constructor(handle) { this._h = handle; }
  /** Feed bytes. Throws after finalize(). */
  update(data) {
    if (fn.b3Update(this._h, u8(data), u8(data).length) !== 1) throw new Error('cryptolib: blake3 update failed (closed or finalized?)');
  }
  /** Produce the digest; outLen 0 = 32 bytes, larger uses extendable output. No further updates afterwards. */
  finalize(outLen = 0) { return consume(fn.b3Finalize(this._h, outLen)); }
  /** Release the native handle. Idempotent. */
  close() { if (this._h) { fn.b3Free(this._h); this._h = null; } }
}

/**
 * Noise_XX_25519_ChaChaPoly_SHA256 — mutual static-key authentication + forward secrecy.
 *
 * Handshake: initiator writeMessage, responder readMessage+writeMessage, initiator
 * readMessage+writeMessage, responder readMessage; then both split(). Handles are
 * NOT thread-safe (decryptAt is re-entrant, see there). close() when done.
 */
class Noise {
  constructor(handle) { this._h = handle; }
  /** Next handshake message on this side's turn, embedding an optional payload. */
  writeMessage(payload = null) { return consume(fn.noiseWrite(this._h, optr(payload), olen(payload))); }
  /** Consume the peer's handshake message; returns its embedded payload. */
  readMessage(message) { return consume(fn.noiseRead(this._h, u8(message), u8(message).length)); }
  /** True once all three handshake messages are processed. */
  handshakeFinished() { return fn.noiseFinished(this._h) === 1; }
  /** 32-byte channel-binding value both sides agree on after the handshake. */
  handshakeHash() { return consume(fn.noiseHash(this._h)); }
  /** The peer's static X25519 public key learned in the handshake — pin it to stop MITM. */
  remoteStatic() { return consume(fn.noiseRemote(this._h)); }
  /** Derive the transport states (Noise Split). Throws if unfinished or already split. */
  split() { if (fn.noiseSplit(this._h) !== 1) throw new Error('cryptolib: noise split failed (handshake unfinished or already split)'); }
  /** Seal one transport record (after split). */
  encrypt(plaintext, ad = null) { return consume(fn.noiseEnc(this._h, u8(plaintext), u8(plaintext).length, optr(ad), olen(ad))); }
  /** Open the next record in sequence (after split). */
  decrypt(ciphertext, ad = null) { return consume(fn.noiseDec(this._h, u8(ciphertext), u8(ciphertext).length, optr(ad), olen(ad))); }
  /**
   * Open the record sent at `nonceCounter` WITHOUT advancing the session counter, so
   * several records can be opened at once. Caller's duty: use each sender counter
   * (from 0 per direction) at most once and reassemble in order — statelessly a
   * replay looks like a fresh record. Do not mix with encrypt/decrypt concurrently.
   * There is deliberately no explicit-nonce encrypt (nonce reuse leaks the key).
   */
  decryptAt(nonceCounter, ciphertext, ad = null) {
    return consume(fn.noiseDecAt(this._h, BigInt(nonceCounter), u8(ciphertext), u8(ciphertext).length, optr(ad), olen(ad)));
  }
  /** Release the native handle. Idempotent. */
  close() { if (this._h) { fn.noiseFree(this._h); this._h = null; } }
}

/** Incremental BLAKE3; pass a 32-byte key for keyed (MAC) mode. */
function blake3Hasher(key = null) {
  if (key !== null && u8(key).length !== 32) throw new Error('cryptolib: BLAKE3 key must be exactly 32 bytes');
  const h = fn.b3Create(optr(key), olen(key));
  if (!h) throw new Error('cryptolib: blake3 hasher create failed (BLAKE3 not enabled?)');
  return new Blake3Hasher(h);
}

/** Create a Noise XX state from this side's X25519 keypair (see x25519Keygen). Both sides must use the same prologue. */
function noise(initiator, staticPublic, staticSecret, prologue = null) {
  if (u8(staticPublic).length !== 32 || u8(staticSecret).length !== 32) throw new Error('cryptolib: Noise static keys must be 32 bytes each');
  const h = fn.noiseCreate(initiator ? 1 : 0, u8(staticPublic), 32, u8(staticSecret), 32, optr(prologue), olen(prologue));
  if (!h) throw new Error('cryptolib: noise create failed');
  return new Noise(h);
}

module.exports = {
  SealedTier, Identity, sealedInspect, sealedAddressedTo, Session, Frost, Hpke, Ecvrf, Bbs, Oprf, Opaque,
  Rng, Drbg, Fortuna, StegoAdvanced, Composed, FecScheme, MediaFormat, assessFileHealth,
  Blake3Hasher, blake3Hasher, Noise, noise,
  SecurityProfile, ProtectionLayer, SignatureAlgorithm, Recipe,
  /** Start a Recipe at the given profile's settings. */
  recipe(profile = SecurityProfile.balanced) { return new Recipe(module.exports, profile); },
  /** A Recipe using the strongest option at every choice. */
  maximumSecurity() { return new Recipe(module.exports, SecurityProfile.maximum); },
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
  aes256gcmEncrypt: (pt, key, aad = null) => consume(fn.aesEnc(u8(pt), u8(pt).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  aes256gcmDecrypt: (ct, key, aad = null) => consume(fn.aesDec(u8(ct), u8(ct).length, u8(key), u8(key).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),

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
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    return { ciphertext: ct, sharedSecret: ss };
  },
  mlKemDecapsulate: (ct, sk, level = 1) => consume(fn.kemDecaps(u8(ct), u8(ct).length, u8(sk), u8(sk).length, level)),

  // Hybrid X25519 + ML-KEM-768
  hybridKemKeygen: () => kp(fn.hyKeygen()),
  hybridKemEncapsulate(pk) {
    const e = [null]; const r = fn.hyEncaps(u8(pk), u8(pk).length, e);
    const ss = b(r.shared_secret), ct = b(r.ciphertext); fn.kemFree(r);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    return { ciphertext: ct, sharedSecret: ss };
  },
  hybridKemDecapsulate: (ct, sk) => consume(fn.hyDecaps(u8(ct), u8(ct).length, u8(sk), u8(sk).length)),

  // X25519 + sntrup761 hybrid KEM (defense-in-diversity; NTRU Prime family).
  sntrupX25519Keygen: () => kp(fn.snKeygen()),
  sntrupX25519Encapsulate(pk) {
    const e = [null]; const r = fn.snEncaps(u8(pk), u8(pk).length, e);
    const ss = b(r.shared_secret), ct = b(r.ciphertext); fn.kemFree(r);
    if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); }
    return { ciphertext: ct, sharedSecret: ss };
  },
  sntrupX25519Decapsulate: (ct, sk) => consume(fn.snDecaps(u8(ct), u8(ct).length, u8(sk), u8(sk).length)),

  blsKeygen: () => kp(fn.blsKeygen()),
  blsSign: (m, sk) => consume(fn.blsSign(u8(m), u8(m).length, u8(sk), u8(sk).length)),
  blsVerify: (m, sig, pk) => fn.blsVerify(u8(m), u8(m).length, u8(sig), u8(sig).length, u8(pk), u8(pk).length) === 1,

  // Keyring
  keyringCreate: () => fn.krCreate(),
  keyringAddDeviceSlot: (kr, factor) => fn.krAddDev(kr, u8(factor), u8(factor).length) === 0,
  keyringAddPassphraseSlot: (kr, pw, kdf = 0) => fn.krAddPw(kr, pw, kdf) === 0,
  keyringSlotCount: (kr) => Number(fn.krCount(kr)),
  keyringSerialise: (kr) => consume(fn.krSer(kr)),
  keyringDeserialise(blob) { const e = [null]; const kr = fn.krDeser(u8(blob), u8(blob).length, e); if (e[0]) { const m = koffi.decode(e[0], 'char', -1); fn.strFree(e[0]); throw new Error(m); } return kr; },
  keyringUnlockWithDevice: (kr, factor) => consume(fn.krUnlockDev(kr, u8(factor), u8(factor).length)),
  keyringUnlockWithPassphrase: (kr, pw) => consume(fn.krUnlockPw(kr, pw)),
  keyringRemoveSlot: (kr, index) => fn.krRemove(kr, index) === 1,
  keyringFree: (kr) => fn.krFree(kr),

  // ── Hash / KDF extras ──
  blake3Keyed: (m, key, len = 32) => consume(fn.blake3Keyed(u8(m), u8(m).length, u8(key), u8(key).length, len)),
  blake3DeriveKey: (ctx, ikm, len = 32) => consume(fn.blake3Derive(ctx, u8(ikm), u8(ikm).length, len)),
  hmacSha512: (m, key) => consume(fn.hmac512(u8(m), u8(m).length, u8(key), u8(key).length)),
  hmacSha512Verify: (m, mac, key) => fn.hmac512v(u8(m), u8(m).length, u8(mac), u8(mac).length, u8(key), u8(key).length) === 1,
  /** One-shot HKDF: extract + expand to `outLen` bytes. */
  hkdfDerive: (ikm, { salt = null, info = null, outLen = 32 } = {}) =>
    consume(fn.hkdf(u8(ikm), u8(ikm).length, salt ? u8(salt) : null, salt ? u8(salt).length : 0,
                    info ? u8(info) : null, info ? u8(info).length : 0, outLen)),
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
  entropyInfo(h) { const i = fn.entInfo(h); const out = { path: i.path ? koffi.decode(i.path, 'char', -1) : '', fileSize: Number(i.file_size), chunksRead: Number(i.chunks_read), entropyBits: i.entropy_bits }; fn.entInfoFree(i); return out; },
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
  stegoEmbed(coverPath, payload, outputPath) { const r = fn.stegoEmbed(coverPath, u8(payload), u8(payload).length, outputPath); if (r.ok !== 1) { const m = r.error ? koffi.decode(r.error, 'char', -1) : 'stego embed failed'; if (r.error) fn.strFree(r.error); throw new Error(m); } },
  stegoExtract: (stegoPath) => consume(fn.stegoExtract(stegoPath)),
  stegoCapacity: (coverPath) => Number(fn.stegoCapacity(coverPath)),

  // ── MolecularVault — max-assurance layered encryption ──
  molecularSeal: (pt, passphrase, aad = null, ops = 0, mem = 0) => consume(fn.molSeal(u8(pt), u8(pt).length, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0, ops, mem)),
  molecularOpen: (env, passphrase, aad = null) => consume(fn.molOpen(u8(env), u8(env).length, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  molecularSealWithKey: (pt, masterKey, aad = null) => consume(fn.molSealKey(u8(pt), u8(pt).length, u8(masterKey), u8(masterKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  molecularOpenWithKey: (env, masterKey, aad = null) => consume(fn.molOpenKey(u8(env), u8(env).length, u8(masterKey), u8(masterKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),

  // ── Suite — one-call advanced combinations (needs OpenSSL + PQ) ──
  // Post-quantum message: hybrid X25519+ML-KEM-768 → MolecularVault.
  suiteSealPq: (pt, recipientKemPublic, aad = null) => consume(fn.suiteSealPq(u8(pt), u8(pt).length, u8(recipientKemPublic), u8(recipientKemPublic).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  // sntrup761 hybrid variant; suiteOpenPq auto-detects the KEM from the envelope.
  suiteSealPqSntrup: (pt, recipientKemPublic, aad = null) => consume(fn.suiteSealPqSntrup(u8(pt), u8(pt).length, u8(recipientKemPublic), u8(recipientKemPublic).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteOpenPq: (env, recipientKemSecret, aad = null) => consume(fn.suiteOpenPq(u8(env), u8(env).length, u8(recipientKemSecret), u8(recipientKemSecret).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  // Flagship: PQ confidentiality + PQ signature authenticity (verified auth-first).
  suiteSealSignedPq: (pt, recipientKemPublic, signerSigSecret, aad = null) => consume(fn.suiteSealSignedPq(u8(pt), u8(pt).length, u8(recipientKemPublic), u8(recipientKemPublic).length, u8(signerSigSecret), u8(signerSigSecret).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteSealSignedPqSntrup: (pt, recipientKemPublic, signerSigSecret, aad = null) => consume(fn.suiteSealSignedPqSntrup(u8(pt), u8(pt).length, u8(recipientKemPublic), u8(recipientKemPublic).length, u8(signerSigSecret), u8(signerSigSecret).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteOpenSignedPq: (env, recipientKemSecret, signerSigPublic, aad = null) => consume(fn.suiteOpenSignedPq(u8(env), u8(env).length, u8(recipientKemSecret), u8(recipientKemSecret).length, u8(signerSigPublic), u8(signerSigPublic).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  // File-as-key: deterministic media entropy from `path` derives the master.
  suiteSealWithFile: (pt, path, aad = null) => consume(fn.suiteSealWithFile(u8(pt), u8(pt).length, path, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteOpenWithFile: (env, path, aad = null) => consume(fn.suiteOpenWithFile(u8(env), u8(env).length, path, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  // Keyring-guarded (kr from keyringCreate()/keyringDeserialise()).
  suiteSealWithKeyringDevice: (pt, kr, factorKey, aad = null) => consume(fn.suiteSealKrDev(u8(pt), u8(pt).length, kr, u8(factorKey), u8(factorKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteOpenWithKeyringDevice: (env, kr, factorKey, aad = null) => consume(fn.suiteOpenKrDev(u8(env), u8(env).length, kr, u8(factorKey), u8(factorKey).length, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteSealWithKeyringPassphrase: (pt, kr, passphrase, aad = null) => consume(fn.suiteSealKrPw(u8(pt), u8(pt).length, kr, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  suiteOpenWithKeyringPassphrase: (env, kr, passphrase, aad = null) => consume(fn.suiteOpenKrPw(u8(env), u8(env).length, kr, passphrase, aad ? u8(aad) : null, aad ? u8(aad).length : 0)),
  // EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  suiteEvmAddress: (secp256k1PublicKey) => consume(fn.suiteEvmAddr(u8(secp256k1PublicKey), u8(secp256k1PublicKey).length)),
  // Threshold (k-of-n): returns { envelope, shares:[record,...] }; open with any k.
  suiteSealThreshold(pt, n, k, aad = null) {
    const outShares = {};
    const env = consume(fn.suiteSealThr(u8(pt), u8(pt).length, n, k, aad ? u8(aad) : null, aad ? u8(aad).length : 0, outShares));
    const blob = (outShares.data && Number(outShares.len) > 0)
      ? Buffer.from(koffi.decode(outShares.data, 'uint8_t', Number(outShares.len))) : Buffer.alloc(0);
    fn.bufFree(outShares);
    return { envelope: env, shares: splitShareRecords(blob) };
  },
  suiteOpenThreshold(env, shares, aad = null) {
    const blob = Buffer.concat(shares.map(u8));
    return consume(fn.suiteOpenThr(u8(env), u8(env).length, blob, blob.length, aad ? u8(aad) : null, aad ? u8(aad).length : 0));
  },

  // Escape hatch for advanced/raw use.
  _fn: fn,
};
