/**
 * CryptoLib C FFI Bridge
 *
 * Flat C API wrapping the C++20 header-only cryptolib.
 * Designed for consumption by Go (cgo), Flutter/Dart (dart:ffi),
 * Python (ctypes/cffi), Rust, and any language with C FFI support.
 *
 * Memory contract:
 *   - Functions returning CryptoBuffer allocate via malloc().
 *   - The caller MUST call cryptolib_buffer_free() when done.
 *   - Input data is borrowed (const pointers) — never freed by the library.
 *   - Error messages are heap-allocated strings — free with cryptolib_str_free().
 *
 * Thread safety:
 *   - All functions are safe to call from multiple threads after cryptolib_init().
 *   - Handle objects (vault, entropy) are NOT thread-safe — use one per thread.
 */

#ifndef CRYPTOLIB_C_H
#define CRYPTOLIB_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#  ifdef CRYPTOLIB_BUILD_SHARED
#    define CRYPTO_API __declspec(dllexport)
#  else
#    define CRYPTO_API __declspec(dllimport)
#  endif
#else
#  define CRYPTO_API __attribute__((visibility("default")))
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Core types
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Heap-allocated byte buffer returned by library functions. */
typedef struct {
    uint8_t* data;   /**< Pointer to bytes (malloc'd). NULL on error. */
    size_t   len;    /**< Byte count. 0 on error. */
} CryptoBuffer;

/** Result of operations that may fail. */
typedef struct {
    int   ok;        /**< 1 = success, 0 = failure */
    char* error;     /**< Error message (heap-allocated). NULL on success. */
} CryptoResult;

/** Result carrying a buffer + possible error. */
typedef struct {
    CryptoBuffer buf;  /**< Output data. data=NULL on error. */
    char*        error; /**< Error message. NULL on success. */
} CryptoBufferResult;

/** Opaque handle types (pointer-sized, passed by value). */
typedef void* CryptoVaultHandle;
typedef void* CryptoEntropyHandle;
typedef void* CryptoStreamEncHandle;
typedef void* CryptoStreamDecHandle;
typedef void* CryptoKeyringHandle;

/** Key pair (two buffers). */
typedef struct {
    CryptoBuffer public_key;
    CryptoBuffer secret_key;
} CryptoKeyPair;

/** Asymmetric key bundle (Box + Sign). */
typedef struct {
    CryptoBuffer box_public;   /**< X25519 public key  (32 B) */
    CryptoBuffer box_secret;   /**< X25519 secret key  (32 B) */
    CryptoBuffer sign_public;  /**< Ed25519 public key (32 B) */
    CryptoBuffer sign_secret;  /**< Ed25519 secret key (64 B) */
} CryptoAsymBundle;

/** Encrypted packet (serialisable vault output). */
typedef struct {
    CryptoBuffer ciphertext;  /**< nonce + encrypted + MAC */
    CryptoBuffer signature;   /**< Ed25519 signature (64 B) */
    CryptoBuffer kdf_salt;    /**< Argon2id salt (16 B) */
} CryptoPacket;

/** Derived keys from media entropy. */
typedef struct {
    CryptoBuffer symmetric_key;     /**< 32 B — XChaCha20/AES-256 */
    CryptoBuffer vault_master_key;  /**< 32 B — SecureVault master */
    CryptoBuffer signing_seed;      /**< 32 B — Ed25519 seed */
    CryptoBuffer box_seed;          /**< 32 B — X25519 seed */
    CryptoBuffer stream_key;        /**< 32 B — SecretStream */
    CryptoBuffer raw_entropy;       /**< 64 B — raw mixed entropy */
} CryptoDerivedKeys;

/** Media entropy info. */
typedef struct {
    char*    path;           /**< Source file path (heap-allocated) */
    uint64_t file_size;      /**< Bytes */
    uint64_t chunks_read;    /**< Number of read passes */
    double   entropy_bits;   /**< Conservative estimate */
} CryptoEntropyInfo;

/* ═══════════════════════════════════════════════════════════════════════════
 * Memory management — MUST call these to avoid leaks
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Free a CryptoBuffer (securely zeroises before freeing). */
CRYPTO_API void cryptolib_buffer_free(CryptoBuffer* buf);

/** Free a heap-allocated error string. */
CRYPTO_API void cryptolib_str_free(char* str);

/** Free a CryptoKeyPair. */
CRYPTO_API void cryptolib_keypair_free(CryptoKeyPair* kp);

/** Free a CryptoAsymBundle. */
CRYPTO_API void cryptolib_bundle_free(CryptoAsymBundle* b);

/** Free a CryptoPacket. */
CRYPTO_API void cryptolib_packet_free(CryptoPacket* p);

/** Free a CryptoDerivedKeys. */
CRYPTO_API void cryptolib_derived_keys_free(CryptoDerivedKeys* dk);

/** Free a CryptoEntropyInfo. */
CRYPTO_API void cryptolib_entropy_info_free(CryptoEntropyInfo* info);

/* ═══════════════════════════════════════════════════════════════════════════
 * Initialisation & utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Initialise libsodium. Call once at program start. Returns 0 on success. */
CRYPTO_API int cryptolib_init(void);

/** Generate n cryptographically secure random bytes. */
CRYPTO_API CryptoBufferResult cryptolib_random_bytes(size_t n);

/** Constant-time comparison. Returns 1 if equal, 0 if not. */
CRYPTO_API int cryptolib_secure_equal(const uint8_t* a, size_t a_len,
                                       const uint8_t* b, size_t b_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * Hashing
 * ═══════════════════════════════════════════════════════════════════════════ */

/** BLAKE2b-512 hash. key/key_len may be NULL/0 for unkeyed. */
CRYPTO_API CryptoBufferResult cryptolib_blake2b(const uint8_t* msg, size_t msg_len,
                                                 const uint8_t* key, size_t key_len);

/** SHA-256 hash. */
CRYPTO_API CryptoBufferResult cryptolib_sha256(const uint8_t* msg, size_t msg_len);

/** SHA-512 hash. */
CRYPTO_API CryptoBufferResult cryptolib_sha512(const uint8_t* msg, size_t msg_len);

/** HMAC-SHA512. */
CRYPTO_API CryptoBufferResult cryptolib_hmac_sha512(const uint8_t* msg, size_t msg_len,
                                                     const uint8_t* key, size_t key_len);

/** HMAC-SHA512 verify. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_hmac_sha512_verify(const uint8_t* msg, size_t msg_len,
                                             const uint8_t* mac, size_t mac_len,
                                             const uint8_t* key, size_t key_len);

/* ─── Argon2id ────────────────────────────────────────────────────────────── */

/** Hash a password to PHC string format (e.g. "$argon2id$v=19$..."). */
CRYPTO_API CryptoBufferResult cryptolib_argon2id_hash_str(const char* password,
                                                           uint64_t ops, size_t mem);

/** Verify password against PHC string. Returns 1 if correct, 0 if not. */
CRYPTO_API int cryptolib_argon2id_verify_str(const char* password, const char* phc_str);

/** Derive a key from password + salt. */
CRYPTO_API CryptoBufferResult cryptolib_argon2id_derive(const char* password,
                                                         const uint8_t* salt, size_t salt_len,
                                                         size_t key_len, uint64_t ops, size_t mem);

/* ═══════════════════════════════════════════════════════════════════════════
 * Symmetric encryption
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Generate a 32-byte random key. */
CRYPTO_API CryptoBufferResult cryptolib_sym_keygen(void);

/** XChaCha20-Poly1305 encrypt. Output: [nonce(24) | ciphertext | MAC(16)]. */
CRYPTO_API CryptoBufferResult cryptolib_xchacha20_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** XChaCha20-Poly1305 decrypt. Input must include nonce prefix. */
CRYPTO_API CryptoBufferResult cryptolib_xchacha20_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** Committing AEAD (UtC) encrypt. Output: [commitment(32) | nonce | ct | MAC].
 *  Commits to (key, AAD) — closes the partitioning-oracle / non-committal gap. */
CRYPTO_API CryptoBufferResult cryptolib_committing_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** Committing AEAD (UtC) decrypt. Fails closed on commitment OR auth mismatch. */
CRYPTO_API CryptoBufferResult cryptolib_committing_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/* ── MolecularVault — max-assurance layered encryption ──────────────────────
 * Cascade of XChaCha20-Poly1305 ∘ AES-256-GCM-SIV under a key-committing outer
 * layer, keyed by Argon2id(passphrase) or a caller-supplied 32-byte master.
 * Requires OpenSSL for the GCM-SIV layer. Self-describing versioned envelope. */

/** Seal under a passphrase. ops/mem are Argon2id work factors; pass 0,0 for the
 *  SENSITIVE preset. Higher mem (e.g. 1<<30 = 1 GiB) makes guessing far costlier. */
CRYPTO_API CryptoBufferResult cryptolib_molecular_seal(
    const uint8_t* plaintext, size_t pt_len,
    const char* passphrase,
    const uint8_t* aad, size_t aad_len,
    uint64_t ops, size_t mem);

/** Open a passphrase-sealed envelope. AAD must match exactly; fails closed. */
CRYPTO_API CryptoBufferResult cryptolib_molecular_open(
    const uint8_t* envelope, size_t env_len,
    const char* passphrase,
    const uint8_t* aad, size_t aad_len);

/** Seal under a 32-byte full-entropy master key (e.g. from the hybrid KEM). */
CRYPTO_API CryptoBufferResult cryptolib_molecular_seal_with_key(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* master_key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** Open a raw-key-sealed envelope. */
CRYPTO_API CryptoBufferResult cryptolib_molecular_open_with_key(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* master_key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/* ── Suite — one-call advanced combinations ─────────────────────────────────
 * High-level facade composing hybrid KEM, hybrid signatures, MolecularVault,
 * media entropy, keyring, Shamir and Keccak into single calls. Every seal is
 * authenticated and fails closed; PQ envelopes are self-describing (they carry
 * the KEM ciphertext). Requires OpenSSL + PQ; without them these return an
 * error (ABI-stable). */

/** Post-quantum message: encapsulate to the recipient's hybrid KEM public key,
 *  then MolecularVault-seal under the shared secret. Envelope carries the KEM ct. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq(
    const uint8_t* pt, size_t pt_len,
    const uint8_t* recipient_kem_public, size_t kem_pub_len,
    const uint8_t* aad, size_t aad_len);
/** Same, but with the X25519+sntrup761 hybrid KEM (a different lattice family).
 *  open_pq below auto-detects which KEM from the envelope's suite id. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq_sntrup(
    const uint8_t* pt, size_t pt_len,
    const uint8_t* recipient_kem_public, size_t kem_pub_len,
    const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_pq(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* recipient_kem_secret, size_t kem_sec_len,
    const uint8_t* aad, size_t aad_len);

/** Signed + PQ-sealed (flagship): PQ confidentiality + hybrid-signature
 *  authenticity. open_* returns plaintext ONLY if the signature verifies. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq(
    const uint8_t* pt, size_t pt_len,
    const uint8_t* recipient_kem_public, size_t kem_pub_len,
    const uint8_t* signer_sig_secret, size_t sig_sec_len,
    const uint8_t* aad, size_t aad_len);
/** Same, but with the X25519+sntrup761 hybrid KEM. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq_sntrup(
    const uint8_t* pt, size_t pt_len,
    const uint8_t* recipient_kem_public, size_t kem_pub_len,
    const uint8_t* signer_sig_secret, size_t sig_sec_len,
    const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_signed_pq(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* recipient_kem_secret, size_t kem_sec_len,
    const uint8_t* signer_sig_public, size_t sig_pub_len,
    const uint8_t* aad, size_t aad_len);

/** File-as-key: deterministic media entropy from `path` derives the master. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_file(
    const uint8_t* pt, size_t pt_len, const char* path,
    const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_file(
    const uint8_t* envelope, size_t env_len, const char* path,
    const uint8_t* aad, size_t aad_len);

/** Keyring-guarded: a Keyring slot unlock provides the MolecularVault master. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_device(
    const uint8_t* pt, size_t pt_len, CryptoKeyringHandle kr,
    const uint8_t* factor_key, size_t factor_len,
    const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_device(
    const uint8_t* envelope, size_t env_len, CryptoKeyringHandle kr,
    const uint8_t* factor_key, size_t factor_len,
    const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_passphrase(
    const uint8_t* pt, size_t pt_len, CryptoKeyringHandle kr,
    const char* passphrase, const uint8_t* aad, size_t aad_len);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_passphrase(
    const uint8_t* envelope, size_t env_len, CryptoKeyringHandle kr,
    const char* passphrase, const uint8_t* aad, size_t aad_len);

/** Threshold (k-of-n): seal under a fresh master, split it into `n` Shamir
 *  shares of which any `k` reconstruct. Returns the envelope; `out_shares`
 *  receives the `n` shares concatenated, each framed [index(1)|ylen(4 LE)|y].
 *  To open, concatenate any >= k of those share records and pass them below.
 *  Free `out_shares` with cryptolib_buffer_free. */
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_threshold(
    const uint8_t* pt, size_t pt_len, uint8_t n, uint8_t k,
    const uint8_t* aad, size_t aad_len, CryptoBuffer* out_shares);
CRYPTO_API CryptoBufferResult cryptolib_suite_open_threshold(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* shares, size_t shares_len,
    const uint8_t* aad, size_t aad_len);

/** EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key. */
CRYPTO_API CryptoBufferResult cryptolib_suite_evm_address(
    const uint8_t* public_key, size_t pk_len);

/* ─── Flagship / Fortress — state-of-the-art sealed messaging ─────────────────
 *   Two tiers of one construction: encapsulate → sign-then-encrypt inside a
 *   key-committing cascade, RECIPIENT-BOUND, auth-first. tier: 0 = Flagship
 *   (X25519+sntrup761 KEM, Ed25519+ML-DSA-65 sig); 1 = Fortress (+ML-KEM-768
 *   triple KEM, +SLH-DSA triple sig). Requires OpenSSL + PQ. */

/** Opaque streaming handles. Free with the matching *_free. */
typedef void* CryptoSealedSealer;
typedef void* CryptoSealedOpener;

/** Public envelope metadata (no secrets). ok=0 if the envelope is unrecognizable. */
typedef struct {
    uint8_t ok;
    uint8_t version;
    uint8_t suite;          /**< 0x01 Flagship, 0x02 Fortress */
    uint8_t streaming;      /**< 1 = stream preamble, 0 = one-shot */
    uint8_t fingerprint[16];/**< BLAKE2b-128 of the recipient public key */
    size_t  kem_ciphertext_len;
} CryptoSealedInfo;

/** Create a recipient (KEM) / sender (signature) keypair for the given tier. */
CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_recipient(int tier);
CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_sender(int tier);

/** One-shot seal (sign-then-encrypt, recipient-bound). purpose may be NULL. */
CRYPTO_API CryptoBufferResult cryptolib_sealed_seal(
    int tier, const uint8_t* pt, size_t pt_len,
    const uint8_t* recipient_public, size_t rpub_len,
    const uint8_t* sender_secret, size_t ssec_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* purpose, size_t purpose_len);
/** One-shot open (auth-first). Needs the recipient's OWN public key for the binding. */
CRYPTO_API CryptoBufferResult cryptolib_sealed_open(
    int tier, const uint8_t* envelope, size_t env_len,
    const uint8_t* recipient_secret, size_t rsec_len,
    const uint8_t* recipient_public, size_t rpub_len,
    const uint8_t* sender_public, size_t spub_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* purpose, size_t purpose_len);

/** Inspect public metadata (no secrets); addressed_to returns 1 on fingerprint match. */
CRYPTO_API CryptoSealedInfo cryptolib_sealed_inspect(const uint8_t* envelope, size_t env_len);
CRYPTO_API int cryptolib_sealed_addressed_to(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* recipient_public, size_t rpub_len);

/* Streaming: begin → (preamble) → push* → finalize(+trailer) ; free when done. */
CRYPTO_API CryptoSealedSealer cryptolib_sealed_sealer_begin(
    int tier, const uint8_t* recipient_public, size_t rpub_len,
    const uint8_t* sender_secret, size_t ssec_len,
    const uint8_t* purpose, size_t purpose_len, char** out_error);
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_preamble(CryptoSealedSealer h);
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_push(
    CryptoSealedSealer h, const uint8_t* chunk, size_t chunk_len);
/** Final ciphertext returned; the signed trailer is written to out_trailer. */
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_finalize(
    CryptoSealedSealer h, const uint8_t* last_chunk, size_t last_len, CryptoBuffer* out_trailer);
CRYPTO_API void cryptolib_sealed_sealer_free(CryptoSealedSealer h);

/* Streaming open: begin → pull* (out_final=1 on the last chunk) → finalize(trailer). */
CRYPTO_API CryptoSealedOpener cryptolib_sealed_opener_begin(
    int tier, const uint8_t* preamble, size_t pre_len,
    const uint8_t* recipient_secret, size_t rsec_len,
    const uint8_t* recipient_public, size_t rpub_len,
    const uint8_t* sender_public, size_t spub_len,
    const uint8_t* purpose, size_t purpose_len, char** out_error);
CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_pull(
    CryptoSealedOpener h, const uint8_t* ct, size_t ct_len, int* out_final);
/** Verify the sender signature over the whole stream. Empty buf + no error = OK. */
CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_finalize(
    CryptoSealedOpener h, const uint8_t* trailer, size_t trailer_len);
CRYPTO_API void cryptolib_sealed_opener_free(CryptoSealedOpener h);

/** AES-256-GCM encrypt. Output: [nonce(12) | ciphertext | MAC(16)]. */
CRYPTO_API CryptoBufferResult cryptolib_aes256gcm_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** AES-256-GCM decrypt. */
CRYPTO_API CryptoBufferResult cryptolib_aes256gcm_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len);

/** Check if AES-256-GCM is available on this CPU. */
CRYPTO_API int cryptolib_aes256gcm_available(void);

/* ─── SecretStream (chunked streaming AEAD) ───────────────────────────────── */

/** Create an encryptor. Returns handle. key must be 32 bytes. */
CRYPTO_API CryptoStreamEncHandle cryptolib_stream_enc_create(const uint8_t* key);

/** Get the stream header (24 bytes). Must be sent to the decryptor. */
CRYPTO_API CryptoBufferResult cryptolib_stream_enc_header(CryptoStreamEncHandle h);

/** Push a chunk. tag: 0=MESSAGE, 3=FINAL. */
CRYPTO_API CryptoBufferResult cryptolib_stream_enc_push(
    CryptoStreamEncHandle h,
    const uint8_t* plaintext, size_t pt_len, uint8_t tag);

/** Destroy encryptor handle. */
CRYPTO_API void cryptolib_stream_enc_free(CryptoStreamEncHandle h);

/** Create a decryptor. key=32B, header=24B. */
CRYPTO_API CryptoStreamDecHandle cryptolib_stream_dec_create(
    const uint8_t* key, const uint8_t* header);

/** Pull a chunk. Returns plaintext. Sets *out_tag to the tag byte. */
CRYPTO_API CryptoBufferResult cryptolib_stream_dec_pull(
    CryptoStreamDecHandle h,
    const uint8_t* ciphertext, size_t ct_len, uint8_t* out_tag);

/** Destroy decryptor handle. */
CRYPTO_API void cryptolib_stream_dec_free(CryptoStreamDecHandle h);

/* ═══════════════════════════════════════════════════════════════════════════
 * Asymmetric cryptography
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ─── Ed25519 ─────────────────────────────────────────────────────────────── */

/** Generate an Ed25519 signing keypair. */
CRYPTO_API CryptoKeyPair cryptolib_ed25519_keygen(void);

/** Generate Ed25519 keypair from a 32-byte seed (deterministic). */
CRYPTO_API CryptoKeyPair cryptolib_ed25519_keygen_from_seed(const uint8_t* seed, size_t seed_len);

/** Sign a message. Returns 64-byte detached signature. */
CRYPTO_API CryptoBufferResult cryptolib_ed25519_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len);

/** Verify a detached signature. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_ed25519_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len);

/* ─── X25519 ──────────────────────────────────────────────────────────────── */

/** Generate an X25519 key agreement keypair. */
CRYPTO_API CryptoKeyPair cryptolib_x25519_keygen(void);

/** Compute X25519 shared secret (32 bytes). */
CRYPTO_API CryptoBufferResult cryptolib_x25519_shared_secret(
    const uint8_t* our_secret, size_t our_len,
    const uint8_t* their_public, size_t their_len);

/* ─── Box (authenticated encryption) ──────────────────────────────────────── */

/** Generate a Box keypair (X25519). */
CRYPTO_API CryptoKeyPair cryptolib_box_keygen(void);

/** Box encrypt: sender→recipient authenticated encryption. */
CRYPTO_API CryptoBufferResult cryptolib_box_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* recipient_pub, size_t rpub_len,
    const uint8_t* sender_sec, size_t ssec_len);

/** Box decrypt. */
CRYPTO_API CryptoBufferResult cryptolib_box_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* sender_pub, size_t spub_len,
    const uint8_t* recipient_sec, size_t rsec_len);

/* ─── SealedBox (anonymous sender) ────────────────────────────────────────── */

/** SealedBox encrypt (anonymous sender). */
CRYPTO_API CryptoBufferResult cryptolib_sealedbox_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* recipient_pub, size_t rpub_len);

/** SealedBox decrypt. */
CRYPTO_API CryptoBufferResult cryptolib_sealedbox_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* recipient_pub, size_t rpub_len,
    const uint8_t* recipient_sec, size_t rsec_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * Vault — 4-layer pipeline (Argon2id → BLAKE2b → XChaCha20 → Ed25519)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Create a vault from a 32-byte master key. kdf: 0=interactive, 1=sensitive. */
CRYPTO_API CryptoVaultHandle cryptolib_vault_create(
    const uint8_t* master_key, size_t mk_len, int kdf_preset);

/** Create a vault from a media entropy handle (file = key). */
CRYPTO_API CryptoVaultHandle cryptolib_vault_from_entropy(
    CryptoEntropyHandle entropy, int kdf_preset);

/** Seal plaintext through the vault pipeline. Returns a packet. */
CRYPTO_API CryptoPacket cryptolib_vault_seal(
    CryptoVaultHandle vault,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, char** out_error);

/** Seal with entropy boost (two-factor: master key + media file). */
CRYPTO_API CryptoPacket cryptolib_vault_seal_boosted(
    CryptoVaultHandle vault,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, CryptoEntropyHandle boost, char** out_error);

/** Open a vault packet. */
CRYPTO_API CryptoBufferResult cryptolib_vault_open(
    CryptoVaultHandle vault,
    const CryptoPacket* packet, const char* aad);

/** Open with entropy boost. */
CRYPTO_API CryptoBufferResult cryptolib_vault_open_boosted(
    CryptoVaultHandle vault,
    const CryptoPacket* packet, const char* aad,
    CryptoEntropyHandle boost);

/** Get the vault's Ed25519 public key. Caller must free the buffer. */
CRYPTO_API CryptoBufferResult cryptolib_vault_public_key(CryptoVaultHandle vault);

/** Serialise a packet to flat bytes. */
CRYPTO_API CryptoBufferResult cryptolib_packet_serialise(const CryptoPacket* packet);

/** Deserialise flat bytes to a packet. */
CRYPTO_API CryptoPacket cryptolib_packet_deserialise(
    const uint8_t* data, size_t len, char** out_error);

/** Destroy a vault handle. */
CRYPTO_API void cryptolib_vault_free(CryptoVaultHandle vault);

/* ═══════════════════════════════════════════════════════════════════════════
 * Asymmetric Vault — Alice→Bob authenticated encryption
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Generate a full asymmetric key bundle (X25519 + Ed25519). */
CRYPTO_API CryptoAsymBundle cryptolib_asym_bundle_generate(void);

/** Seal: sender encrypts for recipient with signature. */
CRYPTO_API CryptoPacket cryptolib_asym_vault_seal(
    const CryptoAsymBundle* sender,
    const uint8_t* recipient_box_pub, size_t rpub_len,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, char** out_error);

/** Open: recipient decrypts and verifies sender's signature. */
CRYPTO_API CryptoBufferResult cryptolib_asym_vault_open(
    const CryptoPacket* packet,
    const CryptoAsymBundle* recipient,
    const uint8_t* sender_sign_pub, size_t spub_len,
    const char* aad);

/* ═══════════════════════════════════════════════════════════════════════════
 * Media Entropy — LavaRand-inspired key derivation from files
 *
 * The core concept: any media file (photo, audio, video) becomes
 * a cryptographic key source. Pixel noise, thermal noise, sensor
 * jitter — all contain physical entropy no algorithm can predict.
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Harvest entropy from a file (LavaRand mode).
 * Mixes system entropy — different keys every call.
 * Best for session keys.
 */
CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_file(
    const char* path, char** out_error);

/**
 * Harvest entropy from a file (deterministic mode).
 * Same file always produces same keys — cross-process reproducible.
 * Best for key agreement: "we both have the same photo."
 */
CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_file_deterministic(
    const char* path, char** out_error);

/**
 * Harvest entropy from multiple files (LavaRand mode).
 * Combined entropy exceeds any single source.
 */
CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_files(
    const char** paths, size_t count, char** out_error);

/**
 * Harvest entropy from multiple files (deterministic mode).
 */
CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_files_deterministic(
    const char** paths, size_t count, char** out_error);

/** Get all 6 domain-separated keys at once. */
CRYPTO_API CryptoDerivedKeys cryptolib_entropy_derive_all(CryptoEntropyHandle h);

/** Get a single 32-byte symmetric key. */
CRYPTO_API CryptoBufferResult cryptolib_entropy_symmetric_key(CryptoEntropyHandle h);

/** Get the 64-byte raw mixed entropy. */
CRYPTO_API CryptoBufferResult cryptolib_entropy_raw(CryptoEntropyHandle h);

/** Get the 32-byte entropy boost key (for two-factor vault). */
CRYPTO_API CryptoBufferResult cryptolib_entropy_boost(CryptoEntropyHandle h);

/** Get entropy info (file path, size, bits). */
CRYPTO_API CryptoEntropyInfo cryptolib_entropy_info(CryptoEntropyHandle h);

/** Get a full asymmetric bundle (X25519 + Ed25519) from entropy. */
CRYPTO_API CryptoAsymBundle cryptolib_entropy_asym_bundle(
    CryptoEntropyHandle h, char** out_error);

/** Refresh system entropy in-place (for long-lived sessions). */
CRYPTO_API void cryptolib_entropy_refresh(CryptoEntropyHandle h);

/** Destroy an entropy handle. */
CRYPTO_API void cryptolib_entropy_free(CryptoEntropyHandle h);

/* ─── Entropy convenience functions (no handle needed) ────────────────────── */

/** One-liner: get a 32-byte key from a file. */
CRYPTO_API CryptoBufferResult cryptolib_key_from_file(const char* path);

/**
 * One-liner: encrypt plaintext using a file as the key.
 * Uses deterministic mode internally so the same file can decrypt.
 */
CRYPTO_API CryptoPacket cryptolib_seal_from_file(
    const char* path, const char* plaintext, const char* aad, char** out_error);

/** One-liner: decrypt a packet using a file as the key. */
CRYPTO_API CryptoBufferResult cryptolib_open_from_file(
    const char* path, const CryptoPacket* packet, const char* aad);

/* ═══════════════════════════════════════════════════════════════════════════
 * BLAKE3 — fast parallelizable hash (requires libblake3, -DCRYPTOLIB_BLAKE3=ON)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** BLAKE3 hash. out_len=0 defaults to 32 bytes. Extendable output. */
CRYPTO_API CryptoBufferResult cryptolib_blake3(const uint8_t* msg, size_t msg_len,
                                                size_t out_len);

/** BLAKE3 keyed MAC. key must be exactly 32 bytes. */
CRYPTO_API CryptoBufferResult cryptolib_blake3_keyed(const uint8_t* msg, size_t msg_len,
                                                      const uint8_t* key, size_t key_len,
                                                      size_t out_len);

/** BLAKE3 key derivation. context is a domain string. */
CRYPTO_API CryptoBufferResult cryptolib_blake3_derive_key(const char* context,
                                                           const uint8_t* ikm, size_t ikm_len,
                                                           size_t out_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 & HKDF-SHA256
 * ═══════════════════════════════════════════════════════════════════════════ */

/** HMAC-SHA256 compute. Key must be >= 32 bytes. */
CRYPTO_API CryptoBufferResult cryptolib_hmac_sha256(const uint8_t* msg, size_t msg_len,
                                                     const uint8_t* key, size_t key_len);

/** HMAC-SHA256 verify. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_hmac_sha256_verify(const uint8_t* msg, size_t msg_len,
                                             const uint8_t* mac, size_t mac_len,
                                             const uint8_t* key, size_t key_len);

/** HKDF-SHA256 extract: PRK = HMAC(salt, IKM). salt may be NULL for default. */
CRYPTO_API CryptoBufferResult cryptolib_hkdf_extract(const uint8_t* salt, size_t salt_len,
                                                      const uint8_t* ikm, size_t ikm_len);

/** HKDF-SHA256 expand: OKM from PRK + info. */
CRYPTO_API CryptoBufferResult cryptolib_hkdf_expand(const uint8_t* prk, size_t prk_len,
                                                     const uint8_t* info, size_t info_len,
                                                     size_t out_len);

/** HKDF-SHA256 one-shot: extract + expand. */
CRYPTO_API CryptoBufferResult cryptolib_hkdf_derive(const uint8_t* ikm, size_t ikm_len,
                                                     const uint8_t* salt, size_t salt_len,
                                                     const uint8_t* info, size_t info_len,
                                                     size_t out_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * Post-Quantum — ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
 *   Requires liboqs, -DCRYPTOLIB_PQ=ON
 * ═══════════════════════════════════════════════════════════════════════════ */

/** KEM encapsulation result (ciphertext + shared secret). */
typedef struct {
    CryptoBuffer ciphertext;
    CryptoBuffer shared_secret;
} CryptoKemEncapsResult;

/** Free a CryptoKemEncapsResult. */
CRYPTO_API void cryptolib_kem_encaps_free(CryptoKemEncapsResult* r);

/* ─── ML-KEM (FIPS 203) ──────────────────────────────────────────────────── */

/** ML-KEM keygen. level: 0=512, 1=768, 2=1024. */
CRYPTO_API CryptoKeyPair cryptolib_ml_kem_keygen(int level);

/** ML-KEM encapsulate. Produces ciphertext + shared_secret. */
CRYPTO_API CryptoKemEncapsResult cryptolib_ml_kem_encapsulate(
    const uint8_t* public_key, size_t pk_len, int level, char** out_error);

/** ML-KEM decapsulate. Returns shared_secret (32 bytes). */
CRYPTO_API CryptoBufferResult cryptolib_ml_kem_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len, int level);

/* ─── Hybrid KEM (X25519 + ML-KEM-768) ───────────────────────────────────────
 *   One shared secret from both a classical (X25519) and a post-quantum
 *   (ML-KEM-768) KEM; secure while either remains unbroken. Keys/ciphertexts
 *   are concatenated: x25519_part(32) || ml_kem_768_part. No level argument —
 *   the pairing is fixed to NIST L3. NOT wire-compatible with TLS/X-Wing. */

/** Hybrid KEM keygen → public_key/secret_key (concatenated layout). */
CRYPTO_API CryptoKeyPair cryptolib_hybrid_kem_keygen(void);

/** Hybrid KEM encapsulate. Produces ciphertext + 32-byte shared_secret. */
CRYPTO_API CryptoKemEncapsResult cryptolib_hybrid_kem_encapsulate(
    const uint8_t* public_key, size_t pk_len, char** out_error);

/** Hybrid KEM decapsulate. Returns shared_secret (32 bytes). */
CRYPTO_API CryptoBufferResult cryptolib_hybrid_kem_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len);

/* ─── Hybrid KEM (X25519 + sntrup761) ────────────────────────────────────────
 *   A SECOND hybrid, using Streamlined NTRU Prime 761 (a different lattice
 *   family than ML-KEM) for defense-in-diversity. Same concatenated layout:
 *   x25519_part(32) || sntrup761_part. Always liboqs-backed. NOT wire-compatible
 *   with OpenSSH's sntrup761x25519-sha512. */

/** sntrup761 hybrid keygen → public_key/secret_key (concatenated layout). */
CRYPTO_API CryptoKeyPair cryptolib_sntrup_x25519_keygen(void);

/** sntrup761 hybrid encapsulate. Produces ciphertext + 32-byte shared_secret. */
CRYPTO_API CryptoKemEncapsResult cryptolib_sntrup_x25519_encapsulate(
    const uint8_t* public_key, size_t pk_len, char** out_error);

/** sntrup761 hybrid decapsulate. Returns shared_secret (32 bytes). */
CRYPTO_API CryptoBufferResult cryptolib_sntrup_x25519_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len);

/* ─── Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet) ─────────
 *   A live channel with forward secrecy + post-compromise security, all
 *   post-quantum. Stateful — a CryptoSession is an opaque handle; free it with
 *   cryptolib_session_free. Handshake: the responder publishes a prekey (a
 *   hybrid-KEM keypair); the initiator encapsulates to it. Requires PQ. */

/** Opaque ratchet session handle. */
typedef void* CryptoSession;

/** Responder: generate a prekey (hybrid-KEM keypair). Publish public_key. */
CRYPTO_API CryptoKeyPair cryptolib_session_generate_prekey(void);

/** Initiator: start a session to responder_prekey_public. The returned handle's
 *  cryptolib_session_handshake() is the message to send to the responder. */
CRYPTO_API CryptoSession cryptolib_session_initiate(
    const uint8_t* responder_prekey_public, size_t pk_len, char** out_error);

/** The handshake message an initiator session must send (empty on a responder). */
CRYPTO_API CryptoBufferResult cryptolib_session_handshake(CryptoSession h);

/** Responder: accept an incoming handshake with your prekey (public + secret). */
CRYPTO_API CryptoSession cryptolib_session_accept(
    const uint8_t* handshake, size_t hs_len,
    const uint8_t* prekey_public, size_t pk_len,
    const uint8_t* prekey_secret, size_t sk_len, char** out_error);

/** Encrypt the next outgoing message (advances the sending ratchet). */
CRYPTO_API CryptoBufferResult cryptolib_session_encrypt(
    CryptoSession h, const uint8_t* pt, size_t pt_len, const uint8_t* aad, size_t aad_len);

/** Decrypt an incoming message (handles ratchet turns + out-of-order; transactional). */
CRYPTO_API CryptoBufferResult cryptolib_session_decrypt(
    CryptoSession h, const uint8_t* msg, size_t msg_len, const uint8_t* aad, size_t aad_len);

/** Free a session handle. */
CRYPTO_API void cryptolib_session_free(CryptoSession h);

/* ─── ML-DSA (FIPS 204) ──────────────────────────────────────────────────── */

/** ML-DSA keygen. level: 0=44, 1=65, 2=87. */
CRYPTO_API CryptoKeyPair cryptolib_ml_dsa_keygen(int level);

/** ML-DSA sign. Returns detached signature. */
CRYPTO_API CryptoBufferResult cryptolib_ml_dsa_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len, int level);

/** ML-DSA verify. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_ml_dsa_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len, int level);

/* ─── Hybrid signature (Ed25519 + ML-DSA-65) ──────────────────────────────────
 *   Both must verify. Keys/sig concatenated: ed25519_part || ml_dsa_part. */
CRYPTO_API CryptoKeyPair cryptolib_hybrid_sig_keygen(void);
CRYPTO_API CryptoBufferResult cryptolib_hybrid_sig_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len);
CRYPTO_API int cryptolib_hybrid_sig_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len);

/* ─── SLH-DSA (FIPS 205) ─────────────────────────────────────────────────── */

/** SLH-DSA keygen. level: 0=128s,1=128f,2=192s,3=192f,4=256s,5=256f. hash: 0=SHA2,1=SHAKE. */
CRYPTO_API CryptoKeyPair cryptolib_slh_dsa_keygen(int level, int hash_family);

/** SLH-DSA sign. Returns signature. */
CRYPTO_API CryptoBufferResult cryptolib_slh_dsa_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len, int level, int hash_family);

/** SLH-DSA verify. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_slh_dsa_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len, int level, int hash_family);

/* ═══════════════════════════════════════════════════════════════════════════
 * BLS12-381 — Aggregate signatures (requires blst, -DCRYPTOLIB_BLS=ON)
 * ═══════════════════════════════════════════════════════════════════════════ */

/** BLS keygen (random). sk=32B, pk=48B. */
CRYPTO_API CryptoKeyPair cryptolib_bls_keygen(void);

/** BLS keygen from IKM (deterministic). ikm must be >= 32 bytes. */
CRYPTO_API CryptoKeyPair cryptolib_bls_keygen_from_ikm(const uint8_t* ikm, size_t ikm_len);

/** BLS sign. Returns 96-byte compressed G2 signature. */
CRYPTO_API CryptoBufferResult cryptolib_bls_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len);

/** BLS verify. Returns 1 if valid, 0 if not. */
CRYPTO_API int cryptolib_bls_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len);

/** BLS aggregate N signatures into 1. sigs = array of 96-byte signatures. */
CRYPTO_API CryptoBufferResult cryptolib_bls_aggregate(
    const uint8_t* const* sigs, const size_t* sig_lens, size_t count);

/** BLS aggregate verify. msgs/pks = arrays of messages/public keys. */
CRYPTO_API int cryptolib_bls_aggregate_verify(
    const uint8_t* const* msgs, const size_t* msg_lens,
    const uint8_t* const* pks,  const size_t* pk_lens,
    size_t count,
    const uint8_t* agg_sig, size_t agg_sig_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * FROST(Ed25519, SHA-512) — t-of-n threshold Schnorr signatures (RFC 9591)
 *   Output is a standard 64-byte Ed25519 signature; verifiers need not know
 *   the threshold setup. libsodium only — no extra deps, no build guard.
 *
 *   A round's commitments are passed as three parallel arrays of length
 *   `count`: identifiers[i] (uint16), hiding_commits[i*32 ..], and
 *   binding_commits[i*32 ..].  Signature shares are `count` contiguous
 *   32-byte scalars.  All scalars/points are 32 bytes; a signature is 64.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Trusted-dealer keygen output. Share k (0-based) has identifier k+1. */
typedef struct {
    CryptoBuffer group_public_key;  /**< 32 B */
    CryptoBuffer secret_shares;     /**< count * 32 B — secret scalars sk_i */
    CryptoBuffer public_shares;     /**< count * 32 B — points PK_i (verify_share) */
    size_t       count;             /**< number of participants (n) */
    char*        error;             /**< heap-allocated; NULL on success */
} CryptoFrostKeyGen;

/** Free a CryptoFrostKeyGen (zeroises secret shares). */
CRYPTO_API void cryptolib_frost_keygen_free(CryptoFrostKeyGen* kg);

/** Round-1 commit output: two secret nonces + their public commitments. */
typedef struct {
    CryptoBuffer hiding_nonce;    /**< 32 B secret scalar */
    CryptoBuffer binding_nonce;   /**< 32 B secret scalar */
    CryptoBuffer hiding_commit;   /**< 32 B point (share to coordinator) */
    CryptoBuffer binding_commit;  /**< 32 B point (share to coordinator) */
    char*        error;           /**< heap-allocated; NULL on success */
} CryptoFrostCommit;

/** Free a CryptoFrostCommit (zeroises nonces). */
CRYPTO_API void cryptolib_frost_commit_free(CryptoFrostCommit* c);

/** keygen(n,t): split a random group key into n shares, any t of which sign. */
CRYPTO_API CryptoFrostKeyGen cryptolib_frost_keygen(uint16_t n, uint16_t t);

/** Round 1: fresh random nonce pair + public commitment for a share. */
CRYPTO_API CryptoFrostCommit cryptolib_frost_commit(
    const uint8_t* share_secret, size_t sk_len, uint16_t identifier);

/** Deterministic round-1 commit from caller-supplied nonces (test vectors). */
CRYPTO_API CryptoFrostCommit cryptolib_frost_commit_with_nonces(
    uint16_t identifier,
    const uint8_t* hiding_nonce, size_t hn_len,
    const uint8_t* binding_nonce, size_t bn_len);

/** Round 2: this participant's 32-byte signature share. */
CRYPTO_API CryptoBufferResult cryptolib_frost_sign(
    uint16_t identifier,
    const uint8_t* share_secret, size_t sk_len,
    const uint8_t* group_public_key, size_t gpk_len,
    const uint8_t* hiding_nonce, size_t hn_len,
    const uint8_t* binding_nonce, size_t bn_len,
    const uint8_t* msg, size_t msg_len,
    const uint16_t* ids,
    const uint8_t* hiding_commits,
    const uint8_t* binding_commits,
    size_t count);

/** Aggregate `count` signature shares → one 64-byte Ed25519 signature. */
CRYPTO_API CryptoBufferResult cryptolib_frost_aggregate(
    const uint8_t* group_public_key, size_t gpk_len,
    const uint8_t* msg, size_t msg_len,
    const uint16_t* ids,
    const uint8_t* hiding_commits,
    const uint8_t* binding_commits,
    size_t count,
    const uint8_t* sig_shares /* count * 32 B */);

/** Verify an aggregate signature with standard Ed25519. Returns 1/0. */
CRYPTO_API int cryptolib_frost_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* group_public_key, size_t gpk_len);

/** Verify one participant's signature share. Returns 1 valid, 0 invalid. */
CRYPTO_API int cryptolib_frost_verify_share(
    uint16_t identifier,
    const uint8_t* public_share, size_t ps_len,
    const uint8_t* sig_share, size_t ss_len,
    const uint8_t* commit_hiding, size_t ch_len,
    const uint8_t* commit_binding, size_t cb_len,
    const uint8_t* group_public_key, size_t gpk_len,
    const uint8_t* msg, size_t msg_len,
    const uint16_t* ids,
    const uint8_t* hiding_commits,
    const uint8_t* binding_commits,
    size_t count);

/* ═══════════════════════════════════════════════════════════════════════════
 * HPKE — Hybrid Public Key Encryption (RFC 9180)
 *   KEM = DHKEM(X25519, HKDF-SHA256). Wire-standard; interoperates with any
 *   conformant HPKE (TLS ECH, MLS, Oblivious HTTP).
 *
 *   Selector ints:
 *     kdf  : 1 = HKDF-SHA256, 3 = HKDF-SHA512
 *     aead : 1 = AES-128-GCM, 2 = AES-256-GCM, 3 = ChaCha20Poly1305,
 *            65535 = export-only   (AES-GCM needs the OpenSSL-enabled build)
 *     mode : 0 = base, 1 = psk, 2 = auth, 3 = auth+psk
 *   Unused byte-string args (psk/psk_id/skS/pkS for modes that don't need them)
 *   may be passed as NULL/0.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Opaque one-directional HPKE context (holds AEAD key + sequence + exporter). */
typedef void* CryptoHpkeContext;

/** Random X25519 key pair (pk 32 B, sk 32 B) for HPKE. */
CRYPTO_API CryptoKeyPair cryptolib_hpke_keygen(void);

/** Deterministic DHKEM(X25519).DeriveKeyPair from input keying material. */
CRYPTO_API CryptoKeyPair cryptolib_hpke_derive_keypair(const uint8_t* ikm, size_t ikm_len);

/** Sender setup. On success returns a context handle and writes the KEM
 *  encapsulation to *out_enc (free with cryptolib_buffer_free). On failure
 *  returns NULL and sets *out_error (free with cryptolib_str_free). */
CRYPTO_API CryptoHpkeContext cryptolib_hpke_setup_s(
    int kdf, int aead, int mode,
    const uint8_t* pkR, size_t pkR_len,
    const uint8_t* info, size_t info_len,
    const uint8_t* psk, size_t psk_len,
    const uint8_t* psk_id, size_t psk_id_len,
    const uint8_t* skS, size_t skS_len,
    CryptoBuffer* out_enc, char** out_error);

/** Receiver setup. Returns a context handle, or NULL + *out_error on failure. */
CRYPTO_API CryptoHpkeContext cryptolib_hpke_setup_r(
    int kdf, int aead, int mode,
    const uint8_t* enc, size_t enc_len,
    const uint8_t* skR, size_t skR_len,
    const uint8_t* info, size_t info_len,
    const uint8_t* psk, size_t psk_len,
    const uint8_t* psk_id, size_t psk_id_len,
    const uint8_t* pkS, size_t pkS_len,
    char** out_error);

/** Sender: AEAD-seal the next message (advances the context sequence). */
CRYPTO_API CryptoBufferResult cryptolib_hpke_seal(
    CryptoHpkeContext h, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len);

/** Receiver: AEAD-open the next message (advances the context sequence). */
CRYPTO_API CryptoBufferResult cryptolib_hpke_open(
    CryptoHpkeContext h, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len);

/** Derive a `length`-byte secret bound to this context (RFC 9180 §5.3). */
CRYPTO_API CryptoBufferResult cryptolib_hpke_export(
    CryptoHpkeContext h, const uint8_t* exporter_context, size_t ctx_len, size_t length);

/** Release an HPKE context (zeroises its key material). */
CRYPTO_API void cryptolib_hpke_context_free(CryptoHpkeContext h);

/* ═══════════════════════════════════════════════════════════════════════════
 * ECVRF — Verifiable Random Function (RFC 9381)
 *   ECVRF-EDWARDS25519-SHA512-TAI. A public-key PRF: the secret-key holder maps
 *   an input to a unique, unpredictable 64-byte output plus an 80-byte proof
 *   anyone can verify with the public key. libsodium only — no build guard.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Fresh Ed25519-style key pair (pk 32 B, sk = 32-byte seed). */
CRYPTO_API CryptoKeyPair cryptolib_ecvrf_keygen(void);

/** Derive the public key Y = x·B from a 32-byte secret seed. */
CRYPTO_API CryptoBufferResult cryptolib_ecvrf_public_key(const uint8_t* sk, size_t sk_len);

/** Prove: returns the 80-byte proof pi for (sk, alpha). */
CRYPTO_API CryptoBufferResult cryptolib_ecvrf_prove(
    const uint8_t* sk, size_t sk_len, const uint8_t* alpha, size_t alpha_len);

/** proof_to_hash: returns the 64-byte VRF output beta for a proof. */
CRYPTO_API CryptoBufferResult cryptolib_ecvrf_proof_to_hash(const uint8_t* pi, size_t pi_len);

/** Verify: returns the 64-byte beta on success, or an error if the proof is
 *  invalid (check .error). */
CRYPTO_API CryptoBufferResult cryptolib_ecvrf_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* alpha, size_t alpha_len,
    const uint8_t* pi, size_t pi_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * BBS Signatures — multi-message signatures + zero-knowledge selective
 *   disclosure (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256).
 *   The privacy primitive for anonymous credentials: sign a vector of messages,
 *   then derive a proof revealing only a chosen subset. Requires blst.
 *
 *   Messages cross as parallel arrays: msgs[i] (pointer) + msg_lens[i] (length),
 *   msg_count entries. Disclosed indexes are `disclosed_count` uint64 positions
 *   into the message vector (0-based). Sizes: sk 32 B, pk 96 B, signature 80 B.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** BBS KeyGen from key material (>= 32 B) + optional key info. pk 96 B, sk 32 B.
 *  Returns an empty key pair (data=NULL) on failure. */
CRYPTO_API CryptoKeyPair cryptolib_bbs_keygen(
    const uint8_t* key_material, size_t km_len, const uint8_t* key_info, size_t ki_len);

/** Derive the 96-byte public key from a 32-byte secret key. */
CRYPTO_API CryptoBufferResult cryptolib_bbs_sk_to_pk(const uint8_t* sk, size_t sk_len);

/** Sign a vector of messages → 80-byte signature. */
CRYPTO_API CryptoBufferResult cryptolib_bbs_sign(
    const uint8_t* sk, size_t sk_len, const uint8_t* pk, size_t pk_len,
    const uint8_t* header, size_t header_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count);

/** Verify a signature over a vector of messages. Returns 1 valid, 0 invalid. */
CRYPTO_API int cryptolib_bbs_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* signature, size_t sig_len,
    const uint8_t* header, size_t header_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count);

/** Derive a selective-disclosure proof. `msgs` is the FULL signed vector;
 *  `disclosed_indexes` (uint64, 0-based) selects which to reveal. */
CRYPTO_API CryptoBufferResult cryptolib_bbs_proof_gen(
    const uint8_t* pk, size_t pk_len, const uint8_t* signature, size_t sig_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count,
    const uint64_t* disclosed_indexes, size_t disclosed_count);

/** Verify a selective-disclosure proof. `disclosed_msgs` are the revealed
 *  messages, aligned with `disclosed_indexes`. Returns 1 valid, 0 invalid. */
CRYPTO_API int cryptolib_bbs_proof_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* proof, size_t proof_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* const* disclosed_msgs, const size_t* disclosed_lens, size_t disclosed_count,
    const uint64_t* disclosed_indexes, size_t indexes_count);

/* ═══════════════════════════════════════════════════════════════════════════
 * OPRF — Oblivious Pseudorandom Function (RFC 9497, ristretto255-SHA-512)
 *   A two-party PRF: the client blinds its input, the server evaluates under
 *   its key without seeing the input, the client unblinds to the PRF output.
 *   Building block for Privacy Pass, PSI, password hardening, OPAQUE.
 *   Elements/scalars are 32 B; the PRF output is 64 B. libsodium only.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** OPRF key pair from a seed (+ optional info). pk 32 B, sk 32 B. Empty on error. */
CRYPTO_API CryptoKeyPair cryptolib_oprf_derive_keypair(
    const uint8_t* seed, size_t seed_len, const uint8_t* info, size_t info_len);

/** Client Blind output: the secret blind + the blinded element to send. */
typedef struct {
    CryptoBuffer blind;            /**< 32 B secret scalar (keep for finalize) */
    CryptoBuffer blinded_element;  /**< 32 B — send to the server */
    char*        error;            /**< heap-allocated; NULL on success */
} CryptoOprfBlind;

/** Free a CryptoOprfBlind (zeroises the blind). */
CRYPTO_API void cryptolib_oprf_blind_free(CryptoOprfBlind* b);

/** Client: blind an input with a fresh random scalar. */
CRYPTO_API CryptoOprfBlind cryptolib_oprf_blind(const uint8_t* input, size_t input_len);

/** Deterministic blind with a caller-supplied 32-byte scalar (test vectors). */
CRYPTO_API CryptoOprfBlind cryptolib_oprf_blind_with_scalar(
    const uint8_t* input, size_t input_len, const uint8_t* blind, size_t blind_len);

/** Server: evaluate a blinded element under the secret key → evaluated element. */
CRYPTO_API CryptoBufferResult cryptolib_oprf_blind_evaluate(
    const uint8_t* sk, size_t sk_len, const uint8_t* blinded_element, size_t be_len);

/** Client: unblind the evaluated element → 64-byte PRF output. */
CRYPTO_API CryptoBufferResult cryptolib_oprf_finalize(
    const uint8_t* input, size_t input_len, const uint8_t* blind, size_t blind_len,
    const uint8_t* evaluated_element, size_t ee_len);

/** Server one-shot: compute the PRF output directly from the key + input. */
CRYPTO_API CryptoBufferResult cryptolib_oprf_evaluate(
    const uint8_t* sk, size_t sk_len, const uint8_t* input, size_t input_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * OPAQUE — asymmetric PAKE (draft-irtf-cfrg-opaque, OPAQUE-3DH,
 *   ristretto255-SHA-512). A client and server agree on a session key from a
 *   password that never leaves the client and is never stored server-side.
 *   Two phases: registration, then a 3DH login. Optional identity strings pass
 *   NULL/0 to default to the public keys. libsodium only. Uses the OPRF above.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Registration record (upload to server) + export_key. */
typedef struct {
    CryptoBuffer record;      /**< 192 B — store on the server */
    CryptoBuffer export_key;  /**< 64 B — client-side derived key */
    char*        error;
} CryptoOpaqueRecord;
CRYPTO_API void cryptolib_opaque_record_free(CryptoOpaqueRecord* r);

/** Client login message 1 + opaque client state (feed to client_finish). */
typedef struct {
    CryptoBuffer ke1;          /**< 96 B — send to server */
    CryptoBuffer client_state; /**< opaque; keep for client_finish */
    char*        error;
} CryptoOpaqueKe1;
CRYPTO_API void cryptolib_opaque_ke1_free(CryptoOpaqueKe1* k);

/** Server login message 2 + opaque server state (feed to server_finish). */
typedef struct {
    CryptoBuffer ke2;          /**< 320 B — send to client */
    CryptoBuffer server_state; /**< opaque; keep for server_finish */
    char*        error;
} CryptoOpaqueKe2;
CRYPTO_API void cryptolib_opaque_ke2_free(CryptoOpaqueKe2* k);

/** Client login message 3 + the agreed session key + export_key. */
typedef struct {
    CryptoBuffer ke3;          /**< 64 B — send to server */
    CryptoBuffer session_key;  /**< 64 B — the shared session key */
    CryptoBuffer export_key;   /**< 64 B */
    char*        error;        /**< set on wrong password / server auth failure */
} CryptoOpaqueKe3;
CRYPTO_API void cryptolib_opaque_ke3_free(CryptoOpaqueKe3* k);

/** Client registration step 1: blind the password. Returns {blind, request}
 *  in a CryptoOprfBlind (send blinded_element as the request; keep blind). */
CRYPTO_API CryptoOprfBlind cryptolib_opaque_registration_request(
    const uint8_t* password, size_t password_len);

/** Server registration step: → 64-byte registration response. */
CRYPTO_API CryptoBufferResult cryptolib_opaque_registration_response(
    const uint8_t* request, size_t request_len, const uint8_t* server_public_key, size_t spk_len,
    const uint8_t* credential_identifier, size_t ci_len, const uint8_t* oprf_seed, size_t seed_len);

/** Client registration step 2: → record + export_key. */
CRYPTO_API CryptoOpaqueRecord cryptolib_opaque_finalize_request(
    const uint8_t* password, size_t password_len, const uint8_t* blind, size_t blind_len,
    const uint8_t* response, size_t response_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len);

/** Client login step 1: → KE1 + client_state. */
CRYPTO_API CryptoOpaqueKe1 cryptolib_opaque_client_init(const uint8_t* password, size_t password_len);

/** Server login step 1: → KE2 + server_state. */
CRYPTO_API CryptoOpaqueKe2 cryptolib_opaque_server_respond(
    const uint8_t* context, size_t context_len,
    const uint8_t* server_private_key, size_t sk_len, const uint8_t* server_public_key, size_t pk_len,
    const uint8_t* record, size_t record_len, const uint8_t* credential_identifier, size_t ci_len,
    const uint8_t* oprf_seed, size_t seed_len, const uint8_t* ke1, size_t ke1_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len);

/** Client login step 2: authenticate the server → KE3 + session_key + export_key. */
CRYPTO_API CryptoOpaqueKe3 cryptolib_opaque_client_finish(
    const uint8_t* client_state, size_t cs_len, const uint8_t* ke2, size_t ke2_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len);

/** Server login step 2: verify KE3 → the session key (error on auth failure). */
CRYPTO_API CryptoBufferResult cryptolib_opaque_server_finish(
    const uint8_t* server_state, size_t ss_len, const uint8_t* ke3, size_t ke3_len);

/* ═══════════════════════════════════════════════════════════════════════════
 * EVM / Bitcoin interop — Keccak-256, RIPEMD-160, secp256k1 ECDSA
 *   secp256k1 functions require CRYPTOLIB_HAS_SECP256K1 (libsecp256k1 w/
 *   recovery module). When disabled they return an error result / 0 rather
 *   than vanishing from the ABI.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Keccak-256 — ORIGINAL Keccak padding (Ethereum). 32-byte output.
 *  NOT NIST SHA3-256 (different padding → different digest). */
CRYPTO_API CryptoBufferResult cryptolib_keccak256(const uint8_t* msg, size_t msg_len);

/** RIPEMD-160. 20-byte output. Bitcoin HASH160(x) = ripemd160(sha256(x)). */
CRYPTO_API CryptoBufferResult cryptolib_ripemd160(const uint8_t* msg, size_t msg_len);

/** secp256k1 keypair. sk = 32 bytes; pk = 65 bytes uncompressed (0x04 ‖ X ‖ Y). */
CRYPTO_API CryptoKeyPair cryptolib_secp256k1_keygen(void);

/** Derive the public key from a 32-byte secret key.
 *  compressed: 1 → 33 bytes (0x02/0x03 ‖ X), 0 → 65 bytes (0x04 ‖ X ‖ Y). */
CRYPTO_API CryptoBufferResult cryptolib_secp256k1_pubkey(
    const uint8_t* secret_key, size_t sk_len, int compressed);

/** Sign a 32-byte digest. RFC6979 deterministic nonce, low-S normalized.
 *  Returns 65 bytes: r(32) ‖ s(32) ‖ recovery_id(1, value 0..3). */
CRYPTO_API CryptoBufferResult cryptolib_secp256k1_sign(
    const uint8_t* digest32, const uint8_t* secret_key, size_t sk_len);

/** Verify. sig is 64 bytes (r ‖ s); pk is 33 or 65 bytes. Low-S enforced.
 *  Returns 1 if valid, 0 otherwise. */
CRYPTO_API int cryptolib_secp256k1_verify(
    const uint8_t* digest32,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len);

/** Recover the public key (65-byte uncompressed) from a 32-byte digest and a
 *  65-byte recoverable signature (r ‖ s ‖ recovery_id). Ethereum ecrecover. */
CRYPTO_API CryptoBufferResult cryptolib_secp256k1_recover(
    const uint8_t* digest32, const uint8_t* sig65);

/* ═══════════════════════════════════════════════════════════════════════════
 * Steganography — hide data inside media files
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Embed raw bytes into a media file. Format auto-detected from extension. */
CRYPTO_API CryptoResult cryptolib_stego_embed(
    const char* cover_path,
    const uint8_t* payload, size_t payload_len,
    const char* output_path);

/** Extract raw bytes from a stego media file. */
CRYPTO_API CryptoBufferResult cryptolib_stego_extract(const char* stego_path);

/** Get the steganographic capacity of a cover file (in bytes). */
CRYPTO_API size_t cryptolib_stego_capacity(const char* cover_path);

/* ═══════════════════════════════════════════════════════════════════════════
 * Keyring — envelope encryption with key-slots
 *
 * One random master key (which you then use with the vault) is wrapped in one
 * or more slots. Each slot unlocks the master key via a different factor:
 *   - device slot:     a 32-byte key from secure hardware (Enclave/Keystore)
 *   - passphrase slot: an Argon2id-hardened passphrase (cross-device path)
 * Default = 1 device slot; add a passphrase slot to enable cross-device.
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Create a keyring with a fresh random master key (unlocked, no slots). */
CRYPTO_API CryptoKeyringHandle cryptolib_keyring_create(void);

/** Add a device slot from a >=32-byte hardware factor key. Returns 1 on success. */
CRYPTO_API int cryptolib_keyring_add_device_slot(
    CryptoKeyringHandle kr, const uint8_t* factor_key, size_t len);

/** Add a passphrase slot. kdf_preset: 0=interactive, 1=sensitive. Returns 1 on success. */
CRYPTO_API int cryptolib_keyring_add_passphrase_slot(
    CryptoKeyringHandle kr, const char* passphrase, int kdf_preset);

/** Number of slots. */
CRYPTO_API size_t cryptolib_keyring_slot_count(CryptoKeyringHandle kr);

/** Revoke a slot by index. Returns 1 on success. */
CRYPTO_API int cryptolib_keyring_remove_slot(CryptoKeyringHandle kr, size_t index);

/** Serialise the envelope blob (no plaintext key). Caller frees the buffer. */
CRYPTO_API CryptoBufferResult cryptolib_keyring_serialise(CryptoKeyringHandle kr);

/** Parse an envelope blob into a new (locked) handle. NULL on error. */
CRYPTO_API CryptoKeyringHandle cryptolib_keyring_deserialise(
    const uint8_t* blob, size_t len, char** out_error);

/** Unlock with a device factor key. Returns the 32-byte master key (caller frees). */
CRYPTO_API CryptoBufferResult cryptolib_keyring_unlock_with_device(
    CryptoKeyringHandle kr, const uint8_t* factor_key, size_t len);

/** Unlock with a passphrase. Returns the 32-byte master key (caller frees). */
CRYPTO_API CryptoBufferResult cryptolib_keyring_unlock_with_passphrase(
    CryptoKeyringHandle kr, const char* passphrase);

/** Destroy a keyring handle. */
CRYPTO_API void cryptolib_keyring_free(CryptoKeyringHandle kr);

/* ═══════════════════════════════════════════════════════════════════════════
 * Version
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Returns version string. Do NOT free. */
CRYPTO_API const char* cryptolib_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOLIB_C_H */
