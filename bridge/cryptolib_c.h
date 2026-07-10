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
