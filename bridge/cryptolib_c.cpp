/**
#include <optional>
 * CryptoLib C FFI Bridge — Implementation
 *
 * Wraps the C++20 header-only library into a flat C API.
 * Compiles as a shared library (libcryptolib_c.dylib / .so / .dll).
 *
 * BOUNDARY CONTRACT: no C++ exception may cross the extern "C" boundary — that
 * is undefined behaviour in the host runtime (Dart/Go/Python/...). Every entry
 * point that can allocate is therefore a function-try-block whose catch returns
 * a safe failure value via the CL_FAIL_* macros below. The catch handlers only
 * use dup_err_cstr() (malloc-based, noexcept) so they cannot themselves throw.
 */

#ifndef CRYPTOLIB_BUILD_SHARED
#define CRYPTOLIB_BUILD_SHARED
#endif
#include "cryptolib_c.h"
#include <cryptolib/cryptolib.hpp>

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>
#include <filesystem>

/* ═══════════════════════════════════════════════════════════════════════════
 * Internal helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace {

/** Copy a SecureBuffer into a malloc'd CryptoBuffer. */
CryptoBuffer to_cbuf(const crypto::SecureBuffer& sb) {
    CryptoBuffer cb;
    cb.len = sb.size();
    if (cb.len == 0) { cb.data = nullptr; return cb; }
    cb.data = static_cast<uint8_t*>(std::malloc(cb.len));
    if (!cb.data) { cb.len = 0; return cb; }   // keep len consistent on OOM
    std::memcpy(cb.data, sb.data(), cb.len);
    return cb;
}

/** Copy raw span into a malloc'd CryptoBuffer. */
CryptoBuffer to_cbuf(std::span<const uint8_t> sp) {
    CryptoBuffer cb;
    cb.len = sp.size();
    if (cb.len == 0) { cb.data = nullptr; return cb; }
    cb.data = static_cast<uint8_t*>(std::malloc(cb.len));
    if (!cb.data) { cb.len = 0; return cb; }   // keep len consistent on OOM
    std::memcpy(cb.data, sp.data(), cb.len);
    return cb;
}

/** Heap-duplicate a C++ string as a C string. */
char* dup_str(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p) { std::memcpy(p, s.c_str(), s.size() + 1); }
    return p;
}

/** Heap-duplicate a C string literal — noexcept, safe to call from catch. */
char* dup_err_cstr(const char* s) noexcept {
    std::size_t n = std::strlen(s);
    char* p = static_cast<char*>(std::malloc(n + 1));
    if (p) std::memcpy(p, s, n + 1);
    return p;
}

/** Make a success CryptoBufferResult. */
CryptoBufferResult ok_buf(const crypto::SecureBuffer& sb) {
    return { to_cbuf(sb), nullptr };
}

/** Make an error CryptoBufferResult. */
CryptoBufferResult err_buf(const std::string& msg) {
    return { {nullptr, 0}, dup_str(msg) };
}

/** Make a null CryptoBuffer. */
CryptoBuffer null_buf() { return {nullptr, 0}; }

/** span from raw pointer + len */
std::span<const uint8_t> sp(const uint8_t* p, size_t n) {
    return {p, n};
}

/** Build a SecureBuffer from a borrowed CryptoBuffer, tolerating null data. */
crypto::SecureBuffer sb_from(const CryptoBuffer& cb) {
    if (!cb.data || cb.len == 0) return crypto::SecureBuffer{};
    return crypto::SecureBuffer(cb.data, cb.len);
}

} // anonymous namespace

/* ═══════════════════════════════════════════════════════════════════════════
 * Exception-isolation fallbacks (one per return type).
 * Used as the catch clause of each function-try-block.
 * ═══════════════════════════════════════════════════════════════════════════ */

#define CL_FAIL_BUFRES catch (...) { return CryptoBufferResult{ {nullptr, 0}, dup_err_cstr("internal error") }; }
#define CL_FAIL_BUF    catch (...) { return CryptoBuffer{nullptr, 0}; }
#define CL_FAIL_INT    catch (...) { return 0; }
#define CL_FAIL_PTR    catch (...) { return nullptr; }
#define CL_FAIL_VOID   catch (...) { return; }
#define CL_FAIL_KP     catch (...) { return CryptoKeyPair{}; }
#define CL_FAIL_BUNDLE catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return CryptoAsymBundle{}; }
#define CL_FAIL_BUNDLE_NOERR catch (...) { return CryptoAsymBundle{}; }
#define CL_FAIL_PKT    catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return CryptoPacket{}; }
#define CL_FAIL_DERIVED catch (...) { return CryptoDerivedKeys{}; }
#define CL_FAIL_KEM    catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return CryptoKemEncapsResult{ {nullptr,0}, {nullptr,0} }; }
#define CL_FAIL_INFO   catch (...) { return CryptoEntropyInfo{nullptr, 0, 0, 0.0}; }
#define CL_FAIL_RESULT catch (...) { return CryptoResult{0, dup_err_cstr("internal error")}; }
#define CL_FAIL_SIZE   catch (...) { return 0; }

/* ═══════════════════════════════════════════════════════════════════════════
 * Opaque handle internals
 * ═══════════════════════════════════════════════════════════════════════════ */

struct VaultImpl     { crypto::SecureVault vault; };
struct EntropyImpl   { crypto::entropy::MediaEntropy me; };
struct StreamEncImpl { crypto::symmetric::SecretStream::Encryptor enc; };
struct StreamDecImpl { crypto::symmetric::SecretStream::Decryptor dec; };
struct KeyringImpl   { crypto::Keyring kr; };
struct DrbgImpl      { crypto::entropy::HmacDrbg d; };
struct FortunaImpl   { crypto::entropy::FortunaPool p; };

/* ═══════════════════════════════════════════════════════════════════════════
 * Memory management
 * ═══════════════════════════════════════════════════════════════════════════ */

extern "C" {

CRYPTO_API void cryptolib_buffer_free(CryptoBuffer* buf) {
    if (!buf || !buf->data) return;
    // Secure zeroisation before free
    volatile uint8_t* p = buf->data;
    for (size_t i = 0; i < buf->len; ++i) p[i] = 0;
    std::free(buf->data);
    buf->data = nullptr;
    buf->len = 0;
}

CRYPTO_API void cryptolib_str_free(char* str) {
    std::free(str);
}

CRYPTO_API void cryptolib_keypair_free(CryptoKeyPair* kp) {
    if (!kp) return;
    cryptolib_buffer_free(&kp->public_key);
    cryptolib_buffer_free(&kp->secret_key);
}

CRYPTO_API void cryptolib_bundle_free(CryptoAsymBundle* b) {
    if (!b) return;
    cryptolib_buffer_free(&b->box_public);
    cryptolib_buffer_free(&b->box_secret);
    cryptolib_buffer_free(&b->sign_public);
    cryptolib_buffer_free(&b->sign_secret);
}

CRYPTO_API void cryptolib_packet_free(CryptoPacket* p) {
    if (!p) return;
    cryptolib_buffer_free(&p->ciphertext);
    cryptolib_buffer_free(&p->signature);
    cryptolib_buffer_free(&p->kdf_salt);
}

CRYPTO_API void cryptolib_derived_keys_free(CryptoDerivedKeys* dk) {
    if (!dk) return;
    cryptolib_buffer_free(&dk->symmetric_key);
    cryptolib_buffer_free(&dk->vault_master_key);
    cryptolib_buffer_free(&dk->signing_seed);
    cryptolib_buffer_free(&dk->box_seed);
    cryptolib_buffer_free(&dk->stream_key);
    cryptolib_buffer_free(&dk->raw_entropy);
}

CRYPTO_API void cryptolib_entropy_info_free(CryptoEntropyInfo* info) {
    if (!info) return;
    std::free(info->path);
    info->path = nullptr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Initialisation & utilities
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API int cryptolib_init(void) try {
    crypto::init();
    return 0;
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_random_bytes(size_t n) try {
    return ok_buf(crypto::random_bytes(n));
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_secure_equal(const uint8_t* a, size_t a_len,
                                       const uint8_t* b, size_t b_len) try {
    return crypto::secure_equal(sp(a, a_len), sp(b, b_len)) ? 1 : 0;
} CL_FAIL_INT

/* ═══════════════════════════════════════════════════════════════════════════
 * Hashing
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoBufferResult cryptolib_blake2b(const uint8_t* msg, size_t msg_len,
                                                 const uint8_t* key, size_t key_len) try {
    auto r = crypto::hash::Blake2b::digest(sp(msg, msg_len),
                 key ? sp(key, key_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sha256(const uint8_t* msg, size_t msg_len) try {
    auto r = crypto::hash::Sha256::digest(sp(msg, msg_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sha512(const uint8_t* msg, size_t msg_len) try {
    auto r = crypto::hash::Sha512::digest(sp(msg, msg_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hmac_sha512(const uint8_t* msg, size_t msg_len,
                                                     const uint8_t* key, size_t key_len) try {
    auto r = crypto::hash::HmacSha512::compute(sp(msg, msg_len), sp(key, key_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_hmac_sha512_verify(const uint8_t* msg, size_t msg_len,
                                             const uint8_t* mac, size_t mac_len,
                                             const uint8_t* key, size_t key_len) try {
    return crypto::hash::HmacSha512::verify(sp(msg, msg_len), sp(mac, mac_len), sp(key, key_len)) ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_argon2id_hash_str(const char* password,
                                                           uint64_t ops, size_t mem) try {
    auto r = crypto::hash::Argon2id::hash_password_str(password, ops, mem);
    if (r.is_err()) return err_buf(r.error().message);
    auto& s = r.value();
    CryptoBuffer buf;
    buf.len = s.size();
    buf.data = static_cast<uint8_t*>(std::malloc(buf.len + 1));
    if (!buf.data) { buf.len = 0; return { buf, dup_err_cstr("internal error") }; }
    std::memcpy(buf.data, s.data(), buf.len);
    buf.data[buf.len] = 0; // null terminate
    return { buf, nullptr };
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_argon2id_verify_str(const char* password, const char* phc_str) try {
    return crypto::hash::Argon2id::verify_str(password, phc_str) ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_argon2id_derive(const char* password,
                                                         const uint8_t* salt, size_t salt_len,
                                                         size_t key_len, uint64_t ops, size_t mem) try {
    auto r = crypto::hash::Argon2id::derive_key(password, sp(salt, salt_len), key_len, ops, mem);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * Symmetric encryption
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoBufferResult cryptolib_sym_keygen(void) try {
    return ok_buf(crypto::symmetric::XChaCha20Poly1305::generate_key());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_xchacha20_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::XChaCha20Poly1305::encrypt(
        sp(plaintext, pt_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_xchacha20_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::XChaCha20Poly1305::decrypt(
        sp(ciphertext, ct_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_committing_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::CommittingAead::encrypt(
        sp(plaintext, pt_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_committing_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::CommittingAead::decrypt(
        sp(ciphertext, ct_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

// ── MolecularVault ──────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_OPENSSL
CRYPTO_API CryptoBufferResult cryptolib_molecular_seal(
    const uint8_t* plaintext, size_t pt_len,
    const char* passphrase,
    const uint8_t* aad, size_t aad_len,
    uint64_t ops, size_t mem) try
{
    crypto::MolecularVault::KdfParams p;
    if (ops != 0) p.ops = ops;   // 0 → keep the SENSITIVE default
    if (mem != 0) p.mem = mem;
    auto r = crypto::MolecularVault::seal(
        sp(plaintext, pt_len), passphrase ? passphrase : "",
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{}, p);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_molecular_open(
    const uint8_t* envelope, size_t env_len,
    const char* passphrase,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::MolecularVault::open(
        sp(envelope, env_len), passphrase ? passphrase : "",
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_molecular_seal_with_key(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* master_key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::MolecularVault::seal_with_key(
        sp(plaintext, pt_len), sp(master_key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_molecular_open_with_key(
    const uint8_t* envelope, size_t env_len,
    const uint8_t* master_key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::MolecularVault::open_with_key(
        sp(envelope, env_len), sp(master_key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES
#else  // !CRYPTOLIB_HAS_OPENSSL — ABI-stable stubs when GCM-SIV is unavailable
static CryptoBufferResult molecular_unavailable() {
    return err_buf("MolecularVault requires OpenSSL (AES-256-GCM-SIV) — not compiled in");
}
CRYPTO_API CryptoBufferResult cryptolib_molecular_seal(
    const uint8_t*, size_t, const char*, const uint8_t*, size_t, uint64_t, size_t) {
    return molecular_unavailable();
}
CRYPTO_API CryptoBufferResult cryptolib_molecular_open(
    const uint8_t*, size_t, const char*, const uint8_t*, size_t) {
    return molecular_unavailable();
}
CRYPTO_API CryptoBufferResult cryptolib_molecular_seal_with_key(
    const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
    return molecular_unavailable();
}
CRYPTO_API CryptoBufferResult cryptolib_molecular_open_with_key(
    const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) {
    return molecular_unavailable();
}
#endif // CRYPTOLIB_HAS_OPENSSL

// ── Suite — one-call advanced combinations ──────────────────────────────────
#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)
namespace {
std::span<const uint8_t> opt_aad(const uint8_t* aad, size_t len) {
    return aad ? sp(aad, len) : std::span<const uint8_t>{};
}
// Serialise Shamir shares to a flat blob: each record = index(1) | ylen(4 LE) | y.
CryptoBuffer serialise_shares(const std::vector<crypto::Shamir::Share>& shares) {
    std::vector<uint8_t> out;
    for (const auto& s : shares) {
        out.push_back(s.index);
        uint32_t n = static_cast<uint32_t>(s.y.size());
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
        out.insert(out.end(), s.y.span().begin(), s.y.span().end());
    }
    return to_cbuf(std::span<const uint8_t>(out.data(), out.size()));
}
// Parse a concatenation of those records back into shares.
bool parse_shares(std::span<const uint8_t> blob, std::vector<crypto::Shamir::Share>& out) {
    size_t off = 0;
    while (off < blob.size()) {
        if (off + 5 > blob.size()) return false;
        uint8_t index = blob[off];
        uint32_t ylen = 0;
        for (int i = 0; i < 4; ++i) ylen |= static_cast<uint32_t>(blob[off + 1 + i]) << (8 * i);
        off += 5;
        if (off + ylen > blob.size()) return false;
        crypto::SecureBuffer y(blob.data() + off, ylen);
        out.push_back(crypto::Shamir::Share{index, std::move(y)});
        off += ylen;
    }
    return !out.empty();
}
crypto::Keyring* kr_of(CryptoKeyringHandle kr) {
    return kr ? &static_cast<KeyringImpl*>(kr)->kr : nullptr;
}
} // namespace

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq(
    const uint8_t* pt, size_t pt_len, const uint8_t* kem_pub, size_t kem_pub_len,
    const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::seal_pq(sp(pt, pt_len), sp(kem_pub, kem_pub_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq_sntrup(
    const uint8_t* pt, size_t pt_len, const uint8_t* kem_pub, size_t kem_pub_len,
    const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::seal_pq_sntrup(sp(pt, pt_len), sp(kem_pub, kem_pub_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_pq(
    const uint8_t* env, size_t env_len, const uint8_t* kem_sec, size_t kem_sec_len,
    const uint8_t* aad, size_t aad_len) try {
    // Auto-detects ML-KEM vs sntrup761 from the envelope's suite id.
    auto r = crypto::Suite::open_pq(sp(env, env_len), sp(kem_sec, kem_sec_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq(
    const uint8_t* pt, size_t pt_len, const uint8_t* kem_pub, size_t kem_pub_len,
    const uint8_t* sig_sec, size_t sig_sec_len, const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::seal_signed_pq(sp(pt, pt_len), sp(kem_pub, kem_pub_len),
                                           sp(sig_sec, sig_sec_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq_sntrup(
    const uint8_t* pt, size_t pt_len, const uint8_t* kem_pub, size_t kem_pub_len,
    const uint8_t* sig_sec, size_t sig_sec_len, const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::seal_signed_pq_sntrup(sp(pt, pt_len), sp(kem_pub, kem_pub_len),
                                                  sp(sig_sec, sig_sec_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_signed_pq(
    const uint8_t* env, size_t env_len, const uint8_t* kem_sec, size_t kem_sec_len,
    const uint8_t* sig_pub, size_t sig_pub_len, const uint8_t* aad, size_t aad_len) try {
    // Auto-detects ML-KEM vs sntrup761 from the envelope's suite id.
    auto r = crypto::Suite::open_signed_pq(sp(env, env_len), sp(kem_sec, kem_sec_len),
                                           sp(sig_pub, sig_pub_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_file(
    const uint8_t* pt, size_t pt_len, const char* path, const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::seal_with_file(sp(pt, pt_len), path ? path : "", opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_file(
    const uint8_t* env, size_t env_len, const char* path, const uint8_t* aad, size_t aad_len) try {
    auto r = crypto::Suite::open_with_file(sp(env, env_len), path ? path : "", opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_device(
    const uint8_t* pt, size_t pt_len, CryptoKeyringHandle kr,
    const uint8_t* factor, size_t factor_len, const uint8_t* aad, size_t aad_len) try {
    auto* k = kr_of(kr); if (!k) return err_buf("null keyring");
    auto r = crypto::Suite::seal_with_keyring_device(sp(pt, pt_len), *k, sp(factor, factor_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_device(
    const uint8_t* env, size_t env_len, CryptoKeyringHandle kr,
    const uint8_t* factor, size_t factor_len, const uint8_t* aad, size_t aad_len) try {
    auto* k = kr_of(kr); if (!k) return err_buf("null keyring");
    auto r = crypto::Suite::open_with_keyring_device(sp(env, env_len), *k, sp(factor, factor_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_passphrase(
    const uint8_t* pt, size_t pt_len, CryptoKeyringHandle kr,
    const char* passphrase, const uint8_t* aad, size_t aad_len) try {
    auto* k = kr_of(kr); if (!k) return err_buf("null keyring");
    auto r = crypto::Suite::seal_with_keyring_passphrase(sp(pt, pt_len), *k, passphrase ? passphrase : "", opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_passphrase(
    const uint8_t* env, size_t env_len, CryptoKeyringHandle kr,
    const char* passphrase, const uint8_t* aad, size_t aad_len) try {
    auto* k = kr_of(kr); if (!k) return err_buf("null keyring");
    auto r = crypto::Suite::open_with_keyring_passphrase(sp(env, env_len), *k, passphrase ? passphrase : "", opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_seal_threshold(
    const uint8_t* pt, size_t pt_len, uint8_t n, uint8_t k,
    const uint8_t* aad, size_t aad_len, CryptoBuffer* out_shares) try {
    if (out_shares) *out_shares = CryptoBuffer{nullptr, 0};
    auto r = crypto::Suite::seal_threshold(sp(pt, pt_len), n, k, opt_aad(aad, aad_len));
    if (r.is_err()) return err_buf(r.error().message);
    if (out_shares) *out_shares = serialise_shares(r.value().shares);
    return ok_buf(r.value().envelope);
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_open_threshold(
    const uint8_t* env, size_t env_len, const uint8_t* shares, size_t shares_len,
    const uint8_t* aad, size_t aad_len) try {
    std::vector<crypto::Shamir::Share> parsed;
    if (!parse_shares(sp(shares, shares_len), parsed)) return err_buf("Suite: malformed shares blob");
    auto r = crypto::Suite::open_threshold(sp(env, env_len), {parsed.data(), parsed.size()}, opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_suite_evm_address(
    const uint8_t* pk, size_t pk_len) try {
    auto r = crypto::Suite::evm_address(sp(pk, pk_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

// ── Flagship / Fortress — sealed messaging (tier-parameterized) ──────────────
namespace {
struct SealedSealerImpl {
    std::optional<crypto::Flagship::StreamSealer> fl;
    std::optional<crypto::Fortress::StreamSealer> fo;
};
struct SealedOpenerImpl {
    std::optional<crypto::Flagship::StreamOpener> fl;
    std::optional<crypto::Fortress::StreamOpener> fo;
};
} // namespace

CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_recipient(int tier) try {
    if (tier == 1) { auto r = crypto::Fortress::generate_recipient();
        return r.is_err() ? CryptoKeyPair{} : CryptoKeyPair{ to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) }; }
    auto r = crypto::Flagship::generate_recipient();
    return r.is_err() ? CryptoKeyPair{} : CryptoKeyPair{ to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_sender(int tier) try {
    if (tier == 1) { auto r = crypto::Fortress::generate_sender();
        return r.is_err() ? CryptoKeyPair{} : CryptoKeyPair{ to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) }; }
    auto r = crypto::Flagship::generate_sender();
    return r.is_err() ? CryptoKeyPair{} : CryptoKeyPair{ to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_sealed_seal(
    int tier, const uint8_t* pt, size_t pt_len,
    const uint8_t* rpub, size_t rpub_len, const uint8_t* ssec, size_t ssec_len,
    const uint8_t* aad, size_t aad_len, const uint8_t* purpose, size_t purpose_len) try {
    auto go = [&](auto tag) {
        using P = decltype(tag);
        auto r = P::seal(sp(pt, pt_len), sp(rpub, rpub_len), sp(ssec, ssec_len),
                         opt_aad(aad, aad_len), opt_aad(purpose, purpose_len));
        return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
    };
    return tier == 1 ? go(crypto::Fortress{}) : go(crypto::Flagship{});
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealed_open(
    int tier, const uint8_t* env, size_t env_len,
    const uint8_t* rsec, size_t rsec_len, const uint8_t* rpub, size_t rpub_len,
    const uint8_t* spub, size_t spub_len, const uint8_t* aad, size_t aad_len,
    const uint8_t* purpose, size_t purpose_len) try {
    auto go = [&](auto tag) {
        using P = decltype(tag);
        auto r = P::open(sp(env, env_len), sp(rsec, rsec_len), sp(rpub, rpub_len),
                         sp(spub, spub_len), opt_aad(aad, aad_len), opt_aad(purpose, purpose_len));
        return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
    };
    return tier == 1 ? go(crypto::Fortress{}) : go(crypto::Flagship{});
} CL_FAIL_BUFRES

CRYPTO_API CryptoSealedInfo cryptolib_sealed_inspect(const uint8_t* env, size_t env_len) try {
    CryptoSealedInfo out{};
    auto info = crypto::Flagship::inspect(sp(env, env_len)); // header parse is tier-agnostic
    if (info.is_err()) return out;
    out.ok = 1;
    out.version = info.value().version;
    out.suite = info.value().suite;
    out.streaming = info.value().streaming ? 1 : 0;
    std::memcpy(out.fingerprint, info.value().recipient_fingerprint.data(), 16);
    out.kem_ciphertext_len = info.value().kem_ciphertext_len;
    return out;
} catch (...) { return CryptoSealedInfo{}; }

CRYPTO_API int cryptolib_sealed_addressed_to(
    const uint8_t* env, size_t env_len, const uint8_t* rpub, size_t rpub_len) try {
    return crypto::Flagship::addressed_to(sp(env, env_len), sp(rpub, rpub_len)) ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoSealedSealer cryptolib_sealed_sealer_begin(
    int tier, const uint8_t* rpub, size_t rpub_len, const uint8_t* ssec, size_t ssec_len,
    const uint8_t* purpose, size_t purpose_len, char** out_error) try {
    if (out_error) *out_error = nullptr;
    auto* impl = new SealedSealerImpl{};
    if (tier == 1) {
        auto r = crypto::Fortress::StreamSealer::begin(sp(rpub, rpub_len), sp(ssec, ssec_len), opt_aad(purpose, purpose_len));
        if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); delete impl; return nullptr; }
        impl->fo.emplace(std::move(r.value()));
    } else {
        auto r = crypto::Flagship::StreamSealer::begin(sp(rpub, rpub_len), sp(ssec, ssec_len), opt_aad(purpose, purpose_len));
        if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); delete impl; return nullptr; }
        impl->fl.emplace(std::move(r.value()));
    }
    return static_cast<CryptoSealedSealer>(impl);
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_preamble(CryptoSealedSealer h) try {
    auto* impl = static_cast<SealedSealerImpl*>(h);
    if (!impl) return err_buf("sealed: null sealer");
    if (impl->fl) return ok_buf(impl->fl->preamble());
    if (impl->fo) return ok_buf(impl->fo->preamble());
    return err_buf("sealed: invalid sealer");
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_push(
    CryptoSealedSealer h, const uint8_t* chunk, size_t chunk_len) try {
    auto* impl = static_cast<SealedSealerImpl*>(h);
    if (!impl) return err_buf("sealed: null sealer");
    if (impl->fl) { auto r = impl->fl->push(sp(chunk, chunk_len)); return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value()); }
    if (impl->fo) { auto r = impl->fo->push(sp(chunk, chunk_len)); return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value()); }
    return err_buf("sealed: invalid sealer");
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_finalize(
    CryptoSealedSealer h, const uint8_t* last, size_t last_len, CryptoBuffer* out_trailer) try {
    if (out_trailer) *out_trailer = CryptoBuffer{nullptr, 0};
    auto* impl = static_cast<SealedSealerImpl*>(h);
    if (!impl) return err_buf("sealed: null sealer");
    if (impl->fl) {
        auto r = impl->fl->finalize(opt_aad(last, last_len));
        if (r.is_err()) return err_buf(r.error().message);
        if (out_trailer) *out_trailer = to_cbuf(r.value().trailer);
        return ok_buf(r.value().ciphertext);
    }
    if (impl->fo) {
        auto r = impl->fo->finalize(opt_aad(last, last_len));
        if (r.is_err()) return err_buf(r.error().message);
        if (out_trailer) *out_trailer = to_cbuf(r.value().trailer);
        return ok_buf(r.value().ciphertext);
    }
    return err_buf("sealed: invalid sealer");
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_sealed_sealer_free(CryptoSealedSealer h) {
    delete static_cast<SealedSealerImpl*>(h);
}

CRYPTO_API CryptoSealedOpener cryptolib_sealed_opener_begin(
    int tier, const uint8_t* preamble, size_t pre_len,
    const uint8_t* rsec, size_t rsec_len, const uint8_t* rpub, size_t rpub_len,
    const uint8_t* spub, size_t spub_len, const uint8_t* purpose, size_t purpose_len,
    char** out_error) try {
    if (out_error) *out_error = nullptr;
    auto* impl = new SealedOpenerImpl{};
    if (tier == 1) {
        auto r = crypto::Fortress::StreamOpener::begin(sp(preamble, pre_len), sp(rsec, rsec_len),
                    sp(rpub, rpub_len), sp(spub, spub_len), opt_aad(purpose, purpose_len));
        if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); delete impl; return nullptr; }
        impl->fo.emplace(std::move(r.value()));
    } else {
        auto r = crypto::Flagship::StreamOpener::begin(sp(preamble, pre_len), sp(rsec, rsec_len),
                    sp(rpub, rpub_len), sp(spub, spub_len), opt_aad(purpose, purpose_len));
        if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); delete impl; return nullptr; }
        impl->fl.emplace(std::move(r.value()));
    }
    return static_cast<CryptoSealedOpener>(impl);
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_pull(
    CryptoSealedOpener h, const uint8_t* ct, size_t ct_len, int* out_final) try {
    if (out_final) *out_final = 0;
    auto* impl = static_cast<SealedOpenerImpl*>(h);
    if (!impl) return err_buf("sealed: null opener");
    if (impl->fl) { auto r = impl->fl->pull(sp(ct, ct_len)); if (r.is_err()) return err_buf(r.error().message);
        if (out_final) *out_final = r.value().final ? 1 : 0; return ok_buf(r.value().plaintext); }
    if (impl->fo) { auto r = impl->fo->pull(sp(ct, ct_len)); if (r.is_err()) return err_buf(r.error().message);
        if (out_final) *out_final = r.value().final ? 1 : 0; return ok_buf(r.value().plaintext); }
    return err_buf("sealed: invalid opener");
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_finalize(
    CryptoSealedOpener h, const uint8_t* trailer, size_t trailer_len) try {
    auto* impl = static_cast<SealedOpenerImpl*>(h);
    if (!impl) return err_buf("sealed: null opener");
    if (impl->fl) { auto r = impl->fl->finalize(sp(trailer, trailer_len)); return r.is_err() ? err_buf(r.error().message) : CryptoBufferResult{ null_buf(), nullptr }; }
    if (impl->fo) { auto r = impl->fo->finalize(sp(trailer, trailer_len)); return r.is_err() ? err_buf(r.error().message) : CryptoBufferResult{ null_buf(), nullptr }; }
    return err_buf("sealed: invalid opener");
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_sealed_opener_free(CryptoSealedOpener h) {
    delete static_cast<SealedOpenerImpl*>(h);
}

#else  // Suite requires OpenSSL + PQ — ABI-stable stubs otherwise
static CryptoBufferResult suite_unavailable() {
    return err_buf("Suite requires OpenSSL + post-quantum support — not compiled in");
}
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_pq_sntrup(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_pq(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_signed_pq_sntrup(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_signed_pq(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_file(const uint8_t*, size_t, const char*, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_file(const uint8_t*, size_t, const char*, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_device(const uint8_t*, size_t, CryptoKeyringHandle, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_device(const uint8_t*, size_t, CryptoKeyringHandle, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_with_keyring_passphrase(const uint8_t*, size_t, CryptoKeyringHandle, const char*, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_with_keyring_passphrase(const uint8_t*, size_t, CryptoKeyringHandle, const char*, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_seal_threshold(const uint8_t*, size_t, uint8_t, uint8_t, const uint8_t*, size_t, CryptoBuffer* out_shares) { if (out_shares) *out_shares = CryptoBuffer{nullptr, 0}; return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_open_threshold(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_suite_evm_address(const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_recipient(int) { return CryptoKeyPair{}; }
CRYPTO_API CryptoKeyPair cryptolib_sealed_generate_sender(int) { return CryptoKeyPair{}; }
CRYPTO_API CryptoBufferResult cryptolib_sealed_seal(int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_sealed_open(int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoSealedInfo cryptolib_sealed_inspect(const uint8_t*, size_t) { return CryptoSealedInfo{}; }
CRYPTO_API int cryptolib_sealed_addressed_to(const uint8_t*, size_t, const uint8_t*, size_t) { return 0; }
CRYPTO_API CryptoSealedSealer cryptolib_sealed_sealer_begin(int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, char** e) { if (e) *e = dup_err_cstr("Suite requires OpenSSL + post-quantum support — not compiled in"); return nullptr; }
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_preamble(CryptoSealedSealer) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_push(CryptoSealedSealer, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_sealed_sealer_finalize(CryptoSealedSealer, const uint8_t*, size_t, CryptoBuffer* t) { if (t) *t = CryptoBuffer{nullptr, 0}; return suite_unavailable(); }
CRYPTO_API void cryptolib_sealed_sealer_free(CryptoSealedSealer) {}
CRYPTO_API CryptoSealedOpener cryptolib_sealed_opener_begin(int, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, char** e) { if (e) *e = dup_err_cstr("Suite requires OpenSSL + post-quantum support — not compiled in"); return nullptr; }
CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_pull(CryptoSealedOpener, const uint8_t*, size_t, int* f) { if (f) *f = 0; return suite_unavailable(); }
CRYPTO_API CryptoBufferResult cryptolib_sealed_opener_finalize(CryptoSealedOpener, const uint8_t*, size_t) { return suite_unavailable(); }
CRYPTO_API void cryptolib_sealed_opener_free(CryptoSealedOpener) {}
#endif // CRYPTOLIB_HAS_OPENSSL && CRYPTOLIB_HAS_PQ

CRYPTO_API CryptoBufferResult cryptolib_aes256gcm_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::Aes256Gcm::encrypt(
        sp(plaintext, pt_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_aes256gcm_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* aad, size_t aad_len) try
{
    auto r = crypto::symmetric::Aes256Gcm::decrypt(
        sp(ciphertext, ct_len), sp(key, key_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_aes256gcm_available(void) try {
    return crypto::symmetric::Aes256Gcm::is_available() ? 1 : 0;
} CL_FAIL_INT

/* ─── SecretStream ────────────────────────────────────────────────────────── */

CRYPTO_API CryptoStreamEncHandle cryptolib_stream_enc_create(const uint8_t* key) try {
    auto* h = new StreamEncImpl{crypto::symmetric::SecretStream::Encryptor(sp(key, 32))};
    return static_cast<CryptoStreamEncHandle>(h);
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_stream_enc_header(CryptoStreamEncHandle h) try {
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<StreamEncImpl*>(h);
    return ok_buf(impl->enc.header());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_stream_enc_push(
    CryptoStreamEncHandle h,
    const uint8_t* plaintext, size_t pt_len, uint8_t tag) try
{
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<StreamEncImpl*>(h);
    auto ct = impl->enc.push(sp(plaintext, pt_len), tag);
    return ok_buf(ct);
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_stream_enc_free(CryptoStreamEncHandle h) {
    delete static_cast<StreamEncImpl*>(h);
}

CRYPTO_API CryptoStreamDecHandle cryptolib_stream_dec_create(
    const uint8_t* key, const uint8_t* header) try
{
    auto* h = new StreamDecImpl{crypto::symmetric::SecretStream::Decryptor(sp(key, 32), sp(header, 24))};
    return static_cast<CryptoStreamDecHandle>(h);
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_stream_dec_pull(
    CryptoStreamDecHandle h,
    const uint8_t* ciphertext, size_t ct_len, uint8_t* out_tag) try
{
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<StreamDecImpl*>(h);
    auto r = impl->dec.pull(sp(ciphertext, ct_len));
    if (r.is_err()) return err_buf(r.error().message);
    if (out_tag) *out_tag = r.value().tag;
    return ok_buf(r.value().plaintext);
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_stream_dec_free(CryptoStreamDecHandle h) {
    delete static_cast<StreamDecImpl*>(h);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Asymmetric
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoKeyPair cryptolib_ed25519_keygen(void) try {
    auto kp = crypto::asymmetric::Ed25519::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoKeyPair cryptolib_ed25519_keygen_from_seed(const uint8_t* seed, size_t seed_len) try {
    auto r = crypto::asymmetric::Ed25519::keypair_from_seed(sp(seed, seed_len));
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_ed25519_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len) try
{
    auto r = crypto::asymmetric::Ed25519::sign(sp(msg, msg_len), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_ed25519_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len) try
{
    return crypto::asymmetric::Ed25519::verify(sp(msg, msg_len), sp(sig, sig_len), sp(public_key, pk_len)) ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoKeyPair cryptolib_x25519_keygen(void) try {
    auto kp = crypto::asymmetric::X25519::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_x25519_shared_secret(
    const uint8_t* our_secret, size_t our_len,
    const uint8_t* their_public, size_t their_len) try
{
    auto r = crypto::asymmetric::X25519::shared_secret(sp(our_secret, our_len), sp(their_public, their_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoKeyPair cryptolib_box_keygen(void) try {
    auto kp = crypto::asymmetric::Box::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_box_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* recipient_pub, size_t rpub_len,
    const uint8_t* sender_sec, size_t ssec_len) try
{
    auto r = crypto::asymmetric::Box::encrypt(sp(plaintext, pt_len), sp(recipient_pub, rpub_len), sp(sender_sec, ssec_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_box_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* sender_pub, size_t spub_len,
    const uint8_t* recipient_sec, size_t rsec_len) try
{
    auto r = crypto::asymmetric::Box::decrypt(sp(ciphertext, ct_len), sp(sender_pub, spub_len), sp(recipient_sec, rsec_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealedbox_encrypt(
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* recipient_pub, size_t rpub_len) try
{
    auto r = crypto::asymmetric::SealedBox::encrypt(sp(plaintext, pt_len), sp(recipient_pub, rpub_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_sealedbox_decrypt(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* recipient_pub, size_t rpub_len,
    const uint8_t* recipient_sec, size_t rsec_len) try
{
    auto r = crypto::asymmetric::SealedBox::decrypt(sp(ciphertext, ct_len), sp(recipient_pub, rpub_len), sp(recipient_sec, rsec_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * Vault
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoVaultHandle cryptolib_vault_create(
    const uint8_t* master_key, size_t mk_len, int kdf_preset) try
{
    auto params = kdf_preset == 1
        ? crypto::KdfParams::sensitive()
        : crypto::KdfParams::interactive();
    auto kp = crypto::SecureVault::generate_keypair();
    auto* h = new VaultImpl{crypto::SecureVault(sp(master_key, mk_len), std::move(kp), params)};
    return static_cast<CryptoVaultHandle>(h);
} CL_FAIL_PTR

CRYPTO_API CryptoVaultHandle cryptolib_vault_from_entropy(
    CryptoEntropyHandle entropy, int kdf_preset) try
{
    if (!entropy) return nullptr;
    auto* me = static_cast<EntropyImpl*>(entropy);
    auto params = kdf_preset == 1
        ? crypto::KdfParams::sensitive()
        : crypto::KdfParams::interactive();
    auto r = me->me.make_vault(params);
    if (r.is_err()) return nullptr;
    auto* h = new VaultImpl{std::move(r.value())};
    return static_cast<CryptoVaultHandle>(h);
} CL_FAIL_PTR

static CryptoPacket packet_from_cpp(const crypto::EncryptedPacket& pkt) {
    return {
        to_cbuf(pkt.ciphertext),
        to_cbuf(pkt.signature),
        to_cbuf(pkt.kdf_salt)
    };
}

static crypto::EncryptedPacket packet_to_cpp(const CryptoPacket* p) {
    return {
        sb_from(p->ciphertext),
        sb_from(p->signature),
        sb_from(p->kdf_salt)
    };
}

CRYPTO_API CryptoPacket cryptolib_vault_seal(
    CryptoVaultHandle vault,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, char** out_error) try
{
    if (!vault) {
        if (out_error) *out_error = dup_str("null vault handle");
        return {{}, {}, {}};
    }
    auto* v = static_cast<VaultImpl*>(vault);
    auto r = v->vault.seal(
        std::string_view(reinterpret_cast<const char*>(plaintext), pt_len),
        aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {{}, {}, {}};
    }
    if (out_error) *out_error = nullptr;
    return packet_from_cpp(r.value());
} CL_FAIL_PKT

CRYPTO_API CryptoPacket cryptolib_vault_seal_boosted(
    CryptoVaultHandle vault,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, CryptoEntropyHandle boost, char** out_error) try
{
    if (!vault || !boost) {
        if (out_error) *out_error = dup_str("null handle");
        return {{}, {}, {}};
    }
    auto* v = static_cast<VaultImpl*>(vault);
    auto* me = static_cast<EntropyImpl*>(boost);
    auto r = v->vault.seal(
        std::string_view(reinterpret_cast<const char*>(plaintext), pt_len),
        aad ? std::string_view(aad) : std::string_view{},
        me->me);
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {{}, {}, {}};
    }
    if (out_error) *out_error = nullptr;
    return packet_from_cpp(r.value());
} CL_FAIL_PKT

CRYPTO_API CryptoBufferResult cryptolib_vault_open(
    CryptoVaultHandle vault,
    const CryptoPacket* packet, const char* aad) try
{
    if (!vault || !packet) return err_buf("null handle/packet");
    auto* v = static_cast<VaultImpl*>(vault);
    auto pkt = packet_to_cpp(packet);
    auto r = v->vault.open(pkt, aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_vault_open_boosted(
    CryptoVaultHandle vault,
    const CryptoPacket* packet, const char* aad,
    CryptoEntropyHandle boost) try
{
    if (!vault || !packet || !boost) return err_buf("null handle/packet/boost");
    auto* v = static_cast<VaultImpl*>(vault);
    auto* me = static_cast<EntropyImpl*>(boost);
    auto pkt = packet_to_cpp(packet);
    auto r = v->vault.open(pkt,
        aad ? std::string_view(aad) : std::string_view{},
        me->me);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_vault_public_key(CryptoVaultHandle vault) try {
    if (!vault) return err_buf("null handle");
    auto* v = static_cast<VaultImpl*>(vault);
    return { to_cbuf(v->vault.public_key()), nullptr };
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_packet_serialise(const CryptoPacket* packet) try {
    if (!packet) return err_buf("null packet");
    auto pkt = packet_to_cpp(packet);
    auto wire = pkt.serialise();
    return ok_buf(wire);
} CL_FAIL_BUFRES

CRYPTO_API CryptoPacket cryptolib_packet_deserialise(
    const uint8_t* data, size_t len, char** out_error) try
{
    auto r = crypto::EncryptedPacket::deserialise(sp(data, len));
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {{}, {}, {}};
    }
    if (out_error) *out_error = nullptr;
    return packet_from_cpp(r.value());
} CL_FAIL_PKT

CRYPTO_API void cryptolib_vault_free(CryptoVaultHandle vault) {
    delete static_cast<VaultImpl*>(vault);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Asymmetric Vault
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoAsymBundle cryptolib_asym_bundle_generate(void) try {
    auto b = crypto::AsymmetricVault::generate_bundle();
    return {
        to_cbuf(b.box_public), to_cbuf(b.box_secret),
        to_cbuf(b.sign_public), to_cbuf(b.sign_secret)
    };
} CL_FAIL_BUNDLE_NOERR

static crypto::AsymKeyBundle bundle_to_cpp(const CryptoAsymBundle* b) {
    return {
        sb_from(b->box_public),
        sb_from(b->box_secret),
        sb_from(b->sign_public),
        sb_from(b->sign_secret)
    };
}

CRYPTO_API CryptoPacket cryptolib_asym_vault_seal(
    const CryptoAsymBundle* sender,
    const uint8_t* recipient_box_pub, size_t rpub_len,
    const uint8_t* plaintext, size_t pt_len,
    const char* aad, char** out_error) try
{
    if (!sender) {
        if (out_error) *out_error = dup_str("null sender");
        return {{}, {}, {}};
    }
    auto s = bundle_to_cpp(sender);
    auto r = crypto::AsymmetricVault::seal(
        std::string_view(reinterpret_cast<const char*>(plaintext), pt_len),
        s, sp(recipient_box_pub, rpub_len),
        aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {{}, {}, {}};
    }
    if (out_error) *out_error = nullptr;
    return packet_from_cpp(r.value());
} CL_FAIL_PKT

CRYPTO_API CryptoBufferResult cryptolib_asym_vault_open(
    const CryptoPacket* packet,
    const CryptoAsymBundle* recipient,
    const uint8_t* sender_sign_pub, size_t spub_len,
    const char* aad) try
{
    if (!packet || !recipient) return err_buf("null packet/recipient");
    auto pkt = packet_to_cpp(packet);
    auto rec = bundle_to_cpp(recipient);
    auto r = crypto::AsymmetricVault::open(
        pkt, rec, sp(sender_sign_pub, spub_len),
        aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * Media Entropy
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_file(
    const char* path, char** out_error) try
{
    auto r = crypto::entropy::MediaEntropy::from_file(path);
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return nullptr;
    }
    auto* h = new EntropyImpl{std::move(r.value())};
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoEntropyHandle>(h);
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_file_deterministic(
    const char* path, char** out_error) try
{
    auto r = crypto::entropy::MediaEntropy::from_file_deterministic(path);
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return nullptr;
    }
    auto* h = new EntropyImpl{std::move(r.value())};
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoEntropyHandle>(h);
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_files(
    const char** paths, size_t count, char** out_error) try
{
    std::vector<std::filesystem::path> ps;
    for (size_t i = 0; i < count; ++i) ps.emplace_back(paths[i]);
    auto r = crypto::entropy::MediaEntropy::from_files(ps);
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return nullptr;
    }
    auto* h = new EntropyImpl{std::move(r.value())};
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoEntropyHandle>(h);
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoEntropyHandle cryptolib_entropy_from_files_deterministic(
    const char** paths, size_t count, char** out_error) try
{
    std::vector<std::filesystem::path> ps;
    for (size_t i = 0; i < count; ++i) ps.emplace_back(paths[i]);
    auto r = crypto::entropy::MediaEntropy::from_files_deterministic(ps);
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return nullptr;
    }
    auto* h = new EntropyImpl{std::move(r.value())};
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoEntropyHandle>(h);
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoDerivedKeys cryptolib_entropy_derive_all(CryptoEntropyHandle h) try {
    if (!h) return {};
    auto* impl = static_cast<EntropyImpl*>(h);
    auto dk = impl->me.derive_all();
    return {
        to_cbuf(dk.symmetric_key),
        to_cbuf(dk.vault_master_key),
        to_cbuf(dk.signing_seed),
        to_cbuf(dk.box_seed),
        to_cbuf(dk.stream_key),
        to_cbuf(dk.raw_entropy)
    };
} CL_FAIL_DERIVED

CRYPTO_API CryptoBufferResult cryptolib_entropy_symmetric_key(CryptoEntropyHandle h) try {
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<EntropyImpl*>(h);
    return ok_buf(impl->me.symmetric_key());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_entropy_raw(CryptoEntropyHandle h) try {
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<EntropyImpl*>(h);
    return ok_buf(impl->me.raw());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_entropy_boost(CryptoEntropyHandle h) try {
    if (!h) return err_buf("null handle");
    auto* impl = static_cast<EntropyImpl*>(h);
    return ok_buf(impl->me.entropy_boost());
} CL_FAIL_BUFRES

CRYPTO_API CryptoEntropyInfo cryptolib_entropy_info(CryptoEntropyHandle h) try {
    if (!h) return {nullptr, 0, 0, 0.0};
    auto* impl = static_cast<EntropyImpl*>(h);
    auto& info = impl->me.info();
    return {
        dup_str(info.path),
        info.file_size,
        info.chunks_read,
        impl->me.entropy_bits()
    };
} CL_FAIL_INFO

CRYPTO_API CryptoAsymBundle cryptolib_entropy_asym_bundle(
    CryptoEntropyHandle h, char** out_error) try
{
    if (!h) {
        if (out_error) *out_error = dup_str("null handle");
        return {};
    }
    auto* impl = static_cast<EntropyImpl*>(h);
    auto r = impl->me.asym_bundle();
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {};
    }
    if (out_error) *out_error = nullptr;
    return {
        to_cbuf(r.value().box_public), to_cbuf(r.value().box_secret),
        to_cbuf(r.value().sign_public), to_cbuf(r.value().sign_secret)
    };
} CL_FAIL_BUNDLE

CRYPTO_API void cryptolib_entropy_refresh(CryptoEntropyHandle h) try {
    if (!h) return;
    auto* impl = static_cast<EntropyImpl*>(h);
    impl->me.refresh_system_entropy();
} CL_FAIL_VOID

CRYPTO_API void cryptolib_entropy_free(CryptoEntropyHandle h) {
    delete static_cast<EntropyImpl*>(h);
}

/* ─── Entropy convenience functions ───────────────────────────────────────── */

CRYPTO_API CryptoBufferResult cryptolib_key_from_file(const char* path) try {
    auto r = crypto::entropy::key_from_file(path);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoPacket cryptolib_seal_from_file(
    const char* path, const char* plaintext, const char* aad, char** out_error) try
{
    auto r = crypto::entropy::seal_from_file(
        path, plaintext,
        aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return {{}, {}, {}};
    }
    if (out_error) *out_error = nullptr;
    return packet_from_cpp(r.value());
} CL_FAIL_PKT

CRYPTO_API CryptoBufferResult cryptolib_open_from_file(
    const char* path, const CryptoPacket* packet, const char* aad) try
{
    if (!packet) return err_buf("null packet");
    auto pkt = packet_to_cpp(packet);
    auto r = crypto::entropy::open_from_file(
        path, pkt,
        aad ? std::string_view(aad) : std::string_view{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * BLAKE3
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoBufferResult cryptolib_blake3(const uint8_t* msg, size_t msg_len,
                                                size_t out_len) try {
#ifdef CRYPTOLIB_HAS_BLAKE3
    auto r = crypto::hash::Blake3::digest(sp(msg, msg_len), out_len == 0 ? 32 : out_len);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)out_len;
    return err_buf("BLAKE3 not enabled (build with -DCRYPTOLIB_BLAKE3=ON)");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_blake3_keyed(const uint8_t* msg, size_t msg_len,
                                                      const uint8_t* key, size_t key_len,
                                                      size_t out_len) try {
#ifdef CRYPTOLIB_HAS_BLAKE3
    auto r = crypto::hash::Blake3::keyed(sp(msg, msg_len), sp(key, key_len), out_len == 0 ? 32 : out_len);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)key; (void)key_len; (void)out_len;
    return err_buf("BLAKE3 not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_blake3_derive_key(const char* context,
                                                           const uint8_t* ikm, size_t ikm_len,
                                                           size_t out_len) try {
#ifdef CRYPTOLIB_HAS_BLAKE3
    auto r = crypto::hash::Blake3::derive_key(context, sp(ikm, ikm_len), out_len == 0 ? 32 : out_len);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)context; (void)ikm; (void)ikm_len; (void)out_len;
    return err_buf("BLAKE3 not enabled");
#endif
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA256 & HKDF-SHA256
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoBufferResult cryptolib_hmac_sha256(const uint8_t* msg, size_t msg_len,
                                                     const uint8_t* key, size_t key_len) try {
    auto r = crypto::hash::HmacSha256::compute(sp(msg, msg_len), sp(key, key_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_hmac_sha256_verify(const uint8_t* msg, size_t msg_len,
                                             const uint8_t* mac, size_t mac_len,
                                             const uint8_t* key, size_t key_len) try {
    return crypto::hash::HmacSha256::verify(sp(msg, msg_len), sp(mac, mac_len), sp(key, key_len)) ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_hkdf_extract(const uint8_t* salt, size_t salt_len,
                                                      const uint8_t* ikm, size_t ikm_len) try {
    auto r = crypto::hash::HkdfSha256::extract(
        salt ? sp(salt, salt_len) : std::span<const uint8_t>{},
        sp(ikm, ikm_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hkdf_expand(const uint8_t* prk, size_t prk_len,
                                                     const uint8_t* info, size_t info_len,
                                                     size_t out_len) try {
    auto r = crypto::hash::HkdfSha256::expand(
        sp(prk, prk_len),
        info ? sp(info, info_len) : std::span<const uint8_t>{},
        out_len);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hkdf_derive(const uint8_t* ikm, size_t ikm_len,
                                                     const uint8_t* salt, size_t salt_len,
                                                     const uint8_t* info, size_t info_len,
                                                     size_t out_len) try {
    auto r = crypto::hash::HkdfSha256::derive(
        sp(ikm, ikm_len),
        salt ? sp(salt, salt_len) : std::span<const uint8_t>{},
        info ? sp(info, info_len) : std::span<const uint8_t>{},
        out_len);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * Post-Quantum — ML-KEM, ML-DSA, SLH-DSA
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API void cryptolib_kem_encaps_free(CryptoKemEncapsResult* r) {
    if (!r) return;
    cryptolib_buffer_free(&r->ciphertext);
    cryptolib_buffer_free(&r->shared_secret);
}

#ifdef CRYPTOLIB_HAS_PQ
static crypto::pq::MlKem::Level to_kem_level(int l) {
    switch (l) {
        case 0: return crypto::pq::MlKem::Level::KEM_512;
        case 2: return crypto::pq::MlKem::Level::KEM_1024;
        default: return crypto::pq::MlKem::Level::KEM_768;
    }
}
static crypto::pq::MlDsa::Level to_dsa_level(int l) {
    switch (l) {
        case 0: return crypto::pq::MlDsa::Level::DSA_44;
        case 2: return crypto::pq::MlDsa::Level::DSA_87;
        default: return crypto::pq::MlDsa::Level::DSA_65;
    }
}
static crypto::pq::SlhDsa::Level to_slh_level(int l) {
    switch (l) {
        case 0: return crypto::pq::SlhDsa::Level::L128s;
        case 1: return crypto::pq::SlhDsa::Level::L128f;
        case 2: return crypto::pq::SlhDsa::Level::L192s;
        case 3: return crypto::pq::SlhDsa::Level::L192f;
        case 4: return crypto::pq::SlhDsa::Level::L256s;
        case 5: return crypto::pq::SlhDsa::Level::L256f;
        default: return crypto::pq::SlhDsa::Level::L128f;
    }
}
static crypto::pq::SlhDsa::HashFamily to_slh_hash(int h) {
    return h == 1 ? crypto::pq::SlhDsa::HashFamily::SHAKE
                  : crypto::pq::SlhDsa::HashFamily::SHA2;
}
#endif

CRYPTO_API CryptoKeyPair cryptolib_ml_kem_keygen(int level) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlKem::generate_keypair(to_kem_level(level));
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    (void)level;
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoKemEncapsResult cryptolib_ml_kem_encapsulate(
    const uint8_t* public_key, size_t pk_len, int level, char** out_error) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlKem::encapsulate(sp(public_key, pk_len), to_kem_level(level));
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return { null_buf(), null_buf() };
    }
    if (out_error) *out_error = nullptr;
    return { to_cbuf(r.value().ciphertext), to_cbuf(r.value().shared_secret) };
#else
    (void)public_key; (void)pk_len; (void)level;
    if (out_error) *out_error = dup_str("PQ not enabled (build with -DCRYPTOLIB_PQ=ON)");
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KEM

CRYPTO_API CryptoBufferResult cryptolib_ml_kem_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len, int level) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlKem::decapsulate(sp(ciphertext, ct_len), sp(secret_key, sk_len), to_kem_level(level));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)ciphertext; (void)ct_len; (void)secret_key; (void)sk_len; (void)level;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoKeyPair cryptolib_hybrid_kem_keygen(void) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridKem::generate_keypair();
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoKemEncapsResult cryptolib_hybrid_kem_encapsulate(
    const uint8_t* public_key, size_t pk_len, char** out_error) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridKem::encapsulate(sp(public_key, pk_len));
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return { null_buf(), null_buf() };
    }
    if (out_error) *out_error = nullptr;
    return { to_cbuf(r.value().ciphertext), to_cbuf(r.value().shared_secret) };
#else
    (void)public_key; (void)pk_len;
    if (out_error) *out_error = dup_str("PQ not enabled (build with -DCRYPTOLIB_PQ=ON)");
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KEM

CRYPTO_API CryptoBufferResult cryptolib_hybrid_kem_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridKem::decapsulate(sp(ciphertext, ct_len), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)ciphertext; (void)ct_len; (void)secret_key; (void)sk_len;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

// ── Hybrid KEM (X25519 + sntrup761) ─────────────────────────────────────────
CRYPTO_API CryptoKeyPair cryptolib_sntrup_x25519_keygen(void) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SntrupX25519::generate_keypair();
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoKemEncapsResult cryptolib_sntrup_x25519_encapsulate(
    const uint8_t* public_key, size_t pk_len, char** out_error) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SntrupX25519::encapsulate(sp(public_key, pk_len));
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return { null_buf(), null_buf() };
    }
    if (out_error) *out_error = nullptr;
    return { to_cbuf(r.value().ciphertext), to_cbuf(r.value().shared_secret) };
#else
    (void)public_key; (void)pk_len;
    if (out_error) *out_error = dup_str("PQ not enabled (build with -DCRYPTOLIB_PQ=ON)");
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KEM

CRYPTO_API CryptoBufferResult cryptolib_sntrup_x25519_decapsulate(
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* secret_key, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SntrupX25519::decapsulate(sp(ciphertext, ct_len), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)ciphertext; (void)ct_len; (void)secret_key; (void)sk_len;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

// ── Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet) ──────────
#ifdef CRYPTOLIB_HAS_PQ
namespace { struct SessionImpl { crypto::Session session; }; }

CRYPTO_API CryptoKeyPair cryptolib_session_generate_prekey(void) try {
    auto r = crypto::Session::generate_prekey();
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoSession cryptolib_session_initiate(
    const uint8_t* prekey_public, size_t pk_len, char** out_error) try {
    if (out_error) *out_error = nullptr;
    auto r = crypto::Session::initiate(sp(prekey_public, pk_len));
    if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); return nullptr; }
    return static_cast<CryptoSession>(new SessionImpl{ std::move(r.value()) });
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_session_handshake(CryptoSession h) try {
    auto* impl = static_cast<SessionImpl*>(h);
    if (!impl) return err_buf("session: null handle");
    return ok_buf(impl->session.handshake());
} CL_FAIL_BUFRES

CRYPTO_API CryptoSession cryptolib_session_accept(
    const uint8_t* handshake, size_t hs_len,
    const uint8_t* prekey_public, size_t pk_len,
    const uint8_t* prekey_secret, size_t sk_len, char** out_error) try {
    if (out_error) *out_error = nullptr;
    crypto::pq::HybridKem::KeyPair kp{
        crypto::SecureBuffer(prekey_public, pk_len),
        crypto::SecureBuffer(prekey_secret, sk_len) };
    auto r = crypto::Session::accept(sp(handshake, hs_len), kp);
    if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); return nullptr; }
    return static_cast<CryptoSession>(new SessionImpl{ std::move(r.value()) });
} CL_FAIL_PTR

CRYPTO_API CryptoBufferResult cryptolib_session_encrypt(
    CryptoSession h, const uint8_t* pt, size_t pt_len, const uint8_t* aad, size_t aad_len) try {
    auto* impl = static_cast<SessionImpl*>(h);
    if (!impl) return err_buf("session: null handle");
    auto r = impl->session.encrypt(sp(pt, pt_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_session_decrypt(
    CryptoSession h, const uint8_t* msg, size_t msg_len, const uint8_t* aad, size_t aad_len) try {
    auto* impl = static_cast<SessionImpl*>(h);
    if (!impl) return err_buf("session: null handle");
    auto r = impl->session.decrypt(sp(msg, msg_len), opt_aad(aad, aad_len));
    return r.is_err() ? err_buf(r.error().message) : ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_session_free(CryptoSession h) { delete static_cast<SessionImpl*>(h); }

#else  // PQ disabled — ABI-stable stubs
CRYPTO_API CryptoKeyPair cryptolib_session_generate_prekey(void) { return { null_buf(), null_buf() }; }
CRYPTO_API CryptoSession cryptolib_session_initiate(const uint8_t*, size_t, char** e) { if (e) *e = dup_err_cstr("PQ not enabled"); return nullptr; }
CRYPTO_API CryptoBufferResult cryptolib_session_handshake(CryptoSession) { return err_buf("PQ not enabled"); }
CRYPTO_API CryptoSession cryptolib_session_accept(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, char** e) { if (e) *e = dup_err_cstr("PQ not enabled"); return nullptr; }
CRYPTO_API CryptoBufferResult cryptolib_session_encrypt(CryptoSession, const uint8_t*, size_t, const uint8_t*, size_t) { return err_buf("PQ not enabled"); }
CRYPTO_API CryptoBufferResult cryptolib_session_decrypt(CryptoSession, const uint8_t*, size_t, const uint8_t*, size_t) { return err_buf("PQ not enabled"); }
CRYPTO_API void cryptolib_session_free(CryptoSession) {}
#endif

CRYPTO_API CryptoKeyPair cryptolib_ml_dsa_keygen(int level) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlDsa::generate_keypair(to_dsa_level(level));
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    (void)level;
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_ml_dsa_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len, int level) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlDsa::sign(sp(msg, msg_len), sp(secret_key, sk_len), to_dsa_level(level));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)secret_key; (void)sk_len; (void)level;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_ml_dsa_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len, int level) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::MlDsa::verify(sp(msg, msg_len), sp(sig, sig_len), sp(public_key, pk_len), to_dsa_level(level));
    return r.is_ok() ? 1 : 0;
#else
    (void)msg; (void)msg_len; (void)sig; (void)sig_len; (void)public_key; (void)pk_len; (void)level;
    return 0;
#endif
} CL_FAIL_INT

CRYPTO_API CryptoKeyPair cryptolib_hybrid_sig_keygen(void) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridSig::generate_keypair();
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_hybrid_sig_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridSig::sign(sp(msg, msg_len), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)secret_key; (void)sk_len;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_hybrid_sig_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::HybridSig::verify(sp(msg, msg_len), sp(sig, sig_len), sp(public_key, pk_len));
    return r.is_ok() ? 1 : 0;
#else
    (void)msg; (void)msg_len; (void)sig; (void)sig_len; (void)public_key; (void)pk_len;
    return 0;
#endif
} CL_FAIL_INT

CRYPTO_API CryptoKeyPair cryptolib_slh_dsa_keygen(int level, int hash_family) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SlhDsa::generate_keypair(to_slh_level(level), to_slh_hash(hash_family));
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    (void)level; (void)hash_family;
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_slh_dsa_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len, int level, int hash_family) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SlhDsa::sign(sp(msg, msg_len), sp(secret_key, sk_len), to_slh_level(level), to_slh_hash(hash_family));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)secret_key; (void)sk_len; (void)level; (void)hash_family;
    return err_buf("PQ not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_slh_dsa_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len, int level, int hash_family) try {
#ifdef CRYPTOLIB_HAS_PQ
    auto r = crypto::pq::SlhDsa::verify(sp(msg, msg_len), sp(sig, sig_len), sp(public_key, pk_len), to_slh_level(level), to_slh_hash(hash_family));
    return r.is_ok() ? 1 : 0;
#else
    (void)msg; (void)msg_len; (void)sig; (void)sig_len; (void)public_key; (void)pk_len; (void)level; (void)hash_family;
    return 0;
#endif
} CL_FAIL_INT

/* ═══════════════════════════════════════════════════════════════════════════
 * BLS12-381
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoKeyPair cryptolib_bls_keygen(void) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::bls::Bls12381::generate_keypair();
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoKeyPair cryptolib_bls_keygen_from_ikm(const uint8_t* ikm, size_t ikm_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::bls::Bls12381::generate_keypair_from_ikm(sp(ikm, ikm_len));
    if (r.is_err()) return { null_buf(), null_buf() };
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    (void)ikm; (void)ikm_len;
    return { null_buf(), null_buf() };
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_bls_sign(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* secret_key, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::bls::Bls12381::sign(sp(msg, msg_len), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)msg; (void)msg_len; (void)secret_key; (void)sk_len;
    return err_buf("BLS not enabled (build with -DCRYPTOLIB_BLS=ON)");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_bls_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::bls::Bls12381::verify(sp(msg, msg_len), sp(sig, sig_len), sp(public_key, pk_len));
    return r.is_ok() ? 1 : 0;
#else
    (void)msg; (void)msg_len; (void)sig; (void)sig_len; (void)public_key; (void)pk_len;
    return 0;
#endif
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_bls_aggregate(
    const uint8_t* const* sigs, const size_t* sig_lens, size_t count) try {
#ifdef CRYPTOLIB_HAS_BLS
    std::vector<std::span<const uint8_t>> sig_spans;
    sig_spans.reserve(count);
    for (size_t i = 0; i < count; ++i)
        sig_spans.push_back(sp(sigs[i], sig_lens[i]));
    auto r = crypto::bls::Bls12381::aggregate_signatures(sig_spans);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)sigs; (void)sig_lens; (void)count;
    return err_buf("BLS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_bls_aggregate_verify(
    const uint8_t* const* msgs, const size_t* msg_lens,
    const uint8_t* const* pks,  const size_t* pk_lens,
    size_t count,
    const uint8_t* agg_sig, size_t agg_sig_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    std::vector<std::span<const uint8_t>> msg_spans, pk_spans;
    msg_spans.reserve(count);
    pk_spans.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        msg_spans.push_back(sp(msgs[i], msg_lens[i]));
        pk_spans.push_back(sp(pks[i], pk_lens[i]));
    }
    auto r = crypto::bls::Bls12381::aggregate_verify(msg_spans, pk_spans, sp(agg_sig, agg_sig_len));
    return r.is_ok() ? 1 : 0;
#else
    (void)msgs; (void)msg_lens; (void)pks; (void)pk_lens; (void)count; (void)agg_sig; (void)agg_sig_len;
    return 0;
#endif
} CL_FAIL_INT

/* ═══════════════════════════════════════════════════════════════════════════
 * FROST(Ed25519, SHA-512) — RFC 9591 threshold signatures
 * ═══════════════════════════════════════════════════════════════════════════ */

// Rebuild the commitment list from the three parallel wire arrays.
static std::vector<crypto::Frost::Commitment>
frost_commitments(const uint16_t* ids, const uint8_t* hidings,
                  const uint8_t* bindings, size_t count) {
    std::vector<crypto::Frost::Commitment> cs;
    cs.reserve(count);
    for (size_t i = 0; i < count; ++i)
        cs.push_back(crypto::Frost::Commitment{
            ids[i],
            crypto::SecureBuffer(hidings + i * 32, 32),
            crypto::SecureBuffer(bindings + i * 32, 32) });
    return cs;
}

#define CL_FAIL_FROST_KG catch (...) { \
    CryptoFrostKeyGen o{}; o.error = dup_err_cstr("internal error"); return o; }
#define CL_FAIL_FROST_COMMIT catch (...) { \
    CryptoFrostCommit o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API void cryptolib_frost_keygen_free(CryptoFrostKeyGen* kg) {
    if (!kg) return;
    cryptolib_buffer_free(&kg->group_public_key);
    cryptolib_buffer_free(&kg->secret_shares);
    cryptolib_buffer_free(&kg->public_shares);
    kg->count = 0;
    if (kg->error) { std::free(kg->error); kg->error = nullptr; }
}

CRYPTO_API void cryptolib_frost_commit_free(CryptoFrostCommit* c) {
    if (!c) return;
    cryptolib_buffer_free(&c->hiding_nonce);
    cryptolib_buffer_free(&c->binding_nonce);
    cryptolib_buffer_free(&c->hiding_commit);
    cryptolib_buffer_free(&c->binding_commit);
    if (c->error) { std::free(c->error); c->error = nullptr; }
}

CRYPTO_API CryptoFrostKeyGen cryptolib_frost_keygen(uint16_t n, uint16_t t) try {
    CryptoFrostKeyGen out{};
    auto r = crypto::Frost::keygen(n, t);
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    auto& kg = r.value();
    const size_t cnt = kg.shares.size();
    crypto::SecureBuffer secs(cnt * 32), pubs(cnt * 32);
    for (size_t i = 0; i < cnt; ++i) {
        std::memcpy(secs.data() + i * 32, kg.shares[i].secret.data(), 32);
        std::memcpy(pubs.data() + i * 32, kg.public_shares[i].data(), 32);
    }
    out.group_public_key = to_cbuf(kg.group_public_key);
    out.secret_shares    = to_cbuf(secs);
    out.public_shares    = to_cbuf(pubs);
    out.count            = cnt;
    return out;
} CL_FAIL_FROST_KG

static CryptoFrostCommit frost_commit_result(
    crypto::Result<std::pair<crypto::Frost::Nonces, crypto::Frost::Commitment>>&& r) {
    CryptoFrostCommit out{};
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    auto& [nonces, commit] = r.value();
    out.hiding_nonce   = to_cbuf(nonces.hiding);
    out.binding_nonce  = to_cbuf(nonces.binding);
    out.hiding_commit  = to_cbuf(commit.hiding);
    out.binding_commit = to_cbuf(commit.binding);
    return out;
}

CRYPTO_API CryptoFrostCommit cryptolib_frost_commit(
    const uint8_t* share_secret, size_t sk_len, uint16_t identifier) try {
    crypto::Frost::SignerShare share{ identifier,
        crypto::SecureBuffer(share_secret, sk_len) };
    return frost_commit_result(crypto::Frost::commit(share));
} CL_FAIL_FROST_COMMIT

CRYPTO_API CryptoFrostCommit cryptolib_frost_commit_with_nonces(
    uint16_t identifier,
    const uint8_t* hiding_nonce, size_t hn_len,
    const uint8_t* binding_nonce, size_t bn_len) try {
    return frost_commit_result(crypto::Frost::commit_with_nonces(
        identifier,
        crypto::SecureBuffer(hiding_nonce, hn_len),
        crypto::SecureBuffer(binding_nonce, bn_len)));
} CL_FAIL_FROST_COMMIT

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
    size_t count) try {
    crypto::Frost::SignerShare share{ identifier,
        crypto::SecureBuffer(share_secret, sk_len) };
    crypto::Frost::Nonces nonces{
        crypto::SecureBuffer(hiding_nonce, hn_len),
        crypto::SecureBuffer(binding_nonce, bn_len) };
    auto cs = frost_commitments(ids, hiding_commits, binding_commits, count);
    auto r = crypto::Frost::sign(share, sp(group_public_key, gpk_len),
                                 nonces, sp(msg, msg_len), cs);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_frost_aggregate(
    const uint8_t* group_public_key, size_t gpk_len,
    const uint8_t* msg, size_t msg_len,
    const uint16_t* ids,
    const uint8_t* hiding_commits,
    const uint8_t* binding_commits,
    size_t count,
    const uint8_t* sig_shares) try {
    auto cs = frost_commitments(ids, hiding_commits, binding_commits, count);
    std::vector<crypto::SecureBuffer> shares;
    shares.reserve(count);
    for (size_t i = 0; i < count; ++i)
        shares.emplace_back(sig_shares + i * 32, 32);
    auto r = crypto::Frost::aggregate(sp(group_public_key, gpk_len),
                                      sp(msg, msg_len), cs, shares);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_frost_verify(
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* group_public_key, size_t gpk_len) try {
    return crypto::Frost::verify(sp(msg, msg_len), sp(sig, sig_len),
                                 sp(group_public_key, gpk_len)) ? 1 : 0;
} CL_FAIL_INT

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
    size_t count) try {
    crypto::Frost::Commitment commitment{
        identifier,
        crypto::SecureBuffer(commit_hiding, ch_len),
        crypto::SecureBuffer(commit_binding, cb_len) };
    auto cs = frost_commitments(ids, hiding_commits, binding_commits, count);
    auto r = crypto::Frost::verify_share(
        identifier, sp(public_share, ps_len), sp(sig_share, ss_len),
        commitment, sp(group_public_key, gpk_len), sp(msg, msg_len), cs);
    return (r.is_ok() && r.value()) ? 1 : 0;
} CL_FAIL_INT

/* ═══════════════════════════════════════════════════════════════════════════
 * HPKE — Hybrid Public Key Encryption (RFC 9180)
 * ═══════════════════════════════════════════════════════════════════════════ */

struct HpkeCtxImpl { crypto::Hpke::Context ctx; };

static crypto::Hpke::Kdf hpke_kdf(int k) {
    return k == 3 ? crypto::Hpke::Kdf::HkdfSha512 : crypto::Hpke::Kdf::HkdfSha256;
}
static crypto::Hpke::Aead hpke_aead(int a) {
    switch (a) {
        case 1:     return crypto::Hpke::Aead::Aes128Gcm;
        case 2:     return crypto::Hpke::Aead::Aes256Gcm;
        case 0xFFFF: return crypto::Hpke::Aead::ExportOnly;
        default:    return crypto::Hpke::Aead::ChaCha20Poly1305;
    }
}
static crypto::Hpke::Mode hpke_mode(int m) {
    switch (m) {
        case 1:  return crypto::Hpke::Mode::Psk;
        case 2:  return crypto::Hpke::Mode::Auth;
        case 3:  return crypto::Hpke::Mode::AuthPsk;
        default: return crypto::Hpke::Mode::Base;
    }
}

CRYPTO_API CryptoKeyPair cryptolib_hpke_keygen(void) try {
    auto kp = crypto::Hpke::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoKeyPair cryptolib_hpke_derive_keypair(const uint8_t* ikm, size_t ikm_len) try {
    auto r = crypto::Hpke::derive_keypair(sp(ikm, ikm_len));
    if (r.is_err()) return CryptoKeyPair{};
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoHpkeContext cryptolib_hpke_setup_s(
    int kdf, int aead, int mode,
    const uint8_t* pkR, size_t pkR_len,
    const uint8_t* info, size_t info_len,
    const uint8_t* psk, size_t psk_len,
    const uint8_t* psk_id, size_t psk_id_len,
    const uint8_t* skS, size_t skS_len,
    CryptoBuffer* out_enc, char** out_error) try {
    if (out_enc) *out_enc = CryptoBuffer{ nullptr, 0 };
    auto r = crypto::Hpke::setup_s_deterministic(
        hpke_mode(mode), hpke_kdf(kdf), hpke_aead(aead),
        sp(pkR, pkR_len), sp(info, info_len),
        sp(psk, psk_len), sp(psk_id, psk_id_len), sp(skS, skS_len), {});
    if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); return nullptr; }
    if (out_enc) *out_enc = to_cbuf(r.value().enc);
    return new HpkeCtxImpl{ std::move(r.value().ctx) };
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoHpkeContext cryptolib_hpke_setup_r(
    int kdf, int aead, int mode,
    const uint8_t* enc, size_t enc_len,
    const uint8_t* skR, size_t skR_len,
    const uint8_t* info, size_t info_len,
    const uint8_t* psk, size_t psk_len,
    const uint8_t* psk_id, size_t psk_id_len,
    const uint8_t* pkS, size_t pkS_len,
    char** out_error) try {
    auto r = crypto::Hpke::setup_r(
        hpke_mode(mode), hpke_kdf(kdf), hpke_aead(aead),
        sp(enc, enc_len), sp(skR, skR_len), sp(info, info_len),
        sp(psk, psk_len), sp(psk_id, psk_id_len), sp(pkS, pkS_len));
    if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); return nullptr; }
    return new HpkeCtxImpl{ std::move(r.value()) };
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoBufferResult cryptolib_hpke_seal(
    CryptoHpkeContext h, const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t pt_len) try {
    if (!h) return err_buf("HPKE: null context");
    auto r = static_cast<HpkeCtxImpl*>(h)->ctx.seal(sp(aad, aad_len), sp(pt, pt_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hpke_open(
    CryptoHpkeContext h, const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t ct_len) try {
    if (!h) return err_buf("HPKE: null context");
    auto r = static_cast<HpkeCtxImpl*>(h)->ctx.open(sp(aad, aad_len), sp(ct, ct_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hpke_export(
    CryptoHpkeContext h, const uint8_t* exporter_context, size_t ctx_len, size_t length) try {
    if (!h) return err_buf("HPKE: null context");
    auto r = static_cast<HpkeCtxImpl*>(h)->ctx.export_secret(sp(exporter_context, ctx_len), length);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_hpke_context_free(CryptoHpkeContext h) {
    delete static_cast<HpkeCtxImpl*>(h);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BBS Signatures — multi-message signatures + selective disclosure
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifdef CRYPTOLIB_HAS_BLS
static std::vector<std::span<const uint8_t>>
bbs_msgs(const uint8_t* const* msgs, const size_t* lens, size_t count) {
    std::vector<std::span<const uint8_t>> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) out.push_back(sp(msgs[i], lens[i]));
    return out;
}
static std::vector<std::size_t>
bbs_indexes(const uint64_t* idx, size_t count) {
    std::vector<std::size_t> out;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) out.push_back(static_cast<std::size_t>(idx[i]));
    return out;
}
#endif

CRYPTO_API CryptoKeyPair cryptolib_bbs_keygen(
    const uint8_t* key_material, size_t km_len, const uint8_t* key_info, size_t ki_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::keygen(sp(key_material, km_len), sp(key_info, ki_len));
    if (r.is_err()) return CryptoKeyPair{};
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
#else
    (void)key_material; (void)km_len; (void)key_info; (void)ki_len;
    return CryptoKeyPair{};
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_bbs_sk_to_pk(const uint8_t* sk, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::sk_to_pk(sp(sk, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)sk; (void)sk_len;
    return err_buf("BBS not enabled (build with -DCRYPTOLIB_BLS=ON)");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_bbs_sign(
    const uint8_t* sk, size_t sk_len, const uint8_t* pk, size_t pk_len,
    const uint8_t* header, size_t header_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::sign(sp(sk, sk_len), sp(pk, pk_len), sp(header, header_len),
                               bbs_msgs(msgs, msg_lens, msg_count));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)sk;(void)sk_len;(void)pk;(void)pk_len;(void)header;(void)header_len;(void)msgs;(void)msg_lens;(void)msg_count;
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_bbs_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* signature, size_t sig_len,
    const uint8_t* header, size_t header_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    return crypto::Bbs::verify(sp(pk, pk_len), sp(signature, sig_len), sp(header, header_len),
                               bbs_msgs(msgs, msg_lens, msg_count)) ? 1 : 0;
#else
    (void)pk;(void)pk_len;(void)signature;(void)sig_len;(void)header;(void)header_len;(void)msgs;(void)msg_lens;(void)msg_count;
    return 0;
#endif
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_bbs_proof_gen(
    const uint8_t* pk, size_t pk_len, const uint8_t* signature, size_t sig_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count,
    const uint64_t* disclosed_indexes, size_t disclosed_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::proof_gen(sp(pk, pk_len), sp(signature, sig_len),
                                    sp(header, header_len), sp(ph, ph_len),
                                    bbs_msgs(msgs, msg_lens, msg_count),
                                    bbs_indexes(disclosed_indexes, disclosed_count));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)pk;(void)pk_len;(void)signature;(void)sig_len;(void)header;(void)header_len;(void)ph;(void)ph_len;
    (void)msgs;(void)msg_lens;(void)msg_count;(void)disclosed_indexes;(void)disclosed_count;
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_bbs_proof_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* proof, size_t proof_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* const* disclosed_msgs, const size_t* disclosed_lens, size_t disclosed_count,
    const uint64_t* disclosed_indexes, size_t indexes_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    return crypto::Bbs::proof_verify(sp(pk, pk_len), sp(proof, proof_len),
                                     sp(header, header_len), sp(ph, ph_len),
                                     bbs_msgs(disclosed_msgs, disclosed_lens, disclosed_count),
                                     bbs_indexes(disclosed_indexes, indexes_count)) ? 1 : 0;
#else
    (void)pk;(void)pk_len;(void)proof;(void)proof_len;(void)header;(void)header_len;(void)ph;(void)ph_len;
    (void)disclosed_msgs;(void)disclosed_lens;(void)disclosed_count;(void)disclosed_indexes;(void)indexes_count;
    return 0;
#endif
} CL_FAIL_INT

// ── BBS pseudonyms + blind issuance ──────────────────────────────────────────
CRYPTO_API CryptoBufferResult cryptolib_bbs_commit_with_nym(
    const uint8_t* const* committed_msgs, const size_t* committed_lens, size_t committed_count,
    const uint8_t* const* prover_nyms, const size_t* nym_lens, size_t nym_count,
    CryptoBuffer* secret_prover_blind) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::commit_with_nym(
        bbs_msgs(committed_msgs, committed_lens, committed_count),
        bbs_msgs(prover_nyms, nym_lens, nym_count), crypto::Bbs::API_ID_PSEUDONYM);
    if (secret_prover_blind)
        *secret_prover_blind = to_cbuf(std::span<const uint8_t>(r.secret_prover_blind.data(), r.secret_prover_blind.size()));
    return { to_cbuf(std::span<const uint8_t>(r.commitment_with_proof)), nullptr };
#else
    (void)committed_msgs;(void)committed_lens;(void)committed_count;(void)prover_nyms;(void)nym_lens;(void)nym_count;
    if (secret_prover_blind) *secret_prover_blind = { nullptr, 0 };
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_bbs_blind_sign_with_nym(
    const uint8_t* sk, size_t sk_len, const uint8_t* pk, size_t pk_len,
    const uint8_t* commitment_with_proof, size_t commit_len,
    const uint8_t* header, size_t header_len,
    const uint8_t* const* msgs, const size_t* msg_lens, size_t msg_count,
    const uint8_t* signer_nym_entropy, size_t entropy_len, uint64_t length_nym_vector) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto sig = crypto::Bbs::blind_sign(sp(sk, sk_len), sp(pk, pk_len),
        sp(commitment_with_proof, commit_len), sp(header, header_len),
        bbs_msgs(msgs, msg_lens, msg_count), crypto::Bbs::API_ID_PSEUDONYM,
        sp(signer_nym_entropy, entropy_len), length_nym_vector);
    return { to_cbuf(std::span<const uint8_t>(sig)), nullptr };
#else
    (void)sk;(void)sk_len;(void)pk;(void)pk_len;(void)commitment_with_proof;(void)commit_len;(void)header;(void)header_len;
    (void)msgs;(void)msg_lens;(void)msg_count;(void)signer_nym_entropy;(void)entropy_len;(void)length_nym_vector;
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_bbs_finalize_nym_secrets(
    const uint8_t* const* prover_nyms, const size_t* nym_lens, size_t nym_count,
    const uint8_t* signer_nym_entropy, size_t entropy_len) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto secrets = crypto::Bbs::finalize_nym_secrets(
        bbs_msgs(prover_nyms, nym_lens, nym_count), sp(signer_nym_entropy, entropy_len));
    std::vector<uint8_t> flat;
    for (const auto& s : secrets) flat.insert(flat.end(), s.begin(), s.end());
    return { to_cbuf(std::span<const uint8_t>(flat)), nullptr };
#else
    (void)prover_nyms;(void)nym_lens;(void)nym_count;(void)signer_nym_entropy;(void)entropy_len;
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_bbs_calculate_pseudonym(
    const uint8_t* context_id, size_t ctx_len,
    const uint8_t* const* nym_secrets, const size_t* nym_lens, size_t nym_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto p = crypto::Bbs::calculate_pseudonym(sp(context_id, ctx_len),
        bbs_msgs(nym_secrets, nym_lens, nym_count), crypto::Bbs::API_ID_PSEUDONYM);
    return { to_cbuf(std::span<const uint8_t>(p.data(), p.size())), nullptr };
#else
    (void)context_id;(void)ctx_len;(void)nym_secrets;(void)nym_lens;(void)nym_count;
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_bbs_proof_gen_with_pseudonym(
    const uint8_t* pk, size_t pk_len, const uint8_t* signature, size_t sig_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* context_id, size_t ctx_len,
    const uint8_t* const* signer_msgs, const size_t* signer_lens, size_t signer_count,
    const uint8_t* const* committed_msgs, const size_t* committed_lens, size_t committed_count,
    const uint8_t* secret_prover_blind, size_t spb_len,
    const uint8_t* const* nym_secrets, const size_t* nym_lens, size_t nym_count,
    const uint64_t* disclosed_signer_indexes, size_t disclosed_signer_count,
    const uint64_t* disclosed_committed_indexes, size_t disclosed_committed_count,
    CryptoBuffer* pseudonym_out) try {
#ifdef CRYPTOLIB_HAS_BLS
    auto r = crypto::Bbs::proof_gen_with_pseudonym(sp(pk, pk_len), sp(signature, sig_len),
        sp(header, header_len), sp(ph, ph_len), sp(context_id, ctx_len),
        bbs_msgs(signer_msgs, signer_lens, signer_count),
        bbs_msgs(committed_msgs, committed_lens, committed_count),
        sp(secret_prover_blind, spb_len), bbs_msgs(nym_secrets, nym_lens, nym_count),
        bbs_indexes(disclosed_signer_indexes, disclosed_signer_count),
        bbs_indexes(disclosed_committed_indexes, disclosed_committed_count),
        crypto::Bbs::API_ID_PSEUDONYM);
    if (r.is_err()) { if (pseudonym_out) *pseudonym_out = { nullptr, 0 }; return err_buf(r.error().message); }
    auto& [proof, pseudonym] = r.value();
    if (pseudonym_out) *pseudonym_out = to_cbuf(std::span<const uint8_t>(pseudonym.data(), pseudonym.size()));
    return ok_buf(proof);
#else
    (void)pk;(void)pk_len;(void)signature;(void)sig_len;(void)header;(void)header_len;(void)ph;(void)ph_len;
    (void)context_id;(void)ctx_len;(void)signer_msgs;(void)signer_lens;(void)signer_count;
    (void)committed_msgs;(void)committed_lens;(void)committed_count;(void)secret_prover_blind;(void)spb_len;
    (void)nym_secrets;(void)nym_lens;(void)nym_count;(void)disclosed_signer_indexes;(void)disclosed_signer_count;
    (void)disclosed_committed_indexes;(void)disclosed_committed_count;
    if (pseudonym_out) *pseudonym_out = { nullptr, 0 };
    return err_buf("BBS not enabled");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_bbs_proof_verify_with_pseudonym(
    const uint8_t* pk, size_t pk_len, const uint8_t* proof, size_t proof_len,
    const uint8_t* header, size_t header_len, const uint8_t* ph, size_t ph_len,
    const uint8_t* context_id, size_t ctx_len, const uint8_t* pseudonym, size_t nym_len,
    uint64_t L, uint64_t length_nym_vector,
    const uint8_t* const* disclosed_msgs, const size_t* disclosed_lens, size_t disclosed_count,
    const uint64_t* disclosed_indexes, size_t indexes_count) try {
#ifdef CRYPTOLIB_HAS_BLS
    return crypto::Bbs::proof_verify_with_pseudonym(sp(pk, pk_len), sp(proof, proof_len),
        sp(header, header_len), sp(ph, ph_len), sp(context_id, ctx_len), sp(pseudonym, nym_len),
        static_cast<std::size_t>(L), static_cast<std::size_t>(length_nym_vector),
        bbs_msgs(disclosed_msgs, disclosed_lens, disclosed_count),
        bbs_indexes(disclosed_indexes, indexes_count), crypto::Bbs::API_ID_PSEUDONYM) ? 1 : 0;
#else
    (void)pk;(void)pk_len;(void)proof;(void)proof_len;(void)header;(void)header_len;(void)ph;(void)ph_len;
    (void)context_id;(void)ctx_len;(void)pseudonym;(void)nym_len;(void)L;(void)length_nym_vector;
    (void)disclosed_msgs;(void)disclosed_lens;(void)disclosed_count;(void)disclosed_indexes;(void)indexes_count;
    return 0;
#endif
} CL_FAIL_INT

/* ═══════════════════════════════════════════════════════════════════════════
 * ECVRF — Verifiable Random Function (RFC 9381)
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoKeyPair cryptolib_ecvrf_keygen(void) try {
    auto kp = crypto::Ecvrf::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_ecvrf_public_key(const uint8_t* sk, size_t sk_len) try {
    if (sk_len != crypto::Ecvrf::SK_BYTES) return err_buf("ECVRF: secret key must be 32 bytes");
    return ok_buf(crypto::Ecvrf::derive_public_key(sp(sk, sk_len)));
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_ecvrf_prove(
    const uint8_t* sk, size_t sk_len, const uint8_t* alpha, size_t alpha_len) try {
    auto r = crypto::Ecvrf::prove(sp(sk, sk_len), sp(alpha, alpha_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_ecvrf_proof_to_hash(const uint8_t* pi, size_t pi_len) try {
    auto r = crypto::Ecvrf::proof_to_hash(sp(pi, pi_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_ecvrf_verify(
    const uint8_t* pk, size_t pk_len, const uint8_t* alpha, size_t alpha_len,
    const uint8_t* pi, size_t pi_len) try {
    auto r = crypto::Ecvrf::verify(sp(pk, pk_len), sp(alpha, alpha_len), sp(pi, pi_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * OPRF — Oblivious Pseudorandom Function (RFC 9497)
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API void cryptolib_oprf_blind_free(CryptoOprfBlind* b) {
    if (!b) return;
    cryptolib_buffer_free(&b->blind);
    cryptolib_buffer_free(&b->blinded_element);
    if (b->error) { std::free(b->error); b->error = nullptr; }
}

CRYPTO_API CryptoKeyPair cryptolib_oprf_derive_keypair(
    const uint8_t* seed, size_t seed_len, const uint8_t* info, size_t info_len) try {
    auto r = crypto::Oprf::derive_keypair(sp(seed, seed_len), sp(info, info_len));
    if (r.is_err()) return CryptoKeyPair{};
    return { to_cbuf(r.value().public_key), to_cbuf(r.value().secret_key) };
} CL_FAIL_KP

static CryptoOprfBlind oprf_blind_out(crypto::Result<crypto::Oprf::BlindResult>&& r) {
    CryptoOprfBlind out{};
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.blind = to_cbuf(r.value().blind);
    out.blinded_element = to_cbuf(r.value().blinded_element);
    return out;
}

CRYPTO_API CryptoOprfBlind cryptolib_oprf_blind(const uint8_t* input, size_t input_len) try {
    return oprf_blind_out(crypto::Oprf::blind(sp(input, input_len)));
} catch (...) { CryptoOprfBlind o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoOprfBlind cryptolib_oprf_blind_with_scalar(
    const uint8_t* input, size_t input_len, const uint8_t* blind, size_t blind_len) try {
    return oprf_blind_out(crypto::Oprf::blind_with_scalar(sp(input, input_len), sp(blind, blind_len)));
} catch (...) { CryptoOprfBlind o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoBufferResult cryptolib_oprf_blind_evaluate(
    const uint8_t* sk, size_t sk_len, const uint8_t* blinded_element, size_t be_len) try {
    auto r = crypto::Oprf::blind_evaluate(sp(sk, sk_len), sp(blinded_element, be_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_oprf_finalize(
    const uint8_t* input, size_t input_len, const uint8_t* blind, size_t blind_len,
    const uint8_t* evaluated_element, size_t ee_len) try {
    auto r = crypto::Oprf::finalize(sp(input, input_len), sp(blind, blind_len), sp(evaluated_element, ee_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_oprf_evaluate(
    const uint8_t* sk, size_t sk_len, const uint8_t* input, size_t input_len) try {
    auto r = crypto::Oprf::evaluate(sp(sk, sk_len), sp(input, input_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * OPAQUE — asymmetric PAKE (draft-irtf-cfrg-opaque, OPAQUE-3DH)
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API void cryptolib_opaque_record_free(CryptoOpaqueRecord* r) {
    if (!r) return;
    cryptolib_buffer_free(&r->record);
    cryptolib_buffer_free(&r->export_key);
    if (r->error) { std::free(r->error); r->error = nullptr; }
}
CRYPTO_API void cryptolib_opaque_ke1_free(CryptoOpaqueKe1* k) {
    if (!k) return;
    cryptolib_buffer_free(&k->ke1);
    cryptolib_buffer_free(&k->client_state);
    if (k->error) { std::free(k->error); k->error = nullptr; }
}
CRYPTO_API void cryptolib_opaque_ke2_free(CryptoOpaqueKe2* k) {
    if (!k) return;
    cryptolib_buffer_free(&k->ke2);
    cryptolib_buffer_free(&k->server_state);
    if (k->error) { std::free(k->error); k->error = nullptr; }
}
CRYPTO_API void cryptolib_opaque_ke3_free(CryptoOpaqueKe3* k) {
    if (!k) return;
    cryptolib_buffer_free(&k->ke3);
    cryptolib_buffer_free(&k->session_key);
    cryptolib_buffer_free(&k->export_key);
    if (k->error) { std::free(k->error); k->error = nullptr; }
}

CRYPTO_API CryptoOprfBlind cryptolib_opaque_registration_request(
    const uint8_t* password, size_t password_len) try {
    CryptoOprfBlind out{};
    auto r = crypto::Opaque::create_registration_request(sp(password, password_len));
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.blind = to_cbuf(r.value().blind);
    out.blinded_element = to_cbuf(r.value().blinded_element);
    return out;
} catch (...) { CryptoOprfBlind o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoBufferResult cryptolib_opaque_registration_response(
    const uint8_t* request, size_t request_len, const uint8_t* server_public_key, size_t spk_len,
    const uint8_t* credential_identifier, size_t ci_len, const uint8_t* oprf_seed, size_t seed_len) try {
    auto r = crypto::Opaque::create_registration_response(sp(request, request_len),
        sp(server_public_key, spk_len), sp(credential_identifier, ci_len), sp(oprf_seed, seed_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoOpaqueRecord cryptolib_opaque_finalize_request(
    const uint8_t* password, size_t password_len, const uint8_t* blind, size_t blind_len,
    const uint8_t* response, size_t response_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len) try {
    CryptoOpaqueRecord out{};
    auto r = crypto::Opaque::finalize_registration_request(sp(password, password_len), sp(blind, blind_len),
        sp(response, response_len), sp(server_identity, sid_len), sp(client_identity, cid_len));
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.record = to_cbuf(r.value().record);
    out.export_key = to_cbuf(r.value().export_key);
    return out;
} catch (...) { CryptoOpaqueRecord o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoOpaqueKe1 cryptolib_opaque_client_init(const uint8_t* password, size_t password_len) try {
    CryptoOpaqueKe1 out{};
    auto r = crypto::Opaque::client_generate_ke1(sp(password, password_len));
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.ke1 = to_cbuf(r.value().ke1);
    out.client_state = to_cbuf(r.value().client_state);
    return out;
} catch (...) { CryptoOpaqueKe1 o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoOpaqueKe2 cryptolib_opaque_server_respond(
    const uint8_t* context, size_t context_len,
    const uint8_t* server_private_key, size_t sk_len, const uint8_t* server_public_key, size_t pk_len,
    const uint8_t* record, size_t record_len, const uint8_t* credential_identifier, size_t ci_len,
    const uint8_t* oprf_seed, size_t seed_len, const uint8_t* ke1, size_t ke1_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len) try {
    CryptoOpaqueKe2 out{};
    auto r = crypto::Opaque::server_generate_ke2(sp(context, context_len), sp(server_private_key, sk_len),
        sp(server_public_key, pk_len), sp(record, record_len), sp(credential_identifier, ci_len),
        sp(oprf_seed, seed_len), sp(ke1, ke1_len), sp(server_identity, sid_len), sp(client_identity, cid_len));
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.ke2 = to_cbuf(r.value().ke2);
    out.server_state = to_cbuf(r.value().server_state);
    return out;
} catch (...) { CryptoOpaqueKe2 o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoOpaqueKe3 cryptolib_opaque_client_finish(
    const uint8_t* client_state, size_t cs_len, const uint8_t* ke2, size_t ke2_len,
    const uint8_t* context, size_t context_len,
    const uint8_t* server_identity, size_t sid_len, const uint8_t* client_identity, size_t cid_len) try {
    CryptoOpaqueKe3 out{};
    auto r = crypto::Opaque::client_generate_ke3(sp(client_state, cs_len), sp(ke2, ke2_len),
        sp(context, context_len), sp(server_identity, sid_len), sp(client_identity, cid_len));
    if (r.is_err()) { out.error = dup_str(r.error().message); return out; }
    out.ke3 = to_cbuf(r.value().ke3);
    out.session_key = to_cbuf(r.value().session_key);
    out.export_key = to_cbuf(r.value().export_key);
    return out;
} catch (...) { CryptoOpaqueKe3 o{}; o.error = dup_err_cstr("internal error"); return o; }

CRYPTO_API CryptoBufferResult cryptolib_opaque_server_finish(
    const uint8_t* server_state, size_t ss_len, const uint8_t* ke3, size_t ke3_len) try {
    auto r = crypto::Opaque::server_finish(sp(server_state, ss_len), sp(ke3, ke3_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * EVM / Bitcoin interop — Keccak-256, RIPEMD-160, secp256k1 ECDSA
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoBufferResult cryptolib_keccak256(const uint8_t* msg, size_t msg_len) try {
    auto r = crypto::hash::Keccak256::digest(sp(msg, msg_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_ripemd160(const uint8_t* msg, size_t msg_len) try {
    auto r = crypto::hash::Ripemd160::digest(sp(msg, msg_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoKeyPair cryptolib_secp256k1_keygen(void) try {
#ifdef CRYPTOLIB_HAS_SECP256K1
    auto kp = crypto::ec::Secp256k1::generate_keypair();
    return { to_cbuf(kp.public_key), to_cbuf(kp.secret_key) };
#else
    return CryptoKeyPair{};
#endif
} CL_FAIL_KP

CRYPTO_API CryptoBufferResult cryptolib_secp256k1_pubkey(
    const uint8_t* secret_key, size_t sk_len, int compressed) try {
#ifdef CRYPTOLIB_HAS_SECP256K1
    auto r = crypto::ec::Secp256k1::public_key(sp(secret_key, sk_len), compressed != 0);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)secret_key; (void)sk_len; (void)compressed;
    return err_buf("secp256k1 not enabled in this build");
#endif
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_secp256k1_sign(
    const uint8_t* digest32, const uint8_t* secret_key, size_t sk_len) try {
#ifdef CRYPTOLIB_HAS_SECP256K1
    auto r = crypto::ec::Secp256k1::sign(sp(digest32, 32), sp(secret_key, sk_len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)digest32; (void)secret_key; (void)sk_len;
    return err_buf("secp256k1 not enabled in this build");
#endif
} CL_FAIL_BUFRES

CRYPTO_API int cryptolib_secp256k1_verify(
    const uint8_t* digest32,
    const uint8_t* sig, size_t sig_len,
    const uint8_t* public_key, size_t pk_len) try {
#ifdef CRYPTOLIB_HAS_SECP256K1
    return crypto::ec::Secp256k1::verify(sp(digest32, 32), sp(sig, sig_len),
                                         sp(public_key, pk_len)) ? 1 : 0;
#else
    (void)digest32; (void)sig; (void)sig_len; (void)public_key; (void)pk_len;
    return 0;
#endif
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_secp256k1_recover(
    const uint8_t* digest32, const uint8_t* sig65) try {
#ifdef CRYPTOLIB_HAS_SECP256K1
    auto r = crypto::ec::Secp256k1::recover(sp(digest32, 32), sp(sig65, 65));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
#else
    (void)digest32; (void)sig65;
    return err_buf("secp256k1 not enabled in this build");
#endif
} CL_FAIL_BUFRES

/* ═══════════════════════════════════════════════════════════════════════════
 * Steganography
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoResult cryptolib_stego_embed(
    const char* cover_path,
    const uint8_t* payload, size_t payload_len,
    const char* output_path) try
{
    auto r = crypto::stego::StegoEngine::embed(cover_path, sp(payload, payload_len), output_path);
    if (r.is_err()) return { 0, dup_str(r.error().message) };
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API CryptoBufferResult cryptolib_stego_extract(const char* stego_path) try {
    auto r = crypto::stego::StegoEngine::extract(stego_path);
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

CRYPTO_API size_t cryptolib_stego_capacity(const char* cover_path) try {
    auto r = crypto::stego::StegoEngine::capacity(cover_path);
    if (r.is_err()) return 0;
    return r.value().max_payload_bytes;
} CL_FAIL_SIZE

// ── Keyed steganography ──────────────────────────────────────────────────────
CRYPTO_API CryptoResult cryptolib_stego_embed_keyed(
    const char* cover_path,
    const uint8_t* payload, size_t payload_len,
    const char* output_path,
    const uint8_t* key, size_t key_len) try
{
    crypto::stego::StegoParams p;
    if (key && key_len) p.key.assign(key, key + key_len);
    auto r = crypto::stego::StegoEngine::embed(cover_path, sp(payload, payload_len), output_path, p);
    if (r.is_err()) return { 0, dup_str(r.error().message) };
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API CryptoBufferResult cryptolib_stego_extract_keyed(
    const char* stego_path,
    const uint8_t* key, size_t key_len) try
{
    crypto::stego::StegoParams p;
    if (key && key_len) p.key.assign(key, key + key_len);
    auto r = crypto::stego::StegoEngine::extract(stego_path, p);
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── Always-encrypt stego (AEAD-then-hide) ────────────────────────────────────
CRYPTO_API CryptoResult cryptolib_stego_embed_encrypted(
    const char* cover_path,
    const uint8_t* plaintext, size_t pt_len,
    const char* output_path,
    const uint8_t* master_key, size_t key_len) try
{
    auto r = crypto::stego::StegoEngine::embed_encrypted(
        cover_path, sp(plaintext, pt_len), output_path, sp(master_key, key_len));
    if (r.is_err()) return { 0, dup_str(r.error().message) };
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API CryptoBufferResult cryptolib_stego_extract_decrypt(
    const char* stego_path,
    const uint8_t* master_key, size_t key_len) try
{
    auto r = crypto::stego::StegoEngine::extract_decrypt(stego_path, sp(master_key, key_len));
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── PhysicalSeal — two-factor media-entropy seal ─────────────────────────────
CRYPTO_API CryptoResult cryptolib_physical_seal(
    const char* key_media_path,
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* aad, size_t aad_len,
    const char* cover_path,
    const char* output_path) try
{
    auto r = crypto::PhysicalSeal::seal(
        key_media_path, sp(plaintext, pt_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{},
        cover_path, output_path);
    if (r.is_err()) return { 0, dup_str(r.error().message) };
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API CryptoBufferResult cryptolib_physical_open(
    const char* key_media_path,
    const uint8_t* aad, size_t aad_len,
    const char* stego_path) try
{
    auto r = crypto::PhysicalSeal::open(
        key_media_path,
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{},
        stego_path);
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── Forward error correction ─────────────────────────────────────────────────
CRYPTO_API CryptoBufferResult cryptolib_fec_encode(
    const uint8_t* data, size_t len, int scheme) try
{
    if (scheme < 0 || scheme > 3) return err_buf("FEC: invalid scheme (0-3)");
    auto enc = crypto::stego::fec::encode(
        sp(data, len), static_cast<crypto::stego::fec::Scheme>(scheme));
    return { to_cbuf(std::span<const uint8_t>(enc)), nullptr };
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_fec_decode(
    const uint8_t* data, size_t len, int scheme, size_t original_len) try
{
    if (scheme < 0 || scheme > 3) return err_buf("FEC: invalid scheme (0-3)");
    auto r = crypto::stego::fec::decode(
        sp(data, len), static_cast<crypto::stego::fec::Scheme>(scheme), original_len);
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── Carrier analysis ─────────────────────────────────────────────────────────
CRYPTO_API CryptoFileInspection cryptolib_stego_inspect(const char* path) try {
    auto r = crypto::stego::StegoAnalyzer::inspect(path ? path : "");
    if (r.is_err())
        return CryptoFileInspection{ 0, 0xFF, 0, 0, 0, 0, nullptr, dup_str(r.error().message) };
    const auto& v = r.value();
    return CryptoFileInspection{
        v.parses ? 1 : 0,
        static_cast<uint8_t>(v.format),
        v.ext_matches ? 1 : 0,
        static_cast<uint64_t>(v.width),
        static_cast<uint64_t>(v.height),
        static_cast<uint64_t>(v.file_size),
        dup_str(v.detail),
        nullptr };
} catch (...) {
    return CryptoFileInspection{ 0, 0xFF, 0, 0, 0, 0, nullptr, dup_err_cstr("internal error") };
}

CRYPTO_API CryptoBufferResult cryptolib_stego_content_digest(const char* path) try {
    auto r = crypto::stego::StegoAnalyzer::content_digest(path ? path : "");
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value().data(), r.value().size())), nullptr };
} CL_FAIL_BUFRES

CRYPTO_API CryptoHiddenDataReport cryptolib_stego_detect_hidden(const char* path) try {
    auto r = crypto::stego::StegoAnalyzer::detect_hidden(path ? path : "");
    if (r.is_err())
        return CryptoHiddenDataReport{ 0, 0.0, 0.0, 0, nullptr, dup_str(r.error().message) };
    const auto& v = r.value();
    return CryptoHiddenDataReport{
        v.cryptolib_payload ? 1 : 0,
        v.lsb_chi_square,
        v.lsb_embedding_likelihood,
        static_cast<uint64_t>(v.samples_analysed),
        dup_str(v.note),
        nullptr };
} catch (...) {
    return CryptoHiddenDataReport{ 0, 0.0, 0.0, 0, nullptr, dup_err_cstr("internal error") };
}

CRYPTO_API CryptoHealthReport cryptolib_entropy_assess_file_health(
    const char* path, size_t max_bytes) try
{
    auto r = crypto::entropy::MediaEntropy::assess_file_health(
        path ? path : "", max_bytes ? max_bytes : (1u << 20));
    if (r.is_err())
        return CryptoHealthReport{ 0.0, 0, 0, 0, 0, dup_str(r.error().message) };
    const auto& v = r.value();
    return CryptoHealthReport{
        v.min_entropy_per_byte,
        static_cast<uint64_t>(v.longest_run),
        static_cast<uint64_t>(v.max_window_count),
        v.rct_passed ? 1 : 0,
        v.apt_passed ? 1 : 0,
        nullptr };
} catch (...) {
    return CryptoHealthReport{ 0.0, 0, 0, 0, 0, dup_err_cstr("internal error") };
}

// ── ImageFactorSeal (C2) ─────────────────────────────────────────────────────
CRYPTO_API CryptoResult cryptolib_image_factor_seal(
    const uint8_t* oprf_seed, size_t seed_len, const char* ref_img,
    const uint8_t* pt, size_t pt_len, const uint8_t* aad, size_t aad_len,
    const char* cover, const char* out) try
{
    auto r = crypto::ImageFactorSeal::seal(
        sp(oprf_seed, seed_len), ref_img ? ref_img : "",
        sp(pt, pt_len), aad ? sp(aad, aad_len) : std::span<const uint8_t>{},
        cover ? cover : "", out ? out : "");
    if (r.is_err()) return { 0, dup_str(r.error().message) };
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API CryptoBufferResult cryptolib_image_factor_open(
    const uint8_t* oprf_seed, size_t seed_len, const char* ref_img,
    const uint8_t* aad, size_t aad_len, const char* stego) try
{
    auto r = crypto::ImageFactorSeal::open(
        sp(oprf_seed, seed_len), ref_img ? ref_img : "",
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{}, stego ? stego : "");
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── HpkeStegoSeal (C3) ───────────────────────────────────────────────────────
CRYPTO_API CryptoBufferResult cryptolib_hpke_stego_seal(
    const uint8_t* pkR, size_t pkR_len, const uint8_t* pt, size_t pt_len,
    const uint8_t* aad, size_t aad_len, const uint8_t* info, size_t info_len,
    const char* cover, const char* out) try
{
    auto r = crypto::HpkeStegoSeal::seal(
        sp(pkR, pkR_len), sp(pt, pt_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{},
        info ? sp(info, info_len) : std::span<const uint8_t>{},
        cover ? cover : "", out ? out : "");
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());   // the public KEM encapsulation `enc`
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_hpke_stego_open(
    const uint8_t* skR, size_t skR_len, const uint8_t* enc, size_t enc_len,
    const uint8_t* aad, size_t aad_len, const uint8_t* info, size_t info_len,
    const char* stego) try
{
    auto r = crypto::HpkeStegoSeal::open(
        sp(skR, skR_len), sp(enc, enc_len),
        aad ? sp(aad, aad_len) : std::span<const uint8_t>{},
        info ? sp(info, info_len) : std::span<const uint8_t>{},
        stego ? stego : "");
    if (r.is_err()) return err_buf(r.error().message);
    return { to_cbuf(std::span<const uint8_t>(r.value())), nullptr };
} CL_FAIL_BUFRES

// ── HMAC-DRBG handle (A3) ────────────────────────────────────────────────────
CRYPTO_API CryptoDrbgHandle cryptolib_drbg_instantiate(
    const uint8_t* entropy, size_t entropy_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* perso, size_t perso_len, char** out_error) try
{
    auto r = crypto::entropy::HmacDrbg::instantiate(
        sp(entropy, entropy_len),
        nonce ? sp(nonce, nonce_len) : std::span<const uint8_t>{},
        perso ? sp(perso, perso_len) : std::span<const uint8_t>{});
    if (r.is_err()) { if (out_error) *out_error = dup_str(r.error().message); return nullptr; }
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoDrbgHandle>(new DrbgImpl{ std::move(r.value()) });
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoBufferResult cryptolib_drbg_generate(
    CryptoDrbgHandle h, size_t num_bytes, const uint8_t* additional, size_t additional_len) try
{
    if (!h) return err_buf("DRBG: null handle");
    auto r = static_cast<DrbgImpl*>(h)->d.generate(
        num_bytes, additional ? sp(additional, additional_len) : std::span<const uint8_t>{});
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoResult cryptolib_drbg_reseed(
    CryptoDrbgHandle h, const uint8_t* entropy, size_t entropy_len,
    const uint8_t* additional, size_t additional_len) try
{
    if (!h) return { 0, dup_str("DRBG: null handle") };
    static_cast<DrbgImpl*>(h)->d.reseed(
        sp(entropy, entropy_len),
        additional ? sp(additional, additional_len) : std::span<const uint8_t>{});
    return { 1, nullptr };
} CL_FAIL_RESULT

CRYPTO_API void cryptolib_drbg_free(CryptoDrbgHandle h) {
    delete static_cast<DrbgImpl*>(h);
}

// ── Fortuna pool handle (A5) ─────────────────────────────────────────────────
CRYPTO_API CryptoFortunaHandle cryptolib_fortuna_new(void) try {
    return static_cast<CryptoFortunaHandle>(new FortunaImpl{});
} CL_FAIL_PTR

CRYPTO_API void cryptolib_fortuna_add_entropy(
    CryptoFortunaHandle h, uint8_t source_id, const uint8_t* data, size_t len) {
    if (!h) return;
    static_cast<FortunaImpl*>(h)->p.add_entropy(source_id, sp(data, len));
}

CRYPTO_API CryptoBufferResult cryptolib_fortuna_generate(
    CryptoFortunaHandle h, size_t num_bytes) try
{
    if (!h) return err_buf("Fortuna: null handle");
    auto r = static_cast<FortunaImpl*>(h)->p.generate(num_bytes);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_fortuna_reseed(CryptoFortunaHandle h) {
    if (h) static_cast<FortunaImpl*>(h)->p.reseed_now();
}

CRYPTO_API uint64_t cryptolib_fortuna_reseed_count(CryptoFortunaHandle h) {
    return h ? static_cast<FortunaImpl*>(h)->p.reseed_count() : 0;
}

CRYPTO_API void cryptolib_fortuna_free(CryptoFortunaHandle h) {
    delete static_cast<FortunaImpl*>(h);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Keyring — envelope encryption with key-slots
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API CryptoKeyringHandle cryptolib_keyring_create(void) try {
    return static_cast<CryptoKeyringHandle>(new KeyringImpl{crypto::Keyring::create()});
} CL_FAIL_PTR

CRYPTO_API int cryptolib_keyring_add_device_slot(
    CryptoKeyringHandle kr, const uint8_t* factor_key, size_t len) try {
    if (!kr) return 0;
    return static_cast<KeyringImpl*>(kr)->kr.add_device_slot(sp(factor_key, len)).is_ok() ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API int cryptolib_keyring_add_passphrase_slot(
    CryptoKeyringHandle kr, const char* passphrase, int kdf_preset) try {
    if (!kr || !passphrase) return 0;
    auto params = kdf_preset == 1 ? crypto::KdfParams::sensitive()
                                  : crypto::KdfParams::interactive();
    return static_cast<KeyringImpl*>(kr)->kr.add_passphrase_slot(passphrase, params).is_ok() ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API size_t cryptolib_keyring_slot_count(CryptoKeyringHandle kr) try {
    if (!kr) return 0;
    return static_cast<KeyringImpl*>(kr)->kr.slot_count();
} CL_FAIL_SIZE

CRYPTO_API int cryptolib_keyring_remove_slot(CryptoKeyringHandle kr, size_t index) try {
    if (!kr) return 0;
    return static_cast<KeyringImpl*>(kr)->kr.remove_slot(index).is_ok() ? 1 : 0;
} CL_FAIL_INT

CRYPTO_API CryptoBufferResult cryptolib_keyring_serialise(CryptoKeyringHandle kr) try {
    if (!kr) return err_buf("null keyring");
    return ok_buf(static_cast<KeyringImpl*>(kr)->kr.serialise());
} CL_FAIL_BUFRES

CRYPTO_API CryptoKeyringHandle cryptolib_keyring_deserialise(
    const uint8_t* blob, size_t len, char** out_error) try {
    auto r = crypto::Keyring::deserialise(sp(blob, len));
    if (r.is_err()) {
        if (out_error) *out_error = dup_str(r.error().message);
        return nullptr;
    }
    if (out_error) *out_error = nullptr;
    return static_cast<CryptoKeyringHandle>(new KeyringImpl{std::move(r.value())});
} catch (...) { if (out_error) *out_error = dup_err_cstr("internal error"); return nullptr; }

CRYPTO_API CryptoBufferResult cryptolib_keyring_unlock_with_device(
    CryptoKeyringHandle kr, const uint8_t* factor_key, size_t len) try {
    if (!kr) return err_buf("null keyring");
    auto r = static_cast<KeyringImpl*>(kr)->kr.unlock_with_device(sp(factor_key, len));
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API CryptoBufferResult cryptolib_keyring_unlock_with_passphrase(
    CryptoKeyringHandle kr, const char* passphrase) try {
    if (!kr || !passphrase) return err_buf("null keyring/passphrase");
    auto r = static_cast<KeyringImpl*>(kr)->kr.unlock_with_passphrase(passphrase);
    if (r.is_err()) return err_buf(r.error().message);
    return ok_buf(r.value());
} CL_FAIL_BUFRES

CRYPTO_API void cryptolib_keyring_free(CryptoKeyringHandle kr) {
    delete static_cast<KeyringImpl*>(kr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Version
 * ═══════════════════════════════════════════════════════════════════════════ */

CRYPTO_API const char* cryptolib_version(void) {
    return "3.0.0";
}

} // extern "C"
