/**
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
