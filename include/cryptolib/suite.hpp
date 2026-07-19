#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Suite — the "advanced combinations", one call each.
//
// CryptoLib's primitives compose into a handful of flows that real systems
// actually want. Suite bakes those compositions into a single call so callers
// never have to wire a KEM to a KDF to a cascade by hand (and never get the
// order wrong). It invents no cryptography: every flow is a documented
// composition of already-vetted parts.
//
//   seal_pq / open_pq                 hybrid X25519+ML-KEM-768 → MolecularVault
//   seal_signed_pq / open_signed_pq   ★ + Ed25519+ML-DSA-65 authenticity
//   seal_with_file / open_with_file   deterministic media entropy is the key
//   seal_with_keyring_* / open_*      Keyring slot unlock → MolecularVault
//   seal_threshold / open_threshold   MolecularVault key split k-of-n (Shamir)
//   evm_address                       secp256k1 pubkey → 20-byte EVM address
//
// Every seal is authenticated and fails closed. The PQ envelopes are versioned
// and self-describing (they carry the KEM ciphertext), so a recipient needs only
// their long-term secret key — never any out-of-band state.
//
// Wire formats (little-endian lengths):
//   PQ         "CSPQ" | ver(1) | suite(1) | kem_ct_len(4) | kem_ct | MVLT-envelope
//   signed PQ  "CSSP" | ver(1) | suite(1) | kem_ct_len(4) | kem_ct | MVLT-envelope
// The suite byte names the algorithm set, so a parameter-set migration is a new
// id decided at open time (never a silent reinterpretation); unknown ids reject.
//                 where the sealed plaintext = sig_len(4) | signature | plaintext
//   file / keyring / threshold  →  a bare MVLT envelope (MolecularVault frames it)
//
// Requires OpenSSL (AES-256-GCM-SIV, via MolecularVault) and liboqs (PQC).
// ─────────────────────────────────────────────────────────────────────────────
#include "types.hpp"
#include "molecular_vault.hpp"
#include "hybrid_kem.hpp"
#include "hybrid_sig.hpp"
#include "media_entropy.hpp"
#include "keyring.hpp"
#include "shamir.hpp"
#include "keccak.hpp"

#include <array>
#include <cstring>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>
#include <sodium.h>

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)

namespace crypto {

class Suite {
public:
    static constexpr uint8_t VERSION = 2;
    static constexpr std::array<uint8_t, 4> MAGIC_PQ  = {'C', 'S', 'P', 'Q'};
    static constexpr std::array<uint8_t, 4> MAGIC_SPQ = {'C', 'S', 'S', 'P'};
    // Algorithm-suite identifiers, bound into the envelope header. Migrating a
    // parameter set (e.g. ML-KEM-768 → 1024) becomes a NEW id dispatched at open
    // time, never a silent reinterpretation of the same bytes; unknown or
    // mismatched ids fail closed. Keep values stable once shipped.
    static constexpr uint8_t SUITE_HYBRID_KEM     = 0x01; // X25519 + ML-KEM-768
    static constexpr uint8_t SUITE_HYBRID_KEM_SIG = 0x02; // + Ed25519 + ML-DSA-65
    static constexpr std::size_t MASTER_BYTES = 32;
    static constexpr std::size_t EVM_ADDRESS_BYTES = 20;

    // ── 1. Post-quantum message ─────────────────────────────────────────────
    // Encapsulate to the recipient's hybrid KEM public key, then seal under the
    // resulting shared secret. Secure while EITHER X25519 or ML-KEM holds.
    [[nodiscard]] static Result<SecureBuffer>
    seal_pq(std::span<const uint8_t> plaintext,
            std::span<const uint8_t> recipient_kem_public,
            std::span<const uint8_t> aad = {}) {
        auto enc = pq::HybridKem::encapsulate(recipient_kem_public);
        if (enc.is_err()) return Result<SecureBuffer>::err(enc.error().message);
        auto env = MolecularVault::seal_with_key(plaintext, enc.value().shared_secret.span(), aad);
        if (env.is_err()) return env;
        return frame(MAGIC_PQ, SUITE_HYBRID_KEM, enc.value().ciphertext.span(), env.value().span());
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_pq(std::span<const uint8_t> envelope,
            std::span<const uint8_t> recipient_kem_secret,
            std::span<const uint8_t> aad = {}) {
        std::span<const uint8_t> kem_ct, inner;
        if (auto e = unframe(MAGIC_PQ, SUITE_HYBRID_KEM, envelope, kem_ct, inner); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);
        auto ss = pq::HybridKem::decapsulate(kem_ct, recipient_kem_secret);
        if (ss.is_err()) return Result<SecureBuffer>::err(ss.error().message);
        return MolecularVault::open_with_key(inner, ss.value().span(), aad);
    }

    // ── 2. Signed + post-quantum sealed  (the flagship) ─────────────────────
    // Confidentiality from the hybrid KEM, authenticity from the hybrid
    // signature — both classical AND post-quantum on each axis. open_* returns
    // the plaintext ONLY if the signature verifies against `signer_sig_public`.
    [[nodiscard]] static Result<SecureBuffer>
    seal_signed_pq(std::span<const uint8_t> plaintext,
                   std::span<const uint8_t> recipient_kem_public,
                   std::span<const uint8_t> signer_sig_secret,
                   std::span<const uint8_t> aad = {}) {
        auto sig = pq::HybridSig::sign(plaintext, signer_sig_secret);
        if (sig.is_err()) return Result<SecureBuffer>::err(sig.error().message);

        // inner = sig_len | signature | plaintext
        std::vector<uint8_t> inner;
        inner.reserve(4 + sig.value().size() + plaintext.size());
        put_u32_le(inner, static_cast<uint32_t>(sig.value().size()));
        inner.insert(inner.end(), sig.value().span().begin(), sig.value().span().end());
        inner.insert(inner.end(), plaintext.begin(), plaintext.end());

        auto enc = pq::HybridKem::encapsulate(recipient_kem_public);
        if (enc.is_err()) return Result<SecureBuffer>::err(enc.error().message);
        auto env = MolecularVault::seal_with_key(inner, enc.value().shared_secret.span(), aad);
        sodium_memzero(inner.data(), inner.size());
        if (env.is_err()) return env;
        return frame(MAGIC_SPQ, SUITE_HYBRID_KEM_SIG, enc.value().ciphertext.span(), env.value().span());
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_signed_pq(std::span<const uint8_t> envelope,
                   std::span<const uint8_t> recipient_kem_secret,
                   std::span<const uint8_t> signer_sig_public,
                   std::span<const uint8_t> aad = {}) {
        std::span<const uint8_t> kem_ct, inner_env;
        if (auto e = unframe(MAGIC_SPQ, SUITE_HYBRID_KEM_SIG, envelope, kem_ct, inner_env); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);
        auto ss = pq::HybridKem::decapsulate(kem_ct, recipient_kem_secret);
        if (ss.is_err()) return Result<SecureBuffer>::err(ss.error().message);
        auto inner = MolecularVault::open_with_key(inner_env, ss.value().span(), aad);
        if (inner.is_err()) return inner;

        auto s = inner.value().span();
        if (s.size() < 4) return Result<SecureBuffer>::err("Suite: signed envelope truncated");
        const uint32_t sig_len = get_u32_le(s.data());
        if (s.size() < 4u + sig_len)
            return Result<SecureBuffer>::err("Suite: signed envelope truncated");
        auto sig = s.subspan(4, sig_len);
        auto pt  = s.subspan(4 + sig_len);

        // AUTH-FIRST: reject before handing back any plaintext.
        if (pq::HybridSig::verify(pt, sig, signer_sig_public).is_err())
            return Result<SecureBuffer>::err("Suite: signature verification failed");
        return Result<SecureBuffer>::ok(SecureBuffer(pt.data(), pt.size()));
    }

    // ── 3. File-as-key ──────────────────────────────────────────────────────
    // The file IS the key: deterministic media entropy re-derives the same
    // master on any machine, so nothing secret is ever stored.
    [[nodiscard]] static Result<SecureBuffer>
    seal_with_file(std::span<const uint8_t> plaintext,
                   const std::filesystem::path& key_file,
                   std::span<const uint8_t> aad = {}) {
        auto m = master_from_file(key_file);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::seal_with_key(plaintext, m.value().span(), aad);
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_with_file(std::span<const uint8_t> envelope,
                   const std::filesystem::path& key_file,
                   std::span<const uint8_t> aad = {}) {
        auto m = master_from_file(key_file);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::open_with_key(envelope, m.value().span(), aad);
    }

    // ── 4. Keyring-guarded ──────────────────────────────────────────────────
    // The master key is never at rest in plaintext: a Keyring wraps it under a
    // device factor and/or a passphrase. Either slot unlocks the same master.
    [[nodiscard]] static Result<SecureBuffer>
    seal_with_keyring_device(std::span<const uint8_t> plaintext, Keyring& kr,
                             std::span<const uint8_t> factor_key,
                             std::span<const uint8_t> aad = {}) {
        auto m = kr.unlock_with_device(factor_key);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::seal_with_key(plaintext, m.value().span(), aad);
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_with_keyring_device(std::span<const uint8_t> envelope, Keyring& kr,
                             std::span<const uint8_t> factor_key,
                             std::span<const uint8_t> aad = {}) {
        auto m = kr.unlock_with_device(factor_key);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::open_with_key(envelope, m.value().span(), aad);
    }

    [[nodiscard]] static Result<SecureBuffer>
    seal_with_keyring_passphrase(std::span<const uint8_t> plaintext, Keyring& kr,
                                 std::string_view passphrase,
                                 std::span<const uint8_t> aad = {}) {
        auto m = kr.unlock_with_passphrase(passphrase);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::seal_with_key(plaintext, m.value().span(), aad);
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_with_keyring_passphrase(std::span<const uint8_t> envelope, Keyring& kr,
                                 std::string_view passphrase,
                                 std::span<const uint8_t> aad = {}) {
        auto m = kr.unlock_with_passphrase(passphrase);
        if (m.is_err()) return Result<SecureBuffer>::err(m.error().message);
        return MolecularVault::open_with_key(envelope, m.value().span(), aad);
    }

    // ── 5. Threshold (k-of-n) ───────────────────────────────────────────────
    // Seal under a fresh random master, then split that master into n Shamir
    // shares of which any k reconstruct it. No single custodian can open — or
    // block — the secret. Distribute the shares; keep the envelope anywhere.
    struct ThresholdSealed {
        SecureBuffer envelope;
        std::vector<Shamir::Share> shares;
    };

    [[nodiscard]] static Result<ThresholdSealed>
    seal_threshold(std::span<const uint8_t> plaintext, uint8_t n, uint8_t k,
                   std::span<const uint8_t> aad = {}) {
        // NOTE: crypto::random_bytes lives in the umbrella header, which this
        // one cannot include (circular); use libsodium's CSPRNG directly.
        SecureBuffer master(MASTER_BYTES);
        randombytes_buf(master.data(), MASTER_BYTES);
        auto env = MolecularVault::seal_with_key(plaintext, master.span(), aad);
        if (env.is_err()) return Result<ThresholdSealed>::err(env.error().message);
        auto shares = Shamir::split(master.span(), n, k);
        if (shares.is_err()) return Result<ThresholdSealed>::err(shares.error().message);
        return Result<ThresholdSealed>::ok(
            ThresholdSealed{std::move(env.value()), std::move(shares.value())});
    }

    [[nodiscard]] static Result<SecureBuffer>
    open_threshold(std::span<const uint8_t> envelope,
                   std::span<const Shamir::Share> shares,
                   std::span<const uint8_t> aad = {}) {
        auto master = Shamir::combine(shares);
        if (master.is_err()) return Result<SecureBuffer>::err(master.error().message);
        return MolecularVault::open_with_key(envelope, master.value().span(), aad);
    }

    // ── 6. EVM address ──────────────────────────────────────────────────────
    // address = last 20 bytes of Keccak-256(uncompressed pubkey without 0x04).
    [[nodiscard]] static Result<SecureBuffer>
    evm_address(std::span<const uint8_t> secp256k1_public_key) {
        if (secp256k1_public_key.size() != 65 || secp256k1_public_key[0] != 0x04)
            return Result<SecureBuffer>::err("Suite: expected a 65-byte uncompressed secp256k1 public key");
        auto h = hash::Keccak256::digest(secp256k1_public_key.subspan(1));
        if (h.is_err()) return Result<SecureBuffer>::err(h.error().message);
        auto tail = h.value().span().subspan(12, EVM_ADDRESS_BYTES);
        return Result<SecureBuffer>::ok(SecureBuffer(tail.data(), tail.size()));
    }

private:
    static void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
    static uint32_t get_u32_le(const uint8_t* p) {
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= static_cast<uint32_t>(p[i]) << (8 * i);
        return x;
    }

    [[nodiscard]] static Result<SecureBuffer>
    master_from_file(const std::filesystem::path& p) {
        auto e = entropy::MediaEntropy::from_file_deterministic(p);
        if (e.is_err()) return Result<SecureBuffer>::err(e.error().message);
        return Result<SecureBuffer>::ok(std::move(e.value().derive_all().vault_master_key));
    }

    // magic | ver | suite | kem_ct_len(4) | kem_ct | inner
    [[nodiscard]] static Result<SecureBuffer>
    frame(const std::array<uint8_t, 4>& magic, uint8_t suite_id,
          std::span<const uint8_t> kem_ct, std::span<const uint8_t> inner) {
        std::vector<uint8_t> out;
        out.reserve(4 + 1 + 1 + 4 + kem_ct.size() + inner.size());
        out.insert(out.end(), magic.begin(), magic.end());
        out.push_back(VERSION);
        out.push_back(suite_id);
        put_u32_le(out, static_cast<uint32_t>(kem_ct.size()));
        out.insert(out.end(), kem_ct.begin(), kem_ct.end());
        out.insert(out.end(), inner.begin(), inner.end());
        return Result<SecureBuffer>::ok(SecureBuffer(std::move(out)));
    }

    [[nodiscard]] static Result<void>
    unframe(const std::array<uint8_t, 4>& magic, uint8_t expected_suite,
            std::span<const uint8_t> env,
            std::span<const uint8_t>& kem_ct, std::span<const uint8_t>& inner) {
        constexpr std::size_t HDR = 4 + 1 + 1 + 4;
        if (env.size() < HDR) return Result<void>::err("Suite: envelope too short");
        if (std::memcmp(env.data(), magic.data(), magic.size()) != 0)
            return Result<void>::err("Suite: bad magic (wrong envelope type)");
        if (env[4] != VERSION) return Result<void>::err("Suite: unsupported version");
        if (env[5] != expected_suite)
            return Result<void>::err("Suite: unknown or mismatched algorithm suite");
        const uint32_t ct_len = get_u32_le(env.data() + 6);
        if (env.size() < HDR + ct_len) return Result<void>::err("Suite: envelope truncated");
        kem_ct = env.subspan(HDR, ct_len);
        inner  = env.subspan(HDR + ct_len);
        return Result<void>::ok();
    }
};

} // namespace crypto

#endif // CRYPTOLIB_HAS_OPENSSL && CRYPTOLIB_HAS_PQ
