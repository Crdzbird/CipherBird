// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 ECDSA — EVM + Bitcoin signing.
//
// Thin wrapper over libsecp256k1 (bitcoin-core): audited, constant-time, with
// RFC6979 deterministic nonces and guaranteed low-S output. We never hand-roll
// the secret-dependent EC math — this file only marshals buffers.
//
// Signs a 32-byte message DIGEST (callers hash first):
//   • Ethereum: keccak256(rlp(tx))     • Bitcoin: sha256(sha256(preimage))
//
// Signatures are low-S normalized (EIP-2 / BIP-62) — libsecp256k1's signer
// always emits low-S, and secp256k1_ecdsa_verify rejects high-S, so malleable
// signatures are refused on both ends.
//
// Guarded by CRYPTOLIB_HAS_SECP256K1 (set when libsecp256k1 is linked).
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#ifdef CRYPTOLIB_HAS_SECP256K1

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <span>

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <sodium.h>

#include "types.hpp"

namespace crypto::ec {

struct Secp256k1KeyPair {
    SecureBuffer public_key;  // 65 bytes, uncompressed (0x04 ‖ X ‖ Y)
    SecureBuffer secret_key;  // 32 bytes
};

class Secp256k1 {
public:
    static constexpr std::size_t SECRET_KEY_BYTES   = 32;
    static constexpr std::size_t PUBKEY_UNCOMP_BYTES = 65;
    static constexpr std::size_t PUBKEY_COMP_BYTES   = 33;
    static constexpr std::size_t DIGEST_BYTES        = 32;
    static constexpr std::size_t SIG_RECOVERABLE_BYTES = 65;  // r ‖ s ‖ recid

    /** Random keypair: sk(32) + uncompressed pk(65). */
    [[nodiscard]] static Secp256k1KeyPair generate_keypair() {
        secp256k1_context* c = ctx();
        SecureBuffer sk(SECRET_KEY_BYTES);
        secp256k1_pubkey pk;
        do {
            randombytes_buf(sk.data(), SECRET_KEY_BYTES);
        } while (secp256k1_ec_seckey_verify(c, sk.data()) != 1);
        (void) secp256k1_ec_pubkey_create(c, &pk, sk.data());  // sk verified above → cannot fail
        uint8_t out[PUBKEY_UNCOMP_BYTES];
        std::size_t outlen = PUBKEY_UNCOMP_BYTES;
        secp256k1_ec_pubkey_serialize(c, out, &outlen, &pk, SECP256K1_EC_UNCOMPRESSED);
        return Secp256k1KeyPair{ SecureBuffer(out, outlen), std::move(sk) };
    }

    /** Derive public key from a 32-byte secret. compressed → 33 bytes else 65. */
    [[nodiscard]] static Result<SecureBuffer>
    public_key(std::span<const uint8_t> sk, bool compressed) {
        if (sk.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("secp256k1: secret key must be 32 bytes");
        secp256k1_context* c = ctx();
        if (secp256k1_ec_seckey_verify(c, sk.data()) != 1)
            return Result<SecureBuffer>::err("secp256k1: invalid secret key");
        secp256k1_pubkey pk;
        if (secp256k1_ec_pubkey_create(c, &pk, sk.data()) != 1)
            return Result<SecureBuffer>::err("secp256k1: pubkey derivation failed");
        uint8_t out[PUBKEY_UNCOMP_BYTES];
        std::size_t outlen = compressed ? PUBKEY_COMP_BYTES : PUBKEY_UNCOMP_BYTES;
        secp256k1_ec_pubkey_serialize(c, out, &outlen, &pk,
            compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        return Result<SecureBuffer>::ok(SecureBuffer(out, outlen));
    }

    /** Sign a 32-byte digest. RFC6979 deterministic nonce, low-S.
     *  Returns 65 bytes: r(32) ‖ s(32) ‖ recovery_id(1, 0..3). */
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> digest32, std::span<const uint8_t> sk) {
        if (digest32.size() != DIGEST_BYTES)
            return Result<SecureBuffer>::err("secp256k1: digest must be 32 bytes");
        if (sk.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("secp256k1: secret key must be 32 bytes");
        secp256k1_context* c = ctx();
        if (secp256k1_ec_seckey_verify(c, sk.data()) != 1)
            return Result<SecureBuffer>::err("secp256k1: invalid secret key");
        secp256k1_ecdsa_recoverable_signature rsig;
        if (secp256k1_ecdsa_sign_recoverable(c, &rsig, digest32.data(), sk.data(),
                                             nullptr, nullptr) != 1)
            return Result<SecureBuffer>::err("secp256k1: signing failed");
        uint8_t out64[64];
        int recid = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(c, out64, &recid, &rsig);
        SecureBuffer out(SIG_RECOVERABLE_BYTES);
        std::memcpy(out.data(), out64, 64);
        out.data()[64] = static_cast<uint8_t>(recid);
        return Result<SecureBuffer>::ok(std::move(out));
    }

    /** Verify. sig is 64 bytes (r ‖ s); pk is 33 or 65 bytes. Low-S enforced. */
    [[nodiscard]] static bool
    verify(std::span<const uint8_t> digest32, std::span<const uint8_t> sig,
           std::span<const uint8_t> pubkey) {
        if (digest32.size() != DIGEST_BYTES || sig.size() != 64) return false;
        secp256k1_context* c = ctx();
        secp256k1_pubkey pk;
        if (secp256k1_ec_pubkey_parse(c, &pk, pubkey.data(), pubkey.size()) != 1) return false;
        secp256k1_ecdsa_signature s;
        if (secp256k1_ecdsa_signature_parse_compact(c, &s, sig.data()) != 1) return false;
        // secp256k1_ecdsa_verify accepts ONLY low-S signatures (anti-malleability).
        return secp256k1_ecdsa_verify(c, &s, digest32.data(), &pk) == 1;
    }

    /** Recover the 65-byte uncompressed public key from a 32-byte digest and a
     *  65-byte recoverable signature (r ‖ s ‖ recovery_id). Ethereum ecrecover. */
    [[nodiscard]] static Result<SecureBuffer>
    recover(std::span<const uint8_t> digest32, std::span<const uint8_t> sig65) {
        if (digest32.size() != DIGEST_BYTES)
            return Result<SecureBuffer>::err("secp256k1: digest must be 32 bytes");
        if (sig65.size() != SIG_RECOVERABLE_BYTES)
            return Result<SecureBuffer>::err("secp256k1: recoverable signature must be 65 bytes");
        int recid = sig65[64];
        if (recid < 0 || recid > 3)
            return Result<SecureBuffer>::err("secp256k1: recovery id out of range (0..3)");
        secp256k1_context* c = ctx();
        secp256k1_ecdsa_recoverable_signature rsig;
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(c, &rsig, sig65.data(), recid) != 1)
            return Result<SecureBuffer>::err("secp256k1: recoverable signature parse failed");
        secp256k1_pubkey pk;
        if (secp256k1_ecdsa_recover(c, &pk, &rsig, digest32.data()) != 1)
            return Result<SecureBuffer>::err("secp256k1: public-key recovery failed");
        uint8_t out[PUBKEY_UNCOMP_BYTES];
        std::size_t outlen = PUBKEY_UNCOMP_BYTES;
        secp256k1_ec_pubkey_serialize(c, out, &outlen, &pk, SECP256K1_EC_UNCOMPRESSED);
        return Result<SecureBuffer>::ok(SecureBuffer(out, outlen));
    }

private:
    // Process-lifetime context, randomized once for side-channel hardening.
    // Thread-safe init (C++11 static-local); read-only during sign/verify, so
    // concurrent use after init is safe. Intentionally never destroyed.
    static secp256k1_context* ctx() {
        static secp256k1_context* c = [] {
            secp256k1_context* cc = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
            uint8_t seed[32];
            randombytes_buf(seed, sizeof seed);
            (void) secp256k1_context_randomize(cc, seed);  // heap context → always succeeds
            sodium_memzero(seed, sizeof seed);
            return cc;
        }();
        return c;
    }
};

} // namespace crypto::ec

#endif // CRYPTOLIB_HAS_SECP256K1
