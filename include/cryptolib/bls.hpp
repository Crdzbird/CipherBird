#pragma once

/**
 * crypto::bls — BLS12-381 signatures and aggregation
 *
 * Wraps the blst library (supranational/blst) to provide:
 *
 *   Bls12381 — BLS signatures on the BLS12-381 curve
 *     - Key generation (from IKM or random)
 *     - Sign / Verify (minimal-pubkey-size: pk in G1, sig in G2)
 *     - Aggregate signatures (combine N signatures into one)
 *     - Aggregate verification (verify N messages from N signers with 1 sig)
 *
 * Requires: blst (build from https://github.com/supranational/blst)
 * Enable:   -DCRYPTOLIB_BLS=ON (default)
 *
 * Domain Separation Tag (DST): BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_
 * (Ethereum 2.0 compatible, "basic" scheme — no augmentation)
 */

#ifdef CRYPTOLIB_HAS_BLS

#include "types.hpp"
#include <blst/blst.h>
#include <sodium.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace crypto::bls {

class Bls12381 {
public:
    // Minimal-pubkey-size scheme: public keys in G1 (48 bytes compressed),
    // signatures in G2 (96 bytes compressed)
    static constexpr std::size_t SECRET_KEY_BYTES = 32;
    static constexpr std::size_t PUBLIC_KEY_BYTES  = 48;   // compressed G1
    static constexpr std::size_t SIGNATURE_BYTES   = 96;   // compressed G2

    struct KeyPair {
        SecureBuffer secret_key;   // 32 bytes (scalar)
        SecureBuffer public_key;   // 48 bytes (compressed G1)
    };

    /// Generate a keypair from random IKM
    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        // 32 bytes of IKM is the minimum for BLS keygen
        uint8_t ikm[32];
        randombytes_buf(ikm, sizeof(ikm));

        blst_scalar sk;
        blst_keygen(&sk, ikm, sizeof(ikm), nullptr, 0);
        sodium_memzero(ikm, sizeof(ikm));

        if (!blst_sk_check(&sk)) {
            sodium_memzero(&sk, sizeof(sk));
            return Result<KeyPair>::err("BLS: generated invalid secret key");
        }

        // Derive public key in G1
        blst_p1 pk_p1;
        blst_sk_to_pk_in_g1(&pk_p1, &sk);

        // Serialize
        SecureBuffer sk_buf(SECRET_KEY_BYTES);
        blst_bendian_from_scalar(sk_buf.data(), &sk);
        sodium_memzero(&sk, sizeof(sk));

        SecureBuffer pk_buf(PUBLIC_KEY_BYTES);
        blst_p1_compress(pk_buf.data(), &pk_p1);

        return Result<KeyPair>::ok(KeyPair{ std::move(sk_buf), std::move(pk_buf) });
    }

    /// Generate a keypair from provided IKM (input keying material, >= 32 bytes)
    [[nodiscard]] static Result<KeyPair>
    generate_keypair_from_ikm(std::span<const uint8_t> ikm) {
        if (ikm.size() < 32)
            return Result<KeyPair>::err("BLS: IKM must be >= 32 bytes");

        blst_scalar sk;
        blst_keygen(&sk, ikm.data(), ikm.size(), nullptr, 0);

        if (!blst_sk_check(&sk)) {
            sodium_memzero(&sk, sizeof(sk));
            return Result<KeyPair>::err("BLS: invalid secret key from IKM");
        }

        blst_p1 pk_p1;
        blst_sk_to_pk_in_g1(&pk_p1, &sk);

        SecureBuffer sk_buf(SECRET_KEY_BYTES);
        blst_bendian_from_scalar(sk_buf.data(), &sk);
        sodium_memzero(&sk, sizeof(sk));

        SecureBuffer pk_buf(PUBLIC_KEY_BYTES);
        blst_p1_compress(pk_buf.data(), &pk_p1);

        return Result<KeyPair>::ok(KeyPair{ std::move(sk_buf), std::move(pk_buf) });
    }

    /// Sign a message (signature in G2, 96 bytes compressed)
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message,
         std::span<const uint8_t> secret_key) {
        if (secret_key.size() != SECRET_KEY_BYTES)
            return Result<SecureBuffer>::err("BLS: secret key must be 32 bytes");

        // Deserialize secret key
        blst_scalar sk;
        blst_scalar_from_bendian(&sk, secret_key.data());
        if (!blst_sk_check(&sk)) {
            sodium_memzero(&sk, sizeof(sk));
            return Result<SecureBuffer>::err("BLS: invalid secret key");
        }

        // Hash message to G2 point
        blst_p2 hash_point;
        blst_hash_to_g2(&hash_point, message.data(), message.size(),
                         DST, DST_LEN, nullptr, 0);

        // Sign: sig = sk * H(m)
        blst_p2 sig_p2;
        blst_sign_pk_in_g1(&sig_p2, &hash_point, &sk);
        sodium_memzero(&sk, sizeof(sk));

        // Compress signature
        SecureBuffer sig(SIGNATURE_BYTES);
        blst_p2_compress(sig.data(), &sig_p2);

        return Result<SecureBuffer>::ok(std::move(sig));
    }

    [[nodiscard]] static Result<SecureBuffer>
    sign(std::string_view message, std::span<const uint8_t> secret_key) {
        return sign({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                    secret_key);
    }

    /// Verify a signature
    [[nodiscard]] static Result<void>
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key) {
        if (public_key.size() != PUBLIC_KEY_BYTES)
            return Result<void>::err("BLS: public key must be 48 bytes");
        if (signature.size() != SIGNATURE_BYTES)
            return Result<void>::err("BLS: signature must be 96 bytes");

        // Deserialize public key
        blst_p1_affine pk_aff;
        if (blst_p1_uncompress(&pk_aff, public_key.data()) != BLST_SUCCESS)
            return Result<void>::err("BLS: invalid public key encoding");
        if (!blst_p1_affine_in_g1(&pk_aff))
            return Result<void>::err("BLS: public key not in G1");

        // Deserialize signature
        blst_p2_affine sig_aff;
        if (blst_p2_uncompress(&sig_aff, signature.data()) != BLST_SUCCESS)
            return Result<void>::err("BLS: invalid signature encoding");
        if (!blst_p2_affine_in_g2(&sig_aff))
            return Result<void>::err("BLS: signature not in G2");

        // Core verify
        auto err = blst_core_verify_pk_in_g1(&pk_aff, &sig_aff, true,
            message.data(), message.size(), DST, DST_LEN, nullptr, 0);

        if (err != BLST_SUCCESS)
            return Result<void>::err("BLS: signature verification failed");

        return Result<void>::ok();
    }

    [[nodiscard]] static Result<void>
    verify(std::string_view message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key) {
        return verify({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                      signature, public_key);
    }

    /// Aggregate multiple signatures into a single signature
    [[nodiscard]] static Result<SecureBuffer>
    aggregate_signatures(const std::vector<std::span<const uint8_t>>& signatures) {
        if (signatures.empty())
            return Result<SecureBuffer>::err("BLS: no signatures to aggregate");

        // Decompress first signature
        blst_p2_affine sig_aff;
        if (signatures[0].size() != SIGNATURE_BYTES)
            return Result<SecureBuffer>::err("BLS: all signatures must be 96 bytes");
        if (blst_p2_uncompress(&sig_aff, signatures[0].data()) != BLST_SUCCESS)
            return Result<SecureBuffer>::err("BLS: invalid signature encoding");

        blst_p2 agg;
        blst_p2_from_affine(&agg, &sig_aff);

        // Add remaining signatures
        for (std::size_t i = 1; i < signatures.size(); ++i) {
            if (signatures[i].size() != SIGNATURE_BYTES)
                return Result<SecureBuffer>::err("BLS: all signatures must be 96 bytes");
            if (blst_p2_uncompress(&sig_aff, signatures[i].data()) != BLST_SUCCESS)
                return Result<SecureBuffer>::err("BLS: invalid signature encoding");

            blst_p2 tmp;
            blst_p2_from_affine(&tmp, &sig_aff);
            blst_p2_add_or_double(&agg, &agg, &tmp);
        }

        SecureBuffer result(SIGNATURE_BYTES);
        blst_p2_compress(result.data(), &agg);
        return Result<SecureBuffer>::ok(std::move(result));
    }

    /// Verify an aggregate signature against multiple (message, public_key) pairs.
    /// Each message must be unique (or augmented) to prevent rogue-key attacks.
    [[nodiscard]] static Result<void>
    aggregate_verify(const std::vector<std::span<const uint8_t>>& messages,
                     const std::vector<std::span<const uint8_t>>& public_keys,
                     std::span<const uint8_t> aggregate_signature) {
        if (messages.size() != public_keys.size())
            return Result<void>::err("BLS: messages and public_keys must have same count");
        if (messages.empty())
            return Result<void>::err("BLS: nothing to verify");
        if (aggregate_signature.size() != SIGNATURE_BYTES)
            return Result<void>::err("BLS: aggregate signature must be 96 bytes");

        // CRYPTO-CRITICAL: the basic scheme (DST ..._NUL_) is only secure
        // against rogue-key attacks when every aggregated message is distinct.
        // If two signers share a message, an attacker who registers a crafted
        // public key can forge a valid aggregate. Enforce distinctness here by
        // comparing BLAKE2b digests of the messages (sorted; O(n log n)).
        {
            std::vector<std::array<uint8_t, 32>> digests(messages.size());
            for (std::size_t i = 0; i < messages.size(); ++i)
                crypto_generichash(digests[i].data(), digests[i].size(),
                                   messages[i].data(), messages[i].size(),
                                   nullptr, 0);
            std::sort(digests.begin(), digests.end());
            for (std::size_t i = 1; i < digests.size(); ++i)
                if (digests[i] == digests[i - 1])
                    return Result<void>::err(
                        "BLS: duplicate message in aggregate (rogue-key risk)");
        }

        // Decompress aggregate signature
        blst_p2_affine agg_sig_aff;
        if (blst_p2_uncompress(&agg_sig_aff, aggregate_signature.data()) != BLST_SUCCESS)
            return Result<void>::err("BLS: invalid aggregate signature encoding");
        if (!blst_p2_affine_in_g2(&agg_sig_aff))
            return Result<void>::err("BLS: aggregate signature not in G2");

        // Convert aggregate signature to GT element for finalverify
        blst_fp12 gtsig;
        blst_aggregated_in_g2(&gtsig, &agg_sig_aff);

        // Allocate pairing context
        std::size_t ctx_size = blst_pairing_sizeof();
        std::vector<uint8_t> ctx_buf(ctx_size);
        auto* ctx = reinterpret_cast<blst_pairing*>(ctx_buf.data());
        blst_pairing_init(ctx, true, DST, DST_LEN);

        // Add each (pk, msg) pair — pass nullptr for signature (aggregated separately)
        for (std::size_t i = 0; i < messages.size(); ++i) {
            if (public_keys[i].size() != PUBLIC_KEY_BYTES)
                return Result<void>::err("BLS: all public keys must be 48 bytes");

            blst_p1_affine pk_aff;
            if (blst_p1_uncompress(&pk_aff, public_keys[i].data()) != BLST_SUCCESS)
                return Result<void>::err("BLS: invalid public key encoding");

            auto err = blst_pairing_aggregate_pk_in_g1(
                ctx, &pk_aff, nullptr,
                messages[i].data(), messages[i].size(),
                nullptr, 0);
            if (err != BLST_SUCCESS)
                return Result<void>::err("BLS: pairing aggregation failed");
        }

        blst_pairing_commit(ctx);

        if (!blst_pairing_finalverify(ctx, &gtsig))
            return Result<void>::err("BLS: aggregate verification failed");

        return Result<void>::ok();
    }

private:
    // Ethereum 2.0 compatible DST for "basic" scheme
    static constexpr const uint8_t DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    static constexpr std::size_t DST_LEN = sizeof(DST) - 1;  // exclude null terminator
};

} // namespace crypto::bls

#endif // CRYPTOLIB_HAS_BLS
