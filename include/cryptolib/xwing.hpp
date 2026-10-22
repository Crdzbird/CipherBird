#pragma once
/**
 * crypto::pq::XWing: the X-Wing hybrid KEM of draft-connolly-cfrg-xwing-kem-11
 * (ML-KEM-768 and X25519 under a SHA3-256 combiner), IANA HPKE KEM id 0x647A.
 *
 * Composition only: ML-KEM-768 comes from liboqs (the derandomised entry
 * points, so a 32-byte seed expands exactly as the draft specifies), X25519
 * from libsodium, SHA3-256 and SHAKE256 from libcrypto. The byte layouts are
 * the draft's: decapsulation key 32 bytes (a seed), encapsulation key
 * pk_M || pk_X (1216 bytes), ciphertext ct_M || ct_X (1120 bytes), shared
 * secret 32 bytes. Known-answer tests use the draft's Appendix C vectors.
 */
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include "types.hpp"
#include "detail/sha3_evp.hpp"
#include <oqs/oqs.h>
#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace crypto::pq {

class XWing {
public:
    static constexpr std::size_t SEED_BYTES   = 32;
    static constexpr std::size_t PK_M_BYTES   = 1184;
    static constexpr std::size_t PK_X_BYTES   = 32;
    static constexpr std::size_t PK_BYTES     = PK_M_BYTES + PK_X_BYTES;
    static constexpr std::size_t CT_M_BYTES   = 1088;
    static constexpr std::size_t CT_X_BYTES   = 32;
    static constexpr std::size_t CT_BYTES     = CT_M_BYTES + CT_X_BYTES;
    static constexpr std::size_t SS_BYTES     = 32;
    static constexpr std::size_t ESEED_BYTES  = 64;
    static constexpr uint16_t    HPKE_KEM_ID  = 0x647A;

    /// Decapsulation key: the 32-byte seed. Encapsulation key: pk_M || pk_X.
    struct KeyPair { SecureBuffer public_key; SecureBuffer secret_key; };
    struct EncapsResult { SecureBuffer ciphertext; SecureBuffer shared_secret; };

    [[nodiscard]] static Result<KeyPair> generate_keypair() {
        SecureBuffer seed(SEED_BYTES);
        randombytes_buf(seed.data(), SEED_BYTES);
        return keypair_from_seed(seed.span());
    }

    /// Draft section 5.2: expand the seed with SHAKE256 to (d || z, sk_X).
    [[nodiscard]] static Result<KeyPair> keypair_from_seed(std::span<const uint8_t> seed) {
        if (seed.size() != SEED_BYTES) return Result<KeyPair>::err("X-Wing: seed must be 32 bytes");
        Expanded e;
        if (!expand(seed, e)) return Result<KeyPair>::err("X-Wing: seed expansion failed");
        KeyPair kp{ SecureBuffer(PK_BYTES), SecureBuffer(seed.data(), seed.size()) };
        SecureBuffer sk_m(sk_m_bytes());
        if (OQS_KEM_ml_kem_768_keypair_derand(kp.public_key.data(), sk_m.data(), e.dz) != OQS_SUCCESS)
            return Result<KeyPair>::err("X-Wing: ML-KEM-768 key generation failed");
        crypto_scalarmult_base(kp.public_key.data() + PK_M_BYTES, e.sk_x);
        return Result<KeyPair>::ok(std::move(kp));
    }

    [[nodiscard]] static Result<EncapsResult> encapsulate(std::span<const uint8_t> public_key) {
        uint8_t eseed[ESEED_BYTES];
        randombytes_buf(eseed, sizeof eseed);
        auto r = encapsulate_derand(public_key, eseed);
        sodium_memzero(eseed, sizeof eseed);
        return r;
    }

    /// Draft section 5.4 with the randomness supplied: eseed[0:32] is the
    /// ML-KEM encapsulation randomness, eseed[32:64] the X25519 ephemeral key.
    [[nodiscard]] static Result<EncapsResult>
    encapsulate_derand(std::span<const uint8_t> public_key, std::span<const uint8_t> eseed) {
        if (public_key.size() != PK_BYTES) return Result<EncapsResult>::err("X-Wing: public key must be 1216 bytes");
        if (eseed.size() != ESEED_BYTES) return Result<EncapsResult>::err("X-Wing: eseed must be 64 bytes");
        const uint8_t* pk_m = public_key.data();
        const uint8_t* pk_x = public_key.data() + PK_M_BYTES;
        EncapsResult out{ SecureBuffer(CT_BYTES), SecureBuffer(SS_BYTES) };
        uint8_t ss_m[32], ss_x[32];
        uint8_t* ct_m = out.ciphertext.data();
        uint8_t* ct_x = out.ciphertext.data() + CT_M_BYTES;
        crypto_scalarmult_base(ct_x, eseed.data() + 32);
        if (crypto_scalarmult(ss_x, eseed.data() + 32, pk_x) != 0)
            return Result<EncapsResult>::err("X-Wing: X25519 public key is a low-order point");
        /* liboqs rejects an encapsulation key that fails the FIPS 203 7.2 check. */
        if (OQS_KEM_ml_kem_768_encaps_derand(ct_m, ss_m, pk_m, eseed.data()) != OQS_SUCCESS) {
            sodium_memzero(ss_x, sizeof ss_x);
            return Result<EncapsResult>::err("X-Wing: ML-KEM-768 encapsulation failed");
        }
        const bool ok = combine(ss_m, ss_x, ct_x, pk_x, out.shared_secret.data());
        sodium_memzero(ss_m, sizeof ss_m);
        sodium_memzero(ss_x, sizeof ss_x);
        if (!ok) return Result<EncapsResult>::err("X-Wing: combiner failed");
        return Result<EncapsResult>::ok(std::move(out));
    }

    /// Draft section 5.5. A wrong ciphertext yields a wrong secret, not an
    /// error (ML-KEM's implicit rejection), as the draft specifies.
    [[nodiscard]] static Result<SecureBuffer>
    decapsulate(std::span<const uint8_t> ciphertext, std::span<const uint8_t> seed) {
        if (ciphertext.size() != CT_BYTES) return Result<SecureBuffer>::err("X-Wing: ciphertext must be 1120 bytes");
        if (seed.size() != SEED_BYTES) return Result<SecureBuffer>::err("X-Wing: seed must be 32 bytes");
        Expanded e;
        if (!expand(seed, e)) return Result<SecureBuffer>::err("X-Wing: seed expansion failed");
        SecureBuffer pk_m(PK_M_BYTES), sk_m(sk_m_bytes());
        if (OQS_KEM_ml_kem_768_keypair_derand(pk_m.data(), sk_m.data(), e.dz) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("X-Wing: ML-KEM-768 key generation failed");
        uint8_t pk_x[32];
        crypto_scalarmult_base(pk_x, e.sk_x);
        const uint8_t* ct_m = ciphertext.data();
        const uint8_t* ct_x = ciphertext.data() + CT_M_BYTES;
        uint8_t ss_m[32], ss_x[32];
        if (OQS_KEM_ml_kem_768_decaps(ss_m, ct_m, sk_m.data()) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("X-Wing: ML-KEM-768 decapsulation failed");
        if (crypto_scalarmult(ss_x, e.sk_x, ct_x) != 0) {
            sodium_memzero(ss_m, sizeof ss_m);
            return Result<SecureBuffer>::err("X-Wing: X25519 ciphertext is a low-order point");
        }
        SecureBuffer ss(SS_BYTES);
        const bool ok = combine(ss_m, ss_x, ct_x, pk_x, ss.data());
        sodium_memzero(ss_m, sizeof ss_m);
        sodium_memzero(ss_x, sizeof ss_x);
        if (!ok) return Result<SecureBuffer>::err("X-Wing: combiner failed");
        return Result<SecureBuffer>::ok(std::move(ss));
    }

private:
    struct Expanded {
        uint8_t dz[64];
        uint8_t sk_x[32];
        ~Expanded() { sodium_memzero(dz, sizeof dz); sodium_memzero(sk_x, sizeof sk_x); }
    };

    static std::size_t sk_m_bytes() { return OQS_KEM_ml_kem_768_length_secret_key; }

    static bool expand(std::span<const uint8_t> seed, Expanded& e) {
        uint8_t expanded[96];
        if (!detail::shake256(seed, expanded, sizeof expanded)) return false;
        std::memcpy(e.dz, expanded, 64);
        std::memcpy(e.sk_x, expanded + 64, 32);
        sodium_memzero(expanded, sizeof expanded);
        return true;
    }

    /// Draft section 5.3: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
    static bool combine(const uint8_t* ss_m, const uint8_t* ss_x, const uint8_t* ct_x,
                        const uint8_t* pk_x, uint8_t* out) {
        static constexpr uint8_t LABEL[6] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };
        const std::span<const uint8_t> parts[] = {
            { ss_m, 32 }, { ss_x, 32 }, { ct_x, 32 }, { pk_x, 32 }, { LABEL, 6 }
        };
        return detail::sha3_256(parts, out);
    }
};

}
#endif
