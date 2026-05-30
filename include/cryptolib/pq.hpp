#pragma once

/**
 * crypto::pq — Post-quantum cryptographic primitives (NIST FIPS 203/204/205)
 *
 * Wraps liboqs (Open Quantum Safe) to provide:
 *
 *   MlKem    — ML-KEM key encapsulation (FIPS 203) — 512/768/1024 security levels
 *   MlDsa    — ML-DSA digital signatures (FIPS 204) — 44/65/87 security levels
 *   SlhDsa   — SLH-DSA hash-based signatures (FIPS 205) — 128s/128f/192s/192f/256s/256f
 *
 * Requires: liboqs (brew install liboqs)
 * Enable:   -DCRYPTOLIB_PQ=ON (default)
 *
 * All three use the same pattern:
 *   - Static methods returning Result<T>
 *   - SecureBuffer for all key material (auto-zeroed on destruction)
 *   - RAII wrapper around OQS_KEM / OQS_SIG objects
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include <oqs/oqs.h>
#include <memory>
#include <string_view>

namespace crypto::pq {

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM — Module-Lattice Key Encapsulation Mechanism (FIPS 203)
//
// Post-quantum IND-CCA2 key encapsulation. Alice generates a keypair; Bob
// encapsulates a shared secret to Alice's public key; Alice decapsulates.
//
// Security levels:
//   ML-KEM-512  — NIST Level 1 (~AES-128)
//   ML-KEM-768  — NIST Level 3 (~AES-192)  ← recommended default
//   ML-KEM-1024 — NIST Level 5 (~AES-256)
// ─────────────────────────────────────────────────────────────────────────────
class MlKem {
public:
    enum class Level { KEM_512, KEM_768, KEM_1024 };

    struct KeyPair {
        SecureBuffer public_key;
        SecureBuffer secret_key;
    };

    struct EncapsResult {
        SecureBuffer ciphertext;
        SecureBuffer shared_secret;
    };

    /// Generate a fresh keypair
    [[nodiscard]] static Result<KeyPair>
    generate_keypair(Level level = Level::KEM_768) {
        auto kem = make_kem(level);
        if (!kem) return Result<KeyPair>::err("ML-KEM: algorithm not available in liboqs build");

        SecureBuffer pk(kem->length_public_key);
        SecureBuffer sk(kem->length_secret_key);

        if (OQS_KEM_keypair(kem.get(), pk.data(), sk.data()) != OQS_SUCCESS)
            return Result<KeyPair>::err("ML-KEM: keypair generation failed");

        return Result<KeyPair>::ok(KeyPair{ std::move(pk), std::move(sk) });
    }

    /// Encapsulate: produce ciphertext + shared secret from a public key
    [[nodiscard]] static Result<EncapsResult>
    encapsulate(std::span<const uint8_t> public_key, Level level = Level::KEM_768) {
        auto kem = make_kem(level);
        if (!kem) return Result<EncapsResult>::err("ML-KEM: algorithm not available");
        if (public_key.size() != kem->length_public_key)
            return Result<EncapsResult>::err("ML-KEM: invalid public key length");

        SecureBuffer ct(kem->length_ciphertext);
        SecureBuffer ss(kem->length_shared_secret);

        if (OQS_KEM_encaps(kem.get(), ct.data(), ss.data(), public_key.data()) != OQS_SUCCESS)
            return Result<EncapsResult>::err("ML-KEM: encapsulation failed");

        return Result<EncapsResult>::ok(EncapsResult{ std::move(ct), std::move(ss) });
    }

    /// Decapsulate: recover shared secret from ciphertext + secret key
    [[nodiscard]] static Result<SecureBuffer>
    decapsulate(std::span<const uint8_t> ciphertext,
                std::span<const uint8_t> secret_key,
                Level level = Level::KEM_768) {
        auto kem = make_kem(level);
        if (!kem) return Result<SecureBuffer>::err("ML-KEM: algorithm not available");
        if (ciphertext.size() != kem->length_ciphertext)
            return Result<SecureBuffer>::err("ML-KEM: invalid ciphertext length");
        if (secret_key.size() != kem->length_secret_key)
            return Result<SecureBuffer>::err("ML-KEM: invalid secret key length");

        SecureBuffer ss(kem->length_shared_secret);

        if (OQS_KEM_decaps(kem.get(), ss.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("ML-KEM: decapsulation failed");

        return Result<SecureBuffer>::ok(std::move(ss));
    }

    /// Query key/ciphertext/secret sizes for a given level
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t ciphertext;
        std::size_t shared_secret;
    };

    [[nodiscard]] static Result<Sizes> sizes(Level level = Level::KEM_768) {
        auto kem = make_kem(level);
        if (!kem) return Result<Sizes>::err("ML-KEM: algorithm not available");
        return Result<Sizes>::ok(Sizes{
            kem->length_public_key, kem->length_secret_key,
            kem->length_ciphertext, kem->length_shared_secret
        });
    }

private:
    struct KemDeleter { void operator()(OQS_KEM* k) { if (k) OQS_KEM_free(k); } };
    using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;

    [[nodiscard]] static KemPtr make_kem(Level level) {
        const char* name = nullptr;
        switch (level) {
            case Level::KEM_512:  name = OQS_KEM_alg_ml_kem_512;  break;
            case Level::KEM_768:  name = OQS_KEM_alg_ml_kem_768;  break;
            case Level::KEM_1024: name = OQS_KEM_alg_ml_kem_1024; break;
        }
        return KemPtr(OQS_KEM_new(name));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// ML-DSA — Module-Lattice Digital Signature Algorithm (FIPS 204)
//
// Post-quantum EUF-CMA digital signatures (lattice-based, formerly Dilithium).
//
// Security levels:
//   ML-DSA-44 — NIST Level 2 (~SHA-256/AES-128)
//   ML-DSA-65 — NIST Level 3 (~AES-192)  ← recommended default
//   ML-DSA-87 — NIST Level 5 (~AES-256)
// ─────────────────────────────────────────────────────────────────────────────
class MlDsa {
public:
    enum class Level { DSA_44, DSA_65, DSA_87 };

    struct KeyPair {
        SecureBuffer public_key;
        SecureBuffer secret_key;
    };

    /// Generate a fresh signing keypair
    [[nodiscard]] static Result<KeyPair>
    generate_keypair(Level level = Level::DSA_65) {
        auto sig = make_sig(level);
        if (!sig) return Result<KeyPair>::err("ML-DSA: algorithm not available in liboqs build");

        SecureBuffer pk(sig->length_public_key);
        SecureBuffer sk(sig->length_secret_key);

        if (OQS_SIG_keypair(sig.get(), pk.data(), sk.data()) != OQS_SUCCESS)
            return Result<KeyPair>::err("ML-DSA: keypair generation failed");

        return Result<KeyPair>::ok(KeyPair{ std::move(pk), std::move(sk) });
    }

    /// Sign a message
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message,
         std::span<const uint8_t> secret_key,
         Level level = Level::DSA_65) {
        auto sig = make_sig(level);
        if (!sig) return Result<SecureBuffer>::err("ML-DSA: algorithm not available");
        if (secret_key.size() != sig->length_secret_key)
            return Result<SecureBuffer>::err("ML-DSA: invalid secret key length");

        SecureBuffer signature(sig->length_signature);
        std::size_t sig_len = 0;

        if (OQS_SIG_sign(sig.get(), signature.data(), &sig_len,
                          message.data(), message.size(), secret_key.data()) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("ML-DSA: signing failed");

        signature.resize(sig_len);
        return Result<SecureBuffer>::ok(std::move(signature));
    }

    [[nodiscard]] static Result<SecureBuffer>
    sign(std::string_view message, std::span<const uint8_t> secret_key,
         Level level = Level::DSA_65) {
        return sign({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                    secret_key, level);
    }

    /// Verify a signature against a message and public key
    [[nodiscard]] static Result<void>
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key,
           Level level = Level::DSA_65) {
        auto sig = make_sig(level);
        if (!sig) return Result<void>::err("ML-DSA: algorithm not available");
        if (public_key.size() != sig->length_public_key)
            return Result<void>::err("ML-DSA: invalid public key length");

        if (OQS_SIG_verify(sig.get(), message.data(), message.size(),
                            signature.data(), signature.size(), public_key.data()) != OQS_SUCCESS)
            return Result<void>::err("ML-DSA: signature verification failed");

        return Result<void>::ok();
    }

    [[nodiscard]] static Result<void>
    verify(std::string_view message, std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key, Level level = Level::DSA_65) {
        return verify({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                      signature, public_key, level);
    }

    /// Query key/signature sizes for a given level
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t signature;
    };

    [[nodiscard]] static Result<Sizes> sizes(Level level = Level::DSA_65) {
        auto sig = make_sig(level);
        if (!sig) return Result<Sizes>::err("ML-DSA: algorithm not available");
        return Result<Sizes>::ok(Sizes{
            sig->length_public_key, sig->length_secret_key, sig->length_signature
        });
    }

private:
    struct SigDeleter { void operator()(OQS_SIG* s) { if (s) OQS_SIG_free(s); } };
    using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;

    [[nodiscard]] static SigPtr make_sig(Level level) {
        const char* name = nullptr;
        switch (level) {
            case Level::DSA_44: name = OQS_SIG_alg_ml_dsa_44; break;
            case Level::DSA_65: name = OQS_SIG_alg_ml_dsa_65; break;
            case Level::DSA_87: name = OQS_SIG_alg_ml_dsa_87; break;
        }
        return SigPtr(OQS_SIG_new(name));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// SLH-DSA — Stateless Hash-Based Digital Signature Algorithm (FIPS 205)
//
// Post-quantum signatures based purely on hash functions (formerly SPHINCS+).
// Conservative choice: security relies only on hash function properties,
// not on lattice hardness assumptions.
//
// Variants:
//   128s/128f — NIST Level 1 (~AES-128), s=small sig / f=fast signing
//   192s/192f — NIST Level 3 (~AES-192)
//   256s/256f — NIST Level 5 (~AES-256)
//
// Hash families: SHA2 (default) or SHAKE
// ─────────────────────────────────────────────────────────────────────────────
class SlhDsa {
public:
    enum class Level { L128s, L128f, L192s, L192f, L256s, L256f };
    enum class HashFamily { SHA2, SHAKE };

    struct KeyPair {
        SecureBuffer public_key;
        SecureBuffer secret_key;
    };

    /// Generate a fresh signing keypair
    [[nodiscard]] static Result<KeyPair>
    generate_keypair(Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        auto sig = make_sig(level, hash);
        if (!sig) return Result<KeyPair>::err("SLH-DSA: algorithm not available in liboqs build");

        SecureBuffer pk(sig->length_public_key);
        SecureBuffer sk(sig->length_secret_key);

        if (OQS_SIG_keypair(sig.get(), pk.data(), sk.data()) != OQS_SUCCESS)
            return Result<KeyPair>::err("SLH-DSA: keypair generation failed");

        return Result<KeyPair>::ok(KeyPair{ std::move(pk), std::move(sk) });
    }

    /// Sign a message
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> message,
         std::span<const uint8_t> secret_key,
         Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        auto sig = make_sig(level, hash);
        if (!sig) return Result<SecureBuffer>::err("SLH-DSA: algorithm not available");
        if (secret_key.size() != sig->length_secret_key)
            return Result<SecureBuffer>::err("SLH-DSA: invalid secret key length");

        SecureBuffer signature(sig->length_signature);
        std::size_t sig_len = 0;

        if (OQS_SIG_sign(sig.get(), signature.data(), &sig_len,
                          message.data(), message.size(), secret_key.data()) != OQS_SUCCESS)
            return Result<SecureBuffer>::err("SLH-DSA: signing failed");

        signature.resize(sig_len);
        return Result<SecureBuffer>::ok(std::move(signature));
    }

    [[nodiscard]] static Result<SecureBuffer>
    sign(std::string_view message, std::span<const uint8_t> secret_key,
         Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        return sign({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                    secret_key, level, hash);
    }

    /// Verify a signature against a message and public key
    [[nodiscard]] static Result<void>
    verify(std::span<const uint8_t> message,
           std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key,
           Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        auto sig = make_sig(level, hash);
        if (!sig) return Result<void>::err("SLH-DSA: algorithm not available");
        if (public_key.size() != sig->length_public_key)
            return Result<void>::err("SLH-DSA: invalid public key length");

        if (OQS_SIG_verify(sig.get(), message.data(), message.size(),
                            signature.data(), signature.size(), public_key.data()) != OQS_SUCCESS)
            return Result<void>::err("SLH-DSA: signature verification failed");

        return Result<void>::ok();
    }

    [[nodiscard]] static Result<void>
    verify(std::string_view message, std::span<const uint8_t> signature,
           std::span<const uint8_t> public_key,
           Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        return verify({ reinterpret_cast<const uint8_t*>(message.data()), message.size() },
                      signature, public_key, level, hash);
    }

    /// Query key/signature sizes for a given variant
    struct Sizes {
        std::size_t public_key;
        std::size_t secret_key;
        std::size_t signature;
    };

    [[nodiscard]] static Result<Sizes>
    sizes(Level level = Level::L128f, HashFamily hash = HashFamily::SHA2) {
        auto sig = make_sig(level, hash);
        if (!sig) return Result<Sizes>::err("SLH-DSA: algorithm not available");
        return Result<Sizes>::ok(Sizes{
            sig->length_public_key, sig->length_secret_key, sig->length_signature
        });
    }

private:
    struct SigDeleter { void operator()(OQS_SIG* s) { if (s) OQS_SIG_free(s); } };
    using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;

    [[nodiscard]] static SigPtr make_sig(Level level, HashFamily hash) {
        const char* name = nullptr;
        if (hash == HashFamily::SHA2) {
            switch (level) {
                case Level::L128s: name = OQS_SIG_alg_slh_dsa_pure_sha2_128s; break;
                case Level::L128f: name = OQS_SIG_alg_slh_dsa_pure_sha2_128f; break;
                case Level::L192s: name = OQS_SIG_alg_slh_dsa_pure_sha2_192s; break;
                case Level::L192f: name = OQS_SIG_alg_slh_dsa_pure_sha2_192f; break;
                case Level::L256s: name = OQS_SIG_alg_slh_dsa_pure_sha2_256s; break;
                case Level::L256f: name = OQS_SIG_alg_slh_dsa_pure_sha2_256f; break;
            }
        } else {
            switch (level) {
                case Level::L128s: name = OQS_SIG_alg_slh_dsa_pure_shake_128s; break;
                case Level::L128f: name = OQS_SIG_alg_slh_dsa_pure_shake_128f; break;
                case Level::L192s: name = OQS_SIG_alg_slh_dsa_pure_shake_192s; break;
                case Level::L192f: name = OQS_SIG_alg_slh_dsa_pure_shake_192f; break;
                case Level::L256s: name = OQS_SIG_alg_slh_dsa_pure_shake_256s; break;
                case Level::L256f: name = OQS_SIG_alg_slh_dsa_pure_shake_256f; break;
            }
        }
        return SigPtr(OQS_SIG_new(name));
    }
};

} // namespace crypto::pq

#endif // CRYPTOLIB_HAS_PQ
