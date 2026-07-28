#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Bbs — BBS Signatures (CFRG draft-irtf-cfrg-bbs-signatures)           ║
 * ║  Ciphersuite BLS12-381-SHA-256  (BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_)║
 * ║                                                                            ║
 * ║  A multi-message signature with SELECTIVE DISCLOSURE: a signer signs a        ║
 * ║  vector of messages; the holder can then derive a zero-knowledge proof that   ║
 * ║  reveals only a chosen subset while proving a valid signature covers ALL of   ║
 * ║  them — the core primitive behind privacy-preserving anonymous credentials    ║
 * ║  (W3C Verifiable Credentials, mDL-style selective disclosure).              ║
 * ║                                                                            ║
 * ║  This header provides the signature core (KeyGen / Sign / Verify). The        ║
 * ║  zero-knowledge proof layer (ProofGen / ProofVerify) is added on top.        ║
 * ║                                                                            ║
 * ║  Built on blst (BLS12-381 G1/G2, pairings) + SHA-256. hash-to-curve and       ║
 * ║  pairings are vetted blst calls; only expand_message_xmd (RFC 9380) is        ║
 * ║  assembled here from SHA-256. No new cryptography — a faithful implementation ║
 * ║  validated against the draft's official fixtures.                           ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_BLS

#include "types.hpp"

#include <blst/blst.h>
#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

class Bbs {
public:
    static constexpr std::size_t SCALAR_BYTES = 32;
    static constexpr std::size_t G1_BYTES     = 48; // compressed G1 point
    static constexpr std::size_t G2_BYTES     = 96; // compressed G2 public key
    static constexpr std::size_t SK_BYTES     = 32;
    static constexpr std::size_t SIGNATURE_BYTES = G1_BYTES + SCALAR_BYTES; // 80
    static constexpr std::size_t EXPAND_LEN   = 48;

    // BLS12-381-SHA-256 ciphersuite api_id.
    static constexpr std::string_view API_ID =
        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    // Ciphersuite fixed generator P1 (compressed G1).
    static constexpr std::string_view P1_HEX =
        "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

    struct KeyPair { SecureBuffer secret_key; SecureBuffer public_key; };

    // ── Key generation ────────────────────────────────────────────────────────
    /// Deterministic KeyGen from key material (KeyGen(key_material, key_info)).
    [[nodiscard]] static Result<KeyPair> keygen(std::span<const uint8_t> key_material,
                                                std::span<const uint8_t> key_info = {}) {
        if (key_material.size() < 32)
            return Result<KeyPair>::err("BBS: key_material must be >= 32 bytes");
        // KeyGen: SK = hash_to_scalar(key_material || I2OSP(len(key_info),2) || key_info, KEYGEN_DST)
        std::vector<uint8_t> ikm(key_material.begin(), key_material.end());
        ikm.push_back(static_cast<uint8_t>((key_info.size() >> 8) & 0xff));
        ikm.push_back(static_cast<uint8_t>(key_info.size() & 0xff));
        ikm.insert(ikm.end(), key_info.begin(), key_info.end());
        auto dst = concat(API_ID, "KEYGEN_DST_");
        blst_scalar sk = hash_to_scalar(ikm, dst);

        KeyPair kp;
        kp.secret_key = SecureBuffer(SK_BYTES);
        blst_bendian_from_scalar(kp.secret_key.data(), &sk);
        kp.public_key = sk_to_pk_internal(sk);
        return Result<KeyPair>::ok(std::move(kp));
    }

    [[nodiscard]] static KeyPair generate_keypair() {
        SecureBuffer km(32);
        randombytes_buf(km.data(), 32);
        return std::move(keygen(km.span()).value());
    }

    /// Public key W = SK · BP2 (96-byte compressed G2).
    [[nodiscard]] static Result<SecureBuffer> sk_to_pk(std::span<const uint8_t> sk) {
        if (sk.size() != SK_BYTES) return Result<SecureBuffer>::err("BBS: secret key must be 32 bytes");
        blst_scalar s;
        blst_scalar_from_bendian(&s, sk.data());
        return Result<SecureBuffer>::ok(sk_to_pk_internal(s));
    }

    // ── Sign / Verify ─────────────────────────────────────────────────────────
    [[nodiscard]] static Result<SecureBuffer>
    sign(std::span<const uint8_t> sk, std::span<const uint8_t> pk,
         std::span<const uint8_t> header, const std::vector<std::span<const uint8_t>>& messages) {
        if (sk.size() != SK_BYTES) return Result<SecureBuffer>::err("BBS: secret key must be 32 bytes");
        if (pk.size() != G2_BYTES) return Result<SecureBuffer>::err("BBS: public key must be 96 bytes");

        const std::size_t L = messages.size();
        auto gens = create_generators(L + 1); // Q1, H_1..H_L
        auto msg_scalars = messages_to_scalars(messages);

        blst_scalar domain = calculate_domain(pk, gens, header);

        // e = hash_to_scalar(serialize(SK, msg_1..msg_L, domain), H2S_dst)
        std::vector<uint8_t> e_in;
        put(e_in, sk);                       // I2OSP(SK, 32)
        for (const auto& m : msg_scalars) put_scalar(e_in, m);
        put_scalar(e_in, domain);
        blst_scalar e = hash_to_scalar(e_in, concat(API_ID, "H2S_"));

        // B = P1 + Q1·domain + Σ H_i·msg_i
        blst_p1 B = compute_B(gens, domain, msg_scalars);

        // A = B · 1/(SK + e)
        blst_scalar sk_sc;
        blst_scalar_from_bendian(&sk_sc, sk.data());
        blst_fr sk_fr, e_fr, sum, inv;
        blst_fr_from_scalar(&sk_fr, &sk_sc);
        blst_fr_from_scalar(&e_fr, &e);
        blst_fr_add(&sum, &sk_fr, &e_fr);
        blst_fr_inverse(&inv, &sum);
        blst_scalar inv_sc;
        blst_scalar_from_fr(&inv_sc, &inv);
        blst_p1 A;
        blst_p1_mult(&A, &B, inv_sc.b, 255);

        SecureBuffer sig(SIGNATURE_BYTES);
        blst_p1_compress(sig.data(), &A);
        blst_bendian_from_scalar(sig.data() + G1_BYTES, &e);
        return Result<SecureBuffer>::ok(std::move(sig));
    }

    [[nodiscard]] static bool
    verify(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
           std::span<const uint8_t> header, const std::vector<std::span<const uint8_t>>& messages) {
        if (pk.size() != G2_BYTES || signature.size() != SIGNATURE_BYTES) return false;

        // Deserialize A and e.
        blst_p1_affine A_aff;
        if (blst_p1_uncompress(&A_aff, signature.data()) != BLST_SUCCESS) return false;
        if (!blst_p1_affine_in_g1(&A_aff)) return false;
        blst_scalar e;
        blst_scalar_from_bendian(&e, signature.data() + G1_BYTES);
        if (!blst_scalar_fr_check(&e)) return false; // e < r
        // e != 0
        static const uint8_t zero[SCALAR_BYTES] = {};
        if (std::memcmp(signature.data() + G1_BYTES, zero, SCALAR_BYTES) == 0) return false;

        blst_p2_affine W_aff;
        if (blst_p2_uncompress(&W_aff, pk.data()) != BLST_SUCCESS) return false;
        if (!blst_p2_affine_in_g2(&W_aff)) return false;

        const std::size_t L = messages.size();
        auto gens = create_generators(L + 1);
        auto msg_scalars = messages_to_scalars(messages);
        blst_scalar domain = calculate_domain(pk, gens, header);
        blst_p1 B = compute_B(gens, domain, msg_scalars);

        // Check: e(A, W + BP2·e) · e(B, -BP2) == 1_GT
        blst_p2 BP2 = *blst_p2_generator();
        blst_p2 eBP2, WQ;
        blst_p2_mult(&eBP2, &BP2, e.b, 255);
        blst_p2 W;
        blst_p2_from_affine(&W, &W_aff);
        blst_p2_add_or_double(&WQ, &W, &eBP2);

        blst_p2 negBP2 = BP2;
        blst_p2_cneg(&negBP2, 1);

        blst_p1_affine B_aff;
        blst_p1_to_affine(&B_aff, &B);
        blst_p2_affine WQ_aff, negBP2_aff;
        blst_p2_to_affine(&WQ_aff, &WQ);
        blst_p2_to_affine(&negBP2_aff, &negBP2);

        blst_fp12 ml1, ml2, prod;
        blst_miller_loop(&ml1, &WQ_aff, &A_aff);
        blst_miller_loop(&ml2, &negBP2_aff, &B_aff);
        blst_fp12_mul(&prod, &ml1, &ml2);
        blst_final_exp(&prod, &prod);
        return blst_fp12_is_one(&prod);
    }

    // ── Proof generation / verification (zero-knowledge selective disclosure) ──
    /// Derive a proof revealing only `disclosed_indexes` of the signed messages.
    /// `messages` is the FULL message vector the signature covers.
    [[nodiscard]] static Result<SecureBuffer>
    proof_gen(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
              std::span<const uint8_t> header, std::span<const uint8_t> ph,
              const std::vector<std::span<const uint8_t>>& messages,
              const std::vector<std::size_t>& disclosed_indexes) {
        return proof_gen_impl(pk, signature, header, ph, messages, disclosed_indexes, {});
    }

    /// Deterministic variant: caller supplies the (5+U) random scalars, each as
    /// 32 big-endian bytes, in order (r1, r2, e~, r1~, r3~, m~_j1, …). For KATs.
    [[nodiscard]] static Result<SecureBuffer>
    proof_gen_deterministic(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
                            std::span<const uint8_t> header, std::span<const uint8_t> ph,
                            const std::vector<std::span<const uint8_t>>& messages,
                            const std::vector<std::size_t>& disclosed_indexes,
                            const std::vector<std::span<const uint8_t>>& random_scalars) {
        std::vector<blst_scalar> rs;
        rs.reserve(random_scalars.size());
        for (const auto& r : random_scalars) {
            if (r.size() != SCALAR_BYTES) return Result<SecureBuffer>::err("BBS: random scalar must be 32 bytes");
            blst_scalar s;
            blst_scalar_from_bendian(&s, r.data());
            rs.push_back(s);
        }
        return proof_gen_impl(pk, signature, header, ph, messages, disclosed_indexes, rs);
    }

    /// Verify a selective-disclosure proof. `disclosed_messages` are the revealed
    /// messages, aligned with `disclosed_indexes`.
    [[nodiscard]] static bool
    proof_verify(std::span<const uint8_t> pk, std::span<const uint8_t> proof,
                 std::span<const uint8_t> header, std::span<const uint8_t> ph,
                 const std::vector<std::span<const uint8_t>>& disclosed_messages,
                 const std::vector<std::size_t>& disclosed_indexes) {
        if (pk.size() != G2_BYTES) return false;
        // proof = Abar(48) Bbar(48) D(48) e^(32) r1^(32) r3^(32) [U commitments](32) c(32)
        if (proof.size() < 3 * G1_BYTES + 4 * SCALAR_BYTES) return false;
        std::size_t rest = proof.size() - 3 * G1_BYTES - 3 * SCALAR_BYTES;
        if (rest % SCALAR_BYTES != 0) return false;
        std::size_t U = rest / SCALAR_BYTES - 1; // minus the trailing challenge
        const std::size_t R = disclosed_indexes.size();
        const std::size_t L = R + U;
        if (disclosed_messages.size() != R) return false;

        // Parse points.
        blst_p1_affine Abar_a, Bbar_a, D_a;
        if (blst_p1_uncompress(&Abar_a, proof.data()) != BLST_SUCCESS) return false;
        if (blst_p1_uncompress(&Bbar_a, proof.data() + G1_BYTES) != BLST_SUCCESS) return false;
        if (blst_p1_uncompress(&D_a, proof.data() + 2 * G1_BYTES) != BLST_SUCCESS) return false;
        if (!blst_p1_affine_in_g1(&Abar_a) || !blst_p1_affine_in_g1(&Bbar_a) || !blst_p1_affine_in_g1(&D_a))
            return false;
        blst_p1 Abar, Bbar, D;
        blst_p1_from_affine(&Abar, &Abar_a);
        blst_p1_from_affine(&Bbar, &Bbar_a);
        blst_p1_from_affine(&D, &D_a);

        // Parse scalars.
        const uint8_t* sc = proof.data() + 3 * G1_BYTES;
        auto read_sc = [&](std::size_t idx) {
            blst_scalar s;
            blst_scalar_from_bendian(&s, sc + idx * SCALAR_BYTES);
            return s;
        };
        blst_scalar e_hat = read_sc(0), r1_hat = read_sc(1), r3_hat = read_sc(2);
        std::vector<blst_scalar> commitments;
        for (std::size_t i = 0; i < U; ++i) commitments.push_back(read_sc(3 + i));
        blst_scalar c = read_sc(3 + U);
        // All response scalars must be canonical.
        for (const blst_scalar* s : { &e_hat, &r1_hat, &r3_hat, &c }) if (!blst_scalar_fr_check(s)) return false;
        for (const auto& m : commitments) if (!blst_scalar_fr_check(&m)) return false;

        blst_p2_affine W_aff;
        if (blst_p2_uncompress(&W_aff, pk.data()) != BLST_SUCCESS) return false;
        if (!blst_p2_affine_in_g2(&W_aff)) return false;

        auto gens = create_generators(L + 1);
        auto disclosed_scalars = messages_to_scalars(disclosed_messages);
        auto undisclosed = complement_indexes(disclosed_indexes, L);
        if (undisclosed.size() != U) return false;
        blst_scalar domain = calculate_domain(pk, gens, header);

        // T1 = Bbar·c + Abar·e^ + D·r1^
        blst_p1 T1 = p1_add(p1_add(p1_mult(Bbar, c), p1_mult(Abar, e_hat)), p1_mult(D, r1_hat));
        // Bv = P1 + Q1·domain + Σ_disclosed H_i·msg_i
        blst_p1 Bv = p1_base();
        Bv = p1_add(Bv, p1_mult(gens[0], domain));
        for (std::size_t k = 0; k < R; ++k)
            Bv = p1_add(Bv, p1_mult(gens[disclosed_indexes[k] + 1], disclosed_scalars[k]));
        // T2 = Bv·c + D·r3^ + Σ_undisclosed H_j·m^_j
        blst_p1 T2 = p1_add(p1_mult(Bv, c), p1_mult(D, r3_hat));
        for (std::size_t k = 0; k < U; ++k)
            T2 = p1_add(T2, p1_mult(gens[undisclosed[k] + 1], commitments[k]));

        blst_scalar c_prime = proof_challenge(disclosed_indexes, disclosed_scalars, Abar, Bbar, D, T1, T2, domain, ph);
        uint8_t cb[SCALAR_BYTES], cpb[SCALAR_BYTES];
        blst_bendian_from_scalar(cb, &c);
        blst_bendian_from_scalar(cpb, &c_prime);
        if (sodium_memcmp(cb, cpb, SCALAR_BYTES) != 0) return false;

        // Pairing: e(Abar, W) · e(Bbar, -BP2) == 1_GT
        blst_p2 BP2 = *blst_p2_generator();
        blst_p2 negBP2 = BP2;
        blst_p2_cneg(&negBP2, 1);
        blst_p2 W;
        blst_p2_from_affine(&W, &W_aff);
        blst_p1_affine Bbar_aff;
        blst_p1_to_affine(&Bbar_aff, &Bbar);
        blst_p2_affine W_a2, negBP2_a;
        blst_p2_to_affine(&W_a2, &W);
        blst_p2_to_affine(&negBP2_a, &negBP2);
        blst_fp12 ml1, ml2, prod;
        blst_miller_loop(&ml1, &W_a2, &Abar_a);
        blst_miller_loop(&ml2, &negBP2_a, &Bbar_aff);
        blst_fp12_mul(&prod, &ml1, &ml2);
        blst_final_exp(&prod, &prod);
        return blst_fp12_is_one(&prod);
    }

private:
    // ── scalar arithmetic (mod r, via blst_fr) ────────────────────────────────
    static blst_scalar sc_from_fr(const blst_fr& f) { blst_scalar s; blst_scalar_from_fr(&s, &f); return s; }
    static blst_fr fr_of(const blst_scalar& s) { blst_fr f; blst_fr_from_scalar(&f, &s); return f; }
    static blst_scalar sc_mul(const blst_scalar& a, const blst_scalar& b) {
        blst_fr r; blst_fr fa = fr_of(a), fb = fr_of(b); blst_fr_mul(&r, &fa, &fb); return sc_from_fr(r);
    }
    static blst_scalar sc_add(const blst_scalar& a, const blst_scalar& b) {
        blst_fr r; blst_fr fa = fr_of(a), fb = fr_of(b); blst_fr_add(&r, &fa, &fb); return sc_from_fr(r);
    }
    static blst_scalar sc_sub(const blst_scalar& a, const blst_scalar& b) {
        blst_fr r; blst_fr fa = fr_of(a), fb = fr_of(b); blst_fr_sub(&r, &fa, &fb); return sc_from_fr(r);
    }
    static blst_scalar sc_inv(const blst_scalar& a) {
        blst_fr r; blst_fr fa = fr_of(a); blst_fr_inverse(&r, &fa); return sc_from_fr(r);
    }

    // ── point arithmetic ──────────────────────────────────────────────────────
    static blst_p1 p1_mult(const blst_p1& p, const blst_scalar& s) {
        blst_p1 o; blst_p1_mult(&o, &p, s.b, 255); return o;
    }
    static blst_p1 p1_add(const blst_p1& a, const blst_p1& b) {
        blst_p1 o; blst_p1_add_or_double(&o, &a, &b); return o;
    }
    static blst_p1 p1_sub(const blst_p1& a, const blst_p1& b) {
        blst_p1 nb = b; blst_p1_cneg(&nb, 1); return p1_add(a, nb);
    }

    static std::vector<std::size_t>
    complement_indexes(const std::vector<std::size_t>& disclosed, std::size_t L) {
        std::vector<char> in(L, 0);
        for (auto i : disclosed) if (i < L) in[i] = 1;
        std::vector<std::size_t> out;
        for (std::size_t i = 0; i < L; ++i) if (!in[i]) out.push_back(i);
        return out;
    }

    static blst_scalar random_scalar() {
        uint8_t r[EXPAND_LEN];
        randombytes_buf(r, EXPAND_LEN);
        blst_scalar s;
        blst_scalar_from_be_bytes(&s, r, EXPAND_LEN);
        return s;
    }

    // c_arr = (R, i1, msg_i1, …, iR, msg_iR, Abar, Bbar, D, T1, T2, domain)
    static blst_scalar proof_challenge(const std::vector<std::size_t>& disclosed_indexes,
                                       const std::vector<blst_scalar>& disclosed_scalars,
                                       const blst_p1& Abar, const blst_p1& Bbar, const blst_p1& D,
                                       const blst_p1& T1, const blst_p1& T2, const blst_scalar& domain,
                                       std::span<const uint8_t> ph) {
        std::vector<uint8_t> c;
        put_u64(c, static_cast<uint64_t>(disclosed_indexes.size()));
        for (std::size_t k = 0; k < disclosed_indexes.size(); ++k) {
            put_u64(c, static_cast<uint64_t>(disclosed_indexes[k]));
            put_scalar(c, disclosed_scalars[k]);
        }
        put_g1(c, Abar); put_g1(c, Bbar); put_g1(c, D); put_g1(c, T1); put_g1(c, T2);
        put_scalar(c, domain);
        put_u64(c, static_cast<uint64_t>(ph.size()));
        put(c, ph);
        return hash_to_scalar(sv(c), concat(API_ID, "H2S_"));
    }

    static Result<SecureBuffer>
    proof_gen_impl(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
                   std::span<const uint8_t> header, std::span<const uint8_t> ph,
                   const std::vector<std::span<const uint8_t>>& messages,
                   const std::vector<std::size_t>& disclosed_indexes,
                   std::vector<blst_scalar> random_scalars) {
        if (pk.size() != G2_BYTES || signature.size() != SIGNATURE_BYTES)
            return Result<SecureBuffer>::err("BBS: bad key/signature length");
        blst_p1_affine A_aff;
        if (blst_p1_uncompress(&A_aff, signature.data()) != BLST_SUCCESS)
            return Result<SecureBuffer>::err("BBS: invalid signature point");
        blst_p1 A;
        blst_p1_from_affine(&A, &A_aff);
        blst_scalar e;
        blst_scalar_from_bendian(&e, signature.data() + G1_BYTES);

        const std::size_t L = messages.size();
        const std::size_t R = disclosed_indexes.size();
        if (R > L) return Result<SecureBuffer>::err("BBS: too many disclosed indexes");
        const std::size_t U = L - R;
        auto undisclosed = complement_indexes(disclosed_indexes, L);

        if (random_scalars.empty()) {
            random_scalars.reserve(5 + U);
            for (std::size_t i = 0; i < 5 + U; ++i) random_scalars.push_back(random_scalar());
        }
        if (random_scalars.size() != 5 + U)
            return Result<SecureBuffer>::err("BBS: expected 5+U random scalars");
        const blst_scalar& r1 = random_scalars[0];
        const blst_scalar& r2 = random_scalars[1];
        const blst_scalar& e_t = random_scalars[2];
        const blst_scalar& r1_t = random_scalars[3];
        const blst_scalar& r3_t = random_scalars[4];

        auto gens = create_generators(L + 1);
        auto msg_scalars = messages_to_scalars(messages);
        blst_scalar domain = calculate_domain(pk, gens, header);
        blst_p1 B = compute_B(gens, domain, msg_scalars);

        blst_p1 D = p1_mult(B, r2);
        blst_p1 Abar = p1_mult(A, sc_mul(r1, r2));
        blst_p1 Bbar = p1_sub(p1_mult(D, r1), p1_mult(Abar, e));
        blst_p1 T1 = p1_add(p1_mult(Abar, e_t), p1_mult(D, r1_t));
        blst_p1 T2 = p1_mult(D, r3_t);
        for (std::size_t k = 0; k < U; ++k)
            T2 = p1_add(T2, p1_mult(gens[undisclosed[k] + 1], random_scalars[5 + k]));

        std::vector<blst_scalar> disclosed_scalars;
        for (auto i : disclosed_indexes) disclosed_scalars.push_back(msg_scalars[i]);
        blst_scalar c = proof_challenge(disclosed_indexes, disclosed_scalars, Abar, Bbar, D, T1, T2, domain, ph);

        blst_scalar r3 = sc_inv(r2);
        blst_scalar e_hat  = sc_add(e_t, sc_mul(e, c));
        blst_scalar r1_hat = sc_sub(r1_t, sc_mul(r1, c));
        blst_scalar r3_hat = sc_sub(r3_t, sc_mul(r3, c));

        SecureBuffer proof(3 * G1_BYTES + (3 + U + 1) * SCALAR_BYTES);
        std::size_t off = 0;
        blst_p1_compress(proof.data() + off, &Abar); off += G1_BYTES;
        blst_p1_compress(proof.data() + off, &Bbar); off += G1_BYTES;
        blst_p1_compress(proof.data() + off, &D);    off += G1_BYTES;
        auto write_sc = [&](const blst_scalar& s) { blst_bendian_from_scalar(proof.data() + off, &s); off += SCALAR_BYTES; };
        write_sc(e_hat); write_sc(r1_hat); write_sc(r3_hat);
        for (std::size_t k = 0; k < U; ++k)
            write_sc(sc_add(random_scalars[5 + k], sc_mul(msg_scalars[undisclosed[k]], c)));
        write_sc(c);
        return Result<SecureBuffer>::ok(std::move(proof));
    }

    // ── byte / serialization helpers ──────────────────────────────────────────
    static void put(std::vector<uint8_t>& v, std::span<const uint8_t> s) {
        v.insert(v.end(), s.begin(), s.end());
    }
    static void put(std::vector<uint8_t>& v, std::string_view s) {
        v.insert(v.end(), s.begin(), s.end());
    }
    static void put_scalar(std::vector<uint8_t>& v, const blst_scalar& s) {
        uint8_t b[SCALAR_BYTES];
        blst_bendian_from_scalar(b, &s);
        v.insert(v.end(), b, b + SCALAR_BYTES);
    }
    static void put_u64(std::vector<uint8_t>& v, uint64_t n) {
        for (int i = 7; i >= 0; --i) v.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
    }
    static std::vector<uint8_t> concat(std::string_view a, std::string_view b) {
        std::vector<uint8_t> v;
        put(v, a); put(v, b);
        return v;
    }
    static std::span<const uint8_t> sv(const std::vector<uint8_t>& v) { return { v.data(), v.size() }; }

    // ── expand_message_xmd (RFC 9380 §5.3.1) over SHA-256 ─────────────────────
    static std::vector<uint8_t>
    expand_message_xmd(std::span<const uint8_t> msg, std::span<const uint8_t> dst, std::size_t len) {
        constexpr std::size_t b_in = 32, s_in = 64;
        std::size_t ell = (len + b_in - 1) / b_in;
        std::vector<uint8_t> dst_prime(dst.begin(), dst.end());
        dst_prime.push_back(static_cast<uint8_t>(dst.size()));

        std::vector<uint8_t> msg_prime(s_in, 0);
        msg_prime.insert(msg_prime.end(), msg.begin(), msg.end());
        msg_prime.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
        msg_prime.push_back(static_cast<uint8_t>(len & 0xff));
        msg_prime.push_back(0x00);
        msg_prime.insert(msg_prime.end(), dst_prime.begin(), dst_prime.end());

        uint8_t b0[b_in];
        crypto_hash_sha256(b0, msg_prime.data(), msg_prime.size());
        std::vector<uint8_t> t;
        t.assign(b0, b0 + b_in);
        t.push_back(0x01);
        t.insert(t.end(), dst_prime.begin(), dst_prime.end());
        uint8_t prev[b_in];
        crypto_hash_sha256(prev, t.data(), t.size());
        std::vector<uint8_t> out(prev, prev + b_in);
        for (std::size_t i = 2; i <= ell; ++i) {
            uint8_t x[b_in];
            for (std::size_t j = 0; j < b_in; ++j) x[j] = b0[j] ^ prev[j];
            std::vector<uint8_t> ti(x, x + b_in);
            ti.push_back(static_cast<uint8_t>(i));
            ti.insert(ti.end(), dst_prime.begin(), dst_prime.end());
            crypto_hash_sha256(prev, ti.data(), ti.size());
            out.insert(out.end(), prev, prev + b_in);
        }
        out.resize(len);
        return out;
    }

    static blst_scalar hash_to_scalar(std::span<const uint8_t> msg, std::span<const uint8_t> dst) {
        auto u = expand_message_xmd(msg, dst, EXPAND_LEN);
        blst_scalar s;
        blst_scalar_from_be_bytes(&s, u.data(), u.size());
        return s;
    }
    static blst_scalar hash_to_scalar(std::span<const uint8_t> msg, const std::vector<uint8_t>& dst) {
        return hash_to_scalar(msg, sv(dst));
    }
    static blst_scalar hash_to_scalar(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& dst) {
        return hash_to_scalar(sv(msg), sv(dst));
    }

    // ── generators / message mapping ──────────────────────────────────────────
    // create_generators is api_id-parameterised: the base BBS suite uses API_ID,
    // while the pseudonym / blind extensions (draft-irtf-cfrg-bbs-per-verifier-
    // linkability) use "..._PSEUDONYM_" and "BLIND_..._PSEUDONYM_" api_ids, which
    // regenerate an independent generator set. The seed/DST strings all fold in
    // api_id, so the sequences are suite-specific by construction.
    static std::vector<blst_p1> create_generators(std::size_t count, std::string_view api_id) {
        auto seed_dst  = concat(api_id, "SIG_GENERATOR_SEED_");
        auto gen_dst   = concat(api_id, "SIG_GENERATOR_DST_");
        auto gen_seed  = concat(api_id, "MESSAGE_GENERATOR_SEED");

        std::vector<blst_p1> gens;
        gens.reserve(count);
        std::vector<uint8_t> v = expand_message_xmd(sv(gen_seed), sv(seed_dst), EXPAND_LEN);
        for (std::size_t i = 1; i <= count; ++i) {
            std::vector<uint8_t> in = v;
            put_u64(in, static_cast<uint64_t>(i));
            v = expand_message_xmd(sv(in), sv(seed_dst), EXPAND_LEN);
            blst_p1 g;
            blst_hash_to_g1(&g, v.data(), v.size(), gen_dst.data(), gen_dst.size(), nullptr, 0);
            gens.push_back(g);
        }
        return gens;
    }
    static std::vector<blst_p1> create_generators(std::size_t count) {
        return create_generators(count, API_ID);
    }

public:
    // Pseudonym-suite api_ids (draft-irtf-cfrg-bbs-per-verifier-linkability-02).
    static constexpr std::string_view API_ID_PSEUDONYM =
        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PSEUDONYM_";
    static constexpr std::string_view API_ID_BLIND_PSEUDONYM =
        "BLIND_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PSEUDONYM_";
    // Standalone blind-issuance interface api_id (draft-irtf-cfrg-bbs-blind-
    // signatures-02) = ciphersuite_id || "BLIND_H2G_HM2S_".
    static constexpr std::string_view API_ID_BLIND =
        "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";

    // Test-visibility hook: reproduce a suite's generators (compressed G1, 48B
    // each) for byte-exact validation against the draft's Section 12 vectors.
    [[nodiscard]] static std::vector<std::array<uint8_t, G1_BYTES>>
    generators_for_test(std::size_t count, std::string_view api_id) {
        auto gens = create_generators(count, api_id);
        std::vector<std::array<uint8_t, G1_BYTES>> out;
        out.reserve(gens.size());
        for (const auto& g : gens) {
            std::array<uint8_t, G1_BYTES> c{};
            blst_p1_compress(c.data(), &g);
            out.push_back(c);
        }
        return out;
    }

    // ── Blind BBS: commitment (draft-irtf-cfrg-bbs-blind-signatures-02) ─────────
    // Deterministic mocked random scalars (draft test generator):
    //   v = expand_message_xmd(seed, dst, EXPAND_LEN*count);
    //   r_i = OS2IP(v[EXPAND_LEN*i : +EXPAND_LEN]) mod r
    static std::vector<blst_scalar>
    mocked_random_scalars(std::size_t count, std::string_view seed, std::string_view dst) {
        std::vector<uint8_t> seed_b(seed.begin(), seed.end());
        std::vector<uint8_t> dst_b(dst.begin(), dst.end());
        auto v = expand_message_xmd(sv(seed_b), sv(dst_b), EXPAND_LEN * count);
        std::vector<blst_scalar> out(count);
        for (std::size_t i = 0; i < count; ++i)
            blst_scalar_from_be_bytes(&out[i], v.data() + i * EXPAND_LEN, EXPAND_LEN);
        return out;
    }

    // calculate_blind_challenge (§5.3): c_octs = I2OSP(M,8) || (blind_gens) || C || Cbar.
    static blst_scalar calculate_blind_challenge(const blst_p1& C, const blst_p1& Cbar,
            const std::vector<blst_p1>& blind_gens, std::string_view api_id) {
        std::vector<uint8_t> c;
        put_u64(c, static_cast<uint64_t>(blind_gens.size() - 1)); // M
        for (const auto& g : blind_gens) put_g1(c, g);
        put_g1(c, C); put_g1(c, Cbar);
        return hash_to_scalar(sv(c), sv(concat(api_id, "H2S_")));
    }

    // CoreCommit (§4.3.1). blind_gens = [Q_2, J_1..J_M];
    // rnd = (secret_prover_blind, s~, m~_1..m~_M) (count M+2).
    // Returns commitment_with_proof = compress(C) || s^ || m^_1..m^_M || challenge.
    static std::vector<uint8_t>
    core_commit(const std::vector<blst_p1>& blind_gens,
                const std::vector<blst_scalar>& committed,
                std::string_view api_id, const std::vector<blst_scalar>& rnd) {
        const std::size_t M = committed.size();
        const blst_scalar& spb = rnd[0];
        const blst_scalar& s_t = rnd[1];
        blst_p1 C = p1_mult(blind_gens[0], spb);
        for (std::size_t i = 0; i < M; ++i) C = p1_add(C, p1_mult(blind_gens[i + 1], committed[i]));
        blst_p1 Cbar = p1_mult(blind_gens[0], s_t);
        for (std::size_t i = 0; i < M; ++i) Cbar = p1_add(Cbar, p1_mult(blind_gens[i + 1], rnd[2 + i]));
        blst_scalar ch = calculate_blind_challenge(C, Cbar, blind_gens, api_id);
        blst_scalar s_hat = sc_add(s_t, sc_mul(spb, ch));
        std::vector<uint8_t> out;
        put_g1(out, C);
        put_scalar(out, s_hat);
        for (std::size_t i = 0; i < M; ++i)
            put_scalar(out, sc_add(rnd[2 + i], sc_mul(committed[i], ch)));
        put_scalar(out, ch);
        return out;
    }

    // api_id-parameterised message→scalar mapping (the base overload uses API_ID).
    static std::vector<blst_scalar>
    messages_to_scalars(const std::vector<std::span<const uint8_t>>& messages, std::string_view api_id) {
        auto map_dst = concat(api_id, "MAP_MSG_TO_SCALAR_AS_HASH_");
        std::vector<blst_scalar> out;
        out.reserve(messages.size());
        for (const auto& m : messages) out.push_back(hash_to_scalar(m, sv(map_dst)));
        return out;
    }

    // Deterministic Commit for KAT validation (draft §9.1.3 / §12.1.3):
    // committed_messages → scalars (api_id map), blind generators under
    // "BLIND_"||api_id, CoreCommit with mocked random scalars.
    [[nodiscard]] static std::vector<uint8_t>
    commit_deterministic_for_test(const std::vector<std::span<const uint8_t>>& committed_messages,
            std::string_view api_id, std::string_view mock_seed, std::string_view mock_dst,
            std::string_view map_api_id = {}) {
        auto scalars = messages_to_scalars(committed_messages,
                                           map_api_id.empty() ? api_id : map_api_id);
        std::string blind_api = "BLIND_";
        blind_api += api_id;
        auto blind_gens = create_generators(scalars.size() + 1, blind_api);
        auto rnd = mocked_random_scalars(scalars.size() + 2, mock_seed, mock_dst);
        return core_commit(blind_gens, scalars, api_id, rnd);
    }

    // CalculatePseudonym (pvl §4): pseudonym = OP · Σ nym_secrets[i]·z^i, where
    // OP = hash_to_curve_g1(context_id, api_id), z = hash_to_scalar(context_id,
    // api_id||"VECT_NYM_SECRETS"). Returns the compressed pseudonym (48 B).
    [[nodiscard]] static std::array<uint8_t, G1_BYTES>
    calculate_pseudonym(std::span<const uint8_t> context_id,
                        const std::vector<std::span<const uint8_t>>& nym_secrets,
                        std::string_view api_id) {
        blst_p1 OP = hash_to_g1(context_id, sv(std::vector<uint8_t>(api_id.begin(), api_id.end())));
        blst_scalar z = hash_to_scalar(context_id, concat(api_id, "VECT_NYM_SECRETS"));
        blst_scalar poly; blst_scalar_from_bendian(&poly, nym_secrets[0].data());
        blst_scalar zn = z;
        for (std::size_t i = 1; i < nym_secrets.size(); ++i) {
            blst_scalar ns; blst_scalar_from_bendian(&ns, nym_secrets[i].data());
            poly = sc_add(poly, sc_mul(ns, zn));
            zn = sc_mul(zn, z);
        }
        blst_p1 P = p1_mult(OP, poly);
        std::array<uint8_t, G1_BYTES> out{};
        blst_p1_compress(out.data(), &P);
        return out;
    }

    // ProofGenWithPseudonym (pvl §6.2/§7.1). Assembles the split message/generator
    // vectors, generates the base BBS proof + the pseudonym sigma Ut, and binds
    // both under the extended challenge. Returns (proof, pseudonym). random_scalars
    // empty ⇒ fresh randomness (round-trip use).
    [[nodiscard]] static Result<std::pair<SecureBuffer, std::array<uint8_t, G1_BYTES>>>
    proof_gen_with_pseudonym(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
            std::span<const uint8_t> header, std::span<const uint8_t> ph,
            std::span<const uint8_t> context_id,
            const std::vector<std::span<const uint8_t>>& signer_messages,
            const std::vector<std::span<const uint8_t>>& committed_messages,
            std::span<const uint8_t> secret_prover_blind,
            const std::vector<std::span<const uint8_t>>& nym_secrets,
            const std::vector<std::size_t>& disclosed_signer_indexes,
            const std::vector<std::size_t>& disclosed_committed_indexes,
            std::string_view api_id, std::vector<blst_scalar> random_scalars = {}) {
        using Ret = std::pair<SecureBuffer, std::array<uint8_t, G1_BYTES>>;
        if (pk.size() != G2_BYTES || signature.size() != SIGNATURE_BYTES)
            return Result<Ret>::err("BBS: bad key/signature length");
        const std::size_t L = signer_messages.size();
        const std::size_t Mc = committed_messages.size();
        const std::size_t Nnym = nym_secrets.size();
        const std::size_t total = L + 1 + Mc + Nnym;

        // Full message scalar vector: signer ++ secret_prover_blind ++ committed ++ nym.
        std::vector<blst_scalar> msg_scalars = messages_to_scalars(signer_messages, api_id);
        blst_scalar spb; blst_scalar_from_bendian(&spb, secret_prover_blind.data());
        msg_scalars.push_back(spb);
        for (auto& cs : messages_to_scalars(committed_messages, api_id)) msg_scalars.push_back(cs);
        for (auto& ns : nym_secrets) { blst_scalar s; blst_scalar_from_bendian(&s, ns.data()); msg_scalars.push_back(s); }

        // Unified generators.
        auto base_gens = create_generators(L + 1, api_id);
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(Mc + Nnym + 1, blind_api);
        std::vector<blst_p1> gens = base_gens;
        for (const auto& bg : blind_gens) gens.push_back(bg);

        // Combined disclosed indexes: signer as-is; committed j -> j+L+1.
        std::vector<std::size_t> disclosed = disclosed_signer_indexes;
        for (auto j : disclosed_committed_indexes) disclosed.push_back(j + L + 1);
        std::sort(disclosed.begin(), disclosed.end());
        const std::size_t R = disclosed.size();
        const std::size_t U = total - R;
        auto undisclosed = complement_indexes(disclosed, total);

        if (random_scalars.empty())
            for (std::size_t i = 0; i < 5 + U; ++i) random_scalars.push_back(random_scalar());
        if (random_scalars.size() != 5 + U) return Result<Ret>::err("BBS: expected 5+U random scalars");

        blst_p1_affine A_aff; blst_p1_uncompress(&A_aff, signature.data());
        blst_p1 A; blst_p1_from_affine(&A, &A_aff);
        blst_scalar e; blst_scalar_from_bendian(&e, signature.data() + G1_BYTES);
        const blst_scalar& r1 = random_scalars[0]; const blst_scalar& r2 = random_scalars[1];
        const blst_scalar& e_t = random_scalars[2]; const blst_scalar& r1_t = random_scalars[3];
        const blst_scalar& r3_t = random_scalars[4];

        std::vector<uint8_t> hdr(header.begin(), header.end());
        put_u64(hdr, Nnym);
        blst_scalar domain = calculate_domain(pk, gens, sv(hdr), api_id);
        blst_p1 B = compute_B(base_gens, domain, messages_to_scalars(signer_messages, api_id));
        // Add the committed + nym contributions (indexes L+1..total-1 use blind gens).
        for (std::size_t idx = L; idx < total; ++idx) B = p1_add(B, p1_mult(gens[idx + 1], msg_scalars[idx]));

        blst_p1 D = p1_mult(B, r2);
        blst_p1 Abar = p1_mult(A, sc_mul(r1, r2));
        blst_p1 Bbar = p1_sub(p1_mult(D, r1), p1_mult(Abar, e));
        blst_p1 T1 = p1_add(p1_mult(Abar, e_t), p1_mult(D, r1_t));
        blst_p1 T2 = p1_mult(D, r3_t);
        for (std::size_t k = 0; k < U; ++k)
            T2 = p1_add(T2, p1_mult(gens[undisclosed[k] + 1], random_scalars[5 + k]));

        // Pseudonym Ut = OP · poly(random_scalars at the nym positions).
        blst_p1 OP = hash_to_g1(context_id, sv(std::vector<uint8_t>(api_id.begin(), api_id.end())));
        blst_scalar z = hash_to_scalar(context_id, concat(api_id, "VECT_NYM_SECRETS"));
        const std::size_t nb = U - Nnym;                    // nym positions = last Nnym undisclosed
        blst_scalar poly = random_scalars[5 + nb], zn = z;
        for (std::size_t i = 1; i < Nnym; ++i) { poly = sc_add(poly, sc_mul(random_scalars[5 + nb + i], zn)); zn = sc_mul(zn, z); }
        blst_p1 Ut = p1_mult(OP, poly);
        auto pseudonym = calculate_pseudonym(context_id, nym_secrets, api_id);
        blst_p1_affine ny_a; blst_p1_uncompress(&ny_a, pseudonym.data());
        blst_p1 nym_pt; blst_p1_from_affine(&nym_pt, &ny_a);

        std::vector<blst_scalar> disclosed_scalars;
        for (auto i : disclosed) disclosed_scalars.push_back(msg_scalars[i]);
        blst_scalar c = pseudonym_proof_challenge(disclosed, disclosed_scalars, Abar, Bbar, D, T1, T2,
                                                  nym_pt, Ut, domain, ph, context_id, api_id);

        blst_scalar r3 = sc_inv(r2);
        blst_scalar e_hat = sc_add(e_t, sc_mul(e, c));
        blst_scalar r1_hat = sc_sub(r1_t, sc_mul(r1, c));
        blst_scalar r3_hat = sc_sub(r3_t, sc_mul(r3, c));

        SecureBuffer proof(3 * G1_BYTES + (3 + U + 1) * SCALAR_BYTES);
        std::size_t off = 0;
        blst_p1_compress(proof.data() + off, &Abar); off += G1_BYTES;
        blst_p1_compress(proof.data() + off, &Bbar); off += G1_BYTES;
        blst_p1_compress(proof.data() + off, &D);    off += G1_BYTES;
        auto write_sc = [&](const blst_scalar& s) { blst_bendian_from_scalar(proof.data() + off, &s); off += SCALAR_BYTES; };
        write_sc(e_hat); write_sc(r1_hat); write_sc(r3_hat);
        for (std::size_t k = 0; k < U; ++k)
            write_sc(sc_add(random_scalars[5 + k], sc_mul(msg_scalars[undisclosed[k]], c)));
        write_sc(c);
        return Result<Ret>::ok(std::make_pair(std::move(proof), pseudonym));
    }

    // Map an octet string to a G1 point (RFC 9380 SSWU_RO) with an explicit DST.
    static blst_p1 hash_to_g1(std::span<const uint8_t> msg, std::span<const uint8_t> dst) {
        blst_p1 p;
        blst_hash_to_g1(&p, msg.data(), msg.size(), dst.data(), dst.size(), nullptr, 0);
        return p;
    }

    // ProofWithPseudonymChallengeCalculate (pvl §8.1): base proof challenge with
    // (pseudonym, Ut) inserted before domain and context_id appended.
    static blst_scalar pseudonym_proof_challenge(
            const std::vector<std::size_t>& disclosed_indexes,
            const std::vector<blst_scalar>& disclosed_scalars,
            const blst_p1& Abar, const blst_p1& Bbar, const blst_p1& D,
            const blst_p1& T1, const blst_p1& T2, const blst_p1& pseudonym, const blst_p1& Ut,
            const blst_scalar& domain, std::span<const uint8_t> ph,
            std::span<const uint8_t> context_id, std::string_view api_id) {
        std::vector<uint8_t> c;
        put_u64(c, static_cast<uint64_t>(disclosed_indexes.size()));
        for (std::size_t k = 0; k < disclosed_indexes.size(); ++k) {
            put_u64(c, static_cast<uint64_t>(disclosed_indexes[k]));
            put_scalar(c, disclosed_scalars[k]);
        }
        put_g1(c, Abar); put_g1(c, Bbar); put_g1(c, D); put_g1(c, T1); put_g1(c, T2);
        put_g1(c, pseudonym); put_g1(c, Ut);
        put_scalar(c, domain);
        put_u64(c, static_cast<uint64_t>(ph.size()));       put(c, ph);
        put_u64(c, static_cast<uint64_t>(context_id.size())); put(c, context_id);
        return hash_to_scalar(sv(c), sv(concat(api_id, "H2S_")));
    }

    // Verify a pseudonym-bound proof (pvl §7.2 CoreProofVerifyWithNym). `disclosed_*`
    // are the COMBINED signer+committed disclosures (committed index j passed as
    // j + L + 1). Returns true iff the proof + pseudonym verify.
    [[nodiscard]] static bool
    proof_verify_with_pseudonym(std::span<const uint8_t> pk, std::span<const uint8_t> proof,
            std::span<const uint8_t> header, std::span<const uint8_t> ph,
            std::span<const uint8_t> context_id, std::span<const uint8_t> pseudonym_bytes,
            std::size_t L, std::size_t length_nym_vector,
            const std::vector<std::span<const uint8_t>>& disclosed_messages,
            const std::vector<std::size_t>& disclosed_indexes, std::string_view api_id) {
        if (pk.size() != G2_BYTES || pseudonym_bytes.size() != G1_BYTES) return false;
        if (proof.size() < 3 * G1_BYTES + 4 * SCALAR_BYTES) return false;
        std::size_t rest = proof.size() - 3 * G1_BYTES - 3 * SCALAR_BYTES;
        if (rest % SCALAR_BYTES != 0) return false;
        std::size_t U = rest / SCALAR_BYTES - 1;
        const std::size_t R = disclosed_indexes.size();
        if (disclosed_messages.size() != R) return false;
        const std::size_t total = R + U;                    // total messages
        if (total < L + 1 + length_nym_vector || U < length_nym_vector) return false;
        const std::size_t M = total - L - 1 - length_nym_vector;

        blst_p1_affine Abar_a, Bbar_a, D_a;
        if (blst_p1_uncompress(&Abar_a, proof.data()) != BLST_SUCCESS) return false;
        if (blst_p1_uncompress(&Bbar_a, proof.data() + G1_BYTES) != BLST_SUCCESS) return false;
        if (blst_p1_uncompress(&D_a, proof.data() + 2 * G1_BYTES) != BLST_SUCCESS) return false;
        if (!blst_p1_affine_in_g1(&Abar_a) || !blst_p1_affine_in_g1(&Bbar_a) || !blst_p1_affine_in_g1(&D_a)) return false;
        blst_p1 Abar, Bbar, D;
        blst_p1_from_affine(&Abar, &Abar_a); blst_p1_from_affine(&Bbar, &Bbar_a); blst_p1_from_affine(&D, &D_a);

        const uint8_t* sc = proof.data() + 3 * G1_BYTES;
        auto read_sc = [&](std::size_t i) { blst_scalar s; blst_scalar_from_bendian(&s, sc + i * SCALAR_BYTES); return s; };
        blst_scalar e_hat = read_sc(0), r1_hat = read_sc(1), r3_hat = read_sc(2);
        std::vector<blst_scalar> commitments;
        for (std::size_t i = 0; i < U; ++i) commitments.push_back(read_sc(3 + i));
        blst_scalar c = read_sc(3 + U);
        for (const blst_scalar* s : { &e_hat, &r1_hat, &r3_hat, &c }) if (!blst_scalar_fr_check(s)) return false;
        for (const auto& m : commitments) if (!blst_scalar_fr_check(&m)) return false;

        blst_p2_affine W_aff;
        if (blst_p2_uncompress(&W_aff, pk.data()) != BLST_SUCCESS) return false;
        if (!blst_p2_affine_in_g2(&W_aff)) return false;
        blst_p1_affine nym_a;
        if (blst_p1_uncompress(&nym_a, pseudonym_bytes.data()) != BLST_SUCCESS) return false;
        if (!blst_p1_affine_in_g1(&nym_a)) return false;
        blst_p1 pseudonym; blst_p1_from_affine(&pseudonym, &nym_a);

        // Unified generators [Q_1, H_1..H_L, Q_2, J_1..J_{M+Nnym}].
        auto base_gens = create_generators(L + 1, api_id);
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(M + length_nym_vector + 1, blind_api);
        std::vector<blst_p1> gens = base_gens;
        for (const auto& bg : blind_gens) gens.push_back(bg);

        auto disclosed_scalars = messages_to_scalars(disclosed_messages, api_id);
        auto undisclosed = complement_indexes(disclosed_indexes, total);
        if (undisclosed.size() != U) return false;

        std::vector<uint8_t> hdr(header.begin(), header.end());
        put_u64(hdr, length_nym_vector);
        blst_scalar domain = calculate_domain(pk, gens, sv(hdr), api_id);

        blst_p1 T1 = p1_add(p1_add(p1_mult(Bbar, c), p1_mult(Abar, e_hat)), p1_mult(D, r1_hat));
        blst_p1 Bv = p1_add(p1_base(), p1_mult(gens[0], domain));
        for (std::size_t k = 0; k < R; ++k)
            Bv = p1_add(Bv, p1_mult(gens[disclosed_indexes[k] + 1], disclosed_scalars[k]));
        blst_p1 T2 = p1_add(p1_mult(Bv, c), p1_mult(D, r3_hat));
        for (std::size_t k = 0; k < U; ++k)
            T2 = p1_add(T2, p1_mult(gens[undisclosed[k] + 1], commitments[k]));

        // Pseudonym sigma: Uv = OP·poly(nym_secret_commitments) − pseudonym·c.
        blst_p1 OP = hash_to_g1(context_id, sv(std::vector<uint8_t>(api_id.begin(), api_id.end())));
        blst_scalar z = hash_to_scalar(context_id, concat(api_id, "VECT_NYM_SECRETS"));
        const std::size_t base = U - length_nym_vector;     // nym_secret_commitments = last Nnym
        blst_scalar poly = commitments[base], zn = z;
        for (std::size_t i = 1; i < length_nym_vector; ++i) {
            poly = sc_add(poly, sc_mul(commitments[base + i], zn));
            zn = sc_mul(zn, z);
        }
        blst_p1 Uv = p1_sub(p1_mult(OP, poly), p1_mult(pseudonym, c));

        blst_scalar c_prime = pseudonym_proof_challenge(disclosed_indexes, disclosed_scalars,
            Abar, Bbar, D, T1, T2, pseudonym, Uv, domain, ph, context_id, api_id);
        uint8_t cb[SCALAR_BYTES], cpb[SCALAR_BYTES];
        blst_bendian_from_scalar(cb, &c); blst_bendian_from_scalar(cpb, &c_prime);
        if (sodium_memcmp(cb, cpb, SCALAR_BYTES) != 0) return false;

        blst_p2 BP2 = *blst_p2_generator(), negBP2 = BP2;
        blst_p2_cneg(&negBP2, 1);
        blst_p2 W; blst_p2_from_affine(&W, &W_aff);
        blst_p1_affine Bbar_aff; blst_p1_to_affine(&Bbar_aff, &Bbar);
        blst_p2_affine W_a2, negBP2_a;
        blst_p2_to_affine(&W_a2, &W); blst_p2_to_affine(&negBP2_a, &negBP2);
        blst_fp12 ml1, ml2, prod;
        blst_miller_loop(&ml1, &W_a2, &Abar_a);
        blst_miller_loop(&ml2, &negBP2_a, &Bbar_aff);
        blst_fp12_mul(&prod, &ml1, &ml2);
        blst_final_exp(&prod, &prod);
        return blst_fp12_is_one(&prod);
    }

    // Pseudonym-proof domain (pvl §6.2/§7): generators = base_gens(L+1, api_id)
    // ++ blind_gens(M + length_nym_vector + 1, "BLIND_"||api_id); combined_header
    // = header || I2OSP(length_nym_vector, 8). Returns the 32-byte domain scalar
    // (big-endian) — a clean anchor for the unified generator layout.
    [[nodiscard]] static std::array<uint8_t, SCALAR_BYTES>
    pseudonym_proof_domain_for_test(std::span<const uint8_t> pk, std::span<const uint8_t> header,
            std::size_t L, std::size_t M, std::size_t length_nym_vector, std::string_view api_id) {
        auto base_gens = create_generators(L + 1, api_id);
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(M + length_nym_vector + 1, blind_api);
        std::vector<blst_p1> gens = base_gens;
        for (const auto& bg : blind_gens) gens.push_back(bg);
        std::vector<uint8_t> hdr(header.begin(), header.end());
        put_u64(hdr, length_nym_vector);
        blst_scalar dom = calculate_domain(pk, gens, sv(hdr), api_id);
        std::array<uint8_t, SCALAR_BYTES> out{};
        blst_bendian_from_scalar(out.data(), &dom);
        return out;
    }

    // CommitWithNym (pvl §6.1.1) for round-trip tests: commit to committed_messages
    // plus prover_nyms (raw scalars), returning the commitment_with_proof and the
    // secret_prover_blind (32-byte scalar) the holder keeps.
    struct CommitWithNymResult {
        std::vector<uint8_t> commitment_with_proof;
        std::array<uint8_t, SCALAR_BYTES> secret_prover_blind{};
    };
    [[nodiscard]] static CommitWithNymResult
    commit_with_nym_for_test(const std::vector<std::span<const uint8_t>>& committed_messages,
            const std::vector<std::span<const uint8_t>>& prover_nyms, std::string_view api_id,
            std::string_view mock_seed, std::string_view mock_dst) {
        auto scalars = messages_to_scalars(committed_messages, api_id);
        for (auto& pn : prover_nyms) { blst_scalar s; blst_scalar_from_bendian(&s, pn.data()); scalars.push_back(s); }
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(scalars.size() + 1, blind_api);
        auto rnd = mocked_random_scalars(scalars.size() + 2, mock_seed, mock_dst);
        CommitWithNymResult r;
        r.commitment_with_proof = core_commit(blind_gens, scalars, api_id, rnd);
        blst_bendian_from_scalar(r.secret_prover_blind.data(), &rnd[0]);
        return r;
    }

    // Production CommitWithNym (real randomness). Same as the test helper but the
    // (secret_prover_blind, s~, m~_i) scalars come from the OS CSPRNG.
    [[nodiscard]] static CommitWithNymResult
    commit_with_nym(const std::vector<std::span<const uint8_t>>& committed_messages,
                    const std::vector<std::span<const uint8_t>>& prover_nyms, std::string_view api_id) {
        auto scalars = messages_to_scalars(committed_messages, api_id);
        for (auto& pn : prover_nyms) { blst_scalar s; blst_scalar_from_bendian(&s, pn.data()); scalars.push_back(s); }
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(scalars.size() + 1, blind_api);
        std::vector<blst_scalar> rnd;
        for (std::size_t i = 0; i < scalars.size() + 2; ++i) rnd.push_back(random_scalar());
        CommitWithNymResult r;
        r.commitment_with_proof = core_commit(blind_gens, scalars, api_id, rnd);
        blst_bendian_from_scalar(r.secret_prover_blind.data(), &rnd[0]);
        return r;
    }

    // Standalone blind Commit (blind draft §4.1.1, non-pseudonym). Commits to
    // committed_messages with real CSPRNG randomness; returns the
    // commitment_with_proof (sent to the signer) and the secret_prover_blind the
    // holder keeps. This is commit_with_nym with an empty nym vector.
    [[nodiscard]] static CommitWithNymResult
    blind_commit(const std::vector<std::span<const uint8_t>>& committed_messages, std::string_view api_id) {
        return commit_with_nym(committed_messages, {}, api_id);
    }

    // VerifyBlindSign (blind draft §4.2.2): rebuild (generators, message_scalars)
    // via prepare_parameters (§6) then run CoreVerify. The signer messages use the
    // base generators [Q_1, H_1..H_L]; the secret_prover_blind (32-byte scalar)
    // and committed_messages use the blind generators [Q_2, J_1..J_C]. A
    // commitment is assumed present, so secret_prover_blind MUST be 32 bytes (the
    // spec's prepare_parameters only balances generators↔scalars when it is).
    [[nodiscard]] static bool
    verify_blind_sign(std::span<const uint8_t> pk, std::span<const uint8_t> signature,
                      std::span<const uint8_t> header,
                      const std::vector<std::span<const uint8_t>>& messages,
                      const std::vector<std::span<const uint8_t>>& committed_messages,
                      std::span<const uint8_t> secret_prover_blind, std::string_view api_id) {
        if (pk.size() != G2_BYTES || signature.size() != SIGNATURE_BYTES) return false;
        if (secret_prover_blind.size() != SCALAR_BYTES) return false;

        // Deserialize A and e.
        blst_p1_affine A_aff;
        if (blst_p1_uncompress(&A_aff, signature.data()) != BLST_SUCCESS) return false;
        if (!blst_p1_affine_in_g1(&A_aff)) return false;
        blst_scalar e;
        blst_scalar_from_bendian(&e, signature.data() + G1_BYTES);
        if (!blst_scalar_fr_check(&e)) return false;
        static const uint8_t zero[SCALAR_BYTES] = {};
        if (std::memcmp(signature.data() + G1_BYTES, zero, SCALAR_BYTES) == 0) return false;

        blst_p2_affine W_aff;
        if (blst_p2_uncompress(&W_aff, pk.data()) != BLST_SUCCESS) return false;
        if (!blst_p2_affine_in_g2(&W_aff)) return false;

        // prepare_parameters (§6): message_scalars = signer-scalars ++ [spb] ++
        // committed-scalars; generators = [Q_1,H_1..H_L] ++ [Q_2,J_1..J_C].
        const std::size_t L = messages.size();
        const std::size_t C = committed_messages.size();
        auto msg_scalars = messages_to_scalars(messages, api_id);
        blst_scalar spb; blst_scalar_from_bendian(&spb, secret_prover_blind.data());
        msg_scalars.push_back(spb);
        for (auto& cs : messages_to_scalars(committed_messages, api_id)) msg_scalars.push_back(cs);

        auto gens = create_generators(L + 1, api_id);
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(C + 1, blind_api);
        gens.insert(gens.end(), blind_gens.begin(), blind_gens.end());
        if (gens.size() != msg_scalars.size() + 1) return false;

        blst_scalar domain = calculate_domain(pk, gens, header, api_id);
        blst_p1 B = compute_B(gens, domain, msg_scalars);

        // e(A, W + BP2·e) · e(B, -BP2) == 1_GT
        blst_p2 BP2 = *blst_p2_generator();
        blst_p2 eBP2, WQ, W;
        blst_p2_mult(&eBP2, &BP2, e.b, 255);
        blst_p2_from_affine(&W, &W_aff);
        blst_p2_add_or_double(&WQ, &W, &eBP2);
        blst_p2 negBP2 = BP2;
        blst_p2_cneg(&negBP2, 1);

        blst_p1_affine B_aff;
        blst_p1_to_affine(&B_aff, &B);
        blst_p2_affine WQ_aff, negBP2_aff;
        blst_p2_to_affine(&WQ_aff, &WQ);
        blst_p2_to_affine(&negBP2_aff, &negBP2);

        blst_fp12 ml1, ml2, prod;
        blst_miller_loop(&ml1, &WQ_aff, &A_aff);
        blst_miller_loop(&ml2, &negBP2_aff, &B_aff);
        blst_fp12_mul(&prod, &ml1, &ml2);
        blst_final_exp(&prod, &prod);
        return blst_fp12_is_one(&prod);
    }

    // nym_secrets = prover_nyms with the LAST element += signer_nym_entropy
    // (pvl §6.1.3 VerifyFinalizeWithNym). Returns each as 32 big-endian bytes.
    [[nodiscard]] static std::vector<std::array<uint8_t, SCALAR_BYTES>>
    finalize_nym_secrets(const std::vector<std::span<const uint8_t>>& prover_nyms,
                         std::span<const uint8_t> signer_nym_entropy) {
        std::vector<std::array<uint8_t, SCALAR_BYTES>> out;
        blst_scalar ent; blst_scalar_from_bendian(&ent, signer_nym_entropy.data());
        for (std::size_t i = 0; i < prover_nyms.size(); ++i) {
            blst_scalar s; blst_scalar_from_bendian(&s, prover_nyms[i].data());
            if (i + 1 == prover_nyms.size()) s = sc_add(s, ent);
            std::array<uint8_t, SCALAR_BYTES> b{}; blst_bendian_from_scalar(b.data(), &s);
            out.push_back(b);
        }
        return out;
    }

    // Blind BBS signing (draft §4.2.1 BlindSign; the real B = P1 + Q_1·domain +
    // Σ H_i·msg_i + commitment — the prose B_calculate is shorthand). Produces the
    // 80-byte (A, e) signature. With signer_nym_entropy set, this is pvl §6.1.2
    // BlindSignWithNym: B += J_M·entropy and header ||= I2OSP(length_nym_vector,8).
    [[nodiscard]] static std::vector<uint8_t>
    blind_sign(std::span<const uint8_t> sk, std::span<const uint8_t> pk,
               std::span<const uint8_t> commitment_with_proof, std::span<const uint8_t> header,
               const std::vector<std::span<const uint8_t>>& messages, std::string_view api_id,
               std::span<const uint8_t> signer_nym_entropy = {}, uint64_t length_nym_vector = 0) {
        const std::size_t L = messages.size();
        const bool have_C = commitment_with_proof.size() >= G1_BYTES;
        const std::size_t M = commitment_with_proof.size() >= (G1_BYTES + 2 * SCALAR_BYTES)
            ? (commitment_with_proof.size() - G1_BYTES - 2 * SCALAR_BYTES) / SCALAR_BYTES : 0;

        auto base_gens = create_generators(L + 1, api_id);          // [Q_1, H_1..H_L]
        std::string blind_api = "BLIND_"; blind_api += api_id;
        auto blind_gens = create_generators(M + 1, blind_api);       // [Q_2, J_1..J_M]

        // Domain generator list = base_gens ++ blind_gens = [Q_1, H_1..H_L, Q_2,
        // J_1..J_M]. (The draft prose lists only (H..,J..) but the vectors include
        // Q_2 — validated byte-exact against §9.1.4.)
        std::vector<blst_p1> dom_gens = base_gens;
        for (const auto& bg : blind_gens) dom_gens.push_back(bg);

        // combined_header = header || I2OSP(length_nym_vector, 8) in nym mode.
        std::vector<uint8_t> hdr(header.begin(), header.end());
        if (!signer_nym_entropy.empty()) put_u64(hdr, length_nym_vector);
        blst_scalar domain = calculate_domain(pk, dom_gens, sv(hdr), api_id);

        auto msg_scalars = messages_to_scalars(messages, api_id);
        blst_p1 B = compute_B(base_gens, domain, msg_scalars);       // P1 + Q_1·domain + Σ H_i·msg
        if (have_C) {
            blst_p1_affine ca; blst_p1_uncompress(&ca, commitment_with_proof.data());
            blst_p1 C; blst_p1_from_affine(&C, &ca);
            B = p1_add(B, C);
        }
        if (!signer_nym_entropy.empty()) {
            blst_scalar ent; blst_scalar_from_bendian(&ent, signer_nym_entropy.data());
            B = p1_add(B, p1_mult(blind_gens.back(), ent));
        }
        // e = hash_to_scalar(SK || B, api_id||"H2S_"); A = B·(1/(SK+e)).
        // NB: domain is NOT in the e-input (the draft's serialize((SK,B,domain))
        // is misleading) — it is already bound via B = P1 + Q_1·domain + ...
        // Validated byte-exact against §9.1.4.
        std::vector<uint8_t> e_in(sk.begin(), sk.begin() + SCALAR_BYTES);
        put_g1(e_in, B);
        blst_scalar e = hash_to_scalar(sv(e_in), sv(concat(api_id, "H2S_")));
        blst_scalar sk_s; blst_scalar_from_bendian(&sk_s, sk.data());
        blst_p1 A = p1_mult(B, sc_inv(sc_add(sk_s, e)));
        std::vector<uint8_t> sig;
        put_g1(sig, A);
        put_scalar(sig, e);
        return sig;
    }

private:

    static std::vector<blst_scalar> messages_to_scalars(const std::vector<std::span<const uint8_t>>& messages) {
        auto map_dst = concat(API_ID, "MAP_MSG_TO_SCALAR_AS_HASH_");
        std::vector<blst_scalar> out;
        out.reserve(messages.size());
        for (const auto& m : messages) out.push_back(hash_to_scalar(m, sv(map_dst)));
        return out;
    }

    // dom_array = (L, Q_1, H_1..H_L); dom_octs = serialize(dom_array) || api_id
    // dom_input = PK || dom_octs || I2OSP(len(header),8) || header
    static blst_scalar calculate_domain(std::span<const uint8_t> pk, const std::vector<blst_p1>& gens,
                                        std::span<const uint8_t> header) {
        return calculate_domain(pk, gens, header, API_ID);
    }
    // api_id-parameterised (blind/pseudonym suites); gens = [Q_1, H_1..H_L, (J_1..J_M)].
    static blst_scalar calculate_domain(std::span<const uint8_t> pk, const std::vector<blst_p1>& gens,
                                        std::span<const uint8_t> header, std::string_view api_id) {
        const std::size_t L = gens.size() - 1;
        std::vector<uint8_t> dom;
        put(dom, pk);
        put_u64(dom, static_cast<uint64_t>(L));
        for (const auto& g : gens) put_g1(dom, g);
        put(dom, api_id);
        put_u64(dom, static_cast<uint64_t>(header.size()));
        put(dom, header);
        return hash_to_scalar(sv(dom), sv(concat(api_id, "H2S_")));
    }

    static void put_g1(std::vector<uint8_t>& v, const blst_p1& p) {
        uint8_t c[G1_BYTES];
        blst_p1_compress(c, &p);
        v.insert(v.end(), c, c + G1_BYTES);
    }

    // B = P1 + Q_1·domain + Σ H_i·msg_i
    static blst_p1 compute_B(const std::vector<blst_p1>& gens, const blst_scalar& domain,
                             const std::vector<blst_scalar>& msg_scalars) {
        blst_p1 B = p1_base();
        blst_p1 tmp;
        blst_p1_mult(&tmp, &gens[0], domain.b, 255); // Q_1·domain
        blst_p1_add_or_double(&B, &B, &tmp);
        for (std::size_t i = 0; i < msg_scalars.size(); ++i) {
            blst_p1_mult(&tmp, &gens[i + 1], msg_scalars[i].b, 255);
            blst_p1_add_or_double(&B, &B, &tmp);
        }
        return B;
    }

    static blst_p1 p1_base() {
        uint8_t bytes[G1_BYTES];
        for (std::size_t i = 0; i < G1_BYTES; ++i) {
            auto hx = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                return (c | 0x20) - 'a' + 10;
            };
            bytes[i] = static_cast<uint8_t>((hx(P1_HEX[2 * i]) << 4) | hx(P1_HEX[2 * i + 1]));
        }
        blst_p1_affine aff;
        blst_p1_uncompress(&aff, bytes);
        blst_p1 p;
        blst_p1_from_affine(&p, &aff);
        return p;
    }

    static SecureBuffer sk_to_pk_internal(const blst_scalar& sk) {
        blst_p2 pk;
        blst_sk_to_pk_in_g2(&pk, &sk);
        SecureBuffer out(G2_BYTES);
        blst_p2_compress(out.data(), &pk);
        return out;
    }
};

} // namespace crypto

#endif // CRYPTOLIB_HAS_BLS
