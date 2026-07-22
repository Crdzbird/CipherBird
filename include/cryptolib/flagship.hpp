#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Flagship / crypto::Fortress — state-of-the-art sealed messaging    ║
 * ║                                                                            ║
 * ║  Two tiers of the same construction — "encapsulate → key-commit → sign-     ║
 * ║  inside, recipient-bound" — differing only in the KEM and the signature:    ║
 * ║                                                                            ║
 * ║              KEM (confidentiality)         Signature (authenticity)         ║
 * ║   Flagship   X25519 + sntrup761            Ed25519 + ML-DSA-65              ║
 * ║   Fortress   X25519 + ML-KEM-768           Ed25519 + ML-DSA-65             ║
 * ║              + sntrup761 (triple)          + SLH-DSA (triple)              ║
 * ║                                                                            ║
 * ║  Every message is:                                                          ║
 * ║   • hybrid post-quantum confidential — secure while ANY one KEM leg holds  ║
 * ║   • hybrid post-quantum authentic — forgery needs breaking ALL sig legs    ║
 * ║   • key-committing (MolecularVault cascade: XChaCha20-Poly1305 ∘           ║
 * ║     AES-256-GCM-SIV) — no partitioning-oracle / multi-key ambiguity         ║
 * ║   • RECIPIENT-BOUND — the signature covers the recipient's public key, so   ║
 * ║     a decrypting recipient cannot re-encrypt and forward it as if you had   ║
 * ║     sent it to a third party (closes surreptitious forwarding)              ║
 * ║   • sign-then-encrypt — the sender's identity is hidden from passive        ║
 * ║     observers (the signature lives INSIDE the encryption)                   ║
 * ║   • AAD- and header-bound — the framing is authenticated                    ║
 * ║                                                                            ║
 * ║  Surface: creating (keypairs) · one-shot seal/open (auth-first) ·           ║
 * ║  streaming (StreamSealer/StreamOpener for large data) · inspect (public     ║
 * ║  metadata + recipient addressing, no secrets).                              ║
 * ║                                                                            ║
 * ║  No new cryptography — composition of vetted primitives with strict domain  ║
 * ║  separation. Library-native wire format, NOT a standard (X-Wing/TLS/PGP).   ║
 * ║                                                                            ║
 * ║  Boundaries (by design): static-recipient KEM ⇒ NOT forward-secret against  ║
 * ║  recipient long-term-key compromise (correct for at-rest / store-and-       ║
 * ║  forward; layer a ratchet for live FS). Streaming gives per-chunk integrity ║
 * ║  immediately but sender-authenticity only at finalize (inherent to one-pass ║
 * ║  streaming) — use the one-shot API when you need auth-before-use.           ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#if defined(CRYPTOLIB_HAS_OPENSSL) && defined(CRYPTOLIB_HAS_PQ)

#include "types.hpp"
#include "molecular_vault.hpp"
#include "sntrup_x25519.hpp"
#include "triple_hybrid_kem.hpp"
#include "hybrid_sig.hpp"
#include "triple_sig.hpp"
#include "hash.hpp"        // Blake2b, HkdfSha256
#include "symmetric.hpp"   // SecretStream

#include <sodium.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {
namespace detail {

// SealedProtocol<Kem, Sig, SuiteId> — the shared implementation of both tiers.
// Kem/Sig must expose the CryptoLib hybrid interface (generate_keypair,
// encapsulate/decapsulate or sign/verify, KeyPair{public_key,secret_key}).
template <class Kem, class Sig, uint8_t SuiteId>
class SealedProtocol {
public:
    using RecipientKeyPair = typename Kem::KeyPair;
    using SenderKeyPair    = typename Sig::KeyPair;

    static constexpr uint8_t     VERSION  = 1;
    static constexpr uint8_t     SUITE    = SuiteId;
    static constexpr std::size_t FP_BYTES = 16;   // recipient fingerprint

    // ── Creating ────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<RecipientKeyPair> generate_recipient() { return Kem::generate_keypair(); }
    [[nodiscard]] static Result<SenderKeyPair>    generate_sender()    { return Sig::generate_keypair(); }

    // A public 16-byte BLAKE2b fingerprint of a recipient public key — for
    // addressing/routing without revealing anything secret.
    [[nodiscard]] static std::array<uint8_t, FP_BYTES>
    fingerprint(std::span<const uint8_t> recipient_public) {
        std::array<uint8_t, FP_BYTES> fp{};
        auto d = hash::Blake2b::digest(recipient_public);
        if (d.is_ok()) std::memcpy(fp.data(), d.value().data(), FP_BYTES);
        return fp;
    }

    // ── Proof / inspection (no secret material touched) ──────────────────────
    struct EnvelopeInfo {
        uint8_t version;
        uint8_t suite;                                  // == SUITE for this tier
        bool    streaming;                              // one-shot vs stream preamble
        std::array<uint8_t, FP_BYTES> recipient_fingerprint;
        std::size_t kem_ciphertext_len;
    };

    [[nodiscard]] static Result<EnvelopeInfo> inspect(std::span<const uint8_t> envelope) {
        bool streaming = false;
        Head h;
        if (auto e = parse_head(MAGIC_ONESHOT, envelope, h); e.is_ok()) streaming = false;
        else if (auto e2 = parse_head(MAGIC_STREAM, envelope, h); e2.is_ok()) streaming = true;
        else return Result<EnvelopeInfo>::err("Flagship: not a recognizable envelope");
        EnvelopeInfo info{h.version, h.suite, streaming, h.fp, h.kem_ct.size()};
        return Result<EnvelopeInfo>::ok(info);
    }

    // True iff the envelope is addressed to this recipient (fingerprint match).
    [[nodiscard]] static bool
    addressed_to(std::span<const uint8_t> envelope, std::span<const uint8_t> recipient_public) {
        auto info = inspect(envelope);
        if (info.is_err()) return false;
        auto fp = fingerprint(recipient_public);
        return sodium_memcmp(info.value().recipient_fingerprint.data(), fp.data(), FP_BYTES) == 0;
    }

    // ── One-shot seal / open ─────────────────────────────────────────────────
    // seal: sign-then-encrypt, recipient-bound. `purpose` is an optional domain
    // label bound into the signature (e.g. "invoice", "session-key").
    [[nodiscard]] static Result<SecureBuffer>
    seal(std::span<const uint8_t> plaintext,
         std::span<const uint8_t> recipient_public,
         std::span<const uint8_t> sender_secret,
         std::span<const uint8_t> aad = {},
         std::span<const uint8_t> purpose = {}) {
        auto enc = Kem::encapsulate(recipient_public);
        if (enc.is_err()) return Result<SecureBuffer>::err(enc.error().message);

        auto to_sign = sig_transcript(DS_SIG, recipient_public, purpose, plaintext);
        auto sig = Sig::sign(to_sign, sender_secret);
        if (sig.is_err()) return Result<SecureBuffer>::err(sig.error().message);

        // inner = sig_len | signature | plaintext
        std::vector<uint8_t> inner;
        inner.reserve(4 + sig.value().size() + plaintext.size());
        put_lp(inner, sig.value().span());
        inner.insert(inner.end(), plaintext.begin(), plaintext.end());

        std::vector<uint8_t> head = build_head(MAGIC_ONESHOT, recipient_public, enc.value().ciphertext.span());
        std::vector<uint8_t> vaad = concat(head, aad);   // bind framing into the AEAD

        auto env = MolecularVault::seal_with_key(inner, enc.value().shared_secret.span(), vaad);
        sodium_memzero(inner.data(), inner.size());
        if (env.is_err()) return env;

        SecureBuffer out(head.size() + env.value().size());
        std::memcpy(out.data(), head.data(), head.size());
        std::memcpy(out.data() + head.size(), env.value().data(), env.value().size());
        return Result<SecureBuffer>::ok(std::move(out));
    }

    // open: decrypt, then verify AUTH-FIRST. Needs the recipient's OWN public key
    // to reconstruct (and thus check) the recipient binding.
    [[nodiscard]] static Result<SecureBuffer>
    open(std::span<const uint8_t> envelope,
         std::span<const uint8_t> recipient_secret,
         std::span<const uint8_t> recipient_public,
         std::span<const uint8_t> sender_public,
         std::span<const uint8_t> aad = {},
         std::span<const uint8_t> purpose = {}) {
        Head h;
        if (auto e = parse_head(MAGIC_ONESHOT, envelope, h); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);
        if (h.suite != SUITE)
            return Result<SecureBuffer>::err("Flagship: wrong suite/tier for this envelope");

        auto ss = Kem::decapsulate(h.kem_ct, recipient_secret);
        if (ss.is_err()) return Result<SecureBuffer>::err(ss.error().message);

        auto head = envelope.first(h.head_len);
        std::vector<uint8_t> vaad = concat(head, aad);
        auto inner = MolecularVault::open_with_key(envelope.subspan(h.head_len), ss.value().span(), vaad);
        if (inner.is_err()) return inner;

        auto s = inner.value().span();
        if (s.size() < 4) return Result<SecureBuffer>::err("Flagship: inner truncated");
        const uint32_t sig_len = get_u32(s.data());
        if (s.size() < 4u + sig_len) return Result<SecureBuffer>::err("Flagship: inner truncated");
        auto sig = s.subspan(4, sig_len);
        auto pt  = s.subspan(4 + sig_len);

        // AUTH-FIRST: recipient-bound signature must verify before returning plaintext.
        auto to_sign = sig_transcript(DS_SIG, recipient_public, purpose, pt);
        if (Sig::verify(to_sign, sig, sender_public).is_err())
            return Result<SecureBuffer>::err("Flagship: signature verification failed");
        return Result<SecureBuffer>::ok(SecureBuffer(pt.data(), pt.size()));
    }

    // ── Streaming (large data / files) ───────────────────────────────────────
    // Wire: preamble  = head(MAGIC_STREAM) ‖ stream_header(24)
    //       chunks    = caller-framed SecretStream ciphertexts (each MAC'd)
    //       trailer   = "SEAT" ‖ sig_len(4) ‖ signature  (over the transcript)
    // Per-chunk integrity is immediate; the sender signature over the running
    // transcript (preamble ‖ all ciphertext chunks) is verified at finalize.
    class StreamSealer {
    public:
        [[nodiscard]] static Result<StreamSealer>
        begin(std::span<const uint8_t> recipient_public,
              std::span<const uint8_t> sender_secret,
              std::span<const uint8_t> purpose = {}) {
            auto enc = Kem::encapsulate(recipient_public);
            if (enc.is_err()) return Result<StreamSealer>::err(enc.error().message);
            auto sk = derive_stream_key(enc.value().shared_secret.span());
            if (sk.is_err()) return Result<StreamSealer>::err(sk.error().message);

            auto encr = std::make_unique<symmetric::SecretStream::Encryptor>(sk.value().span());
            std::vector<uint8_t> pre = build_head(MAGIC_STREAM, recipient_public, enc.value().ciphertext.span());
            pre.insert(pre.end(), encr->header().span().begin(), encr->header().span().end());

            auto ts = std::make_unique<hash::Blake2b::Stream>();
            ts->update(pre);

            return Result<StreamSealer>::ok(StreamSealer(
                std::move(encr), std::move(ts), SecureBuffer(pre),
                SecureBuffer(sender_secret.data(), sender_secret.size()),
                SecureBuffer(recipient_public.data(), recipient_public.size()),
                std::vector<uint8_t>(purpose.begin(), purpose.end())));
        }

        [[nodiscard]] const SecureBuffer& preamble() const noexcept { return preamble_; }

        // Encrypt one interior chunk → returns its ciphertext (store/transmit it).
        [[nodiscard]] Result<SecureBuffer> push(std::span<const uint8_t> chunk) {
            if (finalized_) return Result<SecureBuffer>::err("Flagship: stream already finalized");
            auto ct = encryptor_->push(chunk);
            transcript_->update(ct.span());
            return Result<SecureBuffer>::ok(std::move(ct));
        }

        struct Final { SecureBuffer ciphertext; SecureBuffer trailer; };
        // Encrypt the final chunk (may be empty) and emit the signed trailer.
        [[nodiscard]] Result<Final> finalize(std::span<const uint8_t> last_chunk = {}) {
            if (finalized_) return Result<Final>::err("Flagship: stream already finalized");
            finalized_ = true;
            auto ct = encryptor_->push_final(last_chunk);
            transcript_->update(ct.span());
            auto digest = transcript_->finalize();

            auto to_sign = sig_transcript(DS_STREAM_SIG, recipient_public_.span(), purpose_, digest.span());
            auto sig = Sig::sign(to_sign, sender_secret_.span());
            if (sig.is_err()) return Result<Final>::err(sig.error().message);

            std::vector<uint8_t> tr(MAGIC_TRAILER.begin(), MAGIC_TRAILER.end());
            put_lp(tr, sig.value().span());
            return Result<Final>::ok(Final{ std::move(ct), SecureBuffer(std::move(tr)) });
        }

    private:
        StreamSealer(std::unique_ptr<symmetric::SecretStream::Encryptor> e,
                     std::unique_ptr<hash::Blake2b::Stream> t,
                     SecureBuffer pre, SecureBuffer sec, SecureBuffer rpub, std::vector<uint8_t> purpose)
            : encryptor_(std::move(e)), transcript_(std::move(t)), preamble_(std::move(pre)),
              sender_secret_(std::move(sec)), recipient_public_(std::move(rpub)), purpose_(std::move(purpose)) {}
        std::unique_ptr<symmetric::SecretStream::Encryptor> encryptor_;
        std::unique_ptr<hash::Blake2b::Stream> transcript_;
        SecureBuffer preamble_, sender_secret_, recipient_public_;
        std::vector<uint8_t> purpose_;
        bool finalized_ = false;
    };

    class StreamOpener {
    public:
        [[nodiscard]] static Result<StreamOpener>
        begin(std::span<const uint8_t> preamble,
              std::span<const uint8_t> recipient_secret,
              std::span<const uint8_t> recipient_public,
              std::span<const uint8_t> sender_public,
              std::span<const uint8_t> purpose = {}) {
            Head h;
            if (auto e = parse_head(MAGIC_STREAM, preamble, h); e.is_err())
                return Result<StreamOpener>::err(e.error().message);
            if (h.suite != SUITE)
                return Result<StreamOpener>::err("Flagship: wrong suite/tier for this stream");
            auto after = preamble.subspan(h.head_len);
            if (after.size() != symmetric::SecretStream::HEADER_BYTES)
                return Result<StreamOpener>::err("Flagship: malformed stream preamble");

            auto ss = Kem::decapsulate(h.kem_ct, recipient_secret);
            if (ss.is_err()) return Result<StreamOpener>::err(ss.error().message);
            auto sk = derive_stream_key(ss.value().span());
            if (sk.is_err()) return Result<StreamOpener>::err(sk.error().message);

            auto decr = std::make_unique<symmetric::SecretStream::Decryptor>(sk.value().span(), after);
            auto ts = std::make_unique<hash::Blake2b::Stream>();
            ts->update(preamble);

            return Result<StreamOpener>::ok(StreamOpener(
                std::move(decr), std::move(ts),
                SecureBuffer(recipient_public.data(), recipient_public.size()),
                SecureBuffer(sender_public.data(), sender_public.size()),
                std::vector<uint8_t>(purpose.begin(), purpose.end())));
        }

        struct Chunk { SecureBuffer plaintext; bool final; };
        // Decrypt one ciphertext chunk. `final` is true on the terminating chunk.
        [[nodiscard]] Result<Chunk> pull(std::span<const uint8_t> ciphertext) {
            if (verified_) return Result<Chunk>::err("Flagship: stream already finalized");
            transcript_->update(ciphertext);
            auto r = decryptor_->pull(ciphertext);
            if (r.is_err()) return Result<Chunk>::err(r.error().message);
            bool fin = (r.value().tag == symmetric::SecretStream::TAG_FINAL);
            if (fin) saw_final_ = true;
            return Result<Chunk>::ok(Chunk{ std::move(r.value().plaintext), fin });
        }

        // Verify the sender's signature over the whole stream. Only valid after
        // the FINAL chunk has been pulled (guards against truncation).
        [[nodiscard]] Result<void> finalize(std::span<const uint8_t> trailer) {
            if (!saw_final_) return Result<void>::err("Flagship: stream truncated (no FINAL chunk)");
            if (verified_)   return Result<void>::err("Flagship: stream already finalized");
            constexpr std::size_t HDR = 4 + 4;
            if (trailer.size() < HDR ||
                sodium_memcmp(trailer.data(), MAGIC_TRAILER.data(), 4) != 0)
                return Result<void>::err("Flagship: bad stream trailer");
            const uint32_t sig_len = get_u32(trailer.data() + 4);
            if (trailer.size() < HDR + sig_len)
                return Result<void>::err("Flagship: stream trailer truncated");
            auto sig = trailer.subspan(HDR, sig_len);

            auto digest = transcript_->finalize();
            verified_ = true;
            auto to_sign = sig_transcript(DS_STREAM_SIG, recipient_public_.span(), purpose_, digest.span());
            if (Sig::verify(to_sign, sig, sender_public_.span()).is_err())
                return Result<void>::err("Flagship: stream signature verification failed");
            return Result<void>::ok();
        }

    private:
        StreamOpener(std::unique_ptr<symmetric::SecretStream::Decryptor> d,
                     std::unique_ptr<hash::Blake2b::Stream> t,
                     SecureBuffer rpub, SecureBuffer spub, std::vector<uint8_t> purpose)
            : decryptor_(std::move(d)), transcript_(std::move(t)),
              recipient_public_(std::move(rpub)), sender_public_(std::move(spub)), purpose_(std::move(purpose)) {}
        std::unique_ptr<symmetric::SecretStream::Decryptor> decryptor_;
        std::unique_ptr<hash::Blake2b::Stream> transcript_;
        SecureBuffer recipient_public_, sender_public_;
        std::vector<uint8_t> purpose_;
        bool saw_final_ = false;
        bool verified_  = false;
    };

private:
    static constexpr std::array<uint8_t, 4> MAGIC_ONESHOT = {'S', 'E', 'A', 'L'};
    static constexpr std::array<uint8_t, 4> MAGIC_STREAM  = {'S', 'E', 'A', 'M'};
    static constexpr std::array<uint8_t, 4> MAGIC_TRAILER = {'S', 'E', 'A', 'T'};
    static constexpr std::string_view DS_SIG        = "cryptolib/flagship/sig/v1";
    static constexpr std::string_view DS_STREAM_SIG = "cryptolib/flagship/stream-sig/v1";
    static constexpr std::string_view DS_STREAM_KEY = "cryptolib/flagship/stream-key/v1";
    static constexpr std::size_t HEAD_FIXED = 4 + 1 + 1 + FP_BYTES + 4; // magic|ver|suite|fp|ct_len

    static void put_u32(std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
    static uint32_t get_u32(const uint8_t* p) {
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= static_cast<uint32_t>(p[i]) << (8 * i);
        return x;
    }
    static void put_lp(std::vector<uint8_t>& v, std::span<const uint8_t> s) {
        put_u32(v, static_cast<uint32_t>(s.size()));
        v.insert(v.end(), s.begin(), s.end());
    }
    static std::vector<uint8_t> concat(std::span<const uint8_t> a, std::span<const uint8_t> b) {
        std::vector<uint8_t> out;
        out.reserve(a.size() + b.size());
        out.insert(out.end(), a.begin(), a.end());
        out.insert(out.end(), b.begin(), b.end());
        return out;
    }
    static std::span<const uint8_t> label(std::string_view s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }

    // head = magic | ver | suite | fp(recipient_public) | kem_ct_len(4) | kem_ct
    static std::vector<uint8_t>
    build_head(const std::array<uint8_t, 4>& magic,
               std::span<const uint8_t> recipient_public, std::span<const uint8_t> kem_ct) {
        std::vector<uint8_t> h;
        h.reserve(HEAD_FIXED + kem_ct.size());
        h.insert(h.end(), magic.begin(), magic.end());
        h.push_back(VERSION);
        h.push_back(SUITE);
        auto fp = fingerprint(recipient_public);
        h.insert(h.end(), fp.begin(), fp.end());
        put_u32(h, static_cast<uint32_t>(kem_ct.size()));
        h.insert(h.end(), kem_ct.begin(), kem_ct.end());
        return h;
    }

    struct Head {
        uint8_t version, suite;
        std::array<uint8_t, FP_BYTES> fp;
        std::span<const uint8_t> kem_ct;
        std::size_t head_len;
    };
    static Result<void>
    parse_head(const std::array<uint8_t, 4>& magic, std::span<const uint8_t> env, Head& out) {
        if (env.size() < HEAD_FIXED) return Result<void>::err("Flagship: envelope too short");
        if (std::memcmp(env.data(), magic.data(), 4) != 0)
            return Result<void>::err("Flagship: bad magic (wrong envelope type)");
        out.version = env[4];
        if (out.version != VERSION) return Result<void>::err("Flagship: unsupported version");
        out.suite = env[5];
        std::memcpy(out.fp.data(), env.data() + 6, FP_BYTES);
        const uint32_t ct_len = get_u32(env.data() + 6 + FP_BYTES);
        if (env.size() < HEAD_FIXED + ct_len) return Result<void>::err("Flagship: envelope truncated");
        out.kem_ct  = env.subspan(HEAD_FIXED, ct_len);
        out.head_len = HEAD_FIXED + ct_len;
        return Result<void>::ok();
    }

    // to_sign = ds ‖ suite ‖ lp(recipient_public) ‖ lp(purpose) ‖ payload
    static std::vector<uint8_t>
    sig_transcript(std::string_view ds, std::span<const uint8_t> recipient_public,
                   std::span<const uint8_t> purpose, std::span<const uint8_t> payload) {
        std::vector<uint8_t> t;
        auto dl = label(ds);
        t.insert(t.end(), dl.begin(), dl.end());
        t.push_back(SUITE);
        put_lp(t, recipient_public);
        put_lp(t, purpose);
        t.insert(t.end(), payload.begin(), payload.end());
        return t;
    }

    static Result<SecureBuffer> derive_stream_key(std::span<const uint8_t> shared_secret) {
        auto prk = hash::HkdfSha256::extract(label(DS_STREAM_KEY), shared_secret);
        if (prk.is_err()) return Result<SecureBuffer>::err(prk.error().message);
        std::array<uint8_t, 1> info{ SUITE };
        return hash::HkdfSha256::expand(prk.value().span(), info, symmetric::SecretStream::KEY_BYTES);
    }
};

} // namespace detail

// ── The two flagships ────────────────────────────────────────────────────────
// Recommended default: X25519+sntrup761 KEM, Ed25519+ML-DSA-65 signature.
class Flagship : public detail::SealedProtocol<pq::SntrupX25519, pq::HybridSig, 0x01> {};
// Maximum assurance: triple-hybrid KEM (adds ML-KEM-768) + triple signature
// (adds hash-based SLH-DSA). Larger and slower; no single cryptanalytic point
// of failure on either the confidentiality or the authenticity axis.
class Fortress : public detail::SealedProtocol<pq::TripleHybridKem, pq::TripleSig, 0x02> {};

} // namespace crypto

#endif // CRYPTOLIB_HAS_OPENSSL && CRYPTOLIB_HAS_PQ
