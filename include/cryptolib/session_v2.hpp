#pragma once
/**
 * crypto::SessionV2: the forward-secret ratchet with an authenticated
 * handshake (assessment r2, M6) over X-Wing (M4).
 *
 * The responder publishes a prekey bundle: its X-Wing public key signed by
 * its long-term identity (Ed25519 + ML-DSA-65), so an initiator cannot be
 * tricked into keying to an attacker's prekey. The initiator encapsulates
 * to it and sends a handshake that carries its own identity public key and
 * a signature over the prekey, the KEM ciphertext and both identities. The
 * root secret is derived with that whole transcript as HKDF info, so a
 * session is bound to the two identities on both sides. The responder
 * accepts only the identity it expects; pinning that identity (through a
 * directory, a certificate or a prior session) is the application's part
 * of the contract and is documented in the threat model.
 *
 * Wire: prekey bundle "RPK2" | kem_pub(1216) | sig_len(4 LE) | sig;
 * handshake "RTH2" | id_len(4 LE) | initiator_sig_pub | ct_len(4 LE) | ct
 * | sig_len(4 LE) | sig; messages "RTC2" with the ratchet header.
 */
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_OPENSSL)
#include "types.hpp"
#include "hash.hpp"
#include "hybrid_sig.hpp"
#include "ratchet.hpp"
#include "xwing.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

struct SessionWireV2 {
    static constexpr std::array<uint8_t, 4> MAGIC = {'R', 'T', 'C', '2'};
    static constexpr uint8_t VERSION = 2;
    static constexpr std::string_view L_INIT = "cryptolib/ratchet/init/v2";
    static constexpr std::string_view L_ROOT = "cryptolib/ratchet/root/v2";
    static constexpr std::string_view L_CHAIN = "cryptolib/ratchet/chain/v2";
    static constexpr std::string_view L_MSG  = "cryptolib/ratchet/msg/v2";
};

class SessionV2 {
public:
    using Kem = pq::XWing;
    using Sig = pq::HybridSig;
    using Channel = Ratchet<pq::XWing, SessionWireV2>;
    static constexpr std::array<uint8_t, 4> PREKEY_MAGIC = {'R', 'P', 'K', '2'};
    static constexpr std::array<uint8_t, 4> HANDSHAKE_MAGIC = {'R', 'T', 'H', '2'};
    static constexpr std::string_view L_PREKEY = "cryptolib/session/v2/prekey";
    static constexpr std::string_view L_HANDSHAKE = "cryptolib/session/v2/handshake";
    static constexpr std::string_view L_ROOT = "cryptolib/session/v2/root";

    struct Prekey { Kem::KeyPair pair; PublicBuffer bundle; };
    struct Initiated { Channel channel; PublicBuffer handshake; };

    /// Responder: a fresh X-Wing prekey signed by its identity key.
    [[nodiscard]] static Result<Prekey> generate_prekey(std::span<const uint8_t> responder_sig_secret) {
        auto kp = Kem::generate_keypair();
        if (kp.is_err()) return Result<Prekey>::err(kp.error().message);
        auto sig = Sig::sign(prekey_transcript(kp.value().public_key.span()), responder_sig_secret);
        if (sig.is_err()) return Result<Prekey>::err(sig.error().message);
        std::vector<uint8_t> b(PREKEY_MAGIC.begin(), PREKEY_MAGIC.end());
        b.insert(b.end(), kp.value().public_key.span().begin(), kp.value().public_key.span().end());
        put_lp(b, sig.value().span());
        return Result<Prekey>::ok(Prekey{ std::move(kp.value()), PublicBuffer(std::move(b)) });
    }

    /// The prekey public key inside a bundle, after its signature verified
    /// against [responder_sig_public].
    [[nodiscard]] static Result<PublicBuffer>
    verify_prekey(std::span<const uint8_t> bundle, std::span<const uint8_t> responder_sig_public) {
        if (bundle.size() < 4 + Kem::PK_BYTES + 4 || std::memcmp(bundle.data(), PREKEY_MAGIC.data(), 4) != 0)
            return Result<PublicBuffer>::err("SessionV2: bad prekey bundle");
        auto pk = bundle.subspan(4, Kem::PK_BYTES);
        std::span<const uint8_t> sig;
        if (!take_lp(bundle, 4 + Kem::PK_BYTES, sig)) return Result<PublicBuffer>::err("SessionV2: bad prekey bundle");
        if (Sig::verify(prekey_transcript(pk), sig, responder_sig_public).is_err())
            return Result<PublicBuffer>::err("SessionV2: prekey signature verification failed");
        return Result<PublicBuffer>::ok(PublicBuffer(pk.data(), pk.size()));
    }

    /// Initiator: verify the bundle, key to it, and sign the handshake with
    /// the initiator's identity.
    [[nodiscard]] static Result<Initiated>
    initiate(std::span<const uint8_t> bundle, std::span<const uint8_t> responder_sig_public,
             const Sig::KeyPair& initiator_identity) {
        auto pk = verify_prekey(bundle, responder_sig_public);
        if (pk.is_err()) return Result<Initiated>::err(pk.error().message);
        auto enc = Kem::encapsulate(pk.value().span());
        if (enc.is_err()) return Result<Initiated>::err(enc.error().message);
        auto ipub = initiator_identity.public_key.span();
        auto sig = Sig::sign(handshake_transcript(pk.value().span(), enc.value().ciphertext.span(),
                                                  responder_sig_public, ipub), initiator_identity.secret_key.span());
        if (sig.is_err()) return Result<Initiated>::err(sig.error().message);
        auto root = derive_root(enc.value().shared_secret.span(), pk.value().span(), enc.value().ciphertext.span(),
                                responder_sig_public, ipub);
        if (root.is_err()) return Result<Initiated>::err(root.error().message);
        auto channel = Channel::bootstrap_initiator(root.value().span(), pk.value().span());
        if (channel.is_err()) return Result<Initiated>::err(channel.error().message);
        std::vector<uint8_t> h(HANDSHAKE_MAGIC.begin(), HANDSHAKE_MAGIC.end());
        put_lp(h, ipub);
        put_lp(h, enc.value().ciphertext.span());
        put_lp(h, sig.value().span());
        return Result<Initiated>::ok(Initiated{ std::move(channel.value()), PublicBuffer(std::move(h)) });
    }

    /// The initiator identity a handshake claims, before any verification;
    /// use it to look up the expected identity, never to trust it.
    [[nodiscard]] static Result<PublicBuffer> claimed_initiator(std::span<const uint8_t> handshake) {
        std::span<const uint8_t> ipub, ct, sig;
        if (!parse_handshake(handshake, ipub, ct, sig)) return Result<PublicBuffer>::err("SessionV2: bad handshake");
        return Result<PublicBuffer>::ok(PublicBuffer(ipub.data(), ipub.size()));
    }

    /// Responder: accept a handshake only from [expected_initiator_sig_public].
    [[nodiscard]] static Result<Channel>
    accept(std::span<const uint8_t> handshake, const Prekey& prekey, const Sig::KeyPair& responder_identity,
           std::span<const uint8_t> expected_initiator_sig_public) {
        std::span<const uint8_t> ipub, ct, sig;
        if (!parse_handshake(handshake, ipub, ct, sig)) return Result<Channel>::err("SessionV2: bad handshake");
        if (expected_initiator_sig_public.empty() || ipub.size() != expected_initiator_sig_public.size() ||
            sodium_memcmp(ipub.data(), expected_initiator_sig_public.data(), ipub.size()) != 0)
            return Result<Channel>::err("SessionV2: initiator identity is not the expected one");
        auto pk = prekey.pair.public_key.span();
        auto rpub = responder_identity.public_key.span();
        if (Sig::verify(handshake_transcript(pk, ct, rpub, ipub), sig, ipub).is_err())
            return Result<Channel>::err("SessionV2: handshake signature verification failed");
        auto ss = Kem::decapsulate(ct, prekey.pair.secret_key.span());
        if (ss.is_err()) return Result<Channel>::err(ss.error().message);
        auto root = derive_root(ss.value().span(), pk, ct, rpub, ipub);
        if (root.is_err()) return Result<Channel>::err(root.error().message);
        return Channel::bootstrap_responder(root.value().span(), prekey.pair);
    }

private:
    static std::span<const uint8_t> label(std::string_view s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }
    static std::vector<uint8_t> prekey_transcript(std::span<const uint8_t> kem_pub) {
        std::vector<uint8_t> t(L_PREKEY.begin(), L_PREKEY.end());
        t.insert(t.end(), kem_pub.begin(), kem_pub.end());
        return t;
    }
    static std::vector<uint8_t> handshake_transcript(std::span<const uint8_t> kem_pub, std::span<const uint8_t> ct,
                                                     std::span<const uint8_t> rpub, std::span<const uint8_t> ipub) {
        std::vector<uint8_t> t(L_HANDSHAKE.begin(), L_HANDSHAKE.end());
        put_lp(t, kem_pub); put_lp(t, ct); put_lp(t, rpub); put_lp(t, ipub);
        return t;
    }
    static Result<SecureBuffer> derive_root(std::span<const uint8_t> ss, std::span<const uint8_t> kem_pub,
                                            std::span<const uint8_t> ct, std::span<const uint8_t> rpub,
                                            std::span<const uint8_t> ipub) {
        std::vector<uint8_t> info(L_ROOT.begin(), L_ROOT.end());
        put_lp(info, kem_pub); put_lp(info, ct); put_lp(info, rpub); put_lp(info, ipub);
        return hash::HkdfSha256::derive(ss, {}, std::string_view(reinterpret_cast<const char*>(info.data()), info.size()), 32);
    }
    static bool parse_handshake(std::span<const uint8_t> h, std::span<const uint8_t>& ipub,
                                std::span<const uint8_t>& ct, std::span<const uint8_t>& sig) {
        if (h.size() < 4 || std::memcmp(h.data(), HANDSHAKE_MAGIC.data(), 4) != 0) return false;
        std::size_t off = 4;
        if (!take_lp(h, off, ipub)) return false;
        off += 4 + ipub.size();
        if (!take_lp(h, off, ct)) return false;
        off += 4 + ct.size();
        if (!take_lp(h, off, sig)) return false;
        off += 4 + sig.size();
        return off == h.size() && ct.size() == Kem::CT_BYTES && !ipub.empty() && !sig.empty();
    }
    static void put_lp(std::vector<uint8_t>& v, std::span<const uint8_t> b) {
        uint32_t n = static_cast<uint32_t>(b.size());
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
        v.insert(v.end(), b.begin(), b.end());
    }
    static bool take_lp(std::span<const uint8_t> b, std::size_t off, std::span<const uint8_t>& out) {
        if (off > b.size() || b.size() - off < 4) return false;
        uint32_t n = 0;
        for (int i = 0; i < 4; ++i) n |= static_cast<uint32_t>(b[off + i]) << (8 * i);
        if (n > b.size() - off - 4) return false;
        out = b.subspan(off + 4, n);
        return true;
    }
};

}
#endif
