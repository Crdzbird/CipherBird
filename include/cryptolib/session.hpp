#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Session — post-quantum forward-secret ratchet (hybrid KEM Double     ║
 * ║  Ratchet)                                                                    ║
 * ║                                                                            ║
 * ║  Where Flagship/Fortress seal to a STATIC recipient key (not forward-secret ║
 * ║  against key compromise), a Session is a live, back-and-forth channel with:  ║
 * ║    • FORWARD SECRECY   — compromising the state does not reveal past msgs   ║
 * ║    • POST-COMPROMISE SECURITY (healing) — the channel recovers after a      ║
 * ║      one-time state leak, once each side ratchets again                     ║
 * ║  and both hold POST-QUANTUM, because the asymmetric ratchet is the library's ║
 * ║  hybrid KEM (X25519 + ML-KEM-768) — secure while either leg stands.          ║
 * ║                                                                            ║
 * ║  It is the Signal Double Ratchet structure (root ratchet + per-message      ║
 * ║  symmetric chain ratchet + skipped-key handling for out-of-order delivery)  ║
 * ║  with the Diffie–Hellman step replaced by KEM encapsulate/decapsulate, and   ║
 * ║  each message key used with the KEY-COMMITTING AEAD. Composition of vetted   ║
 * ║  primitives — no new cryptography; domain-separated HKDF throughout.         ║
 * ║                                                                            ║
 * ║  Handshake (PQ X3DH-lite): the responder publishes a prekey (a hybrid-KEM    ║
 * ║  public key); the initiator encapsulates to it to agree the root secret and  ║
 * ║  bootstrap the ratchet.                                                      ║
 * ║                                                                            ║
 * ║    Bob:   kp   = Session::generate_prekey();  publish kp.public_key          ║
 * ║    Alice: hs   = Session::initiate(kp.public_key);  send hs.handshake        ║
 * ║           msg  = hs.session.encrypt(plaintext)                               ║
 * ║    Bob:   sess = Session::accept(hs.handshake, kp);                          ║
 * ║           pt   = sess.decrypt(msg)                                           ║
 * ║                                                                            ║
 * ║  Message wire: "RTC1" | ver | ratchet_pub | kem_ct | PN | N | committing-ct  ║
 * ║  (the header is authenticated as AEAD associated data).                      ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#ifdef CRYPTOLIB_HAS_PQ

#include "types.hpp"
#include "hybrid_kem.hpp"   // crypto::pq::HybridKem  (X25519 + ML-KEM-768)
#include "hash.hpp"         // HkdfSha256, Blake2b
#include "committing.hpp"   // crypto::symmetric::CommittingAead

#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto {

class Session {
public:
    using Kem = pq::HybridKem;

    // Bound on how many skipped (out-of-order) message keys are retained. Beyond
    // this, a gap that large is treated as an attack / unrecoverable loss.
    static constexpr std::size_t MAX_SKIP = 1024;

    // ── Handshake ─────────────────────────────────────────────────────────────
    /// Responder: generate a prekey (a hybrid-KEM keypair). Publish public_key;
    /// keep the pair to accept() an incoming handshake.
    [[nodiscard]] static Result<Kem::KeyPair> generate_prekey() {
        return Kem::generate_keypair();
    }

    /// Initiator: agree a root secret with `responder_prekey_public` and bootstrap
    /// the ratchet. The returned session carries the handshake() message to send
    /// to the responder (via Session::accept) before / alongside the first message.
    [[nodiscard]] static Result<Session>
    initiate(std::span<const uint8_t> responder_prekey_public) {
        auto enc = Kem::encapsulate(responder_prekey_public);
        if (enc.is_err()) return Result<Session>::err(enc.error().message);
        auto sk = derive_root(enc.value().shared_secret.span());
        if (sk.is_err()) return Result<Session>::err(sk.error().message);

        Session s;
        if (auto e = s.init_initiator(sk.value().span(), responder_prekey_public); e.is_err())
            return Result<Session>::err(e.error().message);
        s.handshake_ = SecureBuffer(enc.value().ciphertext.span().data(),
                                    enc.value().ciphertext.span().size());
        return Result<Session>::ok(std::move(s));
    }

    /// The handshake message to hand to the responder's accept(). Only set on an
    /// initiator session (empty on a responder).
    [[nodiscard]] const SecureBuffer& handshake() const noexcept { return handshake_; }

    /// Responder: accept an incoming handshake with your prekey pair.
    [[nodiscard]] static Result<Session>
    accept(std::span<const uint8_t> handshake, const Kem::KeyPair& prekey) {
        auto ss = Kem::decapsulate(handshake, prekey.secret_key.span());
        if (ss.is_err()) return Result<Session>::err(ss.error().message);
        auto sk = derive_root(ss.value().span());
        if (sk.is_err()) return Result<Session>::err(sk.error().message);

        Session s;
        if (auto e = s.init_responder(sk.value().span(), prekey); e.is_err())
            return Result<Session>::err(e.error().message);
        return Result<Session>::ok(std::move(s));
    }

    // ── Messaging ─────────────────────────────────────────────────────────────
    /// Encrypt the next outgoing message. Advances the sending ratchet. `aad` is
    /// bound (authenticated) alongside the message header.
    [[nodiscard]] Result<SecureBuffer>
    encrypt(std::span<const uint8_t> plaintext, std::span<const uint8_t> aad = {}) {
        if (cks_.span().empty())
            return Result<SecureBuffer>::err("Session: no sending chain yet (responder must receive first)");
        auto mk = advance_chain(cks_);
        if (mk.is_err()) return Result<SecureBuffer>::err(mk.error().message);

        std::vector<uint8_t> header = serialize_header(dhs_pub_.span(), pending_ct_.span(), pn_, ns_);
        ns_ += 1;

        std::vector<uint8_t> full_aad(header.begin(), header.end());
        full_aad.insert(full_aad.end(), aad.begin(), aad.end());
        auto body = symmetric::CommittingAead::encrypt(plaintext, mk.value().span(), full_aad);
        if (body.is_err()) return body;

        std::vector<uint8_t> out(header);
        put_u32(out, static_cast<uint32_t>(body.value().size()));
        out.insert(out.end(), body.value().span().begin(), body.value().span().end());
        return Result<SecureBuffer>::ok(SecureBuffer(std::move(out)));
    }

    /// Decrypt an incoming message. Handles ratchet turns and out-of-order /
    /// skipped messages. TRANSACTIONAL: on any authentication failure the ratchet
    /// state is left exactly as it was, so a malformed/injected message cannot
    /// desync the channel (fails closed, no plaintext).
    [[nodiscard]] Result<SecureBuffer>
    decrypt(std::span<const uint8_t> message, std::span<const uint8_t> aad = {}) {
        Header h;
        if (auto e = parse_header(message, h); e.is_err())
            return Result<SecureBuffer>::err(e.error().message);

        std::vector<uint8_t> full_aad(h.header_bytes.begin(), h.header_bytes.end());
        full_aad.insert(full_aad.end(), aad.begin(), aad.end());

        // 1. A message from a chain we already ratchet-stepped past. Decrypt with
        //    the stored key WITHOUT removing it; only consume it on success.
        auto sk = std::make_pair(fingerprint(h.pub), h.n);
        if (auto it = skipped_.find(sk); it != skipped_.end()) {
            auto pt = symmetric::CommittingAead::decrypt(h.body, it->second.span(), full_aad);
            if (pt.is_ok()) skipped_.erase(it);
            return pt;
        }

        // 2. Main path — run the ratchet on a snapshot; commit only if the message
        //    authenticates, otherwise roll back (including any skipped keys added).
        Snapshot snap = take_snapshot();
        std::set<SkipKey> before;
        for (const auto& kv : skipped_) before.insert(kv.first);

        auto attempt = [&]() -> Result<SecureBuffer> {
            if (!same_pub(h.pub)) {
                if (auto e = skip_message_keys(h.pn); e.is_err())
                    return Result<SecureBuffer>::err(e.error().message);
                if (auto e = dh_ratchet(h.pub, h.ct); e.is_err())
                    return Result<SecureBuffer>::err(e.error().message);
            }
            if (auto e = skip_message_keys(h.n); e.is_err())
                return Result<SecureBuffer>::err(e.error().message);
            auto mk = advance_chain(ckr_);
            if (mk.is_err()) return Result<SecureBuffer>::err(mk.error().message);
            nr_ += 1;
            return symmetric::CommittingAead::decrypt(h.body, mk.value().span(), full_aad);
        };

        auto pt = attempt();
        if (pt.is_err()) {
            restore_snapshot(std::move(snap));
            for (auto it = skipped_.begin(); it != skipped_.end();)
                it = before.count(it->first) ? std::next(it) : skipped_.erase(it);
        }
        return pt;
    }

    // Move-only (holds ratchet secrets).
    Session(Session&&) = default;
    Session& operator=(Session&&) = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

private:
    Session() = default;

    static constexpr std::array<uint8_t, 4> MAGIC = {'R', 'T', 'C', '1'};
    static constexpr uint8_t VERSION = 1;
    static constexpr std::string_view L_INIT = "cryptolib/ratchet/init/v1";
    static constexpr std::string_view L_ROOT = "cryptolib/ratchet/root/v1";
    static constexpr std::string_view L_CHAIN = "cryptolib/ratchet/chain/v1";
    static constexpr std::string_view L_MSG  = "cryptolib/ratchet/msg/v1";

    SecureBuffer rk_;                 // root key
    SecureBuffer cks_, ckr_;          // sending / receiving chain keys (may be empty)
    SecureBuffer dhs_pub_, dhs_sec_;  // my current ratchet keypair
    SecureBuffer dhr_;                // peer's current ratchet public key (may be empty)
    SecureBuffer pending_ct_;         // KEM ct advertised in my outgoing headers
    SecureBuffer handshake_;          // initiator only: the message for accept()
    uint32_t ns_ = 0, nr_ = 0, pn_ = 0;
    using SkipKey = std::pair<std::array<uint8_t, 16>, uint32_t>;
    std::map<SkipKey, SecureBuffer> skipped_;

    // Snapshot of the mutable ratchet state (chain/root keys, keypairs, counters)
    // taken before a decrypt attempt, restored on authentication failure so a bad
    // message cannot desync the channel.
    struct Snapshot {
        SecureBuffer rk, cks, ckr, dhs_pub, dhs_sec, dhr, pending_ct;
        uint32_t ns, nr, pn;
    };
    static SecureBuffer copy_of(const SecureBuffer& b) {
        return SecureBuffer(b.span().data(), b.span().size());
    }
    Snapshot take_snapshot() const {
        return Snapshot{ copy_of(rk_), copy_of(cks_), copy_of(ckr_), copy_of(dhs_pub_),
                         copy_of(dhs_sec_), copy_of(dhr_), copy_of(pending_ct_), ns_, nr_, pn_ };
    }
    void restore_snapshot(Snapshot&& s) {
        rk_ = std::move(s.rk); cks_ = std::move(s.cks); ckr_ = std::move(s.ckr);
        dhs_pub_ = std::move(s.dhs_pub); dhs_sec_ = std::move(s.dhs_sec);
        dhr_ = std::move(s.dhr); pending_ct_ = std::move(s.pending_ct);
        ns_ = s.ns; nr_ = s.nr; pn_ = s.pn;
    }

    // ── init ──────────────────────────────────────────────────────────────────
    [[nodiscard]] Result<void>
    init_initiator(std::span<const uint8_t> sk, std::span<const uint8_t> peer_pub) {
        rk_ = SecureBuffer(sk.data(), sk.size());
        dhr_ = SecureBuffer(peer_pub.data(), peer_pub.size());
        auto kp = Kem::generate_keypair();
        if (kp.is_err()) return Result<void>::err(kp.error().message);
        dhs_pub_ = SecureBuffer(kp.value().public_key.span().data(), kp.value().public_key.span().size());
        dhs_sec_ = SecureBuffer(kp.value().secret_key.span().data(), kp.value().secret_key.span().size());
        // First sending chain: encapsulate to the peer prekey.
        auto enc = Kem::encapsulate(peer_pub);
        if (enc.is_err()) return Result<void>::err(enc.error().message);
        pending_ct_ = SecureBuffer(enc.value().ciphertext.span().data(), enc.value().ciphertext.span().size());
        return root_step(enc.value().shared_secret.span(), /*sending=*/true);
    }

    [[nodiscard]] Result<void>
    init_responder(std::span<const uint8_t> sk, const Kem::KeyPair& prekey) {
        rk_ = SecureBuffer(sk.data(), sk.size());
        dhs_pub_ = SecureBuffer(prekey.public_key.span().data(), prekey.public_key.span().size());
        dhs_sec_ = SecureBuffer(prekey.secret_key.span().data(), prekey.secret_key.span().size());
        // No sending chain / DHr yet — the responder must receive first.
        return Result<void>::ok();
    }

    // ── KEM ratchet turn ──────────────────────────────────────────────────────
    [[nodiscard]] Result<void>
    dh_ratchet(std::span<const uint8_t> new_peer_pub, std::span<const uint8_t> ct) {
        pn_ = ns_;
        ns_ = 0;
        nr_ = 0;
        // Receiving chain: decapsulate the header ct with my current ratchet key.
        auto ss_r = Kem::decapsulate(ct, dhs_sec_.span());
        if (ss_r.is_err()) return Result<void>::err(ss_r.error().message);
        if (auto e = root_step(ss_r.value().span(), /*sending=*/false); e.is_err()) return e;
        dhr_ = SecureBuffer(new_peer_pub.data(), new_peer_pub.size());
        // New sending chain: fresh keypair, encapsulate to the new peer key.
        auto kp = Kem::generate_keypair();
        if (kp.is_err()) return Result<void>::err(kp.error().message);
        dhs_pub_ = SecureBuffer(kp.value().public_key.span().data(), kp.value().public_key.span().size());
        dhs_sec_ = SecureBuffer(kp.value().secret_key.span().data(), kp.value().secret_key.span().size());
        auto enc = Kem::encapsulate(dhr_.span());
        if (enc.is_err()) return Result<void>::err(enc.error().message);
        pending_ct_ = SecureBuffer(enc.value().ciphertext.span().data(), enc.value().ciphertext.span().size());
        return root_step(enc.value().shared_secret.span(), /*sending=*/true);
    }

    // (rk, chain) = KDF_RK(rk, kem_output); sets rk_ and the sending/receiving chain.
    [[nodiscard]] Result<void> root_step(std::span<const uint8_t> kem_out, bool sending) {
        auto prk = hash::HkdfSha256::extract(rk_.span(), kem_out);
        if (prk.is_err()) return Result<void>::err(prk.error().message);
        auto okm = hash::HkdfSha256::expand(prk.value().span(), label(L_ROOT), 64);
        if (okm.is_err()) return Result<void>::err(okm.error().message);
        rk_ = SecureBuffer(okm.value().span().data(), 32);
        auto chain = SecureBuffer(okm.value().span().subspan(32, 32).data(), 32);
        (sending ? cks_ : ckr_) = std::move(chain);
        return Result<void>::ok();
    }

    // mk = KDF_CK(ck); ck advances in place.
    [[nodiscard]] Result<SecureBuffer> advance_chain(SecureBuffer& ck) {
        auto mk = hash::HkdfSha256::expand(ck.span(), label(L_MSG), 32);
        if (mk.is_err()) return mk;
        auto next = hash::HkdfSha256::expand(ck.span(), label(L_CHAIN), 32);
        if (next.is_err()) return next;
        ck = SecureBuffer(next.value().span().data(), 32);
        return mk;
    }

    // Store message keys skipped in the current receiving chain up to `until`.
    [[nodiscard]] Result<void> skip_message_keys(uint32_t until) {
        if (ckr_.span().empty()) return Result<void>::ok();
        if (until > nr_ + MAX_SKIP)
            return Result<void>::err("Session: too many skipped messages");
        auto fp = fingerprint(dhr_.span());
        while (nr_ < until) {
            auto mk = advance_chain(ckr_);
            if (mk.is_err()) return Result<void>::err(mk.error().message);
            if (skipped_.size() >= MAX_SKIP) skipped_.erase(skipped_.begin());
            skipped_.emplace(std::make_pair(fp, nr_), std::move(mk.value()));
            nr_ += 1;
        }
        return Result<void>::ok();
    }

    bool same_pub(std::span<const uint8_t> pub) const {
        auto d = dhr_.span();
        return d.size() == pub.size() && std::memcmp(d.data(), pub.data(), d.size()) == 0;
    }

    // ── helpers ───────────────────────────────────────────────────────────────
    static std::span<const uint8_t> label(std::string_view s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }
    static Result<SecureBuffer> derive_root(std::span<const uint8_t> kem_ss) {
        auto prk = hash::HkdfSha256::extract({}, kem_ss);
        if (prk.is_err()) return prk;
        return hash::HkdfSha256::expand(prk.value().span(), label(L_INIT), 32);
    }
    static std::array<uint8_t, 16> fingerprint(std::span<const uint8_t> pub) {
        std::array<uint8_t, 16> fp{};
        auto d = hash::Blake2b::digest(pub);
        if (d.is_ok()) std::memcpy(fp.data(), d.value().data(), 16);
        return fp;
    }
    static void put_u32(std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
    }
    static uint32_t get_u32(const uint8_t* p) {
        uint32_t x = 0;
        for (int i = 0; i < 4; ++i) x |= static_cast<uint32_t>(p[i]) << (8 * i);
        return x;
    }
    // header = MAGIC | ver | pub_len | pub | ct_len | ct | PN | N
    static std::vector<uint8_t>
    serialize_header(std::span<const uint8_t> pub, std::span<const uint8_t> ct, uint32_t pn, uint32_t n) {
        std::vector<uint8_t> h(MAGIC.begin(), MAGIC.end());
        h.push_back(VERSION);
        put_u32(h, static_cast<uint32_t>(pub.size())); h.insert(h.end(), pub.begin(), pub.end());
        put_u32(h, static_cast<uint32_t>(ct.size()));  h.insert(h.end(), ct.begin(),  ct.end());
        put_u32(h, pn);
        put_u32(h, n);
        return h;
    }
    struct Header {
        std::span<const uint8_t> pub, ct, header_bytes, body;
        uint32_t pn = 0, n = 0;
    };
    [[nodiscard]] static Result<void> parse_header(std::span<const uint8_t> m, Header& out) {
        std::size_t off = 0;
        auto need = [&](std::size_t k) { return m.size() >= off + k; };
        if (!need(5) || std::memcmp(m.data(), MAGIC.data(), 4) != 0)
            return Result<void>::err("Session: bad magic");
        if (m[4] != VERSION) return Result<void>::err("Session: unsupported version");
        off = 5;
        if (!need(4)) return Result<void>::err("Session: truncated");
        uint32_t publen = get_u32(m.data() + off); off += 4;
        if (!need(publen)) return Result<void>::err("Session: truncated");
        out.pub = m.subspan(off, publen); off += publen;
        if (!need(4)) return Result<void>::err("Session: truncated");
        uint32_t ctlen = get_u32(m.data() + off); off += 4;
        if (!need(ctlen)) return Result<void>::err("Session: truncated");
        out.ct = m.subspan(off, ctlen); off += ctlen;
        if (!need(8)) return Result<void>::err("Session: truncated");
        out.pn = get_u32(m.data() + off); off += 4;
        out.n  = get_u32(m.data() + off); off += 4;
        out.header_bytes = m.subspan(0, off);
        if (!need(4)) return Result<void>::err("Session: truncated");
        uint32_t bodylen = get_u32(m.data() + off); off += 4;
        if (!need(bodylen)) return Result<void>::err("Session: truncated");
        out.body = m.subspan(off, bodylen);
        return Result<void>::ok();
    }
};

} // namespace crypto

#endif // CRYPTOLIB_HAS_PQ
