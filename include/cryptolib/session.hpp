#pragma once

/**
 * crypto::Session: the post-quantum forward-secret ratchet (hybrid KEM
 * Double Ratchet) in its version 1 wire format ("RTC1"). The construction
 * lives in ratchet.hpp as Ratchet<Kem, Wire>; this header pins the v1 KEM
 * (the library-native X25519 + ML-KEM-768 combiner) and labels so existing
 * sessions keep interoperating. New code should use SessionV2
 * (session_v2.hpp), whose handshake authenticates both parties over X-Wing.
 *
 * Properties: forward secrecy (compromising the state does not reveal past
 * messages), post-compromise security (the channel heals after a
 * compromise once a fresh KEM exchange completes), out-of-order delivery
 * within a bounded window, and committing AEAD on every message. Composed
 * from vetted primitives with domain-separated HKDF throughout; no new
 * cryptography.
 */

#ifdef CRYPTOLIB_HAS_PQ
#include "ratchet.hpp"
#include "hybrid_kem.hpp"   // crypto::pq::HybridKem  (X25519 + ML-KEM-768)

namespace crypto {

/// Wire constants of Session v1: unchanged, so existing peers interoperate.
struct SessionWireV1 {
    static constexpr std::array<uint8_t, 4> MAGIC = {'R', 'T', 'C', '1'};
    static constexpr uint8_t VERSION = 1;
    static constexpr std::string_view L_INIT = "cryptolib/ratchet/init/v1";
    static constexpr std::string_view L_ROOT = "cryptolib/ratchet/root/v1";
    static constexpr std::string_view L_CHAIN = "cryptolib/ratchet/chain/v1";
    static constexpr std::string_view L_MSG  = "cryptolib/ratchet/msg/v1";
};

/// Session v1: the ratchet over the library-native hybrid KEM with the
/// unauthenticated prekey handshake. The initiator is not authenticated
/// (assessment r2, M6); SessionV2 is the authenticated successor.
using Session = Ratchet<pq::HybridKem, SessionWireV1>;

} // namespace crypto
#endif // CRYPTOLIB_HAS_PQ
