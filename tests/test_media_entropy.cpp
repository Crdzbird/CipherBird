#include "test_framework.hpp"
#include <filesystem>
using namespace test;

// Helpers to reduce boilerplate — unwrap Result into a moved value.
// All objects (MediaEntropy, SecureVault, SecureBuffer, etc.) are move-only.
#define UNWRAP(var, expr) \
    auto var##_res = (expr); \
    REQUIRE(var##_res.is_ok()); \
    auto var = std::move(var##_res.value());

static const char* SRC  = "/tmp/me_entropy.ppm";
static const char* SRC2 = "/tmp/me_entropy2.ppm";

static void ensure_sources() {
    using MG = crypto::stego::MediaGenerator;
    if (!std::filesystem::exists(SRC)) {
        crypto::stego::MediaGeneratorParams p; p.ppm_seed = 0xABCD'0001;
        (void)MG::generate_ppm(SRC,  512, 512, p);
    }
    if (!std::filesystem::exists(SRC2)) {
        crypto::stego::MediaGeneratorParams p; p.ppm_seed = 0xABCD'0002;
        (void)MG::generate_ppm(SRC2, 512, 512, p);
    }
}

// ─── from_file / from_files ───────────────────────────────────────────────────

TEST("entropy/from-file/basic") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK(me.entropy_bits() > 0);
    CHECK(me.raw().size() == 64);
}

TEST("entropy/from-file/missing-file") {
    CHECK_ERR(crypto::entropy::MediaEntropy::from_file("/tmp/does_not_exist.ppm"));
}

TEST("entropy/from-files/multiple-sources") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_files({SRC, SRC2}));
    CHECK(me.entropy_bits() > 0);
}

// ─── Key derivation ───────────────────────────────────────────────────────────

TEST("entropy/symmetric-key/length") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK(me.symmetric_key().size() == 32);
}

TEST("entropy/symmetric-key/deterministic-within-instance") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    // Keys derived from the same object are stable (same raw entropy buffer).
    CHECK(me.symmetric_key().to_hex() == me.symmetric_key().to_hex());
}

TEST("entropy/symmetric-key/differs-per-file") {
    ensure_sources();
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file(SRC2));
    CHECK(me1.symmetric_key().to_hex() != me2.symmetric_key().to_hex());
}

TEST("entropy/derive-all/all-fields-non-empty") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    auto all = me.derive_all();
    CHECK(all.symmetric_key.size()    == 32);
    CHECK(all.vault_master_key.size() == 32);
    CHECK(all.signing_seed.size()     == 32);
    CHECK(all.box_seed.size()         == 32);
    CHECK(all.stream_key.size()       == 32);
    CHECK(all.raw_entropy.size()      == 64);
}

TEST("entropy/derive-all/domain-separated") {
    // Every domain key must differ — proves HKDF labels are distinct.
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    auto all = me.derive_all();
    CHECK(all.symmetric_key.to_hex()    != all.vault_master_key.to_hex());
    CHECK(all.symmetric_key.to_hex()    != all.signing_seed.to_hex());
    CHECK(all.vault_master_key.to_hex() != all.signing_seed.to_hex());
    CHECK(all.signing_seed.to_hex()     != all.box_seed.to_hex());
    CHECK(all.box_seed.to_hex()         != all.stream_key.to_hex());
}

// ─── make_vault ───────────────────────────────────────────────────────────────

TEST("entropy/make-vault/returns-vault") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(vault, me.make_vault());
    CHECK(vault.public_key().size() == 32);
}

TEST("entropy/make-vault/seal-open-round-trip") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(vault, me.make_vault());
    UNWRAP(pkt,   vault.seal("entropy vault test", "aad"));
    UNWRAP(plain, vault.open(pkt, "aad"));
    CHECK(plain.to_string() == "entropy vault test");
}

// ─── SecureVault::from_entropy ────────────────────────────────────────────────

TEST("entropy/SecureVault::from_entropy/basic") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(vault, crypto::SecureVault::from_entropy(me));
    CHECK(vault.public_key().size() == 32);
}

TEST("entropy/SecureVault::from_entropy/seal-open-round-trip") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(vault, crypto::SecureVault::from_entropy(me));
    UNWRAP(pkt,   vault.seal("lavarand seeded vault", "ctx"));
    UNWRAP(plain, vault.open(pkt, "ctx"));
    CHECK(plain.to_string() == "lavarand seeded vault");
}

TEST("entropy/SecureVault::from_entropy/different-files-different-vaults") {
    ensure_sources();
    UNWRAP(me1,   crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(me2,   crypto::entropy::MediaEntropy::from_file(SRC2));
    UNWRAP(v1,    crypto::SecureVault::from_entropy(me1));
    UNWRAP(v2,    crypto::SecureVault::from_entropy(me2));
    UNWRAP(pkt,   v1.seal("secret", "ctx"));
    auto bad = v2.open(pkt, "ctx");
    CHECK_ERR(bad);  // v2 has different keys — cannot decrypt v1's packet
}

TEST("entropy/SecureVault::from_entropy/sensitive-kdf") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(vault, crypto::SecureVault::from_entropy(me, crypto::KdfParams::sensitive()));
    UNWRAP(pkt,   vault.seal("sensitive kdf test", "ctx"));
    UNWRAP(plain, vault.open(pkt, "ctx"));
    CHECK(plain.to_string() == "sensitive kdf test");
}

// ─── AsymmetricVault::from_entropy ───────────────────────────────────────────

TEST("entropy/AsymKeyBundle/from_entropy/basic") {
    ensure_sources();
    UNWRAP(me,     crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(bundle, crypto::AsymmetricVault::from_entropy(me));
    CHECK(bundle.box_public.size()  == 32);
    CHECK(bundle.box_secret.size()  == 32);
    CHECK(bundle.sign_public.size() == 32);
    CHECK(bundle.sign_secret.size() == 64);
}

TEST("entropy/AsymKeyBundle/from_entropy/deterministic-within-instance") {
    ensure_sources();
    UNWRAP(me,  crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(b1,  crypto::AsymmetricVault::from_entropy(me));
    UNWRAP(b2,  crypto::AsymmetricVault::from_entropy(me));
    // Derived from the same raw entropy buffer → identical keys.
    CHECK(b1.box_public.to_hex()  == b2.box_public.to_hex());
    CHECK(b1.sign_public.to_hex() == b2.sign_public.to_hex());
}

TEST("entropy/AsymKeyBundle/from_entropy/seal-open-round-trip") {
    ensure_sources();
    UNWRAP(me_alice, crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(me_bob,   crypto::entropy::MediaEntropy::from_file(SRC2));
    UNWRAP(alice,    crypto::AsymmetricVault::from_entropy(me_alice));
    UNWRAP(bob,      crypto::AsymmetricVault::from_entropy(me_bob));
    UNWRAP(pkt,      crypto::AsymmetricVault::seal(
                         "entropy-seeded asym", alice, bob.box_public.span(), "ctx"));
    UNWRAP(plain,    crypto::AsymmetricVault::open(
                         pkt, bob, alice.sign_public.span(), "ctx"));
    CHECK(plain.to_string() == "entropy-seeded asym");
}

// ─── MediaEntropy::seal / open  (direct encryption — no stego) ───────────────

TEST("entropy/direct-seal/round-trip") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(pkt,   me.seal("direct entropy encryption", "aad"));
    UNWRAP(plain, me.open(pkt, "aad"));
    CHECK(plain.to_string() == "direct entropy encryption");
}

TEST("entropy/direct-seal/empty-plaintext") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(pkt,   me.seal("", "aad"));
    UNWRAP(plain, me.open(pkt, "aad"));
    CHECK(plain.size() == 0);
}

TEST("entropy/direct-seal/wrong-aad-rejected") {
    ensure_sources();
    UNWRAP(me,  crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(pkt, me.seal("secret", "correct-aad"));
    CHECK_ERR(me.open(pkt, "wrong-aad"));
}

TEST("entropy/direct-seal/different-source-cannot-open") {
    ensure_sources();
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file(SRC2));
    UNWRAP(pkt, me1.seal("sealed by me1", "ctx"));
    CHECK_ERR(me2.open(pkt, "ctx"));
}

TEST("entropy/direct-seal/packet-serialises-for-transport") {
    ensure_sources();
    UNWRAP(me,    crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(pkt,   me.seal("transport test", "aad"));
    auto wire = pkt.serialise();
    UNWRAP(pkt2,  crypto::EncryptedPacket::deserialise(wire.span()));
    UNWRAP(plain, me.open(pkt2, "aad"));
    CHECK(plain.to_string() == "transport test");
}

// ─── Convenience free functions ───────────────────────────────────────────────

TEST("entropy/vault-from-file/convenience") {
    ensure_sources();
    UNWRAP(vault, crypto::entropy::vault_from_file(SRC));
    UNWRAP(pkt,   vault.seal("vault_from_file test", "ctx"));
    UNWRAP(plain, vault.open(pkt, "ctx"));
    CHECK(plain.to_string() == "vault_from_file test");
}

TEST("entropy/key-from-file/convenience") {
    ensure_sources();
    UNWRAP(k, crypto::entropy::key_from_file(SRC));
    CHECK(k.size() == 32);
}

TEST("entropy/seal-from-file/produces-valid-packet") {
    ensure_sources();
    UNWRAP(pkt, crypto::entropy::seal_from_file(SRC, "convenience seal", "ctx"));
    // Packet must serialise cleanly — proves the full pipeline ran.
    auto wire = pkt.serialise();
    CHECK(wire.size() > 100);
    REQUIRE(crypto::EncryptedPacket::deserialise(wire.span()).is_ok());
}

TEST("entropy/open-from-file/round-trip-with-seal-from-file") {
    ensure_sources();
    // seal_from_file and open_from_file both use from_file_deterministic(),
    // so two separate calls from the same file reproduce the same keys.
    UNWRAP(pkt,   crypto::entropy::seal_from_file(SRC, "cross-call round-trip", "ctx"));
    UNWRAP(plain, crypto::entropy::open_from_file(SRC, pkt, "ctx"));
    CHECK(plain.to_string() == "cross-call round-trip");
}

// ─── from_file vs from_file_deterministic ────────────────────────────────────

TEST("entropy/deterministic/same-file-same-keys") {
    ensure_sources();
    // Two deterministic constructions from the same file must produce identical keys.
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    CHECK(me1.symmetric_key().to_hex() == me2.symmetric_key().to_hex());
    CHECK(me1.vault_master_key().to_hex() == me2.vault_master_key().to_hex());
}

TEST("entropy/deterministic/different-files-different-keys") {
    ensure_sources();
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file_deterministic(SRC2));
    CHECK(me1.symmetric_key().to_hex() != me2.symmetric_key().to_hex());
}

TEST("entropy/deterministic/keys-differ-from-lavarand-mode") {
    ensure_sources();
    // Deterministic and LavaRand constructions from the same file must differ.
    UNWRAP(det,  crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    UNWRAP(rand, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK(det.symmetric_key().to_hex() != rand.symmetric_key().to_hex());
}

TEST("entropy/deterministic/cross-call-seal-open") {
    ensure_sources();
    // Simulate two independent agents both holding the same file.
    UNWRAP(agent_a, crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    UNWRAP(pkt,     agent_a.seal("deterministic cross-agent", "aad"));

    UNWRAP(agent_b, crypto::entropy::MediaEntropy::from_file_deterministic(SRC));
    UNWRAP(plain,   agent_b.open(pkt, "aad"));
    CHECK(plain.to_string() == "deterministic cross-agent");
}

TEST("entropy/lavarand/cross-call-cannot-decrypt") {
    ensure_sources();
    // LavaRand mode: two from_file() calls always produce different keys.
    // A packet sealed by one cannot be opened by the other.
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(pkt, me1.seal("lavarand sealed", "aad"));

    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK_ERR(me2.open(pkt, "aad"));  // different system entropy → different keys
}

TEST("entropy/asym-bundle-from-file/convenience") {
    ensure_sources();
    UNWRAP(b, crypto::entropy::asym_bundle_from_file(SRC));
    CHECK(b.box_public.size()  == 32);
    CHECK(b.sign_public.size() == 32);
}

// ─── LavaRand property ────────────────────────────────────────────────────────

TEST("entropy/system-entropy-mixed") {
    ensure_sources();
    // Two from_file() calls in the same process must produce different raw
    // entropy because randombytes_buf() is mixed at construction time.
    UNWRAP(me1, crypto::entropy::MediaEntropy::from_file(SRC));
    UNWRAP(me2, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK(me1.raw().to_hex() != me2.raw().to_hex());
}

TEST("entropy/raw-buffer/non-empty-and-non-zero") {
    ensure_sources();
    UNWRAP(me, crypto::entropy::MediaEntropy::from_file(SRC));
    CHECK(me.raw().size() == 64);
    bool any_nonzero = false;
    for (auto b : me.raw().span()) if (b) { any_nonzero = true; break; }
    CHECK(any_nonzero);
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_media_entropy() {
    RUN("entropy/from-file/basic");
    RUN("entropy/from-file/missing-file");
    RUN("entropy/from-files/multiple-sources");
    RUN("entropy/symmetric-key/length");
    RUN("entropy/symmetric-key/deterministic-within-instance");
    RUN("entropy/symmetric-key/differs-per-file");
    RUN("entropy/derive-all/all-fields-non-empty");
    RUN("entropy/derive-all/domain-separated");
    RUN("entropy/make-vault/returns-vault");
    RUN("entropy/make-vault/seal-open-round-trip");
    RUN("entropy/SecureVault::from_entropy/basic");
    RUN("entropy/SecureVault::from_entropy/seal-open-round-trip");
    RUN("entropy/SecureVault::from_entropy/different-files-different-vaults");
    RUN("entropy/SecureVault::from_entropy/sensitive-kdf");
    RUN("entropy/AsymKeyBundle/from_entropy/basic");
    RUN("entropy/AsymKeyBundle/from_entropy/deterministic-within-instance");
    RUN("entropy/AsymKeyBundle/from_entropy/seal-open-round-trip");
    RUN("entropy/direct-seal/round-trip");
    RUN("entropy/direct-seal/empty-plaintext");
    RUN("entropy/direct-seal/wrong-aad-rejected");
    RUN("entropy/direct-seal/different-source-cannot-open");
    RUN("entropy/direct-seal/packet-serialises-for-transport");
    RUN("entropy/vault-from-file/convenience");
    RUN("entropy/key-from-file/convenience");
    RUN("entropy/seal-from-file/produces-valid-packet");
    RUN("entropy/open-from-file/round-trip-with-seal-from-file");
    RUN("entropy/deterministic/same-file-same-keys");
    RUN("entropy/deterministic/different-files-different-keys");
    RUN("entropy/deterministic/keys-differ-from-lavarand-mode");
    RUN("entropy/deterministic/cross-call-seal-open");
    RUN("entropy/lavarand/cross-call-cannot-decrypt");
    RUN("entropy/asym-bundle-from-file/convenience");
    RUN("entropy/system-entropy-mixed");
    RUN("entropy/raw-buffer/non-empty-and-non-zero");
}
