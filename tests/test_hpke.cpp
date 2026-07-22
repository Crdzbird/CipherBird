// crypto::Hpke — HPKE (RFC 9180) validated against the official test vectors
// from the CFRG reference test-vectors.json (kem_id 0x20 = DHKEM(X25519,
// HKDF-SHA256)). Covers all four modes, HKDF-SHA256/512, and ChaCha20Poly1305
// (+ AES-128/256-GCM when built with OpenSSL), plus end-to-end round trips.
#include "test_framework.hpp"

#include <cryptolib/hpke.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Hpke;

namespace {
std::vector<uint8_t> unhex(std::string_view h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<uint8_t> o;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) o.push_back((nib(h[i]) << 4) | nib(h[i + 1]));
    return o;
}
std::vector<uint8_t> vec(const crypto::SecureBuffer& b) { return {b.span().begin(), b.span().end()}; }
std::span<const uint8_t> sp(const std::vector<uint8_t>& v) { return {v.data(), v.size()}; }
} // namespace

// ── RFC 9180 §A.2 — DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ──
TEST("hpke/kat/base-chacha20") {
    auto info  = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto ikmE  = unhex("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
    auto skEm  = unhex("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
    auto pkEm  = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    auto ikmR  = unhex("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
    auto skRm  = unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    auto pkRm  = unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    auto enc   = unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    auto exp0  = unhex("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e");
    auto exp2  = unhex("5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53");
    auto expctx2 = unhex("54657374436f6e74657874");

    // DeriveKeyPair reproduces the vector key pairs.
    auto dkE = Hpke::derive_keypair(sp(ikmE));
    REQUIRE(dkE.is_ok());
    CHECK(vec(dkE.value().secret_key) == skEm);
    CHECK(vec(dkE.value().public_key) == pkEm);
    auto dkR = Hpke::derive_keypair(sp(ikmR));
    REQUIRE(dkR.is_ok());
    CHECK(vec(dkR.value().secret_key) == skRm);
    CHECK(vec(dkR.value().public_key) == pkRm);

    // Deterministic sender setup (skE from the vector) → enc matches.
    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Base, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::ChaCha20Poly1305, sp(pkRm), sp(info), {}, {}, {}, sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);

    // Encryptions seq 0 and 1.
    auto pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"));
    auto ct1 = s.value().ctx.seal(sp(unhex("436f756e742d31")), sp(pt));
    REQUIRE(ct1.is_ok());
    CHECK(vec(ct1.value()) == unhex("6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"));

    // Receiver opens both, in order.
    auto r = Hpke::setup_base_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305, sp(enc), sp(skRm), sp(info));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
    auto o1 = r.value().open(sp(unhex("436f756e742d31")), ct1.value().span());
    REQUIRE(o1.is_ok());
    CHECK(vec(o1.value()) == pt);

    // Secret export (seq-independent).
    auto ex0 = r.value().export_secret({}, 32);
    REQUIRE(ex0.is_ok());
    CHECK(vec(ex0.value()) == exp0);
    auto ex2 = r.value().export_secret(sp(expctx2), 32);
    REQUIRE(ex2.is_ok());
    CHECK(vec(ex2.value()) == exp2);
}

// ── HKDF-SHA512 KDF path (kdf_id 0x03) ───────────────────────────────────────
TEST("hpke/kat/base-hkdf-sha512") {
    auto info = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm = unhex("76bb47b1f20139b5506a2f44fd80210e92a6fa32f8ecaf65a42c1e8060c8eb30");
    auto skRm = unhex("fad15f488c09c167bd18d8f48f282e30d944d624c5676742ad820119de44ea91");
    auto pkRm = unhex("06aa193a5612d89a1935c33f1fda3109fcdf4b867da4c4507879f184340b0e0e");
    auto enc  = unhex("1d38fc578d4209ea0ef3ee5f1128ac4876a9549d74dc2d2f46e75942a6188244");
    auto pt   = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Base, Hpke::Kdf::HkdfSha512,
        Hpke::Aead::ChaCha20Poly1305, sp(pkRm), sp(info), {}, {}, {}, sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("72da9627fd7eb3a8b7169c6d97419b80adefca751c6b52b39a2e084d35ce3eb4487aadaca5a9c590e0938c48b9"));
    auto ex0 = s.value().ctx.export_secret({}, 32);
    REQUIRE(ex0.is_ok());
    CHECK(vec(ex0.value()) == unhex("5b6120165c82456080db3c730b886b07129e0aec9b5f7beae9e5bbd103c67f2d"));
}

// ── PSK mode (mode 0x01) ─────────────────────────────────────────────────────
TEST("hpke/kat/psk-chacha20") {
    auto info   = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm   = unhex("0c35fdf49df7aa01cd330049332c40411ebba36e0c718ebc3edf5845795f6321");
    auto skRm   = unhex("77d114e0212be51cb1d76fa99dd41cfd4d0166b08caa09074430a6c59ef17879");
    auto pkRm   = unhex("13640af826b722fc04feaa4de2f28fbd5ecc03623b317834e7ff4120dbe73062");
    auto psk    = unhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    auto psk_id = unhex("456e6e796e20447572696e206172616e204d6f726961");
    auto enc    = unhex("2261299c3f40a9afc133b969a97f05e95be2c514e54f3de26cbe5644ac735b04");
    auto pt     = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Psk, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::ChaCha20Poly1305, sp(pkRm), sp(info), sp(psk), sp(psk_id), {}, sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("4a177f9c0d6f15cfdf533fb65bf84aecdc6ab16b8b85b4cf65a370e07fc1d78d28fb073214525276f4a89608ff"));

    auto r = Hpke::setup_psk_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sp(enc), sp(skRm), sp(info), sp(psk), sp(psk_id));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
    auto ex0 = r.value().export_secret({}, 32);
    REQUIRE(ex0.is_ok());
    CHECK(vec(ex0.value()) == unhex("813c1bfc516c99076ae0f466671f0ba5ff244a41699f7b2417e4c59d46d39f40"));
}

// ── Auth mode (mode 0x02) — sender authentication ────────────────────────────
TEST("hpke/kat/auth-chacha20") {
    auto info = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm = unhex("c94619e1af28971c8fa7957192b7e62a71ca2dcdde0a7cc4a8a9e741d600ab13");
    auto skRm = unhex("3ca22a6d1cda1bb9480949ec5329d3bf0b080ca4c45879c95eddb55c70b80b82");
    auto pkRm = unhex("1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44");
    auto skSm = unhex("2def0cb58ffcf83d1062dd085c8aceca7f4c0c3fd05912d847b61f3e54121f05");
    auto pkSm = unhex("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b");
    auto enc  = unhex("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e");
    auto pt   = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Auth, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::ChaCha20Poly1305, sp(pkRm), sp(info), {}, {}, sp(skSm), sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf"));

    auto r = Hpke::setup_auth_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sp(enc), sp(skRm), sp(info), sp(pkSm));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
    auto ex0 = r.value().export_secret({}, 32);
    REQUIRE(ex0.is_ok());
    CHECK(vec(ex0.value()) == unhex("070cffafd89b67b7f0eeb800235303a223e6ff9d1e774dce8eac585c8688c872"));
}

// ── AuthPSK mode (mode 0x03) ─────────────────────────────────────────────────
TEST("hpke/kat/auth-psk-chacha20") {
    auto info   = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm   = unhex("5e6dd73e82b856339572b7245d3cbb073a7561c0bee52873490e305cbb710410");
    auto skRm   = unhex("7b36a42822e75bf3362dfabbe474b3016236408becb83b859a6909e22803cb0c");
    auto pkRm   = unhex("a5099431c35c491ec62ca91df1525d6349cb8aa170c51f9581f8627be6334851");
    auto skSm   = unhex("90761c5b0a7ef0985ed66687ad708b921d9803d51637c8d1cb72d03ed0f64418");
    auto pkSm   = unhex("3ac5bd4dd66ff9f2740bef0d6ccb66daa77bff7849d7895182b07fb74d087c45");
    auto psk    = unhex("0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    auto psk_id = unhex("456e6e796e20447572696e206172616e204d6f726961");
    auto enc    = unhex("656a2e00dc9990fd189e6e473459392df556e9a2758754a09db3f51179a3fc02");
    auto pt     = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::AuthPsk, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::ChaCha20Poly1305, sp(pkRm), sp(info), sp(psk), sp(psk_id), sp(skSm), sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("9aa52e29274fc6172e38a4461361d2342585d3aeec67fb3b721ecd63f059577c7fe886be0ede01456ebc67d597"));

    auto r = Hpke::setup_auth_psk_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sp(enc), sp(skRm), sp(info), sp(psk), sp(psk_id), sp(pkSm));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
}

#ifdef CRYPTOLIB_HAS_OPENSSL
// ── AES-GCM AEADs (OpenSSL) — base mode ──────────────────────────────────────
TEST("hpke/kat/base-aes128gcm") {
    auto info = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm = unhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    auto skRm = unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    auto pkRm = unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    auto enc  = unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    auto pt   = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Base, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::Aes128Gcm, sp(pkRm), sp(info), {}, {}, {}, sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"));

    auto r = Hpke::setup_base_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes128Gcm, sp(enc), sp(skRm), sp(info));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
}

TEST("hpke/kat/base-aes256gcm") {
    auto info = unhex("4f6465206f6e2061204772656369616e2055726e");
    auto skEm = unhex("179d4b53b6365c45b600c4163b61d95cbc2f4d9e36f1695558dce265ab8bab11");
    auto skRm = unhex("497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d");
    auto pkRm = unhex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
    auto enc  = unhex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
    auto pt   = unhex("4265617574792069732074727574682c20747275746820626561757479");

    auto s = Hpke::setup_s_deterministic(Hpke::Mode::Base, Hpke::Kdf::HkdfSha256,
        Hpke::Aead::Aes256Gcm, sp(pkRm), sp(info), {}, {}, {}, sp(skEm));
    REQUIRE(s.is_ok());
    CHECK(vec(s.value().enc) == enc);
    auto ct0 = s.value().ctx.seal(sp(unhex("436f756e742d30")), sp(pt));
    REQUIRE(ct0.is_ok());
    CHECK(vec(ct0.value()) == unhex("e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"));

    auto r = Hpke::setup_base_r(Hpke::Kdf::HkdfSha256, Hpke::Aead::Aes256Gcm, sp(enc), sp(skRm), sp(info));
    REQUIRE(r.is_ok());
    auto o0 = r.value().open(sp(unhex("436f756e742d30")), ct0.value().span());
    REQUIRE(o0.is_ok());
    CHECK(vec(o0.value()) == pt);
}
#endif

// ── End-to-end with fresh keys + single-shot + tamper rejection ──────────────
TEST("hpke/e2e/base-single-shot") {
    auto bob = Hpke::generate_keypair();
    auto info = unhex("6170702d696e666f");
    auto aad  = unhex("6d657461");
    auto pt   = unhex("746f702d736563726574206d657373616765");

    auto sealed = Hpke::seal_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        bob.public_key.span(), sp(info), sp(aad), sp(pt));
    REQUIRE(sealed.is_ok());
    auto opened = Hpke::open_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sealed.value().enc.span(), bob.secret_key.span(), sp(info), sp(aad), sealed.value().ct.span());
    REQUIRE(opened.is_ok());
    CHECK(vec(opened.value()) == pt);

    // Tampered ciphertext is rejected.
    auto tampered = vec(sealed.value().ct);
    tampered[tampered.size() - 1] ^= 0x01;
    auto bad = Hpke::open_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sealed.value().enc.span(), bob.secret_key.span(), sp(info), sp(aad), sp(tampered));
    CHECK(bad.is_err());

    // Wrong AAD is rejected.
    auto badaad = Hpke::open_base(Hpke::Kdf::HkdfSha256, Hpke::Aead::ChaCha20Poly1305,
        sealed.value().enc.span(), bob.secret_key.span(), sp(info), sp(unhex("00")), sealed.value().ct.span());
    CHECK(badaad.is_err());
}

TEST("hpke/e2e/auth-multi-message") {
    auto bob = Hpke::generate_keypair();
    auto alice = Hpke::generate_keypair();
    auto info = unhex("636f6e76657273");

    auto s = Hpke::setup_auth_s(Hpke::Kdf::HkdfSha512, Hpke::Aead::ChaCha20Poly1305,
        bob.public_key.span(), sp(info), alice.secret_key.span());
    REQUIRE(s.is_ok());
    auto r = Hpke::setup_auth_r(Hpke::Kdf::HkdfSha512, Hpke::Aead::ChaCha20Poly1305,
        s.value().enc.span(), bob.secret_key.span(), sp(info), alice.public_key.span());
    REQUIRE(r.is_ok());

    for (int i = 0; i < 5; ++i) {
        auto msg = unhex("6d736700");
        msg[3] = static_cast<uint8_t>('0' + i);
        auto ct = s.value().ctx.seal({}, sp(msg));
        REQUIRE(ct.is_ok());
        auto o = r.value().open({}, ct.value().span());
        REQUIRE(o.is_ok());
        CHECK(vec(o.value()) == msg);
    }
    // Both sides derive the same exported secret.
    auto es = s.value().ctx.export_secret(sp(unhex("6c6162")), 32);
    auto er = r.value().export_secret(sp(unhex("6c6162")), 32);
    REQUIRE(es.is_ok()); REQUIRE(er.is_ok());
    CHECK(vec(es.value()) == vec(er.value()));
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_hpke() {
    RUN("hpke/kat/base-chacha20");
    RUN("hpke/kat/base-hkdf-sha512");
    RUN("hpke/kat/psk-chacha20");
    RUN("hpke/kat/auth-chacha20");
    RUN("hpke/kat/auth-psk-chacha20");
#ifdef CRYPTOLIB_HAS_OPENSSL
    RUN("hpke/kat/base-aes128gcm");
    RUN("hpke/kat/base-aes256gcm");
#endif
    RUN("hpke/e2e/base-single-shot");
    RUN("hpke/e2e/auth-multi-message");
}
