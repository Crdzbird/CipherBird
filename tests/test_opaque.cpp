// crypto::Opaque — OPAQUE-3DH (ristretto255-SHA-512, Identity KSF), validated
// against the draft's official test vector (registration + full 3DH login) plus
// an end-to-end mutual-auth login and a wrong-password rejection.
#include "test_framework.hpp"

#include <cryptolib/opaque.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using crypto::Opaque;

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

// draft-irtf-cfrg-opaque test vector — OPAQUE-3DH, ristretto255-SHA-512.
namespace v {
const char* context     = "4f50415155452d504f43";
const char* password    = "436f7272656374486f72736542617474657279537461706c65";
const char* blind_reg   = "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01";
const char* blind_login = "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308";
const char* client_nonce = "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc";
const char* client_ks_seed = "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b";
const char* cred_id     = "31323334";
const char* env_nonce   = "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec";
const char* masking_nonce = "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d";
const char* oprf_seed   = "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef";
const char* server_nonce = "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1";
const char* server_ks_seed = "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f";
const char* server_priv = "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d";
const char* server_pub  = "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
const char* reg_request = "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71";
const char* reg_response = "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78";
const char* reg_upload  = "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5";
const char* export_key  = "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16";
const char* KE1         = "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326";
const char* KE2         = "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90";
const char* KE3         = "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442";
const char* session_key = "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f";
}
} // namespace

TEST("opaque/kat/registration") {
    auto req = Opaque::create_registration_request_with_blind(sp(unhex(v::password)), sp(unhex(v::blind_reg)));
    REQUIRE(req.is_ok());
    CHECK(vec(req.value().blinded_element) == unhex(v::reg_request));

    auto resp = Opaque::create_registration_response(req.value().blinded_element.span(),
        sp(unhex(v::server_pub)), sp(unhex(v::cred_id)), sp(unhex(v::oprf_seed)));
    REQUIRE(resp.is_ok());
    CHECK(vec(resp.value()) == unhex(v::reg_response));

    auto fin = Opaque::finalize_registration_request_with_nonce(sp(unhex(v::password)), req.value().blind.span(),
        resp.value().span(), sp(unhex(v::env_nonce)));
    REQUIRE(fin.is_ok());
    CHECK(vec(fin.value().record) == unhex(v::reg_upload));
    CHECK(vec(fin.value().export_key) == unhex(v::export_key));
}

TEST("opaque/kat/login-3dh") {
    auto ctx = unhex(v::context);
    auto ke1 = Opaque::client_generate_ke1(sp(unhex(v::password)), sp(unhex(v::blind_login)),
        sp(unhex(v::client_nonce)), sp(unhex(v::client_ks_seed)));
    REQUIRE(ke1.is_ok());
    CHECK(vec(ke1.value().ke1) == unhex(v::KE1));

    auto ke2 = Opaque::server_generate_ke2(sp(ctx), sp(unhex(v::server_priv)), sp(unhex(v::server_pub)),
        sp(unhex(v::reg_upload)), sp(unhex(v::cred_id)), sp(unhex(v::oprf_seed)), ke1.value().ke1.span(),
        sp(unhex(v::masking_nonce)), sp(unhex(v::server_nonce)), sp(unhex(v::server_ks_seed)));
    REQUIRE(ke2.is_ok());
    CHECK(vec(ke2.value().ke2) == unhex(v::KE2));

    auto ke3 = Opaque::client_generate_ke3(ke1.value().client_state.span(), ke2.value().ke2.span(), sp(ctx));
    REQUIRE(ke3.is_ok());
    CHECK(vec(ke3.value().ke3) == unhex(v::KE3));
    CHECK(vec(ke3.value().session_key) == unhex(v::session_key));
    CHECK(vec(ke3.value().export_key) == unhex(v::export_key));

    auto sk = Opaque::server_finish(ke2.value().server_state.span(), ke3.value().ke3.span());
    REQUIRE(sk.is_ok());
    CHECK(vec(sk.value()) == unhex(v::session_key));
}

TEST("opaque/e2e/mutual-auth-and-wrong-password") {
    // Fresh registration with random blinds/nonces, then a full login.
    auto password = unhex("68756e74657232"); // "hunter2"
    auto oprf_seed = crypto::random_bytes(64);
    auto server = std::move(crypto::Oprf::derive_keypair(crypto::random_bytes(32).span()).value()); // reuse a DH keypair
    auto cred_id = unhex("6964"); // "id"
    auto ctx = unhex("617070"); // "app"

    // Registration.
    auto req = Opaque::create_registration_request(sp(password));
    REQUIRE(req.is_ok());
    auto resp = Opaque::create_registration_response(req.value().blinded_element.span(),
        server.public_key.span(), sp(cred_id), oprf_seed.span());
    REQUIRE(resp.is_ok());
    auto fin = Opaque::finalize_registration_request(sp(password), req.value().blind.span(),
        resp.value().span());
    REQUIRE(fin.is_ok());
    auto record = vec(fin.value().record);

    // Login (correct password) → both sides derive the same session key.
    auto ke1 = Opaque::client_generate_ke1(sp(password));
    REQUIRE(ke1.is_ok());
    auto ke2 = Opaque::server_generate_ke2(sp(ctx), server.secret_key.span(), server.public_key.span(),
        sp(record), sp(cred_id), oprf_seed.span(), ke1.value().ke1.span());
    REQUIRE(ke2.is_ok());
    auto ke3 = Opaque::client_generate_ke3(ke1.value().client_state.span(), ke2.value().ke2.span(), sp(ctx));
    REQUIRE(ke3.is_ok());
    auto sk = Opaque::server_finish(ke2.value().server_state.span(), ke3.value().ke3.span());
    REQUIRE(sk.is_ok());
    CHECK(vec(sk.value()) == vec(ke3.value().session_key));
    CHECK(vec(ke3.value().export_key) == vec(fin.value().export_key));

    // Login with the WRONG password: the client cannot recover the envelope.
    auto bad = unhex("6e6f7065"); // "nope"
    auto ke1b = Opaque::client_generate_ke1(sp(bad));
    REQUIRE(ke1b.is_ok());
    auto ke2b = Opaque::server_generate_ke2(sp(ctx), server.secret_key.span(), server.public_key.span(),
        sp(record), sp(cred_id), oprf_seed.span(), ke1b.value().ke1.span());
    REQUIRE(ke2b.is_ok());
    auto ke3b = Opaque::client_generate_ke3(ke1b.value().client_state.span(), ke2b.value().ke2.span(), sp(ctx));
    CHECK(ke3b.is_err()); // wrong password → recovery/auth failure
}

// ─────────────────────────────────────────────────────────────────────────────
void run_tests_opaque() {
    RUN("opaque/kat/registration");
    RUN("opaque/kat/login-3dh");
    RUN("opaque/e2e/mutual-auth-and-wrong-password");
}
