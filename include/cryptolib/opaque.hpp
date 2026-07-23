#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::Opaque — OPAQUE aPAKE (draft-irtf-cfrg-opaque)                       ║
 * ║  OPAQUE-3DH, ciphersuite ristretto255-SHA-512, KSF = Identity                ║
 * ║                                                                            ║
 * ║  An asymmetric password-authenticated key exchange: a client and server      ║
 * ║  agree on a strong shared session key from a password WITHOUT the password    ║
 * ║  (or anything password-equivalent) ever leaving the client or being stored    ║
 * ║  by the server. The server keeps only an opaque record; a server compromise   ║
 * ║  yields no way to log in without an expensive offline dictionary attack, and  ║
 * ║  the password is never revealed even to a malicious server.                 ║
 * ║                                                                            ║
 * ║  Two phases: registration (client stores an envelope with the server) and    ║
 * ║  login (a 3DH authenticated key exchange). Built on crypto::Oprf (RFC 9497),  ║
 * ║  HKDF-SHA-512, and HMAC-SHA-512 — composition only, no new cryptography.      ║
 * ║  Validated against the draft's official test vectors.                        ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"   // HkdfSha512
#include "oprf.hpp"   // crypto::Oprf (ristretto255-SHA-512)

#include <sodium.h>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace crypto {

class Opaque {
public:
    static constexpr std::size_t Nn = 32;   // nonce
    static constexpr std::size_t Nseed = 32;
    static constexpr std::size_t Nh = 64;   // hash / KDF output
    static constexpr std::size_t Nm = 64;   // MAC
    static constexpr std::size_t Npk = 32, Nsk = 32, Nok = 32, Noe = 32;
    static constexpr std::size_t OPRF_SEED_BYTES = 64;
    static constexpr std::size_t ENVELOPE_BYTES = Nn + Nm;               // 96
    static constexpr std::size_t REGISTRATION_REQUEST_BYTES = Noe;       // 32
    static constexpr std::size_t REGISTRATION_RESPONSE_BYTES = Noe + Npk; // 64
    static constexpr std::size_t REGISTRATION_RECORD_BYTES = Npk + Nh + ENVELOPE_BYTES; // 192

    struct FinalizeResult { SecureBuffer record; SecureBuffer export_key; };

    // ── Registration ──────────────────────────────────────────────────────────
    /// Client step 1: blind the password → registration request (send to server).
    /// Keep `blind` for finalize. (Randomized; use *_with_blind for test vectors.)
    [[nodiscard]] static Result<Oprf::BlindResult>
    create_registration_request(std::span<const uint8_t> password) {
        return Oprf::blind(password);
    }
    [[nodiscard]] static Result<Oprf::BlindResult>
    create_registration_request_with_blind(std::span<const uint8_t> password,
                                            std::span<const uint8_t> blind) {
        return Oprf::blind_with_scalar(password, blind);
    }

    /// Server: evaluate the request under a per-user OPRF key → registration
    /// response (evaluated_message ‖ server_public_key).
    [[nodiscard]] static Result<SecureBuffer>
    create_registration_response(std::span<const uint8_t> request,
                                 std::span<const uint8_t> server_public_key,
                                 std::span<const uint8_t> credential_identifier,
                                 std::span<const uint8_t> oprf_seed) {
        if (request.size() != REGISTRATION_REQUEST_BYTES) return Result<SecureBuffer>::err("OPAQUE: bad request");
        if (server_public_key.size() != Npk) return Result<SecureBuffer>::err("OPAQUE: bad server key");
        if (oprf_seed.size() != OPRF_SEED_BYTES) return Result<SecureBuffer>::err("OPAQUE: bad oprf seed");

        auto oprf_key = derive_oprf_key(oprf_seed, credential_identifier);
        auto ev = Oprf::blind_evaluate(oprf_key.span(), request);
        if (ev.is_err()) return Result<SecureBuffer>::err(ev.error().message);

        SecureBuffer resp(REGISTRATION_RESPONSE_BYTES);
        std::memcpy(resp.data(), ev.value().data(), Noe);
        std::memcpy(resp.data() + Noe, server_public_key.data(), Npk);
        return Result<SecureBuffer>::ok(std::move(resp));
    }

    /// Client step 2 (randomized): finalize → registration record + export_key.
    [[nodiscard]] static Result<FinalizeResult>
    finalize_registration_request(std::span<const uint8_t> password, std::span<const uint8_t> blind,
                                  std::span<const uint8_t> response,
                                  std::span<const uint8_t> server_identity = {},
                                  std::span<const uint8_t> client_identity = {}) {
        SecureBuffer envelope_nonce(Nn);
        randombytes_buf(envelope_nonce.data(), Nn);
        return finalize_registration_request_with_nonce(password, blind, response, envelope_nonce.span(),
                                             server_identity, client_identity);
    }

    /// Client step 2: finalize → registration record (upload to server) +
    /// export_key. Deterministic variant with a caller-supplied envelope nonce.
    [[nodiscard]] static Result<FinalizeResult>
    finalize_registration_request_with_nonce(std::span<const uint8_t> password, std::span<const uint8_t> blind,
                                  std::span<const uint8_t> response, std::span<const uint8_t> envelope_nonce,
                                  std::span<const uint8_t> server_identity = {},
                                  std::span<const uint8_t> client_identity = {}) {
        if (response.size() != REGISTRATION_RESPONSE_BYTES) return Result<FinalizeResult>::err("OPAQUE: bad response");
        std::span<const uint8_t> evaluated = response.subspan(0, Noe);
        std::span<const uint8_t> server_pk = response.subspan(Noe, Npk);

        auto oprf_output = Oprf::finalize(password, blind, evaluated);
        if (oprf_output.is_err()) return Result<FinalizeResult>::err(oprf_output.error().message);
        SecureBuffer randomized_password = extract_randomized_password(oprf_output.value().span());

        SecureBuffer masking_key = expand(randomized_password.span(), lit("MaskingKey"), Nh);
        SecureBuffer auth_key   = expand(randomized_password.span(), cat(envelope_nonce, "AuthKey"), Nh);
        SecureBuffer export_key = expand(randomized_password.span(), cat(envelope_nonce, "ExportKey"), Nh);
        SecureBuffer seed       = expand(randomized_password.span(), cat(envelope_nonce, "PrivateKey"), Nseed);

        auto client_kp = Oprf::derive_keypair(seed.span(), lit("OPAQUE-DeriveDiffieHellmanKeyPair"));
        if (client_kp.is_err()) return Result<FinalizeResult>::err(client_kp.error().message);
        const SecureBuffer& client_pk = client_kp.value().public_key;

        std::span<const uint8_t> sid = server_identity.empty() ? server_pk : server_identity;
        std::span<const uint8_t> cid = client_identity.empty() ? client_pk.span() : client_identity;

        // auth_tag = MAC(auth_key, envelope_nonce ‖ server_pk ‖ len‖sid ‖ len‖cid)
        std::vector<uint8_t> mac_in;
        put(mac_in, envelope_nonce);
        put(mac_in, server_pk);
        put_len16(mac_in, sid.size()); put(mac_in, sid);
        put_len16(mac_in, cid.size()); put(mac_in, cid);
        SecureBuffer auth_tag = hmac(auth_key.span(), mac_in);

        SecureBuffer record(REGISTRATION_RECORD_BYTES);
        std::size_t off = 0;
        std::memcpy(record.data() + off, client_pk.data(), Npk); off += Npk;
        std::memcpy(record.data() + off, masking_key.data(), Nh); off += Nh;
        std::memcpy(record.data() + off, envelope_nonce.data(), Nn); off += Nn;
        std::memcpy(record.data() + off, auth_tag.data(), Nm);
        return Result<FinalizeResult>::ok(FinalizeResult{ std::move(record), std::move(export_key) });
    }

    // ── Login: 3DH AKE ────────────────────────────────────────────────────────
    static constexpr std::size_t KE1_BYTES = Noe + Nn + Npk;                        // 96
    static constexpr std::size_t CRED_RESPONSE_BYTES = Noe + Nn + (Npk + ENVELOPE_BYTES); // 192
    static constexpr std::size_t KE2_BYTES = CRED_RESPONSE_BYTES + Nn + Npk + Nm;   // 320
    static constexpr std::size_t KE3_BYTES = Nm;                                    // 64

    struct Ke1Result { SecureBuffer ke1; SecureBuffer client_state; };
    struct Ke2Result { SecureBuffer ke2; SecureBuffer server_state; };
    struct Ke3Result { SecureBuffer ke3; SecureBuffer session_key; SecureBuffer export_key; };

    /// Client login step 1 (randomized). Returns KE1 (send to server) + an
    /// opaque client_state to pass to client_generate_ke3.
    [[nodiscard]] static Result<Ke1Result>
    client_generate_ke1(std::span<const uint8_t> password) {
        SecureBuffer blind(Nsk), client_nonce(Nn), client_keyshare_seed(Nseed);
        crypto_core_ristretto255_scalar_random(blind.data()); // canonical OPRF blind
        randombytes_buf(client_nonce.data(), Nn);
        randombytes_buf(client_keyshare_seed.data(), Nseed);
        return client_generate_ke1(password, blind.span(), client_nonce.span(), client_keyshare_seed.span());
    }

    /// Client login step 1 (deterministic: caller supplies the AKE randomness;
    /// `blind` MUST be a canonical ristretto255 scalar). For test vectors.
    [[nodiscard]] static Result<Ke1Result>
    client_generate_ke1(std::span<const uint8_t> password, std::span<const uint8_t> blind,
                        std::span<const uint8_t> client_nonce, std::span<const uint8_t> client_keyshare_seed) {
        auto br = Oprf::blind_with_scalar(password, blind);
        if (br.is_err()) return Result<Ke1Result>::err(br.error().message);
        auto ckp = Oprf::derive_keypair(client_keyshare_seed, lit("OPAQUE-DeriveDiffieHellmanKeyPair"));
        if (ckp.is_err()) return Result<Ke1Result>::err(ckp.error().message);

        SecureBuffer ke1(KE1_BYTES);
        std::memcpy(ke1.data(), br.value().blinded_element.data(), Noe);
        std::memcpy(ke1.data() + Noe, client_nonce.data(), Nn);
        std::memcpy(ke1.data() + Noe + Nn, ckp.value().public_key.data(), Npk);

        // client_state = blind ‖ client_secret ‖ ke1 ‖ password
        std::vector<uint8_t> st;
        put(st, blind);
        put(st, ckp.value().secret_key.span());
        put(st, ke1.span());
        put(st, password);
        return Result<Ke1Result>::ok(Ke1Result{ std::move(ke1),
            SecureBuffer(st.data(), st.size()) });
    }

    /// Server login step (randomized). `record` is the stored registration
    /// record. Returns KE2 + an opaque server_state to pass to server_finish.
    [[nodiscard]] static Result<Ke2Result>
    server_generate_ke2(std::span<const uint8_t> context,
                        std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key,
                        std::span<const uint8_t> record, std::span<const uint8_t> credential_identifier,
                        std::span<const uint8_t> oprf_seed, std::span<const uint8_t> ke1,
                        std::span<const uint8_t> server_identity = {}, std::span<const uint8_t> client_identity = {}) {
        SecureBuffer masking_nonce(Nn), server_nonce(Nn), server_keyshare_seed(Nseed);
        randombytes_buf(masking_nonce.data(), Nn);
        randombytes_buf(server_nonce.data(), Nn);
        randombytes_buf(server_keyshare_seed.data(), Nseed);
        return server_generate_ke2(context, server_private_key, server_public_key, record,
            credential_identifier, oprf_seed, ke1, masking_nonce.span(), server_nonce.span(),
            server_keyshare_seed.span(), server_identity, client_identity);
    }

    /// Server login step (deterministic: caller supplies the AKE randomness).
    /// For test vectors.
    [[nodiscard]] static Result<Ke2Result>
    server_generate_ke2(std::span<const uint8_t> context,
                        std::span<const uint8_t> server_private_key, std::span<const uint8_t> server_public_key,
                        std::span<const uint8_t> record, std::span<const uint8_t> credential_identifier,
                        std::span<const uint8_t> oprf_seed, std::span<const uint8_t> ke1,
                        std::span<const uint8_t> masking_nonce, std::span<const uint8_t> server_nonce,
                        std::span<const uint8_t> server_keyshare_seed,
                        std::span<const uint8_t> server_identity = {}, std::span<const uint8_t> client_identity = {}) {
        if (ke1.size() != KE1_BYTES || record.size() != REGISTRATION_RECORD_BYTES)
            return Result<Ke2Result>::err("OPAQUE: bad ke1/record length");
        std::span<const uint8_t> client_pk = record.subspan(0, Npk);
        std::span<const uint8_t> masking_key = record.subspan(Npk, Nh);
        std::span<const uint8_t> envelope = record.subspan(Npk + Nh, ENVELOPE_BYTES);
        std::span<const uint8_t> blinded = ke1.subspan(0, Noe);
        std::span<const uint8_t> client_keyshare = ke1.subspan(Noe + Nn, Npk);

        // CredentialResponse.
        auto oprf_key = derive_oprf_key(oprf_seed, credential_identifier);
        auto ev = Oprf::blind_evaluate(oprf_key.span(), blinded);
        if (ev.is_err()) return Result<Ke2Result>::err(ev.error().message);
        std::vector<uint8_t> pad_info(masking_nonce.begin(), masking_nonce.end());
        put(pad_info, "CredentialResponsePad");
        SecureBuffer pad = expand(masking_key, pad_info, Npk + ENVELOPE_BYTES);
        std::vector<uint8_t> plain; put(plain, server_public_key); put(plain, envelope);
        SecureBuffer masked(pad.size());
        for (std::size_t i = 0; i < pad.size(); ++i) masked.data()[i] = pad.data()[i] ^ plain[i];

        std::vector<uint8_t> cred_response;
        put(cred_response, ev.value().span());
        put(cred_response, masking_nonce);
        put(cred_response, masked.span());

        std::span<const uint8_t> sid = server_identity.empty() ? server_public_key : server_identity;
        std::span<const uint8_t> cid = client_identity.empty() ? client_pk : client_identity;

        // AuthServerRespond.
        auto skp = Oprf::derive_keypair(server_keyshare_seed, lit("OPAQUE-DeriveDiffieHellmanKeyPair"));
        if (skp.is_err()) return Result<Ke2Result>::err(skp.error().message);
        auto pre = preamble(context, cid, ke1, sid, cred_response, server_nonce, skp.value().public_key.span());

        SecureBuffer dh1, dh2, dh3;
        if (!dh(skp.value().secret_key.span(), client_keyshare, dh1) ||
            !dh(server_private_key, client_keyshare, dh2) ||
            !dh(skp.value().secret_key.span(), client_pk, dh3))
            return Result<Ke2Result>::err("OPAQUE: 3DH failed");
        std::vector<uint8_t> ikm; put(ikm, dh1.span()); put(ikm, dh2.span()); put(ikm, dh3.span());

        SecureBuffer km2, km3, session_key;
        derive_keys(ikm, pre, km2, km3, session_key);
        SecureBuffer pre_hash = sha512(pre);
        SecureBuffer server_mac = hmac(km2.span(), pre_hash.span());
        std::vector<uint8_t> pre_smac(pre.begin(), pre.end()); put(pre_smac, server_mac.span());
        SecureBuffer expected_client_mac = hmac(km3.span(), sha512(pre_smac).span());

        std::vector<uint8_t> ke2;
        put(ke2, cred_response);
        put(ke2, server_nonce);
        put(ke2, skp.value().public_key.span());
        put(ke2, server_mac.span());

        std::vector<uint8_t> st; put(st, expected_client_mac.span()); put(st, session_key.span());
        return Result<Ke2Result>::ok(Ke2Result{ SecureBuffer(ke2.data(), ke2.size()),
                                                 SecureBuffer(st.data(), st.size()) });
    }

    /// Client login step 2: recover credentials, authenticate the server, and
    /// produce KE3 + the session key + export key. Fails if the server (or
    /// password) is wrong.
    [[nodiscard]] static Result<Ke3Result>
    client_generate_ke3(std::span<const uint8_t> client_state, std::span<const uint8_t> ke2,
                        std::span<const uint8_t> context,
                        std::span<const uint8_t> server_identity = {}, std::span<const uint8_t> client_identity = {}) {
        if (ke2.size() != KE2_BYTES) return Result<Ke3Result>::err("OPAQUE: bad ke2 length");
        if (client_state.size() < Nsk + Nsk + KE1_BYTES) return Result<Ke3Result>::err("OPAQUE: bad client state");
        std::span<const uint8_t> blind = client_state.subspan(0, Nsk);
        std::span<const uint8_t> client_secret = client_state.subspan(Nsk, Nsk);
        std::span<const uint8_t> ke1 = client_state.subspan(2 * Nsk, KE1_BYTES);
        std::span<const uint8_t> password = client_state.subspan(2 * Nsk + KE1_BYTES);

        std::span<const uint8_t> cred_response = ke2.subspan(0, CRED_RESPONSE_BYTES);
        std::span<const uint8_t> evaluated = cred_response.subspan(0, Noe);
        std::span<const uint8_t> masking_nonce = cred_response.subspan(Noe, Nn);
        std::span<const uint8_t> masked = cred_response.subspan(Noe + Nn, Npk + ENVELOPE_BYTES);

        // RecoverCredentials.
        auto oprf_output = Oprf::finalize(password, blind, evaluated);
        if (oprf_output.is_err()) return Result<Ke3Result>::err(oprf_output.error().message);
        SecureBuffer rp = extract_randomized_password(oprf_output.value().span());
        SecureBuffer masking_key = expand(rp.span(), lit("MaskingKey"), Nh);
        std::vector<uint8_t> pad_info(masking_nonce.begin(), masking_nonce.end());
        put(pad_info, "CredentialResponsePad");
        SecureBuffer pad = expand(masking_key.span(), pad_info, Npk + ENVELOPE_BYTES);
        std::vector<uint8_t> plain(pad.size());
        for (std::size_t i = 0; i < pad.size(); ++i) plain[i] = pad.data()[i] ^ masked[i];
        std::span<const uint8_t> server_pk{ plain.data(), Npk };
        std::span<const uint8_t> envelope{ plain.data() + Npk, ENVELOPE_BYTES };
        std::span<const uint8_t> env_nonce = envelope.subspan(0, Nn);
        std::span<const uint8_t> auth_tag = envelope.subspan(Nn, Nm);

        SecureBuffer auth_key   = expand(rp.span(), cat(env_nonce, "AuthKey"), Nh);
        SecureBuffer export_key = expand(rp.span(), cat(env_nonce, "ExportKey"), Nh);
        SecureBuffer seed       = expand(rp.span(), cat(env_nonce, "PrivateKey"), Nseed);
        auto ckp = Oprf::derive_keypair(seed.span(), lit("OPAQUE-DeriveDiffieHellmanKeyPair"));
        if (ckp.is_err()) return Result<Ke3Result>::err(ckp.error().message);
        std::span<const uint8_t> client_pk = ckp.value().public_key.span();

        std::span<const uint8_t> sid = server_identity.empty() ? server_pk : server_identity;
        std::span<const uint8_t> cid = client_identity.empty() ? client_pk : client_identity;
        std::vector<uint8_t> tag_in;
        put(tag_in, env_nonce); put(tag_in, server_pk);
        put_len16(tag_in, sid.size()); put(tag_in, sid);
        put_len16(tag_in, cid.size()); put(tag_in, cid);
        SecureBuffer expected_tag = hmac(auth_key.span(), tag_in);
        if (sodium_memcmp(expected_tag.data(), auth_tag.data(), Nm) != 0)
            return Result<Ke3Result>::err("OPAQUE: credential recovery failed (bad password)");

        // AuthClientFinalize.
        std::span<const uint8_t> auth_response = ke2.subspan(CRED_RESPONSE_BYTES);
        std::span<const uint8_t> server_nonce = auth_response.subspan(0, Nn);
        std::span<const uint8_t> server_keyshare = auth_response.subspan(Nn, Npk);
        std::span<const uint8_t> server_mac = auth_response.subspan(Nn + Npk, Nm);

        auto pre = preamble(context, cid, ke1, sid, cred_response, server_nonce, server_keyshare);
        SecureBuffer dh1, dh2, dh3;
        if (!dh(client_secret, server_keyshare, dh1) ||
            !dh(client_secret, server_pk, dh2) ||
            !dh(ckp.value().secret_key.span(), server_keyshare, dh3))
            return Result<Ke3Result>::err("OPAQUE: 3DH failed");
        std::vector<uint8_t> ikm; put(ikm, dh1.span()); put(ikm, dh2.span()); put(ikm, dh3.span());

        SecureBuffer km2, km3, session_key;
        derive_keys(ikm, pre, km2, km3, session_key);
        SecureBuffer pre_hash = sha512(pre);
        SecureBuffer expected_server_mac = hmac(km2.span(), pre_hash.span());
        if (sodium_memcmp(expected_server_mac.data(), server_mac.data(), Nm) != 0)
            return Result<Ke3Result>::err("OPAQUE: server authentication failed");

        std::vector<uint8_t> pre_smac(pre.begin(), pre.end()); put(pre_smac, expected_server_mac.span());
        SecureBuffer client_mac = hmac(km3.span(), sha512(pre_smac).span());
        return Result<Ke3Result>::ok(Ke3Result{ std::move(client_mac), std::move(session_key), std::move(export_key) });
    }

    /// Server login step 2: verify the client's KE3 → the session key.
    [[nodiscard]] static Result<SecureBuffer>
    server_finish(std::span<const uint8_t> server_state, std::span<const uint8_t> ke3) {
        if (server_state.size() != Nm + Nh || ke3.size() != KE3_BYTES)
            return Result<SecureBuffer>::err("OPAQUE: bad server state / ke3");
        std::span<const uint8_t> expected = server_state.subspan(0, Nm);
        if (sodium_memcmp(expected.data(), ke3.data(), Nm) != 0)
            return Result<SecureBuffer>::err("OPAQUE: client authentication failed");
        std::span<const uint8_t> session_key = server_state.subspan(Nm, Nh);
        return Result<SecureBuffer>::ok(SecureBuffer(session_key.data(), session_key.size()));
    }

protected:
    // ── shared helpers (also used by the 3DH AKE) ─────────────────────────────
    static std::span<const uint8_t> lit(const char* s) {
        return { reinterpret_cast<const uint8_t*>(s), std::strlen(s) };
    }
    static void put(std::vector<uint8_t>& v, std::span<const uint8_t> s) { v.insert(v.end(), s.begin(), s.end()); }
    static void put(std::vector<uint8_t>& v, std::string_view s) { v.insert(v.end(), s.begin(), s.end()); }
    static void put_len16(std::vector<uint8_t>& v, std::size_t n) {
        v.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
        v.push_back(static_cast<uint8_t>(n & 0xff));
    }
    static std::vector<uint8_t> cat(std::span<const uint8_t> a, std::string_view b) {
        std::vector<uint8_t> v(a.begin(), a.end());
        v.insert(v.end(), b.begin(), b.end());
        return v;
    }

    static SecureBuffer expand(std::span<const uint8_t> prk, std::span<const uint8_t> info, std::size_t L) {
        return std::move(hash::HkdfSha512::expand(prk, info, L).value());
    }
    static SecureBuffer expand(std::span<const uint8_t> prk, const std::vector<uint8_t>& info, std::size_t L) {
        return std::move(hash::HkdfSha512::expand(prk, { info.data(), info.size() }, L).value());
    }
    static SecureBuffer extract(std::span<const uint8_t> salt, std::span<const uint8_t> ikm) {
        return std::move(hash::HkdfSha512::extract(salt, ikm).value());
    }

    // HMAC-SHA-512 with an arbitrary-length key (libsodium streaming API).
    static SecureBuffer hmac(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
        crypto_auth_hmacsha512_state st;
        crypto_auth_hmacsha512_init(&st, key.data(), key.size());
        crypto_auth_hmacsha512_update(&st, msg.data(), msg.size());
        SecureBuffer out(Nm);
        crypto_auth_hmacsha512_final(&st, out.data());
        sodium_memzero(&st, sizeof st);
        return out;
    }
    static SecureBuffer hmac(std::span<const uint8_t> key, const std::vector<uint8_t>& msg) {
        return hmac(key, std::span<const uint8_t>{ msg.data(), msg.size() });
    }

    // randomized_password = Extract("", oprf_output ‖ Stretch(oprf_output)).
    // KSF = Identity ⇒ Stretch is the identity function.
    static SecureBuffer extract_randomized_password(std::span<const uint8_t> oprf_output) {
        std::vector<uint8_t> ikm(oprf_output.begin(), oprf_output.end());
        ikm.insert(ikm.end(), oprf_output.begin(), oprf_output.end());
        return extract({}, { ikm.data(), ikm.size() });
    }

    // Per-user OPRF key: Expand(oprf_seed, credential_identifier ‖ "OprfKey", Nok)
    // then DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair").
    static SecureBuffer derive_oprf_key(std::span<const uint8_t> oprf_seed,
                                        std::span<const uint8_t> credential_identifier) {
        std::vector<uint8_t> info(credential_identifier.begin(), credential_identifier.end());
        put(info, "OprfKey");
        SecureBuffer seed = expand(oprf_seed, info, Nok);
        return std::move(Oprf::derive_keypair(seed.span(), lit("OPAQUE-DeriveKeyPair")).value().secret_key);
    }

    static SecureBuffer sha512(std::span<const uint8_t> msg) {
        SecureBuffer out(Nh);
        crypto_hash_sha512(out.data(), msg.data(), msg.size());
        return out;
    }
    static SecureBuffer sha512(const std::vector<uint8_t>& msg) {
        return sha512(std::span<const uint8_t>{ msg.data(), msg.size() });
    }

    // ristretto255 Diffie-Hellman. Returns false on invalid input.
    static bool dh(std::span<const uint8_t> sk, std::span<const uint8_t> pk, SecureBuffer& out) {
        out = SecureBuffer(Noe);
        return crypto_scalarmult_ristretto255(out.data(), sk.data(), pk.data()) == 0;
    }

    // Expand-Label(Secret, Label, Context, L) with the "OPAQUE-" label prefix.
    static SecureBuffer expand_label(std::span<const uint8_t> secret, std::string_view label,
                                     std::span<const uint8_t> context, std::size_t L) {
        std::string full_label = "OPAQUE-";
        full_label += label;
        std::vector<uint8_t> custom;
        put_len16(custom, L);
        custom.push_back(static_cast<uint8_t>(full_label.size()));
        custom.insert(custom.end(), full_label.begin(), full_label.end());
        custom.push_back(static_cast<uint8_t>(context.size()));
        custom.insert(custom.end(), context.begin(), context.end());
        return expand(secret, custom, L);
    }
    static SecureBuffer derive_secret(std::span<const uint8_t> secret, std::string_view label,
                                      std::span<const uint8_t> context) {
        return expand_label(secret, label, context, Nh); // Nx == Nh == 64
    }

    // Preamble(client_identity, ke1, server_identity, credential_response,
    //          server_nonce, server_public_keyshare) with "OPAQUEv1-" + context.
    static std::vector<uint8_t>
    preamble(std::span<const uint8_t> context, std::span<const uint8_t> client_identity,
             std::span<const uint8_t> ke1, std::span<const uint8_t> server_identity,
             std::span<const uint8_t> credential_response, std::span<const uint8_t> server_nonce,
             std::span<const uint8_t> server_public_keyshare) {
        std::vector<uint8_t> p;
        put(p, "OPAQUEv1-");
        put_len16(p, context.size()); put(p, context);
        put_len16(p, client_identity.size()); put(p, client_identity);
        put(p, ke1);
        put_len16(p, server_identity.size()); put(p, server_identity);
        put(p, credential_response);
        put(p, server_nonce);
        put(p, server_public_keyshare);
        return p;
    }

    static void derive_keys(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& pre,
                            SecureBuffer& km2, SecureBuffer& km3, SecureBuffer& session_key) {
        SecureBuffer prk = extract({}, { ikm.data(), ikm.size() });
        SecureBuffer pre_hash = sha512(pre);
        SecureBuffer handshake_secret = derive_secret(prk.span(), "HandshakeSecret", pre_hash.span());
        session_key = derive_secret(prk.span(), "SessionKey", pre_hash.span());
        km2 = derive_secret(handshake_secret.span(), "ServerMAC", {});
        km3 = derive_secret(handshake_secret.span(), "ClientMAC", {});
    }
};

} // namespace crypto
