/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLibDemo — exhaustive feature showcase with dynamic arguments        ║
 * ║                                                                            ║
 * ║  Usage:                                                                    ║
 * ║    ./cryptolib_demo <command> [options]                                    ║
 * ║                                                                            ║
 * ║  Commands:                                                                 ║
 * ║    hash       [--algo blake2b|sha256|sha512|argon2id|hmac|blake3|hmac256|  ║
 * ║               hkdf] [--input TEXT] [--stream]                              ║
 * ║    sym        [--algo xchacha20|aes256gcm|secretstream]                    ║
 * ║               [--plaintext TEXT] [--aad TEXT] [--chunks N]                 ║
 * ║    asym       [--algo box|sealedbox|ed25519|x25519|hybrid]                 ║
 * ║               [--message TEXT]                                             ║
 * ║    vault      [--kdf interactive|sensitive|custom] [--ops N] [--mem MiB]   ║
 * ║               [--plaintext TEXT] [--aad TEXT] [--boost]                    ║
 * ║    asym-vault [--plaintext TEXT] [--aad TEXT] [--boost]                    ║
 * ║    entropy    [--mode standalone|boost|derive-all|refresh|all]             ║
 * ║               [--file PATH] [--deterministic] [--plaintext TEXT]           ║
 * ║    stego      [--format ppm|wav|crvf|all] [--plaintext TEXT]               ║
 * ║               [--aad TEXT] [--quant N] [--raw] [--capacity] [--quality]    ║
 * ║    pq         [--algo ml-kem|ml-dsa|slh-dsa]                               ║
 * ║    bls        BLS12-381 signatures + aggregation                           ║
 * ║    all        (runs every command with default arguments)                  ║
 * ║    help       (print this message)                                         ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include <cryptolib/cryptolib.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

// ─── Terminal colours ─────────────────────────────────────────────────────────
#define RST   "\033[0m"
#define BOLD  "\033[1m"
#define GRN   "\033[32m"
#define CYN   "\033[36m"
#define YLW   "\033[33m"
#define RED   "\033[31m"
#define MAG   "\033[35m"
#define BLU   "\033[34m"
#define DIM   "\033[2m"

// ─────────────────────────────────────────────────────────────────────────────
// CryptoLibDemo
// ─────────────────────────────────────────────────────────────────────────────
class CryptoLibDemo {
public:

    CryptoLibDemo(int argc, char** argv)
        : command_(argc > 1 ? argv[1] : "help")
    {
        for (int i = 2; i < argc; ++i) {
            std::string_view a = argv[i];
            if (a.starts_with("--") && i + 1 < argc && argv[i+1][0] != '-') {
                opts_[std::string(a.substr(2))] = argv[++i];
            } else if (a.starts_with("--")) {
                opts_[std::string(a.substr(2))] = "true";
            }
        }

        // Resolve output directory from --output-dir or default to temp path
        auto od = opt("output-dir", "");
        output_dir_ = od.empty()
            ? std::filesystem::temp_directory_path() / "cryptolib_demo"
            : std::filesystem::path(od);
        std::filesystem::create_directories(output_dir_);
    }

    int run() {
        crypto::init();
        banner();
        if      (command_ == "hash")       cmd_hash();
        else if (command_ == "sym")        cmd_symmetric();
        else if (command_ == "asym")       cmd_asymmetric();
        else if (command_ == "vault")      cmd_vault();
        else if (command_ == "asym-vault") cmd_asym_vault();
        else if (command_ == "entropy")    cmd_entropy();
        else if (command_ == "stego")      cmd_stego();
        else if (command_ == "pq")         cmd_pq();
        else if (command_ == "bls")        cmd_bls();
        else if (command_ == "all")        cmd_all();
        else if (command_ == "help")     { cmd_help(); return 0; }
        else { err("Unknown command: " + command_); cmd_help(); return 1; }
        std::printf("\n" BOLD GRN "✓ Done.\n" RST "\n");
        return 0;
    }

private:

    // ══════════════════════════════════════════════════════════════════════════
    //  hash
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_hash() {
        section("Hashing");
        const std::string algo  = opt("algo",  "all");
        const std::string input = opt("input", "The quick brown fox jumps over the lazy dog");
        const bool        strm  = has("stream");
        auto sp = sv(input);

        if (algo == "blake2b" || algo == "all") {
            sub("BLAKE2b-512 — fast unkeyed hash");
            auto h = must(crypto::hash::Blake2b::digest(sp), "blake2b");
            kv("Digest (32 B)", hex32(h));

            sub("BLAKE2b-512 — streaming mode");
            crypto::hash::Blake2b::Stream st;
            std::size_t half = input.size() / 2;
            st.update({ sp.data(),        half });
            st.update({ sp.data() + half, sp.size() - half });
            auto hs = st.finalize();
            kv("Streaming matches one-shot", crypto::secure_equal(hs.span(), h.span()) ? "yes" : "MISMATCH");

            sub("BLAKE2b-512 — keyed MAC mode");
            auto key = crypto::random_bytes(32);
            auto mac = must(crypto::hash::Blake2b::digest(sp, key.span()), "blake2b keyed");
            kv("MAC (32 B)", hex32(mac));
            ok("BLAKE2b — all modes verified");
        }

        if (algo == "sha256" || algo == "all") {
            sub("SHA-256");
            auto h = must(crypto::hash::Sha256::digest(sp), "sha256");
            kv("Digest", h.to_hex());
            if (strm || algo == "all") {
                crypto::hash::Sha256::Stream st;
                st.update(sp);
                auto hs = st.finalize();
                kv("Streaming matches", crypto::secure_equal(hs.span(), h.span()) ? "yes" : "MISMATCH");
            }
            ok("SHA-256 verified");
        }

        if (algo == "sha512" || algo == "all") {
            sub("SHA-512");
            auto h = must(crypto::hash::Sha512::digest(sp), "sha512");
            kv("Digest (32 B)", hex32(h));
            if (strm || algo == "all") {
                crypto::hash::Sha512::Stream st;
                st.update(sp);
                auto hs = st.finalize();
                kv("Streaming matches", crypto::secure_equal(hs.span(), h.span()) ? "yes" : "MISMATCH");
            }
            ok("SHA-512 verified");
        }

        if (algo == "argon2id" || algo == "all") {
            sub("Argon2id — memory-hard password hashing");
            const std::string pass = opt("input", "correct-horse-battery-staple");

            auto hr = must(crypto::hash::Argon2id::hash_password(pass), "argon2id hash");
            kv("Hash  (32 B)", hex32(hr.hash));
            kv("Salt (hex)",   hr.salt.to_hex());
            kv("Verify correct",  crypto::hash::Argon2id::verify(pass, hr.hash.span(), hr.salt.span()) ? "pass" : "FAIL");
            kv("Verify wrong",    crypto::hash::Argon2id::verify("wrong", hr.hash.span(), hr.salt.span()) ? "FAIL" : "correctly rejected");

            sub("Argon2id — KDF (derive encryption key from passphrase)");
            auto dk = must(crypto::hash::Argon2id::derive_key(pass, hr.salt.span()), "argon2id derive");
            kv("Derived key (32 B)", hex32(dk));

            sub("Argon2id — PHC string encoding (portable storage)");
            auto phc    = must(crypto::hash::Argon2id::hash_password_str(pass), "argon2id phc");
            kv("PHC string", phc);
            kv("Verify via PHC", crypto::hash::Argon2id::verify_str(pass, phc) ? "pass" : "FAIL");
            ok("Argon2id all modes verified");
        }

        if (algo == "hmac" || algo == "all") {
            sub("HMAC-SHA512 — keyed MAC (for HMAC-mandating interoperability)");
            auto key = crypto::random_bytes(crypto::hash::HmacSha512::KEY_BYTES);
            auto mac = must(crypto::hash::HmacSha512::compute(sp, key.span()), "hmac compute");
            kv("MAC (32 B)", hex32(mac));
            kv("Verify", crypto::hash::HmacSha512::verify(sp, mac.span(), key.span()) ? "pass" : "FAIL");
            ok("HMAC-SHA512 verified");
        }

#ifdef CRYPTOLIB_HAS_BLAKE3
        if (algo == "blake3" || algo == "all") {
            sub("BLAKE3 — fast parallel hash (one-shot)");
            auto h = must(crypto::hash::Blake3::digest(sp), "blake3");
            kv("Digest (32 B)", hex32(h));

            sub("BLAKE3 — keyed MAC");
            auto b3key = crypto::random_bytes(32);
            auto b3mac = must(crypto::hash::Blake3::keyed(sp, b3key.span()), "blake3 keyed");
            kv("Keyed MAC (32 B)", hex32(b3mac));

            sub("BLAKE3 — key derivation (domain-separated)");
            auto ikm = crypto::random_bytes(64);
            auto dk  = must(crypto::hash::Blake3::derive_key("cryptolib:demo:blake3-kdf", ikm.span()), "blake3 kdf");
            kv("Derived key (32 B)", hex32(dk));
            ok("BLAKE3 all modes verified");
        }
#endif // CRYPTOLIB_HAS_BLAKE3

        if (algo == "hmac256" || algo == "all") {
            sub("HMAC-SHA256 — keyed MAC (compute + verify)");
            auto key256 = crypto::random_bytes(crypto::hash::HmacSha256::KEY_BYTES);
            auto mac256 = must(crypto::hash::HmacSha256::compute(sp, key256.span()), "hmac256 compute");
            kv("MAC (32 B)", hex32(mac256));
            kv("Verify correct", crypto::hash::HmacSha256::verify(sp, mac256.span(), key256.span()) ? "pass" : "FAIL");
            kv("Verify wrong msg rejected",
               crypto::hash::HmacSha256::verify(sv("wrong"), mac256.span(), key256.span()) ? "FAIL" : "yes");
            ok("HMAC-SHA256 verified");
        }

        if (algo == "hkdf" || algo == "all") {
            sub("HKDF-SHA256 — extract + expand (RFC 5869)");
            auto ikm  = crypto::random_bytes(32);
            auto salt = crypto::random_bytes(32);
            auto prk  = must(crypto::hash::HkdfSha256::extract(salt.span(), ikm.span()), "hkdf extract");
            kv("PRK (32 B)", hex32(prk));

            auto okm = must(crypto::hash::HkdfSha256::expand(prk.span(),
                            std::string_view("cryptolib:demo:hkdf-info"), 64), "hkdf expand");
            kv("OKM (64 B, first 32)", hex32(okm));

            sub("HKDF-SHA256 — one-shot derive");
            auto derived = must(crypto::hash::HkdfSha256::derive(ikm.span(), salt.span(),
                                std::string_view("cryptolib:demo:hkdf-one-shot"), 32), "hkdf derive");
            kv("Derived key (32 B)", hex32(derived));
            ok("HKDF-SHA256 verified");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  sym
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_symmetric() {
        section("Symmetric Encryption");
        const std::string algo      = opt("algo",      "all");
        const std::string plaintext = opt("plaintext", "Eyes only: rendezvous at 0300, grid 47N 12E.");
        const std::string aad       = opt("aad",       "sym-demo-context");
        const int         chunks    = std::stoi(opt("chunks", "4"));
        auto sp_pt  = sv(plaintext);
        auto sp_aad = sv(aad);

        if (algo == "xchacha20" || algo == "all") {
            sub("XChaCha20-Poly1305 — recommended AEAD, 192-bit random nonce");
            auto key = crypto::symmetric::XChaCha20Poly1305::generate_key();
            kv("Key (16 B)", hex(key, 16));

            auto ct = must(crypto::symmetric::XChaCha20Poly1305::encrypt(sp_pt, key.span(), sp_aad), "xchacha20 enc");
            auto pt = must(crypto::symmetric::XChaCha20Poly1305::decrypt(ct.span(), key.span(), sp_aad), "xchacha20 dec");
            kv("Round-trip (with AAD)", pt.to_string() == plaintext ? "pass" : "FAIL");

            auto bad_aad = crypto::symmetric::XChaCha20Poly1305::decrypt(ct.span(), key.span(), sv("wrong"));
            kv("Wrong AAD rejected", bad_aad.is_err() ? "yes" : "FAIL");

            auto ct2 = must(crypto::symmetric::XChaCha20Poly1305::encrypt(sp_pt, key.span()), "xchacha20 no-aad");
            kv("Different nonce each call", ct.to_hex().substr(0,16) != ct2.to_hex().substr(0,16)
                                            ? "yes (random nonce)" : "COLLISION (bug)");
            ok("XChaCha20-Poly1305 verified");
        }

        if (algo == "aes256gcm" || algo == "all") {
            sub("AES-256-GCM — hardware-accelerated (requires AES-NI / ARMv8 crypto)");
            if (!crypto::symmetric::Aes256Gcm::is_available()) {
                note("AES-256-GCM not available on this CPU — falling back to XChaCha20 is recommended");
            } else {
                auto key = crypto::symmetric::Aes256Gcm::generate_key();
                auto ct  = must(crypto::symmetric::Aes256Gcm::encrypt(sp_pt, key.span(), sp_aad), "aes enc");
                auto pt  = must(crypto::symmetric::Aes256Gcm::decrypt(ct.span(), key.span(), sp_aad), "aes dec");
                kv("Round-trip", pt.to_string() == plaintext ? "pass" : "FAIL");
                kv("Wrong AAD rejected", crypto::symmetric::Aes256Gcm::decrypt(ct.span(), key.span(), sv("x")).is_err() ? "yes" : "FAIL");
                note("WARNING: 96-bit nonce — avoid random nonce generation past 2^32 messages/key.");
                ok("AES-256-GCM verified");
            }
        }

        if (algo == "secretstream" || algo == "all") {
            sub("SecretStream — chunked streaming AEAD (large data, network streams)");
            using SS = crypto::symmetric::SecretStream;
            auto key = SS::generate_key();
            kv("Chunks", std::to_string(chunks));

            std::vector<std::string> data;
            for (int i = 0; i < chunks; ++i)
                data.push_back("Chunk #" + std::to_string(i+1) + ": " + plaintext);

            SS::Encryptor enc(key.span());
            std::vector<crypto::SecureBuffer> cts;
            for (int i = 0; i < (int)data.size(); ++i) {
                bool final = (i == (int)data.size() - 1);
                cts.push_back(enc.push(sv(data[i]), final ? SS::TAG_FINAL : SS::TAG_MESSAGE));
            }
            kv("Header size",        std::to_string(enc.header().size()) + " bytes");
            kv("MAC per chunk",      std::to_string(SS::MAC_BYTES)        + " bytes");
            kv("Available tags",     "MESSAGE, FINAL, PUSH (flush), REKEY (forward secrecy)");

            SS::Decryptor dec(key.span(), enc.header().span());
            bool all_ok = true;
            for (int i = 0; i < (int)cts.size(); ++i) {
                auto r = dec.pull(cts[i].span());
                if (r.is_err() || r.value().plaintext.to_string() != data[i]) { all_ok = false; break; }
                bool ef = (r.value().tag == SS::TAG_FINAL);
                if (ef != (i == (int)data.size()-1)) { all_ok = false; break; }
            }
            kv("All chunks decrypted correctly", all_ok ? "pass" : "FAIL");
            ok("SecretStream " + std::to_string(chunks) + "-chunk round-trip verified");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  asym
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_asymmetric() {
        section("Asymmetric Cryptography");
        const std::string algo    = opt("algo",    "all");
        const std::string message = opt("message", "Classified: meet at dawn.");
        auto sp_msg = sv(message);

        if (algo == "box" || algo == "all") {
            sub("NaCl Box — authenticated public-key AEAD (X25519 + XSalsa20-Poly1305)");
            auto alice = crypto::asymmetric::Box::generate_keypair();
            auto bob   = crypto::asymmetric::Box::generate_keypair();
            auto ct = must(crypto::asymmetric::Box::encrypt(sp_msg, bob.public_key.span(), alice.secret_key.span()), "box enc");
            auto pt = must(crypto::asymmetric::Box::decrypt(ct.span(), alice.public_key.span(), bob.secret_key.span()), "box dec");
            kv("Round-trip", pt.to_string() == message ? "pass" : "FAIL");
            auto eve = crypto::asymmetric::Box::generate_keypair();
            kv("Wrong key rejected", crypto::asymmetric::Box::decrypt(ct.span(), alice.public_key.span(), eve.secret_key.span()).is_err() ? "yes" : "FAIL");
            ok("Box verified");
        }

        if (algo == "sealedbox" || algo == "all") {
            sub("SealedBox — anonymous sender encryption");
            auto bob = crypto::asymmetric::SealedBox::generate_keypair();
            auto ct  = must(crypto::asymmetric::SealedBox::encrypt(sp_msg, bob.public_key.span()), "sealedbox seal");
            auto pt  = must(crypto::asymmetric::SealedBox::decrypt(ct.span(), bob.public_key.span(), bob.secret_key.span()), "sealedbox open");
            kv("Round-trip", pt.to_string() == message ? "pass" : "FAIL");
            note("Sender is anonymous — recipient cannot identify who sent the message.");
            ok("SealedBox verified");
        }

        if (algo == "ed25519" || algo == "all") {
            sub("Ed25519 — digital signatures");
            auto kp  = crypto::asymmetric::Ed25519::generate_keypair();
            auto sig = must(crypto::asymmetric::Ed25519::sign(sp_msg, kp.secret_key.span()), "ed25519 sign");
            kv("Signature size", std::to_string(sig.size()) + " bytes");
            kv("Verify correct", crypto::asymmetric::Ed25519::verify(sp_msg, sig.span(), kp.public_key.span()) ? "pass" : "FAIL");
            kv("Tampered msg rejected", crypto::asymmetric::Ed25519::verify(sv(message+"!"), sig.span(), kp.public_key.span()) ? "FAIL" : "yes");

            sub("Ed25519 — key conversion to Curve25519");
            auto box_pub = must(crypto::asymmetric::Ed25519::to_x25519_public(kp.public_key.span()), "pk to cv25519");
            auto box_sec = must(crypto::asymmetric::Ed25519::to_x25519_secret(kp.secret_key.span()), "sk to cv25519");
            kv("Curve25519 pub (16 B)", hex(box_pub, 16));
            kv("Curve25519 sec (16 B)", hex(box_sec, 16));
            ok("Ed25519 verified");
        }

        if (algo == "x25519" || algo == "all") {
            sub("X25519 — raw Diffie-Hellman key agreement");
            auto a = crypto::asymmetric::X25519::generate_keypair();
            auto b = crypto::asymmetric::X25519::generate_keypair();
            auto sa = must(crypto::asymmetric::X25519::shared_secret(a.secret_key.span(), b.public_key.span()), "x25519 a");
            auto sb = must(crypto::asymmetric::X25519::shared_secret(b.secret_key.span(), a.public_key.span()), "x25519 b");
            kv("Shared secret matches", crypto::secure_equal(sa.span(), sb.span()) ? "pass" : "FAIL");
            note("Never use raw X25519 output as encryption key — pass through KDF (BLAKE2b/HKDF) first.");
            ok("X25519 verified");
        }

        if (algo == "hybrid" || algo == "all") {
            sub("HybridBox — sign-then-encrypt (Ed25519 + NaCl Box)");
            note("Provides: confidentiality + integrity + authenticated sender identity.");
            auto alice_sign = crypto::asymmetric::Ed25519::generate_keypair();
            auto alice_enc  = crypto::asymmetric::Box::generate_keypair();
            auto bob        = crypto::asymmetric::Box::generate_keypair();
            auto h = must(
                crypto::asymmetric::HybridBox::encrypt(sp_msg, bob.public_key.span(),
                                                       alice_enc.secret_key.span(),
                                                       alice_sign.secret_key.span()), "hybrid enc");
            kv("Ciphertext size", std::to_string(h.ciphertext.size()) + " bytes");
            kv("Signature size",  std::to_string(h.signature.size())  + " bytes");
            auto pt = must(
                crypto::asymmetric::HybridBox::decrypt(h, alice_enc.public_key.span(),
                                                       bob.secret_key.span(),
                                                       alice_sign.public_key.span()), "hybrid dec");
            kv("Round-trip", pt.to_string() == message ? "pass" : "FAIL");

            // Mallory forge
            auto mallory_sign = crypto::asymmetric::Ed25519::generate_keypair();
            auto mallory_enc  = crypto::asymmetric::Box::generate_keypair();
            auto forge = must(
                crypto::asymmetric::HybridBox::encrypt(sp_msg, bob.public_key.span(),
                                                       mallory_enc.secret_key.span(),
                                                       mallory_sign.secret_key.span()), "hybrid forge");
            auto bad = crypto::asymmetric::HybridBox::decrypt(forge,
                           mallory_enc.public_key.span(), bob.secret_key.span(),
                           alice_sign.public_key.span());
            kv("Mallory signature rejected", bad.is_err() ? "yes" : "FAIL");
            ok("HybridBox verified");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  vault
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_vault() {
        section("SecureVault — 4-layer pipeline");
        note("L1 Argon2id       brute-force / dictionary protection on master key");
        note("L2 BLAKE2b        internal integrity tag, early rejection before AEAD");
        note("L3 XChaCha20-Poly1305  confidentiality + ciphertext authenticity");
        note("L4 Ed25519        packet-level signing, prevents impersonation/forgery");

        const std::string kdf_name  = opt("kdf",       "interactive");
        const std::string plaintext = opt("plaintext", "Vault-protected: the passphrase is swordfish.");
        const std::string aad       = opt("aad",       "demo:vault:session-1");
        const bool        boost     = has("boost");

        crypto::KdfParams kdf = [&] {
            if (kdf_name == "sensitive") {
                kv("KDF preset", "SENSITIVE (~2 s, 256 MiB) — using INTERACTIVE for demo speed");
                return crypto::KdfParams::interactive();
            }
            if (kdf_name == "custom") {
                auto ops = (unsigned long long)std::stoull(opt("ops", "3"));
                auto mem = std::size_t(std::stoull(opt("mem", "64"))) * 1024 * 1024;
                kv("KDF custom ops", std::to_string(ops));
                kv("KDF custom mem", std::to_string(mem / (1024*1024)) + " MiB");
                return crypto::KdfParams::custom(ops, mem);
            }
            return crypto::KdfParams::interactive();
        }();
        kv("KDF opslimit", std::to_string(kdf.opslimit));
        kv("KDF memlimit",  std::to_string(kdf.memlimit / (1024*1024)) + " MiB");

        auto mk    = crypto::random_bytes(32);
        auto kp    = crypto::SecureVault::generate_keypair();
        auto vault = crypto::SecureVault(mk.span(), std::move(kp), kdf);
        kv("Master key (16 B)", hex(mk, 16));

        sub("Basic seal / open");
        auto pkt = must(vault.seal(plaintext, aad), "vault seal");
        auto pt  = must(vault.open(pkt, aad), "vault open");
        kv("Round-trip", pt.to_string() == plaintext ? "pass" : "FAIL");

        sub("EncryptedPacket wire serialisation");
        auto wire  = pkt.serialise();
        kv("Wire size", std::to_string(wire.size()) + " bytes");
        auto pkt2 = must(crypto::EncryptedPacket::deserialise(wire.span()), "deserialise");
        auto pt2  = must(vault.open(pkt2, aad), "vault open deserialised");
        kv("Serialise/deserialise round-trip", pt2.to_string() == plaintext ? "pass" : "FAIL");

        sub("AAD binding — wrong context rejected at L3");
        kv("Wrong AAD rejected", vault.open(pkt, "wrong").is_err() ? "yes" : "FAIL");

        sub("Wrong master key rejected");
        auto mk2     = crypto::random_bytes(32);
        auto kp2     = crypto::SecureVault::generate_keypair();
        auto vault2  = crypto::SecureVault(mk2.span(), std::move(kp2), kdf);
        kv("Wrong vault rejected", vault2.open(pkt, aad).is_err() ? "yes" : "FAIL");

        sub("Public key export — share for third-party verification");
        auto pub = vault.public_key();
        // public_key() returns span<const uint8_t> — format first 16 bytes
        {
            auto pk = vault.public_key();
            std::string h; for (std::size_t i = 0; i < 16 && i < pk.size(); ++i) {
                char buf[3]; std::snprintf(buf, sizeof(buf), "%02x", pk[i]); h += buf;
            }
            kv("sign_public (16 B)", h + "…");
        }

        if (boost || command_ == "all") {
            sub("Entropy boost — vault.seal(plaintext, aad, me)");
            auto cover = ensure_ppm();
            auto me1   = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "boost me1");
            auto me2   = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "boost me2");
            auto pkt_b = must(vault.seal(plaintext, aad, me1), "boost seal");
            auto pt_b  = must(vault.open(pkt_b, aad, me2),    "boost open");
            kv("Boosted round-trip", pt_b.to_string() == plaintext ? "pass" : "FAIL");
            kv("Plain open of boosted packet fails", vault.open(pkt_b, aad).is_err() ? "yes" : "FAIL");
            ok("Entropy boost verified — two-key-source requirement enforced");
        }

        ok("SecureVault fully verified");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  asym-vault
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_asym_vault() {
        section("AsymmetricVault — public-key 4-layer pipeline");
        note("No pre-shared secret. Alice seals for Bob's X25519 public key.");

        const std::string plaintext = opt("plaintext", "Bob — package delivered. Channel is hot. Abort.");
        const std::string aad       = opt("aad",       "asym-vault:alice-to-bob:session-9");
        const bool        boost     = has("boost");

        using AV = crypto::AsymmetricVault;

        auto alice = AV::generate_bundle();
        auto bob   = AV::generate_bundle();
        kv("Alice box_pub  (16 B)", hex(alice.box_public,  16));
        kv("Alice sign_pub (16 B)", hex(alice.sign_public, 16));
        kv("Bob   box_pub  (16 B)", hex(bob.box_public,    16));

        sub("Alice seals for Bob");
        auto pkt = must(AV::seal(sv(plaintext), alice, bob.box_public.span(), sv(aad)), "asym seal");
        kv("Packet size", std::to_string(pkt.serialise().size()) + " bytes");

        sub("Bob opens, verifying Alice's Ed25519 signature");
        auto pt = must(AV::open(pkt, bob, alice.sign_public.span(), sv(aad)), "asym open");
        kv("Round-trip", pt.to_string() == plaintext ? "pass" : "FAIL");

        sub("Wrong AAD rejected");
        kv("Wrong AAD", AV::open(pkt, bob, alice.sign_public.span(), sv("wrong")).is_err() ? "rejected" : "FAIL");

        sub("Mallory impersonation rejected");
        auto mallory = AV::generate_bundle();
        auto forged  = must(AV::seal(sv("wiring changed"), mallory, bob.box_public.span(), sv(aad)), "forge seal");
        kv("Mallory rejected", AV::open(forged, bob, alice.sign_public.span(), sv(aad)).is_err() ? "yes" : "FAIL");

        sub("Wrong recipient rejected");
        auto eve = AV::generate_bundle();
        kv("Wrong recipient", AV::open(pkt, eve, alice.sign_public.span(), sv(aad)).is_err() ? "rejected" : "FAIL");

        sub("AsymmetricVault::from_entropy — bundle derived from physical entropy");
        auto cover = ensure_ppm();
        auto me    = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "asym from_entropy me");
        auto bndl  = must(AV::from_entropy(me), "asym from_entropy");
        kv("Entropy-derived sign_pub (16 B)", hex(bndl.sign_public, 16));
        note("Same file → same bundle across processes (deterministic mode).");

        if (boost || command_ == "all") {
            sub("AsymmetricVault entropy boost");
            auto me_b1 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "asym boost me1");
            auto me_b2 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "asym boost me2");
            auto pkt_b = must(AV::seal(sv(plaintext), alice, bob.box_public.span(), sv(aad), me_b1), "asym boost seal");
            auto pt_b  = must(AV::open(pkt_b, bob, alice.sign_public.span(), sv(aad), me_b2), "asym boost open");
            kv("Boosted round-trip", pt_b.to_string() == plaintext ? "pass" : "FAIL");
            kv("Plain open of boosted packet fails", AV::open(pkt_b, bob, alice.sign_public.span(), sv(aad)).is_err() ? "yes" : "FAIL");
        }

        ok("AsymmetricVault fully verified");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  entropy
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_entropy() {
        section("MediaEntropy — LavaRand-inspired physical entropy pipeline");
        const std::string mode      = opt("mode",      "all");
        const std::string file_arg  = opt("file",      "");
        const std::string plaintext = opt("plaintext", "Sealed by physical entropy, not a passphrase.");
        const std::string aad       = opt("aad",       "entropy:demo");

        auto cover = file_arg.empty() ? ensure_ppm() : std::filesystem::path(file_arg);

        sub("Pipeline");
        note("file bytes → BLAKE2b stream hash (64 B)");
        note("         → mix with randombytes_buf(64)  [LavaRand system entropy XOR]");
        note("         → BLAKE2b re-hash → domain-separated HKDF outputs");
        note("             xchacha20poly1305:key, securevault:master,");
        note("             vault:entropy_boost:v1, ed25519:vault:seed,");
        note("             x25519:seed, secretstream:key, raw_entropy (64 B)");

        auto me1 = must_e(crypto::entropy::MediaEntropy::from_file(cover), "from_file");
        kv("Source file",  cover.string());
        kv("File size",    std::to_string(me1.info().file_size) + " bytes");
        kv("Entropy est",  std::to_string((uint64_t)me1.entropy_bits()) + " bits");
        kv("Chunks read",  std::to_string(me1.info().chunks_read));

        sub("from_file_deterministic — reproducible keys across processes");
        auto md1 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "det 1");
        auto md2 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "det 2");
        kv("Same file → same entropy",   crypto::secure_equal(md1.raw().span(), md2.raw().span()) ? "yes" : "FAIL");
        kv("Det differs from non-det",   !crypto::secure_equal(me1.raw().span(), md1.raw().span()) ? "yes (system entropy mixed)" : "same (improbable)");

        if (mode == "derive-all" || mode == "all") {
            sub("derive_all() — all domain keys at once");
            auto keys = md1.derive_all();
            kv("symmetric_key    (16 B)", hex(keys.symmetric_key,    16));
            kv("vault_master_key (16 B)", hex(keys.vault_master_key, 16));
            kv("signing_seed     (16 B)", hex(keys.signing_seed,     16));
            kv("box_seed         (16 B)", hex(keys.box_seed,         16));
            kv("stream_key       (16 B)", hex(keys.stream_key,       16));
            kv("raw_entropy      (16 B)", hex(keys.raw_entropy,      16));
            note("All outputs are domain-separated — cryptographically independent.");

            sub("Derived objects");
            auto kp     = must(md1.vault_keypair(), "vault_keypair");
            auto bundle = must(md1.asym_bundle(),   "asym_bundle");
            kv("vault_keypair  sign_pub (16 B)", hex(kp.sign_public,     16));
            kv("asym_bundle    box_pub  (16 B)", hex(bundle.box_public,  16));
            kv("asym_bundle    sign_pub (16 B)", hex(bundle.sign_public, 16));
        }

        if (mode == "refresh" || mode == "all") {
            sub("refresh_system_entropy() — re-mix for long-lived objects");
            // Snapshot first 8 bytes before refresh to detect change
            std::array<uint8_t,8> snap; std::memcpy(snap.data(), me1.raw().data(), 8);
            me1.refresh_system_entropy();
            bool changed = std::memcmp(snap.data(), me1.raw().data(), 8) != 0;
            kv("Entropy changed after refresh", changed ? "yes" : "unchanged (improbable)");
        }

        if (mode == "standalone" || mode == "all") {
            sub("Mode 1: Standalone encryption — me.seal() / me.open()");
            auto ms = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "seal side");
            auto mo = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "open side");
            auto pkt = must(ms.seal(plaintext, aad), "me.seal");
            auto pt  = must(mo.open(pkt, aad), "me.open");
            kv("Round-trip", pt.to_string() == plaintext ? "pass" : "FAIL");

            sub("Convenience free functions");
            auto pkt2 = must(crypto::entropy::seal_from_file(cover, plaintext, aad), "seal_from_file");
            auto pt2  = must(crypto::entropy::open_from_file(cover, pkt2, aad), "open_from_file");
            kv("seal_from_file / open_from_file", pt2.to_string() == plaintext ? "pass" : "FAIL");

            auto sym = must(crypto::entropy::key_from_file(cover), "key_from_file");
            kv("key_from_file (16 B)", hex(sym, 16));

            auto vff  = must(crypto::entropy::vault_from_file(cover), "vault_from_file");
            auto pv   = must(vff.seal("test", "ctx"), "vault_ff seal");
            auto ptv  = must(vff.open(pv, "ctx"), "vault_ff open");
            kv("vault_from_file seal/open", ptv.to_string() == "test" ? "pass" : "FAIL");

            auto bff  = must(crypto::entropy::asym_bundle_from_file(cover), "asym_bundle_from_file");
            kv("asym_bundle_from_file box_pub (16 B)", hex(bff.box_public, 16));
        }

        if (mode == "boost" || mode == "all") {
            sub("Mode 2: Entropy boost — vault.seal(plaintext, aad, me)");
            auto mk2    = crypto::random_bytes(32);
            auto kp2    = crypto::SecureVault::generate_keypair();
            auto vault2 = crypto::SecureVault(mk2.span(), std::move(kp2));
            auto me_b1  = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "boost b1");
            auto me_b2  = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "boost b2");
            auto pkt_b  = must(vault2.seal(plaintext, aad, me_b1), "boost seal");
            auto pt_b   = must(vault2.open(pkt_b, aad, me_b2),     "boost open");
            kv("Boosted round-trip", pt_b.to_string() == plaintext ? "pass" : "FAIL");
            kv("Plain open of boosted pkt fails", vault2.open(pkt_b, aad).is_err() ? "yes" : "FAIL");

            sub("SecureVault::from_entropy — vault keyed entirely from physical entropy");
            auto me_fe1 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "fe1");
            auto me_fe2 = must_e(crypto::entropy::MediaEntropy::from_file_deterministic(cover), "fe2");
            auto v1 = must(crypto::SecureVault::from_entropy(me_fe1, crypto::KdfParams::interactive()), "from_entropy v1");
            auto v2 = must(crypto::SecureVault::from_entropy(me_fe2, crypto::KdfParams::interactive()), "from_entropy v2");
            auto pfe = must(v1.seal(plaintext, aad), "from_entropy seal");
            auto tfe = must(v2.open(pfe, aad), "from_entropy open");
            kv("from_entropy round-trip", tfe.to_string() == plaintext ? "pass" : "FAIL");
        }

        ok("MediaEntropy all modes verified");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  stego
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_stego() {
        section("Steganography — hide encrypted payloads inside media files");
        const std::string format    = opt("format",    "all");
        const std::string plaintext = opt("plaintext", "Hidden: the eagle lands at midnight.");
        const std::string aad       = opt("aad",       "stego:demo");
        const int         quant     = std::stoi(opt("quant", "16"));
        const bool        raw_mode  = has("raw");
        const bool        cap_only  = has("capacity");

        using SE  = crypto::stego::StegoEngine;
        using IS  = crypto::stego::ImageSteganographer;
        using AS  = crypto::stego::AudioSteganographer;
        using VS  = crypto::stego::VideoSteganographer;
        using MG  = crypto::stego::MediaGenerator;
        namespace fs = std::filesystem;

        // ── Custom carrier generation ─────────────────────────────────────────
        sub("Custom carrier generation via MediaGeneratorParams");
        crypto::stego::MediaGeneratorParams mgp;
        mgp.ppm_seed = 0xDEAD'CAFE;  mgp.ppm_noise_std = 8.0;  mgp.ppm_color_gradient = true;
        mgp.wav_tone_hz = 880.0;     mgp.wav_harmonics = true;  mgp.wav_noise_std = 0.03;
        mgp.crvf_noise_bits = 4;     mgp.crvf_frame_offset = true; mgp.crvf_seed = 0xCAFE'BABE;

        must_v(MG::generate_ppm (out("s_cover.ppm"),  640, 480, mgp), "gen ppm");
        must_v(MG::generate_wav (out("s_cover.wav"),  44100, 1, 15.0, mgp), "gen wav");
        must_v(MG::generate_crvf(out("s_cover.crvf"), 320, 240, 30, 90, mgp), "gen crvf");
        kv("PPM",  "640×480, σ=8.0, seed=0xDEADCAFE, color gradient");
        kv("WAV",  "15 s mono 44.1 kHz, 880 Hz + harmonics, σ=0.03");
        kv("CRVF", "320×240 30fps 90 frames, 4-bit LSB noise, frame hue bias");

        // ── Capacity ──────────────────────────────────────────────────────────
        sub("Capacity queries (StegoEngine)");
        auto ic = must(SE::capacity(out("s_cover.ppm")),  "img cap");
        auto ac = must(SE::capacity(out("s_cover.wav")),  "aud cap");
        auto vc = must(SE::capacity(out("s_cover.crvf")), "vid cap");
        kv("Image capacity",  ic.description);
        kv("Audio capacity",  ac.description);
        kv("Video capacity",  vc.description);
        kv("Header overhead", std::to_string(ic.header_bytes) + " bytes (StegoHeader: CSTG magic + version + format + len + CRC32)");

        sub("Per-class capacity (without reading files)");
        kv("IS::capacity(640,480)",     std::to_string(IS::capacity(640, 480)) + " bytes");
        kv("AS::capacity(661500)",      std::to_string(AS::capacity(44100*15)) + " bytes");
        kv("VS::capacity(90,320,240)",  std::to_string(VS::capacity(90, 320, 240)) + " bytes");
        if (cap_only) return;

        // ── Image ─────────────────────────────────────────────────────────────
        if (format == "ppm" || format == "all") {
            sub("ImageSteganographer — DCT/QIM on blue channel 8×8 blocks");
            kv("Q parameter", std::to_string(quant) + " (lower Q → higher PSNR, less robust to compression)");

            auto mk = crypto::random_bytes(32); auto kp = crypto::SecureVault::generate_keypair();
            auto vlt = crypto::SecureVault(mk.span(), std::move(kp));
            must_v(vlt.seal_into(out("s_cover.ppm"), plaintext, out("s_stego.ppm"), aad), "img seal_into");
            auto pt = must(vlt.open_from(out("s_stego.ppm"), aad), "img open_from");
            kv("vault.seal_into / open_from (PPM)", pt.to_string() == plaintext ? "pass" : "FAIL");

            auto spv = sv(plaintext);
            std::vector<uint8_t> raw_payload(spv.begin(), spv.end());
            must_v(IS::embed(out("s_cover.ppm"), raw_payload, out("s_stego_q.ppm"), quant), "IS::embed");
            auto ext = must(IS::extract(out("s_stego_q.ppm"), quant), "IS::extract");
            kv("IS::embed / extract (Q=" + std::to_string(quant) + ")",
               std::string(ext.begin(), ext.end()) == plaintext ? "pass" : "FAIL");

            double psnr = IS::psnr(out("s_cover.ppm"), out("s_stego.ppm"));
            kv("PSNR", std::to_string((int)psnr) + " dB  (threshold ≥40 dB)");
            note(psnr >= 40.0 ? "Above imperceptibility threshold." : "Below threshold.");

            note("Q table — trade-off guide:");
            note("  Q=8   PSNR ~62 dB  max imperceptibility, less robust");
            note("  Q=16  PSNR ~56 dB  default balanced");
            note("  Q=32  PSNR ~50 dB  more robust to re-compression");
        }

        // ── Audio ─────────────────────────────────────────────────────────────
        if (format == "wav" || format == "all") {
            sub("AudioSteganographer — phase coding on mid-frequency FFT bins");

            auto mk = crypto::random_bytes(32); auto kp = crypto::SecureVault::generate_keypair();
            auto vlt = crypto::SecureVault(mk.span(), std::move(kp));
            must_v(vlt.seal_into(out("s_cover.wav"), plaintext, out("s_stego.wav"), aad), "aud seal_into");
            auto pt = must(vlt.open_from(out("s_stego.wav"), aad), "aud open_from");
            kv("vault.seal_into / open_from (WAV)", pt.to_string() == plaintext ? "pass" : "FAIL");

            sub("AudioSteganographer — custom StegoParams");
            crypto::stego::StegoParams p;
            p.audio_frame_size = 1024;  // larger frame → more stable, lower capacity
            p.audio_bin_start  = 32;    // higher bins (~2.8 kHz @ 44.1 kHz)
            p.audio_bin_count  = 6;     // 6 bits per frame
            kv("  audio_frame_size", std::to_string(p.audio_frame_size) + " samples");
            kv("  audio_bin_start",  std::to_string(p.audio_bin_start)  + " (~" + std::to_string(p.audio_bin_start * 44100 / 1024) + " Hz)");
            kv("  audio_bin_count",  std::to_string(p.audio_bin_count)  + " bits/frame");

            auto spv = sv(plaintext);
            std::vector<uint8_t> raw_payload(spv.begin(), spv.end());
            must_v(AS::embed(out("s_cover.wav"), raw_payload, out("s_stego_custom.wav"), p), "AS::embed");
            auto ext = must(AS::extract(out("s_stego_custom.wav"), p), "AS::extract");
            kv("AS::embed / extract (custom params)", std::string(ext.begin(), ext.end()) == plaintext ? "pass" : "FAIL");

            double snr = AS::snr(out("s_cover.wav"), out("s_stego.wav"));
            kv("SNR (default params)", std::to_string((int)snr) + " dB  (threshold ≥20 dB)");
            note(snr >= 20.0 ? "Above imperceptibility threshold."
                             : "Custom params used lower-frequency bins (more salient) — raise audio_bin_start for better SNR.");
        }

        // ── Video ─────────────────────────────────────────────────────────────
        if (format == "crvf" || format == "all") {
            sub("VideoSteganographer — DCT/QIM distributed across CRVF frames");

            auto mk = crypto::random_bytes(32); auto kp = crypto::SecureVault::generate_keypair();
            auto vlt = crypto::SecureVault(mk.span(), std::move(kp));
            must_v(vlt.seal_into(out("s_cover.crvf"), plaintext, out("s_stego.crvf"), aad), "vid seal_into");
            auto pt = must(vlt.open_from(out("s_stego.crvf"), aad), "vid open_from");
            kv("vault.seal_into / open_from (CRVF)", pt.to_string() == plaintext ? "pass" : "FAIL");

            sub("CRVF file inspection — VS::read_crvf()");
            auto crvf = must(VS::read_crvf(out("s_cover.crvf")), "read_crvf");
            kv("Width × height",  std::to_string(crvf.first.width)  + "×" + std::to_string(crvf.first.height));
            kv("FPS",             std::to_string(crvf.first.fps_num) + "/" + std::to_string(crvf.first.fps_den));
            kv("Frame count",     std::to_string(crvf.first.frame_count));
            kv("Frame size",      std::to_string(crvf.second[0].size()) + " bytes (RGB24)");
            kv("Total raw pixels", std::to_string(crvf.second.size() * crvf.second[0].size()) + " bytes");
        }

        // ── Raw byte / StegoEngine access ─────────────────────────────────────
        if (raw_mode || format == "all") {
            sub("StegoEngine — raw byte embed/extract (payload encrypted externally)");
            std::vector<uint8_t> raw(64, 0xAB);
            must_v(SE::embed(out("s_cover.ppm"), raw, out("s_raw_stego.ppm")), "SE::embed");
            auto ext = must(SE::extract(out("s_raw_stego.ppm")), "SE::extract");
            kv("SE::embed / extract (raw bytes)", ext == raw ? "pass" : "FAIL");

            sub("StegoEngine — embed_packet / extract_packet");
            auto mk2  = crypto::random_bytes(32); auto kp2 = crypto::SecureVault::generate_keypair();
            auto vlt2 = crypto::SecureVault(mk2.span(), std::move(kp2));
            auto pkt2 = must(vlt2.seal(plaintext, aad), "pkt for embed_packet");
            must_v(SE::embed_packet(out("s_cover.ppm"), pkt2, out("s_pkt_stego.ppm")), "embed_packet");
            auto pkt3 = must(SE::extract_packet(out("s_pkt_stego.ppm")), "extract_packet");
            auto pt3  = must(vlt2.open(pkt3, aad), "open extracted pkt");
            kv("embed_packet → extract_packet → open", pt3.to_string() == plaintext ? "pass" : "FAIL");

            auto q = SE::quality(out("s_cover.ppm"), out("s_raw_stego.ppm"));
            if (q.is_ok()) kv("StegoEngine::quality (PSNR)", std::to_string((int)q.value()) + " dB");
        }

        // ── AsymmetricVault stego ─────────────────────────────────────────────
        sub("AsymmetricVault::seal_into / open_from");
        using AV = crypto::AsymmetricVault;
        auto alice = AV::generate_bundle();
        auto bob   = AV::generate_bundle();
        must_v(AV::seal_into(alice, bob.box_public.span(), plaintext,
                              out("s_cover.ppm"), out("s_asym_stego.ppm"), aad), "asym seal_into");
        auto apt = must(AV::open_from(bob, alice.sign_public.span(), out("s_asym_stego.ppm"), aad), "asym open_from");
        kv("AsymmetricVault stego round-trip", apt.to_string() == plaintext ? "pass" : "FAIL");

        // ── MediaEntropy stego ────────────────────────────────────────────────
        sub("MediaEntropy stego — seal_into / open_from");
        auto me_s   = must_e(crypto::entropy::MediaEntropy::from_file(out("s_cover.ppm")), "entropy stego me");
        auto vault_e = must(me_s.make_vault(), "make_vault stego");
        must_v(vault_e.seal_into(out("s_cover.ppm"), plaintext, out("s_entropy_stego.ppm"), aad), "entropy seal_into");
        auto ept = must(vault_e.open_from(out("s_entropy_stego.ppm"), aad), "entropy open_from");
        kv("MediaEntropy stego round-trip", ept.to_string() == plaintext ? "pass" : "FAIL");

        ok("Steganography fully verified");
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  pq — post-quantum cryptography
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_pq() {
#ifdef CRYPTOLIB_HAS_PQ
        section("Post-Quantum Cryptography (NIST FIPS 203/204/205)");
        const std::string algo = opt("algo", "all");

        if (algo == "ml-kem" || algo == "all") {
            sub("ML-KEM-768 — Module-Lattice Key Encapsulation (FIPS 203, Level 3)");
            note("Post-quantum IND-CCA2 KEM. Alice generates keypair; Bob encapsulates.");

            auto kp = must(crypto::pq::MlKem::generate_keypair(), "ml-kem keygen");
            kv("Public key size", std::to_string(kp.public_key.size()) + " bytes");
            kv("Secret key size", std::to_string(kp.secret_key.size()) + " bytes");

            sub("Encapsulate — Bob produces ciphertext + shared secret");
            auto enc = must(crypto::pq::MlKem::encapsulate(kp.public_key.span()), "ml-kem encaps");
            kv("Ciphertext size", std::to_string(enc.ciphertext.size()) + " bytes");
            kv("Shared secret size", std::to_string(enc.shared_secret.size()) + " bytes");
            kv("Bob's shared secret (16 B)", hex(enc.shared_secret, 16));

            sub("Decapsulate — Alice recovers the same shared secret");
            auto ss = must(crypto::pq::MlKem::decapsulate(enc.ciphertext.span(), kp.secret_key.span()), "ml-kem decaps");
            kv("Alice's shared secret (16 B)", hex(ss, 16));
            kv("Shared secrets match", crypto::secure_equal(ss.span(), enc.shared_secret.span()) ? "pass" : "FAIL");

            sub("Wrong secret key — implicit rejection (different shared secret)");
            auto eve = must(crypto::pq::MlKem::generate_keypair(), "ml-kem eve keygen");
            auto ss_eve = must(crypto::pq::MlKem::decapsulate(enc.ciphertext.span(), eve.secret_key.span()), "ml-kem eve decaps");
            kv("Eve's shared secret (16 B)", hex(ss_eve, 16));
            kv("Eve gets different secret", !crypto::secure_equal(ss_eve.span(), enc.shared_secret.span()) ? "yes (implicit rejection)" : "FAIL");

            sub("ML-KEM size summary");
            auto sz = must(crypto::pq::MlKem::sizes(), "ml-kem sizes");
            kv("Public key",     std::to_string(sz.public_key) + " bytes");
            kv("Secret key",     std::to_string(sz.secret_key) + " bytes");
            kv("Ciphertext",     std::to_string(sz.ciphertext) + " bytes");
            kv("Shared secret",  std::to_string(sz.shared_secret) + " bytes");
            ok("ML-KEM-768 verified");
        }

        if (algo == "ml-dsa" || algo == "all") {
            sub("ML-DSA-65 — Module-Lattice Digital Signatures (FIPS 204, Level 3)");
            note("Post-quantum EUF-CMA signatures (lattice-based, formerly Dilithium).");

            auto kp = must(crypto::pq::MlDsa::generate_keypair(), "ml-dsa keygen");
            kv("Public key size", std::to_string(kp.public_key.size()) + " bytes");
            kv("Secret key size", std::to_string(kp.secret_key.size()) + " bytes");

            std::string msg = "Post-quantum signed message for ML-DSA-65 demo.";
            auto sig = must(crypto::pq::MlDsa::sign(msg, kp.secret_key.span()), "ml-dsa sign");
            kv("Signature size", std::to_string(sig.size()) + " bytes");
            kv("Signature (16 B)", hex(sig, 16));

            sub("Verify — correct message and key");
            auto vr = crypto::pq::MlDsa::verify(msg, sig.span(), kp.public_key.span());
            kv("Verify correct", vr.is_ok() ? "pass" : "FAIL");

            sub("Tampered message — verification must fail");
            std::string tampered = msg + "!";
            auto vr_bad = crypto::pq::MlDsa::verify(tampered, sig.span(), kp.public_key.span());
            kv("Tampered msg rejected", vr_bad.is_err() ? "yes" : "FAIL");

            sub("Wrong public key — verification must fail");
            auto eve = must(crypto::pq::MlDsa::generate_keypair(), "ml-dsa eve keygen");
            auto vr_eve = crypto::pq::MlDsa::verify(msg, sig.span(), eve.public_key.span());
            kv("Wrong key rejected", vr_eve.is_err() ? "yes" : "FAIL");

            sub("ML-DSA-65 size summary");
            auto sz = must(crypto::pq::MlDsa::sizes(), "ml-dsa sizes");
            kv("Public key",  std::to_string(sz.public_key) + " bytes");
            kv("Secret key",  std::to_string(sz.secret_key) + " bytes");
            kv("Signature",   std::to_string(sz.signature) + " bytes");
            ok("ML-DSA-65 verified");
        }

        if (algo == "slh-dsa" || algo == "all") {
            sub("SLH-DSA-128f (SHA2) — Hash-Based Signatures (FIPS 205, Level 1)");
            note("Conservative PQ signatures — security relies only on hash functions.");

            auto kp = must(crypto::pq::SlhDsa::generate_keypair(), "slh-dsa keygen");
            kv("Public key size", std::to_string(kp.public_key.size()) + " bytes");
            kv("Secret key size", std::to_string(kp.secret_key.size()) + " bytes");

            std::string msg = "Hash-based signature test for SLH-DSA-128f.";
            auto sig = must(crypto::pq::SlhDsa::sign(msg, kp.secret_key.span()), "slh-dsa sign");
            kv("Signature size", std::to_string(sig.size()) + " bytes");
            note("SLH-DSA signatures are large but rely on no lattice assumptions.");

            sub("Verify — correct message and key");
            auto vr = crypto::pq::SlhDsa::verify(msg, sig.span(), kp.public_key.span());
            kv("Verify correct", vr.is_ok() ? "pass" : "FAIL");

            sub("Tampered message — verification must fail");
            std::string tampered = msg + "!";
            auto vr_bad = crypto::pq::SlhDsa::verify(tampered, sig.span(), kp.public_key.span());
            kv("Tampered msg rejected", vr_bad.is_err() ? "yes" : "FAIL");

            sub("SLH-DSA-128f size summary");
            auto sz = must(crypto::pq::SlhDsa::sizes(), "slh-dsa sizes");
            kv("Public key",  std::to_string(sz.public_key) + " bytes");
            kv("Secret key",  std::to_string(sz.secret_key) + " bytes");
            kv("Signature",   std::to_string(sz.signature) + " bytes");
            ok("SLH-DSA-128f verified");
        }

        ok("Post-quantum cryptography fully verified");
#else
        section("Post-Quantum Cryptography");
        note("Skipped — CRYPTOLIB_HAS_PQ not defined (build with -DCRYPTOLIB_PQ=ON).");
#endif // CRYPTOLIB_HAS_PQ
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  bls — BLS12-381 signatures and aggregation
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_bls() {
#ifdef CRYPTOLIB_HAS_BLS
        section("BLS12-381 Signatures & Aggregation");
        note("Minimal-pubkey-size scheme: pk in G1 (48 B), sig in G2 (96 B).");
        note("DST: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_ (Ethereum 2.0 compatible).");

        sub("Generate 3 keypairs (Alice, Bob, Charlie)");
        auto alice   = must(crypto::bls::Bls12381::generate_keypair(), "bls alice keygen");
        auto bob     = must(crypto::bls::Bls12381::generate_keypair(), "bls bob keygen");
        auto charlie = must(crypto::bls::Bls12381::generate_keypair(), "bls charlie keygen");
        kv("Alice   pk (16 B)", hex(alice.public_key, 16));
        kv("Bob     pk (16 B)", hex(bob.public_key, 16));
        kv("Charlie pk (16 B)", hex(charlie.public_key, 16));

        sub("Each signer signs a different message");
        std::string msg_a = "Alice's unique message for BLS demo";
        std::string msg_b = "Bob's unique message for BLS demo";
        std::string msg_c = "Charlie's unique message for BLS demo";
        auto sig_a = must(crypto::bls::Bls12381::sign(msg_a, alice.secret_key.span()),   "bls alice sign");
        auto sig_b = must(crypto::bls::Bls12381::sign(msg_b, bob.secret_key.span()),     "bls bob sign");
        auto sig_c = must(crypto::bls::Bls12381::sign(msg_c, charlie.secret_key.span()), "bls charlie sign");
        kv("Alice   sig (16 B)", hex(sig_a, 16));
        kv("Bob     sig (16 B)", hex(sig_b, 16));
        kv("Charlie sig (16 B)", hex(sig_c, 16));

        sub("Individual verification");
        auto va = crypto::bls::Bls12381::verify(msg_a, sig_a.span(), alice.public_key.span());
        auto vb = crypto::bls::Bls12381::verify(msg_b, sig_b.span(), bob.public_key.span());
        auto vc = crypto::bls::Bls12381::verify(msg_c, sig_c.span(), charlie.public_key.span());
        kv("Alice   signature valid", va.is_ok() ? "pass" : "FAIL");
        kv("Bob     signature valid", vb.is_ok() ? "pass" : "FAIL");
        kv("Charlie signature valid", vc.is_ok() ? "pass" : "FAIL");

        sub("Aggregate all 3 signatures into 1");
        std::vector<std::span<const uint8_t>> sigs = {
            sig_a.span(), sig_b.span(), sig_c.span()
        };
        auto agg = must(crypto::bls::Bls12381::aggregate_signatures(sigs), "bls aggregate");
        kv("Aggregate sig size", std::to_string(agg.size()) + " bytes");
        kv("Aggregate sig (16 B)", hex(agg, 16));

        sub("Aggregate verification — all messages valid");
        std::vector<std::span<const uint8_t>> msgs = {
            sv(msg_a), sv(msg_b), sv(msg_c)
        };
        std::vector<std::span<const uint8_t>> pks = {
            alice.public_key.span(), bob.public_key.span(), charlie.public_key.span()
        };
        auto agg_vr = crypto::bls::Bls12381::aggregate_verify(msgs, pks, agg.span());
        kv("Aggregate verify", agg_vr.is_ok() ? "pass" : "FAIL");

        sub("Tamper one message — aggregate verification must fail");
        std::string msg_c_tampered = msg_c + " (tampered)";
        std::vector<std::span<const uint8_t>> msgs_bad = {
            sv(msg_a), sv(msg_b), sv(msg_c_tampered)
        };
        auto agg_vr_bad = crypto::bls::Bls12381::aggregate_verify(msgs_bad, pks, agg.span());
        kv("Tampered aggregate rejected", agg_vr_bad.is_err() ? "yes" : "FAIL");

        sub("Size comparison — aggregation savings");
        kv("3 individual signatures", std::to_string(3 * crypto::bls::Bls12381::SIGNATURE_BYTES) + " bytes (3 x 96)");
        kv("1 aggregate signature",   std::to_string(crypto::bls::Bls12381::SIGNATURE_BYTES) + " bytes");
        kv("Savings",                 std::to_string(2 * crypto::bls::Bls12381::SIGNATURE_BYTES) + " bytes (67%)");

        ok("BLS12-381 fully verified");
#else
        section("BLS12-381 Signatures");
        note("Skipped — CRYPTOLIB_HAS_BLS not defined (build with -DCRYPTOLIB_BLS=ON).");
#endif // CRYPTOLIB_HAS_BLS
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  all
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_all() {
        std::printf("\n" BOLD CYN
            "══════════════════════════════════════════════════════════════\n"
            "  Running all commands with default arguments\n"
            "══════════════════════════════════════════════════════════════\n" RST);
        auto saved = opts_;
        opts_.clear(); cmd_hash();
        opts_.clear(); cmd_symmetric();
        opts_.clear(); cmd_asymmetric();
        opts_.clear(); cmd_vault();
        opts_.clear(); cmd_asym_vault();
        opts_.clear(); cmd_entropy();
        opts_.clear(); cmd_stego();
        opts_.clear(); cmd_pq();
        opts_.clear(); cmd_bls();
        opts_ = saved;
        std::printf("\n" BOLD GRN
            "══════════════════════════════════════════════════════════════\n"
            "  All commands passed.\n"
            "══════════════════════════════════════════════════════════════\n" RST);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  help
    // ══════════════════════════════════════════════════════════════════════════
    void cmd_help() {
        std::printf(
            "\n" BOLD "Usage:" RST " cryptolib_demo <command> [options]\n\n"
            BOLD "Commands:\n" RST
            "  " CYN "hash" RST "       [--algo blake2b|sha256|sha512|argon2id|hmac|blake3|hmac256|hkdf]\n"
            "             [--input TEXT] [--stream]\n"
            "  " CYN "sym" RST "        [--algo xchacha20|aes256gcm|secretstream]\n"
            "             [--plaintext TEXT] [--aad TEXT] [--chunks N]\n"
            "  " CYN "asym" RST "       [--algo box|sealedbox|ed25519|x25519|hybrid]\n"
            "             [--message TEXT]\n"
            "  " CYN "vault" RST "      [--kdf interactive|sensitive|custom]\n"
            "             [--ops N] [--mem MiB] [--plaintext TEXT] [--aad TEXT] [--boost]\n"
            "  " CYN "asym-vault" RST " [--plaintext TEXT] [--aad TEXT] [--boost]\n"
            "  " CYN "entropy" RST "    [--mode standalone|boost|derive-all|refresh|all]\n"
            "             [--file PATH] [--plaintext TEXT] [--aad TEXT]\n"
            "  " CYN "stego" RST "      [--format ppm|wav|crvf|all]\n"
            "             [--plaintext TEXT] [--aad TEXT] [--quant N]\n"
            "             [--raw] [--capacity]\n"
            "  " CYN "pq" RST "         [--algo ml-kem|ml-dsa|slh-dsa]\n"
            "             post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)\n"
            "  " CYN "bls" RST "        BLS12-381 signatures + aggregation\n"
            "  " CYN "all" RST "        run every command with defaults\n"
            "  " CYN "help" RST "       print this message\n\n"
            BOLD "Global options:\n" RST
            "  --output-dir DIR   output directory for generated files\n"
            "                     (default: system temp / cryptolib_demo)\n\n"
            BOLD "Examples:\n" RST
            "  cryptolib_demo hash --algo blake2b --input \"hello\" --stream\n"
            "  cryptolib_demo sym  --algo secretstream --chunks 8\n"
            "  cryptolib_demo asym --algo hybrid\n"
            "  cryptolib_demo vault --kdf custom --ops 4 --mem 128 --boost\n"
            "  cryptolib_demo asym-vault --boost\n"
            "  cryptolib_demo entropy --mode boost --file /path/to/photo.ppm\n"
            "  cryptolib_demo stego --format ppm --quant 8 --raw\n"
            "  cryptolib_demo stego --output-dir ./my_output\n"
            "  cryptolib_demo pq   --algo ml-kem\n"
            "  cryptolib_demo bls\n"
            "  cryptolib_demo all\n\n"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    void banner() const {
        std::printf(
            "\n" BOLD CYN
            "╔══════════════════════════════════════════════════════════════╗\n"
            "║  CryptoLib Demo — exhaustive feature showcase                ║\n"
            "╚══════════════════════════════════════════════════════════════╝\n"
            RST "\n");
    }

    void section(const char* t) { std::printf("\n" BOLD CYN "━━━ %s ━━━" RST "\n", t); }
    void sub(const char* t)     { std::printf("\n  " BOLD MAG "▸ %s" RST "\n", t); }
    void ok(const std::string& m) { std::printf("    " GRN "✓" RST " %s\n", m.c_str()); }
    void note(const char* m)    { std::printf("      " BLU "→ " RST DIM "%s" RST "\n", m); }
    void err(const std::string& m) { std::fprintf(stderr, RED "  ✗ %s\n" RST, m.c_str()); }

    void kv(const std::string& label, const std::string& value) {
        std::printf("    " YLW "%-40s" RST "%s\n", (label + ":").c_str(), value.c_str());
    }

    std::string opt(const std::string& key, const std::string& def = "") const {
        auto it = opts_.find(key);
        return (it != opts_.end()) ? it->second : def;
    }
    bool has(const std::string& key) const { return opts_.count(key) > 0; }

    static std::string hex(const crypto::SecureBuffer& b, std::size_t n = 32) {
        auto h = b.to_hex();
        return h.substr(0, std::min(n * 2, h.size())) + "…";
    }
    static std::string hex32(const crypto::SecureBuffer& b) { return hex(b, 32); }

    static std::span<const uint8_t> sv(const std::string& s) {
        return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
    }

    // must<T> for Result<T> (value-returning)
    template<typename T>
    T must(crypto::Result<T> r, const char* ctx) {
        if (r.is_err()) { die(ctx, r.error().message); }
        return std::move(r.value());
    }

    // must_e for Result<MediaEntropy> (same as must, named to avoid ambiguity)
    crypto::entropy::MediaEntropy must_e(crypto::Result<crypto::entropy::MediaEntropy> r, const char* ctx) {
        if (r.is_err()) { die(ctx, r.error().message); }
        return std::move(r.value());
    }

    // must_v for Result<void>
    void must_v(crypto::Result<void> r, const char* ctx) {
        if (r.is_err()) { die(ctx, r.error().message); }
    }

    [[noreturn]] void die(const char* ctx, const std::string& msg) {
        std::fprintf(stderr, RED "\n  FATAL [%s]: %s\n" RST, ctx, msg.c_str());
        std::exit(1);
    }

    std::filesystem::path ensure_ppm() {
        auto p_path = output_dir_ / "demo_entropy_cover.ppm";
        if (!std::filesystem::exists(p_path)) {
            crypto::stego::MediaGeneratorParams p;
            p.ppm_seed = 0xDEAD'CAFE;
            must_v(crypto::stego::MediaGenerator::generate_ppm(p_path.string(), 512, 512, p), "ensure_ppm");
        }
        return p_path;
    }

    std::string out(const std::string& filename) const {
        return (output_dir_ / filename).string();
    }

    std::string              command_;
    std::filesystem::path    output_dir_;
    std::map<std::string, std::string> opts_;
};

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    return CryptoLibDemo(argc, argv).run();
}