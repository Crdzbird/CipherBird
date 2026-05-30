/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLib — Full Showcase                                                ║
 * ║                                                                            ║
 * ║  A single example that exercises every feature of the library and         ║
 * ║  combines them into realistic multi-layer workflows.                      ║
 * ║                                                                            ║
 * ║  Sections:                                                                 ║
 * ║    1. Hashing          — Blake2b, SHA-256, SHA-512, Argon2id, HMAC-SHA512 ║
 * ║    2. Symmetric AEAD   — XChaCha20-Poly1305, AES-256-GCM, SecretStream   ║
 * ║    3. Asymmetric       — Box, SealedBox, Ed25519, X25519, HybridBox      ║
 * ║    4. SecureVault      — 4-layer symmetric pipeline                       ║
 * ║    5. AsymmetricVault  — 4-layer public-key pipeline                      ║
 * ║    6. Steganography    — PPM, WAV, CRVF + capacity & quality             ║
 * ║    7. Extended Stego   — BMP, PNG, GIF, JPEG, MP3, AVI, MP4             ║
 * ║    8. MediaEntropy     — LavaRand-style key derivation                    ║
 * ║    9. Post-Quantum     — ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205)    ║
 * ║   10. BLS12-381        — signatures and aggregation                       ║
 * ║   11. BLAKE3 + HKDF    — BLAKE3 hash, HMAC-SHA256, HKDF-SHA256          ║
 * ║   12. Grand Finale     — all layers fused: entropy → vault → stego       ║
 * ║                                                                            ║
 * ║  Supported stego carrier formats:                                         ║
 * ║    .ppm  — Portable Pixmap (image)                                        ║
 * ║    .bmp  — Windows Bitmap (image, uncompressed 24-bit)                    ║
 * ║    .png  — Portable Network Graphics (image, lossless)                    ║
 * ║    .gif  — Graphics Interchange Format (image, palette-based)             ║
 * ║    .jpg  — JPEG (image, lossy — JSteg)                                    ║
 * ║    .wav  — RIFF/WAVE 16-bit PCM (audio)                                   ║
 * ║    .mp3  — MPEG Audio Layer III (audio, ancillary data)                   ║
 * ║    .crvf — CryptoLib Raw Video Format (video)                             ║
 * ║    .avi  — Audio Video Interleave (video, uncompressed)                   ║
 * ║    .mp4  — MPEG-4 Part 14 (video, container-level)                       ║
 * ║                                                                            ║
 * ║  Build:                                                                    ║
 * ║    cmake --build build --target cryptolib_showcase                         ║
 * ║    ./build/cryptolib_showcase [output_dir]                                ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include <cryptolib/cryptolib.hpp>

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr, label)                                                     \
    do {                                                                        \
        if (!(expr)) {                                                         \
            std::cerr << "  [FAIL] " << (label) << "\n";                       \
            ++g_fail;                                                          \
        } else {                                                               \
            std::cout << "  [OK]   " << (label) << "\n";                       \
            ++g_pass;                                                          \
        }                                                                      \
    } while (0)

static void section(const std::string& title) {
    std::cout << "\n══════════════════════════════════════════════════════════\n"
              << "  " << title
              << "\n══════════════════════════════════════════════════════════\n";
}

/// Build an output path that preserves the extension of the cover file.
/// e.g. stego_path("cover.ppm", dir, "stego_vault") → dir/stego_vault.ppm
static std::string stego_path(const std::string& cover,
                              const std::string& dir,
                              const std::string& stem) {
    auto ext = fs::path(cover).extension().string();
    return (fs::path(dir) / (stem + ext)).string();
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. HASHING
// ─────────────────────────────────────────────────────────────────────────────

static void demo_hashing() {
    using namespace crypto::hash;
    section("1. Hashing Primitives");

    const std::string msg = "CryptoLib showcase — hash me!";

    // Blake2b — one-shot
    {
        auto h = Blake2b::digest(msg);
        CHECK(h.is_ok() && h.value().size() == 64, "Blake2b one-shot (64 B)");
        std::cout << "     digest = " << h.value().to_hex().substr(0, 32) << "...\n";
    }

    // Blake2b — streaming
    {
        Blake2b::Stream stream;
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()), msg.size() / 2});
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()) + msg.size() / 2,
                       msg.size() - msg.size() / 2});
        auto h = stream.finalize();
        auto oneshot = std::move(Blake2b::digest(msg).value());
        CHECK(crypto::secure_equal(h.span(), oneshot.span()),
              "Blake2b streaming == one-shot");
    }

    // Blake2b — keyed
    {
        auto key = crypto::random_bytes(32);
        auto h = Blake2b::digest(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(msg.data()), msg.size()},
            key.span());
        CHECK(h.is_ok(), "Blake2b keyed hash");
    }

    // SHA-256
    {
        auto h = Sha256::digest(msg);
        CHECK(h.is_ok() && h.value().size() == 32, "SHA-256 (32 B)");
    }

    // SHA-256 streaming
    {
        Sha256::Stream stream;
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
        auto h = stream.finalize();
        auto oneshot = std::move(Sha256::digest(msg).value());
        CHECK(crypto::secure_equal(h.span(), oneshot.span()),
              "SHA-256 streaming == one-shot");
    }

    // SHA-512
    {
        auto h = Sha512::digest(msg);
        CHECK(h.is_ok() && h.value().size() == 64, "SHA-512 (64 B)");
    }

    // SHA-512 streaming
    {
        Sha512::Stream stream;
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()), msg.size()});
        auto h = stream.finalize();
        auto oneshot = std::move(Sha512::digest(msg).value());
        CHECK(crypto::secure_equal(h.span(), oneshot.span()),
              "SHA-512 streaming == one-shot");
    }

    // Argon2id — hash + verify (raw)
    {
        auto r = Argon2id::hash_password("hunter2");
        CHECK(r.is_ok(), "Argon2id hash_password");
        bool ok = Argon2id::verify("hunter2",
                                   r.value().hash.span(),
                                   r.value().salt.span());
        CHECK(ok, "Argon2id verify (correct pw)");
        bool bad = Argon2id::verify("wrong",
                                    r.value().hash.span(),
                                    r.value().salt.span());
        CHECK(!bad, "Argon2id verify (wrong pw rejected)");
    }

    // Argon2id — derive_key
    {
        auto salt = crypto::random_bytes(Argon2id::SALT_BYTES);
        auto k = Argon2id::derive_key("passphrase", salt.span(), 32);
        CHECK(k.is_ok() && k.value().size() == 32, "Argon2id derive_key (32 B)");
    }

    // Argon2id — PHC string format
    {
        auto phc = Argon2id::hash_password_str("my_password");
        CHECK(phc.is_ok(), "Argon2id PHC hash_password_str");
        CHECK(Argon2id::verify_str("my_password", phc.value()),
              "Argon2id PHC verify_str (correct)");
        CHECK(!Argon2id::verify_str("nope", phc.value()),
              "Argon2id PHC verify_str (wrong rejected)");
    }

    // HMAC-SHA512
    {
        auto key = crypto::random_bytes(HmacSha512::KEY_BYTES);
        auto mac = HmacSha512::compute(
            {reinterpret_cast<const uint8_t*>(msg.data()), msg.size()},
            key.span());
        CHECK(mac.is_ok(), "HMAC-SHA512 compute");
        bool ok = HmacSha512::verify(
            {reinterpret_cast<const uint8_t*>(msg.data()), msg.size()},
            mac.value().span(), key.span());
        CHECK(ok, "HMAC-SHA512 verify (correct)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SYMMETRIC AEAD
// ─────────────────────────────────────────────────────────────────────────────

static void demo_symmetric() {
    using namespace crypto::symmetric;
    section("2. Symmetric AEAD Encryption");

    const std::string plaintext = "Top-secret payload for symmetric demo!";
    const std::string aad = "showcase-context-v1";

    // XChaCha20-Poly1305
    {
        auto key = XChaCha20Poly1305::generate_key();
        auto ct = XChaCha20Poly1305::encrypt(plaintext, key.span(), aad);
        CHECK(ct.is_ok(), "XChaCha20-Poly1305 encrypt");

        auto pt = XChaCha20Poly1305::decrypt(ct.value().span(), key.span(),
            {reinterpret_cast<const uint8_t*>(aad.data()), aad.size()});
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "XChaCha20-Poly1305 round-trip");

        // Tamper detection
        auto tampered = ct.value().span();
        std::vector<uint8_t> bad(tampered.begin(), tampered.end());
        bad.back() ^= 0xFF;
        auto fail = XChaCha20Poly1305::decrypt(bad, key.span(),
            {reinterpret_cast<const uint8_t*>(aad.data()), aad.size()});
        CHECK(fail.is_err(), "XChaCha20-Poly1305 tamper detected");
    }

    // AES-256-GCM
    if (Aes256Gcm::is_available()) {
        auto key = Aes256Gcm::generate_key();
        auto ct = Aes256Gcm::encrypt(
            {reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()},
            key.span());
        CHECK(ct.is_ok(), "AES-256-GCM encrypt");

        auto pt = Aes256Gcm::decrypt(ct.value().span(), key.span());
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "AES-256-GCM round-trip");
    } else {
        std::cout << "  [SKIP] AES-256-GCM not available on this CPU\n";
    }

    // SecretStream — multi-chunk streaming AEAD
    {
        auto key = SecretStream::generate_key();
        SecretStream::Encryptor enc(key.span());
        const auto& header = enc.header();

        std::vector<std::string> chunks = {"chunk-1-data", "chunk-2-data", "final-chunk"};
        std::vector<crypto::SecureBuffer> encrypted_chunks;

        for (std::size_t i = 0; i < chunks.size(); ++i) {
            auto span = std::span<const uint8_t>{
                reinterpret_cast<const uint8_t*>(chunks[i].data()), chunks[i].size()};
            if (i + 1 < chunks.size()) {
                encrypted_chunks.push_back(enc.push(span));
            } else {
                encrypted_chunks.push_back(enc.push_final(span));
            }
        }
        CHECK(encrypted_chunks.size() == 3, "SecretStream encrypt 3 chunks");

        SecretStream::Decryptor dec(key.span(), header.span());
        bool all_ok = true;
        for (std::size_t i = 0; i < encrypted_chunks.size(); ++i) {
            auto r = dec.pull(encrypted_chunks[i].span());
            if (r.is_err() || r.value().plaintext.to_string() != chunks[i]) {
                all_ok = false;
                break;
            }
            if (i + 1 == chunks.size()) {
                if (r.value().tag != SecretStream::TAG_FINAL) all_ok = false;
            }
        }
        CHECK(all_ok, "SecretStream round-trip (3 chunks + TAG_FINAL)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ASYMMETRIC CRYPTO
// ─────────────────────────────────────────────────────────────────────────────

static void demo_asymmetric() {
    using namespace crypto::asymmetric;
    section("3. Asymmetric Primitives");

    const std::string msg = "Asymmetric showcase message";
    auto msg_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};

    // Box (authenticated public-key encryption)
    {
        auto alice = Box::generate_keypair();
        auto bob   = Box::generate_keypair();

        auto ct = Box::encrypt(msg_span, bob.public_key.span(), alice.secret_key.span());
        CHECK(ct.is_ok(), "Box encrypt (Alice -> Bob)");

        auto pt = Box::decrypt(ct.value().span(), alice.public_key.span(), bob.secret_key.span());
        CHECK(pt.is_ok() && pt.value().to_string() == msg, "Box round-trip");
    }

    // SealedBox (anonymous sender)
    {
        auto kp = SealedBox::generate_keypair();
        auto ct = SealedBox::encrypt(msg_span, kp.public_key.span());
        CHECK(ct.is_ok(), "SealedBox encrypt");

        auto pt = SealedBox::decrypt(ct.value().span(), kp.public_key.span(), kp.secret_key.span());
        CHECK(pt.is_ok() && pt.value().to_string() == msg, "SealedBox round-trip");
    }

    // Ed25519 (signatures)
    {
        auto kp = Ed25519::generate_keypair();
        auto sig = Ed25519::sign(msg_span, kp.secret_key.span());
        CHECK(sig.is_ok() && sig.value().size() == 64, "Ed25519 sign (64 B)");

        bool valid = Ed25519::verify(msg_span, sig.value().span(), kp.public_key.span());
        CHECK(valid, "Ed25519 verify (correct)");

        // Tamper detection
        std::vector<uint8_t> bad_msg(msg_span.begin(), msg_span.end());
        bad_msg[0] ^= 0x01;
        bool invalid = Ed25519::verify(bad_msg, sig.value().span(), kp.public_key.span());
        CHECK(!invalid, "Ed25519 verify (tampered msg rejected)");
    }

    // Ed25519 from seed (deterministic)
    {
        auto seed = crypto::random_bytes(32);
        auto kp1 = Ed25519::keypair_from_seed(seed.span());
        auto kp2 = Ed25519::keypair_from_seed(seed.span());
        CHECK(kp1.is_ok() && kp2.is_ok() &&
              crypto::secure_equal(kp1.value().public_key.span(), kp2.value().public_key.span()),
              "Ed25519 keypair_from_seed (deterministic)");
    }

    // Ed25519 -> X25519 curve conversion
    {
        auto ed_kp = Ed25519::generate_keypair();
        auto x_pub = Ed25519::to_x25519_public(ed_kp.public_key.span());
        auto x_sec = Ed25519::to_x25519_secret(ed_kp.secret_key.span());
        CHECK(x_pub.is_ok() && x_sec.is_ok(),
              "Ed25519 -> X25519 curve conversion");
    }

    // X25519 (raw ECDH)
    {
        auto alice = X25519::generate_keypair();
        auto bob   = X25519::generate_keypair();
        auto s1 = X25519::shared_secret(alice.secret_key.span(), bob.public_key.span());
        auto s2 = X25519::shared_secret(bob.secret_key.span(), alice.public_key.span());
        CHECK(s1.is_ok() && s2.is_ok() &&
              crypto::secure_equal(s1.value().span(), s2.value().span()),
              "X25519 shared secret agreement");
    }

    // HybridBox (encrypt-then-sign)
    {
        auto alice_box  = Box::generate_keypair();
        auto alice_sign = Ed25519::generate_keypair();
        auto bob_box    = Box::generate_keypair();

        auto hybrid = HybridBox::encrypt(
            msg_span,
            bob_box.public_key.span(),
            alice_box.secret_key.span(),
            alice_sign.secret_key.span());
        CHECK(hybrid.is_ok(), "HybridBox encrypt");

        auto pt = HybridBox::decrypt(
            hybrid.value(),
            alice_box.public_key.span(),
            bob_box.secret_key.span(),
            alice_sign.public_key.span());
        CHECK(pt.is_ok() && pt.value().to_string() == msg,
              "HybridBox round-trip (encrypt-then-sign)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SECURE VAULT (Symmetric Pipeline)
// ─────────────────────────────────────────────────────────────────────────────

static void demo_secure_vault() {
    section("4. SecureVault — Symmetric 4-Layer Pipeline");

    const std::string plaintext = "Vault-protected classified data";
    const std::string aad = "vault-aad-context";

    // Basic seal / open
    {
        auto kp = crypto::SecureVault::generate_keypair();
        auto master_key = crypto::random_bytes(32);
        crypto::SecureVault vault(master_key.span(), std::move(kp));

        auto pkt = vault.seal(plaintext, aad);
        CHECK(pkt.is_ok(), "SecureVault seal");

        auto pt = vault.open(pkt.value(), aad);
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "SecureVault round-trip (self-open)");
    }

    // Cross-party verification (open with explicit public key)
    {
        auto kp = crypto::SecureVault::generate_keypair();
        auto pub = crypto::SecureBuffer(kp.sign_public.data(), kp.sign_public.size());
        auto master_key = crypto::random_bytes(32);
        crypto::SecureVault vault(master_key.span(), std::move(kp));

        auto pkt = vault.seal(plaintext, aad);
        CHECK(pkt.is_ok(), "SecureVault seal (cross-party)");

        auto pt = vault.open(pkt.value(), pub.span(),
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(aad.data()), aad.size()});
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "SecureVault open with explicit verifier key");
    }

    // Keypair from seed (deterministic)
    {
        auto seed = crypto::random_bytes(32);
        auto kp1 = crypto::SecureVault::keypair_from_seed(seed.span());
        auto kp2 = crypto::SecureVault::keypair_from_seed(seed.span());
        CHECK(kp1.is_ok() && kp2.is_ok() &&
              crypto::secure_equal(kp1.value().sign_public.span(),
                                   kp2.value().sign_public.span()),
              "SecureVault keypair_from_seed (deterministic)");
    }

    // Packet serialisation round-trip
    {
        auto kp = crypto::SecureVault::generate_keypair();
        auto master_key = crypto::random_bytes(32);
        crypto::SecureVault vault(master_key.span(), std::move(kp));

        auto pkt = vault.seal(plaintext, aad);
        CHECK(pkt.is_ok(), "Packet serialise test: seal");

        auto wire = pkt.value().serialise();
        auto recovered = crypto::EncryptedPacket::deserialise(wire.span());
        CHECK(recovered.is_ok(), "EncryptedPacket serialise -> deserialise");

        auto pt = vault.open(recovered.value(), aad);
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "EncryptedPacket full wire round-trip");
    }

    // Wrong-key rejection
    {
        auto kp = crypto::SecureVault::generate_keypair();
        auto key1 = crypto::random_bytes(32);
        auto key2 = crypto::random_bytes(32);
        crypto::SecureVault vault1(key1.span(), std::move(kp));

        auto pkt = vault1.seal(plaintext, aad);
        CHECK(pkt.is_ok(), "SecureVault wrong-key test: seal");

        auto kp2 = crypto::SecureVault::generate_keypair();
        crypto::SecureVault vault2(key2.span(), std::move(kp2));
        auto bad = vault2.open(pkt.value(), aad);
        CHECK(bad.is_err(), "SecureVault wrong-key rejection");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ASYMMETRIC VAULT
// ─────────────────────────────────────────────────────────────────────────────

static void demo_asymmetric_vault() {
    section("5. AsymmetricVault — Public-Key 3-Layer Pipeline");

    const std::string plaintext = "Alice sends this to Bob via AsymmetricVault";
    const std::string aad = "asym-vault-ctx";

    // Basic seal / open
    {
        auto alice = crypto::AsymmetricVault::generate_bundle();
        auto bob   = crypto::AsymmetricVault::generate_bundle();

        auto pkt = crypto::AsymmetricVault::seal(
            plaintext, alice, bob.box_public.span(), aad);
        CHECK(pkt.is_ok(), "AsymmetricVault seal (Alice -> Bob)");

        auto pt = crypto::AsymmetricVault::open(
            pkt.value(), bob, alice.sign_public.span(), aad);
        CHECK(pt.is_ok() && pt.value().to_string() == plaintext,
              "AsymmetricVault round-trip");
    }

    // Wrong sender rejection
    {
        auto alice   = crypto::AsymmetricVault::generate_bundle();
        auto bob     = crypto::AsymmetricVault::generate_bundle();
        auto mallory = crypto::AsymmetricVault::generate_bundle();

        auto pkt = crypto::AsymmetricVault::seal(
            plaintext, alice, bob.box_public.span());
        CHECK(pkt.is_ok(), "AsymmetricVault wrong-sender test: seal");

        // Bob tries to open claiming it's from Mallory
        auto bad = crypto::AsymmetricVault::open(
            pkt.value(), bob, mallory.sign_public.span());
        CHECK(bad.is_err(), "AsymmetricVault wrong-sender rejected");
    }

    // Span-based seal/open with AAD
    {
        auto alice = crypto::AsymmetricVault::generate_bundle();
        auto bob   = crypto::AsymmetricVault::generate_bundle();

        auto pt_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()};
        auto aad_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(aad.data()), aad.size()};

        auto pkt = crypto::AsymmetricVault::seal(
            pt_span, alice, bob.box_public.span(), aad_span);
        CHECK(pkt.is_ok(), "AsymmetricVault seal (span overload)");

        auto result = crypto::AsymmetricVault::open(
            pkt.value(), bob, alice.sign_public.span(), aad_span);
        CHECK(result.is_ok() && result.value().to_string() == plaintext,
              "AsymmetricVault open (span overload)");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. STEGANOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

static void demo_steganography(const std::string& dir) {
    using namespace crypto::stego;
    section("6. Steganography — Embed & Extract across PPM, WAV, CRVF");

    // Generate all three carrier types
    const std::string cover_ppm  = (fs::path(dir) / "cover.ppm").string();
    const std::string cover_wav  = (fs::path(dir) / "cover.wav").string();
    const std::string cover_crvf = (fs::path(dir) / "cover.crvf").string();

    auto r1 = MediaGenerator::generate_ppm(cover_ppm, 640, 480);
    CHECK(r1.is_ok(), "Generate cover.ppm (640x480)");

    auto r2 = MediaGenerator::generate_wav(cover_wav, 44100, 1, 5.0);
    CHECK(r2.is_ok(), "Generate cover.wav (44.1kHz mono, 5s)");

    auto r3 = MediaGenerator::generate_crvf(cover_crvf, 320, 240, 30, 30);
    CHECK(r3.is_ok(), "Generate cover.crvf (320x240, 30fps, 30 frames)");

    // ── Capacity queries ──────────────────────────────────────────────────
    {
        auto cap_ppm = StegoEngine::capacity(cover_ppm);
        CHECK(cap_ppm.is_ok(), "Capacity query: PPM");
        std::cout << "     " << cap_ppm.value().description << "\n";

        auto cap_wav = StegoEngine::capacity(cover_wav);
        CHECK(cap_wav.is_ok(), "Capacity query: WAV");
        std::cout << "     " << cap_wav.value().description << "\n";

        auto cap_crvf = StegoEngine::capacity(cover_crvf);
        CHECK(cap_crvf.is_ok(), "Capacity query: CRVF");
        std::cout << "     " << cap_crvf.value().description << "\n";
    }

    // ── Raw bytes embed/extract (PPM) — output preserves .ppm extension ──
    {
        std::vector<uint8_t> secret = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        auto out = stego_path(cover_ppm, dir, "stego_raw");

        auto embed = StegoEngine::embed(cover_ppm, secret, out);
        CHECK(embed.is_ok(), "StegoEngine embed raw bytes (PPM)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == secret,
              "StegoEngine extract raw bytes (PPM) round-trip");
    }

    // ── Raw bytes embed/extract (WAV) — output preserves .wav extension ──
    {
        std::vector<uint8_t> secret = {0x01, 0x02, 0x03, 0x04};
        auto out = stego_path(cover_wav, dir, "stego_raw");

        auto embed = StegoEngine::embed(cover_wav, secret, out);
        CHECK(embed.is_ok(), "StegoEngine embed raw bytes (WAV)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == secret,
              "StegoEngine extract raw bytes (WAV) round-trip");
    }

    // ── Raw bytes embed/extract (CRVF) — output preserves .crvf extension ──
    {
        std::vector<uint8_t> secret = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        auto out = stego_path(cover_crvf, dir, "stego_raw");

        auto embed = StegoEngine::embed(cover_crvf, secret, out);
        CHECK(embed.is_ok(), "StegoEngine embed raw bytes (CRVF)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == secret,
              "StegoEngine extract raw bytes (CRVF) round-trip");
    }

    // ── Quality measurement (PSNR/SNR) ────────────────────────────────────
    {
        auto psnr = StegoEngine::quality(cover_ppm,
                                          stego_path(cover_ppm, dir, "stego_raw"));
        if (psnr.is_ok()) {
            std::cout << "     Image PSNR = " << psnr.value() << " dB"
                      << (psnr.value() >= 40.0 ? " (imperceptible)" : "") << "\n";
            CHECK(psnr.value() > 30.0, "Image PSNR > 30 dB");
        }

        auto snr = StegoEngine::quality(cover_wav,
                                         stego_path(cover_wav, dir, "stego_raw"));
        if (snr.is_ok()) {
            std::cout << "     Audio SNR  = " << snr.value() << " dB"
                      << (snr.value() >= 20.0 ? " (imperceptible)" : "") << "\n";
            CHECK(snr.value() > 10.0, "Audio SNR > 10 dB");
        }
    }

    // ── EncryptedPacket embed/extract (PPM) ───────────────────────────────
    {
        auto kp  = crypto::SecureVault::generate_keypair();
        auto key = crypto::random_bytes(32);
        crypto::SecureVault vault(key.span(), std::move(kp));

        auto pkt = vault.seal("stego packet test", "pkt-ctx");
        CHECK(pkt.is_ok(), "Vault seal for packet embed");

        auto out = stego_path(cover_ppm, dir, "stego_packet");
        auto embed = StegoEngine::embed_packet(cover_ppm, pkt.value(), out);
        CHECK(embed.is_ok(), "StegoEngine embed_packet (PPM)");

        auto recovered = StegoEngine::extract_packet(out);
        CHECK(recovered.is_ok(), "StegoEngine extract_packet (PPM)");

        auto pt = vault.open(recovered.value(), "pkt-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == "stego packet test",
              "Vault open from extracted packet");
    }

    // ── SecureVault seal_into / open_from (WAV) ───────────────────────────
    {
        auto kp  = crypto::SecureVault::generate_keypair();
        auto key = crypto::random_bytes(32);
        crypto::SecureVault vault(key.span(), std::move(kp));

        auto out = stego_path(cover_wav, dir, "stego_vault");

        auto seal_r = vault.seal_into(cover_wav, "hidden in audio", out, "audio-ctx");
        CHECK(seal_r.is_ok(), "SecureVault seal_into WAV");

        auto open_r = vault.open_from(out, "audio-ctx");
        CHECK(open_r.is_ok() && open_r.value().to_string() == "hidden in audio",
              "SecureVault open_from WAV round-trip");
    }

    // ── AsymmetricVault seal_into / open_from (PPM) ───────────────────────
    {
        auto alice = crypto::AsymmetricVault::generate_bundle();
        auto bob   = crypto::AsymmetricVault::generate_bundle();

        auto out = stego_path(cover_ppm, dir, "stego_asym");

        auto seal_r = crypto::AsymmetricVault::seal_into(
            alice, bob.box_public.span(),
            "Bob, the image carries secrets", cover_ppm, out, "asym-stego-ctx");
        CHECK(seal_r.is_ok(), "AsymmetricVault seal_into PPM");

        auto open_r = crypto::AsymmetricVault::open_from(
            bob, alice.sign_public.span(), out, "asym-stego-ctx");
        CHECK(open_r.is_ok() &&
              open_r.value().to_string() == "Bob, the image carries secrets",
              "AsymmetricVault open_from PPM round-trip");
    }

    // ── SecureVault seal_into / open_from (CRVF) ──────────────────────────
    {
        auto kp  = crypto::SecureVault::generate_keypair();
        auto key = crypto::random_bytes(32);
        crypto::SecureVault vault(key.span(), std::move(kp));

        auto out = stego_path(cover_crvf, dir, "stego_vault");

        auto seal_r = vault.seal_into(cover_crvf, "hidden in video", out, "video-ctx");
        CHECK(seal_r.is_ok(), "SecureVault seal_into CRVF");

        auto open_r = vault.open_from(out, "video-ctx");
        CHECK(open_r.is_ok() && open_r.value().to_string() == "hidden in video",
              "SecureVault open_from CRVF round-trip");
    }

    // ── Format detection ──────────────────────────────────────────────────
    {
        CHECK(StegoEngine::detect_format("photo.ppm") == MediaFormat::PPM_IMAGE,
              "detect_format(.ppm)");
        CHECK(StegoEngine::detect_format("song.wav") == MediaFormat::WAV_AUDIO,
              "detect_format(.wav)");
        CHECK(StegoEngine::detect_format("clip.crvf") == MediaFormat::CRVF_VIDEO,
              "detect_format(.crvf)");
        CHECK(StegoEngine::detect_format("photo.bmp") == MediaFormat::BMP_IMAGE,
              "detect_format(.bmp)");
        CHECK(StegoEngine::detect_format("photo.png") == MediaFormat::PNG_IMAGE,
              "detect_format(.png)");
        CHECK(StegoEngine::detect_format("anim.gif") == MediaFormat::GIF_IMAGE,
              "detect_format(.gif)");
        CHECK(StegoEngine::detect_format("photo.jpg") == MediaFormat::JPEG_IMAGE,
              "detect_format(.jpg)");
        CHECK(StegoEngine::detect_format("photo.jpeg") == MediaFormat::JPEG_IMAGE,
              "detect_format(.jpeg)");
        CHECK(StegoEngine::detect_format("song.flac") == MediaFormat::FLAC_AUDIO,
              "detect_format(.flac)");
        CHECK(StegoEngine::detect_format("song.mp3") == MediaFormat::MP3_AUDIO,
              "detect_format(.mp3)");
        CHECK(StegoEngine::detect_format("clip.avi") == MediaFormat::AVI_VIDEO,
              "detect_format(.avi)");
        CHECK(StegoEngine::detect_format("clip.mp4") == MediaFormat::MP4_VIDEO,
              "detect_format(.mp4)");
        CHECK(StegoEngine::detect_format("file.xyz") == MediaFormat::UNKNOWN,
              "detect_format(.xyz) == UNKNOWN");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. EXTENDED FORMAT STEGANOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

static void demo_extended_stego(const std::string& dir) {
    using namespace crypto::stego;
    section("7. Extended Steganography — BMP, PNG, GIF, JPEG, MP3, AVI, MP4");

    const std::string payload_str = "Extended format stego test!";
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());

    // Try to find a real JPEG source for BMP/PNG/GIF conversions.
    // convert_to_bmp/png/gif uses stb_image to load the source, which is
    // compiled with STBI_ONLY_PNG|BMP|GIF|JPEG (PNM support excluded).
    // So we need a JPEG/PNG/BMP source — not a PPM.
    // Generate a PPM, convert to BMP manually, then use that BMP as source.
    const std::string source_ppm = (fs::path(dir) / "source_convert.ppm").string();
    auto gen_src = MediaGenerator::generate_ppm(source_ppm, 640, 480);
    CHECK(gen_src.is_ok(), "Generate source PPM for format conversions (640x480)");

    // Read the PPM manually (P6 format: "P6\nW H\n255\n<rgb>")
    // then write as BMP to create a stb_image-loadable source
    auto read_ppm_pixels = [](const std::string& path)
        -> std::tuple<int, int, std::vector<uint8_t>> {
        std::ifstream f(path, std::ios::binary);
        std::string magic; int w, h, maxval;
        f >> magic >> w >> h >> maxval;
        f.get(); // skip the single whitespace after maxval
        std::vector<uint8_t> pixels(w * h * 3);
        f.read(reinterpret_cast<char*>(pixels.data()),
               static_cast<std::streamsize>(pixels.size()));
        return {w, h, std::move(pixels)};
    };

    auto [src_w, src_h, src_pixels] = read_ppm_pixels(source_ppm);

    // ── BMP: 24-bit uncompressed bitmap ──────────────────────────────────
    {
        const std::string cover = (fs::path(dir) / "cover.bmp").string();
        // Write BMP directly from PPM pixel data
        {
            std::size_t row_bytes = src_w * 3;
            std::size_t row_pad = (4 - (row_bytes % 4)) % 4;
            std::size_t pixel_data_size = (row_bytes + row_pad) * src_h;
            uint32_t file_size = 14 + 40 + static_cast<uint32_t>(pixel_data_size);

            std::ofstream bf(cover, std::ios::binary);
            uint8_t fh[14] = {'B', 'M'};
            fh[2]=uint8_t(file_size); fh[3]=uint8_t(file_size>>8);
            fh[4]=uint8_t(file_size>>16); fh[5]=uint8_t(file_size>>24);
            fh[10]=54;
            bf.write(reinterpret_cast<char*>(fh), 14);

            uint8_t dib[40] = {};
            dib[0]=40;
            dib[4]=uint8_t(src_w); dib[5]=uint8_t(src_w>>8);
            dib[8]=uint8_t(src_h); dib[9]=uint8_t(src_h>>8);
            dib[12]=1; dib[14]=24;
            bf.write(reinterpret_cast<char*>(dib), 40);

            std::vector<uint8_t> pad(row_pad, 0);
            for (int y = src_h - 1; y >= 0; --y) {
                const uint8_t* row = src_pixels.data() + y * src_w * 3;
                // Convert RGB to BGR for BMP
                for (int x = 0; x < src_w; ++x) {
                    uint8_t bgr[3] = {row[x*3+2], row[x*3+1], row[x*3]};
                    bf.write(reinterpret_cast<char*>(bgr), 3);
                }
                if (row_pad > 0) bf.write(reinterpret_cast<char*>(pad.data()),
                                          static_cast<std::streamsize>(row_pad));
            }
        }
        CHECK(fs::exists(cover), "Generate cover.bmp directly from PPM pixels");

        auto cap = StegoEngine::capacity(cover);
        CHECK(cap.is_ok(), "Capacity query: BMP");
        std::cout << "     " << cap.value().description << "\n";

        auto out = stego_path(cover, dir, "stego_bmp");
        auto embed = StegoEngine::embed(cover, payload, out);
        CHECK(embed.is_ok(), "StegoEngine embed (BMP)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == payload,
              "StegoEngine extract (BMP) round-trip");

        auto psnr = StegoEngine::quality(cover, out);
        if (psnr.is_ok()) {
            std::cout << "     BMP PSNR = " << psnr.value() << " dB\n";
            CHECK(psnr.value() > 30.0, "BMP PSNR > 30 dB");
        }
    }

    // ── PNG: lossless compressed ─────────────────────────────────────────
    {
        const std::string bmp_source = (fs::path(dir) / "cover.bmp").string();
        const std::string cover = (fs::path(dir) / "cover.png").string();
        auto gen = MediaGenerator::convert_to_png(bmp_source, cover);
        CHECK(gen.is_ok(), "Convert BMP -> cover.png");

        auto cap = StegoEngine::capacity(cover);
        CHECK(cap.is_ok(), "Capacity query: PNG");
        std::cout << "     " << cap.value().description << "\n";

        auto out = stego_path(cover, dir, "stego_png");
        auto embed = StegoEngine::embed(cover, payload, out);
        CHECK(embed.is_ok(), "StegoEngine embed (PNG)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == payload,
              "StegoEngine extract (PNG) round-trip");

        auto psnr = StegoEngine::quality(cover, out);
        if (psnr.is_ok()) {
            std::cout << "     PNG PSNR = " << psnr.value() << " dB\n";
            CHECK(psnr.value() > 30.0, "PNG PSNR > 30 dB");
        }
    }

    // ── GIF: palette-based (LSB, lower capacity) ─────────────────────────
    {
        const std::string bmp_source = (fs::path(dir) / "cover.bmp").string();
        const std::string cover = (fs::path(dir) / "cover.gif").string();
        auto gen = MediaGenerator::convert_to_gif(bmp_source, cover);
        CHECK(gen.is_ok(), "Convert BMP -> cover.gif");

        auto cap = StegoEngine::capacity(cover);
        CHECK(cap.is_ok(), "Capacity query: GIF");
        std::cout << "     " << cap.value().description << "\n";

        auto out = stego_path(cover, dir, "stego_gif");
        // GIF has lower capacity — use shorter payload
        std::vector<uint8_t> short_payload = {0xDE, 0xAD, 0xBE, 0xEF};
        auto embed = StegoEngine::embed(cover, short_payload, out);
        CHECK(embed.is_ok(), "StegoEngine embed (GIF)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == short_payload,
              "StegoEngine extract (GIF) round-trip");
    }

    // ── JPEG: JSteg (lossy, coefficient-level) ──────────────────────────
    // NOTE: JPEG stego requires a real JPEG file (no generate_jpeg API).
    //       Skipped when no JPEG cover is available.
    {
        const std::string cover = (fs::path(dir) / "cover.jpg").string();
        if (fs::exists(cover)) {
            auto cap = StegoEngine::capacity(cover);
            CHECK(cap.is_ok(), "Capacity query: JPEG");
            std::cout << "     " << cap.value().description << "\n";

            auto out = stego_path(cover, dir, "stego_jpeg");
            auto embed = StegoEngine::embed(cover, payload, out);
            CHECK(embed.is_ok(), "StegoEngine embed (JPEG/JSteg)");

            auto extracted = StegoEngine::extract(out);
            CHECK(extracted.is_ok() && extracted.value() == payload,
                  "StegoEngine extract (JPEG/JSteg) round-trip");
        } else {
            std::cout << "  [SKIP] JPEG stego: no cover.jpg found in output dir "
                      << "(place a real JPEG there to test JSteg)\n";
        }
    }

    // ── MP3: ancillary data embedding ────────────────────────────────────
    // NOTE: MP3 stego requires a real MP3 file (no generate_mp3 API).
    //       Skipped when no MP3 cover is available.
    {
        const std::string cover = (fs::path(dir) / "cover.mp3").string();
        if (fs::exists(cover)) {
            auto cap = StegoEngine::capacity(cover);
            CHECK(cap.is_ok(), "Capacity query: MP3");
            std::cout << "     " << cap.value().description << "\n";

            auto out = stego_path(cover, dir, "stego_mp3");
            auto embed = StegoEngine::embed(cover, payload, out);
            CHECK(embed.is_ok(), "StegoEngine embed (MP3)");

            auto extracted = StegoEngine::extract(out);
            CHECK(extracted.is_ok() && extracted.value() == payload,
                  "StegoEngine extract (MP3) round-trip");
        } else {
            std::cout << "  [SKIP] MP3 stego: no cover.mp3 found in output dir "
                      << "(place a real MP3 there to test ancillary data embedding)\n";
        }
    }

    // ── AVI: uncompressed video (DCT/QIM per frame) ─────────────────────
    {
        const std::string cover = (fs::path(dir) / "cover.avi").string();
        auto gen = MediaGenerator::generate_avi(cover, 320, 240, 15, 10);
        CHECK(gen.is_ok(), "Generate cover.avi (320x240, 15fps, 10 frames)");

        auto cap = StegoEngine::capacity(cover);
        CHECK(cap.is_ok(), "Capacity query: AVI");
        std::cout << "     " << cap.value().description << "\n";

        auto out = stego_path(cover, dir, "stego_avi");
        auto embed = StegoEngine::embed(cover, payload, out);
        CHECK(embed.is_ok(), "StegoEngine embed (AVI)");

        auto extracted = StegoEngine::extract(out);
        CHECK(extracted.is_ok() && extracted.value() == payload,
              "StegoEngine extract (AVI) round-trip");

        auto psnr = StegoEngine::quality(cover, out);
        if (psnr.is_ok()) {
            std::cout << "     AVI PSNR = " << psnr.value() << " dB\n";
        }
    }

    // ── MP4: container-level free-box embedding ──────────────────────────
    // NOTE: MP4 stego requires a real MP4 file (no generate_mp4 API).
    //       Skipped when no MP4 cover is available.
    {
        const std::string cover = (fs::path(dir) / "cover.mp4").string();
        if (fs::exists(cover)) {
            auto cap = StegoEngine::capacity(cover);
            CHECK(cap.is_ok(), "Capacity query: MP4");
            std::cout << "     " << cap.value().description << "\n";

            auto out = stego_path(cover, dir, "stego_mp4");
            auto embed = StegoEngine::embed(cover, payload, out);
            CHECK(embed.is_ok(), "StegoEngine embed (MP4)");

            auto extracted = StegoEngine::extract(out);
            CHECK(extracted.is_ok() && extracted.value() == payload,
                  "StegoEngine extract (MP4) round-trip");
        } else {
            std::cout << "  [SKIP] MP4 stego: no cover.mp4 found in output dir "
                      << "(place a real MP4 there to test container-level embedding)\n";
        }
    }

    // ── Extension preservation for all generated formats ─────────────────
    {
        bool ext_ok = true;
        auto check_ext = [&](const std::string& path, const std::string& expected) {
            auto actual = fs::path(path).extension().string();
            if (actual != expected) {
                std::cerr << "     EXT MISMATCH: " << path
                          << " expected " << expected << " got " << actual << "\n";
                ext_ok = false;
            }
        };

        check_ext(stego_path((fs::path(dir) / "cover.bmp").string(), dir, "stego_bmp"), ".bmp");
        check_ext(stego_path((fs::path(dir) / "cover.png").string(), dir, "stego_png"), ".png");
        check_ext(stego_path((fs::path(dir) / "cover.gif").string(), dir, "stego_gif"), ".gif");
        check_ext(stego_path((fs::path(dir) / "cover.avi").string(), dir, "stego_avi"), ".avi");

        // Only check extensions for formats that have covers present
        if (fs::exists((fs::path(dir) / "cover.jpg").string()))
            check_ext(stego_path((fs::path(dir) / "cover.jpg").string(), dir, "stego_jpeg"), ".jpg");
        if (fs::exists((fs::path(dir) / "cover.mp3").string()))
            check_ext(stego_path((fs::path(dir) / "cover.mp3").string(), dir, "stego_mp3"), ".mp3");
        if (fs::exists((fs::path(dir) / "cover.mp4").string()))
            check_ext(stego_path((fs::path(dir) / "cover.mp4").string(), dir, "stego_mp4"), ".mp4");

        CHECK(ext_ok, "All extended format outputs preserve original extension");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. MEDIA ENTROPY (LavaRand)
// ─────────────────────────────────────────────────────────────────────────────

static void demo_media_entropy(const std::string& dir) {
    using namespace crypto::entropy;
    section("8. MediaEntropy — LavaRand Physical Entropy Harvesting");

    // Create a synthetic media file to harvest entropy from
    const std::string entropy_src = (fs::path(dir) / "entropy_source.ppm").string();
    auto gen = crypto::stego::MediaGenerator::generate_ppm(entropy_src, 256, 256);
    CHECK(gen.is_ok(), "Generate entropy source image (256x256)");

    // ── LavaRand mode (non-deterministic) ─────────────────────────────────
    {
        auto me1 = MediaEntropy::from_file(entropy_src);
        auto me2 = MediaEntropy::from_file(entropy_src);
        CHECK(me1.is_ok() && me2.is_ok(), "MediaEntropy::from_file (LavaRand)");

        // Different instances produce different keys (system entropy mixed)
        auto k1 = me1.value().symmetric_key();
        auto k2 = me2.value().symmetric_key();
        CHECK(!crypto::secure_equal(k1.span(), k2.span()),
              "LavaRand mode: two calls produce different keys");

        std::cout << "     entropy estimate = "
                  << me1.value().entropy_bits() << " bits\n";
        std::cout << "     source = " << me1.value().info().path
                  << " (" << me1.value().info().file_size << " bytes)\n";
    }

    // ── Deterministic mode (reproducible) ─────────────────────────────────
    {
        auto me1 = MediaEntropy::from_file_deterministic(entropy_src);
        auto me2 = MediaEntropy::from_file_deterministic(entropy_src);
        CHECK(me1.is_ok() && me2.is_ok(),
              "MediaEntropy::from_file_deterministic");

        auto k1 = me1.value().symmetric_key();
        auto k2 = me2.value().symmetric_key();
        CHECK(crypto::secure_equal(k1.span(), k2.span()),
              "Deterministic mode: same file -> same key");
    }

    // ── derive_all() — all domain-separated keys at once ──────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto keys = me.derive_all();

        CHECK(keys.symmetric_key.size() == 32,    "derive_all: symmetric_key (32 B)");
        CHECK(keys.vault_master_key.size() == 32,  "derive_all: vault_master_key (32 B)");
        CHECK(keys.signing_seed.size() == 32,      "derive_all: signing_seed (32 B)");
        CHECK(keys.box_seed.size() == 32,          "derive_all: box_seed (32 B)");
        CHECK(keys.stream_key.size() == 32,        "derive_all: stream_key (32 B)");
        CHECK(keys.raw_entropy.size() == 64,       "derive_all: raw_entropy (64 B)");

        // All keys must be different from each other (domain separation)
        CHECK(!crypto::secure_equal(keys.symmetric_key.span(), keys.vault_master_key.span()),
              "Domain separation: sym != vault");
        CHECK(!crypto::secure_equal(keys.signing_seed.span(), keys.box_seed.span()),
              "Domain separation: sign != box");
    }

    // ── vault_keypair() — deterministic Ed25519 from entropy ──────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto kp1 = me.vault_keypair();
        auto kp2 = me.vault_keypair();
        CHECK(kp1.is_ok() && kp2.is_ok() &&
              crypto::secure_equal(kp1.value().sign_public.span(),
                                   kp2.value().sign_public.span()),
              "vault_keypair deterministic from same entropy");
    }

    // ── asym_bundle() — deterministic X25519 + Ed25519 ────────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto b1 = me.asym_bundle();
        auto b2 = me.asym_bundle();
        CHECK(b1.is_ok() && b2.is_ok() &&
              crypto::secure_equal(b1.value().box_public.span(),
                                   b2.value().box_public.span()) &&
              crypto::secure_equal(b1.value().sign_public.span(),
                                   b2.value().sign_public.span()),
              "asym_bundle deterministic from same entropy");
    }

    // ── make_vault() — full vault from entropy ────────────────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto vault_res = me.make_vault();
        CHECK(vault_res.is_ok(), "make_vault from entropy");

        auto& vault = vault_res.value();
        auto pkt = vault.seal("entropy-vault data", "e-ctx");
        auto pt  = vault.open(pkt.value(), "e-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == "entropy-vault data",
              "Entropy-seeded vault round-trip");
    }

    // ── MediaEntropy::seal() / open() — direct encryption ─────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto pkt = me.seal("entropy-direct seal", "d-ctx");
        CHECK(pkt.is_ok(), "MediaEntropy::seal direct");

        auto pt = me.open(pkt.value(), "d-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == "entropy-direct seal",
              "MediaEntropy::seal/open direct round-trip");
    }

    // ── Entropy boost injection into vault ─────────────────────────────────
    {
        auto me  = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto kp  = crypto::SecureVault::generate_keypair();
        auto key = crypto::random_bytes(32);
        crypto::SecureVault vault(key.span(), std::move(kp));

        // Seal with boost
        auto pkt = vault.seal("boosted payload", "boost-ctx", me);
        CHECK(pkt.is_ok(), "Vault seal with entropy boost");

        // Open with same boost
        auto pt = vault.open(pkt.value(), "boost-ctx", me);
        CHECK(pt.is_ok() && pt.value().to_string() == "boosted payload",
              "Vault open with entropy boost round-trip");

        // Open WITHOUT boost must fail (different derived key)
        auto fail = vault.open(pkt.value(), "boost-ctx");
        CHECK(fail.is_err(), "Vault open WITHOUT boost correctly fails");
    }

    // ── Entropy boost with AsymmetricVault ─────────────────────────────────
    {
        auto me    = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto alice = crypto::AsymmetricVault::generate_bundle();
        auto bob   = crypto::AsymmetricVault::generate_bundle();

        auto pt_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>("asym boost"), 10};
        auto aad_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>("ab-ctx"), 6};

        auto pkt = crypto::AsymmetricVault::seal(
            pt_span, alice, bob.box_public.span(), aad_span, me);
        CHECK(pkt.is_ok(), "AsymmetricVault seal with entropy boost");

        auto result = crypto::AsymmetricVault::open(
            pkt.value(), bob, alice.sign_public.span(), aad_span, me);
        CHECK(result.is_ok() && result.value().to_string() == "asym boost",
              "AsymmetricVault open with entropy boost round-trip");
    }

    // ── Multi-file entropy ────────────────────────────────────────────────
    {
        // Create a second source
        const std::string src2 = (fs::path(dir) / "entropy_source2.ppm").string();
        (void)crypto::stego::MediaGenerator::generate_ppm(src2, 128, 128);

        auto me = MediaEntropy::from_files_deterministic({entropy_src, src2});
        CHECK(me.is_ok(), "MediaEntropy::from_files_deterministic (2 files)");
        std::cout << "     multi-file source = "
                  << me.value().info().path << "\n";
    }

    // ── refresh_system_entropy() ──────────────────────────────────────────
    {
        auto me = std::move(MediaEntropy::from_file(entropy_src).value());
        auto k_before = me.symmetric_key();
        me.refresh_system_entropy();
        auto k_after = me.symmetric_key();
        CHECK(!crypto::secure_equal(k_before.span(), k_after.span()),
              "refresh_system_entropy changes derived keys");
    }

    // ── MediaEntropy::seal_into / open_from (stego) ───────────────────────
    {
        const std::string cover = (fs::path(dir) / "cover.ppm").string();
        if (!fs::exists(cover))
            (void)crypto::stego::MediaGenerator::generate_ppm(cover, 640, 480);

        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto out = stego_path(cover, dir, "stego_entropy");

        auto seal_r = me.seal_into(cover, "entropy-stego msg", out, "es-ctx");
        CHECK(seal_r.is_ok(), "MediaEntropy seal_into PPM");

        auto open_r = me.open_from(out, "es-ctx");
        CHECK(open_r.is_ok() && open_r.value().to_string() == "entropy-stego msg",
              "MediaEntropy open_from PPM round-trip");
    }

    // ── Convenience free functions ────────────────────────────────────────
    {
        auto key = key_from_file(entropy_src);
        CHECK(key.is_ok() && key.value().size() == 32,
              "key_from_file convenience");

        auto vault = vault_from_file(entropy_src);
        CHECK(vault.is_ok(), "vault_from_file convenience");
    }

    // ── seal_from_file / open_from_file ───────────────────────────────────
    {
        auto pkt = seal_from_file(entropy_src, "file-seal test", "fs-ctx");
        CHECK(pkt.is_ok(), "seal_from_file convenience");

        auto pt = open_from_file(entropy_src, pkt.value(), "fs-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == "file-seal test",
              "open_from_file convenience round-trip");
    }

    // ── SecureVault::from_entropy ─────────────────────────────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto vault_res = crypto::SecureVault::from_entropy(me);
        CHECK(vault_res.is_ok(), "SecureVault::from_entropy");

        auto& vault = vault_res.value();
        auto pkt = vault.seal("from_entropy test", "fe-ctx");
        auto pt  = vault.open(pkt.value(), "fe-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == "from_entropy test",
              "SecureVault::from_entropy round-trip");
    }

    // ── AsymmetricVault::from_entropy ─────────────────────────────────────
    {
        auto me = std::move(MediaEntropy::from_file_deterministic(entropy_src).value());
        auto bundle_res = crypto::AsymmetricVault::from_entropy(me);
        CHECK(bundle_res.is_ok(), "AsymmetricVault::from_entropy");

        // Use the derived bundle to seal/open
        auto& bundle = bundle_res.value();
        auto bob = crypto::AsymmetricVault::generate_bundle();
        auto pkt = crypto::AsymmetricVault::seal(
            "from_entropy asym", bundle, bob.box_public.span());
        CHECK(pkt.is_ok(), "AsymmetricVault seal with entropy-derived bundle");

        auto pt = crypto::AsymmetricVault::open(
            pkt.value(), bob, bundle.sign_public.span());
        CHECK(pt.is_ok() && pt.value().to_string() == "from_entropy asym",
              "AsymmetricVault from_entropy round-trip");
    }

    // ── asym_bundle_from_file ─────────────────────────────────────────────
    {
        auto b1 = asym_bundle_from_file(entropy_src);
        auto b2 = asym_bundle_from_file(entropy_src);
        CHECK(b1.is_ok() && b2.is_ok() &&
              crypto::secure_equal(b1.value().box_public.span(),
                                   b2.value().box_public.span()),
              "asym_bundle_from_file deterministic identity");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. POST-QUANTUM CRYPTOGRAPHY
// ─────────────────────────────────────────────────────────────────────────────

#ifdef CRYPTOLIB_HAS_PQ
static void demo_pq() {
    using namespace crypto::pq;
    section("9. Post-Quantum Cryptography (FIPS 203/204/205)");

    const std::string msg = "Post-quantum showcase message";
    auto msg_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};

    // ── ML-KEM-512: keygen, encaps, decaps ──────────────────────────────
    {
        auto kp = MlKem::generate_keypair(MlKem::Level::KEM_512);
        CHECK(kp.is_ok(), "ML-KEM-512 keygen");

        auto encap = MlKem::encapsulate(kp.value().public_key.span(), MlKem::Level::KEM_512);
        CHECK(encap.is_ok(), "ML-KEM-512 encapsulate");

        auto decap = MlKem::decapsulate(encap.value().ciphertext.span(),
                                         kp.value().secret_key.span(),
                                         MlKem::Level::KEM_512);
        CHECK(decap.is_ok(), "ML-KEM-512 decapsulate");

        CHECK(crypto::secure_equal(encap.value().shared_secret.span(),
                                   decap.value().span()),
              "ML-KEM-512 shared secrets match");

        // Wrong key produces different secret
        auto kp2 = MlKem::generate_keypair(MlKem::Level::KEM_512);
        auto decap_wrong = MlKem::decapsulate(encap.value().ciphertext.span(),
                                               kp2.value().secret_key.span(),
                                               MlKem::Level::KEM_512);
        CHECK(decap_wrong.is_ok() &&
              !crypto::secure_equal(encap.value().shared_secret.span(),
                                    decap_wrong.value().span()),
              "ML-KEM-512 wrong key -> different secret");

        auto sizes = MlKem::sizes(MlKem::Level::KEM_512);
        std::cout << "     ML-KEM-512: pk=" << sizes.value().public_key
                  << " sk=" << sizes.value().secret_key
                  << " ct=" << sizes.value().ciphertext
                  << " ss=" << sizes.value().shared_secret << " bytes\n";
    }

    // ── ML-KEM-768: keygen, encaps, decaps ──────────────────────────────
    {
        auto kp = MlKem::generate_keypair(MlKem::Level::KEM_768);
        CHECK(kp.is_ok(), "ML-KEM-768 keygen");

        auto encap = MlKem::encapsulate(kp.value().public_key.span(), MlKem::Level::KEM_768);
        CHECK(encap.is_ok(), "ML-KEM-768 encapsulate");

        auto decap = MlKem::decapsulate(encap.value().ciphertext.span(),
                                         kp.value().secret_key.span(),
                                         MlKem::Level::KEM_768);
        CHECK(decap.is_ok() &&
              crypto::secure_equal(encap.value().shared_secret.span(),
                                   decap.value().span()),
              "ML-KEM-768 round-trip (shared secrets match)");
    }

    // ── ML-KEM-1024: keygen, encaps, decaps ─────────────────────────────
    {
        auto kp = MlKem::generate_keypair(MlKem::Level::KEM_1024);
        CHECK(kp.is_ok(), "ML-KEM-1024 keygen");

        auto encap = MlKem::encapsulate(kp.value().public_key.span(), MlKem::Level::KEM_1024);
        CHECK(encap.is_ok(), "ML-KEM-1024 encapsulate");

        auto decap = MlKem::decapsulate(encap.value().ciphertext.span(),
                                         kp.value().secret_key.span(),
                                         MlKem::Level::KEM_1024);
        CHECK(decap.is_ok() &&
              crypto::secure_equal(encap.value().shared_secret.span(),
                                   decap.value().span()),
              "ML-KEM-1024 round-trip (shared secrets match)");

        auto sizes = MlKem::sizes(MlKem::Level::KEM_1024);
        std::cout << "     ML-KEM-1024: pk=" << sizes.value().public_key
                  << " sk=" << sizes.value().secret_key
                  << " ct=" << sizes.value().ciphertext
                  << " ss=" << sizes.value().shared_secret << " bytes\n";
    }

    // ── Hybrid KEM: X25519 + ML-KEM-768 (secure if EITHER survives) ──────
    {
        auto kp = HybridKem::generate_keypair();
        CHECK(kp.is_ok(), "Hybrid KEM (X25519+ML-KEM-768) keygen");

        auto encap = HybridKem::encapsulate(kp.value().public_key.span());
        CHECK(encap.is_ok(), "Hybrid KEM encapsulate");
        CHECK(encap.is_ok() && encap.value().shared_secret.size() == 32,
              "Hybrid KEM shared secret is 32 bytes");

        auto decap = HybridKem::decapsulate(encap.value().ciphertext.span(),
                                            kp.value().secret_key.span());
        CHECK(decap.is_ok() &&
              crypto::secure_equal(encap.value().shared_secret.span(),
                                   decap.value().span()),
              "Hybrid KEM round-trip (shared secrets match)");

        // A different keypair must not recover the same secret.
        auto other = HybridKem::generate_keypair();
        auto decap_wrong = HybridKem::decapsulate(encap.value().ciphertext.span(),
                                                  other.value().secret_key.span());
        CHECK(decap_wrong.is_ok() &&
              !crypto::secure_equal(encap.value().shared_secret.span(),
                                    decap_wrong.value().span()),
              "Hybrid KEM wrong key -> different secret");

        auto sz = HybridKem::sizes();
        std::cout << "     Hybrid (X25519+ML-KEM-768): pk=" << sz.value().public_key
                  << " sk=" << sz.value().secret_key
                  << " ct=" << sz.value().ciphertext
                  << " ss=" << sz.value().shared_secret << " bytes\n";
    }

    // ── ML-DSA-44: keygen, sign, verify ─────────────────────────────────
    {
        auto kp = MlDsa::generate_keypair(MlDsa::Level::DSA_44);
        CHECK(kp.is_ok(), "ML-DSA-44 keygen");

        auto sig = MlDsa::sign(msg, kp.value().secret_key.span(), MlDsa::Level::DSA_44);
        CHECK(sig.is_ok(), "ML-DSA-44 sign");

        auto ver = MlDsa::verify(msg, sig.value().span(),
                                  kp.value().public_key.span(), MlDsa::Level::DSA_44);
        CHECK(ver.is_ok(), "ML-DSA-44 verify (correct)");

        // Tampered message rejected
        std::string tampered = msg;
        tampered[0] ^= 0x01;
        auto ver_bad = MlDsa::verify(tampered, sig.value().span(),
                                      kp.value().public_key.span(), MlDsa::Level::DSA_44);
        CHECK(ver_bad.is_err(), "ML-DSA-44 verify (tampered msg rejected)");

        // Wrong key rejected
        auto kp2 = MlDsa::generate_keypair(MlDsa::Level::DSA_44);
        auto ver_wk = MlDsa::verify(msg, sig.value().span(),
                                     kp2.value().public_key.span(), MlDsa::Level::DSA_44);
        CHECK(ver_wk.is_err(), "ML-DSA-44 verify (wrong key rejected)");

        auto sizes = MlDsa::sizes(MlDsa::Level::DSA_44);
        std::cout << "     ML-DSA-44: pk=" << sizes.value().public_key
                  << " sk=" << sizes.value().secret_key
                  << " sig=" << sizes.value().signature << " bytes\n";
    }

    // ── ML-DSA-65: keygen, sign, verify ─────────────────────────────────
    {
        auto kp = MlDsa::generate_keypair(MlDsa::Level::DSA_65);
        CHECK(kp.is_ok(), "ML-DSA-65 keygen");

        auto sig = MlDsa::sign(msg, kp.value().secret_key.span(), MlDsa::Level::DSA_65);
        CHECK(sig.is_ok(), "ML-DSA-65 sign");

        auto ver = MlDsa::verify(msg, sig.value().span(),
                                  kp.value().public_key.span(), MlDsa::Level::DSA_65);
        CHECK(ver.is_ok(), "ML-DSA-65 verify (correct)");

        std::string tampered = msg;
        tampered[0] ^= 0x01;
        auto ver_bad = MlDsa::verify(tampered, sig.value().span(),
                                      kp.value().public_key.span(), MlDsa::Level::DSA_65);
        CHECK(ver_bad.is_err(), "ML-DSA-65 verify (tampered msg rejected)");
    }

    // ── ML-DSA-87: keygen, sign, verify ─────────────────────────────────
    {
        auto kp = MlDsa::generate_keypair(MlDsa::Level::DSA_87);
        CHECK(kp.is_ok(), "ML-DSA-87 keygen");

        auto sig = MlDsa::sign(msg, kp.value().secret_key.span(), MlDsa::Level::DSA_87);
        CHECK(sig.is_ok(), "ML-DSA-87 sign");

        auto ver = MlDsa::verify(msg, sig.value().span(),
                                  kp.value().public_key.span(), MlDsa::Level::DSA_87);
        CHECK(ver.is_ok(), "ML-DSA-87 verify (correct)");

        auto kp2 = MlDsa::generate_keypair(MlDsa::Level::DSA_87);
        auto ver_wk = MlDsa::verify(msg, sig.value().span(),
                                     kp2.value().public_key.span(), MlDsa::Level::DSA_87);
        CHECK(ver_wk.is_err(), "ML-DSA-87 verify (wrong key rejected)");

        auto sizes = MlDsa::sizes(MlDsa::Level::DSA_87);
        std::cout << "     ML-DSA-87: pk=" << sizes.value().public_key
                  << " sk=" << sizes.value().secret_key
                  << " sig=" << sizes.value().signature << " bytes\n";
    }

    // ── SLH-DSA-128f SHA2: keygen, sign, verify ────────────────────────
    {
        auto kp = SlhDsa::generate_keypair(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        CHECK(kp.is_ok(), "SLH-DSA-128f-SHA2 keygen");

        auto sig = SlhDsa::sign(msg, kp.value().secret_key.span(),
                                 SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        CHECK(sig.is_ok(), "SLH-DSA-128f-SHA2 sign");

        auto ver = SlhDsa::verify(msg, sig.value().span(),
                                   kp.value().public_key.span(),
                                   SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        CHECK(ver.is_ok(), "SLH-DSA-128f-SHA2 verify (correct)");

        std::string tampered = msg;
        tampered[0] ^= 0x01;
        auto ver_bad = SlhDsa::verify(tampered, sig.value().span(),
                                       kp.value().public_key.span(),
                                       SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        CHECK(ver_bad.is_err(), "SLH-DSA-128f-SHA2 verify (tampered rejected)");

        auto sizes_f = SlhDsa::sizes(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        std::cout << "     SLH-DSA-128f: pk=" << sizes_f.value().public_key
                  << " sig=" << sizes_f.value().signature << " bytes (fast)\n";
    }

    // ── SLH-DSA-128s SHA2: keygen, sign, verify ────────────────────────
    {
        auto kp = SlhDsa::generate_keypair(SlhDsa::Level::L128s, SlhDsa::HashFamily::SHA2);
        CHECK(kp.is_ok(), "SLH-DSA-128s-SHA2 keygen");

        auto sig = SlhDsa::sign(msg, kp.value().secret_key.span(),
                                 SlhDsa::Level::L128s, SlhDsa::HashFamily::SHA2);
        CHECK(sig.is_ok(), "SLH-DSA-128s-SHA2 sign");

        auto ver = SlhDsa::verify(msg, sig.value().span(),
                                   kp.value().public_key.span(),
                                   SlhDsa::Level::L128s, SlhDsa::HashFamily::SHA2);
        CHECK(ver.is_ok(), "SLH-DSA-128s-SHA2 verify (correct)");

        auto ver_bad = SlhDsa::verify(msg, sig.value().span(),
                                       kp.value().public_key.span(),
                                       SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        CHECK(ver_bad.is_err(), "SLH-DSA-128s verify (wrong variant rejected)");

        auto sizes_s = SlhDsa::sizes(SlhDsa::Level::L128s, SlhDsa::HashFamily::SHA2);
        auto sizes_f = SlhDsa::sizes(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        std::cout << "     SLH-DSA-128s: pk=" << sizes_s.value().public_key
                  << " sig=" << sizes_s.value().signature << " bytes (small)\n";
        std::cout << "     Size comparison: 128s sig=" << sizes_s.value().signature
                  << " vs 128f sig=" << sizes_f.value().signature
                  << " (s=smaller sig, f=faster signing)\n";
    }
}
#endif // CRYPTOLIB_HAS_PQ

// ─────────────────────────────────────────────────────────────────────────────
// 10. BLS12-381
// ─────────────────────────────────────────────────────────────────────────────

#ifdef CRYPTOLIB_HAS_BLS
static void demo_bls() {
    using namespace crypto::bls;
    section("10. BLS12-381 Signatures and Aggregation");

    const std::string msg = "BLS12-381 showcase message";
    auto msg_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};

    // ── Keygen from random ──────────────────────────────────────────────
    {
        auto kp = Bls12381::generate_keypair();
        CHECK(kp.is_ok(), "BLS keygen (random)");
        CHECK(kp.value().secret_key.size() == Bls12381::SECRET_KEY_BYTES,
              "BLS secret key size (32 B)");
        CHECK(kp.value().public_key.size() == Bls12381::PUBLIC_KEY_BYTES,
              "BLS public key size (48 B)");
    }

    // ── Keygen from IKM (deterministic) ─────────────────────────────────
    {
        auto ikm = crypto::random_bytes(32);
        auto kp1 = Bls12381::generate_keypair_from_ikm(ikm.span());
        auto kp2 = Bls12381::generate_keypair_from_ikm(ikm.span());
        CHECK(kp1.is_ok() && kp2.is_ok(), "BLS keygen from IKM");
        CHECK(crypto::secure_equal(kp1.value().public_key.span(),
                                   kp2.value().public_key.span()),
              "BLS keygen from IKM (deterministic — same pk)");
        CHECK(crypto::secure_equal(kp1.value().secret_key.span(),
                                   kp2.value().secret_key.span()),
              "BLS keygen from IKM (deterministic — same sk)");
    }

    // ── Sign / verify round-trip ────────────────────────────────────────
    auto kp = std::move(Bls12381::generate_keypair().value());
    {
        auto sig = Bls12381::sign(msg, kp.secret_key.span());
        CHECK(sig.is_ok(), "BLS sign");
        CHECK(sig.value().size() == Bls12381::SIGNATURE_BYTES,
              "BLS signature size (96 B)");

        auto ver = Bls12381::verify(msg, sig.value().span(), kp.public_key.span());
        CHECK(ver.is_ok(), "BLS verify (correct)");

        // Tampered message rejection
        std::string tampered = msg;
        tampered[0] ^= 0x01;
        auto ver_bad = Bls12381::verify(tampered, sig.value().span(), kp.public_key.span());
        CHECK(ver_bad.is_err(), "BLS verify (tampered msg rejected)");

        // Wrong key rejection
        auto kp2 = Bls12381::generate_keypair();
        auto ver_wk = Bls12381::verify(msg, sig.value().span(),
                                        kp2.value().public_key.span());
        CHECK(ver_wk.is_err(), "BLS verify (wrong key rejected)");
    }

    // ── Aggregate 3 signatures, verify aggregate ────────────────────────
    {
        auto kp1 = std::move(Bls12381::generate_keypair().value());
        auto kp2 = std::move(Bls12381::generate_keypair().value());
        auto kp3 = std::move(Bls12381::generate_keypair().value());

        std::string msg1 = "Message from signer 1";
        std::string msg2 = "Message from signer 2";
        std::string msg3 = "Message from signer 3";

        auto sig1 = Bls12381::sign(msg1, kp1.secret_key.span());
        auto sig2 = Bls12381::sign(msg2, kp2.secret_key.span());
        auto sig3 = Bls12381::sign(msg3, kp3.secret_key.span());
        CHECK(sig1.is_ok() && sig2.is_ok() && sig3.is_ok(),
              "BLS sign 3 messages from 3 signers");

        std::vector<std::span<const uint8_t>> sigs = {
            sig1.value().span(), sig2.value().span(), sig3.value().span()};
        auto agg = Bls12381::aggregate_signatures(sigs);
        CHECK(agg.is_ok(), "BLS aggregate 3 signatures");
        CHECK(agg.value().size() == Bls12381::SIGNATURE_BYTES,
              "BLS aggregate sig still 96 B (constant size)");

        std::vector<std::span<const uint8_t>> msgs = {
            {reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size()},
            {reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size()},
            {reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size()}};
        std::vector<std::span<const uint8_t>> pks = {
            kp1.public_key.span(), kp2.public_key.span(), kp3.public_key.span()};

        auto agg_ver = Bls12381::aggregate_verify(msgs, pks, agg.value().span());
        CHECK(agg_ver.is_ok(), "BLS aggregate verify (all correct)");

        // Tamper one message in aggregate — verify must fail
        std::string tampered_msg1 = "Tampered message from signer 1";
        std::vector<std::span<const uint8_t>> bad_msgs = {
            {reinterpret_cast<const uint8_t*>(tampered_msg1.data()), tampered_msg1.size()},
            {reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size()},
            {reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size()}};
        auto agg_ver_bad = Bls12381::aggregate_verify(bad_msgs, pks, agg.value().span());
        CHECK(agg_ver_bad.is_err(), "BLS aggregate verify (tampered msg1 rejected)");
    }

    // ── Size efficiency comparison ──────────────────────────────────────
    {
        std::cout << "     BLS12-381 sizes: sk=" << Bls12381::SECRET_KEY_BYTES
                  << " pk=" << Bls12381::PUBLIC_KEY_BYTES
                  << " sig=" << Bls12381::SIGNATURE_BYTES << " bytes\n";
        std::cout << "     Aggregate N sigs -> still " << Bls12381::SIGNATURE_BYTES
                  << " bytes (constant, regardless of N signers)\n";
    }
}
#endif // CRYPTOLIB_HAS_BLS

// ─────────────────────────────────────────────────────────────────────────────
// 11. BLAKE3 + HKDF
// ─────────────────────────────────────────────────────────────────────────────

static void demo_hkdf_blake3() {
    using namespace crypto::hash;
    section("11. BLAKE3, HMAC-SHA256 & HKDF-SHA256");

    const std::string msg = "BLAKE3 and HKDF showcase message";
    auto msg_span = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()};

    // ── BLAKE3 ──────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_BLAKE3
    // One-shot unkeyed hash
    {
        auto h = Blake3::digest(msg);
        CHECK(h.is_ok() && h.value().size() == 32, "BLAKE3 one-shot (32 B)");
        std::cout << "     BLAKE3 digest = " << h.value().to_hex().substr(0, 32) << "...\n";
    }

    // Keyed hash (MAC mode)
    {
        auto key = crypto::random_bytes(32);
        auto h = Blake3::keyed(msg_span, key.span());
        CHECK(h.is_ok() && h.value().size() == 32, "BLAKE3 keyed hash (32 B)");

        // Same key + message -> same output
        auto h2 = Blake3::keyed(msg_span, key.span());
        CHECK(h2.is_ok() &&
              crypto::secure_equal(h.value().span(), h2.value().span()),
              "BLAKE3 keyed hash (deterministic)");
    }

    // Key derivation (derive_key)
    {
        auto ikm = crypto::random_bytes(64);
        auto dk = Blake3::derive_key("cryptolib-showcase-2026", ikm.span(), 32);
        CHECK(dk.is_ok() && dk.value().size() == 32, "BLAKE3 derive_key (32 B)");

        // Different context -> different output
        auto dk2 = Blake3::derive_key("different-context", ikm.span(), 32);
        CHECK(dk2.is_ok() &&
              !crypto::secure_equal(dk.value().span(), dk2.value().span()),
              "BLAKE3 derive_key (different context -> different output)");
    }

    // Streaming API
    {
        Blake3::Stream stream;
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()), msg.size() / 2});
        stream.update({reinterpret_cast<const uint8_t*>(msg.data()) + msg.size() / 2,
                       msg.size() - msg.size() / 2});
        auto h_stream = stream.finalize();

        auto h_oneshot = Blake3::digest(msg);
        CHECK(h_oneshot.is_ok() &&
              crypto::secure_equal(h_stream.span(), h_oneshot.value().span()),
              "BLAKE3 streaming == one-shot");
    }
#else
    std::cout << "  [SKIP] BLAKE3 not available (CRYPTOLIB_BLAKE3=OFF)\n";
#endif // CRYPTOLIB_HAS_BLAKE3

    // ── HMAC-SHA256 ─────────────────────────────────────────────────────
    {
        auto key = crypto::random_bytes(HmacSha256::KEY_BYTES);
        auto mac = HmacSha256::compute(msg_span, key.span());
        CHECK(mac.is_ok(), "HMAC-SHA256 compute");
        CHECK(mac.value().size() == HmacSha256::MAC_BYTES, "HMAC-SHA256 tag size (32 B)");

        // Verify correct
        bool ok = HmacSha256::verify(msg_span, mac.value().span(), key.span());
        CHECK(ok, "HMAC-SHA256 verify (correct)");

        // Wrong key fails
        auto wrong_key = crypto::random_bytes(HmacSha256::KEY_BYTES);
        bool bad = HmacSha256::verify(msg_span, mac.value().span(), wrong_key.span());
        CHECK(!bad, "HMAC-SHA256 verify (wrong key rejected)");
    }

    // ── HKDF-SHA256 ─────────────────────────────────────────────────────

    // Extract + Expand
    {
        auto salt = crypto::random_bytes(32);
        auto ikm  = crypto::random_bytes(32);
        std::string info_str = "cryptolib-hkdf-test";
        auto info_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()};

        auto prk = HkdfSha256::extract(salt.span(), ikm.span());
        CHECK(prk.is_ok() && prk.value().size() == HkdfSha256::PRK_BYTES,
              "HKDF-SHA256 extract (PRK 32 B)");

        auto okm = HkdfSha256::expand(prk.value().span(), info_span, 64);
        CHECK(okm.is_ok() && okm.value().size() == 64,
              "HKDF-SHA256 expand (64 B output)");
    }

    // Deterministic: same inputs -> same output
    {
        auto salt = crypto::random_bytes(32);
        auto ikm  = crypto::random_bytes(32);
        std::string info_str = "determinism-test";
        auto info_span = std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()};

        auto k1 = HkdfSha256::derive(ikm.span(), salt.span(), info_span, 32);
        auto k2 = HkdfSha256::derive(ikm.span(), salt.span(), info_span, 32);
        CHECK(k1.is_ok() && k2.is_ok() &&
              crypto::secure_equal(k1.value().span(), k2.value().span()),
              "HKDF-SHA256 deterministic (same inputs -> same output)");
    }

    // RFC 5869 Test Vector (Test Case 1)
    {
        // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
        // Salt = 0x000102030405060708090a0b0c (13 bytes)
        // Info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
        // L    = 42
        std::vector<uint8_t> ikm(22, 0x0b);
        std::vector<uint8_t> salt = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,
                                     0x07,0x08,0x09,0x0a,0x0b,0x0c};
        std::vector<uint8_t> info = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,
                                     0xf7,0xf8,0xf9};

        // Expected PRK (from RFC 5869)
        std::vector<uint8_t> expected_prk = {
            0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,
            0x0d,0xdc,0x3f,0x0d,0xc4,0x7b,0xba,0x63,
            0x90,0xb6,0xc7,0x3b,0xb5,0x0f,0x9c,0x31,
            0x22,0xec,0x84,0x4a,0xd7,0xc2,0xb3,0xe5};

        auto prk = HkdfSha256::extract(salt, ikm);
        CHECK(prk.is_ok(), "HKDF-SHA256 RFC 5869 extract");

        bool prk_match = (prk.value().size() == expected_prk.size()) &&
            std::equal(prk.value().data(), prk.value().data() + prk.value().size(),
                       expected_prk.begin());
        CHECK(prk_match, "HKDF-SHA256 RFC 5869 PRK matches test vector");

        auto okm = HkdfSha256::expand(prk.value().span(), std::span<const uint8_t>{info}, 42);
        CHECK(okm.is_ok() && okm.value().size() == 42,
              "HKDF-SHA256 RFC 5869 expand (42 B)");

        // Expected OKM (from RFC 5869)
        std::vector<uint8_t> expected_okm = {
            0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,
            0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
            0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,
            0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
            0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
            0x58,0x65};

        bool okm_match = (okm.value().size() == expected_okm.size()) &&
            std::equal(okm.value().data(), okm.value().data() + okm.value().size(),
                       expected_okm.begin());
        CHECK(okm_match, "HKDF-SHA256 RFC 5869 OKM matches test vector");
    }

    // Different info -> different output
    {
        auto salt = crypto::random_bytes(32);
        auto ikm  = crypto::random_bytes(32);
        std::string info_a = "context-alpha";
        std::string info_b = "context-beta";

        auto ka = HkdfSha256::derive(ikm.span(), salt.span(),
            {reinterpret_cast<const uint8_t*>(info_a.data()), info_a.size()}, 32);
        auto kb = HkdfSha256::derive(ikm.span(), salt.span(),
            {reinterpret_cast<const uint8_t*>(info_b.data()), info_b.size()}, 32);
        CHECK(ka.is_ok() && kb.is_ok() &&
              !crypto::secure_equal(ka.value().span(), kb.value().span()),
              "HKDF-SHA256 different info -> different output");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. KEYRING — Envelope encryption with device + passphrase slots
// ─────────────────────────────────────────────────────────────────────────────

static void demo_keyring() {
    section("12. Keyring — Multi-Slot Envelope Encryption");

    // One random master key, wrapped under two independent unlock factors:
    // a device factor (HKDF) and a passphrase (Argon2id). Either recovers the
    // same master key — that is what makes single-device default + opt-in
    // cross-device recovery possible from one stored blob.
    auto kr = crypto::Keyring::create();
    CHECK(kr.slot_count() == 0, "Keyring::create (no slots yet)");

    // Device slot: the 32-byte factor stands in for a Secure Enclave /
    // Keystore / WebAuthn-PRF key — opaque, non-exportable in production.
    auto device_factor = crypto::random_bytes(32);
    CHECK(kr.add_device_slot(device_factor.span()).is_ok(), "add_device_slot (default path)");

    // Passphrase slot: opt-in cross-device recovery. Interactive params keep
    // the showcase fast; production guards the master with sensitive() params.
    CHECK(kr.add_passphrase_slot("cross-device pass", crypto::KdfParams::interactive()).is_ok(),
          "add_passphrase_slot (cross-device opt-in)");
    CHECK(kr.slot_count() == 2, "Keyring has 2 slots");

    // Persist the envelope — contains NO plaintext master key.
    auto blob = kr.serialise();
    CHECK(blob.size() > 0, "serialise envelope blob");
    std::cout << "     envelope = " << blob.size() << " bytes (no plaintext key)\n";

    // Reconstruct from the blob (as a fresh device would) and unlock both ways.
    auto kr2 = crypto::Keyring::deserialise(blob.span());
    CHECK(kr2.is_ok(), "deserialise envelope blob");

    auto m_dev  = kr2.value().unlock_with_device(device_factor.span());
    auto m_pass = kr2.value().unlock_with_passphrase("cross-device pass");
    CHECK(m_dev.is_ok() && m_pass.is_ok(), "unlock with device AND passphrase");
    CHECK(m_dev.is_ok() && m_pass.is_ok() &&
          crypto::secure_equal(m_dev.value().span(), m_pass.value().span()),
          "device factor and passphrase recover the SAME master key");

    // Wrong factors must fail closed.
    auto wrong_dev = crypto::random_bytes(32);
    CHECK(kr2.value().unlock_with_device(wrong_dev.span()).is_err(),
          "wrong device factor rejected");
    CHECK(kr2.value().unlock_with_passphrase("not the pass").is_err(),
          "wrong passphrase rejected");

    // Anti-downgrade: flipping the last byte corrupts the passphrase slot's
    // wrapped ciphertext, so AEAD authentication on that slot must fail.
    {
        std::vector<uint8_t> tampered(blob.span().begin(), blob.span().end());
        tampered.back() ^= 0xFF;
        auto kr_bad = crypto::Keyring::deserialise(tampered);
        bool opened = kr_bad.is_ok() &&
                      kr_bad.value().unlock_with_passphrase("cross-device pass").is_ok();
        CHECK(!opened, "tampered envelope fails authentication");
    }

    // Revocation: remove the passphrase slot, re-serialise → it no longer opens.
    {
        auto kr3 = std::move(crypto::Keyring::deserialise(blob.span()).value());
        CHECK(kr3.remove_slot(1).is_ok(), "remove_slot (revoke passphrase)");
        auto reblob = kr3.serialise();
        auto kr4 = std::move(crypto::Keyring::deserialise(reblob.span()).value());
        CHECK(kr4.unlock_with_passphrase("cross-device pass").is_err(),
              "revoked passphrase no longer opens master");
        CHECK(kr4.unlock_with_device(device_factor.span()).is_ok(),
              "device factor still opens after revocation");
    }

    // Convenience: unlock straight into a ready-to-use SecureVault.
    {
        auto kr5 = std::move(crypto::Keyring::deserialise(blob.span()).value());
        auto kp  = crypto::SecureVault::generate_keypair();
        auto vault = kr5.open_vault_with_device(device_factor.span(), std::move(kp));
        CHECK(vault.is_ok(), "open_vault_with_device");
        if (vault.is_ok()) {
            auto pkt = vault.value().seal("keyring-protected data", "kr-ctx");
            auto pt  = vault.value().open(pkt.value(), "kr-ctx");
            CHECK(pt.is_ok() && pt.value().to_string() == "keyring-protected data",
                  "keyring-opened vault round-trip");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 13. GRAND FINALE — Everything combined
// ─────────────────────────────────────────────────────────────────────────────

static void demo_grand_finale(const std::string& dir) {
    section("13. Grand Finale — Full-Stack Cryptographic Workflow");

    std::cout << R"(
  Scenario: Alice and Bob communicate via steganographic channels.
  - A private photo provides physical entropy (LavaRand)
  - Entropy seeds deterministic identities for both parties
  - Symmetric vault encrypts with 4-layer pipeline + entropy boost
  - Ciphertext is hidden inside carrier media files
  - Each output preserves the original carrier's file extension
)" << "\n";

    // ── Step 1: Generate carrier media ────────────────────────────────────
    const std::string cover_img   = (fs::path(dir) / "finale_cover.ppm").string();
    const std::string cover_audio = (fs::path(dir) / "finale_cover.wav").string();
    const std::string cover_video = (fs::path(dir) / "finale_cover.crvf").string();

    (void)crypto::stego::MediaGenerator::generate_ppm(cover_img, 640, 480);
    (void)crypto::stego::MediaGenerator::generate_wav(cover_audio, 44100, 1, 5.0);
    (void)crypto::stego::MediaGenerator::generate_crvf(cover_video, 320, 240, 30, 30);
    std::cout << "  Step 1: Generated 3 carrier files (PPM, WAV, CRVF)\n";

    // ── Step 2: Harvest entropy from a private photo ──────────────────────
    const std::string private_photo = (fs::path(dir) / "private_photo.ppm").string();
    (void)crypto::stego::MediaGenerator::generate_ppm(private_photo, 512, 512);

    auto entropy = crypto::entropy::MediaEntropy::from_file_deterministic(private_photo);
    CHECK(entropy.is_ok(), "Harvest entropy from private photo");
    auto& me = entropy.value();
    std::cout << "  Step 2: Entropy harvested (" << me.entropy_bits() << " bits)\n";

    // ── Step 3: Derive all key material from entropy ──────────────────────
    auto all_keys = me.derive_all();
    std::cout << "  Step 3: Derived 6 domain-separated keys from entropy\n";

    // ── Step 4: Hash the secret message with multiple algorithms ──────────
    const std::string secret = "OPERATION MIDNIGHT: rendezvous at coordinates 48.8566N 2.3522E";

    auto blake2b_hash = crypto::hash::Blake2b::digest(secret);
    auto sha256_hash  = crypto::hash::Sha256::digest(secret);
    auto sha512_hash  = crypto::hash::Sha512::digest(secret);
    auto hmac_tag     = crypto::hash::HmacSha512::compute(
        {reinterpret_cast<const uint8_t*>(secret.data()), secret.size()},
        all_keys.raw_entropy.span());

    CHECK(blake2b_hash.is_ok() && sha256_hash.is_ok() &&
          sha512_hash.is_ok() && hmac_tag.is_ok(),
          "Compute 4 hash digests of the secret message");
    std::cout << "  Step 4: Fingerprinted message (Blake2b + SHA-256 + SHA-512 + HMAC)\n";

    // ── Step 5: Encrypt with standalone symmetric cipher ──────────────────
    auto sym_ct = crypto::symmetric::XChaCha20Poly1305::encrypt(
        secret, all_keys.symmetric_key.span(), "standalone-aead");
    CHECK(sym_ct.is_ok(), "XChaCha20-Poly1305 standalone encrypt");

    auto sym_pt = crypto::symmetric::XChaCha20Poly1305::decrypt(
        sym_ct.value().span(), all_keys.symmetric_key.span(),
        {reinterpret_cast<const uint8_t*>("standalone-aead"), 15});
    CHECK(sym_pt.is_ok() && sym_pt.value().to_string() == secret,
          "XChaCha20-Poly1305 standalone round-trip");
    std::cout << "  Step 5: Standalone AEAD encryption verified\n";

    // ── Step 6: Encrypt with SecretStream (chunked) ───────────────────────
    {
        crypto::symmetric::SecretStream::Encryptor enc(all_keys.stream_key.span());
        const auto& hdr = enc.header();

        // Split message into chunks
        auto c1 = enc.push({reinterpret_cast<const uint8_t*>(secret.data()), 30});
        auto c2 = enc.push_final(
            {reinterpret_cast<const uint8_t*>(secret.data()) + 30, secret.size() - 30});

        crypto::symmetric::SecretStream::Decryptor dec(all_keys.stream_key.span(), hdr.span());
        auto r1 = dec.pull(c1.span());
        auto r2 = dec.pull(c2.span());

        std::string reassembled = r1.value().plaintext.to_string() +
                                  r2.value().plaintext.to_string();
        CHECK(reassembled == secret, "SecretStream chunked round-trip");
        std::cout << "  Step 6: SecretStream chunked encryption verified\n";
    }

    // ── Step 7: Build asymmetric identities from entropy ──────────────────
    auto alice_bundle = std::move(me.asym_bundle().value());
    auto bob_bundle   = crypto::AsymmetricVault::generate_bundle();

    // Sign the message with Alice's derived identity
    auto sig = crypto::asymmetric::Ed25519::sign(
        {reinterpret_cast<const uint8_t*>(secret.data()), secret.size()},
        alice_bundle.sign_secret.span());
    CHECK(sig.is_ok(), "Ed25519 sign with entropy-derived key");

    bool sig_ok = crypto::asymmetric::Ed25519::verify(
        {reinterpret_cast<const uint8_t*>(secret.data()), secret.size()},
        sig.value().span(),
        alice_bundle.sign_public.span());
    CHECK(sig_ok, "Ed25519 verify with entropy-derived key");
    std::cout << "  Step 7: Asymmetric identities derived, signature verified\n";

    // ── Step 8: AsymmetricVault — Alice -> Bob with stego (PPM) ───────────
    {
        auto out = stego_path(cover_img, dir, "finale_asym_stego");

        auto r = crypto::AsymmetricVault::seal_into(
            alice_bundle, bob_bundle.box_public.span(),
            secret, cover_img, out, "finale-asym-ctx");
        CHECK(r.is_ok(), "AsymmetricVault seal_into PPM (Alice -> Bob)");

        auto pt = crypto::AsymmetricVault::open_from(
            bob_bundle, alice_bundle.sign_public.span(), out, "finale-asym-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == secret,
              "AsymmetricVault open_from PPM (Bob decrypts)");
        std::cout << "  Step 8: Asymmetric vault + stego (PPM) verified\n";
    }

    // ── Step 9: SecureVault with entropy boost — hidden in WAV ────────────
    {
        auto vault = std::move(me.make_vault().value());
        auto out = stego_path(cover_audio, dir, "finale_vault_stego");

        // Seal with entropy boost into audio carrier
        auto pkt = vault.seal("boosted secret in audio", "audio-boost-ctx", me);
        CHECK(pkt.is_ok(), "Entropy-boosted vault seal");

        auto embed = crypto::stego::StegoEngine::embed_packet(
            cover_audio, pkt.value(), out);
        CHECK(embed.is_ok(), "Embed boosted packet into WAV");

        auto extracted = crypto::stego::StegoEngine::extract_packet(out);
        CHECK(extracted.is_ok(), "Extract boosted packet from WAV");

        auto pt = vault.open(extracted.value(), "audio-boost-ctx", me);
        CHECK(pt.is_ok() && pt.value().to_string() == "boosted secret in audio",
              "Entropy-boosted vault + WAV stego round-trip");
        std::cout << "  Step 9: Entropy-boosted vault + WAV stego verified\n";
    }

    // ── Step 10: MediaEntropy seal_into / open_from (CRVF) ────────────────
    {
        auto out = stego_path(cover_video, dir, "finale_entropy_stego");

        auto r = me.seal_into(cover_video, secret, out, "finale-video-ctx");
        CHECK(r.is_ok(), "MediaEntropy seal_into CRVF");

        auto pt = me.open_from(out, "finale-video-ctx");
        CHECK(pt.is_ok() && pt.value().to_string() == secret,
              "MediaEntropy open_from CRVF round-trip");
        std::cout << "  Step 10: MediaEntropy + CRVF video stego verified\n";
    }

    // ── Step 11: Verify all output files have correct extensions ──────────
    {
        bool ext_ok = true;
        auto check_ext = [&](const std::string& path, const std::string& expected) {
            auto actual = fs::path(path).extension().string();
            if (actual != expected) {
                std::cerr << "     EXTENSION MISMATCH: " << path
                          << " expected " << expected << " got " << actual << "\n";
                ext_ok = false;
            }
        };

        check_ext(stego_path(cover_img, dir, "finale_asym_stego"), ".ppm");
        check_ext(stego_path(cover_audio, dir, "finale_vault_stego"), ".wav");
        check_ext(stego_path(cover_video, dir, "finale_entropy_stego"), ".crvf");
        CHECK(ext_ok, "All stego output files preserve original extension");
    }

    // ── Step 12: Cross-verify — constant-time equality checks ─────────────
    {
        auto a = crypto::random_bytes(32);
        auto b = crypto::SecureBuffer(a.data(), a.size());
        CHECK(crypto::secure_equal(a.span(), b.span()),
              "secure_equal (matching buffers)");

        auto c = crypto::random_bytes(32);
        CHECK(!crypto::secure_equal(a.span(), c.span()),
              "secure_equal (different buffers)");
        std::cout << "  Step 12: Constant-time comparisons verified\n";
    }

    // ── Step 13: Final quality check on all stego outputs ─────────────────
    {
        auto psnr = crypto::stego::StegoEngine::quality(
            cover_img, stego_path(cover_img, dir, "finale_asym_stego"));
        if (psnr.is_ok()) {
            std::cout << "     Finale image PSNR = " << psnr.value() << " dB\n";
            CHECK(psnr.value() >= 30.0, "Finale image PSNR >= 30 dB");
        }

        auto snr = crypto::stego::StegoEngine::quality(
            cover_audio, stego_path(cover_audio, dir, "finale_vault_stego"));
        if (snr.is_ok()) {
            std::cout << "     Finale audio SNR  = " << snr.value() << " dB\n";
            CHECK(snr.value() >= 10.0, "Finale audio SNR >= 10 dB");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    crypto::init();

    // Default output directory: system temp path (fully portable, no hardcoded paths)
    std::string out_dir = (fs::temp_directory_path() / "cryptolib_showcase").string();
    if (argc > 1) out_dir = argv[1];

    fs::create_directories(out_dir);
    std::cout << "CryptoLib v3.0.0 — Full Showcase\n"
              << "Output directory: " << out_dir << "\n";

    // Run all demos
    demo_hashing();
    demo_symmetric();
    demo_asymmetric();
    demo_secure_vault();
    demo_asymmetric_vault();
    demo_steganography(out_dir);
    demo_extended_stego(out_dir);
    demo_media_entropy(out_dir);
#ifdef CRYPTOLIB_HAS_PQ
    demo_pq();
#endif
#ifdef CRYPTOLIB_HAS_BLS
    demo_bls();
#endif
    demo_hkdf_blake3();
    demo_keyring();
    demo_grand_finale(out_dir);

    // Summary
    section("SUMMARY");
    std::cout << "  Passed: " << g_pass << "\n"
              << "  Failed: " << g_fail << "\n"
              << "  Total:  " << (g_pass + g_fail) << "\n\n";

    if (g_fail == 0) {
        std::cout << "  ALL CHECKS PASSED — every CryptoLib feature verified.\n\n";
        std::cout << "  Features exercised:\n"
                  << "    - Blake2b (one-shot, streaming, keyed)\n"
                  << "    - SHA-256 (one-shot, streaming)\n"
                  << "    - SHA-512 (one-shot, streaming)\n"
                  << "    - Argon2id (hash, verify, derive, PHC string)\n"
                  << "    - HMAC-SHA512 (compute, verify)\n"
                  << "    - XChaCha20-Poly1305 (encrypt, decrypt, tamper detection)\n"
                  << "    - AES-256-GCM (encrypt, decrypt — if CPU supports)\n"
                  << "    - SecretStream (multi-chunk streaming AEAD)\n"
                  << "    - Box (authenticated public-key encryption)\n"
                  << "    - SealedBox (anonymous sender encryption)\n"
                  << "    - Ed25519 (sign, verify, from_seed, curve conversion)\n"
                  << "    - X25519 (raw ECDH shared secret)\n"
                  << "    - HybridBox (encrypt-then-sign)\n"
                  << "    - SecureVault (4-layer symmetric pipeline)\n"
                  << "    - AsymmetricVault (3-layer public-key pipeline)\n"
                  << "    - EncryptedPacket serialisation\n"
                  << "    - Steganography: PPM (DCT/QIM), WAV (phase), CRVF (per-frame)\n"
                  << "    - Extended stego: BMP, PNG, GIF, JPEG (JSteg), MP3, AVI, MP4\n"
                  << "    - StegoEngine: embed, extract, embed_packet, extract_packet\n"
                  << "    - Capacity queries and quality (PSNR/SNR) measurements\n"
                  << "    - MediaGenerator (PPM, WAV, CRVF, BMP, PNG, GIF, AVI)\n"
                  << "    - MediaEntropy (LavaRand + deterministic modes)\n"
                  << "    - derive_all, vault_keypair, asym_bundle\n"
                  << "    - Entropy boost (vault + asymmetric vault)\n"
                  << "    - Multi-file entropy, refresh_system_entropy\n"
                  << "    - from_entropy (SecureVault, AsymmetricVault)\n"
                  << "    - Convenience: key_from_file, vault_from_file, seal_from_file\n"
                  << "    - Vault seal_into/open_from (PPM, WAV, CRVF)\n"
                  << "    - AsymmetricVault seal_into/open_from\n"
                  << "    - MediaEntropy seal_into/open_from\n"
#ifdef CRYPTOLIB_HAS_PQ
                  << "    - ML-KEM (512/768/1024 encaps/decaps, wrong-key detection)\n"
                  << "    - Hybrid KEM (X25519 + ML-KEM-768, HKDF combiner)\n"
                  << "    - ML-DSA (44/65/87 sign/verify, tamper/wrong-key rejection)\n"
                  << "    - SLH-DSA (128f/128s SHA2 sign/verify, size comparison)\n"
#endif
#ifdef CRYPTOLIB_HAS_BLS
                  << "    - BLS12-381 (keygen, IKM keygen, sign/verify, aggregation)\n"
#endif
#ifdef CRYPTOLIB_HAS_BLAKE3
                  << "    - BLAKE3 (one-shot, keyed, derive_key, streaming)\n"
#endif
                  << "    - HMAC-SHA256 (compute, verify, wrong-key rejection)\n"
                  << "    - HKDF-SHA256 (extract, expand, RFC 5869 test vector)\n"
                  << "    - Keyring (device + passphrase slots, revocation, anti-downgrade)\n"
                  << "    - secure_equal, random_bytes\n"
                  << "    - Output file extension preservation\n";
    }

    return g_fail > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
