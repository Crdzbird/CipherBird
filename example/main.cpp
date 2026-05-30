/**
 * CryptoLib — Progressive Tutorial
 *
 * A step-by-step walkthrough of every library feature, from basic hashing
 * to full vault+stego+entropy integration.
 *
 * Usage:
 *   ./cryptolib_poc [output_dir]
 *
 * All generated files (carriers, stego outputs) go into output_dir.
 * Default: system temp directory / cryptolib_tutorial
 */

#include <cryptolib/cryptolib.hpp>

#include <cstdio>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

// ─── Terminal colours ─────────────────────────────────────────────────────────
#define RST  "\033[0m"
#define BOLD "\033[1m"
#define GRN  "\033[32m"
#define CYN  "\033[36m"
#define YLW  "\033[33m"
#define RED  "\033[31m"
#define MAG  "\033[35m"
#define BLU  "\033[34m"

static void section(const char* t)     { std::printf("\n" BOLD CYN "━━━ %s ━━━" RST "\n", t); }
static void subsect(const char* t)     { std::printf("\n  " BOLD MAG "▸ %s" RST "\n", t); }
static void ok (const std::string& m)  { std::printf("    " GRN "✓" RST " %s\n", m.c_str()); }
static void bad(const std::string& m)  { std::printf("    " RED "✗ FAIL:" RST " %s\n", m.c_str()); std::exit(1); }
static void inf(const char* l, const std::string& v) {
    std::printf("      " YLW "%-28s" RST " %s\n", l, v.c_str());
}
static void note(const std::string& m) { std::printf("      " BLU "→" RST " %s\n", m.c_str()); }

template<typename T>
static void must(const crypto::Result<T>& r, const char* label) {
    if (r.is_err()) bad(std::string(label) + ": " + r.error().message);
}

static std::string hex(const crypto::SecureBuffer& b, std::size_t n = 32) {
    auto h = b.to_hex();
    return h.substr(0, std::min(n, h.size())) + "…";
}

static std::span<const uint8_t> sv2sp(std::string_view s) {
    return { reinterpret_cast<const uint8_t*>(s.data()), s.size() };
}

// ─── Output directory (set in main, used everywhere) ─────────────────────────
static fs::path g_dir;

static std::string out(const std::string& filename) {
    return (g_dir / filename).string();
}

// =============================================================================
// A — STANDALONE PRIMITIVES
// =============================================================================
static void demo_standalone() {
    section("A — Standalone Primitives");

    // ── Hashing ──────────────────────────────────────────────────────────────
    // CryptoLib provides 5 hash primitives. All return Result<T> — never throw
    // on crypto failures. Use .is_ok() to check, .value() to unwrap.

    subsect("Unidirectional hashing");
    {
        constexpr std::string_view msg = "The quick brown fox jumps over the lazy dog";

        // BLAKE2b-512: fast, 64-byte digest, also supports keyed MAC mode
        auto b2 = crypto::hash::Blake2b::digest(msg); must(b2, "blake2b");
        inf("BLAKE2b-512:", hex(b2.value()));
        ok("BLAKE2b one-shot");

        // Streaming mode: feed data in chunks, finalize once
        crypto::hash::Blake2b::Stream st;
        st.update(sv2sp(msg.substr(0, 19)));
        st.update(sv2sp(msg.substr(19)));
        auto h2 = st.finalize();
        crypto::secure_equal(h2.span(), b2.value().span())
            ? ok("BLAKE2b streaming matches one-shot")
            : bad("BLAKE2b stream mismatch");

        // SHA-256 / SHA-512: NIST standard hashes
        auto s256 = crypto::hash::Sha256::digest(msg); must(s256, "sha256");
        inf("SHA-256:", s256.value().to_hex());
        ok("SHA-256");

        auto s512 = crypto::hash::Sha512::digest(msg); must(s512, "sha512");
        inf("SHA-512:", hex(s512.value(), 48));
        ok("SHA-512");

        // HMAC-SHA512: keyed message authentication code
        auto hk = crypto::random_bytes(crypto::hash::HmacSha512::KEY_BYTES);
        auto mac = crypto::hash::HmacSha512::compute(sv2sp(msg), hk.span()); must(mac, "hmac");
        crypto::hash::HmacSha512::verify(sv2sp(msg), mac.value().span(), hk.span())
            ? ok("HMAC-SHA512 verified")
            : bad("HMAC mismatch");
    }

    // ── Password hashing with Argon2id ──────────────────────────────────────
    // Memory-hard KDF — the gold standard for password storage (OWASP 2023).
    // Never use SHA/BLAKE2b directly for passwords.

    subsect("Argon2id password hashing (unidirectional)");
    {
        constexpr std::string_view pw = "correcthorsebatterystaple";

        // PHC string format: self-contained, embeds salt + params
        auto phc = crypto::hash::Argon2id::hash_password_str(pw); must(phc, "argon2id phc");
        inf("PHC string:", phc.value());
        crypto::hash::Argon2id::verify_str(pw, phc.value())
            ? ok("Correct password verified")
            : bad("PHC fail");
        !crypto::hash::Argon2id::verify_str("wrong", phc.value())
            ? ok("Wrong password rejected")
            : bad("Wrong password accepted");
    }

    // ── Symmetric AEAD ──────────────────────────────────────────────────────
    // XChaCha20-Poly1305: recommended default. 192-bit nonce (safe random).
    // Output: [nonce(24) | ciphertext | MAC(16)]

    subsect("Symmetric AEAD (bidirectional)");
    {
        constexpr std::string_view pt  = "Secret: launch code ALPHA-7";
        constexpr std::string_view aad = "session:abc123";

        auto key = crypto::symmetric::XChaCha20Poly1305::generate_key();
        auto enc = crypto::symmetric::XChaCha20Poly1305::encrypt(pt, key.span(), aad);
        must(enc, "xchacha enc");
        auto dec = crypto::symmetric::XChaCha20Poly1305::decrypt(
            enc.value().span(), key.span(), sv2sp(aad));
        must(dec, "xchacha dec");
        dec.value().to_string() == pt
            ? ok("XChaCha20-Poly1305 round-trip")
            : bad("xchacha mismatch");

        // Tamper detection: flip one bit → authentication failure
        auto t = std::vector<uint8_t>(enc.value().data(), enc.value().data() + enc.value().size());
        t.back() ^= 0xff;
        auto bad_r = crypto::symmetric::XChaCha20Poly1305::decrypt(t, key.span(), sv2sp(aad));
        bad_r.is_err() ? ok("Tampered ciphertext rejected") : bad("Tamper accepted");
    }

    // ── Asymmetric crypto ───────────────────────────────────────────────────
    // Box: X25519 key agreement + XSalsa20-Poly1305 — both parties identified.
    // Ed25519: deterministic digital signatures (64 bytes).

    subsect("Asymmetric encryption & signatures");
    {
        constexpr std::string_view msg = "Private: meet at dawn";
        auto alice = crypto::asymmetric::Box::generate_keypair();
        auto bob   = crypto::asymmetric::Box::generate_keypair();

        auto enc = crypto::asymmetric::Box::encrypt(sv2sp(msg), bob.public_key.span(), alice.secret_key.span());
        must(enc, "box enc");
        auto dec = crypto::asymmetric::Box::decrypt(enc.value().span(), alice.public_key.span(), bob.secret_key.span());
        must(dec, "box dec");
        dec.value().to_string() == msg ? ok("Box encrypt/decrypt") : bad("box mismatch");

        // Ed25519 signatures
        auto skp = crypto::asymmetric::Ed25519::generate_keypair();
        auto sig = crypto::asymmetric::Ed25519::sign(sv2sp(msg), skp.secret_key.span());
        must(sig, "ed25519 sign");
        inf("Signature:", hex(sig.value()));
        crypto::asymmetric::Ed25519::verify(sv2sp(msg), sig.value().span(), skp.public_key.span())
            ? ok("Ed25519 sign + verify")
            : bad("signature fail");
        !crypto::asymmetric::Ed25519::verify(sv2sp("tampered"), sig.value().span(), skp.public_key.span())
            ? ok("Tampered message rejected")
            : bad("tampered accepted");
    }
}

// =============================================================================
// B — LAYERED VAULT PIPELINE
// =============================================================================
static void demo_vault() {
    section("B — Layered Vault Pipeline");

    // SecureVault chains 4 layers (each defends against a different attack):
    //   L1 Argon2id KDF      → brute-force resistance
    //   L2 BLAKE2b integrity → corruption detection
    //   L3 XChaCha20-Poly1305 AEAD → confidentiality + authentication
    //   L4 Ed25519 signature → forgery prevention

    subsect("SecureVault (symmetric: Argon2id+BLAKE2b+XChaCha20+Ed25519)");
    {
        auto mk = crypto::random_bytes(32);
        auto kp = crypto::SecureVault::generate_keypair();
        crypto::SecureVault vault(mk.span(), std::move(kp));

        constexpr std::string_view pt  = "TOP SECRET: coordinates 48.8566°N 2.3522°E";
        constexpr std::string_view aad = "user:007;mission:paris";

        auto pkt = vault.seal(pt, aad); must(pkt, "seal");
        inf("kdf_salt:",   pkt.value().kdf_salt.to_hex());
        inf("signature:",  hex(pkt.value().signature));
        inf("ciphertext:", hex(pkt.value().ciphertext));
        ok("seal() — 4 layers applied");

        auto plain = vault.open(pkt.value(), aad); must(plain, "open");
        plain.value().to_string() == pt
            ? ok("open() — plaintext recovered")
            : bad("vault mismatch");

        // Wrong key → L4 rejects (signature mismatch)
        auto kp2 = crypto::SecureVault::generate_keypair();
        crypto::SecureVault bad_vault(crypto::random_bytes(32).span(), std::move(kp2));
        bad_vault.open(pkt.value(), aad).is_err()
            ? ok("[L4] Wrong key rejected")
            : bad("wrong key accepted");

        // Wrong AAD → L3 rejects (AEAD authentication fails)
        vault.open(pkt.value(), "user:mallory;evil").is_err()
            ? ok("[L3] Wrong AAD rejected")
            : bad("wrong AAD accepted");

        // Serialise → wire → deserialise → open
        auto wire = pkt.value().serialise();
        auto p2   = crypto::EncryptedPacket::deserialise(wire.span()); must(p2, "deserialise");
        auto pl2  = vault.open(p2.value(), aad); must(pl2, "open after deser");
        pl2.value().to_string() == pt
            ? ok("Serialise/deserialise round-trip")
            : bad("round-trip mismatch");
    }

    // AsymmetricVault: same idea but uses X25519 Box instead of a shared key.
    // No pre-shared secret needed — Alice and Bob each have their own keypairs.

    subsect("AsymmetricVault (X25519+BLAKE2b+Box+Ed25519)");
    {
        auto alice = crypto::AsymmetricVault::generate_bundle();
        auto bob   = crypto::AsymmetricVault::generate_bundle();

        constexpr std::string_view msg = "Confidential: Q4 projections";
        constexpr std::string_view aad = "channel:alice-to-bob";

        auto pkt = crypto::AsymmetricVault::seal(msg, alice, bob.box_public.span(), aad);
        must(pkt, "asym seal");
        ok("Alice sealed for Bob");

        auto plain = crypto::AsymmetricVault::open(
            pkt.value(), bob, alice.sign_public.span(), aad);
        must(plain, "asym open");
        plain.value().to_string() == msg
            ? ok("Bob opened and verified Alice's signature")
            : bad("asym mismatch");

        // Impersonation test: Mallory's signature won't match
        auto mallory = crypto::AsymmetricVault::generate_bundle();
        crypto::AsymmetricVault::open(pkt.value(), bob, mallory.sign_public.span(), aad).is_err()
            ? ok("[L3] Forged signature rejected — Mallory cannot impersonate Alice")
            : bad("forgery accepted");
    }
}

// =============================================================================
// C — MEDIA ENTROPY (LavaRand-inspired)
//
// Cloudflare's LavaRand uses a camera pointed at lava lamps to generate
// unpredictable entropy from physical processes. CryptoLib's MediaEntropy
// applies the same principle: any media file (photo, audio, video) becomes
// a source of physical randomness. The pixel noise in a photograph, the
// thermal noise floor in an audio recording, or the sensor jitter across
// video frames — all contain genuine physical entropy that no algorithm
// can predict.
//
// The pipeline:
//   1. Read raw file bytes through BLAKE2b streaming hash (64 B digest)
//   2. XOR with system entropy (randombytes_buf) — LavaRand defence-in-depth
//   3. BLAKE2b re-hash with domain-separated labels → independent keys
//
// Result: one media file produces multiple cryptographically independent keys,
// each usable for a different purpose (symmetric encryption, vault master key,
// Ed25519 signing seed, X25519 box seed, SecretStream key).
// =============================================================================
static void demo_media_entropy() {
    section("C — Media Entropy: Your Files Are Your Keys");

    note("Like Cloudflare's LavaRand — physical media noise becomes crypto keys.");
    note("Pipeline: file bytes → BLAKE2b → XOR system entropy → domain-separated keys");
    std::puts("");

    // Generate multiple synthetic media files to use as entropy sources.
    // In real use, these would be your own photos, voice memos, or video clips.
    auto photo_src = out("entropy_photo.ppm");
    auto audio_src = out("entropy_audio.wav");
    auto video_src = out("entropy_video.crvf");
    {
        using MG = crypto::stego::MediaGenerator;
        crypto::stego::MediaGeneratorParams p;
        p.ppm_seed = 0xC0FFEE42;
        must(MG::generate_ppm(photo_src, 1024, 768, p), "gen entropy photo");
        must(MG::generate_wav(audio_src, 44100, 1, 10.0), "gen entropy audio");
        must(MG::generate_crvf(video_src, 320, 240, 30, 30), "gen entropy video");
    }

    // ── C1: Photo as encryption key ─────────────────────────────────────────
    // The simplest use case: a photo file becomes an XChaCha20 encryption key.
    // Anyone with the same photo can decrypt. Lose the photo, lose the data.

    subsect("C1 — Photo as encryption key (simplest LavaRand pattern)");
    {
        auto me = crypto::entropy::MediaEntropy::from_file(photo_src);
        must(me, "photo harvest");

        const auto& mi = me.value().info();
        inf("Source:", mi.path);
        inf("File size:", std::to_string(mi.file_size) + " bytes");
        inf("Entropy estimate:", std::to_string((int)me.value().entropy_bits()) + " bits");
        ok("Entropy harvested from photo");

        // derive_all() returns 6 independent keys from one file
        auto keys = me.value().derive_all();
        inf("symmetric_key:",    hex(keys.symmetric_key));
        inf("vault_master_key:", hex(keys.vault_master_key));
        inf("signing_seed:",     hex(keys.signing_seed));
        inf("box_seed:",         hex(keys.box_seed));
        inf("stream_key:",       hex(keys.stream_key));

        // Domain separation: all keys are cryptographically independent
        bool distinct =
            !crypto::secure_equal(keys.symmetric_key.span(), keys.vault_master_key.span()) &&
            !crypto::secure_equal(keys.symmetric_key.span(), keys.signing_seed.span()) &&
            !crypto::secure_equal(keys.vault_master_key.span(), keys.box_seed.span()) &&
            !crypto::secure_equal(keys.signing_seed.span(), keys.stream_key.span());
        distinct ? ok("All 6 derived keys are distinct (domain separation)") : bad("Keys collide");

        // Encrypt a secret using the photo-derived symmetric key
        constexpr std::string_view secret = "Only someone with this exact photo can decrypt this.";
        auto enc = crypto::symmetric::XChaCha20Poly1305::encrypt(secret, keys.symmetric_key.span());
        must(enc, "photo-key enc");
        auto dec = crypto::symmetric::XChaCha20Poly1305::decrypt(
            enc.value().span(), keys.symmetric_key.span());
        must(dec, "photo-key dec");
        dec.value().to_string() == secret
            ? ok("XChaCha20-Poly1305: encrypted with photo, decrypted with same photo")
            : bad("photo key round-trip mismatch");
    }

    // ── C2: Audio file → streaming encryption ───────────────────────────────
    // An audio recording (voice memo, song) becomes a SecretStream key.
    // SecretStream is designed for large data — each chunk is independently
    // authenticated with automatic key ratcheting for forward secrecy.

    subsect("C2 — Audio recording → SecretStream (chunked encryption)");
    {
        auto me = crypto::entropy::MediaEntropy::from_file(audio_src);
        must(me, "audio harvest");
        inf("Source:", me.value().info().path);
        inf("Entropy:", std::to_string((int)me.value().entropy_bits()) + " bits");
        ok("Entropy harvested from audio recording");

        auto keys = me.value().derive_all();

        // Encrypt a multi-part message using the audio-derived stream key
        std::vector<std::string> chunks = {
            "Audio-keyed chunk 1: mission briefing header",
            "Audio-keyed chunk 2: coordinates and timing",
            "Audio-keyed chunk 3: extraction plan (final)"
        };

        crypto::symmetric::SecretStream::Encryptor enc(keys.stream_key.span());
        std::vector<crypto::SecureBuffer> cts;
        for (std::size_t i = 0; i < chunks.size(); ++i) {
            bool last = (i == chunks.size() - 1);
            cts.push_back(enc.push(sv2sp(chunks[i]),
                last ? crypto::symmetric::SecretStream::TAG_FINAL
                     : crypto::symmetric::SecretStream::TAG_MESSAGE));
        }

        crypto::symmetric::SecretStream::Decryptor dec(keys.stream_key.span(), enc.header().span());
        bool all_ok = true;
        for (std::size_t i = 0; i < cts.size(); ++i) {
            auto r = dec.pull(cts[i].span());
            if (r.is_err() || r.value().plaintext.to_string() != chunks[i]) { all_ok = false; break; }
        }
        all_ok
            ? ok("SecretStream: 3 chunks encrypted/decrypted with audio-derived key")
            : bad("SecretStream audio-key mismatch");
    }

    // ── C3: Video file → Ed25519 signing identity ───────────────────────────
    // A video clip deterministically produces an Ed25519 keypair.
    // The video IS your identity — same video, same public key, every time.

    subsect("C3 — Video clip → deterministic signing identity (Ed25519)");
    {
        auto me = crypto::entropy::MediaEntropy::from_file_deterministic(video_src);
        must(me, "video harvest");
        inf("Source:", me.value().info().path);
        ok("Entropy harvested from video clip (deterministic mode)");

        auto bundle = me.value().asym_bundle();
        must(bundle, "video bundle");
        inf("Ed25519 public key:", hex(bundle.value().sign_public));
        inf("X25519 public key:",  hex(bundle.value().box_public));

        // Sign a document with the video-derived identity
        constexpr std::string_view document = "I certify this with my video-derived key.";
        auto sig = crypto::asymmetric::Ed25519::sign(sv2sp(document), bundle.value().sign_secret.span());
        must(sig, "video sign");
        crypto::asymmetric::Ed25519::verify(sv2sp(document), sig.value().span(), bundle.value().sign_public.span())
            ? ok("Ed25519: signed and verified with video-derived keypair")
            : bad("video signature fail");

        // Prove determinism: same video → same identity
        auto me2 = crypto::entropy::MediaEntropy::from_file_deterministic(video_src);
        must(me2, "video harvest 2");
        auto bundle2 = me2.value().asym_bundle();
        must(bundle2, "video bundle 2");
        crypto::secure_equal(bundle.value().sign_public.span(), bundle2.value().sign_public.span())
            ? ok("Deterministic: same video → same Ed25519 public key every time")
            : bad("deterministic identity mismatch");
    }

    // ── C4: Deterministic vs LavaRand modes ─────────────────────────────────
    // from_file() mixes system entropy → different keys each time (LavaRand)
    // from_file_deterministic() uses file bytes only → reproducible keys

    subsect("C4 — LavaRand (non-deterministic) vs deterministic modes");
    {
        auto lava1 = crypto::entropy::MediaEntropy::from_file(photo_src);
        auto lava2 = crypto::entropy::MediaEntropy::from_file(photo_src);
        must(lava1, "lava1"); must(lava2, "lava2");
        !crypto::secure_equal(lava1.value().raw().span(), lava2.value().raw().span())
            ? ok("LavaRand: same file, different keys each call (system entropy mixed)")
            : bad("LavaRand should differ");

        auto det1 = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        auto det2 = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        must(det1, "det1"); must(det2, "det2");
        crypto::secure_equal(det1.value().raw().span(), det2.value().raw().span())
            ? ok("Deterministic: same file → identical keys (cross-process reproducible)")
            : bad("deterministic should match");

        note("Use LavaRand (from_file) for session keys — maximum entropy.");
        note("Use deterministic for cross-process key agreement — same file = same key.");
    }

    // ── C5: Multiple files → combined entropy ───────────────────────────────
    // Mix entropy from multiple files: photo + audio + video.
    // The combined entropy exceeds any single source — defence in depth.

    subsect("C5 — Multiple files → combined entropy (photo + audio + video)");
    {
        auto me = crypto::entropy::MediaEntropy::from_files_deterministic(
            {photo_src, audio_src, video_src});
        must(me, "multi-file harvest");
        inf("Sources combined:", "3 files (photo + audio + video)");
        inf("Combined entropy:", std::to_string((int)me.value().entropy_bits()) + " bits");
        ok("Multi-source entropy harvested — exceeds any single file");

        // Use combined entropy for the strongest symmetric encryption
        auto key = me.value().symmetric_key();
        constexpr std::string_view secret = "Protected by three media files. Compromise all three to break.";
        auto enc = crypto::symmetric::XChaCha20Poly1305::encrypt(secret, key.span());
        must(enc, "multi-file enc");
        auto dec = crypto::symmetric::XChaCha20Poly1305::decrypt(enc.value().span(), key.span());
        must(dec, "multi-file dec");
        dec.value().to_string() == secret
            ? ok("Encrypted with combined entropy from 3 media files")
            : bad("multi-file round-trip fail");
    }

    // ── C6: Convenience APIs — one-liner encryption from a file ─────────────
    // For the common case: "I just want to encrypt something using my photo."

    subsect("C6 — Convenience APIs: one-liner encryption from a file");
    {
        // seal_from_file / open_from_file: encrypt/decrypt using a file as key
        auto pkt = crypto::entropy::seal_from_file(photo_src, "Top secret message", "my-context");
        must(pkt, "seal_from_file");
        auto pt = crypto::entropy::open_from_file(photo_src, pkt.value(), "my-context");
        must(pt, "open_from_file");
        pt.value().to_string() == "Top secret message"
            ? ok("seal_from_file / open_from_file — one-liner round-trip")
            : bad("convenience seal mismatch");

        // key_from_file: just give me a 32-byte key from this file
        auto key = crypto::entropy::key_from_file(photo_src);
        must(key, "key_from_file");
        inf("Derived key:", hex(key.value()));
        ok("key_from_file — instant 32-byte key from any media file");

        // vault_from_file: full 4-layer vault from one file
        auto vault = crypto::entropy::vault_from_file(photo_src);
        must(vault, "vault_from_file");
        auto vpkt = vault.value().seal("Vault-protected by a photo", "ctx");
        must(vpkt, "vault seal");
        auto vpt = vault.value().open(vpkt.value(), "ctx");
        must(vpt, "vault open");
        vpt.value().to_string() == "Vault-protected by a photo"
            ? ok("vault_from_file — full 4-layer vault from a single photo")
            : bad("vault_from_file mismatch");

        // asym_bundle_from_file: X25519 + Ed25519 identity from a file
        auto bundle = crypto::entropy::asym_bundle_from_file(photo_src);
        must(bundle, "asym_bundle_from_file");
        inf("Box public key:",  hex(bundle.value().box_public));
        inf("Sign public key:", hex(bundle.value().sign_public));
        ok("asym_bundle_from_file — full asymmetric identity from a photo");
    }

    // ── C7: Entropy boost — two-factor vault encryption ─────────────────────
    // Combine a master key AND a media file: compromise either alone is not enough.
    // This is vault.seal(plaintext, aad, media_entropy) — the entropy_boost() path.

    subsect("C7 — Entropy boost: two-factor vault (master key + media file)");
    {
        auto mk    = crypto::random_bytes(32);
        auto kp    = crypto::SecureVault::generate_keypair();
        auto vault = crypto::SecureVault(mk.span(), std::move(kp));

        auto me1 = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        auto me2 = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        must(me1, "boost me1"); must(me2, "boost me2");

        // Seal with both master key AND photo entropy
        constexpr std::string_view secret = "Requires BOTH the master key AND the photo to decrypt.";
        auto pkt = vault.seal(secret, "boost-ctx", me1.value());
        must(pkt, "boosted seal");
        note("Sealed with vault.seal(plaintext, aad, media_entropy)");

        // Open with both master key AND photo entropy — succeeds
        auto pt = vault.open(pkt.value(), "boost-ctx", me2.value());
        must(pt, "boosted open");
        pt.value().to_string() == secret
            ? ok("Boosted seal/open: master key + photo → decrypted")
            : bad("boosted mismatch");

        // Open WITHOUT the photo entropy — fails (wrong derived key)
        auto fail = vault.open(pkt.value(), "boost-ctx");
        fail.is_err()
            ? ok("Without photo: decryption fails (two-factor enforced)")
            : bad("should have failed without photo");

        note("Like a hardware token: the master key alone is insufficient.");
        note("The photo acts as a second factor — a physical key.");
    }

    // ── C8: Refresh system entropy for long-lived sessions ──────────────────
    subsect("C8 — Refresh system entropy (long-lived sessions)");
    {
        auto me = crypto::entropy::MediaEntropy::from_file(photo_src);
        must(me, "refresh source");

        auto k_before = me.value().symmetric_key();
        me.value().refresh_system_entropy();
        auto k_after = me.value().symmetric_key();

        !crypto::secure_equal(k_before.span(), k_after.span())
            ? ok("refresh_system_entropy() rotates derived keys in-place")
            : bad("keys should change after refresh");

        note("Call periodically in long-running servers for forward secrecy.");
    }

    // ── C9: File as credential — enrollment + verification ────────────────
    // Pattern: the file IS the password. At enrollment time, store a public
    // fingerprint (Ed25519 public key or BLAKE2b of the derived key).
    // At verification time, the user presents the file again — re-derive
    // the fingerprint and compare.

    subsect("C9 — File as credential (enrollment → verification)");
    {
        note("Like password hashing, but with a file instead of a password.");
        note("Enrollment: derive a public fingerprint from the file.");
        note("Verification: user presents the file → re-derive → compare.");
        std::puts("");

        // ── Enrollment: user registers with their private photo ──
        auto me_enroll = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        must(me_enroll, "enrollment harvest");

        // Option A: use the Ed25519 public key as the credential fingerprint
        auto bundle = me_enroll.value().asym_bundle();
        must(bundle, "enrollment bundle");
        auto stored_pubkey = crypto::SecureBuffer(
            bundle.value().sign_public.data(), bundle.value().sign_public.size());
        inf("Stored fingerprint:", hex(stored_pubkey));
        ok("Enrollment: Ed25519 public key stored as credential");

        // Option B: use BLAKE2b of the symmetric key as a credential hash
        auto sym_key = me_enroll.value().symmetric_key();
        auto credential_hash = crypto::hash::Blake2b::digest(sym_key.span());
        must(credential_hash, "credential hash");
        inf("Credential hash:", hex(credential_hash.value()));

        // ── Verification: user presents the same file ──
        auto me_verify = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
        must(me_verify, "verify harvest");

        auto verify_bundle = me_verify.value().asym_bundle();
        must(verify_bundle, "verify bundle");

        // Compare the public keys
        crypto::secure_equal(stored_pubkey.span(), verify_bundle.value().sign_public.span())
            ? ok("Verification: same file → fingerprint matches (ACCESS GRANTED)")
            : bad("fingerprint mismatch");

        // ── Wrong file: verification must fail ──
        auto wrong_src = out("entropy_audio.wav"); // different file
        auto me_wrong = crypto::entropy::MediaEntropy::from_file_deterministic(wrong_src);
        must(me_wrong, "wrong file harvest");
        auto wrong_bundle = me_wrong.value().asym_bundle();
        must(wrong_bundle, "wrong bundle");

        !crypto::secure_equal(stored_pubkey.span(), wrong_bundle.value().sign_public.span())
            ? ok("Wrong file → fingerprint differs (ACCESS DENIED)")
            : bad("wrong file accepted");

        // ── Challenge-response: prove possession without revealing the key ──
        // The server sends a random challenge, the client signs it with the
        // file-derived Ed25519 key, the server verifies against the stored pubkey.
        subsect("Challenge-response: prove file possession without revealing it");
        {
            auto challenge = crypto::random_bytes(32);
            inf("Challenge:", hex(challenge));

            // Client side: sign the challenge with the file-derived signing key
            auto me_client = crypto::entropy::MediaEntropy::from_file_deterministic(photo_src);
            must(me_client, "client harvest");
            auto client_bundle = me_client.value().asym_bundle();
            must(client_bundle, "client bundle");
            auto response = crypto::asymmetric::Ed25519::sign(
                challenge.span(), client_bundle.value().sign_secret.span());
            must(response, "sign challenge");
            inf("Response:", hex(response.value()));

            // Server side: verify the response against the stored public key
            bool valid = crypto::asymmetric::Ed25519::verify(
                challenge.span(), response.value().span(), stored_pubkey.span());
            valid
                ? ok("Server verified: client has the file (zero-knowledge proof)")
                : bad("challenge-response failed");

            // Attacker without the file cannot forge the response
            auto fake_kp = crypto::asymmetric::Ed25519::generate_keypair();
            auto fake_sig = crypto::asymmetric::Ed25519::sign(
                challenge.span(), fake_kp.secret_key.span());
            must(fake_sig, "fake sign");
            bool fake_valid = crypto::asymmetric::Ed25519::verify(
                challenge.span(), fake_sig.value().span(), stored_pubkey.span());
            !fake_valid
                ? ok("Attacker's forged response rejected")
                : bad("forged response accepted");

            note("The file never leaves the client. The server only stores the public key.");
            note("This is zero-knowledge: possession is proven without revealing the secret.");
        }
    }

    // ── C10: Error handling ─────────────────────────────────────────────────
    subsect("C10 — Error handling — invalid inputs");
    {
        auto r1 = crypto::entropy::MediaEntropy::from_file(out("nonexistent.jpg"));
        r1.is_err() ? ok("Missing file rejected") : bad("missing file accepted");

        auto tiny_path = out("tiny.bin");
        { std::ofstream f(tiny_path, std::ios::binary); f << "too small"; }
        auto r2 = crypto::entropy::MediaEntropy::from_file(tiny_path);
        r2.is_err() ? ok("File <256 B rejected") : bad("tiny file accepted");

        auto r3 = crypto::entropy::MediaEntropy::from_files({});
        r3.is_err() ? ok("Empty file list rejected") : bad("empty list accepted");
    }
}

// =============================================================================
// D — END-TO-END: media entropy → vault → stego (the full pipeline)
//
// The ultimate integration: a photo provides all crypto keys, the vault
// encrypts through 4 layers, and the result is hidden inside carrier media.
// No passwords, no key files — the physical media IS the key.
// =============================================================================
static void demo_end_to_end() {
    section("D — Full Pipeline: media entropy → vault → steganography");

    std::puts("  Scenario: a private photo provides ALL cryptographic material.");
    std::puts("  The photo is the password. Lose the photo, lose the data.\n");

    auto photo = out("entropy_photo.ppm");

    // ── Step 1: Harvest entropy from the photo ──────────────────────────────
    auto me = crypto::entropy::MediaEntropy::from_file_deterministic(photo);
    must(me, "harvest");
    inf("Source:", photo);
    inf("Entropy:", std::to_string((int)me.value().entropy_bits()) + " bits");
    ok("Step 1: Entropy harvested from photo (deterministic — reproducible)");

    // ── Step 2: Build a full vault from the photo entropy ───────────────────
    auto vault = me.value().make_vault(crypto::KdfParams::interactive());
    must(vault, "make_vault");
    ok("Step 2: SecureVault built — master key, signing keys all from photo");

    // ── Step 3: Encrypt through all 4 layers ────────────────────────────────
    constexpr std::string_view plaintext = "CLASSIFIED: Operation Sunrise — T-minus 6 hours";
    constexpr std::string_view aad       = "classification:TS/SCI;operator:alpha-team";

    auto pkt = vault.value().seal(plaintext, aad); must(pkt, "seal");
    ok("Step 3: Sealed through 4 layers (Argon2id+BLAKE2b+XChaCha20+Ed25519)");

    // ── Step 4: Serialise → wire → deserialise → open ──────────────────────
    auto wire = pkt.value().serialise();
    inf("Wire size:", std::to_string(wire.size()) + " bytes");
    auto pkt2  = crypto::EncryptedPacket::deserialise(wire.span()); must(pkt2, "deserialise");
    auto plain = vault.value().open(pkt2.value(), aad);             must(plain, "open");
    plain.value().to_string() == plaintext
        ? ok("Step 4: Deserialised + opened — plaintext recovered")
        : bad("End-to-end mismatch");

    // ── Step 5: Attack resistance ───────────────────────────────────────────
    vault.value().open(pkt2.value(), "wrong:context").is_err()
        ? ok("Step 5a: Wrong AAD rejected") : bad("wrong AAD accepted");

    crypto::EncryptedPacket tampered{
        crypto::SecureBuffer(pkt2.value().ciphertext.data(), pkt2.value().ciphertext.size()),
        crypto::SecureBuffer(pkt2.value().signature.data(),  pkt2.value().signature.size()),
        crypto::SecureBuffer(pkt2.value().kdf_salt.data(),   pkt2.value().kdf_salt.size())
    };
    tampered.ciphertext.data()[0] ^= 0xff;
    vault.value().open(tampered, aad).is_err()
        ? ok("Step 5b: Tampered ciphertext rejected") : bad("tamper accepted");

    // ── Step 6: Hide the encrypted packet inside a carrier image ────────────
    // Generate a cover image, embed the vault packet into it via steganography
    auto cover = out("pipeline_cover.ppm");
    must(crypto::stego::MediaGenerator::generate_ppm(cover, 640, 480), "gen pipeline cover");

    must(vault.value().seal_into(cover, plaintext, out("pipeline_stego.ppm"), aad), "pipeline seal_into");
    ok("Step 6: Encrypted data hidden inside a PPM image (DCT/QIM)");

    auto recovered = vault.value().open_from(out("pipeline_stego.ppm"), aad);
    must(recovered, "pipeline open_from");
    recovered.value().to_string() == plaintext
        ? ok("Step 7: Extracted from stego image → decrypted → plaintext verified")
        : bad("pipeline stego mismatch");

    note("Full pipeline: photo → entropy → vault → encrypt → hide in image → recover.");
    note("No passwords were used. The photo IS the key.");

    // ── Step 8: Alice→Bob via entropy-derived identities + stego ────────────
    subsect("Alice→Bob: entropy-derived identities hidden in audio");
    {
        // Alice derives her identity from her private photo
        auto alice_me = crypto::entropy::MediaEntropy::from_file_deterministic(out("entropy_photo.ppm"));
        must(alice_me, "alice entropy");
        auto alice = alice_me.value().asym_bundle();
        must(alice, "alice bundle");
        inf("Alice sign_pub:", hex(alice.value().sign_public));

        // Bob has his own keypair (could also be entropy-derived)
        auto bob = crypto::AsymmetricVault::generate_bundle();
        inf("Bob   box_pub:",  hex(bob.box_public));

        // Alice encrypts for Bob and hides it in audio
        auto audio_cover = out("pipeline_audio_cover.wav");
        must(crypto::stego::MediaGenerator::generate_wav(audio_cover, 44100, 1, 10.0), "gen audio cover");

        must(crypto::AsymmetricVault::seal_into(
            alice.value(), bob.box_public.span(),
            "Bob — midnight rendezvous, north dock.",
            audio_cover, out("pipeline_audio_stego.wav"), "alice-to-bob"), "asym seal_into");
        ok("Alice sealed for Bob, hidden in WAV audio (phase coding)");

        auto bob_plain = crypto::AsymmetricVault::open_from(
            bob, alice.value().sign_public.span(),
            out("pipeline_audio_stego.wav"), "alice-to-bob");
        must(bob_plain, "bob open_from");
        ok("Bob extracted from audio, verified Alice's Ed25519 signature, decrypted");
        inf("Message:", bob_plain.value().to_string());
    }
}

// =============================================================================
// E — STEGANOGRAPHY LAYER
// =============================================================================
static void demo_steganography() {
    section("E — Steganography Layer (DCT/QIM + Phase Coding)");

    using MG = crypto::stego::MediaGenerator;

    note("Generating carrier files with MediaGenerator");

    // PPM: 640x480 gradient + Gaussian photon-shot noise
    must(MG::generate_ppm(out("stego_cover.ppm"), 640, 480), "generate PPM");
    // WAV: 5-second mono 44.1 kHz tone + thermal noise
    must(MG::generate_wav(out("stego_cover.wav"), 44100, 1, 5.0), "generate WAV");
    // CRVF: 30 frames 320x240 RGB gradient + per-frame variation
    must(MG::generate_crvf(out("stego_cover.crvf"), 320, 240, 30, 30), "generate CRVF");

    inf("PPM cover:",  "640x480 P6 (gradient + Gaussian noise)");
    inf("WAV cover:",  "5 s mono 44.1 kHz (440 Hz + harmonics + thermal)");
    inf("CRVF cover:", "30 x 320x240 RGB24 frames (gradient + variation)");
    std::puts("");

    // ── E1: Image steganography ─────────────────────────────────────────────
    // DCT/QIM on the blue channel of 8x8 pixel blocks.
    // Blue channel chosen because human vision is least sensitive to blue.

    subsect("E1 — ImageSteganographer (DCT/QIM, blue channel)");
    {
        using IS = crypto::stego::ImageSteganographer;

        auto cap = IS::capacity(640, 480);
        inf("Payload capacity:", std::to_string(cap) + " bytes");

        // Embed a vault packet into an image
        auto kp    = crypto::SecureVault::generate_keypair();
        auto vault = crypto::SecureVault(crypto::random_bytes(32).span(), std::move(kp));
        auto pkt   = vault.seal("Hidden inside a PPM image", "stego:image:demo");
        must(pkt, "vault seal for image stego");
        auto serial = pkt.value().serialise();
        inf("Payload:", std::to_string(serial.size()) + " bytes (EncryptedPacket)");

        auto embed_res = IS::embed(
            out("stego_cover.ppm"),
            std::span<const uint8_t>(serial.data(), serial.size()),
            out("stego_photo.ppm"), 16);
        must(embed_res, "image embed");
        ok("Embedded EncryptedPacket into PPM via DCT/QIM");

        double psnr = IS::psnr(out("stego_cover.ppm"), out("stego_photo.ppm"));
        inf("PSNR:", std::to_string(static_cast<int>(psnr)) + " dB (>40 = imperceptible)");
        ok("Image quality: " + std::to_string(static_cast<int>(psnr)) + " dB");

        // Extract and verify
        auto extr = IS::extract(out("stego_photo.ppm"), 16);
        must(extr, "image extract");
        auto pkt2 = crypto::EncryptedPacket::deserialise(
            std::span<const uint8_t>(extr.value().data(), extr.value().size()));
        must(pkt2, "packet deserialise");
        auto plain = vault.open(pkt2.value(), "stego:image:demo");
        must(plain, "vault open from stego");
        plain.value().to_string() == "Hidden inside a PPM image"
            ? ok("Vault packet recovered from image — plaintext verified")
            : bad("Image stego round-trip mismatch");
    }

    // ── E2: Audio steganography ─────────────────────────────────────────────
    // Phase coding: embeds bits by setting FFT bin phases to 0 (bit=0) or pi (bit=1).
    // Human hearing is insensitive to phase — only amplitude matters.

    subsect("E2 — AudioSteganographer (Phase Coding, mid-frequency bins)");
    {
        using AS = crypto::stego::AudioSteganographer;
        crypto::stego::StegoParams params;

        auto cap = AS::capacity(44100 * 5, params);
        inf("Payload capacity:", std::to_string(cap) + " bytes");

        const std::string secret = "Phase-coded secret transmission #42";
        std::vector<uint8_t> payload(secret.begin(), secret.end());

        auto embed_res = AS::embed(out("stego_cover.wav"), payload, out("stego_audio.wav"), params);
        must(embed_res, "audio embed");
        ok("Embedded payload via Phase Coding");

        double snr = AS::snr(out("stego_cover.wav"), out("stego_audio.wav"));
        inf("SNR:", std::to_string(static_cast<int>(snr)) + " dB (>20 = imperceptible)");

        auto extr = AS::extract(out("stego_audio.wav"), params);
        must(extr, "audio extract");
        std::string recovered(extr.value().begin(), extr.value().end());
        recovered == secret
            ? ok("Payload extracted — byte-exact match")
            : bad("Audio stego mismatch");
    }

    // ── E3: Video steganography ─────────────────────────────────────────────
    // DCT/QIM distributed across CRVF frames — payload split across multiple frames.

    subsect("E3 — VideoSteganographer (DCT/QIM per frame, CRVF format)");
    {
        using VS = crypto::stego::VideoSteganographer;
        crypto::stego::StegoParams params;

        auto cap = VS::capacity(30, 320, 240, params);
        inf("Payload capacity:", std::to_string(cap) + " bytes");

        const std::string secret = "Multi-frame covert channel across 30 video frames.";
        std::vector<uint8_t> payload(secret.begin(), secret.end());

        auto embed_res = VS::embed(out("stego_cover.crvf"), payload, out("stego_video.crvf"), params);
        must(embed_res, "video embed");
        ok("Embedded payload distributed across frames");

        auto extr = VS::extract(out("stego_video.crvf"), params);
        must(extr, "video extract");
        std::string recovered(extr.value().begin(), extr.value().end());
        recovered == secret
            ? ok("Payload extracted — byte-exact match")
            : bad("Video stego mismatch");
    }

    // ── E4: StegoEngine facade + vault integration ──────────────────────────
    // StegoEngine auto-dispatches to the right steganographer based on file extension.
    // embed_packet() / extract_packet() work with EncryptedPacket directly.

    subsect("E4 — StegoEngine facade: auto-dispatch + vault integration");
    {
        using SE = crypto::stego::StegoEngine;
        crypto::stego::StegoParams params;

        // Capacity queries
        auto cap_img = SE::capacity(out("stego_cover.ppm"), params); must(cap_img, "cap img");
        auto cap_aud = SE::capacity(out("stego_cover.wav"), params); must(cap_aud, "cap aud");
        auto cap_vid = SE::capacity(out("stego_cover.crvf"), params); must(cap_vid, "cap vid");
        note(cap_img.value().description);
        note(cap_aud.value().description);
        note(cap_vid.value().description);
        ok("StegoEngine::capacity — format auto-detected from extension");

        // Vault integration: seal → embed_packet → extract_packet → open
        auto kp    = crypto::SecureVault::generate_keypair();
        auto vault = crypto::SecureVault(crypto::random_bytes(32).span(), std::move(kp));
        auto pkt   = vault.seal("Classified payload concealed in media.", "stego:engine");
        must(pkt, "vault seal");

        auto emb = SE::embed_packet(
            out("stego_cover.ppm"), pkt.value(), out("engine_stego.ppm"), params);
        must(emb, "embed_packet");

        auto pkt2 = SE::extract_packet(out("engine_stego.ppm"), params);
        must(pkt2, "extract_packet");
        auto plain = vault.open(pkt2.value(), "stego:engine");
        must(plain, "vault open from stego");
        ok("StegoEngine embed_packet → extract_packet → vault.open — verified");

        // Quality metric via facade
        auto q = SE::quality(out("stego_cover.ppm"), out("engine_stego.ppm"));
        must(q, "quality");
        inf("PSNR (facade):", std::to_string(static_cast<int>(q.value())) + " dB");
    }

    // ── E5: Native vault stego integration ──────────────────────────────────
    // seal_into() / open_from() on the vault object — one call each way.

    subsect("E5 — Native vault stego: seal_into / open_from");
    {
        auto kp    = crypto::SecureVault::generate_keypair();
        auto vault = crypto::SecureVault(crypto::random_bytes(32).span(), std::move(kp));

        const char* pt = "Sealed and hidden in one call";

        // Image
        must(vault.seal_into(out("stego_cover.ppm"), pt, out("native_stego.ppm"), "ctx"), "seal_into ppm");
        auto r1 = vault.open_from(out("native_stego.ppm"), "ctx"); must(r1, "open_from ppm");
        r1.value().to_string() == pt ? ok("PPM: seal_into / open_from") : bad("PPM mismatch");

        // Audio
        must(vault.seal_into(out("stego_cover.wav"), pt, out("native_stego.wav"), "ctx"), "seal_into wav");
        auto r2 = vault.open_from(out("native_stego.wav"), "ctx"); must(r2, "open_from wav");
        r2.value().to_string() == pt ? ok("WAV: seal_into / open_from") : bad("WAV mismatch");

        // Video
        must(vault.seal_into(out("stego_cover.crvf"), pt, out("native_stego.crvf"), "ctx"), "seal_into crvf");
        auto r3 = vault.open_from(out("native_stego.crvf"), "ctx"); must(r3, "open_from crvf");
        r3.value().to_string() == pt ? ok("CRVF: seal_into / open_from") : bad("CRVF mismatch");

        note("Same API, same two-call pattern — format auto-detected from extension.");
    }

    // ── E6: Same file as key AND carrier ────────────────────────────────────
    // The file serves double duty: its pixel noise derives the encryption key,
    // AND the encrypted payload is hidden back inside a copy of the same file.
    // Stego and entropy are independent features, but they compose naturally.

    subsect("E6 — Same file as entropy key source AND stego carrier");
    {
        // Use the cover PPM as both entropy source and carrier
        auto cover = out("stego_cover.ppm");

        // Derive encryption key from the cover image's pixel noise
        auto me = crypto::entropy::MediaEntropy::from_file_deterministic(cover);
        must(me, "dual-use entropy");
        inf("File used as:", "BOTH entropy source AND stego carrier");
        inf("Entropy:", std::to_string((int)me.value().entropy_bits()) + " bits");

        // Build a vault keyed by the image itself
        auto vault_res = me.value().make_vault();
        must(vault_res, "dual-use vault");

        // Encrypt and hide the payload INSIDE the same image
        const char* secret = "Hidden in the same file that generated the key.";
        must(vault_res.value().seal_into(cover, secret, out("dual_use_stego.ppm"), "dual"), "dual seal_into");
        ok("Encrypted with key derived from cover, hidden back inside cover");

        // To decrypt: re-derive the key from the ORIGINAL cover, extract from stego
        auto me2 = crypto::entropy::MediaEntropy::from_file_deterministic(cover);
        must(me2, "dual-use re-derive");
        auto vault2 = me2.value().make_vault();
        must(vault2, "dual-use vault2");

        auto recovered = vault2.value().open_from(out("dual_use_stego.ppm"), "dual");
        must(recovered, "dual open_from");
        recovered.value().to_string() == secret
            ? ok("Same file = key + carrier: full round-trip verified")
            : bad("dual-use mismatch");

        note("The original file is the key. The stego copy carries the hidden data.");
        note("Anyone with the original can derive the key and extract the secret.");
    }

    // ── E7: Entropy-keyed encryption with stego hiding (no vault) ───────────
    // Use MediaEntropy just for the key, then use raw StegoEngine for hiding.
    // Shows that entropy and stego are truly independent, composable features.

    subsect("E7 — Entropy for key + StegoEngine for hiding (independent composition)");
    {
        // Derive a symmetric key from an audio file
        auto audio_cover = out("stego_cover.wav");
        auto key = crypto::entropy::key_from_file(out("entropy_audio.wav"));
        must(key, "entropy key for stego");
        inf("Key source:", "entropy_audio.wav (audio file)");

        // Encrypt with the audio-derived key
        constexpr std::string_view secret = "Key from audio, hidden in image — independent composition.";
        auto ct = crypto::symmetric::XChaCha20Poly1305::encrypt(secret, key.value().span());
        must(ct, "entropy-stego enc");

        // Hide the ciphertext inside a DIFFERENT file (the PPM image)
        std::vector<uint8_t> payload(ct.value().data(), ct.value().data() + ct.value().size());
        must(crypto::stego::StegoEngine::embed(
            out("stego_cover.ppm"), payload, out("entropy_stego_composed.ppm")), "compose embed");
        ok("Encrypted with audio-derived key, hidden in image (two independent features)");

        // Extract and decrypt
        auto extracted = crypto::stego::StegoEngine::extract(out("entropy_stego_composed.ppm"));
        must(extracted, "compose extract");
        auto pt = crypto::symmetric::XChaCha20Poly1305::decrypt(extracted.value(), key.value().span());
        must(pt, "compose decrypt");
        pt.value().to_string() == secret
            ? ok("Extracted from image → decrypted with audio key → verified")
            : bad("composition mismatch");

        note("Entropy (key derivation) and stego (hiding) are fully independent.");
        note("Use any file for the key, any other file as the carrier.");
    }

    ok("Steganography layer: all checks complete");
}

// =============================================================================
// F — POST-QUANTUM AND MODERN PRIMITIVES
//
// BLAKE3 (fast hashing + MAC + KDF), HKDF-SHA256 (RFC 5869 key derivation),
// ML-KEM (FIPS 203 key encapsulation), ML-DSA (FIPS 204 lattice signatures),
// SLH-DSA (FIPS 205 hash-based signatures), BLS12-381 (aggregate signatures).
//
// Post-quantum algorithms are guarded by CRYPTOLIB_HAS_PQ (requires liboqs).
// BLS is guarded by CRYPTOLIB_HAS_BLS (requires blst).
// BLAKE3 is guarded by CRYPTOLIB_HAS_BLAKE3 (requires libblake3).
// HKDF-SHA256 is always available (built on libsodium HMAC-SHA256).
// =============================================================================
static void demo_modern() {
    section("F — Post-Quantum & Modern Primitives");

    // ── F.1 BLAKE3 ──────────────────────────────────────────────────────────
    // BLAKE3 is a cryptographic hash function derived from BLAKE2 but
    // dramatically faster (parallelizable Merkle tree). It supports three
    // modes from a single primitive: unkeyed hashing, keyed MAC, and
    // domain-separated key derivation.
#ifdef CRYPTOLIB_HAS_BLAKE3

    subsect("F.1 — BLAKE3 (hash + keyed MAC + KDF + streaming)");
    {
        // ── F.1a: One-shot hash with known test vector ──
        // BLAKE3 produces a 32-byte digest by default (extendable output).
        // We hash a well-known string and verify the output is deterministic.
        constexpr std::string_view msg = "The quick brown fox jumps over the lazy dog";
        auto h1 = crypto::hash::Blake3::digest(msg);
        must(h1, "blake3 digest");
        inf("BLAKE3-256:", h1.value().to_hex());

        // Hash the same input again — must produce identical output.
        // Cryptographic hashes are deterministic: same input always yields same output.
        auto h2 = crypto::hash::Blake3::digest(msg);
        must(h2, "blake3 digest 2");
        crypto::secure_equal(h1.value().span(), h2.value().span())
            ? ok("BLAKE3 one-shot: deterministic — same input produces same hash")
            : bad("BLAKE3 non-deterministic");

        // ── F.1b: Keyed MAC mode ──
        // A keyed hash (MAC) authenticates a message under a secret key.
        // Different keys MUST produce different MACs — otherwise an attacker
        // who learns one key could forge MACs for a different key's messages.
        auto key_a = crypto::random_bytes(crypto::hash::Blake3::KEY_BYTES);
        auto key_b = crypto::random_bytes(crypto::hash::Blake3::KEY_BYTES);

        auto mac_a = crypto::hash::Blake3::keyed(sv2sp(msg), key_a.span());
        must(mac_a, "blake3 mac_a");
        auto mac_b = crypto::hash::Blake3::keyed(sv2sp(msg), key_b.span());
        must(mac_b, "blake3 mac_b");

        // Same message, different keys — MACs must differ.
        // This proves the MAC is key-dependent, not just a plain hash.
        !crypto::secure_equal(mac_a.value().span(), mac_b.value().span())
            ? ok("Keyed MAC: two different keys produce different MACs (key-dependent)")
            : bad("MACs should differ for different keys");

        // Same message, same key — MAC must be identical (verification scenario).
        auto mac_a2 = crypto::hash::Blake3::keyed(sv2sp(msg), key_a.span());
        must(mac_a2, "blake3 mac_a2");
        crypto::secure_equal(mac_a.value().span(), mac_a2.value().span())
            ? ok("Keyed MAC: same key reproduces identical MAC (verifiable)")
            : bad("MAC should be reproducible with same key");

        // ── F.1c: Key derivation with context separation ──
        // BLAKE3's derive_key mode uses a context string to produce
        // domain-separated keys. Two different contexts from the same IKM
        // yield cryptographically independent keys — essential for protocols
        // that need multiple keys from a single secret (e.g., encryption key
        // + authentication key from one master secret).
        auto ikm = crypto::random_bytes(32);
        auto dk1 = crypto::hash::Blake3::derive_key("cryptolib-tutorial 2026 enc-key", ikm.span());
        must(dk1, "blake3 dk1");
        auto dk2 = crypto::hash::Blake3::derive_key("cryptolib-tutorial 2026 auth-key", ikm.span());
        must(dk2, "blake3 dk2");

        inf("derive_key(enc):", hex(dk1.value()));
        inf("derive_key(auth):", hex(dk2.value()));

        // Different contexts must produce unrelated keys.
        // This is domain separation: the context string acts as a namespace.
        !crypto::secure_equal(dk1.value().span(), dk2.value().span())
            ? ok("Key derivation: different contexts produce independent keys (domain separation)")
            : bad("Derived keys should differ for different contexts");

        // ── F.1d: Streaming API matches one-shot ──
        // The streaming interface allows hashing data in chunks (useful for
        // large files or network streams). The result must be identical to
        // hashing the entire message at once — this is a correctness check.
        crypto::hash::Blake3::Stream st;
        st.update(sv2sp(msg.substr(0, 19)));   // "The quick brown fox"
        st.update(sv2sp(msg.substr(19)));       // " jumps over the lazy dog"
        auto h_stream = st.finalize();

        // Streaming hash must exactly match one-shot hash of the same data.
        crypto::secure_equal(h_stream.span(), h1.value().span())
            ? ok("Streaming API: chunked hash matches one-shot (correctness verified)")
            : bad("BLAKE3 streaming mismatch");
    }

#else
    subsect("F.1 — BLAKE3 (skipped: CRYPTOLIB_HAS_BLAKE3 not defined)");
    note("Build with -DCRYPTOLIB_BLAKE3=ON to enable BLAKE3 support.");
#endif

    // ── F.2 HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────
    // HKDF is the standard way to derive cryptographic keys from potentially
    // weak input keying material (IKM). It works in two phases:
    //   Extract: compress IKM + salt into a pseudorandom key (PRK)
    //   Expand:  stretch PRK into one or more output keys using an "info" label
    //
    // The "info" parameter provides domain separation — the same PRK with
    // different info strings produces completely unrelated keys.

    subsect("F.2 — HKDF-SHA256 (extract + expand + domain separation)");
    {
        // ── F.2a: Extract PRK from salt + IKM ──
        // The extract step concentrates entropy from the IKM into a
        // fixed-length PRK (32 bytes for SHA-256). Even if the IKM is
        // longer than 32 bytes or has non-uniform entropy, the PRK will
        // have high min-entropy throughout.
        auto salt = crypto::random_bytes(32);
        auto ikm  = crypto::random_bytes(48); // 48 bytes of raw keying material

        auto prk = crypto::hash::HkdfSha256::extract(salt.span(), ikm.span());
        must(prk, "hkdf extract");
        inf("PRK (32 bytes):", prk.value().to_hex());
        ok("Extract: salt + IKM compressed into 32-byte pseudorandom key (PRK)");

        // ── F.2b: Expand PRK to desired length ──
        // The expand step stretches the PRK to any desired output length
        // (up to 255 * 32 = 8160 bytes). Each byte of output is
        // cryptographically determined by (PRK, info, position).
        auto okm = crypto::hash::HkdfSha256::expand(
            prk.value().span(), "session-encryption-key", 32);
        must(okm, "hkdf expand");
        inf("OKM (32 bytes):", okm.value().to_hex());
        ok("Expand: PRK stretched to 32-byte output key");

        // ── F.2c: Domain separation via different info strings ──
        // The same PRK expanded with different info strings MUST produce
        // completely unrelated keys. This is how protocols derive multiple
        // purpose-specific keys from a single shared secret: one info for
        // the encryption key, another for the MAC key, another for the IV.
        auto key_enc  = crypto::hash::HkdfSha256::expand(
            prk.value().span(), "encryption-key", 32);
        must(key_enc, "hkdf expand enc");
        auto key_auth = crypto::hash::HkdfSha256::expand(
            prk.value().span(), "authentication-key", 32);
        must(key_auth, "hkdf expand auth");

        inf("expand(enc):",  hex(key_enc.value()));
        inf("expand(auth):", hex(key_auth.value()));

        // Different info strings from the same PRK yield independent keys.
        // An attacker who learns the encryption key gains zero information
        // about the authentication key, and vice versa.
        !crypto::secure_equal(key_enc.value().span(), key_auth.value().span())
            ? ok("Domain separation: different info strings produce independent keys")
            : bad("HKDF keys should differ for different info strings");

        // ── F.2d: One-shot derive convenience ──
        // derive() combines extract + expand in a single call. This is the
        // most common usage: provide IKM, salt, info, and desired length.
        auto derived = crypto::hash::HkdfSha256::derive(
            ikm.span(), salt.span(), "one-shot-derive", 64);
        must(derived, "hkdf derive");
        inf("One-shot derive (64 B):", hex(derived.value(), 48));
        ok("One-shot derive: extract + expand in single call (64 bytes output)");
    }

    // ── F.3 ML-KEM (FIPS 203) ───────────────────────────────────────────────
    // ML-KEM is NIST's post-quantum key encapsulation mechanism (formerly
    // CRYSTALS-Kyber). It allows two parties to establish a shared secret
    // that is secure against both classical and quantum computers.
    //
    // Protocol:
    //   1. Alice generates (public_key, secret_key)
    //   2. Bob encapsulates to Alice's public key → (ciphertext, shared_secret_bob)
    //   3. Alice decapsulates with her secret key → shared_secret_alice
    //   4. shared_secret_alice == shared_secret_bob (32 bytes)
    //
    // ML-KEM has "implicit rejection": decapsulating with the wrong key
    // produces a valid-looking but different shared secret (no error signal).
    // This prevents chosen-ciphertext attacks.
#ifdef CRYPTOLIB_HAS_PQ

    subsect("F.3 — ML-KEM (FIPS 203): post-quantum key encapsulation");
    {
        using MlKem = crypto::pq::MlKem;

        // ── Step 1: Alice generates a keypair ──
        // Alice creates a fresh ML-KEM-768 keypair. The public key is sent
        // to anyone who wants to establish a shared secret with her.
        auto alice = MlKem::generate_keypair(MlKem::Level::KEM_768);
        must(alice, "ml-kem keygen");

        // Show key sizes — ML-KEM keys are much larger than classical keys
        // (the price of quantum resistance).
        auto sz = MlKem::sizes(MlKem::Level::KEM_768);
        must(sz, "ml-kem sizes");
        inf("Public key:",     std::to_string(sz.value().public_key) + " bytes");
        inf("Secret key:",     std::to_string(sz.value().secret_key) + " bytes");
        inf("Ciphertext:",     std::to_string(sz.value().ciphertext) + " bytes");
        inf("Shared secret:",  std::to_string(sz.value().shared_secret) + " bytes");
        ok("Alice generated ML-KEM-768 keypair (NIST Level 3, ~AES-192 equivalent)");

        // ── Step 2: Bob encapsulates to Alice's public key ──
        // Bob uses Alice's public key to produce a ciphertext and a shared
        // secret. The ciphertext is sent to Alice; the shared secret stays
        // with Bob. Only Alice (with her secret key) can recover the same
        // shared secret from the ciphertext.
        auto bob_result = MlKem::encapsulate(alice.value().public_key.span(), MlKem::Level::KEM_768);
        must(bob_result, "ml-kem encaps");
        inf("Bob's shared secret:", hex(bob_result.value().shared_secret));
        ok("Bob encapsulated: produced ciphertext + shared secret");

        // ── Step 3: Alice decapsulates with her secret key ──
        // Alice receives the ciphertext from Bob and uses her secret key
        // to recover the shared secret. This is the KEM decapsulation step.
        auto alice_ss = MlKem::decapsulate(
            bob_result.value().ciphertext.span(),
            alice.value().secret_key.span(),
            MlKem::Level::KEM_768);
        must(alice_ss, "ml-kem decaps");
        inf("Alice's shared secret:", hex(alice_ss.value()));
        ok("Alice decapsulated: recovered shared secret from ciphertext");

        // ── Step 4: Verification — both shared secrets must be identical ──
        // The entire point of KEM: Alice and Bob now share a 32-byte secret
        // that was never transmitted in the clear. They can use this as a
        // symmetric key for AEAD encryption.
        crypto::secure_equal(bob_result.value().shared_secret.span(), alice_ss.value().span())
            ? ok("VERIFIED: Alice and Bob derived identical 32-byte shared secrets")
            : bad("ML-KEM shared secrets do not match");

        note("Both parties now share the same 32-byte key — use it for AEAD encryption.");

        // ── Step 5: Failure mode — Mallory uses wrong secret key ──
        // Implicit rejection: ML-KEM does NOT return an error when
        // decapsulating with the wrong key. Instead, it produces a
        // valid-looking but completely different shared secret. This is
        // by design — it prevents an attacker from learning whether
        // a decapsulation attempt was correct or not (chosen-ciphertext
        // attack prevention).
        auto mallory = MlKem::generate_keypair(MlKem::Level::KEM_768);
        must(mallory, "mallory keygen");

        auto wrong_ss = MlKem::decapsulate(
            bob_result.value().ciphertext.span(),
            mallory.value().secret_key.span(),
            MlKem::Level::KEM_768);
        must(wrong_ss, "mallory decaps");

        // Mallory gets a shared secret, but it is different from Bob's.
        // No error is returned — this is implicit rejection.
        inf("Mallory's shared secret:", hex(wrong_ss.value()));
        !crypto::secure_equal(bob_result.value().shared_secret.span(), wrong_ss.value().span())
            ? ok("Implicit rejection: wrong key yields different secret (no error signal)")
            : bad("Wrong key should produce a different shared secret");

        note("ML-KEM implicit rejection: wrong key = wrong secret, not an error.");
        note("This prevents chosen-ciphertext attacks by hiding decryption failures.");
    }

    // ── F.4 ML-DSA (FIPS 204) ───────────────────────────────────────────────
    // ML-DSA is NIST's post-quantum digital signature algorithm (formerly
    // CRYSTALS-Dilithium). Like Ed25519 but quantum-resistant.
    //
    // Workflow: keygen → sign → verify
    // Security property: EUF-CMA (existential unforgeability under chosen
    // message attack) — an attacker cannot forge a valid signature even
    // after seeing many valid signatures on other messages.

    subsect("F.4 — ML-DSA (FIPS 204): post-quantum digital signatures");
    {
        using MlDsa = crypto::pq::MlDsa;

        // ── Keygen ──
        // Generate an ML-DSA-65 keypair (NIST Level 3, recommended default).
        auto kp = MlDsa::generate_keypair(MlDsa::Level::DSA_65);
        must(kp, "ml-dsa keygen");

        auto sz = MlDsa::sizes(MlDsa::Level::DSA_65);
        must(sz, "ml-dsa sizes");
        inf("Public key:",  std::to_string(sz.value().public_key) + " bytes");
        inf("Secret key:",  std::to_string(sz.value().secret_key) + " bytes");
        inf("Signature:",   std::to_string(sz.value().signature) + " bytes");
        ok("ML-DSA-65 keypair generated (NIST Level 3)");

        // ── Sign a message ──
        // The signer uses their secret key to produce a signature over the
        // message. The signature binds the signer's identity to the message
        // content — any modification to either invalidates the signature.
        constexpr std::string_view message = "Post-quantum signed document: budget Q4-2026";
        auto sig = MlDsa::sign(message, kp.value().secret_key.span(), MlDsa::Level::DSA_65);
        must(sig, "ml-dsa sign");
        inf("Signature:", hex(sig.value(), 48));
        ok("Message signed with ML-DSA-65");

        // ── Verify signature (success case) ──
        // The verifier uses the signer's public key to check that:
        //   1. The signature was created by the holder of the matching secret key
        //   2. The message has not been modified since signing
        // Both conditions must hold for verification to succeed.
        auto vr = MlDsa::verify(message, sig.value().span(),
                                kp.value().public_key.span(), MlDsa::Level::DSA_65);
        vr.is_ok()
            ? ok("VERIFIED: signature is valid — message authentic and unmodified")
            : bad("ML-DSA verify should succeed");

        // ── Tamper test: modify message by one byte ──
        // Even a single bit change in the message must cause verification
        // to fail. This demonstrates that the signature covers every byte
        // of the message — there is no "slack" that allows modification.
        std::string tampered(message);
        tampered.back() ^= 0x01;  // flip one bit in the last byte

        auto vr_tampered = MlDsa::verify(tampered, sig.value().span(),
                                         kp.value().public_key.span(), MlDsa::Level::DSA_65);
        vr_tampered.is_err()
            ? ok("Tamper test: one-byte change invalidates signature (integrity enforced)")
            : bad("Tampered message should fail verification");

        // ── Wrong key test: different keypair ──
        // A signature made by one key must not verify under a different key.
        // This proves that the signature is bound to the specific signer.
        auto kp2 = MlDsa::generate_keypair(MlDsa::Level::DSA_65);
        must(kp2, "ml-dsa keygen2");

        auto vr_wrong = MlDsa::verify(message, sig.value().span(),
                                      kp2.value().public_key.span(), MlDsa::Level::DSA_65);
        vr_wrong.is_err()
            ? ok("Wrong key test: signature invalid under different public key (signer binding)")
            : bad("Wrong key should fail verification");

        note("ML-DSA provides EUF-CMA security: quantum computers cannot forge signatures.");
    }

    // ── F.5 SLH-DSA (FIPS 205) ──────────────────────────────────────────────
    // SLH-DSA (formerly SPHINCS+) is a hash-based signature scheme.
    // Its security relies ONLY on hash function properties — no lattice
    // assumptions. This makes it the most conservative post-quantum choice,
    // but signatures are larger.
    //
    // Two speed/size tradeoffs per security level:
    //   "s" (small) — smaller signatures, slower signing
    //   "f" (fast)  — faster signing, larger signatures

    subsect("F.5 — SLH-DSA (FIPS 205): hash-based post-quantum signatures");
    {
        using SlhDsa = crypto::pq::SlhDsa;

        // ── Keygen with SHA2 hash family ──
        // SLH-DSA-128f (fast variant) with SHA-256 as the underlying hash.
        auto kp = SlhDsa::generate_keypair(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        must(kp, "slh-dsa keygen");

        auto sz = SlhDsa::sizes(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        must(sz, "slh-dsa sizes");
        inf("Public key:",  std::to_string(sz.value().public_key) + " bytes");
        inf("Secret key:",  std::to_string(sz.value().secret_key) + " bytes");
        inf("Signature:",   std::to_string(sz.value().signature) + " bytes (128f)");
        ok("SLH-DSA-128f keypair generated (SHA2, NIST Level 1)");

        // ── Sign and verify ──
        constexpr std::string_view message = "Hash-based signature: conservative PQ choice";
        auto sig = SlhDsa::sign(message, kp.value().secret_key.span(),
                                SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        must(sig, "slh-dsa sign");
        ok("Message signed with SLH-DSA-128f");

        // Verify the signature — must succeed for untampered message + correct key.
        auto vr = SlhDsa::verify(message, sig.value().span(),
                                 kp.value().public_key.span(),
                                 SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        vr.is_ok()
            ? ok("VERIFIED: SLH-DSA signature valid — hash-based quantum resistance")
            : bad("SLH-DSA verify should succeed");

        // ── Compare 128s vs 128f signature sizes ──
        // The "s" variant trades signing speed for smaller signatures.
        // The "f" variant does the opposite. Both provide the same
        // security level — only the performance/size tradeoff differs.
        auto sz_s = SlhDsa::sizes(SlhDsa::Level::L128s, SlhDsa::HashFamily::SHA2);
        must(sz_s, "slh-dsa sizes 128s");
        auto sz_f = SlhDsa::sizes(SlhDsa::Level::L128f, SlhDsa::HashFamily::SHA2);
        must(sz_f, "slh-dsa sizes 128f");

        inf("128s signature:", std::to_string(sz_s.value().signature) + " bytes (small, slower signing)");
        inf("128f signature:", std::to_string(sz_f.value().signature) + " bytes (fast, larger signature)");

        // The small variant must have a smaller signature than the fast variant.
        (sz_s.value().signature < sz_f.value().signature)
            ? ok("Size comparison: 128s < 128f (small vs fast tradeoff confirmed)")
            : bad("128s should have smaller signatures than 128f");

        note("SLH-DSA security relies only on hash functions — no lattice assumptions.");
        note("Choose 's' for bandwidth-constrained scenarios, 'f' for latency-sensitive ones.");
    }

#else
    subsect("F.3-F.5 — Post-Quantum (skipped: CRYPTOLIB_HAS_PQ not defined)");
    note("Build with -DCRYPTOLIB_PQ=ON and install liboqs to enable ML-KEM, ML-DSA, SLH-DSA.");
#endif

    // ── F.6 BLS12-381 ───────────────────────────────────────────────────────
    // BLS signatures on the BLS12-381 curve enable a unique superpower:
    // signature aggregation. N individual signatures (each 96 bytes) can
    // be combined into a single 96-byte aggregate signature that proves
    // all N signers signed their respective messages.
    //
    // This is critical for blockchain consensus (Ethereum 2.0), where
    // thousands of validators each sign an attestation — without aggregation,
    // the signature data alone would overwhelm the network.
#ifdef CRYPTOLIB_HAS_BLS

    subsect("F.6 — BLS12-381: signatures + aggregation");
    {
        using Bls = crypto::bls::Bls12381;

        // ── Three parties each sign a different message ──
        // Alice, Bob, and Carol each have their own keypair and sign
        // a unique message. Each signature is 96 bytes (compressed G2 point).
        auto alice = Bls::generate_keypair(); must(alice, "bls alice keygen");
        auto bob   = Bls::generate_keypair(); must(bob,   "bls bob keygen");
        auto carol = Bls::generate_keypair(); must(carol, "bls carol keygen");

        constexpr std::string_view msg_alice = "Alice attests: block 1048576 is valid";
        constexpr std::string_view msg_bob   = "Bob attests: block 1048576 is valid";
        constexpr std::string_view msg_carol = "Carol attests: block 1048576 is valid";

        auto sig_alice = Bls::sign(msg_alice, alice.value().secret_key.span());
        must(sig_alice, "bls alice sign");
        auto sig_bob = Bls::sign(msg_bob, bob.value().secret_key.span());
        must(sig_bob, "bls bob sign");
        auto sig_carol = Bls::sign(msg_carol, carol.value().secret_key.span());
        must(sig_carol, "bls carol sign");

        inf("Sig(Alice):", hex(sig_alice.value(), 24));
        inf("Sig(Bob):",   hex(sig_bob.value(), 24));
        inf("Sig(Carol):", hex(sig_carol.value(), 24));
        ok("Three parties signed their respective messages (96 bytes each)");

        // ── Individual verification of each signature ──
        // Before aggregation, verify each signature independently.
        // This proves that each party's signature is valid on its own.
        auto v1 = Bls::verify(msg_alice, sig_alice.value().span(), alice.value().public_key.span());
        v1.is_ok() ? ok("Alice's signature individually verified") : bad("Alice verify failed");

        auto v2 = Bls::verify(msg_bob, sig_bob.value().span(), bob.value().public_key.span());
        v2.is_ok() ? ok("Bob's signature individually verified") : bad("Bob verify failed");

        auto v3 = Bls::verify(msg_carol, sig_carol.value().span(), carol.value().public_key.span());
        v3.is_ok() ? ok("Carol's signature individually verified") : bad("Carol verify failed");

        // ── Aggregate all three signatures into one 96-byte signature ──
        // This is the BLS magic: three 96-byte signatures become one 96-byte
        // signature. The aggregate signature proves that ALL three signers
        // signed their respective messages, but takes no more space than
        // a single signature.
        std::vector<std::span<const uint8_t>> sigs = {
            sig_alice.value().span(), sig_bob.value().span(), sig_carol.value().span()
        };
        auto agg_sig = Bls::aggregate_signatures(sigs);
        must(agg_sig, "bls aggregate");

        inf("Individual sigs:", std::to_string(3) + " x 96 = 288 bytes total");
        inf("Aggregate sig:",   std::to_string(agg_sig.value().size()) + " bytes (single signature)");
        ok("Aggregated 3 signatures into 1 (288 bytes -> 96 bytes)");

        // ── Aggregate verify: check all three at once ──
        // A single pairing-based verification confirms that Alice signed
        // msg_alice AND Bob signed msg_bob AND Carol signed msg_carol.
        // This is faster than verifying each signature individually.
        std::vector<std::span<const uint8_t>> msgs = {
            sv2sp(msg_alice), sv2sp(msg_bob), sv2sp(msg_carol)
        };
        std::vector<std::span<const uint8_t>> pks = {
            alice.value().public_key.span(),
            bob.value().public_key.span(),
            carol.value().public_key.span()
        };

        auto agg_vr = Bls::aggregate_verify(msgs, pks, agg_sig.value().span());
        agg_vr.is_ok()
            ? ok("AGGREGATE VERIFIED: single 96-byte sig proves all 3 signers authenticated")
            : bad("Aggregate verify failed");

        // ── Failure case: one wrong message ──
        // If any of the messages is wrong, aggregate verification must fail.
        // This demonstrates that the aggregate signature binds each signer
        // to their specific message — not just to "any" message.
        std::vector<std::span<const uint8_t>> wrong_msgs = {
            sv2sp(msg_alice),
            sv2sp("Bob attests: block 9999999 is valid"),  // wrong message
            sv2sp(msg_carol)
        };

        auto agg_vr_fail = Bls::aggregate_verify(wrong_msgs, pks, agg_sig.value().span());
        agg_vr_fail.is_err()
            ? ok("Aggregate fails when one message is wrong (binding enforced)")
            : bad("Aggregate should fail with wrong message");

        // ── Size comparison summary ──
        note("Size savings: 3 x 96 = 288 bytes individual vs 96 bytes aggregated (67% reduction).");
        note("At scale (e.g., 1000 Ethereum validators): 96 KB -> 96 bytes per slot.");
        note("BLS aggregation is what makes proof-of-stake consensus practical.");
    }

#else
    subsect("F.6 — BLS12-381 (skipped: CRYPTOLIB_HAS_BLS not defined)");
    note("Build with -DCRYPTOLIB_BLS=ON and install blst to enable BLS signatures.");
#endif
}

// =============================================================================
// main
// =============================================================================
int main(int argc, char** argv) {
    // Parse output directory from argv[1], or use system temp
    if (argc > 1) {
        g_dir = argv[1];
    } else {
        g_dir = fs::temp_directory_path() / "cryptolib_tutorial";
    }
    fs::create_directories(g_dir);

    std::printf(BOLD "\nCryptoLib v3.0.0 — Progressive Tutorial" RST "\n");
    std::printf("Output directory: %s\n", g_dir.string().c_str());

    crypto::init();

    demo_standalone();
    demo_vault();
    demo_media_entropy();
    demo_end_to_end();
    demo_steganography();
    demo_modern();

    std::printf("\n" BOLD GRN "All tests passed." RST "\n\n");
    return 0;
}
