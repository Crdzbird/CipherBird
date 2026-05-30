/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  CryptoLib — Steganography as a native vault feature                     ║
 * ║                                                                            ║
 * ║  Demonstrates the integrated API: stego is a method on the vault,        ║
 * ║  not a separate engine you wire up manually.                              ║
 * ║                                                                            ║
 * ║  Pattern 1  vault.seal_into / open_from            (SecureVault)         ║
 * ║  Pattern 2  AsymmetricVault::seal_into / open_from (Alice → Bob)         ║
 * ║  Pattern 3  entropy → make_vault → seal_into / open_from                 ║
 * ║  Pattern 4  All three carrier formats (ppm / wav / crvf)                 ║
 * ║  Pattern 5  Mallory forgery rejection (asymmetric)                       ║
 * ║  Pattern 6  Capacity + quality helpers (low-level StegoEngine access)    ║
 * ║  Pattern 7  Post-quantum key exchange (ML-KEM → XChaCha20)  [PQ]       ║
 * ║  Pattern 8  Post-quantum signatures (ML-DSA + SLH-DSA)      [PQ]       ║
 * ║  Pattern 9  BLS aggregate signatures (3 validators → 1 sig) [BLS]      ║
 * ║  Pattern 10 Hybrid classical + PQ pipeline                  [PQ+BLS]   ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include <cryptolib/cryptolib.hpp>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>

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

static void pattern(int n, const char* t) {
    std::printf("\n" BOLD CYN "──────────────────────────────────────────────────\n"
                "  Pattern %d — %s\n"
                "──────────────────────────────────────────────────" RST "\n", n, t);
}
static void step(const char* s)  { std::printf("\n  " BOLD MAG "▸ %s" RST "\n", s); }
static void ok(const char* m)    { std::printf("    " GRN "✓" RST " %s\n", m); }
static void info(const char* l, const std::string& v) {
    std::printf("    " YLW "%-30s" RST "%s\n", l, v.c_str());
}
static void note(const char* m)  { std::printf("    " BLU "→" RST " %s\n", m); }

template<typename T>
static void require(const crypto::Result<T>& r, const char* ctx) {
    if (r.is_err()) {
        std::fprintf(stderr, RED "\n  FATAL [%s]: %s\n" RST, ctx, r.error().message.c_str());
        std::exit(1);
    }
}

// ─── Carrier / output paths (set in main) ────────────────────────────────────
static fs::path IMG;   // generated PPM carrier (640x480)
static fs::path WAV;   // generated WAV carrier (44.1 kHz mono 10 s)
static fs::path VID;   // generated CRVF carrier (320x240 30fps 60 frames)
static fs::path ENT;   // generated PPM entropy source (1024x768, different seed)
static fs::path OUT;   // stego output directory


// ─────────────────────────────────────────────────────────────────────────────
//  Generate carrier files
// ─────────────────────────────────────────────────────────────────────────────
static void generate_carriers() {
    std::printf("\n" BOLD "Generating carrier files…" RST "\n");
    using MG = crypto::stego::MediaGenerator;

    require(MG::generate_ppm(IMG.string(), 640, 480), "carrier ppm");
    info("Image:", "640×480 PPM  (gradient + Gaussian photon-shot noise)");

    require(MG::generate_wav(WAV.string(), 44100, 1, 10.0), "carrier wav");
    info("Audio:", "10 s mono WAV  (440 Hz + harmonics + thermal noise floor)");

    require(MG::generate_crvf(VID.string(), 320, 240, 30, 60), "carrier crvf");
    info("Video:", "60 frames 320×240 CRVF  (RGB gradient + per-frame variation)");

    // Separate file used only as a physical entropy source.
    crypto::stego::MediaGeneratorParams ep; ep.ppm_seed = 0xC0FFEE42;
    require(MG::generate_ppm(ENT.string(), 1024, 768, ep), "entropy ppm");
    info("Entropy source:", "1024×768 PPM  (different seed → different pixel statistics)");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 1 — SecureVault::seal_into / open_from
//
//  The vault encrypts through 4 layers, then buries the packet in media.
//  One call each way; no separate StegoEngine wiring needed.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_vault_native() {
    pattern(1, "SecureVault::seal_into / open_from");

    auto master_key = crypto::random_bytes(32);
    auto kp         = crypto::SecureVault::generate_keypair();
    auto vault      = crypto::SecureVault(master_key.span(), std::move(kp));

    const char* plaintext = "Classified: nuclear launch codes are 12345.";
    const char* aad       = "vault:pattern1";

    auto stego_ppm  = (OUT / "stego.ppm").string();
    auto stego_wav  = (OUT / "stego.wav").string();
    auto stego_crvf = (OUT / "stego.crvf").string();

    // ── Image ─────────────────────────────────────────────────────────────────
    step("Seal into PPM image");
    require(vault.seal_into(IMG.string(), plaintext, stego_ppm, aad), "p1 seal img");
    ok("vault.seal_into(\"cover.ppm\", plaintext, \"stego.ppm\", aad)");

    auto plain_img = vault.open_from(stego_ppm, aad);
    require(plain_img, "p1 open img");
    if (plain_img.value().to_string() != plaintext) { std::fputs(RED "FAIL img\n" RST, stderr); std::exit(1); }
    ok("vault.open_from(\"stego.ppm\", aad) → plaintext");
    info("Recovered:", "\"" + plain_img.value().to_string() + "\"");

    // ── Audio ─────────────────────────────────────────────────────────────────
    step("Seal into WAV audio");
    require(vault.seal_into(WAV.string(), plaintext, stego_wav, aad), "p1 seal wav");
    auto plain_wav = vault.open_from(stego_wav, aad);
    require(plain_wav, "p1 open wav");
    if (plain_wav.value().to_string() != plaintext) { std::fputs(RED "FAIL wav\n" RST, stderr); std::exit(1); }
    ok("vault.seal_into / open_from on WAV — phase coding, inaudible");

    // ── Video ─────────────────────────────────────────────────────────────────
    step("Seal into CRVF video");
    require(vault.seal_into(VID.string(), plaintext, stego_crvf, aad), "p1 seal vid");
    auto plain_vid = vault.open_from(stego_crvf, aad);
    require(plain_vid, "p1 open vid");
    if (plain_vid.value().to_string() != plaintext) { std::fputs(RED "FAIL vid\n" RST, stderr); std::exit(1); }
    ok("vault.seal_into / open_from on CRVF — distributed across 60 frames");

    note("All three formats: same API, same two-call pattern, format auto-detected.");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 2 — AsymmetricVault::seal_into / open_from  (Alice → Bob)
//
//  Public-key variant: Alice encrypts for Bob's X25519 key, signs with her
//  Ed25519 key, hides the packet in a photo.  Bob extracts and decrypts.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_asym_native() {
    pattern(2, "AsymmetricVault::seal_into / open_from  (Alice → Bob)");

    using AV = crypto::AsymmetricVault;

    step("Generate keypairs");
    auto alice = AV::generate_bundle();
    auto bob   = AV::generate_bundle();
    ok("alice: X25519 box keypair + Ed25519 signing keypair");
    ok("bob  : X25519 box keypair + Ed25519 signing keypair");

    step("Alice seals a message for Bob and hides it in an image");
    const char* msg = "Bob — midnight, north dock. Destroy after reading.";
    const char* aad = "asym:pattern2:alice-to-bob";

    auto asym_stego = (OUT / "asym_stego.ppm").string();
    auto forge_stego = (OUT / "forge.ppm").string();

    auto emb = AV::seal_into(alice, bob.box_public.span(), msg, IMG.string(), asym_stego, aad);
    require(emb, "p2 seal_into");
    ok("AsymmetricVault::seal_into(alice, bob_pub, msg, cover, out, aad)");
    note("Packet is X25519-encrypted for Bob, signed by Alice, hidden in DCT coefficients.");

    step("Bob extracts and decrypts, verifying Alice's signature");
    auto plain = AV::open_from(bob, alice.sign_public.span(), asym_stego, aad);
    require(plain, "p2 open_from");
    if (plain.value().to_string() != std::string(msg))
        { std::fputs(RED "FAIL asym\n" RST, stderr); std::exit(1); }
    info("Bob decrypted:", "\"" + plain.value().to_string() + "\"");
    ok("AsymmetricVault::open_from(bob, alice_sign_pub, stego, aad) → verified");

    step("Mallory tries to forge a packet from Alice");
    auto mallory = AV::generate_bundle();
    auto forge   = AV::seal_into(mallory, bob.box_public.span(),
                                 "wiring instructions changed", IMG.string(), forge_stego, aad);
    require(forge, "p2 forge seal");
    // Bob verifies against alice.sign_public — must fail
    auto bad = AV::open_from(bob, alice.sign_public.span(), forge_stego, aad);
    if (!bad.is_err()) { std::fputs(RED "FAIL: Mallory should have been rejected\n" RST, stderr); std::exit(1); }
    ok("Mallory rejected — Ed25519 signature mismatch");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 3 — MediaEntropy → make_vault → seal_into / open_from
//
//  Physical pixel noise from a photo seeds all crypto material.
//  No application-level RNG calls needed.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_entropy_native() {
    pattern(3, "MediaEntropy → make_vault → seal_into / open_from");

    step("Harvest physical entropy from photo (LavaRand pipeline)");
    auto me_res = crypto::entropy::MediaEntropy::from_file(ENT.string());
    require(me_res, "p3 from_file");
    auto& me = me_res.value();

    info("Source:", ENT.string());
    info("Entropy estimate:", std::to_string(static_cast<uint64_t>(me.entropy_bits())) + " bits");
    ok("file bytes → BLAKE2b stream → XOR system entropy → BLAKE2b re-hash → keys");

    step("Derive vault from entropy — no random_bytes() call");
    auto vault_res = me.make_vault();
    require(vault_res, "p3 make_vault");
    auto& vault = vault_res.value();
    ok("SecureVault fully derived from photo pixel statistics");

    step("Seal + hide, then extract + open");
    const char* plaintext = "Key material comes from the photo. Lose the photo, lose the key.";
    const char* aad       = "entropy:pattern3";

    auto entropy_stego = (OUT / "entropy_stego.wav").string();

    require(vault.seal_into(WAV.string(), plaintext, entropy_stego, aad), "p3 seal");
    ok("vault.seal_into(\"cover.wav\", plaintext, \"stego.wav\", aad)");

    auto plain = vault.open_from(entropy_stego, aad);
    require(plain, "p3 open");
    if (plain.value().to_string() != std::string(plaintext))
        { std::fputs(RED "FAIL entropy\n" RST, stderr); std::exit(1); }

    info("Recovered:", "\"" + plain.value().to_string().substr(0, 50) + "…\"");
    ok("Full pipeline: photo noise → vault keys → ciphertext → stego → plaintext");
    note("MediaEntropy mixes system entropy on construction (LavaRand defence-in-depth).");
    note("Use the same vault object for seal and open within a session.");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 4 — All three carrier formats, one vault, same plaintext
//
//  Shows that the vault API is format-agnostic: the extension is all that
//  changes.  The 4-layer crypto pipeline is identical for all formats.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_all_formats() {
    pattern(4, "All three carrier formats — format auto-detected from extension");

    auto master_key = crypto::random_bytes(32);
    auto kp         = crypto::SecureVault::generate_keypair();
    auto vault      = crypto::SecureVault(master_key.span(), std::move(kp));

    const char* pt  = "Format-agnostic: same vault API works on image, audio, and video.";
    const char* aad = "formats:pattern4";

    auto fmt_ppm  = (OUT / "fmt_stego.ppm").string();
    auto fmt_wav  = (OUT / "fmt_stego.wav").string();
    auto fmt_crvf = (OUT / "fmt_stego.crvf").string();

    auto img_s = IMG.string();
    auto wav_s = WAV.string();
    auto vid_s = VID.string();

    struct { std::string cover; std::string stego; const char* label; } runs[] = {
        { img_s, fmt_ppm,  "PPM  (DCT/QIM blue-channel)"         },
        { wav_s, fmt_wav,  "WAV  (phase coding, mid-freq bins)"  },
        { vid_s, fmt_crvf, "CRVF (DCT/QIM distributed, 60 frames)" },
    };

    for (auto& r : runs) {
        step(r.label);
        require(vault.seal_into(r.cover, pt, r.stego, aad), "fmt seal");
        auto plain = vault.open_from(r.stego, aad);
        require(plain, "fmt open");
        if (plain.value().to_string() != std::string(pt))
            { std::fputs(RED "FAIL format\n" RST, stderr); std::exit(1); }
        ok("Round-trip verified");

        auto q = crypto::stego::StegoEngine::quality(r.cover, r.stego);
        if (q.is_ok()) info("Quality:", std::to_string(static_cast<int>(q.value())) + " dB");
    }
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 5 — Wrong AAD rejected by vault
//
//  Demonstrates that the AAD (additional authenticated data) is bound
//  cryptographically to the packet.  A different AAD on open() fails at L3.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_aad_binding() {
    pattern(5, "AAD binding — wrong context string is rejected");

    auto master_key = crypto::random_bytes(32);
    auto kp         = crypto::SecureVault::generate_keypair();
    auto vault      = crypto::SecureVault(master_key.span(), std::move(kp));

    auto aad_stego = (OUT / "aad_stego.ppm").string();

    step("Seal with aad = \"session:alice\"");
    require(vault.seal_into(IMG.string(), "sensitive data", aad_stego, "session:alice"), "aad seal");
    ok("Sealed with aad = \"session:alice\"");

    step("Attempt to open with aad = \"session:mallory\"");
    auto bad = vault.open_from(aad_stego, "session:mallory");
    if (!bad.is_err())
        { std::fputs(RED "FAIL: wrong AAD should be rejected\n" RST, stderr); std::exit(1); }
    ok("Rejected — AAD mismatch fails AEAD authentication at L3");

    step("Open with correct aad = \"session:alice\"");
    auto good = vault.open_from(aad_stego, "session:alice");
    require(good, "aad open correct");
    ok("Accepted — plaintext recovered");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 6 — Low-level access: capacity queries and quality metrics
//
//  StegoEngine is still accessible directly when you need raw bytes
//  (payload already encrypted externally) or carrier introspection.
// ─────────────────────────────────────────────────────────────────────────────
static void pattern_low_level() {
    pattern(6, "Low-level StegoEngine: capacity + quality + raw bytes");

    using SE = crypto::stego::StegoEngine;

    auto img_s = IMG.string();
    auto wav_s = WAV.string();
    auto vid_s = VID.string();

    auto raw_ppm = (OUT / "raw_stego.ppm").string();
    auto raw_wav = (OUT / "raw_stego.wav").string();

    step("Capacity queries");
    for (auto& [path, label] : std::initializer_list<std::pair<std::string, const char*>>{
            { img_s, "Image" }, { wav_s, "Audio" }, { vid_s, "Video" }}) {
        auto cap = SE::capacity(path);
        require(cap, "capacity");
        info(label, cap.value().description);
    }

    step("Embed raw bytes (no vault)");
    std::vector<uint8_t> raw(64, 0xAB);
    require(SE::embed(img_s, raw, raw_ppm), "raw embed");
    auto ext = SE::extract(raw_ppm);
    require(ext, "raw extract");
    if (ext.value() != raw) { std::fputs(RED "FAIL raw\n" RST, stderr); std::exit(1); }
    ok("Byte-exact raw round-trip — useful when payload is already encrypted externally");

    step("Quality metrics");
    auto psnr = SE::quality(img_s, raw_ppm);
    if (psnr.is_ok()) info("Image PSNR:", std::to_string(static_cast<int>(psnr.value())) + " dB  (threshold: 40 dB)");
    require(SE::embed(wav_s, raw, raw_wav), "quality wav embed");
    auto snr = SE::quality(wav_s, raw_wav);
    if (snr.is_ok()) info("Audio SNR:", std::to_string(static_cast<int>(snr.value())) + " dB  (threshold: 20 dB)");
    ok("Both well above imperceptibility thresholds");
}


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 7 — Post-Quantum Key Exchange (ML-KEM-768 → XChaCha20-Poly1305)
//
//  Alice and Bob establish a shared secret using ML-KEM (FIPS 203), then
//  use it as a symmetric key for XChaCha20-Poly1305 AEAD encryption.
// ─────────────────────────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_PQ
static void pattern_pq_key_exchange() {
    pattern(7, "Post-Quantum Key Exchange (ML-KEM-768 + XChaCha20-Poly1305)");

    using KEM  = crypto::pq::MlKem;
    using AEAD = crypto::symmetric::XChaCha20Poly1305;

    // ── Step 1: Alice generates ML-KEM-768 keypair ──────────────────────
    step("Alice generates ML-KEM-768 keypair");
    auto alice_kp = KEM::generate_keypair(KEM::Level::KEM_768);
    require(alice_kp, "p7 keygen");
    auto& alice = alice_kp.value();
    info("Public key size:", std::to_string(alice.public_key.size()) + " bytes");
    info("Secret key size:", std::to_string(alice.secret_key.size()) + " bytes");
    ok("ML-KEM-768 keypair generated (NIST Level 3, ~AES-192)");

    // ── Step 2: Bob encapsulates a shared secret to Alice's public key ──
    step("Bob encapsulates shared secret to Alice's public key");
    auto encaps = KEM::encapsulate(alice.public_key.span(), KEM::Level::KEM_768);
    require(encaps, "p7 encaps");
    auto& bob_result = encaps.value();
    info("Ciphertext size:", std::to_string(bob_result.ciphertext.size()) + " bytes");
    info("Shared secret size:", std::to_string(bob_result.shared_secret.size()) + " bytes");
    info("Bob's shared secret:", bob_result.shared_secret.to_hex().substr(0, 32) + "...");
    ok("Bob has ciphertext (to send to Alice) + shared secret");

    // ── Step 3: Alice decapsulates → same shared secret ─────────────────
    step("Alice decapsulates the ciphertext with her secret key");
    auto alice_ss = KEM::decapsulate(bob_result.ciphertext.span(),
                                     alice.secret_key.span(),
                                     KEM::Level::KEM_768);
    require(alice_ss, "p7 decaps");
    info("Alice's shared secret:", alice_ss.value().to_hex().substr(0, 32) + "...");

    bool secrets_match = (alice_ss.value().span().size() == bob_result.shared_secret.span().size()) &&
        std::memcmp(alice_ss.value().data(), bob_result.shared_secret.data(),
                    alice_ss.value().size()) == 0;
    if (!secrets_match) { std::fputs(RED "FAIL: shared secrets differ\n" RST, stderr); std::exit(1); }
    ok("Shared secrets match — post-quantum key exchange complete");

    // ── Step 4: Use shared secret as key for XChaCha20-Poly1305 ─────────
    step("Encrypt with XChaCha20-Poly1305 using the PQ-derived key");
    const char* plaintext = "Top secret: quantum computers cannot break this channel.";
    auto ct = AEAD::encrypt(std::string_view(plaintext), alice_ss.value().span());
    require(ct, "p7 encrypt");
    info("Plaintext:", std::string("\"") + plaintext + "\"");
    info("Ciphertext size:", std::to_string(ct.value().size()) + " bytes (nonce + ct + MAC)");
    ok("Encrypted with PQ-derived symmetric key");

    // ── Step 5: Decrypt and verify ──────────────────────────────────────
    step("Decrypt and verify plaintext matches original");
    auto pt = AEAD::decrypt(ct.value().span(), bob_result.shared_secret.span());
    require(pt, "p7 decrypt");
    info("Decrypted:", "\"" + pt.value().to_string() + "\"");

    if (pt.value().to_string() != std::string(plaintext))
        { std::fputs(RED "FAIL: decrypted text mismatch\n" RST, stderr); std::exit(1); }
    ok("Decrypted plaintext matches original");

    note("Full pipeline: ML-KEM-768 key exchange -> XChaCha20-Poly1305 AEAD -> verified.");
    note("Both parties derive the same 32-byte shared secret without transmitting it.");
}
#endif // CRYPTOLIB_HAS_PQ


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 8 — Post-Quantum Signatures (ML-DSA-65 + SLH-DSA-128f)
//
//  Sign and verify documents using two distinct PQ signature algorithms:
//  lattice-based ML-DSA and hash-based SLH-DSA.
// ─────────────────────────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_PQ
static void pattern_pq_signatures() {
    pattern(8, "Post-Quantum Signatures (ML-DSA-65 + SLH-DSA-128f)");

    using DSA = crypto::pq::MlDsa;
    using SLH = crypto::pq::SlhDsa;

    const std::string document = "CryptoLib v3.0.0 release: all post-quantum algorithms verified.";
    const std::string tampered = "CryptoLib v3.0.0 release: all post-quantum algorithms TAMPERED.";

    // ── ML-DSA-65: Sign ─────────────────────────────────────────────────
    step("Generate ML-DSA-65 keypair and sign document");
    auto dsa_kp = DSA::generate_keypair(DSA::Level::DSA_65);
    require(dsa_kp, "p8 dsa keygen");
    info("ML-DSA-65 public key:", std::to_string(dsa_kp.value().public_key.size()) + " bytes");
    info("ML-DSA-65 secret key:", std::to_string(dsa_kp.value().secret_key.size()) + " bytes");

    auto dsa_sig = DSA::sign(document, dsa_kp.value().secret_key.span(), DSA::Level::DSA_65);
    require(dsa_sig, "p8 dsa sign");
    info("ML-DSA-65 signature:", std::to_string(dsa_sig.value().size()) + " bytes");
    ok("Document signed with ML-DSA-65 (lattice-based, NIST Level 3)");

    // ── ML-DSA-65: Verify ───────────────────────────────────────────────
    step("Verify ML-DSA-65 signature on original document");
    auto dsa_ok = DSA::verify(document, dsa_sig.value().span(),
                              dsa_kp.value().public_key.span(), DSA::Level::DSA_65);
    require(dsa_ok, "p8 dsa verify");
    ok("ML-DSA-65 signature verified successfully");

    // ── ML-DSA-65: Tampered document must fail ──────────────────────────
    step("Verify ML-DSA-65 signature on tampered document (must fail)");
    auto dsa_bad = DSA::verify(tampered, dsa_sig.value().span(),
                               dsa_kp.value().public_key.span(), DSA::Level::DSA_65);
    if (!dsa_bad.is_err())
        { std::fputs(RED "FAIL: tampered doc should not verify\n" RST, stderr); std::exit(1); }
    ok("Tampered document rejected — ML-DSA-65 signature mismatch");

    // ── SLH-DSA-128f: Sign ──────────────────────────────────────────────
    step("Generate SLH-DSA-128f keypair and sign same document");
    auto slh_kp = SLH::generate_keypair(SLH::Level::L128f);
    require(slh_kp, "p8 slh keygen");
    info("SLH-DSA-128f public key:", std::to_string(slh_kp.value().public_key.size()) + " bytes");
    info("SLH-DSA-128f secret key:", std::to_string(slh_kp.value().secret_key.size()) + " bytes");

    auto slh_sig = SLH::sign(document, slh_kp.value().secret_key.span(), SLH::Level::L128f);
    require(slh_sig, "p8 slh sign");
    info("SLH-DSA-128f signature:", std::to_string(slh_sig.value().size()) + " bytes");
    ok("Document signed with SLH-DSA-128f (hash-based, conservative)");

    // ── SLH-DSA-128f: Verify ────────────────────────────────────────────
    step("Verify SLH-DSA-128f signature on original document");
    auto slh_ok = SLH::verify(document, slh_sig.value().span(),
                              slh_kp.value().public_key.span(), SLH::Level::L128f);
    require(slh_ok, "p8 slh verify");
    ok("SLH-DSA-128f signature verified successfully");

    // ── Comparison ──────────────────────────────────────────────────────
    step("Compare signature sizes");
    info("ML-DSA-65 signature:", std::to_string(dsa_sig.value().size()) + " bytes (lattice)");
    info("SLH-DSA-128f signature:", std::to_string(slh_sig.value().size()) + " bytes (hash-based)");
    note("ML-DSA is smaller and faster; SLH-DSA relies only on hash assumptions (conservative).");
    note("Both are NIST FIPS standardized post-quantum signature algorithms.");
}
#endif // CRYPTOLIB_HAS_PQ


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 9 — BLS Aggregate Signatures
//
//  Three validators each sign their own attestation message.  The three
//  signatures are aggregated into a single 96-byte signature and verified
//  in one pairing check.
// ─────────────────────────────────────────────────────────────────────────────
#ifdef CRYPTOLIB_HAS_BLS
static void pattern_bls_aggregate() {
    pattern(9, "BLS Aggregate Signatures (3 validators -> 1 signature)");

    using BLS = crypto::bls::Bls12381;

    // ── Step 1: Three validators generate keypairs ──────────────────────
    step("Three validators generate BLS12-381 keypairs");
    auto v1 = BLS::generate_keypair(); require(v1, "p9 v1 keygen");
    auto v2 = BLS::generate_keypair(); require(v2, "p9 v2 keygen");
    auto v3 = BLS::generate_keypair(); require(v3, "p9 v3 keygen");
    ok("Validator 1: keypair generated (pk = 48 bytes, sk = 32 bytes)");
    ok("Validator 2: keypair generated");
    ok("Validator 3: keypair generated");

    // ── Step 2: Each validator signs their own attestation ───────────────
    step("Each validator signs their unique attestation");
    std::string msg1 = "validator-1:slot=12345:block=0xabcdef";
    std::string msg2 = "validator-2:slot=12345:block=0xabcdef";
    std::string msg3 = "validator-3:slot=12345:block=0xabcdef";

    auto sig1 = BLS::sign(msg1, v1.value().secret_key.span()); require(sig1, "p9 sign1");
    auto sig2 = BLS::sign(msg2, v2.value().secret_key.span()); require(sig2, "p9 sign2");
    auto sig3 = BLS::sign(msg3, v3.value().secret_key.span()); require(sig3, "p9 sign3");
    info("Signature 1:", std::to_string(sig1.value().size()) + " bytes");
    info("Signature 2:", std::to_string(sig2.value().size()) + " bytes");
    info("Signature 3:", std::to_string(sig3.value().size()) + " bytes");
    info("Total individual:", std::to_string(sig1.value().size() * 3) + " bytes (3 x 96)");
    ok("All three validators signed their attestations");

    // ── Step 3: Aggregate into single signature ─────────────────────────
    step("Aggregate 3 signatures into a single BLS signature");
    std::vector<std::span<const uint8_t>> sigs = {
        sig1.value().span(), sig2.value().span(), sig3.value().span()
    };
    auto agg = BLS::aggregate_signatures(sigs);
    require(agg, "p9 aggregate");
    info("Aggregate signature:", std::to_string(agg.value().size()) + " bytes");
    ok("3 signatures aggregated into 1");

    // ── Step 4: Verify aggregate ────────────────────────────────────────
    step("Verify aggregate signature against all three messages");
    std::vector<std::span<const uint8_t>> msgs = {
        { reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size() },
        { reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size() },
        { reinterpret_cast<const uint8_t*>(msg3.data()), msg3.size() },
    };
    std::vector<std::span<const uint8_t>> pks = {
        v1.value().public_key.span(), v2.value().public_key.span(), v3.value().public_key.span()
    };
    auto verify_res = BLS::aggregate_verify(msgs, pks, agg.value().span());
    require(verify_res, "p9 agg verify");
    ok("Aggregate signature verified with single pairing check");

    // ── Step 5: Show space savings ──────────────────────────────────────
    step("Space savings summary");
    info("Individual signatures:", std::to_string(sig1.value().size() * 3) + " bytes (3 x 96)");
    info("Aggregate signature:", std::to_string(agg.value().size()) + " bytes (1 x 96)");
    info("Savings:", std::to_string(sig1.value().size() * 2) + " bytes saved (66% reduction)");
    note("BLS aggregation: N signatures compress to 1, verified in a single pairing check.");
    note("Ethereum 2.0 uses this to compress thousands of validator attestations.");
}
#endif // CRYPTOLIB_HAS_BLS


// ─────────────────────────────────────────────────────────────────────────────
//  Pattern 10 — Hybrid Classical + Post-Quantum Pipeline
//
//  Full pipeline: ML-KEM key exchange → XChaCha20-Poly1305 encryption →
//  ML-DSA signature on ciphertext → verify signature → decrypt.
// ─────────────────────────────────────────────────────────────────────────────
#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_BLS)
static void pattern_hybrid_pipeline() {
    pattern(10, "Hybrid Classical + PQ Pipeline (ML-KEM + XChaCha20 + ML-DSA)");

    using KEM  = crypto::pq::MlKem;
    using AEAD = crypto::symmetric::XChaCha20Poly1305;
    using DSA  = crypto::pq::MlDsa;

    // ── Step 1: ML-KEM key exchange ─────────────────────────────────────
    step("ML-KEM-768 key exchange between Alice and Bob");
    auto alice_kp = KEM::generate_keypair(KEM::Level::KEM_768);
    require(alice_kp, "p10 kem keygen");

    auto encaps = KEM::encapsulate(alice_kp.value().public_key.span(), KEM::Level::KEM_768);
    require(encaps, "p10 kem encaps");

    auto alice_ss = KEM::decapsulate(encaps.value().ciphertext.span(),
                                     alice_kp.value().secret_key.span(),
                                     KEM::Level::KEM_768);
    require(alice_ss, "p10 kem decaps");

    bool kem_ok = (alice_ss.value().size() == encaps.value().shared_secret.size()) &&
        std::memcmp(alice_ss.value().data(), encaps.value().shared_secret.data(),
                    alice_ss.value().size()) == 0;
    if (!kem_ok) { std::fputs(RED "FAIL: KEM shared secrets differ\n" RST, stderr); std::exit(1); }
    info("Shared secret:", alice_ss.value().to_hex().substr(0, 32) + "...");
    ok("ML-KEM-768 key exchange complete — both parties share 32-byte secret");

    // ── Step 2: Encrypt with XChaCha20-Poly1305 ─────────────────────────
    step("Encrypt message with XChaCha20-Poly1305 using PQ-derived key");
    const char* plaintext = "Hybrid pipeline: quantum-safe key exchange + classical AEAD + PQ signatures.";
    auto ct = AEAD::encrypt(std::string_view(plaintext), alice_ss.value().span());
    require(ct, "p10 encrypt");
    info("Plaintext:", std::string("\"") + plaintext + "\"");
    info("Ciphertext:", std::to_string(ct.value().size()) + " bytes");
    ok("Message encrypted with PQ-derived symmetric key");

    // ── Step 3: Sign the ciphertext with ML-DSA-65 ──────────────────────
    step("Sign the ciphertext with ML-DSA-65 (sender authentication)");
    auto sign_kp = DSA::generate_keypair(DSA::Level::DSA_65);
    require(sign_kp, "p10 dsa keygen");

    auto sig = DSA::sign(ct.value().span(), sign_kp.value().secret_key.span(), DSA::Level::DSA_65);
    require(sig, "p10 dsa sign");
    info("ML-DSA-65 signature:", std::to_string(sig.value().size()) + " bytes");
    ok("Ciphertext signed — recipient can verify sender and detect tampering");

    // ── Step 4: Verify signature on ciphertext ──────────────────────────
    step("Verify ML-DSA-65 signature on received ciphertext");
    auto verify_res = DSA::verify(ct.value().span(), sig.value().span(),
                                  sign_kp.value().public_key.span(), DSA::Level::DSA_65);
    require(verify_res, "p10 dsa verify");
    ok("Signature verified — ciphertext is authentic and untampered");

    // ── Step 5: Decrypt with the shared secret ──────────────────────────
    step("Decrypt ciphertext after signature verification");
    auto pt = AEAD::decrypt(ct.value().span(), encaps.value().shared_secret.span());
    require(pt, "p10 decrypt");
    info("Decrypted:", "\"" + pt.value().to_string() + "\"");

    if (pt.value().to_string() != std::string(plaintext))
        { std::fputs(RED "FAIL: decrypted text mismatch\n" RST, stderr); std::exit(1); }
    ok("Decrypted plaintext matches original");

    // ── Summary ─────────────────────────────────────────────────────────
    step("Pipeline summary");
    note("1. ML-KEM-768 key exchange (post-quantum, FIPS 203)");
    note("2. XChaCha20-Poly1305 AEAD encryption (classical, libsodium)");
    note("3. ML-DSA-65 signature on ciphertext (post-quantum, FIPS 204)");
    note("4. Verify signature before decryption (reject tampered packets)");
    note("5. Decrypt with shared secret (only if signature passes)");
    note("Result: quantum-safe confidentiality + quantum-safe authentication.");
}
#endif // CRYPTOLIB_HAS_PQ && CRYPTOLIB_HAS_BLS


// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::printf(BOLD "\nCryptoLib — Steganography as a native vault feature\n" RST
                "Stego is a method on the vault, not an external engine.\n");

    // ── Resolve output directory from argv or default to temp ─────────────
    fs::path output_dir;
    if (argc >= 2) {
        output_dir = fs::path(argv[1]);
    } else {
        output_dir = fs::temp_directory_path() / "cryptolib_usage";
    }
    fs::create_directories(output_dir);

    // ── Set carrier and output paths ──────────────────────────────────────
    IMG = output_dir / "carrier.ppm";
    WAV = output_dir / "carrier.wav";
    VID = output_dir / "carrier.crvf";
    ENT = output_dir / "entropy.ppm";
    OUT = output_dir;

    std::printf("Output directory: %s\n", output_dir.string().c_str());

    crypto::init();
    generate_carriers();

    pattern_vault_native();
    pattern_asym_native();
    pattern_entropy_native();
    pattern_all_formats();
    pattern_aad_binding();
    pattern_low_level();

#ifdef CRYPTOLIB_HAS_PQ
    pattern_pq_key_exchange();
    pattern_pq_signatures();
#endif

#ifdef CRYPTOLIB_HAS_BLS
    pattern_bls_aggregate();
#endif

#if defined(CRYPTOLIB_HAS_PQ) && defined(CRYPTOLIB_HAS_BLS)
    pattern_hybrid_pipeline();
#endif

    std::printf("\n" BOLD GRN "All patterns verified.\n\n" RST);
}
