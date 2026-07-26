// ─────────────────────────────────────────────────────────────────────────────
// Advanced steganography example — the Phase 1-4 additions in one runnable tour:
//   1. Keyed stego (whitened: no 'CSTG' signature)          — StegoParams.key
//   2. Always-encrypt (AEAD-then-hide)                       — embed_encrypted
//   3. PhysicalSeal (two-factor: the photo is the key)       — crypto::PhysicalSeal
//   4. FEC robustness codec (survive bit errors)             — crypto::stego::fec
//   5. Carrier analysis (validity, tamper, hidden-data)      — crypto::stego::StegoAnalyzer
//
// HONEST framing throughout: stego is concealment, not confidentiality (the AEAD
// provides that); the analyzer's hidden-data probe is a heuristic, not a proof.
//
// Build:  cmake --build build --target cryptolib_stego_advanced
// Run:    ./build/cryptolib_stego_advanced
// ─────────────────────────────────────────────────────────────────────────────
#include <cryptolib/cryptolib.hpp>

#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

using namespace crypto;
namespace fs = std::filesystem;

static void section(const char* t) { std::printf("\n=== %s ===\n", t); }
static void ok(const char* label, bool pass) {
    std::printf("  [%s] %s\n", pass ? "ok" : "FAIL", label);
}
static std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

int main() {
    init();
    fs::path dir = fs::temp_directory_path() / "cryptolib_stego_advanced";
    fs::create_directories(dir);
    const std::string cover = (dir / "cover.ppm").string();
    (void)stego::MediaGenerator::generate_ppm(cover, 256, 256);

    // ── 1. Keyed stego ───────────────────────────────────────────────────────
    section("1. Keyed stego (whitened — no CSTG signature)");
    {
        std::vector<uint8_t> key(32, 0x5a);
        auto payload = bytes("keyed concealment");
        stego::StegoParams p; p.key = key;
        const std::string out = (dir / "keyed.ppm").string();
        ok("embed", stego::StegoEngine::embed(cover, payload, out, p).is_ok());
        auto got = stego::StegoEngine::extract(out, p);
        ok("extract round-trip", got.is_ok() && got.value() == payload);
        // Wrong key fails fast; an unkeyed extract can't even find the header.
        ok("unkeyed extract of keyed carrier fails", stego::StegoEngine::extract(out).is_err());
    }

    // ── 2. Always-encrypt (AEAD-then-hide) ───────────────────────────────────
    section("2. Always-encrypt (payload never in the clear)");
    {
        std::vector<uint8_t> key(32, 0x11);
        auto secret = bytes("attack at dawn");
        const std::string out = (dir / "enc.ppm").string();
        ok("embed_encrypted", stego::StegoEngine::embed_encrypted(cover, secret, out, key).is_ok());
        auto got = stego::StegoEngine::extract_decrypt(out, key);
        ok("extract_decrypt round-trip", got.is_ok() && got.value() == secret);
        std::vector<uint8_t> wrong(32, 0x22);
        ok("wrong key rejected", stego::StegoEngine::extract_decrypt(out, wrong).is_err());
    }

    // ── 3. PhysicalSeal (the photo is the key) ───────────────────────────────
    section("3. PhysicalSeal (two-factor by media possession)");
    {
        const std::string keyMedia = (dir / "keymedia.ppm").string();
        (void)stego::MediaGenerator::generate_ppm(keyMedia, 96, 96);
        const std::string out = (dir / "physical.ppm").string();
        auto msg = bytes("need both files to read this");
        ok("seal", PhysicalSeal::seal(keyMedia, msg, bytes("ctx"), cover, out).is_ok());
        auto got = PhysicalSeal::open(keyMedia, bytes("ctx"), out);
        ok("open with correct key-media + aad", got.is_ok() && got.value() == msg);
        ok("wrong aad rejected", PhysicalSeal::open(keyMedia, bytes("nope"), out).is_err());
    }

    // ── 4. FEC robustness codec ──────────────────────────────────────────────
    section("4. FEC — recover from bit errors");
    {
        auto data = bytes("robust payload");
        for (auto scheme : {stego::fec::Scheme::Repetition3,
                            stego::fec::Scheme::Repetition5,
                            stego::fec::Scheme::Hamming74}) {
            auto enc = stego::fec::encode(data, scheme);
            enc[0] ^= 0x40;  // inject one bit error in the first block
            auto dec = stego::fec::decode(enc, scheme, data.size());
            ok("corrects a single-bit flip", dec.is_ok() && dec.value() == data);
        }
    }

    // ── 5. Carrier analysis ──────────────────────────────────────────────────
    section("5. Analysis — validity, tamper, hidden-data (heuristic)");
    {
        // Validity.
        auto insp = stego::StegoAnalyzer::inspect(cover);
        ok("inspect: valid carrier", insp.is_ok() && insp.value().parses);
        if (insp.is_ok()) std::printf("      %s\n", insp.value().detail.c_str());

        // Reference-based tamper detection: store a digest, mutate, compare.
        auto probe = (dir / "probe.ppm").string();
        (void)stego::MediaGenerator::generate_ppm(probe, 128, 128);
        auto d1 = stego::StegoAnalyzer::content_digest(probe);
        { std::FILE* f = std::fopen(probe.c_str(), "r+b"); std::fseek(f, 500, SEEK_SET);
          int c = std::fgetc(f); std::fseek(f, 500, SEEK_SET); std::fputc(c ^ 0x01, f); std::fclose(f); }
        auto v = stego::StegoAnalyzer::verify_digest(probe,
                     std::span<const uint8_t>(d1.value().data(), d1.value().size()));
        ok("tamper detected vs stored digest", v.is_ok() && !v.value());

        // Hidden-data probe: an unkeyed cryptolib payload is detected; a keyed
        // (whitened) one is statistically invisible — the honest limit.
        const std::string plain = (dir / "plain.ppm").string();
        (void)stego::MediaGenerator::generate_ppm(plain, 128, 128);
        (void)stego::StegoEngine::embed(plain, bytes("hi"), plain);
        auto hd = stego::StegoAnalyzer::detect_hidden(plain);
        ok("detect: unkeyed cryptolib payload flagged", hd.is_ok() && hd.value().cryptolib_payload);
        if (hd.is_ok()) std::printf("      note: %s\n", hd.value().note.c_str());
    }

    fs::remove_all(dir);
    std::printf("\nDone.\n");
    return 0;
}
