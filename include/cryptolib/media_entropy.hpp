#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::entropy::MediaEntropy                                            ║
 * ║                                                                            ║
 * ║  A LavaRand-inspired entropy layer: harvest cryptographic randomness      ║
 * ║  from user-supplied media — photo, video, or audio — and integrate it     ║
 * ║  seamlessly with the rest of the library.                                  ║
 * ║                                                                            ║
 * ║  WHY THIS WORKS                                                            ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║  Every real media file contains physical entropy:                          ║
 * ║                                                                            ║
 * ║    Photo / frame  — sensor photon shot noise, thermal noise, lens         ║
 * ║                     aberration, JPEG/RAW quantisation artifacts.           ║
 * ║                     Even two photos of the same scene taken milliseconds  ║
 * ║                     apart produce completely different LSBs.               ║
 * ║                                                                            ║
 * ║    Video          — all of the above, multiplied by every frame, plus     ║
 * ║                     motion-compensation residuals, codec noise,            ║
 * ║                     inter-frame temporal variations.                       ║
 * ║                                                                            ║
 * ║    Audio          — microphone thermal noise floor, quantisation noise,   ║
 * ║                     room acoustics, analogue-to-digital converter jitter.  ║
 * ║                                                                            ║
 * ║  PIPELINE (mirrors Cloudflare's LavaRand design)                          ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║                                                                            ║
 * ║   media file(s)                                                            ║
 * ║       │                                                                    ║
 * ║       ▼  [1] BLAKE2b streaming hash  (unidirectional)                    ║
 * ║       │       processes any file size without loading into RAM             ║
 * ║       │       extracts and compresses all entropy into 64 bytes           ║
 * ║       │                                                                    ║
 * ║       ▼  [2] Mix with system entropy  (defense-in-depth)                 ║
 * ║       │       XOR + BLAKE2b re-hash with fresh randombytes_buf output     ║
 * ║       │       so even a fully predictable file adds to existing security  ║
 * ║       │                                                                    ║
 * ║       ▼  [3] HKDF-style key derivation  (domain separation)              ║
 * ║       │       Argon2id for keys that need memory-hardness                 ║
 * ║       │       BLAKE2b keyed hash for fast sub-key derivation              ║
 * ║       │                                                                    ║
 * ║       ▼  Domain-specific outputs, all compatible with the library:        ║
 * ║              symmetric key   → XChaCha20Poly1305 / Aes256Gcm              ║
 * ║              vault key       → SecureVault master key                     ║
 * ║              signing seed    → Ed25519 keypair (deterministic)            ║
 * ║              box seed        → X25519 keypair (deterministic)             ║
 * ║              raw entropy     → feed into your own pipeline                ║
 * ║                                                                            ║
 * ║  SECURITY NOTE                                                             ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║  Like LavaRand, this layer is additive — it mixes with system entropy,   ║
 * ║  never replaces it. A predictable file weakens no existing security;      ║
 * ║  an unpredictable file strengthens everything it touches.                 ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "hash.hpp"
#include "entropy_drbg.hpp"
#include "entropy_health.hpp"
#include "asymmetric.hpp"
#include "vault.hpp"

#include <sodium.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto::entropy {

// ─────────────────────────────────────────────────────────────────────────────
// MediaInfo — metadata about harvested file(s)
// ─────────────────────────────────────────────────────────────────────────────
struct MediaInfo {
    std::string              path;         // source file path
    std::uintmax_t           file_size;    // bytes
    std::size_t              chunks_read;  // number of read passes
    double                   entropy_estimate_bits; // conservative lower bound
};

// ─────────────────────────────────────────────────────────────────────────────
// DerivedKeys — all domain-specific keys produced from the harvested entropy
// ─────────────────────────────────────────────────────────────────────────────
struct DerivedKeys {
    SecureBuffer symmetric_key;    // 32 B — for XChaCha20Poly1305 / Aes256Gcm
    SecureBuffer vault_master_key; // 32 B — master key for SecureVault
    SecureBuffer signing_seed;     // 32 B — deterministic Ed25519 seed
    SecureBuffer box_seed;         // 32 B — deterministic X25519 seed
    SecureBuffer stream_key;       // 32 B — for SecretStream
    SecureBuffer raw_entropy;      // 64 B — raw mixed entropy for custom use
};

// ─────────────────────────────────────────────────────────────────────────────
// MediaEntropy — the main harvester class
// ─────────────────────────────────────────────────────────────────────────────
class MediaEntropy {
public:
    // Internal constants
    static constexpr std::size_t CHUNK_SIZE     = 65536;   // 64 KiB read buffer
    static constexpr std::size_t ENTROPY_BYTES  = 64;      // BLAKE2b-512 output
    static constexpr std::size_t KEY_BYTES      = 32;      // derived key size
    static constexpr std::size_t MIN_FILE_BYTES = 256;     // reject tiny files

    // ─── Primary constructors ────────────────────────────────────────────────
    //
    // Two construction modes — choose based on your use case:
    //
    //  from_file()              — LavaRand mode (recommended for in-session use)
    //    Mixes fresh system entropy (randombytes_buf) into the file hash on every
    //    call.  Two calls from the same file in the same process produce different
    //    MediaEntropy objects and therefore different vault keys.  Use this when
    //    you derive the object ONCE and keep it for the lifetime of your session.
    //
    //  from_file_deterministic() — Reproducible mode (cross-session / cross-process)
    //    Uses only the file's byte content — no system entropy mixing.  Two calls
    //    from the same file (same bytes) always produce identical keys, even across
    //    processes or reboots.  Use this when BOTH the sealing side and the opening
    //    side must independently re-derive the same keys from the same file.
    //
    //    ┌─────────────────────────┬──────────────────────────────────────────┐
    //    │                         │  seal & open in SAME process/session     │
    //    │                         │  → use from_file() + keep one instance   │
    //    │                         ├──────────────────────────────────────────┤
    //    │                         │  seal in process A, open in process B    │
    //    │                         │  (same file available to both)           │
    //    │                         │  → use from_file_deterministic()         │
    //    └─────────────────────────┴──────────────────────────────────────────┘

    /// LavaRand mode — mixes fresh system entropy on every call.
    /// Keys are NOT reproducible across separate from_file() calls.
    /// Use when you derive once and keep the object for the session lifetime.
    [[nodiscard]] static Result<MediaEntropy>
    from_file(const std::filesystem::path& path) {
        return harvest_single(path, /*mix_system=*/true);
    }

    /// Reproducible mode — keys are derived solely from the file's byte content.
    /// Two calls from the same file always produce the same keys.
    /// Use for cross-session or cross-process scenarios where both sides
    /// independently re-derive from the same file (e.g. seal_from_file /
    /// open_from_file convenience functions).
    ///
    /// ⚠ SECURITY: If the attacker can obtain or guess the exact media file
    ///   (e.g. a stock photo, public video, default wallpaper), all derived
    ///   keys are fully recoverable.  Only use files with genuine physical
    ///   entropy that are kept confidential (private photos, unique recordings).
    ///   For maximum security, prefer from_file() which mixes system entropy.
    [[nodiscard]] static Result<MediaEntropy>
    from_file_deterministic(const std::filesystem::path& path) {
        return harvest_single(path, /*mix_system=*/false);
    }

    /// LavaRand mode — mixes fresh system entropy on every call.
    /// Keys are NOT reproducible across separate from_files() calls.
    [[nodiscard]] static Result<MediaEntropy>
    from_files(const std::vector<std::filesystem::path>& paths) {
        return harvest_multiple(paths, /*mix_system=*/true);
    }

    /// Reproducible mode — keys derived solely from the files' byte content.
    /// Use for cross-session or cross-process scenarios.
    [[nodiscard]] static Result<MediaEntropy>
    from_files_deterministic(const std::vector<std::filesystem::path>& paths) {
        return harvest_multiple(paths, /*mix_system=*/false);
    }

    // ─── Internal multi-file harvest (shared by both modes) ──────────────────
    [[nodiscard]] static Result<MediaEntropy>
    harvest_multiple(const std::vector<std::filesystem::path>& paths,
                     bool mix_system) {
        if (paths.empty())
            return Result<MediaEntropy>::err("MediaEntropy: no files provided");

        // Stream all files through a single BLAKE2b state — one unified hash
        crypto_generichash_state state{};
        crypto_generichash_init(&state, nullptr, 0, ENTROPY_BYTES);

        std::vector<MediaInfo> info_list;
        std::uintmax_t total_bytes = 0;

        for (const auto& p : paths) {
            auto result = stream_file_into_hash(state, p);
            if (result.is_err())
                return Result<MediaEntropy>::err(result.error().message);
            info_list.push_back(result.value());
            total_bytes += result.value().file_size;
        }

        SecureBuffer file_hash(ENTROPY_BYTES);
        crypto_generichash_final(&state, file_hash.data(), ENTROPY_BYTES);

        // Optionally mix with system entropy (LavaRand mode)
        SecureBuffer mixed = mix_system
            ? mix_with_system_entropy(file_hash)
            : std::move(file_hash);

        // Combine all MediaInfo into one summary
        MediaInfo combined{
            .path                  = "[" + std::to_string(paths.size()) + " files]",
            .file_size             = total_bytes,
            .chunks_read           = 0,
            .entropy_estimate_bits = 0.0
        };
        for (auto& mi : info_list) {
            combined.chunks_read           += mi.chunks_read;
            combined.entropy_estimate_bits += mi.entropy_estimate_bits;
        }

        return Result<MediaEntropy>::ok(MediaEntropy(std::move(mixed), combined));
    }

    // ─── Key derivation ──────────────────────────────────────────────────────

    /// Derive all domain-specific keys at once.
    [[nodiscard]] DerivedKeys derive_all() const {
        return DerivedKeys{
            .symmetric_key    = derive_key("xchacha20poly1305:key"),
            .vault_master_key = derive_key("securevault:master"),
            .signing_seed     = derive_key("ed25519:seed"),
            .box_seed         = derive_key("x25519:seed"),
            .stream_key       = derive_key("secretstream:key"),
            .raw_entropy      = SecureBuffer(entropy_.data(), entropy_.size())
        };
    }

    /// Derive a 32-byte key for XChaCha20Poly1305 or Aes256Gcm.
    [[nodiscard]] SecureBuffer symmetric_key() const {
        return derive_key("xchacha20poly1305:key");
    }

    /// Derive a 32-byte master key for SecureVault.
    [[nodiscard]] SecureBuffer vault_master_key() const {
        return derive_key("securevault:master");
    }

    /// Derive a VaultKeyPair (Ed25519) deterministically from the entropy.
    /// The same media file will always produce the same keypair.
    [[nodiscard]] Result<VaultKeyPair> vault_keypair() const {
        auto seed = derive_key("ed25519:vault:seed");
        return SecureVault::keypair_from_seed(seed.span());
    }

    /// Derive an AsymKeyBundle (X25519 + Ed25519) from the entropy.
    [[nodiscard]] Result<AsymKeyBundle> asym_bundle() const {
        // Derive separate seeds for box and signing keys
        auto box_seed  = derive_key("x25519:seed");
        auto sign_seed = derive_key("ed25519:seed");

        AsymKeyBundle b;
        b.box_public.resize(crypto_box_PUBLICKEYBYTES);
        b.box_secret.resize(crypto_box_SECRETKEYBYTES);

        // X25519 keypair from seed: scalar multiply base point
        std::memcpy(b.box_secret.data(), box_seed.data(), KEY_BYTES);
        crypto_scalarmult_base(b.box_public.data(), b.box_secret.data());

        b.sign_public.resize(crypto_sign_PUBLICKEYBYTES);
        b.sign_secret.resize(crypto_sign_SECRETKEYBYTES);
        crypto_sign_seed_keypair(
            b.sign_public.data(), b.sign_secret.data(), sign_seed.data());

        return Result<AsymKeyBundle>::ok(std::move(b));
    }

    /// Derive a SecureVault ready to use — one call to get a fully configured vault.
    [[nodiscard]] Result<SecureVault> make_vault(
            KdfParams params = KdfParams::interactive()) const {
        auto master = vault_master_key();
        auto kp_res = vault_keypair();
        if (kp_res.is_err())
            return Result<SecureVault>::err(kp_res.error().message);
        return Result<SecureVault>::ok(
            SecureVault(master.span(), std::move(kp_res.value()), params));
    }

    /// Return the raw 64-byte mixed entropy — plug into any custom pipeline.
    [[nodiscard]] const SecureBuffer& raw() const noexcept { return entropy_; }

    /// Derive an arbitrary-length, namespaced key from the harvested entropy via
    /// HKDF-SHA-512 (RFC 5869): the entropy is the IKM, `label` the info string.
    /// A vetted randomness extractor + expander — unlike derive_key()'s keyed
    /// BLAKE2b (kept for the fixed 32-byte purpose keys), this supports any
    /// length and any label, ideal for seeding the newer primitives, e.g.
    ///   auto oprf_seed = me.derive("opaque:oprf_seed:v1", 64);
    ///   auto stego_key = me.derive("stego:embed_key:v1", 32);
    /// Each distinct label yields an independent key.
    [[nodiscard]] SecureBuffer derive(std::string_view label, std::size_t len = 32) const {
        return std::move(hash::HkdfSha512::derive(entropy_.span(), {}, label, len).value());
    }

    /// Seed an HMAC-DRBG (SP 800-90A) from the harvested entropy — turns the
    /// one-shot 64-byte pull into a beacon that yields an arbitrarily long
    /// keystream via drbg.generate(n). In deterministic mode the beacon is fully
    /// reproducible from the media; in mixed mode it also folds in system entropy.
    [[nodiscard]] Result<HmacDrbg>
    make_drbg(std::string_view personalization = {}) const {
        return HmacDrbg::instantiate(entropy_.span(), {},
            { reinterpret_cast<const uint8_t*>(personalization.data()), personalization.size() });
    }

    /// Assess the *raw* source file against the SP 800-90B health tests
    /// (Most-Common-Value min-entropy, Repetition-Count, Adaptive-Proportion)
    /// BEFORE trusting it — especially in deterministic "the file IS the key"
    /// mode, where a low-entropy carrier (a blank frame, a solid-colour image)
    /// silently weakens every derived key.
    ///
    /// Samples up to `max_bytes` from the start of the file (media entropy is
    /// spread throughout, so a leading sample is representative and bounds cost).
    ///
    ///   auto h = MediaEntropy::assess_file_health("photo.ppm").value();
    ///   if (!h.healthy(1.0)) { /* reject: too little entropy per byte */ }
    [[nodiscard]] static Result<HealthReport>
    assess_file_health(const std::filesystem::path& path,
                       std::size_t max_bytes = (1u << 20)) {
        std::error_code ec;
        auto file_size = std::filesystem::file_size(path, ec);
        if (ec)
            return Result<HealthReport>::err("MediaEntropy: cannot stat: " + path.string());
        if (file_size < MIN_FILE_BYTES)
            return Result<HealthReport>::err("MediaEntropy: file too small (<256 bytes): " + path.string());

        std::ifstream file(path, std::ios::binary);
        if (!file)
            return Result<HealthReport>::err("MediaEntropy: cannot open: " + path.string());

        const std::size_t want = std::min<std::size_t>(max_bytes, static_cast<std::size_t>(file_size));
        std::vector<uint8_t> sample(want);
        file.read(reinterpret_cast<char*>(sample.data()), static_cast<std::streamsize>(want));
        sample.resize(static_cast<std::size_t>(file.gcount()));
        auto report = assess_health({ sample.data(), sample.size() });
        sodium_memzero(sample.data(), sample.size());
        return Result<HealthReport>::ok(report);
    }

    /// Return a 32-byte entropy boost key suitable for injection into
    /// SecureVault::seal() / open() or AsymmetricVault::seal() / open().
    ///
    /// Domain-separated from symmetric_key() and vault_master_key() — derived
    /// from the same entropy source but bound to a unique purpose label so it
    /// is cryptographically independent of every other derived key.
    ///
    /// Usage (symmetric vault + entropy boost):
    ///
    ///   auto me  = MediaEntropy::from_file_deterministic("photo.ppm").value();
    ///   auto pkt = vault.seal(plaintext, aad, me);          // MediaEntropy overload
    ///   auto pt  = vault.open(pkt.value(), aad, me);        // MediaEntropy overload
    ///
    /// Or, passing the raw span explicitly:
    ///   auto boost = me.entropy_boost();
    ///   auto pkt = vault.seal(plaintext, aad_span, boost.span());
    ///   auto pt  = vault.open(pkt.value(), pub_key, aad_span, boost.span());
    [[nodiscard]] SecureBuffer entropy_boost() const {
        return derive_key("vault:entropy_boost:v1");
    }

    /// Conservative lower-bound entropy estimate in bits.
    [[nodiscard]] double entropy_bits() const noexcept {
        return info_.entropy_estimate_bits;
    }

    /// Source file metadata.
    [[nodiscard]] const MediaInfo& info() const noexcept { return info_; }

    // ─── Refresh ─────────────────────────────────────────────────────────────

    /// Mix fresh system entropy into the existing harvested entropy.
    /// Call periodically if the MediaEntropy object is long-lived.
    void refresh_system_entropy() {
        entropy_ = mix_with_system_entropy(entropy_);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direct encryption — use this entropy as the sole key source.
    //
    // seal() / open() derive a SecureVault on the fly and use it to encrypt or
    // decrypt.  No stego, no carrier file — just the 4-layer pipeline with keys
    // seeded from physical media entropy.
    //
    // Both ends must use a MediaEntropy object derived from the *same* media
    // file.  Because system entropy is mixed at from_file() time, re-derive from
    // file for the opening side rather than constructing a new object in-process.
    //
    //   sender side:
    //     auto me  = MediaEntropy::from_file("photo.ppm").value();
    //     auto ct  = me.seal("classified", "ctx").value();
    //     transmit(ct);
    //
    //   receiver side (same photo.ppm):
    //     auto me  = MediaEntropy::from_file("photo.ppm").value();
    //     auto pt  = me.open(ct, "ctx").value();
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] Result<EncryptedPacket>
    seal(std::string_view plaintext,
         std::string_view aad = {}) const {
        auto vault_res = make_vault();
        if (vault_res.is_err())
            return Result<EncryptedPacket>::err(vault_res.error().message);
        return vault_res.value().seal(plaintext, aad);
    }

    [[nodiscard]] Result<SecureBuffer>
    open(const EncryptedPacket& packet,
         std::string_view       aad = {}) const {
        auto vault_res = make_vault();
        if (vault_res.is_err())
            return Result<SecureBuffer>::err(vault_res.error().message);
        return vault_res.value().open(packet, aad);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Steganography integration — encrypt + hide in a single call.
    //
    // seal_into() seals through all 4 crypto layers then embeds the packet
    // inside a carrier media file.  open_from() extracts and decrypts.
    //
    // Both ends must use a MediaEntropy object from the *same* source file.
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] Result<void>
    seal_into(std::string_view cover_path,
              std::string_view plaintext,
              std::string_view output_path,
              std::string_view aad = {}) const;

    [[nodiscard]] Result<SecureBuffer>
    open_from(std::string_view stego_path,
              std::string_view aad = {}) const;

private:
    // ─── Private constructor ─────────────────────────────────────────────────
    MediaEntropy(SecureBuffer entropy, MediaInfo info)
        : entropy_(std::move(entropy))
        , info_(std::move(info))
    {}

    // ─── Core: stream a file through a BLAKE2b state ─────────────────────────
    // Does NOT load the full file into memory — safe for multi-GB video files.
    [[nodiscard]] static Result<MediaInfo>
    stream_file_into_hash(crypto_generichash_state& state,
                          const std::filesystem::path& path) {
        // Validate path
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec)
            return Result<MediaInfo>::err(
                "MediaEntropy: file not found: " + path.string());

        auto file_size = std::filesystem::file_size(path, ec);
        if (ec)
            return Result<MediaInfo>::err(
                "MediaEntropy: cannot stat: " + path.string());

        if (file_size < MIN_FILE_BYTES)
            return Result<MediaInfo>::err(
                "MediaEntropy: file too small (<256 bytes): " + path.string());

        std::ifstream file(path, std::ios::binary);
        if (!file)
            return Result<MediaInfo>::err(
                "MediaEntropy: cannot open: " + path.string());

        // NOTE: we intentionally do NOT hash the file path.  Binding the
        // path breaks deterministic-mode portability — the same file content
        // at different filesystem locations would yield different keys.
        // Only the file's byte content determines the entropy output.

        // Stream file contents in chunks, accumulating a byte histogram so we
        // can report a real entropy estimate instead of a fixed bits-per-byte.
        std::vector<uint8_t> buf(CHUNK_SIZE);
        std::size_t chunks = 0;
        std::array<std::uint64_t, 256> hist{};
        std::uint64_t total = 0;

        while (file) {
            file.read(reinterpret_cast<char*>(buf.data()),
                      static_cast<std::streamsize>(CHUNK_SIZE));
            const auto bytes_read = static_cast<std::size_t>(file.gcount());
            if (bytes_read == 0) break;
            crypto_generichash_update(&state, buf.data(), bytes_read);
            for (std::size_t i = 0; i < bytes_read; ++i) ++hist[buf[i]];
            total += bytes_read;
            ++chunks;
        }

        // Wipe the read buffer — it may contain sensitive frame data.
        // Use sodium_memzero (compiler-proof) instead of std::fill which
        // can be dead-store eliminated at -O2.
        sodium_memzero(buf.data(), buf.size());

        return Result<MediaInfo>::ok(MediaInfo{
            .path                  = path.string(),
            .file_size             = file_size,
            .chunks_read           = chunks,
            .entropy_estimate_bits = shannon_entropy_bits(hist, total)
        });
    }

    // ─── Harvest a single file: open, hash, optionally mix ───────────────────
    [[nodiscard]] static Result<MediaEntropy>
    harvest_single(const std::filesystem::path& path, bool mix_system) {
        crypto_generichash_state state{};
        crypto_generichash_init(&state, nullptr, 0, ENTROPY_BYTES);

        auto info = stream_file_into_hash(state, path);
        if (info.is_err())
            return Result<MediaEntropy>::err(info.error().message);

        SecureBuffer file_hash(ENTROPY_BYTES);
        crypto_generichash_final(&state, file_hash.data(), ENTROPY_BYTES);

        SecureBuffer mixed = mix_system
            ? mix_with_system_entropy(file_hash)
            : std::move(file_hash);
        return Result<MediaEntropy>::ok(
            MediaEntropy(std::move(mixed), info.value()));
    }

    // ─── Step 2: mix file hash with fresh system entropy ─────────────────────
    // Even if the file is fully known to an attacker, the system entropy
    // (from /dev/urandom via randombytes_buf) keeps the output unpredictable.
    // And if system entropy is somehow compromised, the file entropy compensates.
    [[nodiscard]] static SecureBuffer
    mix_with_system_entropy(const SecureBuffer& file_hash) {
        // Generate fresh system randomness
        SecureBuffer sys(ENTROPY_BYTES);
        randombytes_buf(sys.data(), ENTROPY_BYTES);

        // Mix: BLAKE2b( file_hash || sys_entropy )
        // Using BLAKE2b's streaming API to combine both inputs without XOR
        // (XOR can cancel out bits; hashing avoids that vulnerability)
        SecureBuffer mixed(ENTROPY_BYTES);
        crypto_generichash_state mix_state{};
        crypto_generichash_init(&mix_state, nullptr, 0, ENTROPY_BYTES);
        crypto_generichash_update(&mix_state, file_hash.data(), file_hash.size());
        crypto_generichash_update(&mix_state, sys.data(), sys.size());
        crypto_generichash_final(&mix_state, mixed.data(), ENTROPY_BYTES);

        return mixed;
    }

    // ─── Step 3: HKDF-style derivation with domain separation ─────────────────
    // Each purpose gets its own key, bound by a domain label.
    // This ensures symmetric_key and signing_seed are completely independent
    // even though they come from the same entropy source.
    // Uses BLAKE2b in keyed mode: output = BLAKE2b(domain_label, key=entropy)
    [[nodiscard]] SecureBuffer derive_key(std::string_view domain) const {
        SecureBuffer out(KEY_BYTES);
        crypto_generichash(
            out.data(), KEY_BYTES,
            reinterpret_cast<const uint8_t*>(domain.data()), domain.size(),
            entropy_.data(), entropy_.size());
        return out;
    }

    // ─── Entropy estimation ───────────────────────────────────────────────────
    // Shannon entropy of the file's byte distribution: H = -Σ p·log2(p) bits per
    // byte (0–8), multiplied by the byte count for a total-bits estimate.
    //
    // NOTE: this is a statistical *upper bound* assuming i.i.d. bytes — it does
    // NOT account for structure/correlation in real media, so true min-entropy
    // is lower. It is an indicator, not a guarantee. A low value (e.g. a
    // solid-colour image) correctly reports near-zero, unlike the previous
    // file_size×1.0 heuristic. Security never relies on this number: from_file()
    // mixes system entropy regardless, and deterministic mode is documented as
    // "the file IS the key".
    [[nodiscard]] static double
    shannon_entropy_bits(const std::array<std::uint64_t, 256>& hist,
                         std::uint64_t total) noexcept {
        if (total == 0) return 0.0;
        const double n = static_cast<double>(total);
        double bits_per_byte = 0.0;
        for (std::uint64_t c : hist) {
            if (c == 0) continue;
            const double p = static_cast<double>(c) / n;
            bits_per_byte -= p * std::log2(p);
        }
        return bits_per_byte * n;
    }

    SecureBuffer entropy_;   // 64-byte mixed entropy (always zeroed on destruction)
    MediaInfo    info_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Convenience free functions
// ─────────────────────────────────────────────────────────────────────────────

/// Quickly derive a symmetric key from a single media file.
/// Equivalent to: MediaEntropy::from_file(path) → .symmetric_key()
[[nodiscard]] inline Result<SecureBuffer>
key_from_file(const std::filesystem::path& path) {
    auto me = MediaEntropy::from_file(path);
    if (me.is_err()) return Result<SecureBuffer>::err(me.error().message);
    return Result<SecureBuffer>::ok(me.value().symmetric_key());
}

/// Quickly create a SecureVault seeded from a single media file.
[[nodiscard]] inline Result<SecureVault>
vault_from_file(const std::filesystem::path& path,
                KdfParams params = KdfParams::interactive()) {
    auto me = MediaEntropy::from_file(path);
    if (me.is_err()) return Result<SecureVault>::err(me.error().message);
    return me.value().make_vault(params);
}

/// Quickly create a SecureVault seeded from multiple media files.
[[nodiscard]] inline Result<SecureVault>
vault_from_files(const std::vector<std::filesystem::path>& paths,
                 KdfParams params = KdfParams::interactive()) {
    auto me = MediaEntropy::from_files(paths);
    if (me.is_err()) return Result<SecureVault>::err(me.error().message);
    return me.value().make_vault(params);
}

/// Seal plaintext using entropy derived deterministically from a media file.
/// Uses from_file_deterministic() so that open_from_file() — called separately,
/// even in a different process — can reproduce the same keys from the same file.
///
/// Do NOT use from_file() for this pattern — its system-entropy mixing makes
/// every construction produce different keys, breaking cross-call round-trips.
[[nodiscard]] inline Result<EncryptedPacket>
seal_from_file(const std::filesystem::path& path,
               std::string_view             plaintext,
               std::string_view             aad = {}) {
    auto me = MediaEntropy::from_file_deterministic(path);
    if (me.is_err()) return Result<EncryptedPacket>::err(me.error().message);
    return me.value().seal(plaintext, aad);
}

/// Open an EncryptedPacket produced by seal_from_file().
/// Re-derives keys deterministically from the same file content.
/// The file must be byte-for-byte identical to the one used during sealing.
[[nodiscard]] inline Result<SecureBuffer>
open_from_file(const std::filesystem::path& path,
               const EncryptedPacket&       packet,
               std::string_view             aad = {}) {
    auto me = MediaEntropy::from_file_deterministic(path);
    if (me.is_err()) return Result<SecureBuffer>::err(me.error().message);
    return me.value().open(packet, aad);
}

/// Derive an AsymKeyBundle anchored to a media file's content.
/// Uses from_file_deterministic() so the same file always yields the same
/// identity — useful for stable pseudonymous identities across sessions.
[[nodiscard]] inline Result<AsymKeyBundle>
asym_bundle_from_file(const std::filesystem::path& path) {
    auto me = MediaEntropy::from_file_deterministic(path);
    if (me.is_err()) return Result<AsymKeyBundle>::err(me.error().message);
    return me.value().asym_bundle();
}

} // namespace crypto::entropy

// ─────────────────────────────────────────────────────────────────────────────
// Steganography engine — included here so MediaEntropy::seal_into / open_from
// can delegate to StegoEngine.  media_entropy.hpp → steganography.hpp →
// packet.hpp (no vault.hpp, no cycle).
// ─────────────────────────────────────────────────────────────────────────────
#include "steganography.hpp"

namespace crypto::entropy {

// ── MediaEntropy::seal_into / open_from ───────────────────────────────────────

inline Result<void>
MediaEntropy::seal_into(std::string_view cover_path,
                        std::string_view plaintext,
                        std::string_view output_path,
                        std::string_view aad) const
{
    auto vault_res = make_vault();
    if (vault_res.is_err()) return Result<void>::err(vault_res.error().message);
    return vault_res.value().seal_into(cover_path, plaintext, output_path, aad);
}

inline Result<crypto::SecureBuffer>
MediaEntropy::open_from(std::string_view stego_path,
                        std::string_view aad) const
{
    auto vault_res = make_vault();
    if (vault_res.is_err())
        return Result<crypto::SecureBuffer>::err(vault_res.error().message);
    return vault_res.value().open_from(stego_path, aad);
}

} // namespace crypto::entropy

// ─────────────────────────────────────────────────────────────────────────────
// SecureVault::from_entropy / AsymmetricVault::from_entropy
//
// Defined here because the full MediaEntropy type is now visible.  Declared
// in vault.hpp using a forward declaration of entropy::MediaEntropy.
// ─────────────────────────────────────────────────────────────────────────────

namespace crypto {

inline Result<SecureVault>
SecureVault::from_entropy(const entropy::MediaEntropy& source,
                          KdfParams                    params)
{
    auto master = source.vault_master_key();
    auto kp_res = source.vault_keypair();
    if (kp_res.is_err())
        return Result<SecureVault>::err(kp_res.error().message);
    return Result<SecureVault>::ok(
        SecureVault(master.span(), std::move(kp_res.value()), params));
}

inline Result<AsymKeyBundle>
AsymmetricVault::from_entropy(const entropy::MediaEntropy& source)
{
    return source.asym_bundle();
}

// ── SecureVault MediaEntropy boost overloads ─────────────────────────────────
//
// Defined here (not in vault.hpp) because MediaEntropy must be fully visible
// before entropy_boost() can be called.  Declared in vault.hpp.

inline Result<EncryptedPacket>
SecureVault::seal(std::span<const uint8_t>     plaintext,
                  std::span<const uint8_t>     aad,
                  const entropy::MediaEntropy& boost) const {
    auto bk = boost.entropy_boost();
    return seal(plaintext, aad, bk.span());
}

inline Result<EncryptedPacket>
SecureVault::seal(std::string_view             plaintext,
                  std::string_view             aad,
                  const entropy::MediaEntropy& boost) const {
    auto bk = boost.entropy_boost();
    return seal(
        { reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size() },
        { reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
        bk.span());
}

inline Result<SecureBuffer>
SecureVault::open(const EncryptedPacket&        packet,
                  std::span<const uint8_t>      verifier_public_key,
                  std::span<const uint8_t>      aad,
                  const entropy::MediaEntropy&  boost) const {
    auto bk = boost.entropy_boost();
    return open(packet, verifier_public_key, aad, bk.span());
}

inline Result<SecureBuffer>
SecureVault::open(const EncryptedPacket&        packet,
                  std::string_view              aad,
                  const entropy::MediaEntropy&  boost) const {
    auto bk = boost.entropy_boost();
    return open(
        packet,
        keypair_.sign_public.span(),
        { reinterpret_cast<const uint8_t*>(aad.data()), aad.size() },
        bk.span());
}

// ── AsymmetricVault MediaEntropy boost overloads ─────────────────────────────

inline Result<EncryptedPacket>
AsymmetricVault::seal(std::span<const uint8_t>       plaintext,
                      const AsymKeyBundle&            sender,
                      std::span<const uint8_t>        recipient_box_public,
                      std::span<const uint8_t>        aad,
                      const entropy::MediaEntropy&    boost) {
    auto bk = boost.entropy_boost();
    return seal(plaintext, sender, recipient_box_public, aad, bk.span());
}

inline Result<SecureBuffer>
AsymmetricVault::open(const EncryptedPacket&          packet,
                      const AsymKeyBundle&             recipient,
                      std::span<const uint8_t>         sender_sign_public,
                      std::span<const uint8_t>         aad,
                      const entropy::MediaEntropy&     boost) {
    auto bk = boost.entropy_boost();
    return open(packet, recipient, sender_sign_public, aad, bk.span());
}

} // namespace crypto
