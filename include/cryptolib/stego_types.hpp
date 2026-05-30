#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::stego — Shared Types                                             ║
 * ║                                                                            ║
 * ║  Common foundation for all steganography classes:                         ║
 * ║    StegoHeader   — 14-byte magic prefix embedded before every payload.   ║
 * ║    StegoParams   — per-algorithm tuning knobs (quality / robustness).     ║
 * ║    MediaFormat   — carrier format enum.                                   ║
 * ║    StegoCapacity — result of a capacity query.                            ║
 * ║    crc32()       — IEEE 802.3 CRC-32 (no external dependency).            ║
 * ║                                                                            ║
 * ║  StegoHeader wire format (14 bytes, all integers LE):                     ║
 * ║    [0-3]  magic       'C' 'S' 'T' 'G'                                    ║
 * ║    [4]    version     1                                                    ║
 * ║    [5]    media_type  MediaFormat as uint8_t                              ║
 * ║    [6-9]  length      payload byte count (uint32_t)                       ║
 * ║    [10-13] crc32      CRC-32 of payload bytes (uint32_t)                  ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace crypto::stego {

// ─────────────────────────────────────────────────────────────────────────────
// Untrusted-input guards.
// Media parsers read width/height/count fields from attacker-controlled files
// and feed them into allocation + pixel-index arithmetic. Without overflow and
// range checks, w*h*channels can wrap to a small value (→ heap overflow when
// DctQimEngine::blue_idx later indexes by the logical dimensions) or balloon to
// an absurd allocation (→ DoS). Every decode site funnels its dimensions through
// checked_image_bytes() so those invariants hold by construction.
// ─────────────────────────────────────────────────────────────────────────────
namespace detail {

// Generous enough for legitimate media, small enough to bound worst-case memory.
inline constexpr std::size_t MAX_IMAGE_DIM     = 1u << 16;  // 65,536 px per side
inline constexpr std::size_t MAX_IMAGE_PIXELS  = 1u << 28;  // 268M px (~805 MB RGB)
inline constexpr std::size_t MAX_FRAME_COUNT   = 1u << 20;  // 1,048,576 frames
inline constexpr std::size_t MAX_AUDIO_SAMPLES = 1u << 30;  // ~1.07e9 samples

[[nodiscard]] inline bool checked_mul(std::size_t a, std::size_t b,
                                      std::size_t& out) noexcept {
    if (a != 0 && b > (SIZE_MAX / a)) return false;
    out = a * b;
    return true;
}

} // namespace detail

// Validate untrusted width/height and return w*h*channels, or nullopt if the
// dimensions are zero, exceed sane bounds, or overflow size_t.
[[nodiscard]] inline std::optional<std::size_t>
checked_image_bytes(std::size_t w, std::size_t h, std::size_t channels = 3) noexcept {
    using namespace detail;
    if (w == 0 || h == 0) return std::nullopt;
    if (w > MAX_IMAGE_DIM || h > MAX_IMAGE_DIM) return std::nullopt;
    std::size_t px = 0, bytes = 0;
    if (!checked_mul(w, h, px)) return std::nullopt;
    if (px > MAX_IMAGE_PIXELS) return std::nullopt;
    if (!checked_mul(px, channels, bytes)) return std::nullopt;
    return bytes;
}

// ─────────────────────────────────────────────────────────────────────────────
// MediaFormat — identifies which steganographer to dispatch to.
// ─────────────────────────────────────────────────────────────────────────────
enum class MediaFormat : uint8_t {
    PPM_IMAGE  = 0,   // Portable Pixmap (.ppm), RGB24 raw pixels
    WAV_AUDIO  = 1,   // RIFF/WAVE, 16-bit signed PCM
    CRVF_VIDEO = 2,   // CryptoLib Raw Video Format (.crvf)
    BMP_IMAGE  = 3,   // Windows Bitmap (.bmp), 24-bit uncompressed
    PNG_IMAGE  = 4,   // Portable Network Graphics (.png), lossless
    FLAC_AUDIO = 5,   // Free Lossless Audio Codec (.flac) — output as WAV
    AVI_VIDEO  = 6,   // Audio Video Interleave (.avi), uncompressed only
    GIF_IMAGE  = 7,   // Graphics Interchange Format (.gif) — output as PNG
    JPEG_IMAGE = 8,   // JPEG (.jpg/.jpeg), JSteg coefficient embedding
    MP3_AUDIO  = 9,   // MPEG Layer III (.mp3), ancillary data embedding
    MP4_VIDEO  = 10,  // MPEG-4 Part 14 (.mp4), free-box container embedding
    UNKNOWN    = 0xFF
};

// ─────────────────────────────────────────────────────────────────────────────
// StegoParams — algorithm tuning.
// The defaults give good imperceptibility for typical media files.
// ─────────────────────────────────────────────────────────────────────────────
struct StegoParams {
    // ── Image (DCT/QIM) ──────────────────────────────────────────────────────
    int image_quant_step = 16;
    // Quantization step Q for QIM embedding in DCT coefficients.
    // Larger Q → more robust against JPEG re-save, but more visible distortion.
    // Range: 4 (subtle, fragile) … 32 (strong, slight blocking artifacts).

    // ── Audio (Phase Coding) ─────────────────────────────────────────────────
    // ⚠ STEGANALYSIS NOTE: The default bin range (28-35) is fixed and public.
    //   An ML classifier trained on this specific bin set can detect phase-coded
    //   payloads.  For high-security use, vary audio_bin_start per-key (both
    //   embedder and extractor must agree on the same parameters).
    int audio_frame_size      = 512;   // samples per analysis frame (power of 2)
    int audio_bin_start       = 28;    // first target frequency bin (~2.4 kHz @ 44.1 kHz)
    int audio_bin_count       = 8;     // bits encoded per frame (= bins used)
    // 8 bits/frame × (total_samples/512) frames = capacity in bits.
    // For 44.1 kHz mono: 10 s → ~690 bytes; 60 s → ~4 kB.
};

// ─────────────────────────────────────────────────────────────────────────────
// StegoCapacity — returned by capacity queries.
// ─────────────────────────────────────────────────────────────────────────────
struct StegoCapacity {
    std::size_t max_payload_bytes;  // maximum payload the carrier can hide
    std::size_t header_bytes;       // overhead used by StegoHeader (always 14)
    std::string description;        // human-readable summary
};

// ─────────────────────────────────────────────────────────────────────────────
// CRC-32 (IEEE 802.3, polynomial 0xEDB88320).
// Implemented as a constexpr-friendly lookup table; no external dependency.
// ─────────────────────────────────────────────────────────────────────────────
namespace detail {

inline constexpr std::array<uint32_t, 256> make_crc32_table() noexcept {
    std::array<uint32_t, 256> t{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[i] = c;
    }
    return t;
}

inline constexpr auto CRC32_TABLE = make_crc32_table();

} // namespace detail

[[nodiscard]] inline uint32_t crc32(std::span<const uint8_t> data) noexcept {
    uint32_t c = 0xFFFF'FFFFu;
    for (uint8_t b : data)
        c = detail::CRC32_TABLE[(c ^ b) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFF'FFFFu;
}

// ─────────────────────────────────────────────────────────────────────────────
// StegoHeader — prefixed before every payload during embedding.
// The extractor reads this first to validate and determine payload length.
// ─────────────────────────────────────────────────────────────────────────────
struct StegoHeader {
    static constexpr std::size_t SIZE    = 14;
    // ⚠ FORENSIC NOTE: This fixed 4-byte magic ('CSTG') is a detectable
    //   fingerprint in extracted streams.  An adversary who successfully
    //   extracts the raw bit stream can confirm steganographic content by
    //   checking for this signature.  The payload itself is AEAD-encrypted
    //   so content remains confidential, but existence is provable.
    //   Future enhancement: encrypt the header with a stream cipher keyed
    //   to the embedding key, so the magic only appears after decryption.
    static constexpr uint8_t     MAGIC[] = {'C', 'S', 'T', 'G'};
    static constexpr uint8_t     VERSION = 1;

    MediaFormat format      = MediaFormat::UNKNOWN;
    uint32_t    payload_len = 0;
    uint32_t    payload_crc = 0;

    // Serialise to exactly SIZE bytes (little-endian integers).
    [[nodiscard]] Bytes serialise() const {
        Bytes out(SIZE);
        out[0] = 'C'; out[1] = 'S'; out[2] = 'T'; out[3] = 'G';
        out[4] = VERSION;
        out[5] = static_cast<uint8_t>(format);
        out[6]  = static_cast<uint8_t>(payload_len);
        out[7]  = static_cast<uint8_t>(payload_len >> 8);
        out[8]  = static_cast<uint8_t>(payload_len >> 16);
        out[9]  = static_cast<uint8_t>(payload_len >> 24);
        out[10] = static_cast<uint8_t>(payload_crc);
        out[11] = static_cast<uint8_t>(payload_crc >> 8);
        out[12] = static_cast<uint8_t>(payload_crc >> 16);
        out[13] = static_cast<uint8_t>(payload_crc >> 24);
        return out;
    }

    // Deserialise from a byte span of at least SIZE bytes.
    [[nodiscard]] static Result<StegoHeader> deserialise(
        std::span<const uint8_t> raw)
    {
        if (raw.size() < SIZE)
            return Result<StegoHeader>::err("stego header: buffer too small");
        if (raw[0] != 'C' || raw[1] != 'S' || raw[2] != 'T' || raw[3] != 'G')
            return Result<StegoHeader>::err("stego header: invalid magic bytes");
        if (raw[4] != VERSION)
            return Result<StegoHeader>::err("stego header: unsupported version");

        StegoHeader h;
        h.format      = static_cast<MediaFormat>(raw[5]);
        h.payload_len = static_cast<uint32_t>(raw[6])
                      | static_cast<uint32_t>(raw[7])  << 8
                      | static_cast<uint32_t>(raw[8])  << 16
                      | static_cast<uint32_t>(raw[9])  << 24;
        h.payload_crc = static_cast<uint32_t>(raw[10])
                      | static_cast<uint32_t>(raw[11]) << 8
                      | static_cast<uint32_t>(raw[12]) << 16
                      | static_cast<uint32_t>(raw[13]) << 24;
        return Result<StegoHeader>::ok(std::move(h));
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility: build the full embedded byte stream = header || payload.
// This is what every steganographer actually embeds.
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] inline Bytes make_embed_stream(
    std::span<const uint8_t> payload,
    MediaFormat               fmt)
{
    // Guard against overflow on 32-bit platforms: payload.size() could exceed
    // uint32_t max, silently truncating payload_len.
    if (payload.size() > static_cast<std::size_t>(UINT32_MAX))
        return {};  // Caller should check for empty result

    StegoHeader hdr;
    hdr.format      = fmt;
    hdr.payload_len = static_cast<uint32_t>(payload.size());
    hdr.payload_crc = crc32(payload);

    auto hdr_bytes = hdr.serialise();
    Bytes stream;
    stream.reserve(hdr_bytes.size() + payload.size());
    stream.insert(stream.end(), hdr_bytes.begin(), hdr_bytes.end());
    stream.insert(stream.end(), payload.begin(), payload.end());
    return stream;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: validate header + CRC, return the payload portion.
// ─────────────────────────────────────────────────────────────────────────────
[[nodiscard]] inline Result<Bytes> parse_embed_stream(
    std::span<const uint8_t> stream)
{
    auto hdr_res = StegoHeader::deserialise(stream);
    if (hdr_res.is_err())
        return Result<Bytes>::err(hdr_res.error().message);

    const auto& hdr = hdr_res.value();
    const std::size_t expected_total = StegoHeader::SIZE + hdr.payload_len;

    if (stream.size() < expected_total)
        return Result<Bytes>::err("stego stream: truncated payload (got "
            + std::to_string(stream.size()) + " bytes, need "
            + std::to_string(expected_total) + ")");

    auto payload_span = stream.subspan(StegoHeader::SIZE, hdr.payload_len);
    uint32_t actual_crc = crc32(payload_span);
    if (actual_crc != hdr.payload_crc)
        return Result<Bytes>::err("stego stream: CRC-32 mismatch — data corrupted");

    return Result<Bytes>::ok(Bytes(payload_span.begin(), payload_span.end()));
}

} // namespace crypto::stego
