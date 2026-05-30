#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::stego::MediaGenerator                                            ║
 * ║                                                                            ║
 * ║  Programmatic cover-media factory for steganography.                      ║
 * ║                                                                            ║
 * ║  Produces synthetic but physically plausible carrier files that contain  ║
 * ║  enough entropy for MediaEntropy and enough redundancy for steganography. ║
 * ║  All outputs are byte-for-byte deterministic given the same seed.         ║
 * ║                                                                            ║
 * ║  ┌─────────────────────────────────────────────────────────────────────┐  ║
 * ║  │  GENERATED FORMATS                                                  │  ║
 * ║  │                                                                     │  ║
 * ║  │  PPM  — Portable Pixmap P6 (binary RGB24)                          │  ║
 * ║  │         gradient background + Gaussian photon-shot noise            │  ║
 * ║  │         → same pixel statistics as a real camera RAW file           │  ║
 * ║  │                                                                     │  ║
 * ║  │  WAV  — RIFF/WAVE 16-bit PCM (mono or stereo)                      │  ║
 * ║  │         sinusoidal tone + Gaussian thermal noise floor               │  ║
 * ║  │         → passes HAS perceptual tests, non-trivial frequency content ║
 * ║  │                                                                     │  ║
 * ║  │  CRVF — CryptoLib Raw Video Format                                  │  ║
 * ║  │         per-frame RGB gradient + inter-frame variation noise        │  ║
 * ║  │         → each frame is unique (mirrors sensor photon shot noise)   │  ║
 * ║  └─────────────────────────────────────────────────────────────────────┘  ║
 * ║                                                                            ║
 * ║  SEPARATION OF CONCERNS                                                   ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║  MediaGenerator creates carrier files.                                   ║
 * ║  ImageSteganographer / AudioSteganographer / VideoSteganographer embed   ║
 * ║  payloads into carrier files.                                             ║
 * ║  These responsibilities are entirely separate; neither class imports     ║
 * ║  or depends on the other.                                                 ║
 * ║                                                                            ║
 * ║  USAGE                                                                     ║
 * ║    namespace MG = crypto::stego;                                          ║
 * ║    MG::MediaGenerator::generate_ppm("/tmp/cover.ppm",  640, 480);        ║
 * ║    MG::MediaGenerator::generate_wav("/tmp/cover.wav",  44100, 1, 10.0);  ║
 * ║    MG::MediaGenerator::generate_crvf("/tmp/cover.crvf",320, 240, 30, 60);║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "stego_types.hpp"
#include "stego_video.hpp"   // for VideoSteganographer::CrvfHeader + write_crvf
#include "stego_png.hpp"     // for stbi_write_png_to_func (PNG/GIF generation)

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <numbers>
#include <string>
#include <vector>

namespace crypto::stego {

// ─────────────────────────────────────────────────────────────────────────────
// MediaGeneratorParams — controls the visual / auditory character of the output.
// Declared outside MediaGenerator so it can appear as a default argument.
// ─────────────────────────────────────────────────────────────────────────────
struct MediaGeneratorParams {
    // ── PPM image ─────────────────────────────────────────────────────────────
    uint32_t ppm_seed           = 0xDEAD'CAFE; // PRNG seed
    double   ppm_noise_std      = 12.0;        // Gaussian σ for photon-shot noise
    bool     ppm_color_gradient = true;        // gradient + noise vs flat noise

    // ── WAV audio ─────────────────────────────────────────────────────────────
    uint32_t wav_seed      = 0xBEEF'1234;
    double   wav_tone_hz   = 440.0;   // fundamental frequency (A4)
    double   wav_tone_amp  = 0.60;    // [0..1], normalised amplitude
    double   wav_noise_std = 0.04;    // Gaussian σ thermal noise floor
    bool     wav_harmonics = true;    // add 2nd + 3rd harmonics

    // ── CRVF video ────────────────────────────────────────────────────────────
    uint32_t crvf_seed         = 0xCAFE'BABE;
    uint8_t  crvf_noise_bits   = 3;   // LSB noise depth per channel [1..6]
    bool     crvf_frame_offset = true;// each frame has a unique hue bias
};

// ─────────────────────────────────────────────────────────────────────────────
class MediaGenerator {
public:
    // Expose params type as a nested alias for ergonomic usage.
    using Params = MediaGeneratorParams;

    // ─────────────────────────────────────────────────────────────────────────
    // generate_ppm
    // ─────────────────────────────────────────────────────────────────────────
    /// Write a P6 PPM file with a colour-gradient background and Gaussian
    /// photon-shot noise.  The noise is sampled using the Box-Muller transform.
    ///
    /// @param path    output file path (should end in .ppm)
    /// @param width   image width  in pixels (must be ≥ 8)
    /// @param height  image height in pixels (must be ≥ 8)
    /// @param p       generator parameters (optional — defaults are sane)
    [[nodiscard]] static Result<void> generate_ppm(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_ppm — "
                                     "dimensions must be ≥ 8×8");

        LcgRng rng(p.ppm_seed);
        const std::size_t npixels = static_cast<std::size_t>(width) * height;
        std::vector<uint8_t> pixels(npixels * 3);

        for (uint32_t row = 0; row < height; ++row) {
            for (uint32_t col = 0; col < width; ++col) {
                double noise_r, noise_g, noise_b, dummy;
                gauss(rng, noise_r, noise_g);
                gauss(rng, noise_b, dummy);
                noise_r *= p.ppm_noise_std;
                noise_g *= p.ppm_noise_std;
                noise_b *= p.ppm_noise_std;

                double base_r, base_g, base_b;
                if (p.ppm_color_gradient) {
                    base_r = 30.0 + (col * 195.0 / (width  - 1));
                    base_g = 30.0 + (row * 165.0 / (height - 1));
                    base_b = 60.0 + ((col + row) * 100.0
                             / static_cast<double>(width + height - 2));
                } else {
                    base_r = base_g = base_b = 128.0;
                }

                const std::size_t idx = (static_cast<std::size_t>(row) * width + col) * 3;
                pixels[idx + 0] = clamp8(base_r + noise_r);
                pixels[idx + 1] = clamp8(base_g + noise_g);
                pixels[idx + 2] = clamp8(base_b + noise_b);
            }
        }

        // Write P6 PPM
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err(
            "MediaGenerator::generate_ppm — cannot open '" + path + "' for writing");

        f << "P6\n" << width << ' ' << height << "\n255\n";
        f.write(reinterpret_cast<const char*>(pixels.data()),
                static_cast<std::streamsize>(pixels.size()));
        if (!f) return Result<void>::err(
            "MediaGenerator::generate_ppm — write error on '" + path + "'");

        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_wav
    // ─────────────────────────────────────────────────────────────────────────
    /// Write a RIFF/WAV file with a sinusoidal tone, optional harmonics, and a
    /// Gaussian thermal-noise floor that mimics microphone self-noise.
    ///
    /// @param path         output file path (should end in .wav)
    /// @param sample_rate  samples per second (e.g. 44100)
    /// @param channels     1 = mono, 2 = stereo (same signal on both channels)
    /// @param duration_s   duration in seconds (e.g. 5.0 for 5 seconds)
    /// @param p            generator parameters (optional — defaults are sane)
    [[nodiscard]] static Result<void> generate_wav(
        const std::string& path,
        uint32_t           sample_rate,
        uint16_t           channels,
        double             duration_s,
        const Params&      p = Params{})
    {
        if (sample_rate < 8000 || sample_rate > 192000)
            return Result<void>::err("MediaGenerator::generate_wav — "
                                     "sample_rate must be in [8000, 192000]");
        if (channels == 0 || channels > 8)
            return Result<void>::err("MediaGenerator::generate_wav — "
                                     "channels must be in [1, 8]");
        if (duration_s < 0.1)
            return Result<void>::err("MediaGenerator::generate_wav — "
                                     "duration must be ≥ 0.1 s");

        LcgRng rng(p.wav_seed);

        const auto num_samples = static_cast<uint32_t>(
            std::round(duration_s * sample_rate));

        std::vector<int16_t> interleaved;
        interleaved.reserve(static_cast<std::size_t>(num_samples) * channels);

        for (uint32_t i = 0; i < num_samples; ++i) {
            const double t = static_cast<double>(i) / sample_rate;

            double sample = p.wav_tone_amp
                          * std::sin(2.0 * std::numbers::pi * p.wav_tone_hz * t);

            if (p.wav_harmonics) {
                // 2nd harmonic at half amplitude, 3rd at quarter
                sample += 0.5 * p.wav_tone_amp
                        * std::sin(4.0 * std::numbers::pi * p.wav_tone_hz * t);
                sample += 0.25 * p.wav_tone_amp
                        * std::sin(6.0 * std::numbers::pi * p.wav_tone_hz * t);
                // Normalise so peak stays ≤ 1.0
                sample /= (1.0 + 0.5 + 0.25);
            }

            // Add Gaussian thermal-noise floor
            double n1, n2;
            gauss(rng, n1, n2);
            sample += n1 * p.wav_noise_std;

            const int16_t s = static_cast<int16_t>(
                std::clamp(sample * 32767.0, -32768.0, 32767.0));

            for (uint16_t ch = 0; ch < channels; ++ch)
                interleaved.push_back(s);
        }

        // Write RIFF/WAV header + samples
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err(
            "MediaGenerator::generate_wav — cannot open '" + path + "' for writing");

        const uint32_t data_size   = static_cast<uint32_t>(interleaved.size() * 2);
        const uint32_t file_size   = 36 + data_size;
        const uint32_t byte_rate   = sample_rate * channels * 2;
        const uint16_t block_align = static_cast<uint16_t>(channels * 2);

        auto wu32 = [&](uint32_t v) {
            uint8_t b[4] = {
                uint8_t(v),       uint8_t(v >> 8),
                uint8_t(v >> 16), uint8_t(v >> 24)
            };
            f.write(reinterpret_cast<const char*>(b), 4);
        };
        auto wu16 = [&](uint16_t v) {
            uint8_t b[2] = { uint8_t(v), uint8_t(v >> 8) };
            f.write(reinterpret_cast<const char*>(b), 2);
        };

        f.write("RIFF", 4); wu32(file_size);
        f.write("WAVE", 4);
        f.write("fmt ", 4); wu32(16);
        wu16(1);                // PCM
        wu16(channels);
        wu32(sample_rate);
        wu32(byte_rate);
        wu16(block_align);
        wu16(16);               // bits per sample
        f.write("data", 4); wu32(data_size);
        f.write(reinterpret_cast<const char*>(interleaved.data()),
                static_cast<std::streamsize>(data_size));

        if (!f) return Result<void>::err(
            "MediaGenerator::generate_wav — write error on '" + path + "'");

        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_crvf
    // ─────────────────────────────────────────────────────────────────────────
    /// Write a CRVF (CryptoLib Raw Video Format) file with:
    ///   - A smooth RGB-gradient base that varies across the frame.
    ///   - Per-frame inter-frame variation (simulates photon-shot noise and
    ///     video encoder residuals).
    ///   - Optional per-frame hue bias so that each frame is visually distinct.
    ///
    /// @param path        output file path (should end in .crvf)
    /// @param width       frame width  in pixels (must be ≥ 8)
    /// @param height      frame height in pixels (must be ≥ 8)
    /// @param fps         frames per second (stored in header, e.g. 30)
    /// @param num_frames  total frame count
    /// @param p           generator parameters (optional — defaults are sane)
    [[nodiscard]] static Result<void> generate_crvf(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        uint32_t           fps,
        uint32_t           num_frames,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_crvf — "
                                     "frame dimensions must be ≥ 8×8");
        if (fps == 0)
            return Result<void>::err("MediaGenerator::generate_crvf — "
                                     "fps must be > 0");
        if (num_frames == 0)
            return Result<void>::err("MediaGenerator::generate_crvf — "
                                     "num_frames must be > 0");

        LcgRng rng(p.crvf_seed);
        const std::size_t frame_bytes = static_cast<std::size_t>(width) * height * 3;
        const uint8_t noise_mask = static_cast<uint8_t>((1u << p.crvf_noise_bits) - 1u);

        std::vector<std::vector<uint8_t>> frames(num_frames,
                                                  std::vector<uint8_t>(frame_bytes));

        for (uint32_t fi = 0; fi < num_frames; ++fi) {
            auto& frame = frames[fi];

            // Per-frame hue offset in [0, 50]: gives each frame a subtle tint
            const double hue_bias = p.crvf_frame_offset
                ? (static_cast<double>(fi) * 50.0
                   / std::max(1u, num_frames - 1u))
                : 0.0;

            for (uint32_t row = 0; row < height; ++row) {
                for (uint32_t col = 0; col < width; ++col) {
                    const std::size_t idx =
                        (static_cast<std::size_t>(row) * width + col) * 3;

                    // Gradient base [0..205] + hue bias
                    const double r_base = hue_bias
                        + (col * 205.0 / (width  - 1));
                    const double g_base = hue_bias
                        + (row * 205.0 / (height - 1));
                    const double b_base = hue_bias
                        + ((col + row) * 100.0
                           / static_cast<double>(width + height - 2));

                    // Per-pixel noise via LCG — produces distinct LSBs
                    const uint8_t noise = static_cast<uint8_t>(
                        rng.next() & noise_mask);

                    frame[idx + 0] = clamp8(r_base + noise);
                    frame[idx + 1] = clamp8(g_base + noise);
                    frame[idx + 2] = clamp8(b_base + noise);
                }
            }
        }

        VideoSteganographer::CrvfHeader hdr;
        hdr.width       = width;
        hdr.height      = height;
        hdr.fps_num     = fps;
        hdr.fps_den     = 1;
        hdr.frame_count = num_frames;
        hdr.pixel_fmt   = 0; // RGB24

        return VideoSteganographer::write_crvf(path, hdr, frames);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_bmp — 24-bit uncompressed BMP with gradient + noise
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_bmp(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_bmp — dimensions must be >= 8x8");

        LcgRng rng(p.ppm_seed ^ 0x424D5000u); // 'BMP\0'
        std::size_t row_bytes = width * 3;
        std::size_t row_pad = (4 - (row_bytes % 4)) % 4;
        std::size_t stride = row_bytes + row_pad;
        std::size_t pixel_data_size = stride * height;

        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_bmp — cannot write '" + path + "'");

        // BMP File Header (14 bytes)
        uint32_t file_size = 14 + 40 + static_cast<uint32_t>(pixel_data_size);
        uint8_t fh[14] = {'B', 'M'};
        fh[2]=uint8_t(file_size); fh[3]=uint8_t(file_size>>8);
        fh[4]=uint8_t(file_size>>16); fh[5]=uint8_t(file_size>>24);
        fh[10]=54; // pixel offset = 14+40
        f.write(reinterpret_cast<char*>(fh), 14);

        // DIB Header (BITMAPINFOHEADER, 40 bytes)
        uint8_t dib[40] = {};
        dib[0]=40; // biSize
        dib[4]=uint8_t(width); dib[5]=uint8_t(width>>8);
        dib[6]=uint8_t(width>>16); dib[7]=uint8_t(width>>24);
        dib[8]=uint8_t(height); dib[9]=uint8_t(height>>8);
        dib[10]=uint8_t(height>>16); dib[11]=uint8_t(height>>24);
        dib[12]=1; // biPlanes
        dib[14]=24; // biBitCount
        // biCompression = 0 (BI_RGB)
        uint32_t img_size = static_cast<uint32_t>(pixel_data_size);
        dib[20]=uint8_t(img_size); dib[21]=uint8_t(img_size>>8);
        dib[22]=uint8_t(img_size>>16); dib[23]=uint8_t(img_size>>24);
        f.write(reinterpret_cast<char*>(dib), 40);

        // Pixel data (bottom-up, BGR)
        uint8_t pad_bytes[3] = {0, 0, 0};
        for (uint32_t row = 0; row < height; ++row) {
            uint32_t src_row = height - 1 - row; // bottom-up
            for (uint32_t col = 0; col < width; ++col) {
                double n_r, n_g, n_b, dummy;
                gauss(rng, n_r, n_g); gauss(rng, n_b, dummy);
                n_r *= p.ppm_noise_std; n_g *= p.ppm_noise_std; n_b *= p.ppm_noise_std;

                double r = 30.0 + (col * 195.0 / (width-1)) + n_r;
                double g = 30.0 + (src_row * 165.0 / (height-1)) + n_g;
                double b = 60.0 + ((col + src_row) * 100.0 / double(width+height-2)) + n_b;

                uint8_t bgr[3] = {clamp8(b), clamp8(g), clamp8(r)};
                f.write(reinterpret_cast<char*>(bgr), 3);
            }
            if (row_pad > 0)
                f.write(reinterpret_cast<char*>(pad_bytes), static_cast<std::streamsize>(row_pad));
        }

        if (!f) return Result<void>::err("MediaGenerator::generate_bmp — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_png — PNG with gradient + noise (via stb_image_write)
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_png(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_png — dimensions must be >= 8x8");

        // Generate RGB pixels (same as PPM)
        LcgRng rng(p.ppm_seed ^ 0x504E4700u); // 'PNG\0'
        std::vector<uint8_t> pixels(static_cast<std::size_t>(width) * height * 3);

        for (uint32_t row = 0; row < height; ++row) {
            for (uint32_t col = 0; col < width; ++col) {
                double n_r, n_g, n_b, dummy;
                gauss(rng, n_r, n_g); gauss(rng, n_b, dummy);
                n_r *= p.ppm_noise_std; n_g *= p.ppm_noise_std; n_b *= p.ppm_noise_std;

                double r = 30.0 + (col * 195.0 / (width-1)) + n_r;
                double g = 30.0 + (row * 165.0 / (height-1)) + n_g;
                double b = 60.0 + ((col + row) * 100.0 / double(width+height-2)) + n_b;

                std::size_t idx = (static_cast<std::size_t>(row) * width + col) * 3;
                pixels[idx+0] = clamp8(r);
                pixels[idx+1] = clamp8(g);
                pixels[idx+2] = clamp8(b);
            }
        }

        // Write PNG using stb_image_write callback
        struct PngCtx { std::vector<uint8_t> buf; };
        PngCtx ctx;
        auto cb = [](void* c, void* d, int sz) {
            auto* pc = static_cast<PngCtx*>(c);
            auto* bytes = static_cast<uint8_t*>(d);
            pc->buf.insert(pc->buf.end(), bytes, bytes + sz);
        };

        int ok = stbi_write_png_to_func(cb, &ctx,
            static_cast<int>(width), static_cast<int>(height), 3,
            pixels.data(), static_cast<int>(width * 3));
        if (!ok) return Result<void>::err("MediaGenerator::generate_png — encode failed");

        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_png — cannot write '" + path + "'");
        f.write(reinterpret_cast<const char*>(ctx.buf.data()),
                static_cast<std::streamsize>(ctx.buf.size()));
        if (!f) return Result<void>::err("MediaGenerator::generate_png — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_gif — valid GIF89a with a 256-colour palette (no LZW — uses
    // uncompressed sub-blocks via the clear-code trick for simplicity)
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_gif(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_gif — dimensions must be >= 8x8");

        LcgRng rng(p.ppm_seed ^ 0x47494600u); // 'GIF\0'

        // Build a 256-colour palette (6×6×7 colour cube ≈ 252 + 4 extras)
        struct RGB { uint8_t r, g, b; };
        std::vector<RGB> palette(256);
        int idx = 0;
        for (int r = 0; r < 6 && idx < 256; ++r)
            for (int g = 0; g < 6 && idx < 256; ++g)
                for (int b = 0; b < 7 && idx < 256; ++b)
                    palette[idx++] = {
                        uint8_t(r * 51), uint8_t(g * 51), uint8_t(b * 42)};
        while (idx < 256) palette[idx++] = {0, 0, 0};

        // Map pixels to palette indices (nearest in RGB space)
        std::vector<uint8_t> indices(static_cast<std::size_t>(width) * height);
        for (uint32_t row = 0; row < height; ++row) {
            for (uint32_t col = 0; col < width; ++col) {
                double n_r, n_g, n_b, dummy;
                gauss(rng, n_r, n_g); gauss(rng, n_b, dummy);
                n_r *= p.ppm_noise_std * 0.5; n_g *= p.ppm_noise_std * 0.5;
                n_b *= p.ppm_noise_std * 0.5;

                uint8_t pr = clamp8(30.0 + col * 195.0 / (width - 1) + n_r);
                uint8_t pg = clamp8(30.0 + row * 165.0 / (height - 1) + n_g);
                uint8_t pb = clamp8(60.0 + (col + row) * 100.0 / double(width + height - 2) + n_b);

                // Find nearest palette entry
                int best = 0;
                int best_dist = 999999;
                for (int i = 0; i < 256; ++i) {
                    int dr = int(pr) - int(palette[i].r);
                    int dg = int(pg) - int(palette[i].g);
                    int db = int(pb) - int(palette[i].b);
                    int dist = dr * dr + dg * dg + db * db;
                    if (dist < best_dist) { best_dist = dist; best = i; }
                }
                indices[static_cast<std::size_t>(row) * width + col] = static_cast<uint8_t>(best);
            }
        }

        // Write GIF89a
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_gif — cannot write '" + path + "'");

        auto wu16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v >> 8)};
            f.write(reinterpret_cast<char*>(b), 2);
        };

        // Header
        f.write("GIF89a", 6);

        // Logical screen descriptor
        wu16(static_cast<uint16_t>(width));
        wu16(static_cast<uint16_t>(height));
        uint8_t lsd_packed = 0x80  // global colour table flag
                           | (7 << 4) // colour resolution (8 bits)
                           | 7;       // GCT size = 2^(7+1) = 256
        f.put(static_cast<char>(lsd_packed));
        f.put(0); // background colour index
        f.put(0); // pixel aspect ratio

        // Global Colour Table (256 × 3 = 768 bytes)
        for (int i = 0; i < 256; ++i) {
            f.put(static_cast<char>(palette[i].r));
            f.put(static_cast<char>(palette[i].g));
            f.put(static_cast<char>(palette[i].b));
        }

        // Image descriptor
        f.put(0x2C); // image separator
        wu16(0);      // left
        wu16(0);      // top
        wu16(static_cast<uint16_t>(width));
        wu16(static_cast<uint16_t>(height));
        f.put(0);     // packed (no local table, not interlaced)

        // Image data using LZW minimum code size = 8 (for 256 colours)
        uint8_t min_code_size = 8;
        f.put(static_cast<char>(min_code_size));

        // LZW encoding: emit literals with proper code-size tracking.
        // The decoder adds no table entry for the first code after clear,
        // then adds one entry per subsequent code. Code size grows when
        // next_code reaches 2^code_size.
        uint16_t clear_code = 256;
        uint16_t eoi_code = 257;
        int code_size = 9;
        int next_code = 258;
        bool first_after_clear = true;

        // Bit packing state
        Bytes sub_block_data;
        uint32_t bit_buffer = 0;
        int bits_in_buffer = 0;

        auto emit_code = [&](uint16_t code) {
            bit_buffer |= (static_cast<uint32_t>(code) << bits_in_buffer);
            bits_in_buffer += code_size;
            while (bits_in_buffer >= 8) {
                sub_block_data.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }
        };

        auto flush_sub_blocks = [&]() {
            std::size_t off = 0;
            while (off < sub_block_data.size()) {
                std::size_t chunk = std::min<std::size_t>(255, sub_block_data.size() - off);
                f.put(static_cast<char>(chunk));
                f.write(reinterpret_cast<const char*>(sub_block_data.data() + off),
                        static_cast<std::streamsize>(chunk));
                off += chunk;
            }
            sub_block_data.clear();
        };

        emit_code(clear_code);

        for (std::size_t i = 0; i < indices.size(); ++i) {
            emit_code(indices[i]);

            if (first_after_clear) {
                first_after_clear = false;
            } else {
                next_code++;
                if (next_code == (1 << code_size)) {
                    if (code_size < 12) {
                        code_size++;
                    } else {
                        // Table full — reset
                        emit_code(clear_code);
                        code_size = 9;
                        next_code = 258;
                        first_after_clear = true;
                    }
                }
            }
        }

        emit_code(eoi_code);

        if (bits_in_buffer > 0)
            sub_block_data.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));

        flush_sub_blocks();
        f.put(0); // block terminator

        // Trailer
        f.put(0x3B);

        if (!f) return Result<void>::err("MediaGenerator::generate_gif — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_avi — uncompressed AVI with noise frames
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_avi(
        const std::string& path,
        uint32_t           width,
        uint32_t           height,
        uint32_t           fps,
        uint32_t           num_frames,
        const Params&      p = Params{})
    {
        if (width < 8 || height < 8)
            return Result<void>::err("MediaGenerator::generate_avi — dimensions must be >= 8x8");
        if (fps == 0 || num_frames == 0)
            return Result<void>::err("MediaGenerator::generate_avi — fps and frames must be > 0");

        LcgRng rng(p.crvf_seed ^ 0x41564900u); // 'AVI\0'
        std::size_t frame_bytes = static_cast<std::size_t>(width) * height * 3;
        std::size_t row_bytes = width * 3;
        std::size_t row_pad = (4 - (row_bytes % 4)) % 4;
        std::size_t padded_frame = (row_bytes + row_pad) * height;

        // Build frames as RGB top-down, AviSteganographer will read them
        std::vector<std::vector<uint8_t>> frames(num_frames);
        for (uint32_t fi = 0; fi < num_frames; ++fi) {
            frames[fi].resize(frame_bytes);
            double hue_bias = (static_cast<double>(fi) * 50.0 / std::max(1u, num_frames - 1u));
            for (uint32_t row = 0; row < height; ++row) {
                for (uint32_t col = 0; col < width; ++col) {
                    std::size_t idx = (static_cast<std::size_t>(row) * width + col) * 3;
                    uint8_t noise = static_cast<uint8_t>(rng.next() & 0x07);
                    frames[fi][idx+0] = clamp8(hue_bias + col * 205.0 / (width-1) + noise);
                    frames[fi][idx+1] = clamp8(hue_bias + row * 205.0 / (height-1) + noise);
                    frames[fi][idx+2] = clamp8(hue_bias + (col+row) * 100.0 / double(width+height-2) + noise);
                }
            }
        }

        // Write AVI manually
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_avi — cannot write '" + path + "'");

        auto w32 = [&](uint32_t v) {
            uint8_t b[4] = {uint8_t(v), uint8_t(v>>8), uint8_t(v>>16), uint8_t(v>>24)};
            f.write(reinterpret_cast<char*>(b), 4);
        };
        auto w16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v>>8)};
            f.write(reinterpret_cast<char*>(b), 2);
        };

        std::size_t movi_size = 4;
        for (std::size_t i = 0; i < num_frames; ++i)
            movi_size += 8 + padded_frame;

        std::size_t hdrl_size = 4 + 8 + 56 + 8 + 4 + 8 + 56 + 8 + 40;
        std::size_t file_size = 4 + 8 + hdrl_size + 8 + movi_size;

        f.write("RIFF", 4); w32(static_cast<uint32_t>(file_size));
        f.write("AVI ", 4);

        // hdrl
        f.write("LIST", 4); w32(static_cast<uint32_t>(hdrl_size));
        f.write("hdrl", 4);

        // avih
        f.write("avih", 4); w32(56);
        w32(1000000 / fps); w32(0); w32(0); w32(0x10);
        w32(num_frames); w32(0); w32(1);
        w32(static_cast<uint32_t>(padded_frame));
        w32(width); w32(height);
        w32(0); w32(0); w32(0); w32(0);

        // strl
        f.write("LIST", 4); w32(4 + 8 + 56 + 8 + 40);
        f.write("strl", 4);

        // strh
        f.write("strh", 4); w32(56);
        f.write("vids", 4); w32(0); w32(0);
        w16(0); w16(0); w32(0); w32(1); w32(fps); w32(0);
        w32(num_frames); w32(static_cast<uint32_t>(padded_frame));
        w32(0xFFFFFFFF); w32(0);
        w16(0); w16(0); w16(static_cast<uint16_t>(width)); w16(static_cast<uint16_t>(height));

        // strf (BITMAPINFOHEADER)
        f.write("strf", 4); w32(40);
        w32(40); w32(width); w32(height);
        w16(1); w16(24); w32(0);
        w32(static_cast<uint32_t>(padded_frame));
        w32(0); w32(0); w32(0); w32(0);

        // movi
        f.write("LIST", 4); w32(static_cast<uint32_t>(movi_size));
        f.write("movi", 4);

        for (uint32_t fi = 0; fi < num_frames; ++fi) {
            f.write("00db", 4); w32(static_cast<uint32_t>(padded_frame));
            // Write BGR bottom-up
            for (uint32_t y = 0; y < height; ++y) {
                uint32_t src_y = height - 1 - y;
                for (uint32_t x = 0; x < width; ++x) {
                    std::size_t si = (src_y * width + x) * 3;
                    uint8_t bgr[3] = {frames[fi][si+2], frames[fi][si+1], frames[fi][si+0]};
                    f.write(reinterpret_cast<char*>(bgr), 3);
                }
                uint8_t pad_row[3] = {0,0,0};
                if (row_pad > 0) f.write(reinterpret_cast<char*>(pad_row), static_cast<std::streamsize>(row_pad));
            }
        }

        if (!f) return Result<void>::err("MediaGenerator::generate_avi — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_mp3 — valid MPEG1 Layer III with silence frames
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_mp3(
        const std::string& path,
        double             duration_s = 5.0,
        int                bitrate_kbps = 128)
    {
        // Generate valid MPEG1 Layer III mono frames that decode as silence.
        // Using mono mode simplifies side info (17 bytes instead of 32 for stereo)
        // and avoids decoder issues with stereo mode requiring channel data.
        int samplerate = 44100;
        int num_frames = static_cast<int>(duration_s * samplerate / 1152.0);

        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_mp3 — cannot write '" + path + "'");

        // Determine bitrate index
        int br_idx = 0;
        constexpr int brtable[] = {0,32,40,48,56,64,80,96,112,128,160,192,224,256,320};
        for (int i = 1; i < 15; ++i) if (brtable[i] == bitrate_kbps) { br_idx = i; break; }
        if (br_idx == 0) br_idx = 9; // default 128kbps

        for (int i = 0; i < num_frames; ++i) {
            // MPEG1 Layer III header (4 bytes)
            // 0xFF 0xFB = sync + MPEG1 + Layer III + no CRC
            // Byte 2: bitrate_idx(4) + samplerate_idx(2=00→44100) + padding(1) + private(1)
            // Byte 3: mode(2=11→mono) + mode_ext(2) + copyright(1) + original(1=1) + emphasis(2)
            uint8_t header[4] = {
                0xFF, 0xFB,
                static_cast<uint8_t>((br_idx << 4) | 0x00),
                0xC4  // mode=11(mono), mode_ext=00, copyright=0, original=1, emphasis=00
            };

            int cur_frame_size = 144 * (bitrate_kbps * 1000) / samplerate;
            f.write(reinterpret_cast<char*>(header), 4);

            // Side information (17 bytes for mono MPEG1 Layer III)
            // Structure (bit-level):
            //   main_data_begin: 9 bits = 0 (no bit reservoir)
            //   private_bits:    5 bits = 0
            //   scfsi:           4 bits = 0 (1 band × 4 bits)
            //   -- granule 0 --
            //   part2_3_length: 12 bits = 0 (no Huffman data)
            //   big_values:      9 bits = 0
            //   global_gain:     8 bits = 0 (silence)
            //   scalefac_compress: 4 bits = 0
            //   window_switching: 1 bit = 0
            //   table_select[0]: 5 bits = 0
            //   table_select[1]: 5 bits = 0
            //   table_select[2]: 5 bits = 0
            //   region0_count:   4 bits = 0
            //   region1_count:   3 bits = 0
            //   preflag:         1 bit = 0
            //   scalefac_scale:  1 bit = 0
            //   count1table_select: 1 bit = 0
            //   -- granule 1 -- (same)
            //   All zero → part2_3_length = 0 → decoder outputs silence
            std::vector<uint8_t> side_info(17, 0);
            f.write(reinterpret_cast<char*>(side_info.data()), 17);

            // Remaining frame bytes are ancillary data (zeros = no audio content)
            int remaining = cur_frame_size - 4 - 17;
            if (remaining > 0) {
                std::vector<uint8_t> zeros(remaining, 0);
                f.write(reinterpret_cast<char*>(zeros.data()), remaining);
            }
        }

        if (!f) return Result<void>::err("MediaGenerator::generate_mp3 — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // generate_mp4 — valid MP4 container with a single raw video frame
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> generate_mp4(
        const std::string& path,
        uint32_t           width = 320,
        uint32_t           height = 240)
    {
        // Build the complete MP4 in memory, then write at once.
        // Structure: ftyp + mdat (1 raw frame) + moov (mvhd + trak)
        // The MP4 steganographer works at container level (free boxes),
        // so the video track just needs to be structurally valid.
        Bytes mp4;

        auto abe32 = [](Bytes& out, uint32_t v) {
            out.push_back(uint8_t(v >> 24));
            out.push_back(uint8_t(v >> 16));
            out.push_back(uint8_t(v >> 8));
            out.push_back(uint8_t(v));
        };
        auto abe16 = [](Bytes& out, uint16_t v) {
            out.push_back(uint8_t(v >> 8));
            out.push_back(uint8_t(v));
        };
        auto astr = [](Bytes& out, const char* s, int n) {
            for (int i = 0; i < n; ++i) out.push_back(static_cast<uint8_t>(s[i]));
        };
        auto azeros = [](Bytes& out, int n) {
            for (int i = 0; i < n; ++i) out.push_back(0);
        };

        // ── ftyp (20 bytes) ─────────────────────────────────────────────
        abe32(mp4, 20);
        astr(mp4, "ftyp", 4);
        astr(mp4, "isom", 4);
        abe32(mp4, 0x200);

        // ── mdat (8 + frame_data) ───────────────────────────────────────
        uint32_t frame_size = width * height * 3; // RGB24
        uint32_t mdat_offset = 20;
        uint32_t mdat_size = 8 + frame_size;
        abe32(mp4, mdat_size);
        astr(mp4, "mdat", 4);
        // Generate a gradient frame
        for (uint32_t y = 0; y < height; ++y) {
            for (uint32_t x = 0; x < width; ++x) {
                mp4.push_back(clamp8(30.0 + x * 195.0 / (width - 1)));
                mp4.push_back(clamp8(30.0 + y * 165.0 / (height - 1)));
                mp4.push_back(clamp8(60.0 + (x + y) * 100.0 / double(width + height - 2)));
            }
        }
        uint32_t sample_offset = mdat_offset + 8; // offset to frame data within mdat

        // ── Build moov ──────────────────────────────────────────────────
        // We'll build sub-boxes, then wrap in moov.
        Bytes moov_content;

        // ── mvhd (108 bytes total) ──────────────────────────────────────
        abe32(moov_content, 108);
        astr(moov_content, "mvhd", 4);
        abe32(moov_content, 0);          // version 0 + flags
        abe32(moov_content, 0);          // creation_time
        abe32(moov_content, 0);          // modification_time
        abe32(moov_content, 1000);       // timescale
        abe32(moov_content, 1000);       // duration (1 second)
        abe32(moov_content, 0x00010000); // rate = 1.0
        abe16(moov_content, 0x0100);     // volume = 1.0
        azeros(moov_content, 10);        // reserved
        // Identity matrix (36 bytes = 9 * 4)
        abe32(moov_content, 0x00010000); azeros(moov_content, 4); azeros(moov_content, 4);
        azeros(moov_content, 4); abe32(moov_content, 0x00010000); azeros(moov_content, 4);
        azeros(moov_content, 4); azeros(moov_content, 4); abe32(moov_content, 0x40000000);
        azeros(moov_content, 24);        // pre-defined
        abe32(moov_content, 2);          // next_track_ID

        // ── trak ────────────────────────────────────────────────────────
        Bytes trak_content;

        // tkhd (92 bytes)
        abe32(trak_content, 92);
        astr(trak_content, "tkhd", 4);
        abe32(trak_content, 0x00000003); // version 0 + flags (track_enabled | track_in_movie)
        abe32(trak_content, 0);          // creation_time
        abe32(trak_content, 0);          // modification_time
        abe32(trak_content, 1);          // track_ID
        abe32(trak_content, 0);          // reserved
        abe32(trak_content, 1000);       // duration
        azeros(trak_content, 8);         // reserved
        abe16(trak_content, 0);          // layer
        abe16(trak_content, 0);          // alternate_group
        abe16(trak_content, 0);          // volume (0 for video)
        abe16(trak_content, 0);          // reserved
        // Identity matrix (36 bytes)
        abe32(trak_content, 0x00010000); azeros(trak_content, 4); azeros(trak_content, 4);
        azeros(trak_content, 4); abe32(trak_content, 0x00010000); azeros(trak_content, 4);
        azeros(trak_content, 4); azeros(trak_content, 4); abe32(trak_content, 0x40000000);
        abe32(trak_content, width << 16);  // width (fixed-point 16.16)
        abe32(trak_content, height << 16); // height (fixed-point 16.16)

        // mdia
        Bytes mdia_content;

        // mdhd (32 bytes)
        abe32(mdia_content, 32);
        astr(mdia_content, "mdhd", 4);
        abe32(mdia_content, 0);    // version + flags
        abe32(mdia_content, 0);    // creation_time
        abe32(mdia_content, 0);    // modification_time
        abe32(mdia_content, 1000); // timescale
        abe32(mdia_content, 1000); // duration
        abe16(mdia_content, 0x55C4); // language (undetermined)
        abe16(mdia_content, 0);      // quality

        // hdlr (33 bytes)
        abe32(mdia_content, 33);
        astr(mdia_content, "hdlr", 4);
        abe32(mdia_content, 0);    // version + flags
        abe32(mdia_content, 0);    // pre-defined
        astr(mdia_content, "vide", 4); // handler_type
        azeros(mdia_content, 12);  // reserved
        mdia_content.push_back(0); // name (null-terminated)

        // minf
        Bytes minf_content;

        // vmhd (20 bytes)
        abe32(minf_content, 20);
        astr(minf_content, "vmhd", 4);
        abe32(minf_content, 0x00000001); // version + flags (flag=1 for vmhd)
        abe16(minf_content, 0);    // graphicsmode
        azeros(minf_content, 6);   // opcolor

        // dinf + dref (36 bytes)
        Bytes dinf_content;
        // dref with one self-reference entry
        abe32(dinf_content, 28);
        astr(dinf_content, "dref", 4);
        abe32(dinf_content, 0);    // version + flags
        abe32(dinf_content, 1);    // entry_count
        abe32(dinf_content, 12);   // entry size
        astr(dinf_content, "url ", 4);
        abe32(dinf_content, 0x00000001); // flags = self-contained

        abe32(minf_content, 8 + static_cast<uint32_t>(dinf_content.size()));
        astr(minf_content, "dinf", 4);
        minf_content.insert(minf_content.end(), dinf_content.begin(), dinf_content.end());

        // stbl (sample table)
        Bytes stbl_content;

        // stsd — sample description (raw video RGB24)
        {
            // Visual sample entry for 'raw ' codec (102 bytes)
            uint32_t entry_size = 86 + 16; // base visual entry is 86 bytes + we add 16 for name padding
            // Actually, minimal visual sample entry = 86 bytes
            entry_size = 86;
            uint32_t stsd_size = 8 + 8 + entry_size; // box header + version/flags + entry_count + entry
            abe32(stbl_content, stsd_size);
            astr(stbl_content, "stsd", 4);
            abe32(stbl_content, 0);    // version + flags
            abe32(stbl_content, 1);    // entry_count
            // Visual sample entry
            abe32(stbl_content, entry_size); // entry size
            astr(stbl_content, "raw ", 4);   // codec type
            azeros(stbl_content, 6);   // reserved
            abe16(stbl_content, 1);    // data_reference_index
            abe16(stbl_content, 0);    // pre-defined
            abe16(stbl_content, 0);    // reserved
            azeros(stbl_content, 12);  // pre-defined
            abe16(stbl_content, static_cast<uint16_t>(width));
            abe16(stbl_content, static_cast<uint16_t>(height));
            abe32(stbl_content, 0x00480000); // horizontal resolution 72 dpi
            abe32(stbl_content, 0x00480000); // vertical resolution 72 dpi
            abe32(stbl_content, 0);    // reserved
            abe16(stbl_content, 1);    // frame_count
            azeros(stbl_content, 32);  // compressor name (32 bytes)
            abe16(stbl_content, 0x0018); // depth (24-bit)
            abe16(stbl_content, static_cast<uint16_t>(0xFFFF)); // pre-defined = -1
        }

        // stts — time to sample
        abe32(stbl_content, 24);
        astr(stbl_content, "stts", 4);
        abe32(stbl_content, 0);    // version + flags
        abe32(stbl_content, 1);    // entry_count
        abe32(stbl_content, 1);    // sample_count
        abe32(stbl_content, 1000); // sample_delta

        // stsc — sample to chunk
        abe32(stbl_content, 28);
        astr(stbl_content, "stsc", 4);
        abe32(stbl_content, 0);    // version + flags
        abe32(stbl_content, 1);    // entry_count
        abe32(stbl_content, 1);    // first_chunk
        abe32(stbl_content, 1);    // samples_per_chunk
        abe32(stbl_content, 1);    // sample_description_index

        // stsz — sample sizes
        abe32(stbl_content, 20);
        astr(stbl_content, "stsz", 4);
        abe32(stbl_content, 0);    // version + flags
        abe32(stbl_content, frame_size); // sample_size (uniform)
        abe32(stbl_content, 1);    // sample_count

        // stco — chunk offsets
        abe32(stbl_content, 16);
        astr(stbl_content, "stco", 4);
        abe32(stbl_content, 0);    // version + flags
        abe32(stbl_content, 1);    // entry_count
        // The actual offset will be fixed after we know the total moov size.
        // For now, use sample_offset (offset of frame data in mdat).
        abe32(stbl_content, sample_offset);

        // Wrap stbl
        abe32(minf_content, 8 + static_cast<uint32_t>(stbl_content.size()));
        astr(minf_content, "stbl", 4);
        minf_content.insert(minf_content.end(), stbl_content.begin(), stbl_content.end());

        // Wrap minf
        abe32(mdia_content, 8 + static_cast<uint32_t>(minf_content.size()));
        astr(mdia_content, "minf", 4);
        mdia_content.insert(mdia_content.end(), minf_content.begin(), minf_content.end());

        // Wrap mdia
        abe32(trak_content, 8 + static_cast<uint32_t>(mdia_content.size()));
        astr(trak_content, "mdia", 4);
        trak_content.insert(trak_content.end(), mdia_content.begin(), mdia_content.end());

        // Wrap trak
        abe32(moov_content, 8 + static_cast<uint32_t>(trak_content.size()));
        astr(moov_content, "trak", 4);
        moov_content.insert(moov_content.end(), trak_content.begin(), trak_content.end());

        // Wrap moov
        abe32(mp4, 8 + static_cast<uint32_t>(moov_content.size()));
        astr(mp4, "moov", 4);
        mp4.insert(mp4.end(), moov_content.begin(), moov_content.end());

        // Write to file
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MediaGenerator::generate_mp4 — cannot write '" + path + "'");
        f.write(reinterpret_cast<const char*>(mp4.data()),
                static_cast<std::streamsize>(mp4.size()));
        if (!f) return Result<void>::err("MediaGenerator::generate_mp4 — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // File size helpers (useful for pre-allocating buffers or progress display)
    // ─────────────────────────────────────────────────────────────────────────

    /// Expected byte size of a PPM file produced by generate_ppm().
    [[nodiscard]] static std::size_t ppm_file_size(
        uint32_t width, uint32_t height) noexcept
    {
        // Conservative: "P6\n65535 65535\n255\n" = 20 bytes + raw pixels
        return 20 + static_cast<std::size_t>(width) * height * 3;
    }

    /// Expected byte size of a WAV file produced by generate_wav().
    [[nodiscard]] static std::size_t wav_file_size(
        uint32_t sample_rate,
        uint16_t channels,
        double   duration_s) noexcept
    {
        const uint32_t num_samples =
            static_cast<uint32_t>(std::round(duration_s * sample_rate));
        const uint32_t data_size = num_samples * channels * 2;
        return 44 + data_size; // 44-byte RIFF header
    }

    /// Expected byte size of a CRVF file produced by generate_crvf().
    [[nodiscard]] static std::size_t crvf_file_size(
        uint32_t width,
        uint32_t height,
        uint32_t num_frames) noexcept
    {
        return VideoSteganographer::CrvfHeader::SIZE
             + static_cast<std::size_t>(width) * height * 3 * num_frames;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // convert_to_bmp — load any stb-supported image and save as 24-bit BMP
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> convert_to_bmp(
        const std::string& source_path,
        const std::string& output_path)
    {
        auto img = load_image_rgb(source_path);
        if (img.is_err()) return Result<void>::err(img.error().message);
        auto& [w, h, pixels] = img.value();

        std::size_t row_bytes = w * 3;
        std::size_t row_pad = (4 - (row_bytes % 4)) % 4;
        std::size_t pixel_data_size = (row_bytes + row_pad) * h;

        std::ofstream f(output_path, std::ios::binary);
        if (!f) return Result<void>::err("convert_to_bmp — cannot write '" + output_path + "'");

        uint32_t file_size = 14 + 40 + static_cast<uint32_t>(pixel_data_size);
        uint8_t fh[14] = {'B', 'M'};
        fh[2]=uint8_t(file_size); fh[3]=uint8_t(file_size>>8);
        fh[4]=uint8_t(file_size>>16); fh[5]=uint8_t(file_size>>24);
        fh[10]=54;
        f.write(reinterpret_cast<char*>(fh), 14);

        uint8_t dib[40] = {};
        dib[0]=40;
        dib[4]=uint8_t(w); dib[5]=uint8_t(w>>8);
        dib[6]=uint8_t(w>>16); dib[7]=uint8_t(w>>24);
        dib[8]=uint8_t(h); dib[9]=uint8_t(h>>8);
        dib[10]=uint8_t(h>>16); dib[11]=uint8_t(h>>24);
        dib[12]=1; dib[14]=24;
        uint32_t img_size = static_cast<uint32_t>(pixel_data_size);
        dib[20]=uint8_t(img_size); dib[21]=uint8_t(img_size>>8);
        dib[22]=uint8_t(img_size>>16); dib[23]=uint8_t(img_size>>24);
        f.write(reinterpret_cast<char*>(dib), 40);

        uint8_t pad_bytes[3] = {0, 0, 0};
        for (std::size_t row = 0; row < h; ++row) {
            std::size_t src_row = h - 1 - row; // bottom-up
            for (std::size_t col = 0; col < w; ++col) {
                std::size_t idx = (src_row * w + col) * 3;
                uint8_t bgr[3] = {pixels[idx+2], pixels[idx+1], pixels[idx+0]};
                f.write(reinterpret_cast<char*>(bgr), 3);
            }
            if (row_pad > 0)
                f.write(reinterpret_cast<char*>(pad_bytes), static_cast<std::streamsize>(row_pad));
        }

        if (!f) return Result<void>::err("convert_to_bmp — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // convert_to_png — load any stb-supported image and save as PNG
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> convert_to_png(
        const std::string& source_path,
        const std::string& output_path)
    {
        auto img = load_image_rgb(source_path);
        if (img.is_err()) return Result<void>::err(img.error().message);
        auto& [w, h, pixels] = img.value();

        struct PngCtx { std::vector<uint8_t> buf; };
        PngCtx ctx;
        auto cb = [](void* c, void* d, int sz) {
            auto* pc = static_cast<PngCtx*>(c);
            auto* bytes = static_cast<uint8_t*>(d);
            pc->buf.insert(pc->buf.end(), bytes, bytes + sz);
        };

        int ok = stbi_write_png_to_func(cb, &ctx,
            static_cast<int>(w), static_cast<int>(h), 3,
            pixels.data(), static_cast<int>(w * 3));
        if (!ok) return Result<void>::err("convert_to_png — encode failed");

        std::ofstream f(output_path, std::ios::binary);
        if (!f) return Result<void>::err("convert_to_png — cannot write '" + output_path + "'");
        f.write(reinterpret_cast<const char*>(ctx.buf.data()),
                static_cast<std::streamsize>(ctx.buf.size()));
        if (!f) return Result<void>::err("convert_to_png — write error");
        return Result<void>::ok();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // convert_to_gif — load any stb-supported image and save as GIF89a
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static Result<void> convert_to_gif(
        const std::string& source_path,
        const std::string& output_path)
    {
        auto img = load_image_rgb(source_path);
        if (img.is_err()) return Result<void>::err(img.error().message);
        auto& [w, h, pixels] = img.value();

        // Build 256-colour palette (6x6x7 colour cube)
        struct RGB { uint8_t r, g, b; };
        std::vector<RGB> palette(256);
        int pidx = 0;
        for (int r = 0; r < 6 && pidx < 256; ++r)
            for (int g = 0; g < 6 && pidx < 256; ++g)
                for (int b = 0; b < 7 && pidx < 256; ++b)
                    palette[pidx++] = {uint8_t(r*51), uint8_t(g*51), uint8_t(b*42)};
        while (pidx < 256) palette[pidx++] = {0, 0, 0};

        // Quantize pixels to palette indices
        std::vector<uint8_t> indices(w * h);
        for (std::size_t i = 0; i < w * h; ++i) {
            uint8_t pr = pixels[i*3+0], pg = pixels[i*3+1], pb = pixels[i*3+2];
            int best = 0, best_dist = 999999;
            for (int j = 0; j < 256; ++j) {
                int dr = int(pr) - int(palette[j].r);
                int dg = int(pg) - int(palette[j].g);
                int db = int(pb) - int(palette[j].b);
                int dist = dr*dr + dg*dg + db*db;
                if (dist < best_dist) { best_dist = dist; best = j; }
            }
            indices[i] = static_cast<uint8_t>(best);
        }

        // Write GIF89a
        std::ofstream f(output_path, std::ios::binary);
        if (!f) return Result<void>::err("convert_to_gif — cannot write '" + output_path + "'");

        auto wu16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v >> 8)};
            f.write(reinterpret_cast<char*>(b), 2);
        };

        f.write("GIF89a", 6);
        wu16(static_cast<uint16_t>(w));
        wu16(static_cast<uint16_t>(h));
        uint8_t lsd_packed = 0x80 | (7 << 4) | 7;
        f.put(static_cast<char>(lsd_packed));
        f.put(0); f.put(0);

        for (int i = 0; i < 256; ++i) {
            f.put(static_cast<char>(palette[i].r));
            f.put(static_cast<char>(palette[i].g));
            f.put(static_cast<char>(palette[i].b));
        }

        f.put(0x2C);
        wu16(0); wu16(0);
        wu16(static_cast<uint16_t>(w));
        wu16(static_cast<uint16_t>(h));
        f.put(0);

        uint8_t min_code_size = 8;
        f.put(static_cast<char>(min_code_size));

        uint16_t clear_code = 256, eoi_code = 257;
        int code_size = 9, next_code = 258;
        bool first_after_clear = true;
        Bytes sub_block_data;
        uint32_t bit_buffer = 0;
        int bits_in_buffer = 0;

        auto emit_code = [&](uint16_t code) {
            bit_buffer |= (static_cast<uint32_t>(code) << bits_in_buffer);
            bits_in_buffer += code_size;
            while (bits_in_buffer >= 8) {
                sub_block_data.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }
        };

        auto flush_sub_blocks = [&]() {
            std::size_t off = 0;
            while (off < sub_block_data.size()) {
                std::size_t chunk = std::min<std::size_t>(255, sub_block_data.size() - off);
                f.put(static_cast<char>(chunk));
                f.write(reinterpret_cast<const char*>(sub_block_data.data() + off),
                        static_cast<std::streamsize>(chunk));
                off += chunk;
            }
            sub_block_data.clear();
        };

        emit_code(clear_code);
        for (std::size_t i = 0; i < indices.size(); ++i) {
            emit_code(indices[i]);
            if (first_after_clear) {
                first_after_clear = false;
            } else {
                next_code++;
                if (next_code == (1 << code_size)) {
                    if (code_size < 12) { code_size++; }
                    else {
                        emit_code(clear_code);
                        code_size = 9; next_code = 258; first_after_clear = true;
                    }
                }
            }
        }
        emit_code(eoi_code);
        if (bits_in_buffer > 0)
            sub_block_data.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
        flush_sub_blocks();
        f.put(0);
        f.put(0x3B);

        if (!f) return Result<void>::err("convert_to_gif — write error");
        return Result<void>::ok();
    }

private:
    struct LoadedImage {
        std::size_t w, h;
        std::vector<uint8_t> pixels; // RGB interleaved
    };

    [[nodiscard]] static Result<LoadedImage> load_image_rgb(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<LoadedImage>::err("cannot open '" + path + "'");
        auto sz = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> buf(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(buf.data()), sz);

        int w, h, channels;
        uint8_t* data = stbi_load_from_memory(buf.data(), static_cast<int>(buf.size()),
                                               &w, &h, &channels, 3);
        if (!data) return Result<LoadedImage>::err(
            std::string("stb_image load failed: ") + stbi_failure_reason());

        LoadedImage img;
        img.w = static_cast<std::size_t>(w);
        img.h = static_cast<std::size_t>(h);
        img.pixels.assign(data, data + w * h * 3);
        stbi_image_free(data);
        return Result<LoadedImage>::ok(std::move(img));
    }
    // ─────────────────────────────────────────────────────────────────────────
    // LcgRng — deterministic 32-bit LCG (Knuth's multiplicative congruential).
    // No external dependencies; used for reproducible per-pixel noise.
    // NOT cryptographically secure — for test media generation only.
    // ─────────────────────────────────────────────────────────────────────────
    struct LcgRng {
        explicit LcgRng(uint32_t seed) noexcept : state_(seed ? seed : 1u) {}

        [[nodiscard]] uint32_t next() noexcept {
            // Knuth's multiplicative LCG; full-period modulo 2^32
            state_ = state_ * 1'664'525u + 1'013'904'223u;
            return state_;
        }

        // Returns a uniform double in [0, 1).
        [[nodiscard]] double uniform() noexcept {
            return static_cast<double>(next()) / 4'294'967'296.0;
        }

    private:
        uint32_t state_;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Box-Muller transform — produces two independent N(0,1) samples.
    // Avoids <random> to maintain no-external-dependency policy.
    // ─────────────────────────────────────────────────────────────────────────
    static void gauss(LcgRng& rng, double& z0, double& z1) noexcept {
        double u1, u2;
        do { u1 = rng.uniform(); } while (u1 < 1e-10);
        u2 = rng.uniform();
        const double r = std::sqrt(-2.0 * std::log(u1));
        z0 = r * std::cos(2.0 * std::numbers::pi * u2);
        z1 = r * std::sin(2.0 * std::numbers::pi * u2);
    }

    // Clamp a double to [0, 255] and return as uint8_t.
    [[nodiscard]] static uint8_t clamp8(double v) noexcept {
        return static_cast<uint8_t>(std::clamp(v, 0.0, 255.0));
    }
};

} // namespace crypto::stego
