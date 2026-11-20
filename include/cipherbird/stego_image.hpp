#pragma once

/**
 * crypto::stego::ImageSteganographer
 *
 * DCT-domain steganography for PPM (P6) images using Quantization Index
 * Modulation (QIM). Delegates core DCT/QIM operations to DctQimEngine.
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace crypto::stego {

class ImageSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      Q = 16)
    {
        auto img = read_ppm(cover_path);
        if (img.is_err()) return Result<void>::err(img.error().message);

        auto [w, h, pixels] = img.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::PPM_IMAGE);

        std::size_t cap = capacity(w, h);
        if (payload.size() > cap)
            return Result<void>::err(
                "ImageSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity is "
                + std::to_string(cap) + " bytes");

        DctQimEngine::embed_bits(pixels, w, h, stream, Q);
        return write_ppm(output_path, w, h, pixels);
    }

    /// Keyed embed: whitens the stream (no 'CSTG' magic) and scatters the
    /// payload across a key-seeded block permutation. Extract with the same key.
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        std::span<const uint8_t> key,
        int                      Q = 16)
    {
        auto img = read_ppm(cover_path);
        if (img.is_err()) return Result<void>::err(img.error().message);

        auto [w, h, pixels] = img.value();
        std::size_t cap = capacity(w, h);
        if (payload.size() > cap)
            return Result<void>::err(
                "ImageSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity is "
                + std::to_string(cap) + " bytes");

        Bytes stream = make_embed_stream(payload, MediaFormat::PPM_IMAGE, key);
        auto perm = block_permutation((w / 8) * (h / 8), key);
        DctQimEngine::embed_bits(pixels, w, h, stream, Q, key.empty() ? nullptr : &perm);
        return write_ppm(output_path, w, h, pixels);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                Q = 16)
    {
        auto img = read_ppm(stego_path);
        if (img.is_err()) return Result<Bytes>::err(img.error().message);

        auto [w, h, pixels] = img.value();
        std::size_t max_stream = capacity(w, h) + StegoHeader::SIZE;
        Bytes raw = DctQimEngine::extract_bits(pixels, w, h, max_stream, Q);
        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    /// Keyed extract — supply the same key used at embed time.
    [[nodiscard]] static Result<Bytes> extract(
        const std::string&       stego_path,
        std::span<const uint8_t> key,
        int                      Q = 16)
    {
        auto img = read_ppm(stego_path);
        if (img.is_err()) return Result<Bytes>::err(img.error().message);

        auto [w, h, pixels] = img.value();
        std::size_t max_stream = capacity(w, h) + StegoHeader::SIZE;
        auto perm = block_permutation((w / 8) * (h / 8), key);
        Bytes raw = DctQimEngine::extract_bits(pixels, w, h, max_stream, Q, key.empty() ? nullptr : &perm);
        return parse_embed_stream(std::span<const uint8_t>(raw), key);
    }

    [[nodiscard]] static std::size_t capacity(std::size_t w, std::size_t h) noexcept {
        return DctQimEngine::capacity(w, h);
    }

    [[nodiscard]] static double psnr(
        const std::string& cover_path,
        const std::string& stego_path)
    {
        auto cov_res = read_ppm(cover_path);
        auto stg_res = read_ppm(stego_path);
        if (cov_res.is_err() || stg_res.is_err()) return -1.0;

        auto& [cw, ch, cpix] = cov_res.value();
        auto& [sw, sh, spix] = stg_res.value();
        if (cw != sw || ch != sh) return -1.0;

        return DctQimEngine::psnr(cpix, spix);
    }

    // PPM I/O — public for reuse by other components
    struct PpmImage {
        std::size_t          w, h;
        std::vector<uint8_t> pixels;
    };

    [[nodiscard]] static Result<PpmImage> read_ppm(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<PpmImage>::err("PPM: cannot open '" + path + "'");

        std::string magic;
        f >> magic;
        if (magic != "P6")
            return Result<PpmImage>::err("PPM: only P6 binary format supported (got " + magic + ")");

        PpmImage img;
        int maxval = 0;
        skip_comments_and_whitespace(f);
        f >> img.w;
        skip_comments_and_whitespace(f);
        f >> img.h;
        skip_comments_and_whitespace(f);
        f >> maxval;

        if (!f || img.w == 0 || img.h == 0)
            return Result<PpmImage>::err("PPM: invalid header in '" + path + "'");
        if (maxval != 255)
            return Result<PpmImage>::err("PPM: only 8-bit images (maxval=255) supported");

        // Validate dimensions before allocating/indexing — an attacker-crafted
        // header could otherwise overflow w*h*3 into a small buffer that
        // DctQimEngine::blue_idx then indexes far out of bounds.
        auto byte_count = checked_image_bytes(img.w, img.h);
        if (!byte_count)
            return Result<PpmImage>::err("PPM: image dimensions out of range in '" + path + "'");

        char sep;
        f.get(sep);

        img.pixels.resize(*byte_count);
        f.read(reinterpret_cast<char*>(img.pixels.data()),
               static_cast<std::streamsize>(img.pixels.size()));
        if (!f)
            return Result<PpmImage>::err("PPM: truncated pixel data in '" + path + "'");

        return Result<PpmImage>::ok(std::move(img));
    }

    [[nodiscard]] static Result<void> write_ppm(
        const std::string&          path,
        std::size_t                 w,
        std::size_t                 h,
        const std::vector<uint8_t>& pixels)
    {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("PPM: cannot write '" + path + "'");
        f << "P6\n" << w << ' ' << h << "\n255\n";
        f.write(reinterpret_cast<const char*>(pixels.data()),
                static_cast<std::streamsize>(pixels.size()));
        if (!f) return Result<void>::err("PPM: write error");
        return Result<void>::ok();
    }

private:
    static void skip_comments_and_whitespace(std::ifstream& f) {
        char c;
        while (f.get(c)) {
            if (c == '#') {
                while (f.get(c) && c != '\n') {}
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                continue;
            } else {
                f.putback(c);
                break;
            }
        }
    }
};

} // namespace crypto::stego
