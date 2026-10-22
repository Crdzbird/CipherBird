#pragma once

/**
 * crypto::stego::PngSteganographer
 *
 * DCT/QIM steganography for PNG images.
 * Uses stb_image for decode and stb_image_write for encode.
 *
 * NOTE: stb implementation is included in a single .hpp to keep the library
 * header-only. The STB_IMAGE_IMPLEMENTATION / STB_IMAGE_WRITE_IMPLEMENTATION
 * defines are guarded so only one TU defines them.
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"

// stb headers — make all functions static to avoid duplicate symbols
// when multiple TUs include this header (header-only library).
#ifndef CRYPTOLIB_STB_IMAGE_IMPL_GUARD
#define CRYPTOLIB_STB_IMAGE_IMPL_GUARD
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_STATIC
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_NO_STDIO
#endif

#include "third_party/stb_image.h"

#ifndef CRYPTOLIB_STB_IMAGE_WRITE_IMPL_GUARD
#define CRYPTOLIB_STB_IMAGE_WRITE_IMPL_GUARD
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STB_IMAGE_WRITE_STATIC
#define STBI_WRITE_NO_STDIO
#endif

#include "third_party/stb_image_write.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class PngSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      Q = 16,
        std::span<const uint8_t> key = {})
    {
        auto img = load_image(cover_path);
        if (img.is_err()) return Result<void>::err(img.error().message);

        auto& [w, h, pixels] = img.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::PNG_IMAGE, key);

        std::size_t cap = DctQimEngine::capacity(w, h);
        if (payload.size() > cap)
            return Result<void>::err(
                "PngSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        DctQimEngine::embed_bits(pixels, w, h, stream, Q);
        return save_png(output_path, w, h, pixels);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                Q = 16,
        std::span<const uint8_t> key = {})
    {
        auto img = load_image(stego_path);
        if (img.is_err()) return Result<Bytes>::err(img.error().message);

        auto& [w, h, pixels] = img.value();
        std::size_t max_stream = DctQimEngine::capacity(w, h) + StegoHeader::SIZE;
        Bytes raw = DctQimEngine::extract_bits(pixels, w, h, max_stream, Q);
        return parse_embed_stream(std::span<const uint8_t>(raw), key);
    }

    [[nodiscard]] static std::size_t capacity(std::size_t w, std::size_t h) noexcept {
        return DctQimEngine::capacity(w, h);
    }

    [[nodiscard]] static double psnr(
        const std::string& cover_path,
        const std::string& stego_path)
    {
        auto a = load_image(cover_path);
        auto b = load_image(stego_path);
        if (a.is_err() || b.is_err()) return -1.0;
        if (a.value().w != b.value().w || a.value().h != b.value().h) return -1.0;
        return DctQimEngine::psnr(a.value().pixels, b.value().pixels);
    }

private:
    struct RgbImage {
        std::size_t          w, h;
        std::vector<uint8_t> pixels; // RGB interleaved
    };

    /// Every chunk's declared length must fit the bytes that follow it:
    /// the decoder grows its IDAT buffer by the declared length before it
    /// reads a byte, so a 900 MB length on a 1 KB file is a 900 MB
    /// allocation unless it is refused here.
    [[nodiscard]] static bool png_chunks_well_formed(const std::vector<uint8_t>& buf) {
        std::size_t pos = 8;
        bool saw_iend = false;
        while (pos + 8 <= buf.size() && !saw_iend) {
            const std::size_t len = (std::size_t(buf[pos]) << 24) | (std::size_t(buf[pos + 1]) << 16) |
                                    (std::size_t(buf[pos + 2]) << 8) | std::size_t(buf[pos + 3]);
            if (len > (1u << 31) || len > buf.size() - pos - 8) return false;
            saw_iend = std::memcmp(buf.data() + pos + 4, "IEND", 4) == 0;
            pos += 12 + len;
        }
        return saw_iend && pos <= buf.size();
    }

    [[nodiscard]] static Result<RgbImage> load_image(const std::string& path) {
        // Read file into memory
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<RgbImage>::err("PNG: cannot open '" + path + "'");
        auto sz = f.tellg();
        if (sz <= 0) return Result<RgbImage>::err("PNG: empty or unreadable '" + path + "'");
        f.seekg(0);
        std::vector<uint8_t> buf(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(buf.data()), sz);

        /* Only a PNG reaches the decoder, and only one whose header dims
         * pass the caps: the decoder allocates from the header, so the
         * check has to come before stbi_load, not after. */
        static constexpr uint8_t PNG_MAGIC[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
        if (buf.size() < 8 || std::memcmp(buf.data(), PNG_MAGIC, 8) != 0)
            return Result<RgbImage>::err("PNG: not a PNG file '" + path + "'");
        if (!png_chunks_well_formed(buf))
            return Result<RgbImage>::err("PNG: chunk structure does not fit the file '" + path + "'");
        int w, h, channels;
        if (!stbi_info_from_memory(buf.data(), static_cast<int>(buf.size()), &w, &h, &channels))
            return Result<RgbImage>::err("PNG: unreadable header in '" + path + "'");
        auto byte_count = (w > 0 && h > 0)
            ? checked_image_bytes(static_cast<std::size_t>(w), static_cast<std::size_t>(h))
            : std::nullopt;
        if (!byte_count)
            return Result<RgbImage>::err("PNG: image dimensions out of range in '" + path + "'");
        uint8_t* data = stbi_load_from_memory(buf.data(), static_cast<int>(buf.size()),
                                               &w, &h, &channels, 3);
        if (!data) return Result<RgbImage>::err(
            std::string("PNG: stb_image load failed: ") + stbi_failure_reason());
        if (!checked_image_bytes(static_cast<std::size_t>(w), static_cast<std::size_t>(h))) {
            stbi_image_free(data);
            return Result<RgbImage>::err("PNG: image dimensions out of range in '" + path + "'");
        }

        RgbImage img;
        img.w = static_cast<std::size_t>(w);
        img.h = static_cast<std::size_t>(h);
        img.pixels.assign(data, data + *byte_count);
        stbi_image_free(data);
        return Result<RgbImage>::ok(std::move(img));
    }

    static void png_write_callback(void* context, void* data, int size) {
        auto* vec = static_cast<std::vector<uint8_t>*>(context);
        auto* bytes = static_cast<uint8_t*>(data);
        vec->insert(vec->end(), bytes, bytes + size);
    }

    [[nodiscard]] static Result<void> save_png(
        const std::string&          path,
        std::size_t                 w,
        std::size_t                 h,
        const std::vector<uint8_t>& pixels)
    {
        std::vector<uint8_t> out_buf;
        int ok = stbi_write_png_to_func(
            png_write_callback, &out_buf,
            static_cast<int>(w), static_cast<int>(h), 3,
            pixels.data(), static_cast<int>(w * 3));

        if (!ok) return Result<void>::err("PNG: stb_image_write encode failed");

        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("PNG: cannot write '" + path + "'");
        f.write(reinterpret_cast<const char*>(out_buf.data()),
                static_cast<std::streamsize>(out_buf.size()));
        if (!f) return Result<void>::err("PNG: write error");
        return Result<void>::ok();
    }
};

} // namespace crypto::stego
