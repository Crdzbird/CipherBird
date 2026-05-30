#pragma once

/**
 * crypto::stego::BmpSteganographer
 *
 * DCT/QIM steganography for 24-bit uncompressed BMP images.
 * Custom BMP parser — no external dependency.
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class BmpSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      Q = 16)
    {
        auto img = read_bmp(cover_path);
        if (img.is_err()) return Result<void>::err(img.error().message);

        auto& [w, h, pixels, header_data, row_padding] = img.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::BMP_IMAGE);

        std::size_t cap = DctQimEngine::capacity(w, h);
        if (payload.size() > cap)
            return Result<void>::err(
                "BmpSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        DctQimEngine::embed_bits(pixels, w, h, stream, Q);
        return write_bmp(output_path, w, h, pixels, header_data, row_padding);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                Q = 16)
    {
        auto img = read_bmp(stego_path);
        if (img.is_err()) return Result<Bytes>::err(img.error().message);

        auto& [w, h, pixels, header_data, row_padding] = img.value();
        std::size_t max_stream = DctQimEngine::capacity(w, h) + StegoHeader::SIZE;
        Bytes raw = DctQimEngine::extract_bits(pixels, w, h, max_stream, Q);
        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    [[nodiscard]] static std::size_t capacity(std::size_t w, std::size_t h) noexcept {
        return DctQimEngine::capacity(w, h);
    }

    [[nodiscard]] static double psnr(
        const std::string& cover_path,
        const std::string& stego_path)
    {
        auto a = read_bmp(cover_path);
        auto b = read_bmp(stego_path);
        if (a.is_err() || b.is_err()) return -1.0;
        if (a.value().w != b.value().w || a.value().h != b.value().h) return -1.0;
        return DctQimEngine::psnr(a.value().pixels, b.value().pixels);
    }

private:
    struct BmpImage {
        std::size_t          w, h;
        std::vector<uint8_t> pixels;      // row-major RGB (top-to-bottom)
        std::vector<uint8_t> header_data; // original file header + info header
        std::size_t          row_padding;
    };

    [[nodiscard]] static Result<BmpImage> read_bmp(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<BmpImage>::err("BMP: cannot open '" + path + "'");

        // File header (14 bytes)
        uint8_t fh[14];
        f.read(reinterpret_cast<char*>(fh), 14);
        if (!f || fh[0] != 'B' || fh[1] != 'M')
            return Result<BmpImage>::err("BMP: invalid magic");

        uint32_t pixel_offset = le32(fh + 10);

        // DIB header size
        uint8_t dib_size_bytes[4];
        f.read(reinterpret_cast<char*>(dib_size_bytes), 4);
        uint32_t dib_size = le32(dib_size_bytes);

        // Cap DIB header size: legitimate BITMAPV5HEADER is 124 bytes. An
        // attacker-supplied huge value would otherwise drive a multi-GB
        // allocation before any further validation.
        if (dib_size < 40 || dib_size > 1024)
            return Result<BmpImage>::err("BMP: unsupported DIB header size");

        // Read rest of DIB header
        std::vector<uint8_t> dib(dib_size);
        std::memcpy(dib.data(), dib_size_bytes, 4);
        f.read(reinterpret_cast<char*>(dib.data() + 4), dib_size - 4);
        if (!f)
            return Result<BmpImage>::err("BMP: truncated DIB header");

        int32_t  w_signed  = static_cast<int32_t>(le32(dib.data() + 4));
        int32_t  h_signed  = static_cast<int32_t>(le32(dib.data() + 8));
        uint16_t bpp       = le16(dib.data() + 14);
        uint32_t compress   = le32(dib.data() + 16);

        if (bpp != 24)
            return Result<BmpImage>::err("BMP: only 24-bit images supported (got " + std::to_string(bpp) + ")");
        if (compress != 0)
            return Result<BmpImage>::err("BMP: only uncompressed (BI_RGB) supported");

        std::size_t w = static_cast<std::size_t>(std::abs(static_cast<int64_t>(w_signed)));
        std::size_t h = static_cast<std::size_t>(std::abs(static_cast<int64_t>(h_signed)));
        bool bottom_up = (h_signed > 0);

        // Validate dimensions before allocating/indexing — guards against
        // w*h*3 integer overflow that would undersize img.pixels and turn the
        // row-copy loop below into a heap overflow.
        auto byte_count = checked_image_bytes(w, h);
        if (!byte_count)
            return Result<BmpImage>::err("BMP: image dimensions out of range");

        // Store full header for write-back
        BmpImage img;
        img.w = w;
        img.h = h;
        img.header_data.resize(14 + dib_size);
        std::memcpy(img.header_data.data(), fh, 14);
        std::memcpy(img.header_data.data() + 14, dib.data(), dib_size);

        // BMP row stride is padded to 4-byte boundary
        std::size_t row_bytes = w * 3;
        img.row_padding = (4 - (row_bytes % 4)) % 4;
        std::size_t stride = row_bytes + img.row_padding;

        // Seek to pixel data
        f.seekg(pixel_offset, std::ios::beg);

        // Read pixel data (BMP is BGR, bottom-up by default)
        img.pixels.resize(*byte_count);
        std::vector<uint8_t> row_buf(stride);

        for (std::size_t y = 0; y < h; ++y) {
            f.read(reinterpret_cast<char*>(row_buf.data()), static_cast<std::streamsize>(stride));
            if (!f) return Result<BmpImage>::err("BMP: truncated pixel data");

            std::size_t dest_y = bottom_up ? (h - 1 - y) : y;
            for (std::size_t x = 0; x < w; ++x) {
                std::size_t si = x * 3;
                std::size_t di = (dest_y * w + x) * 3;
                img.pixels[di + 0] = row_buf[si + 2]; // R (BMP stores BGR)
                img.pixels[di + 1] = row_buf[si + 1]; // G
                img.pixels[di + 2] = row_buf[si + 0]; // B
            }
        }

        return Result<BmpImage>::ok(std::move(img));
    }

    [[nodiscard]] static Result<void> write_bmp(
        const std::string&          path,
        std::size_t                 w,
        std::size_t                 h,
        const std::vector<uint8_t>& pixels,
        const std::vector<uint8_t>& header_data,
        std::size_t                 row_padding)
    {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("BMP: cannot write '" + path + "'");

        // Write original header
        f.write(reinterpret_cast<const char*>(header_data.data()),
                static_cast<std::streamsize>(header_data.size()));

        // Check if original was bottom-up (positive height in header)
        int32_t h_signed = static_cast<int32_t>(le32(header_data.data() + 14 + 8));
        bool bottom_up = (h_signed > 0);

        uint8_t pad[3] = {0, 0, 0};
        for (std::size_t y = 0; y < h; ++y) {
            std::size_t src_y = bottom_up ? (h - 1 - y) : y;
            for (std::size_t x = 0; x < w; ++x) {
                std::size_t si = (src_y * w + x) * 3;
                uint8_t bgr[3] = {pixels[si + 2], pixels[si + 1], pixels[si + 0]};
                f.write(reinterpret_cast<char*>(bgr), 3);
            }
            if (row_padding > 0)
                f.write(reinterpret_cast<char*>(pad), static_cast<std::streamsize>(row_padding));
        }

        if (!f) return Result<void>::err("BMP: write error");
        return Result<void>::ok();
    }

    static uint32_t le32(const uint8_t* p) {
        return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
    }
    static uint16_t le16(const uint8_t* p) {
        return uint16_t(p[0]) | uint16_t(p[1])<<8;
    }
};

} // namespace crypto::stego
