#pragma once

/**
 * crypto::stego::GifSteganographer
 *
 * LSB steganography for static GIF images.
 * Works at the palette-index level: parses GIF natively (LZW decode),
 * modifies the LSB of each palette index, then re-encodes as valid GIF89a.
 *
 * CAPACITY: 1 bit per pixel (index LSB).
 *   capacity_bytes = (width * height) / 8 - StegoHeader::SIZE
 *   Example: 640x480 = 38400 bytes - 14 = 38386 bytes
 *
 * The output is always a valid GIF89a file with the same palette as the input.
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"  // for DctQimEngine::psnr
#include "stego_png.hpp"      // for stbi_load_from_memory (PSNR only)

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class GifSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      /*Q*/ = 16,
        std::span<const uint8_t> key = {})
    {
        auto gif = parse_gif(cover_path);
        if (gif.is_err()) return Result<void>::err(gif.error().message);

        auto& g = gif.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::GIF_IMAGE, key);

        std::size_t cap = capacity(g.width, g.height);
        if (payload.size() > cap)
            return Result<void>::err(
                "GifSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        // LSB embed in palette indices
        embed_index_lsb(g.indices, stream);
        return write_gif(output_path, g);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                /*Q*/ = 16,
        std::span<const uint8_t> key = {})
    {
        auto gif = parse_gif(stego_path);
        if (gif.is_err()) return Result<Bytes>::err(gif.error().message);

        auto& g = gif.value();
        std::size_t max_stream = capacity(g.width, g.height) + StegoHeader::SIZE;
        Bytes raw = extract_index_lsb(g.indices, max_stream);
        return parse_embed_stream(std::span<const uint8_t>(raw), key);
    }

    [[nodiscard]] static std::size_t capacity(std::size_t w, std::size_t h) noexcept {
        std::size_t bits = w * h;
        std::size_t bytes = bits / 8;
        return (bytes > StegoHeader::SIZE) ? (bytes - StegoHeader::SIZE) : 0;
    }

    [[nodiscard]] static double psnr(
        const std::string& cover_path,
        const std::string& stego_path)
    {
        // Use stb_image for PSNR calculation (decodes both GIF formats)
        auto load = [](const std::string& p) -> std::vector<uint8_t> {
            std::ifstream f(p, std::ios::binary | std::ios::ate);
            if (!f) return {};
            auto sz = f.tellg(); f.seekg(0);
            std::vector<uint8_t> buf(static_cast<std::size_t>(sz));
            f.read(reinterpret_cast<char*>(buf.data()), sz);
            int w, h, c;
            uint8_t* d = stbi_load_from_memory(buf.data(), int(buf.size()), &w, &h, &c, 3);
            if (!d) return {};
            std::vector<uint8_t> pix(d, d + w*h*3);
            stbi_image_free(d);
            return pix;
        };
        auto a = load(cover_path), b = load(stego_path);
        if (a.empty() || b.empty() || a.size() != b.size()) return -1.0;
        return DctQimEngine::psnr(a, b);
    }

private:
    struct GifData {
        uint16_t width, height;
        std::vector<uint8_t> palette; // 256 * 3 bytes (R,G,B)
        std::vector<uint8_t> indices; // width * height palette indices
        uint8_t bg_color;
    };

    // ── GIF Parser ───────────────────────────────────────────────────────────

    [[nodiscard]] static Result<GifData> parse_gif(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<GifData>::err("GIF: cannot open '" + path + "'");
        auto sz = f.tellg(); f.seekg(0);
        if (sz <= 0) return Result<GifData>::err("GIF: empty or unreadable '" + path + "'");
        Bytes data(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);

        if (data.size() < 13)
            return Result<GifData>::err("GIF: file too small");
        if (data[0]!='G'||data[1]!='I'||data[2]!='F')
            return Result<GifData>::err("GIF: not a GIF file");

        GifData g;
        g.width  = uint16_t(data[6]) | (uint16_t(data[7]) << 8);
        g.height = uint16_t(data[8]) | (uint16_t(data[9]) << 8);
        uint8_t packed = data[10];
        g.bg_color = data[11];
        // data[12] = pixel aspect ratio (ignored)

        bool has_gct = (packed & 0x80) != 0;
        int gct_size_exp = (packed & 7) + 1;
        int gct_entries = 1 << gct_size_exp;

        std::size_t pos = 13;

        // Read global colour table
        g.palette.resize(256 * 3, 0);
        if (has_gct) {
            std::size_t gct_bytes = gct_entries * 3;
            if (pos + gct_bytes > data.size())
                return Result<GifData>::err("GIF: truncated colour table");
            for (int i = 0; i < gct_entries && i < 256; ++i) {
                g.palette[i*3+0] = data[pos + i*3 + 0];
                g.palette[i*3+1] = data[pos + i*3 + 1];
                g.palette[i*3+2] = data[pos + i*3 + 2];
            }
            pos += gct_bytes;
        }

        // Find first image descriptor, skipping extensions
        while (pos < data.size()) {
            uint8_t block = data[pos++];

            if (block == 0x3B) break; // trailer

            if (block == 0x21) { // extension
                if (pos >= data.size()) break;
                pos++; // extension type
                // skip sub-blocks
                while (pos < data.size()) {
                    uint8_t bsz = data[pos++];
                    if (bsz == 0) break;
                    pos += bsz;
                }
                continue;
            }

            if (block == 0x2C) { // image descriptor
                if (pos + 9 > data.size())
                    return Result<GifData>::err("GIF: truncated image descriptor");

                // uint16_t left = uint16_t(data[pos]) | (uint16_t(data[pos+1]) << 8);
                // uint16_t top  = uint16_t(data[pos+2]) | (uint16_t(data[pos+3]) << 8);
                uint16_t iw = uint16_t(data[pos+4]) | (uint16_t(data[pos+5]) << 8);
                uint16_t ih = uint16_t(data[pos+6]) | (uint16_t(data[pos+7]) << 8);
                uint8_t img_packed = data[pos+8];
                pos += 9;

                bool has_lct = (img_packed & 0x80) != 0;
                // bool interlaced = (img_packed & 0x40) != 0;

                if (has_lct) {
                    int lct_entries = 1 << ((img_packed & 7) + 1);
                    // Use local colour table instead
                    for (int i = 0; i < lct_entries && i < 256; ++i) {
                        if (pos + 3 > data.size()) break;
                        g.palette[i*3+0] = data[pos++];
                        g.palette[i*3+1] = data[pos++];
                        g.palette[i*3+2] = data[pos++];
                    }
                }

                // Use image dimensions if they differ from logical screen
                if (iw > 0 && ih > 0) {
                    g.width = iw;
                    g.height = ih;
                }

                // Validate final dimensions before allocating the index buffer
                // (width*height) — guards against a ~4 GB allocation from a
                // crafted 65535×65535 descriptor.
                if (!checked_image_bytes(g.width, g.height, 1))
                    return Result<GifData>::err("GIF: image dimensions out of range");

                // LZW decode
                if (pos >= data.size())
                    return Result<GifData>::err("GIF: missing LZW data");

                uint8_t min_code_size = data[pos++];
                if (min_code_size < 2 || min_code_size > 11)
                    return Result<GifData>::err("GIF: invalid min code size");

                // Collect all sub-block data
                Bytes lzw_data;
                while (pos < data.size()) {
                    uint8_t bsz = data[pos++];
                    if (bsz == 0) break;
                    if (pos + bsz > data.size()) break;
                    lzw_data.insert(lzw_data.end(), data.begin()+pos, data.begin()+pos+bsz);
                    pos += bsz;
                }

                // Decode LZW to indices
                auto decoded = lzw_decode(lzw_data, min_code_size,
                                          std::size_t(g.width) * g.height);
                if (decoded.is_err())
                    return Result<GifData>::err(decoded.error().message);

                g.indices = std::move(decoded.value());
                return Result<GifData>::ok(std::move(g));
            }
        }

        return Result<GifData>::err("GIF: no image data found");
    }

    // ── LZW Decoder ─────────────────────────────────────────────────────────

    [[nodiscard]] static Result<Bytes> lzw_decode(
        const Bytes& data, uint8_t min_code_size, std::size_t expected_pixels)
    {
        int clear_code = 1 << min_code_size;
        int eoi_code = clear_code + 1;
        int code_size = min_code_size + 1;

        // String table: each entry is a sequence of bytes
        // For efficiency, store as (prefix_code, suffix_byte)
        struct Entry { int prefix; uint8_t suffix; int length; };
        std::vector<Entry> table;

        auto reset_table = [&]() {
            table.clear();
            table.resize(clear_code + 2);
            for (int i = 0; i < clear_code; ++i)
                table[i] = {-1, uint8_t(i), 1};
            table[clear_code] = {-1, 0, 0};   // clear
            table[eoi_code]   = {-1, 0, 0};    // eoi
            code_size = min_code_size + 1;
        };

        auto output_string = [&](Bytes& out, int code) {
            // Recursively output the string for this code
            int len = table[code].length;
            std::size_t start = out.size();
            out.resize(start + len);
            int c = code;
            for (int i = len - 1; i >= 0; --i) {
                out[start + i] = table[c].suffix;
                c = table[c].prefix;
            }
        };

        auto first_char = [&](int code) -> uint8_t {
            while (table[code].prefix >= 0) code = table[code].prefix;
            return table[code].suffix;
        };

        // Bit reader (LSB first, as per GIF spec)
        std::size_t bit_pos = 0;
        auto read_code = [&]() -> int {
            if (bit_pos + code_size > data.size() * 8) return -1;
            int val = 0;
            for (int i = 0; i < code_size; ++i) {
                std::size_t byte_idx = (bit_pos + i) / 8;
                int bit_idx = (bit_pos + i) % 8;
                if (data[byte_idx] & (1 << bit_idx)) val |= (1 << i);
            }
            bit_pos += code_size;
            return val;
        };

        reset_table();

        Bytes output;
        output.reserve(expected_pixels);

        int prev_code = -1;

        while (output.size() < expected_pixels) {
            int code = read_code();
            if (code < 0 || code == eoi_code) break;

            if (code == clear_code) {
                reset_table();
                prev_code = -1;
                continue;
            }

            // GIF's maximum table size; no new codes are defined past this
            // point (a clear code must intervene). Bounding growth also caps the
            // table allocation for a hostile stream.
            constexpr int LZW_MAX_CODES = 4096;

            if (prev_code < 0) {
                // First code after a clear must already exist in the table.
                if (code >= int(table.size())) break;  // corrupt stream
                output_string(output, code);
                prev_code = code;
                continue;
            }

            if (code < int(table.size())) {
                // Code exists in table
                output_string(output, code);
                // Add new entry: prev_string + first_char(code)
                if (int(table.size()) < LZW_MAX_CODES)
                    table.push_back({prev_code, first_char(code),
                                     table[prev_code].length + 1});
            } else if (code == int(table.size())) {
                // Code not in table yet (KwKwK case) — the only valid code that
                // may exceed the current table size is exactly the next index.
                uint8_t fc = first_char(prev_code);
                if (int(table.size()) < LZW_MAX_CODES)
                    table.push_back({prev_code, fc,
                                     table[prev_code].length + 1});
                else
                    break;  // table full but stream needs a new entry → corrupt
                output_string(output, code);
            } else {
                break;  // code beyond next-expected index → corrupt stream
            }

            prev_code = code;

            // Grow code size when table reaches threshold
            if (int(table.size()) == (1 << code_size) && code_size < 12)
                code_size++;
        }

        if (output.size() < expected_pixels)
            output.resize(expected_pixels, 0); // pad with zeros

        return Result<Bytes>::ok(std::move(output));
    }

    // ── LSB embedding on palette indices ─────────────────────────────────────

    static void embed_index_lsb(std::vector<uint8_t>& indices, const Bytes& stream) {
        std::size_t total_bits = stream.size() * 8;
        for (std::size_t i = 0; i < indices.size() && i < total_bits; ++i) {
            int byte_i = static_cast<int>(i / 8);
            int bit_i  = 7 - static_cast<int>(i % 8);
            int bit = (stream[byte_i] >> bit_i) & 1;
            indices[i] = (indices[i] & 0xFE) | static_cast<uint8_t>(bit);
        }
    }

    [[nodiscard]] static Bytes extract_index_lsb(
        const std::vector<uint8_t>& indices, std::size_t max_bytes)
    {
        Bytes result(max_bytes, 0);
        std::size_t total_bits = max_bytes * 8;
        for (std::size_t i = 0; i < indices.size() && i < total_bits; ++i) {
            int bit = indices[i] & 1;
            int byte_i = static_cast<int>(i / 8);
            int bit_i  = 7 - static_cast<int>(i % 8);
            if (bit) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
        }
        return result;
    }

    // ── GIF Writer ───────────────────────────────────────────────────────────

    [[nodiscard]] static Result<void> write_gif(
        const std::string& path, const GifData& g)
    {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("GIF: cannot write '" + path + "'");

        auto wu16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v >> 8)};
            f.write(reinterpret_cast<char*>(b), 2);
        };

        // Header
        f.write("GIF89a", 6);

        // Logical screen descriptor
        wu16(g.width);
        wu16(g.height);
        uint8_t packed = 0x80   // global colour table
                       | (7 << 4) // colour resolution (8 bits)
                       | 7;       // GCT size = 2^(7+1) = 256
        f.put(static_cast<char>(packed));
        f.put(static_cast<char>(g.bg_color));
        f.put(0); // pixel aspect ratio

        // Global Colour Table (256 entries)
        f.write(reinterpret_cast<const char*>(g.palette.data()),
                static_cast<std::streamsize>(g.palette.size()));

        // Image descriptor
        f.put(0x2C);
        wu16(0); wu16(0); // left, top
        wu16(g.width); wu16(g.height);
        f.put(0); // no local table, not interlaced

        // LZW encode indices
        uint8_t min_code_size = 8; // 256-colour palette
        f.put(static_cast<char>(min_code_size));

        Bytes lzw_data = lzw_encode(g.indices, min_code_size);

        // Write as sub-blocks (max 255 bytes each)
        std::size_t off = 0;
        while (off < lzw_data.size()) {
            std::size_t chunk = std::min<std::size_t>(255, lzw_data.size() - off);
            f.put(static_cast<char>(chunk));
            f.write(reinterpret_cast<const char*>(lzw_data.data() + off),
                    static_cast<std::streamsize>(chunk));
            off += chunk;
        }
        f.put(0); // block terminator

        // Trailer
        f.put(0x3B);

        if (!f) return Result<void>::err("GIF: write error");
        return Result<void>::ok();
    }

    // ── LZW Encoder (same algorithm as MediaGenerator::generate_gif) ─────────

    [[nodiscard]] static Bytes lzw_encode(const std::vector<uint8_t>& indices,
                                           uint8_t min_code_size) {
        int clear_code = 1 << min_code_size;
        int eoi_code   = clear_code + 1;
        int code_size  = min_code_size + 1;
        int next_code  = eoi_code + 1;
        bool first_after_clear = true;

        Bytes output;
        uint32_t bit_buffer = 0;
        int bits_in_buffer = 0;

        auto emit = [&](int code) {
            bit_buffer |= (static_cast<uint32_t>(code) << bits_in_buffer);
            bits_in_buffer += code_size;
            while (bits_in_buffer >= 8) {
                output.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }
        };

        emit(clear_code);

        for (std::size_t i = 0; i < indices.size(); ++i) {
            emit(indices[i]);

            if (first_after_clear) {
                first_after_clear = false;
            } else {
                next_code++;
                if (next_code == (1 << code_size)) {
                    if (code_size < 12) {
                        code_size++;
                    } else {
                        emit(clear_code);
                        code_size = min_code_size + 1;
                        next_code = eoi_code + 1;
                        first_after_clear = true;
                    }
                }
            }
        }

        emit(eoi_code);

        if (bits_in_buffer > 0)
            output.push_back(static_cast<uint8_t>(bit_buffer & 0xFF));

        return output;
    }
};

} // namespace crypto::stego
