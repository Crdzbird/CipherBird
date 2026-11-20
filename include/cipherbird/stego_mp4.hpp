#pragma once

/**
 * crypto::stego::Mp4Steganographer
 *
 * Steganography for MP4 files using custom metadata embedding.
 *
 * Embeds data as a custom 'free' (free space) atom/box in the MP4 container.
 * This approach:
 *   1. Parses the MP4 box structure to find a safe insertion point
 *   2. Inserts a 'free' box containing the steganographic payload
 *   3. The payload is wrapped in a custom UUID to avoid collisions
 *
 * This is a container-level technique: data survives remuxing but not
 * re-encoding. The 'free' box is a standard MP4 feature used for padding
 * and is typically preserved by MP4 tools.
 *
 * CAPACITY: Limited by available space. We insert a new box, so capacity
 * is essentially unlimited (constrained only by filesystem).
 */

#include "stego_types.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class Mp4Steganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      /*Q*/ = 16,
        std::span<const uint8_t> key = {})
    {
        auto data_res = read_file(cover_path);
        if (data_res.is_err()) return Result<void>::err(data_res.error().message);

        auto& data = data_res.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::MP4_VIDEO, key);

        // Build a 'free' box containing our magic UUID + payload
        Bytes free_box = build_free_box(stream);

        // Find insertion point: after 'ftyp' box or at the start
        std::size_t insert_pos = find_insert_position(data);

        // Insert the box
        Bytes output;
        output.reserve(data.size() + free_box.size());
        output.insert(output.end(), data.begin(), data.begin() + insert_pos);
        output.insert(output.end(), free_box.begin(), free_box.end());
        output.insert(output.end(), data.begin() + insert_pos, data.end());

        // Fix up any 'mdat' offsets if needed (stco/co64 atoms)
        // For simplicity, we insert before moov/mdat so chunk offsets
        // may need updating. We'll adjust stco/co64 entries.
        fix_chunk_offsets(output, insert_pos, free_box.size());

        return write_file(output_path, output);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                /*Q*/ = 16,
        std::span<const uint8_t> key = {})
    {
        auto data_res = read_file(stego_path);
        if (data_res.is_err()) return Result<Bytes>::err(data_res.error().message);

        auto& data = data_res.value();

        // Search for our custom 'free' box with the magic UUID
        auto payload = find_and_extract_free_box(data);
        if (payload.is_err()) return Result<Bytes>::err(payload.error().message);

        return parse_embed_stream(std::span<const uint8_t>(payload.value()), key);
    }

    [[nodiscard]] static std::size_t capacity() noexcept {
        // Container-level embedding: practically unlimited
        return 1024 * 1024; // Report 1MB as nominal capacity
    }

private:
    // Magic UUID to identify our steganographic 'free' boxes
    // "CSTG-MP4S-TEGO-UUID" encoded as 16 bytes
    static constexpr uint8_t MAGIC_UUID[16] = {
        0xC5, 0x7E, 0x60, 0x4D, 0x50, 0x34, 0x53, 0x54,
        0x45, 0x47, 0x4F, 0x55, 0x55, 0x49, 0x44, 0x00
    };

    [[nodiscard]] static Result<Bytes> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<Bytes>::err("MP4: cannot open '" + path + "'");
        auto sz = f.tellg();
        f.seekg(0);
        Bytes data(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);
        return Result<Bytes>::ok(std::move(data));
    }

    [[nodiscard]] static Result<void> write_file(const std::string& path, const Bytes& data) {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("MP4: cannot write '" + path + "'");
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        if (!f) return Result<void>::err("MP4: write error");
        return Result<void>::ok();
    }

    static uint32_t be32(const uint8_t* p) {
        return uint32_t(p[0])<<24 | uint32_t(p[1])<<16 | uint32_t(p[2])<<8 | uint32_t(p[3]);
    }

    static void put_be32(uint8_t* p, uint32_t v) {
        p[0]=uint8_t(v>>24); p[1]=uint8_t(v>>16); p[2]=uint8_t(v>>8); p[3]=uint8_t(v);
    }

    static uint64_t be64(const uint8_t* p) {
        return uint64_t(be32(p))<<32 | uint64_t(be32(p+4));
    }

    static void put_be64(uint8_t* p, uint64_t v) {
        put_be32(p, static_cast<uint32_t>(v >> 32));
        put_be32(p+4, static_cast<uint32_t>(v));
    }

    static Bytes build_free_box(const Bytes& stream) {
        // Box format: [size:4][type:4='free'][uuid:16][payload]
        uint32_t box_size = 8 + 16 + static_cast<uint32_t>(stream.size());
        Bytes box(box_size);
        put_be32(box.data(), box_size);
        box[4] = 'f'; box[5] = 'r'; box[6] = 'e'; box[7] = 'e';
        std::memcpy(box.data() + 8, MAGIC_UUID, 16);
        std::memcpy(box.data() + 24, stream.data(), stream.size());
        return box;
    }

    static std::size_t find_insert_position(const Bytes& data) {
        // Insert after 'ftyp' box if present
        if (data.size() < 8) return 0;
        std::size_t pos = 0;
        while (pos + 8 <= data.size()) {
            uint32_t size = be32(data.data() + pos);
            std::string type(reinterpret_cast<const char*>(data.data() + pos + 4), 4);
            if (size < 8) break;
            if (type == "ftyp") return pos + size;
            pos += size;
        }
        return 0; // Insert at beginning if no ftyp
    }

    [[nodiscard]] static Result<Bytes> find_and_extract_free_box(const Bytes& data) {
        std::size_t pos = 0;
        while (pos + 8 <= data.size()) {
            uint32_t size = be32(data.data() + pos);
            if (size < 8) break;
            if (pos + size > data.size()) break;

            std::string type(reinterpret_cast<const char*>(data.data() + pos + 4), 4);
            if (type == "free" && size >= 24) {
                // Check for our magic UUID
                if (std::memcmp(data.data() + pos + 8, MAGIC_UUID, 16) == 0) {
                    std::size_t payload_size = size - 24;
                    Bytes payload(data.data() + pos + 24, data.data() + pos + 24 + payload_size);
                    return Result<Bytes>::ok(std::move(payload));
                }
            }
            pos += size;
        }
        return Result<Bytes>::err("MP4: no steganographic data found");
    }

    static void fix_chunk_offsets(Bytes& data, std::size_t insert_pos, std::size_t shift) {
        // Find and fix stco (32-bit chunk offsets) and co64 (64-bit) atoms
        // These are inside moov/trak/mdia/minf/stbl
        fix_offsets_recursive(data, 0, data.size(), insert_pos, shift);
    }

    static void fix_offsets_recursive(
        Bytes& data, std::size_t start, std::size_t end,
        std::size_t insert_pos, std::size_t shift)
    {
        std::size_t pos = start;
        while (pos + 8 <= end) {
            uint32_t size = be32(data.data() + pos);
            if (size < 8 || pos + size > end) break;

            std::string type(reinterpret_cast<const char*>(data.data() + pos + 4), 4);

            if (type == "moov" || type == "trak" || type == "mdia"
                || type == "minf" || type == "stbl") {
                fix_offsets_recursive(data, pos + 8, pos + size, insert_pos, shift);
            } else if (type == "stco") {
                // 32-bit chunk offset table
                if (size >= 16) {
                    uint32_t entry_count = be32(data.data() + pos + 12);
                    for (uint32_t i = 0; i < entry_count && pos + 16 + i * 4 + 4 <= end; ++i) {
                        std::size_t off_pos = pos + 16 + i * 4;
                        uint32_t offset = be32(data.data() + off_pos);
                        if (offset >= insert_pos)
                            put_be32(data.data() + off_pos, offset + static_cast<uint32_t>(shift));
                    }
                }
            } else if (type == "co64") {
                // 64-bit chunk offset table
                if (size >= 16) {
                    uint32_t entry_count = be32(data.data() + pos + 12);
                    for (uint32_t i = 0; i < entry_count && pos + 16 + i * 8 + 8 <= end; ++i) {
                        std::size_t off_pos = pos + 16 + i * 8;
                        uint64_t offset = be64(data.data() + off_pos);
                        if (offset >= insert_pos)
                            put_be64(data.data() + off_pos, offset + shift);
                    }
                }
            }

            pos += size;
        }
    }
};

} // namespace crypto::stego
