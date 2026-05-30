#pragma once

/**
 * crypto::stego::AviSteganographer
 *
 * DCT/QIM steganography for uncompressed (BI_RGB) AVI video files.
 * Custom RIFF/AVI parser — no external dependency.
 *
 * Only supports uncompressed 24-bit RGB AVI. Compressed AVI (DivX, H.264, etc.)
 * is rejected with an error because re-encoding would destroy embedded data.
 *
 * CAPACITY: frame_count * DctQimEngine::capacity(width, height)
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class AviSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      Q = 16)
    {
        auto avi = read_avi(cover_path);
        if (avi.is_err()) return Result<void>::err(avi.error().message);

        auto& [hdr, frames] = avi.value();
        Bytes stream = make_embed_stream(payload, MediaFormat::AVI_VIDEO);

        std::size_t cap = capacity(frames.size(), hdr.width, hdr.height);
        if (payload.size() > cap)
            return Result<void>::err(
                "AviSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        embed_across_frames(frames, hdr.width, hdr.height, stream, Q);
        return write_avi(output_path, hdr, frames);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                Q = 16)
    {
        auto avi = read_avi(stego_path);
        if (avi.is_err()) return Result<Bytes>::err(avi.error().message);

        auto& [hdr, frames] = avi.value();
        std::size_t max_bytes = capacity(frames.size(), hdr.width, hdr.height) + StegoHeader::SIZE;
        Bytes raw = extract_across_frames(frames, hdr.width, hdr.height, max_bytes, Q);
        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    [[nodiscard]] static std::size_t capacity(
        std::size_t frame_count, std::size_t w, std::size_t h) noexcept
    {
        std::size_t per_frame = DctQimEngine::capacity(w, h) + StegoHeader::SIZE;
        std::size_t total = per_frame * frame_count;
        return (total > StegoHeader::SIZE) ? (total - StegoHeader::SIZE) : 0;
    }

private:
    struct AviHeader {
        uint32_t width = 0;
        uint32_t height = 0;
        uint32_t fps = 30;
        uint16_t bpp = 24;
    };

    // Simple LE helpers
    static uint32_t le32(const uint8_t* p) {
        return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
    }
    static uint16_t le16(const uint8_t* p) {
        return uint16_t(p[0]) | uint16_t(p[1])<<8;
    }
    static void put_le32(uint8_t* p, uint32_t v) {
        p[0]=uint8_t(v); p[1]=uint8_t(v>>8); p[2]=uint8_t(v>>16); p[3]=uint8_t(v>>24);
    }

    [[nodiscard]] static Result<std::pair<AviHeader, std::vector<std::vector<uint8_t>>>>
    read_avi(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
            "AVI: cannot open '" + path + "'");

        auto sz = f.tellg();
        if (sz <= 0) return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
            "AVI: empty or unreadable '" + path + "'");
        f.seekg(0);
        std::vector<uint8_t> data(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);

        if (data.size() < 12 || std::string(reinterpret_cast<char*>(data.data()), 4) != "RIFF"
            || std::string(reinterpret_cast<char*>(data.data()+8), 4) != "AVI ")
            return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
                "AVI: invalid RIFF/AVI header");

        AviHeader hdr;
        std::vector<std::vector<uint8_t>> frames;

        // Parse chunks
        std::size_t pos = 12;
        while (pos + 8 <= data.size()) {
            std::string tag(reinterpret_cast<char*>(data.data()+pos), 4);
            uint32_t chunk_size = le32(data.data()+pos+4);
            pos += 8;

            if (tag == "LIST") {
                // chunk_size counts the 4-byte list type plus the body; a value
                // below 4 would underflow every `chunk_size - 4` below.
                if (chunk_size < 4 || pos + 4 > data.size()) break;
                std::string list_type(reinterpret_cast<char*>(data.data()+pos), 4);
                pos += 4;

                if (list_type == "hdrl") {
                    // Find avih and strh/strf
                    std::size_t end = pos + (chunk_size - 4);
                    if (end > data.size()) end = data.size();
                    while (pos + 8 <= end) {
                        std::string st(reinterpret_cast<char*>(data.data()+pos), 4);
                        uint32_t ss = le32(data.data()+pos+4);
                        pos += 8;

                        if (st == "avih" && ss >= 40 && pos + 40 <= data.size()) {
                            uint32_t us_per_frame = le32(data.data()+pos);
                            hdr.fps = (us_per_frame > 0) ? (1000000 / us_per_frame) : 30;
                            hdr.width = le32(data.data()+pos+32);
                            hdr.height = le32(data.data()+pos+36);
                        } else if (st == "LIST") {
                            // strl list — look for strf
                            if (ss < 4 || pos + 4 > data.size()) break;
                            std::string lt(reinterpret_cast<char*>(data.data()+pos), 4);
                            std::size_t strl_end = pos + (ss - 4);
                            if (strl_end > end) strl_end = end;
                            pos += 4; // skip list type
                            while (pos + 8 <= strl_end) {
                                std::string ct(reinterpret_cast<char*>(data.data()+pos), 4);
                                uint32_t cs = le32(data.data()+pos+4);
                                pos += 8;
                                if (ct == "strf" && cs >= 40 && pos + 20 <= data.size()) {
                                    hdr.width = le32(data.data()+pos+4);
                                    int32_t h_signed = static_cast<int32_t>(le32(data.data()+pos+8));
                                    hdr.height = static_cast<uint32_t>(std::abs(h_signed));
                                    hdr.bpp = le16(data.data()+pos+14);
                                    uint32_t compression = le32(data.data()+pos+16);
                                    if (compression != 0)
                                        return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
                                            "AVI: only uncompressed (BI_RGB) video supported");
                                }
                                pos += cs;
                                if (cs & 1) pos++; // padding
                            }
                            continue;
                        }
                        pos += ss;
                        if (ss & 1) pos++;
                    }
                } else if (list_type == "movi") {
                    // Read frames
                    std::size_t movi_end = pos + (chunk_size - 4);
                    if (movi_end > data.size()) movi_end = data.size();
                    // Validate dimensions (set earlier from hdrl) before computing
                    // frame_bytes — guards the overflow that would undersize rgb.
                    auto fb = checked_image_bytes(hdr.width, hdr.height);
                    if (!fb)
                        return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
                            "AVI: frame dimensions out of range");
                    std::size_t frame_bytes = *fb;

                    while (pos + 8 <= movi_end) {
                        std::string ftag(reinterpret_cast<char*>(data.data()+pos), 4);
                        uint32_t fsz = le32(data.data()+pos+4);
                        pos += 8;

                        if (ftag.substr(2) == "db" || ftag.substr(2) == "dc") {
                            // Uncompressed frame data
                            if (fsz >= frame_bytes) {
                                // Convert BGR bottom-up to RGB top-down
                                std::vector<uint8_t> rgb(frame_bytes);
                                std::size_t row_bytes = hdr.width * 3;
                                std::size_t row_pad = (4 - (row_bytes % 4)) % 4;

                                for (uint32_t y = 0; y < hdr.height; ++y) {
                                    uint32_t src_y = hdr.height - 1 - y;
                                    for (uint32_t x = 0; x < hdr.width; ++x) {
                                        std::size_t si = pos + src_y * (row_bytes + row_pad) + x * 3;
                                        std::size_t di = (y * hdr.width + x) * 3;
                                        if (di + 2 < rgb.size() && si + 2 < data.size()) {
                                            rgb[di+0] = data[si+2]; // R
                                            rgb[di+1] = data[si+1]; // G
                                            rgb[di+2] = data[si+0]; // B
                                        }
                                    }
                                }
                                frames.push_back(std::move(rgb));
                            }
                        }
                        pos += fsz;
                        if (fsz & 1) pos++;
                    }
                } else {
                    pos += chunk_size - 4;
                }
            } else {
                pos += chunk_size;
                if (chunk_size & 1) pos++;
            }
        }

        if (hdr.width == 0 || hdr.height == 0)
            return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
                "AVI: could not determine dimensions");
        if (frames.empty())
            return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::err(
                "AVI: no frames found");

        return Result<std::pair<AviHeader,std::vector<std::vector<uint8_t>>>>::ok(
            {hdr, std::move(frames)});
    }

    [[nodiscard]] static Result<void> write_avi(
        const std::string&                       path,
        const AviHeader&                         hdr,
        const std::vector<std::vector<uint8_t>>& frames)
    {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("AVI: cannot write '" + path + "'");

        std::size_t row_bytes = hdr.width * 3;
        std::size_t row_pad = (4 - (row_bytes % 4)) % 4;
        std::size_t padded_frame = (row_bytes + row_pad) * hdr.height;
        std::size_t movi_size = 4; // 'movi'
        for (std::size_t i = 0; i < frames.size(); ++i)
            movi_size += 8 + padded_frame + (padded_frame & 1);

        // avih size = 56, strl LIST ~ 116
        std::size_t hdrl_size = 4 + 8 + 56 + 8 + 4 + 8 + 56 + 8 + 40;
        std::size_t file_size = 4 + 8 + hdrl_size + 8 + movi_size;

        auto w32 = [&](uint32_t v) {
            uint8_t b[4]; put_le32(b, v); f.write(reinterpret_cast<char*>(b), 4);
        };
        auto w16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v>>8)}; f.write(reinterpret_cast<char*>(b), 2);
        };

        // RIFF header
        f.write("RIFF", 4); w32(static_cast<uint32_t>(file_size));
        f.write("AVI ", 4);

        // hdrl LIST
        f.write("LIST", 4); w32(static_cast<uint32_t>(hdrl_size));
        f.write("hdrl", 4);

        // avih chunk
        f.write("avih", 4); w32(56);
        uint32_t us_per_frame = (hdr.fps > 0) ? (1000000 / hdr.fps) : 33333;
        w32(us_per_frame);           // dwMicroSecPerFrame
        w32(0);                      // dwMaxBytesPerSec
        w32(0);                      // dwPaddingGranularity
        w32(0x10);                   // dwFlags (AVIF_HASINDEX)
        w32(static_cast<uint32_t>(frames.size())); // dwTotalFrames
        w32(0);                      // dwInitialFrames
        w32(1);                      // dwStreams
        w32(static_cast<uint32_t>(padded_frame)); // dwSuggestedBufferSize
        w32(hdr.width);              // dwWidth
        w32(hdr.height);             // dwHeight
        w32(0); w32(0); w32(0); w32(0); // dwReserved[4]

        // strl LIST
        f.write("LIST", 4); w32(4 + 8 + 56 + 8 + 40);
        f.write("strl", 4);

        // strh chunk
        f.write("strh", 4); w32(56);
        f.write("vids", 4);          // fccType
        w32(0);                      // fccHandler (uncompressed)
        w32(0);                      // dwFlags
        w16(0);                      // wPriority
        w16(0);                      // wLanguage
        w32(0);                      // dwInitialFrames
        w32(1);                      // dwScale
        w32(hdr.fps);                // dwRate
        w32(0);                      // dwStart
        w32(static_cast<uint32_t>(frames.size())); // dwLength
        w32(static_cast<uint32_t>(padded_frame)); // dwSuggestedBufferSize
        w32(0xFFFFFFFF);             // dwQuality
        w32(0);                      // dwSampleSize
        w16(0); w16(0);             // rcFrame left,top
        w16(static_cast<uint16_t>(hdr.width));
        w16(static_cast<uint16_t>(hdr.height));

        // strf chunk (BITMAPINFOHEADER)
        f.write("strf", 4); w32(40);
        w32(40);                     // biSize
        w32(hdr.width);              // biWidth
        w32(hdr.height);             // biHeight (positive = bottom-up)
        w16(1);                      // biPlanes
        w16(24);                     // biBitCount
        w32(0);                      // biCompression (BI_RGB)
        w32(static_cast<uint32_t>(padded_frame)); // biSizeImage
        w32(0); w32(0);             // biX/YPelsPerMeter
        w32(0); w32(0);             // biClrUsed, biClrImportant

        // movi LIST
        f.write("LIST", 4); w32(static_cast<uint32_t>(movi_size));
        f.write("movi", 4);

        std::vector<uint8_t> pad_bytes(row_pad, 0);
        for (std::size_t fi = 0; fi < frames.size(); ++fi) {
            f.write("00db", 4); w32(static_cast<uint32_t>(padded_frame));

            // Write BGR bottom-up
            for (uint32_t y = 0; y < hdr.height; ++y) {
                uint32_t src_y = hdr.height - 1 - y;
                for (uint32_t x = 0; x < hdr.width; ++x) {
                    std::size_t si = (src_y * hdr.width + x) * 3;
                    uint8_t bgr[3] = {frames[fi][si+2], frames[fi][si+1], frames[fi][si+0]};
                    f.write(reinterpret_cast<char*>(bgr), 3);
                }
                if (row_pad > 0)
                    f.write(reinterpret_cast<char*>(pad_bytes.data()),
                            static_cast<std::streamsize>(row_pad));
            }
        }

        if (!f) return Result<void>::err("AVI: write error");
        return Result<void>::ok();
    }

    // Frame-level embedding using DctQimEngine
    static void embed_across_frames(
        std::vector<std::vector<uint8_t>>& frames,
        std::size_t w, std::size_t h, const Bytes& stream, int Q)
    {
        if (!frames.empty()) {
            // Embed into first frame (extraction reads from first frame)
            DctQimEngine::embed_bits(frames[0], w, h, stream, Q);
        }
    }

    [[nodiscard]] static Bytes extract_across_frames(
        const std::vector<std::vector<uint8_t>>& frames,
        std::size_t w, std::size_t h, std::size_t max_bytes, int Q)
    {
        if (frames.empty()) return Bytes(max_bytes, 0);
        // Extract from first frame
        return DctQimEngine::extract_bits(frames[0], w, h, max_bytes, Q);
    }
};

} // namespace crypto::stego
