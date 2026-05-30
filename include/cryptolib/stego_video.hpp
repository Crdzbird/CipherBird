#pragma once

/**
 * crypto::stego::VideoSteganographer
 *
 * DCT-domain steganography for the CryptoLib Raw Video Format (CRVF).
 * Delegates core DCT/QIM operations to DctQimEngine on a per-frame basis.
 */

#include "stego_types.hpp"
#include "stego_dct_qim.hpp"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class VideoSteganographer {
public:
    struct CrvfHeader {
        static constexpr std::size_t SIZE = 25;

        uint32_t width       = 0;
        uint32_t height      = 0;
        uint32_t fps_num     = 30;
        uint16_t fps_den     = 1;
        uint32_t frame_count = 0;
        uint16_t pixel_fmt   = 0;
    };

    [[nodiscard]] static Result<void> write_crvf(
        const std::string&                       path,
        const CrvfHeader&                        hdr,
        const std::vector<std::vector<uint8_t>>& frames)
    {
        if (frames.size() != hdr.frame_count)
            return Result<void>::err("CRVF write: frame_count mismatch");

        std::size_t frame_bytes = static_cast<std::size_t>(hdr.width)
                                * static_cast<std::size_t>(hdr.height) * 3;
        for (auto& fr : frames)
            if (fr.size() != frame_bytes)
                return Result<void>::err("CRVF write: frame size mismatch");

        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("CRVF: cannot write '" + path + "'");

        write_crvf_header(f, hdr);
        for (const auto& fr : frames)
            f.write(reinterpret_cast<const char*>(fr.data()),
                    static_cast<std::streamsize>(fr.size()));

        if (!f) return Result<void>::err("CRVF: write error");
        return Result<void>::ok();
    }

    [[nodiscard]] static Result<std::pair<CrvfHeader, std::vector<std::vector<uint8_t>>>>
    read_crvf(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
            "CRVF: cannot open '" + path + "'");

        auto hdr_res = read_crvf_header(f);
        if (hdr_res.is_err())
            return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
                hdr_res.error().message);

        const auto& hdr = hdr_res.value();

        // Validate dimensions and frame count before allocating. Without this,
        // crafted width/height overflow frame_bytes (→ per-frame buffers too
        // small for blue_idx) and a huge frame_count drives an astronomical
        // allocation before a single byte is read.
        auto frame_bytes_opt = checked_image_bytes(hdr.width, hdr.height);
        if (!frame_bytes_opt)
            return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
                "CRVF: frame dimensions out of range in '" + path + "'");
        const std::size_t frame_bytes = *frame_bytes_opt;

        if (hdr.frame_count > detail::MAX_FRAME_COUNT)
            return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
                "CRVF: frame_count out of range in '" + path + "'");

        // Cross-check the declared payload against the bytes actually present so
        // a lie in the header can't trigger an over-large allocation.
        const std::streampos data_start = f.tellg();
        f.seekg(0, std::ios::end);
        const std::streampos file_end = f.tellg();
        f.seekg(data_start);
        const std::size_t remaining =
            (file_end > data_start)
                ? static_cast<std::size_t>(file_end - data_start) : 0;
        std::size_t required = 0;
        if (!detail::checked_mul(hdr.frame_count, frame_bytes, required)
            || required > remaining)
            return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
                "CRVF: truncated frame data in '" + path + "'");

        std::vector<std::vector<uint8_t>> frames(hdr.frame_count,
                                                  std::vector<uint8_t>(frame_bytes));
        for (auto& fr : frames) {
            f.read(reinterpret_cast<char*>(fr.data()),
                   static_cast<std::streamsize>(frame_bytes));
            if (!f)
                return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::err(
                    "CRVF: truncated frame data in '" + path + "'");
        }

        return Result<std::pair<CrvfHeader,std::vector<std::vector<uint8_t>>>>::ok(
            {hdr, std::move(frames)});
    }

    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        const StegoParams&       params = {})
    {
        auto vid_res = read_crvf(cover_path);
        if (vid_res.is_err()) return Result<void>::err(vid_res.error().message);

        auto& [hdr, frames] = vid_res.value();
        const std::size_t w = hdr.width, h = hdr.height;

        Bytes stream = make_embed_stream(payload, MediaFormat::CRVF_VIDEO);

        std::size_t cap = capacity(hdr.frame_count, w, h, params);
        if (payload.size() > cap)
            return Result<void>::err(
                "VideoSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        embed_across_frames(frames, w, h, stream, params.image_quant_step);
        return write_crvf(output_path, hdr, frames);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        const StegoParams& params = {})
    {
        auto vid_res = read_crvf(stego_path);
        if (vid_res.is_err()) return Result<Bytes>::err(vid_res.error().message);

        auto& [hdr, frames] = vid_res.value();
        const std::size_t w = hdr.width, h = hdr.height;

        std::size_t max_bytes = capacity(hdr.frame_count, w, h, params) + StegoHeader::SIZE;
        Bytes raw = extract_across_frames(frames, w, h, max_bytes, params.image_quant_step);
        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    [[nodiscard]] static std::size_t capacity(
        std::size_t        frame_count,
        std::size_t        w,
        std::size_t        h,
        const StegoParams& = {}) noexcept
    {
        std::size_t per_frame_bits  = (w / 8) * (h / 8) * DctQimEngine::EMBED_BITS_PER_BLOCK;
        std::size_t total_bits      = per_frame_bits * frame_count;
        std::size_t total_bytes     = total_bits / 8;
        return (total_bytes > StegoHeader::SIZE) ? (total_bytes - StegoHeader::SIZE) : 0;
    }

private:
    static void write_crvf_header(std::ofstream& f, const CrvfHeader& hdr) {
        f.write("CRVF", 4);
        uint8_t ver = 1;
        f.write(reinterpret_cast<const char*>(&ver), 1);
        write_u32(f, hdr.width);
        write_u32(f, hdr.height);
        write_u32(f, hdr.fps_num);
        write_u16(f, hdr.fps_den);
        write_u32(f, hdr.frame_count);
        write_u16(f, hdr.pixel_fmt);
    }

    [[nodiscard]] static Result<CrvfHeader> read_crvf_header(std::ifstream& f) {
        char magic[4];
        f.read(magic, 4);
        if (std::string(magic, 4) != "CRVF")
            return Result<CrvfHeader>::err("CRVF: invalid magic — expected 'CRVF'");

        uint8_t ver;
        f.read(reinterpret_cast<char*>(&ver), 1);
        if (ver != 1)
            return Result<CrvfHeader>::err("CRVF: unsupported version "
                + std::to_string(ver));

        CrvfHeader hdr;
        hdr.width       = read_u32(f);
        hdr.height      = read_u32(f);
        hdr.fps_num     = read_u32(f);
        hdr.fps_den     = read_u16(f);
        hdr.frame_count = read_u32(f);
        hdr.pixel_fmt   = read_u16(f);

        if (!f || hdr.width == 0 || hdr.height == 0 || hdr.frame_count == 0)
            return Result<CrvfHeader>::err("CRVF: corrupt or empty header");

        return Result<CrvfHeader>::ok(hdr);
    }

    static void write_u32(std::ofstream& f, uint32_t v) {
        uint8_t b[4] = {uint8_t(v), uint8_t(v>>8), uint8_t(v>>16), uint8_t(v>>24)};
        f.write(reinterpret_cast<char*>(b), 4);
    }
    static void write_u16(std::ofstream& f, uint16_t v) {
        uint8_t b[2] = {uint8_t(v), uint8_t(v>>8)};
        f.write(reinterpret_cast<char*>(b), 2);
    }
    static uint32_t read_u32(std::ifstream& f) {
        uint8_t b[4]; f.read(reinterpret_cast<char*>(b), 4);
        return uint32_t(b[0]) | uint32_t(b[1])<<8 | uint32_t(b[2])<<16 | uint32_t(b[3])<<24;
    }
    static uint16_t read_u16(std::ifstream& f) {
        uint8_t b[2]; f.read(reinterpret_cast<char*>(b), 2);
        return uint16_t(b[0]) | uint16_t(b[1])<<8;
    }

    // Embed bits across frames using DctQimEngine per-frame
    static void embed_across_frames(
        std::vector<std::vector<uint8_t>>& frames,
        std::size_t                         w,
        std::size_t                         h,
        const Bytes&                        stream,
        int                                 Q)
    {
        const std::size_t bx_count = w / 8;
        const std::size_t by_count = h / 8;
        const std::size_t bits_per_frame = bx_count * by_count * DctQimEngine::EMBED_BITS_PER_BLOCK;

        std::size_t global_bit = 0;
        const std::size_t total_bits = stream.size() * 8;

        for (auto& frame : frames) {
            if (global_bit >= total_bits) break;

            std::size_t frame_end = std::min(global_bit + bits_per_frame, total_bits);

            for (std::size_t by = 0; by < by_count && global_bit < frame_end; ++by) {
                for (std::size_t bx = 0; bx < bx_count && global_bit < frame_end; ++bx) {
                    std::size_t bits_here = std::min(
                        static_cast<std::size_t>(DctQimEngine::EMBED_BITS_PER_BLOCK),
                        frame_end - global_bit);

                    // Use DctQimEngine primitives directly for per-block embed
                    embed_block_cl(frame, bx, by, w, stream, global_bit, bits_here, Q);
                    global_bit += bits_here;
                }
            }
        }
    }

    static void embed_block_cl(
        std::vector<uint8_t>& frame,
        std::size_t            bx,
        std::size_t            by,
        std::size_t            w,
        const Bytes&           stream,
        std::size_t            first_bit,
        std::size_t            num_bits,
        int                    Q)
    {
        constexpr int MAX_ITER = 4;
        for (int iter = 0; iter < MAX_ITER; ++iter) {
            double blk[8][8];
            for (int r = 0; r < 8; ++r)
                for (int c = 0; c < 8; ++c)
                    blk[r][c] = static_cast<double>(
                        frame[DctQimEngine::blue_idx(bx*8+c, by*8+r, w)]);

            DctQimEngine::dct2d(blk);

            bool any_wrong = false;
            for (std::size_t b = 0; b < num_bits; ++b) {
                const auto& [pr, pc] = DctQimEngine::EMBED_COORDS[b];
                std::size_t global = first_bit + b;
                int byte_i = static_cast<int>(global / 8);
                int bit_i  = 7 - static_cast<int>(global % 8);
                int want   = (stream[byte_i] >> bit_i) & 1;
                int got    = DctQimEngine::qim_extract(blk[pr][pc], Q);
                if (got != want) {
                    DctQimEngine::qim_embed(blk[pr][pc], want, Q);
                    any_wrong = true;
                }
            }

            DctQimEngine::idct2d(blk);
            for (int r = 0; r < 8; ++r)
                for (int c = 0; c < 8; ++c) {
                    double v = std::round(blk[r][c]);
                    frame[DctQimEngine::blue_idx(bx*8+c, by*8+r, w)] =
                        static_cast<uint8_t>(std::clamp(v, 0.0, 255.0));
                }
            if (!any_wrong) break;
        }
    }

    [[nodiscard]] static Bytes extract_across_frames(
        const std::vector<std::vector<uint8_t>>& frames,
        std::size_t                               w,
        std::size_t                               h,
        std::size_t                               max_bytes,
        int                                       Q)
    {
        const std::size_t bx_count = w / 8;
        const std::size_t by_count = h / 8;

        Bytes result(max_bytes, 0);
        std::size_t global_bit = 0;
        const std::size_t total_bits = max_bytes * 8;

        for (const auto& frame : frames) {
            if (global_bit >= total_bits) break;

            for (std::size_t by = 0; by < by_count && global_bit < total_bits; ++by) {
                for (std::size_t bx = 0; bx < bx_count && global_bit < total_bits; ++bx) {
                    double blk[8][8];
                    for (int r = 0; r < 8; ++r)
                        for (int c = 0; c < 8; ++c)
                            blk[r][c] = static_cast<double>(
                                frame[DctQimEngine::blue_idx(bx*8+c, by*8+r, w)]);

                    DctQimEngine::dct2d(blk);

                    for (const auto& [pr, pc] : DctQimEngine::EMBED_COORDS) {
                        if (global_bit >= total_bits) break;
                        int bit    = DctQimEngine::qim_extract(blk[pr][pc], Q);
                        int byte_i = static_cast<int>(global_bit / 8);
                        int bit_i  = 7 - static_cast<int>(global_bit % 8);
                        if (bit) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
                        ++global_bit;
                    }
                }
            }
        }

        return result;
    }
};

} // namespace crypto::stego
