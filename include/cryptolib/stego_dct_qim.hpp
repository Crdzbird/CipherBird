#pragma once

/**
 * crypto::stego::DctQimEngine — Shared DCT/QIM steganography primitives
 *
 * Provides the core DCT-domain Quantization Index Modulation (QIM) engine
 * used by all image-based steganographers (PPM, BMP, PNG, GIF, AVI, CRVF).
 *
 * All operations work on raw RGB24 pixel buffers (row-major, R G B interleaved).
 * Format-specific I/O is handled by each steganographer individually.
 */

#include "stego_types.hpp"

#include <array>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <numbers>
#include <vector>

namespace crypto::stego {

class DctQimEngine {
public:
    // 8 mid-frequency (r, c) positions in an 8x8 DCT block (zigzag positions 7-14).
    static constexpr std::array<std::pair<int,int>, 8> EMBED_COORDS = {{
        {1, 2}, {2, 1}, {0, 3}, {3, 0},
        {2, 2}, {1, 3}, {3, 1}, {4, 0}
    }};
    static constexpr int EMBED_BITS_PER_BLOCK = static_cast<int>(EMBED_COORDS.size());

    /// Maximum payload bytes (excluding header) an image of size w x h can carry.
    [[nodiscard]] static std::size_t capacity(std::size_t w, std::size_t h) noexcept {
        std::size_t blocks = (w / 8) * (h / 8);
        std::size_t bits   = blocks * EMBED_BITS_PER_BLOCK;
        std::size_t bytes  = bits / 8;
        return (bytes > StegoHeader::SIZE) ? (bytes - StegoHeader::SIZE) : 0;
    }

    /// Embed bits into the blue channel of an RGB24 pixel buffer using DCT/QIM.
    /// `perm`, when non-null, remaps logical block k → physical block perm[k],
    /// scattering the payload across the carrier (keyed permutation).
    static void embed_bits(
        std::vector<uint8_t>& pixels,
        std::size_t           w,
        std::size_t           h,
        const Bytes&          stream,
        int                   Q,
        const std::vector<uint32_t>* perm = nullptr)
    {
        const std::size_t blocks_x = w / 8;
        const std::size_t blocks_y = h / 8;
        const std::size_t total_blocks = blocks_x * blocks_y;
        const std::size_t total_bits = stream.size() * 8;
        const std::size_t bpb = static_cast<std::size_t>(EMBED_BITS_PER_BLOCK);
        const std::size_t needed_blocks = (total_bits + bpb - 1) / bpb;

        for (std::size_t k = 0; k < needed_blocks && k < total_blocks; ++k) {
            std::size_t p = perm ? static_cast<std::size_t>((*perm)[k]) : k;
            std::size_t bx = p % blocks_x, by = p / blocks_x;
            std::size_t first_bit = k * bpb;
            std::size_t bits_here = std::min(bpb, total_bits - first_bit);
            embed_block_cl(pixels, bx, by, w, stream, first_bit, bits_here, Q);
        }
    }

    /// Extract bits from the blue channel of an RGB24 pixel buffer using DCT/QIM.
    /// `perm` must match the permutation used at embed time (or null for none).
    [[nodiscard]] static Bytes extract_bits(
        const std::vector<uint8_t>& pixels,
        std::size_t                 w,
        std::size_t                 h,
        std::size_t                 max_stream_bytes,
        int                         Q,
        const std::vector<uint32_t>* perm = nullptr)
    {
        const std::size_t blocks_x = w / 8;
        const std::size_t blocks_y = h / 8;
        const std::size_t total_blocks = blocks_x * blocks_y;
        const std::size_t total_bits = max_stream_bytes * 8;
        const std::size_t bpb = static_cast<std::size_t>(EMBED_BITS_PER_BLOCK);
        const std::size_t needed_blocks = (total_bits + bpb - 1) / bpb;

        Bytes result(max_stream_bytes, 0);
        for (std::size_t k = 0; k < needed_blocks && k < total_blocks; ++k) {
            std::size_t p = perm ? static_cast<std::size_t>((*perm)[k]) : k;
            std::size_t bx = p % blocks_x, by = p / blocks_x;
            double blk[8][8];
            for (int r = 0; r < 8; ++r)
                for (int c = 0; c < 8; ++c)
                    blk[r][c] = static_cast<double>(pixels[blue_idx(bx*8+c, by*8+r, w)]);
            dct2d(blk);

            std::size_t bit_idx = k * bpb;
            for (const auto& [pr, pc] : EMBED_COORDS) {
                if (bit_idx >= total_bits) break;
                int bit    = qim_extract(blk[pr][pc], Q);
                int byte_i = static_cast<int>(bit_idx / 8);
                int bit_i  = 7 - static_cast<int>(bit_idx % 8);
                if (bit) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
                ++bit_idx;
            }
        }
        return result;
    }

    /// Compute PSNR (dB) between two RGB24 pixel buffers.
    [[nodiscard]] static double psnr(
        const std::vector<uint8_t>& a,
        const std::vector<uint8_t>& b)
    {
        if (a.size() != b.size() || a.empty()) return -1.0;
        double mse = 0.0;
        for (std::size_t i = 0; i < a.size(); ++i) {
            double d = static_cast<double>(a[i]) - static_cast<double>(b[i]);
            mse += d * d;
        }
        mse /= static_cast<double>(a.size());
        if (mse < 1e-10) return std::numeric_limits<double>::infinity();
        return 10.0 * std::log10(255.0 * 255.0 / mse);
    }

    // ── Low-level primitives (public for advanced use) ────────────────────────

    static std::size_t blue_idx(std::size_t c, std::size_t r, std::size_t w) noexcept {
        return (r * w + c) * 3 + 2;
    }

    static const std::array<std::array<double,8>,8>& dct_matrix() {
        static const auto M = [] {
            std::array<std::array<double,8>,8> m{};
            for (int k = 0; k < 8; ++k) {
                const double alpha = (k == 0)
                    ? 1.0 / std::sqrt(8.0)
                    : std::sqrt(2.0 / 8.0);
                for (int n = 0; n < 8; ++n)
                    m[k][n] = alpha * std::cos(std::numbers::pi * (2*n+1) * k / 16.0);
            }
            return m;
        }();
        return M;
    }

    static void dct1d(const double in[8], double out[8]) {
        const auto& M = dct_matrix();
        for (int k = 0; k < 8; ++k) {
            out[k] = 0.0;
            for (int n = 0; n < 8; ++n) out[k] += M[k][n] * in[n];
        }
    }

    static void idct1d(const double in[8], double out[8]) {
        const auto& M = dct_matrix();
        for (int n = 0; n < 8; ++n) {
            out[n] = 0.0;
            for (int k = 0; k < 8; ++k) out[n] += M[k][n] * in[k];
        }
    }

    static void dct2d(double blk[8][8]) {
        double tmp[8][8];
        for (int r = 0; r < 8; ++r) dct1d(blk[r], tmp[r]);
        for (int c = 0; c < 8; ++c) {
            double col[8], out[8];
            for (int r = 0; r < 8; ++r) col[r] = tmp[r][c];
            dct1d(col, out);
            for (int r = 0; r < 8; ++r) blk[r][c] = out[r];
        }
    }

    static void idct2d(double blk[8][8]) {
        double tmp[8][8];
        for (int r = 0; r < 8; ++r) idct1d(blk[r], tmp[r]);
        for (int c = 0; c < 8; ++c) {
            double col[8], out[8];
            for (int r = 0; r < 8; ++r) col[r] = tmp[r][c];
            idct1d(col, out);
            for (int r = 0; r < 8; ++r) blk[r][c] = out[r];
        }
    }

    static void qim_embed(double& coeff, int bit, int Q) {
        int idx = static_cast<int>(std::round(coeff / static_cast<double>(Q)));
        if ((idx & 1) != bit) {
            double val_minus = static_cast<double>((idx - 1) * Q);
            double val_plus  = static_cast<double>((idx + 1) * Q);
            coeff = (std::abs(val_minus - coeff) <= std::abs(val_plus - coeff))
                    ? val_minus : val_plus;
        } else {
            coeff = static_cast<double>(idx * Q);
        }
    }

    [[nodiscard]] static int qim_extract(double coeff, int Q) noexcept {
        return static_cast<int>(std::round(coeff / static_cast<double>(Q))) & 1;
    }

private:
    static void embed_block_cl(
        std::vector<uint8_t>& pixels,
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
                        pixels[blue_idx(bx*8+c, by*8+r, w)]);
            dct2d(blk);

            bool any_wrong = false;
            for (std::size_t b = 0; b < num_bits; ++b) {
                const auto& [pr, pc] = EMBED_COORDS[b];
                std::size_t gi = first_bit + b;
                int byte_i = static_cast<int>(gi / 8);
                int bit_i  = 7 - static_cast<int>(gi % 8);
                int want   = (stream[byte_i] >> bit_i) & 1;
                if (qim_extract(blk[pr][pc], Q) != want) {
                    qim_embed(blk[pr][pc], want, Q);
                    any_wrong = true;
                }
            }

            idct2d(blk);
            for (int r = 0; r < 8; ++r)
                for (int c = 0; c < 8; ++c) {
                    double v = std::round(blk[r][c]);
                    pixels[blue_idx(bx*8+c, by*8+r, w)] =
                        static_cast<uint8_t>(std::clamp(v, 0.0, 255.0));
                }
            if (!any_wrong) break;
        }
    }
};

} // namespace crypto::stego
