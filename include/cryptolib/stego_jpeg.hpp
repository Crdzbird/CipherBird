#pragma once

/**
 * crypto::stego::JpegSteganographer
 *
 * JSteg-style steganography for JPEG images.
 *
 * Embeds data in the LSBs of quantized DCT coefficients without full
 * decode/re-encode, preserving image quality. Coefficients with values
 * 0, +1, and -1 are skipped to minimize visual artifacts and avoid
 * statistical detectability.
 *
 * This implementation includes a minimal JPEG parser that:
 *   1. Reads JPEG markers (SOI, DQT, SOF, DHT, SOS, EOI)
 *   2. Builds Huffman tables from DHT markers
 *   3. Decodes the entropy-coded segment to access DCT coefficients
 *   4. Modifies coefficient LSBs (JSteg algorithm)
 *   5. Re-encodes the entropy-coded segment with modified coefficients
 *
 * CAPACITY: ~5-15% of JPEG file size (depends on image content).
 * LIMITATION: Detectable by chi-square attack. Not forensic-grade.
 *
 * Progressive JPEG (SOF2) is auto-converted to baseline (SOF0) before
 * embedding via stb_image decode + stbi_write_jpg re-encode (quality 95).
 */

#include "stego_types.hpp"
#include "stego_png.hpp"  // stb_image / stb_image_write (with STBI_ONLY_JPEG enabled)

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class JpegSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        int                      /*Q*/ = 16)
    {
        auto file_data = read_file(cover_path);
        if (file_data.is_err()) return Result<void>::err(file_data.error().message);

        // Auto-convert progressive JPEG to baseline
        if (is_progressive(file_data.value())) {
            auto conv = progressive_to_baseline(file_data.value());
            if (conv.is_err()) return Result<void>::err(conv.error().message);
            file_data = Result<Bytes>::ok(std::move(conv.value()));
        }

        Bytes stream = make_embed_stream(payload, MediaFormat::JPEG_IMAGE);

        auto result = jsteg_embed(file_data.value(), stream);
        if (result.is_err()) return Result<void>::err(result.error().message);

        return write_file(output_path, result.value());
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        int                /*Q*/ = 16)
    {
        auto file_data = read_file(stego_path);
        if (file_data.is_err()) return Result<Bytes>::err(file_data.error().message);

        // Stego output from embed() is always baseline, but handle gracefully
        if (is_progressive(file_data.value())) {
            auto conv = progressive_to_baseline(file_data.value());
            if (conv.is_err()) return Result<Bytes>::err(conv.error().message);
            file_data = Result<Bytes>::ok(std::move(conv.value()));
        }

        auto raw = jsteg_extract(file_data.value());
        if (raw.is_err()) return Result<Bytes>::err(raw.error().message);

        return parse_embed_stream(std::span<const uint8_t>(raw.value()));
    }

    [[nodiscard]] static Result<std::size_t> capacity_from_file(const std::string& path) {
        auto file_data = read_file(path);
        if (file_data.is_err()) return Result<std::size_t>::err(file_data.error().message);

        if (is_progressive(file_data.value())) {
            auto conv = progressive_to_baseline(file_data.value());
            if (conv.is_err()) return Result<std::size_t>::err(conv.error().message);
            file_data = Result<Bytes>::ok(std::move(conv.value()));
        }

        return jsteg_capacity(file_data.value());
    }

private:
    // ── File I/O ──────────────────────────────────────────────────────────────

    [[nodiscard]] static Result<Bytes> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<Bytes>::err("JPEG: cannot open '" + path + "'");
        auto sz = f.tellg();
        if (sz <= 0) return Result<Bytes>::err("JPEG: empty or unreadable '" + path + "'");
        f.seekg(0);
        Bytes data(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);
        if (!f) return Result<Bytes>::err("JPEG: read error");
        return Result<Bytes>::ok(std::move(data));
    }

    [[nodiscard]] static Result<void> write_file(const std::string& path, const Bytes& data) {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("JPEG: cannot write '" + path + "'");
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        if (!f) return Result<void>::err("JPEG: write error");
        return Result<void>::ok();
    }

    // ── Progressive JPEG detection and conversion ──────────────────────────────

    static bool is_progressive(const Bytes& jpeg) {
        if (jpeg.size() < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8) return false;
        std::size_t pos = 2;
        while (pos + 3 < jpeg.size()) {
            if (jpeg[pos] != 0xFF) { pos++; continue; }
            uint8_t marker = jpeg[pos + 1];
            if (marker == 0xC0) return false; // SOF0 = baseline
            if (marker == 0xC2) return true;  // SOF2 = progressive
            if (marker == 0xD9) break;        // EOI
            if (marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
                pos += 2; continue;
            }
            if (pos + 3 >= jpeg.size()) break;
            uint16_t len = (uint16_t(jpeg[pos+2]) << 8) | jpeg[pos+3];
            pos += 2 + len;
        }
        return false;
    }

    static void jpg_write_cb(void* ctx, void* data, int size) {
        auto* vec = static_cast<Bytes*>(ctx);
        auto* d = static_cast<const uint8_t*>(data);
        vec->insert(vec->end(), d, d + size);
    }

    [[nodiscard]] static Result<Bytes> progressive_to_baseline(const Bytes& jpeg) {
        int w, h, channels;
        uint8_t* pixels = stbi_load_from_memory(
            jpeg.data(), static_cast<int>(jpeg.size()), &w, &h, &channels, 3);
        if (!pixels)
            return Result<Bytes>::err(
                std::string("JPEG: cannot decode progressive: ") + stbi_failure_reason());

        Bytes baseline;
        int ok = stbi_write_jpg_to_func(jpg_write_cb, &baseline, w, h, 3, pixels, 95);
        stbi_image_free(pixels);

        if (!ok || baseline.empty())
            return Result<Bytes>::err("JPEG: baseline re-encode failed");

        return Result<Bytes>::ok(std::move(baseline));
    }

    // ── Huffman table ─────────────────────────────────────────────────────────

    struct HuffTable {
        std::array<uint8_t, 256> symbols{};
        std::array<int, 17> offsets{};   // offsets[i] = first symbol index for codes of length i
        std::array<int, 17> mincode{};   // mincode[i] = smallest code of length i
        std::array<int, 17> maxcode{};   // maxcode[i] = largest code of length i (-1 if none)
        int total_symbols = 0;

        // For encoding: symbol -> (code, length)
        std::array<uint16_t, 256> encode_code{};
        std::array<uint8_t, 256>  encode_len{};
    };

    static void build_huff_table(HuffTable& ht, const uint8_t* bits, const uint8_t* values) {
        int offset = 0;
        for (int i = 1; i <= 16; ++i) {
            ht.offsets[i] = offset;
            offset += bits[i - 1];
        }
        ht.total_symbols = offset;

        for (int i = 0; i < offset; ++i)
            ht.symbols[i] = values[i];

        int code = 0;
        for (int i = 1; i <= 16; ++i) {
            ht.mincode[i] = code;
            if (bits[i - 1] == 0) {
                ht.maxcode[i] = -1; // no codes at this length
            } else {
                for (int j = 0; j < bits[i - 1]; ++j) {
                    int sym_idx = ht.offsets[i] + j;
                    ht.encode_code[ht.symbols[sym_idx]] = static_cast<uint16_t>(code);
                    ht.encode_len[ht.symbols[sym_idx]] = static_cast<uint8_t>(i);
                    code++;
                }
                ht.maxcode[i] = code - 1;
            }
            code <<= 1;
        }
    }

    // ── Bitstream reader/writer ──────────────────────────────────────────────

    struct BitReader {
        const uint8_t* data;
        std::size_t    pos;
        std::size_t    end;
        int            bit_pos; // bits remaining in current byte
        uint8_t        cur_byte;

        BitReader(const uint8_t* d, std::size_t start, std::size_t e)
            : data(d), pos(start), end(e), bit_pos(0), cur_byte(0) {}

        int read_bit() {
            if (bit_pos == 0) {
                if (pos >= end) return -1;
                cur_byte = data[pos++];
                // Handle byte stuffing (0xFF 0x00)
                if (cur_byte == 0xFF && pos < end && data[pos] == 0x00)
                    pos++;
                bit_pos = 8;
            }
            bit_pos--;
            return (cur_byte >> bit_pos) & 1;
        }

        int read_bits(int n) {
            int val = 0;
            for (int i = 0; i < n; ++i) {
                int b = read_bit();
                if (b < 0) return -1;
                val = (val << 1) | b;
            }
            return val;
        }
    };

    struct BitWriter {
        Bytes          output;
        uint8_t        cur_byte = 0;
        int            bit_pos = 0;

        void write_bit(int bit) {
            cur_byte = (cur_byte << 1) | (bit & 1);
            bit_pos++;
            if (bit_pos == 8) {
                output.push_back(cur_byte);
                // Byte stuffing
                if (cur_byte == 0xFF)
                    output.push_back(0x00);
                cur_byte = 0;
                bit_pos = 0;
            }
        }

        void write_bits(int val, int n) {
            for (int i = n - 1; i >= 0; --i)
                write_bit((val >> i) & 1);
        }

        void flush() {
            if (bit_pos > 0) {
                cur_byte <<= (8 - bit_pos);
                output.push_back(cur_byte);
                if (cur_byte == 0xFF)
                    output.push_back(0x00);
                cur_byte = 0;
                bit_pos = 0;
            }
        }
    };

    // ── Decode one Huffman symbol ─────────────────────────────────────────────

    static int decode_huff(BitReader& br, const HuffTable& ht) {
        int code = 0;
        for (int len = 1; len <= 16; ++len) {
            int b = br.read_bit();
            if (b < 0) return -1;
            code = (code << 1) | b;
            if (ht.maxcode[len] >= 0 && code <= ht.maxcode[len]) {
                int idx = ht.offsets[len] + (code - ht.mincode[len]);
                if (idx >= 0 && idx < ht.total_symbols)
                    return ht.symbols[idx];
                return -1;
            }
        }
        return -1;
    }

    // ── Encode one Huffman symbol ─────────────────────────────────────────────

    static void encode_huff(BitWriter& bw, const HuffTable& ht, uint8_t symbol) {
        bw.write_bits(ht.encode_code[symbol], ht.encode_len[symbol]);
    }

    // ── JPEG scan info parsed from markers ─────────────────────────────────

    struct SofComponent {
        uint8_t id;           // component identifier
        int     h_samp;       // horizontal sampling factor
        int     v_samp;       // vertical sampling factor
        int     quant_table;  // quantization table index
    };

    struct JpegScanInfo {
        HuffTable     dc_tables[4];
        HuffTable     ac_tables[4];
        SofComponent  sof_comps[4];       // from SOF0
        int           sof_num_components = 0;
        int           scan_comp_order[4]; // SOS component index → SOF component index
        int           comp_dc_table[4] = {};
        int           comp_ac_table[4] = {};
        int           num_scan_comps = 0;
        int           max_h_samp = 1;
        int           max_v_samp = 1;
        int           restart_interval = 0; // 0 = no restart markers
        std::size_t   scan_start = 0;
        std::size_t   scan_end = 0;
        int           image_width = 0;
        int           image_height = 0;
    };

    /// Parse all JPEG markers (SOF0, DHT, DRI, SOS) to build scan info.
    [[nodiscard]] static Result<JpegScanInfo> parse_jpeg_markers(
        const Bytes& jpeg, Bytes* output_prefix = nullptr)
    {
        if (jpeg.size() < 2 || jpeg[0] != 0xFF || jpeg[1] != 0xD8)
            return Result<JpegScanInfo>::err("JPEG: invalid SOI marker");

        JpegScanInfo info;
        std::size_t pos = 2;

        while (pos < jpeg.size() - 1) {
            if (jpeg[pos] != 0xFF) { pos++; continue; }
            uint8_t marker = jpeg[pos + 1];
            pos += 2;

            if (marker == 0xD9) break; // EOI
            if (marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
                continue;
            if (pos + 1 >= jpeg.size()) break;
            uint16_t length = (static_cast<uint16_t>(jpeg[pos]) << 8) | jpeg[pos + 1];

            // The segment occupies [pos, pos+length); length counts its own 2
            // length bytes. Validate once against the buffer so every field read
            // in the marker handlers below stays in bounds — these fields are
            // attacker-controlled and previously read with no bounds checks.
            if (length < 2 || pos + length > jpeg.size())
                return Result<JpegScanInfo>::err("JPEG: truncated marker segment");

            // SOF0 (baseline DCT) — component subsampling info
            if (marker == 0xC0) {
                // body: precision(1) + height(2) + width(2) + num_comp(1) + comps*3
                if (length < 8)
                    return Result<JpegScanInfo>::err("JPEG: malformed SOF0 segment");
                info.image_height = (jpeg[pos + 3] << 8) | jpeg[pos + 4];
                info.image_width  = (jpeg[pos + 5] << 8) | jpeg[pos + 6];
                info.sof_num_components = jpeg[pos + 7];
                if (info.sof_num_components > 4) info.sof_num_components = 4;
                if (8 + info.sof_num_components * 3 > length)
                    return Result<JpegScanInfo>::err("JPEG: SOF0 component list out of range");

                for (int i = 0; i < info.sof_num_components; ++i) {
                    std::size_t cp = pos + 8 + i * 3;
                    info.sof_comps[i].id         = jpeg[cp];
                    info.sof_comps[i].h_samp     = (jpeg[cp + 1] >> 4) & 0x0F;
                    info.sof_comps[i].v_samp     = jpeg[cp + 1] & 0x0F;
                    info.sof_comps[i].quant_table = jpeg[cp + 2];
                    if (info.sof_comps[i].h_samp > info.max_h_samp)
                        info.max_h_samp = info.sof_comps[i].h_samp;
                    if (info.sof_comps[i].v_samp > info.max_v_samp)
                        info.max_v_samp = info.sof_comps[i].v_samp;
                }
            }

            // DHT — Huffman tables
            if (marker == 0xC4) {
                std::size_t dht_pos = pos + 2;
                std::size_t dht_end = pos + length;
                while (dht_pos < dht_end) {
                    uint8_t hi = jpeg[dht_pos++];
                    int table_class = (hi >> 4) & 0x0F;
                    int table_id    = hi & 0x0F;
                    if (table_id >= 4) break;
                    // Need 16 count bytes, then `total` symbol bytes, all within
                    // this segment — otherwise build_huff_table would over-read.
                    if (dht_pos + 16 > dht_end) break;
                    uint8_t bits[16]; int total = 0;
                    for (int i = 0; i < 16; ++i) {
                        bits[i] = jpeg[dht_pos++]; total += bits[i];
                    }
                    if (dht_pos + static_cast<std::size_t>(total) > dht_end) break;
                    if (table_class == 0)
                        build_huff_table(info.dc_tables[table_id], bits, &jpeg[dht_pos]);
                    else
                        build_huff_table(info.ac_tables[table_id], bits, &jpeg[dht_pos]);
                    dht_pos += total;
                }
            }

            // DRI — Define Restart Interval
            if (marker == 0xDD) {
                if (length < 4)
                    return Result<JpegScanInfo>::err("JPEG: malformed DRI segment");
                info.restart_interval = (jpeg[pos + 2] << 8) | jpeg[pos + 3];
            }

            // SOS — Start of Scan
            if (marker == 0xDA) {
                if (length < 3)
                    return Result<JpegScanInfo>::err("JPEG: malformed SOS segment");
                info.num_scan_comps = jpeg[pos + 2];
                if (info.num_scan_comps > 4) info.num_scan_comps = 4;
                if (3 + info.num_scan_comps * 2 > length)
                    return Result<JpegScanInfo>::err("JPEG: SOS component list out of range");
                for (int i = 0; i < info.num_scan_comps; ++i) {
                    uint8_t comp_id  = jpeg[pos + 3 + i * 2];
                    uint8_t table_sel = jpeg[pos + 4 + i * 2];
                    info.comp_dc_table[i] = (table_sel >> 4) & 0x0F;
                    info.comp_ac_table[i] = table_sel & 0x0F;
                    // Selector nibbles index dc_tables[4]/ac_tables[4]; a value
                    // >3 would read past those arrays during scan decoding.
                    if (info.comp_dc_table[i] >= 4 || info.comp_ac_table[i] >= 4)
                        return Result<JpegScanInfo>::err("JPEG: invalid Huffman table selector");

                    // Map SOS component to SOF component by matching component ID
                    info.scan_comp_order[i] = 0; // default to first
                    for (int j = 0; j < info.sof_num_components; ++j) {
                        if (info.sof_comps[j].id == comp_id) {
                            info.scan_comp_order[i] = j;
                            break;
                        }
                    }
                }
                info.scan_start = pos + length;
                if (output_prefix)
                    output_prefix->assign(jpeg.begin(), jpeg.begin() + info.scan_start);
                break;
            }

            pos += length;
        }

        if (info.scan_start == 0)
            return Result<JpegScanInfo>::err("JPEG: no SOS marker found");

        // Find end of entropy data
        info.scan_end = info.scan_start;
        while (info.scan_end < jpeg.size() - 1) {
            if (jpeg[info.scan_end] == 0xFF && jpeg[info.scan_end + 1] != 0x00
                && !(jpeg[info.scan_end + 1] >= 0xD0 && jpeg[info.scan_end + 1] <= 0xD7))
                break;
            info.scan_end++;
        }

        // If no SOF0 was found, assume 1×1 subsampling for all components
        if (info.sof_num_components == 0) {
            info.sof_num_components = info.num_scan_comps;
            for (int i = 0; i < info.sof_num_components; ++i) {
                info.sof_comps[i].h_samp = 1;
                info.sof_comps[i].v_samp = 1;
            }
        }

        return Result<JpegScanInfo>::ok(info);
    }

    /// Get the number of 8×8 blocks for scan component i in one MCU.
    static int blocks_per_mcu(const JpegScanInfo& si, int scan_comp) {
        int sof_idx = si.scan_comp_order[scan_comp];
        return si.sof_comps[sof_idx].h_samp * si.sof_comps[sof_idx].v_samp;
    }

    // ── JSteg embed: modify LSBs of AC coefficients ──────────────────────────

    [[nodiscard]] static Result<Bytes> jsteg_embed(const Bytes& jpeg, const Bytes& stream) {
        Bytes output_prefix;
        auto si_res = parse_jpeg_markers(jpeg, &output_prefix);
        if (si_res.is_err()) return Result<Bytes>::err(si_res.error().message);
        auto& si = si_res.value();

        BitReader br(jpeg.data(), si.scan_start, si.scan_end);
        BitWriter bw;

        std::size_t stream_bit = 0;
        std::size_t total_stream_bits = stream.size() * 8;
        int mcu_count = 0;
        int next_rst = 0; // expected restart marker index (0-7 cycling)

        bool done = false;
        while (!done) {
            // Handle restart markers
            if (si.restart_interval > 0 && mcu_count > 0
                && (mcu_count % si.restart_interval) == 0) {
                // Flush current byte in reader (align to byte boundary)
                br.bit_pos = 0;
                // Skip restart marker in input (0xFF 0xDn)
                while (br.pos < br.end) {
                    if (jpeg[br.pos] == 0xFF && br.pos + 1 < br.end
                        && (jpeg[br.pos + 1] & 0xF8) == 0xD0) {
                        br.pos += 2;
                        break;
                    }
                    br.pos++;
                }
                // Write restart marker to output
                bw.flush();
                bw.output.push_back(0xFF);
                bw.output.push_back(0xD0 | (next_rst & 0x07));
                next_rst = (next_rst + 1) & 0x07;
            }

            for (int comp = 0; comp < si.num_scan_comps && !done; ++comp) {
                int nblocks = blocks_per_mcu(si, comp);
                for (int blk = 0; blk < nblocks && !done; ++blk) {
                    // Decode DC coefficient
                    int dc_sym = decode_huff(br, si.dc_tables[si.comp_dc_table[comp]]);
                    if (dc_sym < 0) { done = true; break; }
                    encode_huff(bw, si.dc_tables[si.comp_dc_table[comp]],
                                static_cast<uint8_t>(dc_sym));
                    int dc_bits = dc_sym & 0x0F;
                    if (dc_bits > 0) {
                        int dc_val = br.read_bits(dc_bits);
                        if (dc_val < 0) { done = true; break; }
                        bw.write_bits(dc_val, dc_bits);
                    }

                    // Decode 63 AC coefficients
                    for (int k = 1; k < 64 && !done; ) {
                        int ac_sym = decode_huff(br, si.ac_tables[si.comp_ac_table[comp]]);
                        if (ac_sym < 0) { done = true; break; }

                        int run_length = (ac_sym >> 4) & 0x0F;
                        int ac_size    = ac_sym & 0x0F;

                        if (ac_sym == 0x00) { // EOB
                            encode_huff(bw, si.ac_tables[si.comp_ac_table[comp]], 0x00);
                            break;
                        }
                        if (ac_sym == 0xF0) { // ZRL (16 zeros)
                            encode_huff(bw, si.ac_tables[si.comp_ac_table[comp]], 0xF0);
                            k += 16;
                            continue;
                        }

                        int ac_val = br.read_bits(ac_size);
                        if (ac_val < 0) { done = true; break; }

                        // Decode coefficient value
                        int coeff;
                        if (ac_val >= (1 << (ac_size - 1)))
                            coeff = ac_val;
                        else
                            coeff = ac_val - (1 << ac_size) + 1;

                        // JSteg: modify LSB if coefficient is not 0, 1, or -1
                        if (coeff != 0 && coeff != 1 && coeff != -1
                            && stream_bit < total_stream_bits) {
                            int byte_i = static_cast<int>(stream_bit / 8);
                            int bit_i  = 7 - static_cast<int>(stream_bit % 8);
                            int want   = (stream[byte_i] >> bit_i) & 1;
                            if (coeff > 0) {
                                coeff = (coeff & ~1) | want;
                            } else {
                                int abs_val = -coeff;
                                abs_val = (abs_val & ~1) | want;
                                coeff = -abs_val;
                            }
                            stream_bit++;
                        }

                        // Re-encode
                        encode_huff(bw, si.ac_tables[si.comp_ac_table[comp]],
                                    static_cast<uint8_t>(ac_sym));
                        int new_val;
                        if (coeff >= 0) new_val = coeff;
                        else new_val = (1 << ac_size) - 1 + coeff;
                        bw.write_bits(new_val, ac_size);

                        k += run_length + 1;
                    }
                }
            }
            mcu_count++;
        }

        bw.flush();

        // Assemble output: prefix + new entropy data + suffix
        Bytes result;
        result.reserve(output_prefix.size() + bw.output.size() + (jpeg.size() - si.scan_end));
        result.insert(result.end(), output_prefix.begin(), output_prefix.end());
        result.insert(result.end(), bw.output.begin(), bw.output.end());
        result.insert(result.end(), jpeg.begin() + si.scan_end, jpeg.end());

        return Result<Bytes>::ok(std::move(result));
    }

    // ── JSteg extract ────────────────────────────────────────────────────────

    [[nodiscard]] static Result<Bytes> jsteg_extract(const Bytes& jpeg) {
        auto si_res = parse_jpeg_markers(jpeg);
        if (si_res.is_err()) return Result<Bytes>::err(si_res.error().message);
        auto& si = si_res.value();

        BitReader br(jpeg.data(), si.scan_start, si.scan_end);

        std::size_t max_coeff_bits = (si.scan_end - si.scan_start) * 8;
        std::size_t max_bytes = max_coeff_bits / 8;
        if (max_bytes > 1024 * 1024) max_bytes = 1024 * 1024;

        Bytes result(max_bytes, 0);
        std::size_t bit_idx = 0;
        int mcu_count = 0;
        bool done = false;

        while (!done && bit_idx < max_bytes * 8) {
            // Handle restart markers
            if (si.restart_interval > 0 && mcu_count > 0
                && (mcu_count % si.restart_interval) == 0) {
                br.bit_pos = 0;
                while (br.pos < br.end) {
                    if (jpeg[br.pos] == 0xFF && br.pos + 1 < br.end
                        && (jpeg[br.pos + 1] & 0xF8) == 0xD0) {
                        br.pos += 2;
                        break;
                    }
                    br.pos++;
                }
            }

            for (int comp = 0; comp < si.num_scan_comps && !done; ++comp) {
                int nblocks = blocks_per_mcu(si, comp);
                for (int blk = 0; blk < nblocks && !done; ++blk) {
                    int dc_sym = decode_huff(br, si.dc_tables[si.comp_dc_table[comp]]);
                    if (dc_sym < 0) { done = true; break; }
                    int dc_bits = dc_sym & 0x0F;
                    if (dc_bits > 0) {
                        int v = br.read_bits(dc_bits);
                        if (v < 0) { done = true; break; }
                    }

                    for (int k = 1; k < 64 && !done; ) {
                        int ac_sym = decode_huff(br, si.ac_tables[si.comp_ac_table[comp]]);
                        if (ac_sym < 0) { done = true; break; }
                        if (ac_sym == 0x00) break;
                        if (ac_sym == 0xF0) { k += 16; continue; }

                        int run = (ac_sym >> 4) & 0x0F;
                        int sz  = ac_sym & 0x0F;
                        int ac_val = br.read_bits(sz);
                        if (ac_val < 0) { done = true; break; }

                        int coeff;
                        if (ac_val >= (1 << (sz - 1))) coeff = ac_val;
                        else coeff = ac_val - (1 << sz) + 1;

                        if (coeff != 0 && coeff != 1 && coeff != -1
                            && bit_idx < max_bytes * 8) {
                            int lsb;
                            if (coeff > 0) lsb = coeff & 1;
                            else lsb = (-coeff) & 1;
                            int byte_i = static_cast<int>(bit_idx / 8);
                            int bit_i  = 7 - static_cast<int>(bit_idx % 8);
                            if (lsb) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
                            bit_idx++;
                        }

                        k += run + 1;
                    }
                }
            }
            mcu_count++;
        }

        return Result<Bytes>::ok(std::move(result));
    }

    // ── Capacity estimation ──────────────────────────────────────────────────

    [[nodiscard]] static Result<std::size_t> jsteg_capacity(const Bytes& jpeg) {
        auto si_res = parse_jpeg_markers(jpeg);
        if (si_res.is_err()) return Result<std::size_t>::err(si_res.error().message);
        auto& si = si_res.value();

        // Count usable coefficients by doing a dry-run extract
        BitReader br(jpeg.data(), si.scan_start, si.scan_end);
        std::size_t usable_bits = 0;
        int mcu_count = 0;
        bool done = false;

        while (!done) {
            if (si.restart_interval > 0 && mcu_count > 0
                && (mcu_count % si.restart_interval) == 0) {
                br.bit_pos = 0;
                while (br.pos < br.end) {
                    if (jpeg[br.pos] == 0xFF && br.pos + 1 < br.end
                        && (jpeg[br.pos + 1] & 0xF8) == 0xD0) {
                        br.pos += 2; break;
                    }
                    br.pos++;
                }
            }

            for (int comp = 0; comp < si.num_scan_comps && !done; ++comp) {
                int nblocks = blocks_per_mcu(si, comp);
                for (int blk = 0; blk < nblocks && !done; ++blk) {
                    int dc_sym = decode_huff(br, si.dc_tables[si.comp_dc_table[comp]]);
                    if (dc_sym < 0) { done = true; break; }
                    int dc_bits = dc_sym & 0x0F;
                    if (dc_bits > 0) { if (br.read_bits(dc_bits) < 0) { done = true; break; } }

                    for (int k = 1; k < 64 && !done; ) {
                        int ac_sym = decode_huff(br, si.ac_tables[si.comp_ac_table[comp]]);
                        if (ac_sym < 0) { done = true; break; }
                        if (ac_sym == 0x00) break;
                        if (ac_sym == 0xF0) { k += 16; continue; }
                        int run = (ac_sym >> 4) & 0x0F;
                        int sz  = ac_sym & 0x0F;
                        int ac_val = br.read_bits(sz);
                        if (ac_val < 0) { done = true; break; }
                        int coeff;
                        if (ac_val >= (1 << (sz - 1))) coeff = ac_val;
                        else coeff = ac_val - (1 << sz) + 1;
                        if (coeff != 0 && coeff != 1 && coeff != -1) usable_bits++;
                        k += run + 1;
                    }
                }
            }
            mcu_count++;
        }

        std::size_t usable_bytes = usable_bits / 8;
        if (usable_bytes > StegoHeader::SIZE)
            return Result<std::size_t>::ok(usable_bytes - StegoHeader::SIZE);
        return Result<std::size_t>::ok(0);
    }
};

} // namespace crypto::stego
