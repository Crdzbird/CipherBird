#pragma once

/**
 * crypto::stego::FlacSteganographer
 *
 * Phase-coding steganography for FLAC audio files.
 * Uses dr_flac.h for decoding FLAC to PCM samples, then applies the same
 * FFT phase-coding algorithm as AudioSteganographer.
 *
 * LIMITATION: Output is always WAV format because no header-only FLAC
 * encoder exists. The output file preserves the extension from the caller
 * but contains WAV data.
 */

#include "stego_types.hpp"
#include "stego_audio.hpp"  // Reuse WAV writing and phase-coding via AudioSteganographer

// Make dr_flac functions static to avoid duplicate symbols in multi-TU builds
#ifndef CRYPTOLIB_DR_FLAC_IMPL_GUARD
#define CRYPTOLIB_DR_FLAC_IMPL_GUARD
#define DR_FLAC_IMPLEMENTATION
#define DR_FLAC_NO_STDIO
#define DRFLAC_API     static
#define DRFLAC_PRIVATE static
#endif

#include "third_party/dr_flac.h"

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace crypto::stego {

class FlacSteganographer {
public:
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        const StegoParams&       params = {})
    {
        if (!AudioSteganographer::valid_phase_params(params))
            return Result<void>::err("FlacSteganographer: invalid phase-coding parameters");

        auto wav = decode_flac_to_wav(cover_path);
        if (wav.is_err()) return Result<void>::err(wav.error().message);

        auto& w = wav.value();

        std::vector<int16_t> channel = extract_channel(w.samples, w.num_channels, 0);
        Bytes stream = make_embed_stream(payload, MediaFormat::FLAC_AUDIO);

        std::size_t cap = AudioSteganographer::capacity(channel.size(), params);
        if (payload.size() > cap)
            return Result<void>::err(
                "FlacSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        auto res = embed_phase(channel, stream, params);
        if (res.is_err()) return Result<void>::err(res.error().message);

        merge_channel(w.samples, channel, w.num_channels, 0);
        return write_wav(output_path, w);
    }

    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        const StegoParams& params = {})
    {
        // Output is WAV, so we read it as WAV for extraction
        // But also support FLAC input for the case where cover is FLAC
        // Try WAV first (output format), then FLAC
        if (!AudioSteganographer::valid_phase_params(params))
            return Result<Bytes>::err("FlacSteganographer: invalid phase-coding parameters");

        auto wav = read_wav_or_flac(stego_path);
        if (wav.is_err()) return Result<Bytes>::err(wav.error().message);

        auto& w = wav.value();
        std::vector<int16_t> channel = extract_channel(w.samples, w.num_channels, 0);

        std::size_t max_bytes = AudioSteganographer::capacity(channel.size(), params) + StegoHeader::SIZE;
        Bytes raw = extract_phase(channel, max_bytes, params);
        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    [[nodiscard]] static std::size_t capacity(
        std::size_t        sample_count,
        const StegoParams& params = {}) noexcept
    {
        return AudioSteganographer::capacity(sample_count, params);
    }

private:
    struct WavData {
        uint16_t              num_channels;
        uint32_t              sample_rate;
        std::vector<int16_t>  samples;
    };

    // Custom FLAC memory reader for dr_flac
    struct FlacMemory {
        const uint8_t* data;
        std::size_t    size;
        std::size_t    pos;
    };

    static size_t flac_read_cb(void* pUserData, void* pBufferOut, size_t bytesToRead) {
        auto* mem = static_cast<FlacMemory*>(pUserData);
        size_t remaining = mem->size - mem->pos;
        size_t to_read = (bytesToRead < remaining) ? bytesToRead : remaining;
        std::memcpy(pBufferOut, mem->data + mem->pos, to_read);
        mem->pos += to_read;
        return to_read;
    }

    static drflac_bool32 flac_seek_cb(void* pUserData, int offset, drflac_seek_origin origin) {
        auto* mem = static_cast<FlacMemory*>(pUserData);
        size_t new_pos;
        if (origin == DRFLAC_SEEK_SET)
            new_pos = static_cast<size_t>(offset);
        else
            new_pos = mem->pos + static_cast<size_t>(offset);
        if (new_pos > mem->size) return DRFLAC_FALSE;
        mem->pos = new_pos;
        return DRFLAC_TRUE;
    }

    static drflac_bool32 flac_tell_cb(void* pUserData, drflac_int64* pCursor) {
        auto* mem = static_cast<FlacMemory*>(pUserData);
        *pCursor = static_cast<drflac_int64>(mem->pos);
        return DRFLAC_TRUE;
    }

    [[nodiscard]] static Result<WavData> decode_flac_to_wav(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return Result<WavData>::err("FLAC: cannot open '" + path + "'");
        auto sz = f.tellg();
        if (sz <= 0) return Result<WavData>::err("FLAC: empty or unreadable '" + path + "'");
        f.seekg(0);
        std::vector<uint8_t> buf(static_cast<std::size_t>(sz));
        f.read(reinterpret_cast<char*>(buf.data()), sz);

        FlacMemory mem{buf.data(), buf.size(), 0};
        drflac* flac = drflac_open(flac_read_cb, flac_seek_cb, flac_tell_cb, &mem, nullptr);
        if (!flac) return Result<WavData>::err("FLAC: failed to decode '" + path + "'");

        WavData w;
        w.num_channels = static_cast<uint16_t>(flac->channels);
        w.sample_rate  = flac->sampleRate;

        // channels and totalPCMFrameCount come from the FLAC STREAMINFO and are
        // attacker-controlled; reject degenerate/huge values before allocating.
        if (flac->channels == 0) {
            drflac_close(flac);
            return Result<WavData>::err("FLAC: zero channels");
        }
        drflac_uint64 total_samples = flac->totalPCMFrameCount * flac->channels;
        if (total_samples == 0 || total_samples > detail::MAX_AUDIO_SAMPLES) {
            drflac_close(flac);
            return Result<WavData>::err("FLAC: sample count out of range");
        }
        w.samples.resize(static_cast<std::size_t>(total_samples));

        drflac_uint64 read = drflac_read_pcm_frames_s16(flac, flac->totalPCMFrameCount,
                                                         w.samples.data());
        drflac_close(flac);

        if (read == 0) return Result<WavData>::err("FLAC: no samples decoded");
        w.samples.resize(static_cast<std::size_t>(read * w.num_channels));

        return Result<WavData>::ok(std::move(w));
    }

    [[nodiscard]] static Result<WavData> read_wav_or_flac(const std::string& path) {
        // Try reading as WAV first (since our output is WAV)
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<WavData>::err("Cannot open '" + path + "'");

        char magic[4];
        f.read(magic, 4);
        f.close();

        if (std::string(magic, 4) == "RIFF") {
            // It's a WAV file
            return read_wav(path);
        } else if (std::string(magic, 4) == "fLaC") {
            // It's a FLAC file
            return decode_flac_to_wav(path);
        }
        return Result<WavData>::err("Unknown audio format in '" + path + "'");
    }

    [[nodiscard]] static Result<WavData> read_wav(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<WavData>::err("WAV: cannot open '" + path + "'");

        auto read_u32 = [&]() -> uint32_t {
            uint8_t b[4]; f.read(reinterpret_cast<char*>(b), 4);
            return uint32_t(b[0]) | uint32_t(b[1])<<8 | uint32_t(b[2])<<16 | uint32_t(b[3])<<24;
        };
        auto read_u16 = [&]() -> uint16_t {
            uint8_t b[2]; f.read(reinterpret_cast<char*>(b), 2);
            return uint16_t(b[0]) | uint16_t(b[1])<<8;
        };
        auto read_tag = [&]() { char t[4]; f.read(t, 4); return std::string(t, 4); };

        if (read_tag() != "RIFF") return Result<WavData>::err("Not RIFF");
        read_u32(); read_tag();

        WavData w{};
        bool found_data = false;
        while (f && !found_data) {
            std::string chunk = read_tag();
            uint32_t chunk_size = read_u32();
            if (chunk == "fmt ") {
                read_u16(); w.num_channels = read_u16(); w.sample_rate = read_u32();
                read_u32(); read_u16(); read_u16();
                if (chunk_size > 16) f.seekg(chunk_size - 16, std::ios::cur);
            } else if (chunk == "data") {
                // Clamp to bytes actually present (see stego_audio.hpp read_wav).
                const std::streampos cur = f.tellg();
                f.seekg(0, std::ios::end);
                const std::streampos end = f.tellg();
                f.seekg(cur);
                const std::size_t remaining =
                    (end > cur) ? static_cast<std::size_t>(end - cur) : 0;
                const std::size_t bytes =
                    std::min<std::size_t>(chunk_size, remaining);
                std::size_t n = bytes / 2;   // whole int16 samples
                w.samples.resize(n);
                // Read exactly n*2 bytes (an odd byte count would over-read).
                f.read(reinterpret_cast<char*>(w.samples.data()),
                       static_cast<std::streamsize>(n * 2));
                found_data = true;
            } else {
                f.seekg(chunk_size, std::ios::cur);
            }
        }
        if (!found_data) return Result<WavData>::err("No data chunk");
        return Result<WavData>::ok(std::move(w));
    }

    [[nodiscard]] static Result<void> write_wav(const std::string& path, const WavData& w) {
        std::ofstream f(path, std::ios::binary);
        if (!f) return Result<void>::err("WAV: cannot write '" + path + "'");

        uint32_t data_size = static_cast<uint32_t>(w.samples.size() * 2);
        uint32_t file_size = 36 + data_size;

        auto write_u32 = [&](uint32_t v) {
            uint8_t b[4] = {uint8_t(v), uint8_t(v>>8), uint8_t(v>>16), uint8_t(v>>24)};
            f.write(reinterpret_cast<char*>(b), 4);
        };
        auto write_u16 = [&](uint16_t v) {
            uint8_t b[2] = {uint8_t(v), uint8_t(v>>8)};
            f.write(reinterpret_cast<char*>(b), 2);
        };

        f.write("RIFF", 4); write_u32(file_size);
        f.write("WAVE", 4);
        f.write("fmt ", 4); write_u32(16);
        write_u16(1);
        write_u16(w.num_channels);
        write_u32(w.sample_rate);
        write_u32(w.sample_rate * w.num_channels * 2);
        write_u16(static_cast<uint16_t>(w.num_channels * 2));
        write_u16(16);
        f.write("data", 4); write_u32(data_size);
        f.write(reinterpret_cast<const char*>(w.samples.data()),
                static_cast<std::streamsize>(data_size));

        if (!f) return Result<void>::err("WAV: write error");
        return Result<void>::ok();
    }

    // Channel helpers
    [[nodiscard]] static std::vector<int16_t> extract_channel(
        const std::vector<int16_t>& interleaved, uint16_t ch_count, uint16_t ch) {
        if (ch_count == 1) return interleaved;
        std::vector<int16_t> out;
        out.reserve(interleaved.size() / ch_count);
        for (std::size_t i = ch; i < interleaved.size(); i += ch_count)
            out.push_back(interleaved[i]);
        return out;
    }

    static void merge_channel(
        std::vector<int16_t>& interleaved, const std::vector<int16_t>& channel,
        uint16_t ch_count, uint16_t ch) {
        if (ch_count == 1) { interleaved = channel; return; }
        for (std::size_t i = 0, j = ch; j < interleaved.size(); ++i, j += ch_count)
            if (i < channel.size()) interleaved[j] = channel[i];
    }

    // Phase coding (replicating AudioSteganographer's logic)
    using Complex = std::complex<double>;

    static void fft(std::vector<Complex>& a, bool inverse) {
        const int n = static_cast<int>(a.size());
        for (int i = 1, j = 0; i < n; ++i) {
            int bit = n >> 1;
            for (; j & bit; bit >>= 1) j ^= bit;
            j ^= bit;
            if (i < j) std::swap(a[i], a[j]);
        }
        for (int len = 2; len <= n; len <<= 1) {
            double ang = std::numbers::pi * 2.0 / len * (inverse ? 1.0 : -1.0);
            Complex wlen(std::cos(ang), std::sin(ang));
            for (int i = 0; i < n; i += len) {
                Complex w(1.0, 0.0);
                for (int j = 0; j < len / 2; ++j) {
                    Complex u = a[i+j], v = a[i+j+len/2] * w;
                    a[i+j] = u + v; a[i+j+len/2] = u - v;
                    w *= wlen;
                }
            }
        }
        if (inverse) { double s = 1.0/n; for (auto& x : a) x *= s; }
    }

    [[nodiscard]] static Result<void> embed_phase(
        std::vector<int16_t>& samples, const Bytes& stream, const StegoParams& params) {
        const int N = params.audio_frame_size;
        const int bin_start = params.audio_bin_start;
        const int bin_count = params.audio_bin_count;
        const double SCALE = 32767.0;

        if ((N & (N-1)) != 0) return Result<void>::err("frame_size must be power of 2");
        if (bin_start + bin_count >= N/2) return Result<void>::err("bins out of range");

        const std::size_t total_bits = stream.size() * 8;
        const std::size_t frames = samples.size() / static_cast<std::size_t>(N);
        std::size_t bit_idx = 0;

        for (std::size_t fr = 0; fr < frames && bit_idx < total_bits; ++fr) {
            const std::size_t offset = fr * N;
            std::vector<Complex> frame(N);
            for (int i = 0; i < N; ++i)
                frame[i] = Complex(samples[offset+i] / SCALE, 0.0);
            fft(frame, false);
            for (int b = 0; b < bin_count && bit_idx < total_bits; ++b, ++bit_idx) {
                int bin = bin_start + b;
                int byte_i = static_cast<int>(bit_idx/8);
                int bit_i = 7 - static_cast<int>(bit_idx%8);
                int bit = (stream[byte_i] >> bit_i) & 1;
                double mag = std::abs(frame[bin]);
                if (mag < 1e-6) mag = 1e-4;
                double phase = bit ? std::numbers::pi : 0.0;
                frame[bin] = Complex(mag*std::cos(phase), mag*std::sin(phase));
                frame[N-bin] = std::conj(frame[bin]);
            }
            fft(frame, true);
            for (int i = 0; i < N; ++i)
                samples[offset+i] = static_cast<int16_t>(std::clamp(frame[i].real()*SCALE, -32768.0, 32767.0));
        }
        return Result<void>::ok();
    }

    [[nodiscard]] static Bytes extract_phase(
        const std::vector<int16_t>& samples, std::size_t max_bytes, const StegoParams& params) {
        const int N = params.audio_frame_size;
        const int bin_start = params.audio_bin_start;
        const int bin_count = params.audio_bin_count;
        const double SCALE = 32767.0;

        Bytes result(max_bytes, 0);
        std::size_t bit_idx = 0;
        const std::size_t total_bits = max_bytes * 8;
        const std::size_t frames = samples.size() / static_cast<std::size_t>(N);

        for (std::size_t fr = 0; fr < frames && bit_idx < total_bits; ++fr) {
            const std::size_t offset = fr * N;
            std::vector<Complex> frame(N);
            for (int i = 0; i < N; ++i)
                frame[i] = Complex(samples[offset+i] / SCALE, 0.0);
            fft(frame, false);
            for (int b = 0; b < bin_count && bit_idx < total_bits; ++b, ++bit_idx) {
                int bin = bin_start + b;
                double phase = std::arg(frame[bin]);
                int bit = (std::abs(phase) < std::numbers::pi/2.0) ? 0 : 1;
                int byte_i = static_cast<int>(bit_idx/8);
                int bit_i = 7 - static_cast<int>(bit_idx%8);
                if (bit) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
            }
        }
        return result;
    }
};

} // namespace crypto::stego
