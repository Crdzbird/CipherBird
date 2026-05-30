#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::stego::AudioSteganographer                                       ║
 * ║                                                                            ║
 * ║  Phase-coding steganography for 16-bit signed PCM WAV files.             ║
 * ║                                                                            ║
 * ║  WHY PHASE CODING OVER LSB                                                ║
 * ║  ─────────────────────────────────────────────────────────────────────    ║
 * ║  The Human Auditory System (HAS) is highly sensitive to amplitude noise  ║
 * ║  but relatively insensitive to absolute phase values in mid-frequencies. ║
 * ║  LSB-based audio stego is detected by Mel-cepstrum SVM classifiers and  ║
 * ║  by frequency-domain steganalysis (characteristic histogram distortion). ║
 * ║                                                                            ║
 * ║  Phase coding exploits the HAS's phase insensitivity:                    ║
 * ║    1. Segment the audio into non-overlapping frames of N samples.         ║
 * ║    2. Compute the FFT of each frame.                                       ║
 * ║    3. For each of B target mid-frequency bins (default bins 28-35):       ║
 * ║         bit = 0 → set phase to 0  (real positive)                         ║
 * ║         bit = 1 → set phase to π  (real negative)                         ║
 * ║    4. Restore conjugate symmetry so IFFT yields a real signal.            ║
 * ║    5. IFFT → modified audio samples.                                       ║
 * ║    6. Decode: |phase(bin)| < π/2 → bit 0, else → bit 1.                  ║
 * ║                                                                            ║
 * ║  CAPACITY (default N=512, B=8):                                           ║
 * ║    capacity_bits = ⌊total_samples / N⌋ × B                               ║
 * ║    Example @ 44100 Hz mono: 10 s → ~688 bytes; 30 s → ~2 kB.            ║
 * ║    Uses interleaved stereo independently per channel when present.        ║
 * ║                                                                            ║
 * ║  QUALITY METRIC                                                            ║
 * ║    SNR ≥ 20 dB is considered imperceptible for audio.                     ║
 * ║    Phase coding with mid-frequency bins typically achieves SNR > 30 dB.  ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "stego_types.hpp"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <fstream>
#include <numbers>
#include <string>
#include <vector>

namespace crypto::stego {

class AudioSteganographer {
public:
    // ── Public API ────────────────────────────────────────────────────────────

    /// Embed payload into a 16-bit PCM WAV file.
    /// @param cover_path   source .wav file (16-bit signed PCM, mono or stereo)
    /// @param payload      bytes to hide
    /// @param output_path  destination stego .wav file
    /// @param params       phase coding parameters
    [[nodiscard]] static Result<void> embed(
        const std::string&       cover_path,
        std::span<const uint8_t> payload,
        const std::string&       output_path,
        const StegoParams&       params = {})
    {
        if (!valid_phase_params(params))
            return Result<void>::err("AudioSteganographer: invalid phase-coding parameters");

        auto wav = read_wav(cover_path);
        if (wav.is_err()) return Result<void>::err(wav.error().message);
        auto& w = wav.value();

        // We embed in the first (left) channel if stereo, deinterleaving first.
        std::vector<int16_t> channel = extract_channel(w.samples, w.num_channels, 0);

        Bytes stream = make_embed_stream(payload, MediaFormat::WAV_AUDIO);

        // Compare payload.size() against user-facing capacity (header already excluded).
        std::size_t cap = capacity(channel.size(), params);
        if (payload.size() > cap)
            return Result<void>::err(
                "AudioSteganographer::embed — payload too large: need "
                + std::to_string(payload.size()) + " bytes, capacity "
                + std::to_string(cap) + " bytes");

        auto res = embed_phase(channel, stream, params);
        if (res.is_err()) return Result<void>::err(res.error().message);

        // Merge modified channel back into interleaved samples
        merge_channel(w.samples, channel, w.num_channels, 0);

        return write_wav(output_path, w);
    }

    /// Extract the hidden payload from a stego WAV file.
    [[nodiscard]] static Result<Bytes> extract(
        const std::string& stego_path,
        const StegoParams& params = {})
    {
        if (!valid_phase_params(params))
            return Result<Bytes>::err("AudioSteganographer: invalid phase-coding parameters");

        auto wav = read_wav(stego_path);
        if (wav.is_err()) return Result<Bytes>::err(wav.error().message);
        auto& w = wav.value();

        std::vector<int16_t> channel = extract_channel(w.samples, w.num_channels, 0);

        // Add header size back: capacity() returns user-payload bytes (header excluded).
        std::size_t max_bytes = capacity(channel.size(), params) + StegoHeader::SIZE;
        Bytes raw = extract_phase(channel, max_bytes, params);

        return parse_embed_stream(std::span<const uint8_t>(raw));
    }

    /// Maximum payload bytes this audio can carry.
    [[nodiscard]] static std::size_t capacity(
        std::size_t        sample_count,
        const StegoParams& params = {}) noexcept
    {
        if (params.audio_frame_size <= 0 || params.audio_bin_count <= 0)
            return 0;
        std::size_t frames = sample_count / static_cast<std::size_t>(params.audio_frame_size);
        std::size_t bits   = frames * static_cast<std::size_t>(params.audio_bin_count);
        std::size_t bytes  = bits / 8;
        return (bytes > StegoHeader::SIZE) ? (bytes - StegoHeader::SIZE) : 0;
    }

    /// Compute Signal-to-Noise Ratio (dB) between cover and stego WAV files.
    [[nodiscard]] static double snr(
        const std::string& cover_path,
        const std::string& stego_path)
    {
        auto cov_res = read_wav(cover_path);
        auto stg_res = read_wav(stego_path);
        if (cov_res.is_err() || stg_res.is_err()) return -1.0;

        auto& cv = cov_res.value().samples;
        auto& sv = stg_res.value().samples;
        if (cv.size() != sv.size()) return -1.0;

        double signal_power = 0.0, noise_power = 0.0;
        for (std::size_t i = 0; i < cv.size(); ++i) {
            double s = static_cast<double>(cv[i]);
            double n = static_cast<double>(sv[i]) - s;
            signal_power += s * s;
            noise_power  += n * n;
        }
        if (noise_power < 1e-10) return std::numeric_limits<double>::infinity();
        return 10.0 * std::log10(signal_power / noise_power);
    }

    // Phase-coding parameters come from the caller (StegoParams) and drive FFT
    // sizing and bin indexing. Reject anything that would make the radix-2 FFT
    // or the bin accesses (frame[bin], frame[N-bin]) read out of bounds.
    // Public so FlacSteganographer (which shares the phase-coding scheme) reuses it.
    [[nodiscard]] static bool valid_phase_params(const StegoParams& p) noexcept {
        const int N = p.audio_frame_size;
        if (N <= 0 || (N & (N - 1)) != 0) return false;       // power of two
        if (p.audio_bin_start < 0 || p.audio_bin_count < 0) return false;
        return p.audio_bin_start + p.audio_bin_count < N / 2; // within Nyquist
    }

private:
    // ── WAV I/O ───────────────────────────────────────────────────────────────

    struct WavData {
        uint16_t              num_channels;
        uint32_t              sample_rate;
        uint16_t              bits_per_sample;
        std::vector<int16_t>  samples; // interleaved if stereo
    };

    [[nodiscard]] static Result<WavData> read_wav(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<WavData>::err("WAV: cannot open '" + path + "'");

        auto read_u32 = [&]() -> uint32_t {
            uint8_t b[4]; f.read(reinterpret_cast<char*>(b), 4);
            return static_cast<uint32_t>(b[0])
                 | static_cast<uint32_t>(b[1]) << 8
                 | static_cast<uint32_t>(b[2]) << 16
                 | static_cast<uint32_t>(b[3]) << 24;
        };
        auto read_u16 = [&]() -> uint16_t {
            uint8_t b[2]; f.read(reinterpret_cast<char*>(b), 2);
            return static_cast<uint16_t>(b[0])
                 | static_cast<uint16_t>(b[1]) << 8;
        };
        auto read_tag = [&]() -> std::string {
            char t[4]; f.read(t, 4);
            return {t, 4};
        };

        if (read_tag() != "RIFF")
            return Result<WavData>::err("WAV: missing RIFF chunk");
        read_u32(); // file size minus 8
        if (read_tag() != "WAVE")
            return Result<WavData>::err("WAV: missing WAVE tag");

        WavData w{};
        bool found_fmt = false, found_data = false;
        uint32_t data_size = 0;

        while (f && !found_data) {
            std::string chunk = read_tag();
            uint32_t    chunk_size = read_u32();

            if (chunk == "fmt ") {
                uint16_t audio_fmt = read_u16();
                if (audio_fmt != 1)
                    return Result<WavData>::err("WAV: only PCM (format=1) supported");
                w.num_channels    = read_u16();
                w.sample_rate     = read_u32();
                read_u32(); // byte rate
                read_u16(); // block align
                w.bits_per_sample = read_u16();
                if (w.bits_per_sample != 16)
                    return Result<WavData>::err("WAV: only 16-bit samples supported");
                // Skip any extra fmt bytes
                if (chunk_size > 16)
                    f.seekg(static_cast<std::streamoff>(chunk_size - 16), std::ios::cur);
                found_fmt = true;

            } else if (chunk == "data") {
                if (!found_fmt)
                    return Result<WavData>::err("WAV: data chunk before fmt chunk");
                // Clamp the declared data size to the bytes actually present so a
                // crafted 4 GB chunk_size can't drive an over-large allocation.
                const std::streampos cur = f.tellg();
                f.seekg(0, std::ios::end);
                const std::streampos end = f.tellg();
                f.seekg(cur);
                const std::size_t remaining =
                    (end > cur) ? static_cast<std::size_t>(end - cur) : 0;
                data_size = static_cast<uint32_t>(
                    std::min<std::size_t>(chunk_size, remaining));
                std::size_t n = data_size / 2; // whole int16 samples
                w.samples.resize(n);
                // Read exactly n*2 bytes: the buffer holds n samples, and an odd
                // data_size would otherwise read one byte past the allocation.
                f.read(reinterpret_cast<char*>(w.samples.data()),
                       static_cast<std::streamsize>(n * 2));
                found_data = true;

            } else {
                // Skip unknown chunks
                f.seekg(static_cast<std::streamoff>(chunk_size), std::ios::cur);
            }
        }

        if (!found_data)
            return Result<WavData>::err("WAV: no data chunk found in '" + path + "'");
        return Result<WavData>::ok(std::move(w));
    }

    [[nodiscard]] static Result<void> write_wav(
        const std::string& path,
        const WavData&     w)
    {
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
        write_u16(1);                          // PCM
        write_u16(w.num_channels);
        write_u32(w.sample_rate);
        write_u32(w.sample_rate * w.num_channels * 2); // byte rate
        write_u16(static_cast<uint16_t>(w.num_channels * 2)); // block align
        write_u16(16);                         // bits per sample
        f.write("data", 4); write_u32(data_size);
        f.write(reinterpret_cast<const char*>(w.samples.data()),
                static_cast<std::streamsize>(data_size));

        if (!f) return Result<void>::err("WAV: write error");
        return Result<void>::ok();
    }

    // De-interleave and re-interleave helpers for multi-channel audio.
    [[nodiscard]] static std::vector<int16_t> extract_channel(
        const std::vector<int16_t>& interleaved,
        uint16_t                    num_channels,
        uint16_t                    ch)
    {
        if (num_channels == 1) return interleaved;
        std::vector<int16_t> out;
        out.reserve(interleaved.size() / num_channels);
        for (std::size_t i = ch; i < interleaved.size(); i += num_channels)
            out.push_back(interleaved[i]);
        return out;
    }

    static void merge_channel(
        std::vector<int16_t>&       interleaved,
        const std::vector<int16_t>& channel,
        uint16_t                    num_channels,
        uint16_t                    ch)
    {
        if (num_channels == 1) { interleaved = channel; return; }
        for (std::size_t i = 0, j = ch; j < interleaved.size(); ++i, j += num_channels)
            if (i < channel.size()) interleaved[j] = channel[i];
    }

    // ── Cooley-Tukey Radix-2 FFT ─────────────────────────────────────────────
    //
    // In-place iterative FFT. N must be a power of two.
    // inverse=false → DFT;  inverse=true → IDFT (divided by N).
    // ──────────────────────────────────────────────────────────────────────────

    using Complex = std::complex<double>;

    static void fft(std::vector<Complex>& a, bool inverse) {
        const int n = static_cast<int>(a.size());

        // Bit-reversal permutation
        for (int i = 1, j = 0; i < n; ++i) {
            int bit = n >> 1;
            for (; j & bit; bit >>= 1) j ^= bit;
            j ^= bit;
            if (i < j) std::swap(a[i], a[j]);
        }

        // Butterfly stages
        for (int len = 2; len <= n; len <<= 1) {
            double ang = std::numbers::pi * 2.0 / len * (inverse ? 1.0 : -1.0);
            Complex wlen(std::cos(ang), std::sin(ang));
            for (int i = 0; i < n; i += len) {
                Complex w(1.0, 0.0);
                for (int j = 0; j < len / 2; ++j) {
                    Complex u = a[i + j];
                    Complex v = a[i + j + len/2] * w;
                    a[i + j]          = u + v;
                    a[i + j + len/2]  = u - v;
                    w *= wlen;
                }
            }
        }

        if (inverse) {
            double scale = 1.0 / n;
            for (auto& x : a) x *= scale;
        }
    }

    // ── Phase Coding Embed / Extract ──────────────────────────────────────────

    [[nodiscard]] static Result<void> embed_phase(
        std::vector<int16_t>& samples,
        const Bytes&          stream,
        const StegoParams&    params)
    {
        const int    N         = params.audio_frame_size;
        const int    bin_start = params.audio_bin_start;
        const int    bin_count = params.audio_bin_count;
        const double SCALE     = 32767.0;

        // Validate N is a power of two (required for radix-2 FFT)
        if ((N & (N - 1)) != 0)
            return Result<void>::err("AudioSteganographer: frame_size must be a power of 2");
        if (bin_start + bin_count >= N / 2)
            return Result<void>::err("AudioSteganographer: target bins out of Nyquist range");

        const std::size_t total_bits = stream.size() * 8;
        const std::size_t frames     = samples.size() / static_cast<std::size_t>(N);

        std::size_t bit_idx = 0;

        for (std::size_t f = 0; f < frames && bit_idx < total_bits; ++f) {
            const std::size_t offset = f * static_cast<std::size_t>(N);

            // Load frame into complex vector
            std::vector<Complex> frame(N);
            for (int i = 0; i < N; ++i)
                frame[i] = Complex(static_cast<double>(samples[offset + i]) / SCALE, 0.0);

            fft(frame, false);

            // Embed up to bin_count bits into target bins
            for (int b = 0; b < bin_count && bit_idx < total_bits; ++b, ++bit_idx) {
                const int bin = bin_start + b;

                int byte_i = static_cast<int>(bit_idx / 8);
                int bit_i  = 7 - static_cast<int>(bit_idx % 8); // MSB first
                int bit    = (stream[byte_i] >> bit_i) & 1;

                // Set phase: 0 for bit=0, π for bit=1
                // Preserve amplitude |frame[bin]|
                double magnitude = std::abs(frame[bin]);
                // Ensure a non-zero magnitude so phase is meaningful
                if (magnitude < 1e-6) magnitude = 1e-4;

                double target_phase = (bit == 0) ? 0.0 : std::numbers::pi;
                frame[bin] = Complex(magnitude * std::cos(target_phase),
                                     magnitude * std::sin(target_phase));

                // Maintain conjugate symmetry for real output: FFT[N-bin] = conj(FFT[bin])
                frame[N - bin] = std::conj(frame[bin]);
            }

            fft(frame, true); // IFFT

            // Write back clamped samples
            for (int i = 0; i < N; ++i) {
                double v = frame[i].real() * SCALE;
                samples[offset + i] = static_cast<int16_t>(
                    std::clamp(v, -32768.0, 32767.0));
            }
        }

        return Result<void>::ok();
    }

    [[nodiscard]] static Bytes extract_phase(
        const std::vector<int16_t>& samples,
        std::size_t                 max_stream_bytes,
        const StegoParams&          params)
    {
        const int    N         = params.audio_frame_size;
        const int    bin_start = params.audio_bin_start;
        const int    bin_count = params.audio_bin_count;
        const double SCALE     = 32767.0;

        const std::size_t total_bits = max_stream_bytes * 8;
        const std::size_t frames     = samples.size() / static_cast<std::size_t>(N);

        Bytes result(max_stream_bytes, 0);
        std::size_t bit_idx = 0;

        for (std::size_t f = 0; f < frames && bit_idx < total_bits; ++f) {
            const std::size_t offset = f * static_cast<std::size_t>(N);

            std::vector<Complex> frame(N);
            for (int i = 0; i < N; ++i)
                frame[i] = Complex(static_cast<double>(samples[offset + i]) / SCALE, 0.0);

            fft(frame, false);

            for (int b = 0; b < bin_count && bit_idx < total_bits; ++b, ++bit_idx) {
                const int bin    = bin_start + b;
                double    phase  = std::arg(frame[bin]); // in [-π, π]
                int       bit    = (std::abs(phase) < std::numbers::pi / 2.0) ? 0 : 1;

                int byte_i = static_cast<int>(bit_idx / 8);
                int bit_i  = 7 - static_cast<int>(bit_idx % 8); // MSB first
                if (bit) result[byte_i] |= static_cast<uint8_t>(1 << bit_i);
            }
        }

        return result;
    }
};

} // namespace crypto::stego
