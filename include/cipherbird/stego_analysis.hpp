#pragma once

/**
 * ╔════════════════════════════════════════════════════════════════════════════╗
 * ║  crypto::stego::StegoAnalyzer — carrier validity, tamper, hidden-data probes ║
 * ║                                                                            ║
 * ║  Three honest capabilities. Read the LIMITS: none of these is a proof.        ║
 * ║                                                                            ║
 * ║  1. inspect()        — is the file a structurally valid media carrier?        ║
 * ║                        (content magic-byte sniff, dimensions for images).     ║
 * ║  2. content_digest() — a 32-byte BLAKE2b of the whole file. Reference-based    ║
 * ║                        tamper detection: store it out-of-band, recompute        ║
 * ║                        later; ANY single-byte change flips the digest. There   ║
 * ║                        is NO reference-free way to know a file was altered.    ║
 * ║  3. detect_hidden()  — a HEURISTIC hidden-data probe:                          ║
 * ║        • cipherbird_payload: an *unkeyed* cipherbird stego payload is            ║
 * ║          recoverable (definitive for that case).                              ║
 * ║        • lsb_embedding_likelihood: the Westfeld–Pfitzmann chi-square LSB       ║
 * ║          attack — a 0..1 probability that LSBs carry embedded data.           ║
 * ║                                                                            ║
 * ║  LIMITS (stated, never hidden): the LSB test targets naive LSB embedding in    ║
 * ║  NATURAL images; high-entropy carriers (noise, already-compressed) LSB-        ║
 * ║  saturate and read as false positives. cipherbird's own KEYED/whitened and      ║
 * ║  DCT/QIM payloads are statistically indistinguishable — a low likelihood is    ║
 * ║  NOT evidence of absence. Composition only (BLAKE2b + arithmetic).            ║
 * ╚════════════════════════════════════════════════════════════════════════════╝
 */

#include "types.hpp"
#include "steganography.hpp"

#include <sodium.h>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace crypto::stego {

/// `parses` is true only when the content is a recognised format AND the
/// engine's reader for that format accepts the whole file: for PPM, BMP, PNG
/// and GIF every pixel the header declares must be present, for WAV the data
/// chunk must fit the file, for CRVF every frame, and JPEG and MP3 must pass
/// the same parse the embed path runs. FLAC, AVI and MP4 are recognised by
/// their magic bytes only; `detail` says so. A file whose header is
/// recognised but whose body is missing keeps its `format`, reports
/// `parses` = false and width/height 0, and `detail` names the problem.
struct FileInspection {
    bool        parses      = false;                 // recognised, structurally plausible carrier
    MediaFormat format      = MediaFormat::UNKNOWN;  // format inferred from CONTENT (not extension)
    bool        ext_matches = false;                 // content format == extension format
    std::size_t width       = 0;                     // images only (0 otherwise)
    std::size_t height      = 0;
    std::size_t file_size   = 0;
    std::string detail;
};

struct HiddenDataReport {
    bool        cipherbird_payload         = false;   // an UNKEYED cipherbird payload was recovered (definitive)
    double      lsb_chi_square            = 0.0;     // raw chi-square statistic over LSB pairs
    double      lsb_embedding_likelihood  = 0.0;     // 0..1 heuristic (Westfeld–Pfitzmann)
    std::size_t samples_analysed          = 0;
    std::string note;                                // honesty caveat, always populated
};

class StegoAnalyzer {
public:
    // 1) Validity ------------------------------------------------------------
    [[nodiscard]] static Result<FileInspection> inspect(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<FileInspection>::err("StegoAnalyzer: cannot open '" + path + "'");
        std::vector<uint8_t> head(64, 0);
        f.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
        auto got = static_cast<std::size_t>(f.gcount());
        head.resize(got);

        FileInspection r;
        f.clear(); f.seekg(0, std::ios::end);
        r.file_size = static_cast<std::size_t>(f.tellg());
        r.format    = sniff(head);
        r.ext_matches = (r.format == StegoEngine::detect_format(path));
        std::string problem;
        if (r.format != MediaFormat::UNKNOWN) {
            problem = body_problem(path, r.format, r.width, r.height);
            r.parses = problem.empty();
            if (!r.parses) { r.width = 0; r.height = 0; }
        }
        r.detail = describe(r, problem);
        return Result<FileInspection>::ok(std::move(r));
    }

    // 2) Reference-based tamper detection ------------------------------------
    [[nodiscard]] static Result<std::array<uint8_t, 32>> content_digest(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<std::array<uint8_t, 32>>::err("StegoAnalyzer: cannot open '" + path + "'");
        crypto_generichash_state st;
        crypto_generichash_init(&st, nullptr, 0, 32);
        std::vector<uint8_t> buf(65536);
        while (f) {
            f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
            auto n = static_cast<std::size_t>(f.gcount());
            if (n == 0) break;
            crypto_generichash_update(&st, buf.data(), n);
        }
        std::array<uint8_t, 32> out{};
        crypto_generichash_final(&st, out.data(), out.size());
        return Result<std::array<uint8_t, 32>>::ok(out);
    }

    /// Constant-time compare of the file's current digest against `expected`.
    /// Returns true iff unchanged. `expected` must be 32 bytes.
    [[nodiscard]] static Result<bool>
    verify_digest(const std::string& path, std::span<const uint8_t> expected) {
        if (expected.size() != 32)
            return Result<bool>::err("StegoAnalyzer: expected digest must be 32 bytes");
        auto d = content_digest(path);
        if (d.is_err()) return Result<bool>::err(d.error().message);
        bool same = sodium_memcmp(d.value().data(), expected.data(), 32) == 0;
        return Result<bool>::ok(same);
    }

    // 3) Hidden-data heuristic ----------------------------------------------
    [[nodiscard]] static Result<HiddenDataReport> detect_hidden(const std::string& path) {
        HiddenDataReport r;
        r.note = "Heuristic, not proof. LSB test targets naive LSB embedding in natural "
                 "images; high-entropy carriers false-positive. cipherbird keyed/whitened "
                 "and DCT/QIM payloads are statistically invisible here — a low score is "
                 "NOT evidence of absence.";

        // (a) Definitive check for an UNKEYED cipherbird payload.
        auto payload = StegoEngine::extract(path);
        r.cipherbird_payload = payload.is_ok();

        // (b) Read the bytes and run the chi-square LSB attack over the payload
        //     region (skip a plausible header so structural bytes don't dominate).
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<HiddenDataReport>::err("StegoAnalyzer: cannot open '" + path + "'");
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                    std::istreambuf_iterator<char>());
        std::size_t off = header_skip(bytes);
        chi_square_lsb(bytes, off, r);
        return Result<HiddenDataReport>::ok(std::move(r));
    }

private:
    // ── Content-based format sniff (magic bytes) ────────────────────────────
    [[nodiscard]] static MediaFormat sniff(const std::vector<uint8_t>& h) {
        auto has = [&](std::initializer_list<uint8_t> m, std::size_t at = 0) {
            if (at + m.size() > h.size()) return false;
            std::size_t i = at; for (uint8_t b : m) if (h[i++] != b) return false; return true;
        };
        if (has({'P','6'}))                                   return MediaFormat::PPM_IMAGE;
        if (has({'B','M'}))                                   return MediaFormat::BMP_IMAGE;
        if (has({0x89,'P','N','G'}))                          return MediaFormat::PNG_IMAGE;
        if (has({'G','I','F','8'}))                           return MediaFormat::GIF_IMAGE;
        if (has({0xFF,0xD8,0xFF}))                            return MediaFormat::JPEG_IMAGE;
        if (has({'f','L','a','C'}))                           return MediaFormat::FLAC_AUDIO;
        if (has({'C','R','V','F'}))                           return MediaFormat::CRVF_VIDEO;
        if (has({'I','D','3'}) || has({0xFF,0xFB}) || has({0xFF,0xF3})) return MediaFormat::MP3_AUDIO;
        if (has({'R','I','F','F'})) {
            if (has({'W','A','V','E'}, 8)) return MediaFormat::WAV_AUDIO;
            if (has({'A','V','I',' '}, 8)) return MediaFormat::AVI_VIDEO;
        }
        if (has({'f','t','y','p'}, 4))                        return MediaFormat::MP4_VIDEO;
        return MediaFormat::UNKNOWN;
    }

    /// Run the engine's reader for `fmt` over the whole file. Returns an empty
    /// string when the body holds what the header promises, otherwise the
    /// reason. Fills width/height for the image formats that report them.
    [[nodiscard]] static std::string body_problem(const std::string& path, MediaFormat fmt,
                                                  std::size_t& w, std::size_t& h) {
        auto dims = [&](auto res) -> std::string {
            if (res.is_err()) return res.error().message;
            w = res.value().first;
            h = res.value().second;
            return {};
        };
        auto accepted = [](auto res) -> std::string {
            return res.is_err() ? res.error().message : std::string{};
        };
        switch (fmt) {
        case MediaFormat::PPM_IMAGE: {
            auto img = ImageSteganographer::read_ppm(path);
            if (img.is_err()) return img.error().message;
            w = img.value().w;
            h = img.value().h;
            return {};
        }
        case MediaFormat::BMP_IMAGE:  return dims(BmpSteganographer::dimensions(path));
        case MediaFormat::PNG_IMAGE:  return dims(PngSteganographer::dimensions(path));
        case MediaFormat::GIF_IMAGE:  return dims(GifSteganographer::dimensions(path));
        case MediaFormat::JPEG_IMAGE: return accepted(JpegSteganographer::capacity_from_file(path));
        case MediaFormat::MP3_AUDIO:  return accepted(Mp3Steganographer::capacity_from_file(path));
        case MediaFormat::CRVF_VIDEO: return accepted(VideoSteganographer::read_crvf(path));
        case MediaFormat::WAV_AUDIO:  return wav_problem(path);
        default:                      return {};
        }
    }

    /// A WAV must hold a fmt chunk and a data chunk whose declared length fits
    /// the bytes that follow it. The embed path clamps a short data chunk, so
    /// this check is stricter than embed on purpose.
    [[nodiscard]] static std::string wav_problem(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return "WAV: cannot open '" + path + "'";
        std::vector<uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        auto le32 = [&](std::size_t at) {
            return std::size_t(b[at]) | std::size_t(b[at + 1]) << 8
                 | std::size_t(b[at + 2]) << 16 | std::size_t(b[at + 3]) << 24;
        };
        if (b.size() < 12) return "WAV: truncated RIFF header";
        std::size_t pos = 12;
        bool fmt = false;
        while (pos + 8 <= b.size()) {
            const std::size_t len = le32(pos + 4);
            const bool is_fmt = std::memcmp(b.data() + pos, "fmt ", 4) == 0;
            const bool is_data = std::memcmp(b.data() + pos, "data", 4) == 0;
            const std::size_t left = b.size() - pos - 8;
            if (is_data && len > left)
                return "WAV: data chunk declares " + std::to_string(len) + " bytes but "
                    + std::to_string(left) + " remain";
            if (len > left) return "WAV: a chunk runs past the end of the file";
            if (is_data) return fmt ? std::string{} : std::string("WAV: data chunk before fmt chunk");
            if (is_fmt) fmt = true;
            pos += 8 + len + (len & 1);
        }
        return "WAV: no data chunk";
    }

    // Skip a header so the chi-square runs over payload-carrying bytes. For known
    // formats use a coarse offset; otherwise 0.
    [[nodiscard]] static std::size_t header_skip(const std::vector<uint8_t>& b) {
        if (b.size() > 2 && b[0] == 'P' && b[1] == '6') {          // PPM: skip past the 3 header tokens
            std::size_t nl = 0, i = 0;
            for (; i < b.size() && nl < 3; ++i) if (b[i] == '\n') ++nl;
            return i;
        }
        if (b.size() > 54 && b[0] == 'B' && b[1] == 'M') return 54; // BMP pixel data starts ~54
        return 0;
    }

    // Westfeld–Pfitzmann chi-square attack on LSB value-pairs (2i, 2i+1).
    static void chi_square_lsb(const std::vector<uint8_t>& b, std::size_t off, HiddenDataReport& r) {
        if (off >= b.size()) return;
        std::array<std::uint64_t, 256> hist{};
        std::size_t n = 0;
        for (std::size_t i = off; i < b.size(); ++i) { ++hist[b[i]]; ++n; }
        r.samples_analysed = n;

        double chi2 = 0.0; int df = 0;
        for (int i = 0; i < 128; ++i) {
            double even = static_cast<double>(hist[2 * i]);
            double odd  = static_cast<double>(hist[2 * i + 1]);
            double expected = (even + odd) / 2.0;
            if (expected < 5.0) continue;                 // chi-square validity floor
            chi2 += (even - expected) * (even - expected) / expected;
            ++df;
        }
        r.lsb_chi_square = chi2;
        if (df >= 2)
            r.lsb_embedding_likelihood = 1.0 - reg_lower_gamma((df - 1) / 2.0, chi2 / 2.0);
    }

    // Regularised lower incomplete gamma P(a,x) (Numerical Recipes gammp).
    [[nodiscard]] static double reg_lower_gamma(double a, double x) {
        if (x <= 0.0 || a <= 0.0) return 0.0;
        const double gln = std::lgamma(a);
        if (x < a + 1.0) {                                // series
            double ap = a, sum = 1.0 / a, del = sum;
            for (int n = 0; n < 300; ++n) {
                ap += 1.0; del *= x / ap; sum += del;
                if (std::fabs(del) < std::fabs(sum) * 1e-14) break;
            }
            return sum * std::exp(-x + a * std::log(x) - gln);
        }
        // continued fraction for Q, return 1-Q
        const double FPMIN = 1e-300;
        double bb = x + 1.0 - a, c = 1.0 / FPMIN, d = 1.0 / bb, h = d;
        for (int i = 1; i < 300; ++i) {
            double an = -i * (i - a);
            bb += 2.0;
            d = an * d + bb; if (std::fabs(d) < FPMIN) d = FPMIN;
            c = bb + an / c;  if (std::fabs(c) < FPMIN) c = FPMIN;
            d = 1.0 / d; double del = d * c; h *= del;
            if (std::fabs(del - 1.0) < 1e-14) break;
        }
        return 1.0 - std::exp(-x + a * std::log(x) - gln) * h;
    }

    [[nodiscard]] static std::string describe(const FileInspection& r, const std::string& problem) {
        if (r.format == MediaFormat::UNKNOWN) return "unrecognised / not a supported media carrier";
        std::string s;
        if (!r.parses) {
            s = fmt_name(r.format) + " magic bytes, but not a usable carrier ("
                + std::to_string(r.file_size) + " bytes): " + problem;
        } else {
            s = "valid " + fmt_name(r.format) + " (" + std::to_string(r.file_size) + " bytes)";
            if (r.width && r.height) s += ", " + std::to_string(r.width) + "x" + std::to_string(r.height);
            if (r.format == MediaFormat::FLAC_AUDIO || r.format == MediaFormat::AVI_VIDEO
                || r.format == MediaFormat::MP4_VIDEO)
                s += " [magic bytes only; contents not checked]";
        }
        if (!r.ext_matches) s += " [WARNING: content does not match file extension]";
        return s;
    }

    [[nodiscard]] static std::string fmt_name(MediaFormat f) {
        switch (f) {
            case MediaFormat::PPM_IMAGE:  return "PPM";
            case MediaFormat::BMP_IMAGE:  return "BMP";
            case MediaFormat::PNG_IMAGE:  return "PNG";
            case MediaFormat::GIF_IMAGE:  return "GIF";
            case MediaFormat::JPEG_IMAGE: return "JPEG";
            case MediaFormat::WAV_AUDIO:  return "WAV";
            case MediaFormat::FLAC_AUDIO: return "FLAC";
            case MediaFormat::MP3_AUDIO:  return "MP3";
            case MediaFormat::CRVF_VIDEO: return "CRVF";
            case MediaFormat::AVI_VIDEO:  return "AVI";
            case MediaFormat::MP4_VIDEO:  return "MP4";
            default:                      return "unknown";
        }
    }
};

} // namespace crypto::stego
