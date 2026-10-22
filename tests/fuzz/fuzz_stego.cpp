/**
 * fuzz_stego.cpp — libFuzzer target for the steganography extract parsers.
 *
 * The format extractors take file paths, so each input is written to a temp
 * file and run through every format parser (BMP/PPM/PNG/GIF/JPEG/WAV/FLAC/AVI/
 * CRVF/MP3/MP4 via StegoEngine plus the direct format classes), the carrier
 * analyzer and the media entropy harvester. This exercises every reader of
 * untrusted media in the library.
 *
 * Build with -DCRYPTOLIB_FUZZ=ON (clang), then:
 *   ./fuzz_stego -max_total_time=120 tests/fuzz/corpus/stego
 * The seed corpus is produced by fuzz_corpus_gen (small valid carriers of
 * every format) so the fuzzer starts from well-formed structure.
 */

#include <cryptolib/cryptolib.hpp>

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>

namespace {

void write_tmp(const char* path, const uint8_t* data, size_t size) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace crypto::stego;

    // Each parser gets the same bytes via its own temp file. Errors are expected;
    // we only care that nothing reads/writes out of bounds (ASan/UBSan enforce).
    {
        const char* p = "/tmp/cryptolib_fuzz.bmp";
        write_tmp(p, data, size);
        (void)BmpSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.ppm";
        write_tmp(p, data, size);
        (void)ImageSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.png";
        write_tmp(p, data, size);
        (void)PngSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.gif";
        write_tmp(p, data, size);
        (void)GifSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.jpg";
        write_tmp(p, data, size);
        (void)JpegSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.wav";
        write_tmp(p, data, size);
        (void)AudioSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.flac";
        write_tmp(p, data, size);
        (void)FlacSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.mp3";
        write_tmp(p, data, size);
        (void)Mp3Steganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.mp4";
        write_tmp(p, data, size);
        (void)Mp4Steganographer::extract(p);
    }
    {
        /* The engine sniffs content, not the extension; the analyzer and the
         * entropy harvester read the same bytes through their own paths. */
        const char* p = "/tmp/cryptolib_fuzz.bin";
        write_tmp(p, data, size);
        (void)StegoEngine::extract(p);
        (void)StegoAnalyzer::inspect(p);
        (void)StegoAnalyzer::detect_hidden(p);
        (void)crypto::entropy::MediaEntropy::from_file_deterministic(
            p, crypto::entropy::SourcePolicy::permissive());
        (void)crypto::entropy::MediaEntropy::assess_file_health(p);
        {
            crypto::entropy::LiveEntropy live(crypto::entropy::SourcePolicy::permissive(), 64.0);
            (void)live.feed(std::span<const uint8_t>(data, size));
            (void)live.feed(std::span<const uint8_t>(data, size), 1);
            (void)live.generate(32);
        }
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.avi";
        write_tmp(p, data, size);
        (void)AviSteganographer::extract(p);
    }
    {
        const char* p = "/tmp/cryptolib_fuzz.crvf";
        write_tmp(p, data, size);
        (void)VideoSteganographer::extract(p);
    }
    return 0;
}
