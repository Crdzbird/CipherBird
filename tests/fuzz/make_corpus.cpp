/**
 * make_corpus.cpp: writes one small, valid carrier of every format the
 * library reads into a directory, as the seed corpus for fuzz_stego.
 * Usage: fuzz_corpus_gen <directory>
 */
#include <cryptolib/cryptolib.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: fuzz_corpus_gen <directory>\n";
        return EXIT_FAILURE;
    }
    crypto::init();
    using MG = crypto::stego::MediaGenerator;
    const std::filesystem::path dir = argv[1];
    std::filesystem::create_directories(dir);
    auto at = [&](const char* name) { return (dir / name).string(); };
    int failures = 0;
    auto check = [&](const char* name, crypto::Result<void> r) {
        if (r.is_err()) { std::cerr << name << ": " << r.error().message << "\n"; ++failures; }
    };
    check("ppm", MG::generate_ppm(at("seed.ppm"), 16, 16));
    check("bmp", MG::generate_bmp(at("seed.bmp"), 16, 16));
    check("png", MG::generate_png(at("seed.png"), 16, 16));
    check("gif", MG::generate_gif(at("seed.gif"), 16, 16));
    check("wav", MG::generate_wav(at("seed.wav"), 8000, 1, 0.1));
    check("crvf", MG::generate_crvf(at("seed.crvf"), 16, 16, 4, 2));
    check("avi", MG::generate_avi(at("seed.avi"), 16, 16, 4, 2));
    check("mp3", MG::generate_mp3(at("seed.mp3"), 0.1, 32));
    check("mp4", MG::generate_mp4(at("seed.mp4"), 16, 16));
    /* A JPEG and a FLAC come from the carriers the stego tests embed into;
     * the generator has no encoder for them, so the fuzzer derives them by
     * mutation from the other seeds. */
    for (auto& entry : std::filesystem::directory_iterator(dir))
        std::cout << entry.path().filename().string() << " " << std::filesystem::file_size(entry.path()) << " bytes\n";
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
