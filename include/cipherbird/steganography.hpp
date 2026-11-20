#pragma once

/**
 * crypto::stego::StegoEngine — Unified facade over all steganography classes.
 *
 * Dispatches embed / extract operations to the appropriate specialist
 * class based on the carrier file's extension (or explicit MediaFormat).
 *
 * Supported formats:
 *   .ppm       → ImageSteganographer  (DCT/QIM, blue channel)
 *   .bmp       → BmpSteganographer    (DCT/QIM, blue channel)
 *   .png       → PngSteganographer    (DCT/QIM via stb_image)
 *   .gif       → GifSteganographer    (LSB blue channel, output PNG)
 *   .jpg/.jpeg → JpegSteganographer   (JSteg coefficient LSB)
 *   .wav       → AudioSteganographer  (Phase Coding, mid-freq bins)
 *   .flac      → FlacSteganographer   (Phase Coding, output WAV)
 *   .mp3       → Mp3Steganographer    (Ancillary data embedding)
 *   .crvf      → VideoSteganographer  (DCT/QIM per frame)
 *   .avi       → AviSteganographer    (DCT/QIM, uncompressed only)
 *   .mp4       → Mp4Steganographer    (Free-box container embedding)
 */

#include "stego_types.hpp"
#include "stego_fec.hpp"
#include "symmetric.hpp"
#include "stego_image.hpp"
#include "stego_audio.hpp"
#include "stego_video.hpp"
#include "stego_bmp.hpp"
#include "stego_png.hpp"
#include "stego_gif.hpp"
#include "stego_jpeg.hpp"
#include "stego_flac.hpp"
#include "stego_mp3.hpp"
#include "stego_avi.hpp"
#include "stego_mp4.hpp"
#include "packet.hpp"

#include <algorithm>
#include <string>
#include <string_view>

namespace crypto::stego {

class StegoEngine {
public:
    /// Embed arbitrary bytes into a carrier file.
    [[nodiscard]] static Result<void> embed(
        std::string_view         cover_path,
        std::span<const uint8_t> payload,
        std::string_view         output_path,
        const StegoParams&       params = {})
    {
        auto fmt = detect_format(cover_path);
        // Keyed embedding: EVERY carrier whitens the embedded stream when a key is
        // set, so no 'CSTG' signature survives (B1, all formats). The PPM/DCT image
        // path additionally applies the key-seeded block permutation (B2); other
        // carriers whiten only. An empty key ⇒ legacy (unkeyed) behaviour.
        switch (fmt) {
        case MediaFormat::PPM_IMAGE:
            if (!params.key.empty())
                return ImageSteganographer::embed(
                    std::string(cover_path), payload, std::string(output_path),
                    std::span<const uint8_t>(params.key), params.image_quant_step);
            return ImageSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step);
        case MediaFormat::BMP_IMAGE:
            return BmpSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::PNG_IMAGE:
            return PngSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::GIF_IMAGE:
            return GifSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::JPEG_IMAGE:
            return JpegSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::WAV_AUDIO:
            return AudioSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params);
        case MediaFormat::FLAC_AUDIO:
            return FlacSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params);
        case MediaFormat::MP3_AUDIO:
            return Mp3Steganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::CRVF_VIDEO:
            return VideoSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params);
        case MediaFormat::AVI_VIDEO:
            return AviSteganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::MP4_VIDEO:
            return Mp4Steganographer::embed(
                std::string(cover_path), payload,
                std::string(output_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        default:
            return Result<void>::err(
                "StegoEngine::embed — unsupported format for '"
                + std::string(cover_path) + "' (supported: .ppm .bmp .png .gif "
                ".jpg .jpeg .wav .flac .mp3 .crvf .avi .mp4)");
        }
    }

    /// Extract hidden bytes from a stego carrier file.
    [[nodiscard]] static Result<Bytes> extract(
        std::string_view   stego_path,
        const StegoParams& params = {})
    {
        auto fmt = detect_format(stego_path);
        // Keyed extraction mirrors embed: un-whiten every carrier (B1) and, for
        // PPM/DCT, invert the block permutation (B2). Empty key ⇒ legacy path.
        switch (fmt) {
        case MediaFormat::PPM_IMAGE:
            if (!params.key.empty())
                return ImageSteganographer::extract(
                    std::string(stego_path), std::span<const uint8_t>(params.key), params.image_quant_step);
            return ImageSteganographer::extract(
                std::string(stego_path), params.image_quant_step);
        case MediaFormat::BMP_IMAGE:
            return BmpSteganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::PNG_IMAGE:
            return PngSteganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::GIF_IMAGE:
            return GifSteganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::JPEG_IMAGE:
            return JpegSteganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::WAV_AUDIO:
            return AudioSteganographer::extract(
                std::string(stego_path), params);
        case MediaFormat::FLAC_AUDIO:
            return FlacSteganographer::extract(
                std::string(stego_path), params);
        case MediaFormat::MP3_AUDIO:
            return Mp3Steganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::CRVF_VIDEO:
            return VideoSteganographer::extract(
                std::string(stego_path), params);
        case MediaFormat::AVI_VIDEO:
            return AviSteganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        case MediaFormat::MP4_VIDEO:
            return Mp4Steganographer::extract(
                std::string(stego_path), params.image_quant_step,
                std::span<const uint8_t>(params.key));
        default:
            return Result<Bytes>::err(
                "StegoEngine::extract — unsupported format for '"
                + std::string(stego_path) + "'");
        }
    }

    /// Embed a serialised EncryptedPacket into a carrier file.
    [[nodiscard]] static Result<void> embed_packet(
        std::string_view           cover_path,
        const crypto::EncryptedPacket& packet,
        std::string_view           output_path,
        const StegoParams&         params = {})
    {
        auto serial = packet.serialise();
        return embed(cover_path,
                     std::span<const uint8_t>(serial.data(), serial.size()),
                     output_path, params);
    }

    /// Extract and deserialise an EncryptedPacket from a stego carrier file.
    [[nodiscard]] static Result<crypto::EncryptedPacket> extract_packet(
        std::string_view   stego_path,
        const StegoParams& params = {})
    {
        auto bytes_res = extract(stego_path, params);
        if (bytes_res.is_err())
            return Result<crypto::EncryptedPacket>::err(bytes_res.error().message);

        auto& bytes = bytes_res.value();
        return crypto::EncryptedPacket::deserialise(
            std::span<const uint8_t>(bytes.data(), bytes.size()));
    }

    /// Encrypt-then-hide (the always-encrypt path). AEAD-seals `plaintext`
    /// under a key derived from `master_key`, then embeds the *ciphertext* via
    /// the keyed (whitened + block-permuted) stego path. A single master key
    /// fans out into three domain-separated subkeys — AEAD, whitening,
    /// permutation — so confidentiality (XChaCha20-Poly1305), integrity (the
    /// Poly1305 tag) and unlinkability (no surviving 'CSTG' signature) all hold
    /// under one secret. Unlike embed(), the payload is never written to the
    /// carrier as cleartext, so a caller cannot accidentally hide a secret in
    /// the clear. Currently restricted to the .ppm DCT carrier (the keyed path).
    [[nodiscard]] static Result<void> embed_encrypted(
        std::string_view         cover_path,
        std::span<const uint8_t> plaintext,
        std::string_view         output_path,
        std::span<const uint8_t> master_key,
        const StegoParams&       base_params = {})
    {
        if (master_key.empty())
            return Result<void>::err("StegoEngine::embed_encrypted — master_key must be non-empty");

        // AEAD subkey — domain-separated from the whiten/perm subkeys.
        auto aead_key = stego_subkey(master_key, kAeadLabel);
        auto ct = crypto::symmetric::XChaCha20Poly1305::encrypt(
            plaintext, { aead_key.data(), aead_key.size() });
        sodium_memzero(aead_key.data(), aead_key.size());
        if (ct.is_err()) return Result<void>::err(ct.error().message);

        StegoParams p = base_params;
        p.key.assign(master_key.begin(), master_key.end());
        const auto& blob = ct.value();
        auto r = embed(cover_path, { blob.data(), blob.size() }, output_path, p);
        sodium_memzero(p.key.data(), p.key.size());
        return r;
    }

    /// Inverse of embed_encrypted(): keyed-extract the ciphertext, then AEAD-open
    /// it. A wrong key fails fast at the CRC/whitening layer and, underneath, at
    /// the Poly1305 tag; a tampered carrier fails the tag. Returns the recovered
    /// plaintext bytes.
    [[nodiscard]] static Result<Bytes> extract_decrypt(
        std::string_view         stego_path,
        std::span<const uint8_t> master_key,
        const StegoParams&       base_params = {})
    {
        if (master_key.empty())
            return Result<Bytes>::err("StegoEngine::extract_decrypt — master_key must be non-empty");

        StegoParams p = base_params;
        p.key.assign(master_key.begin(), master_key.end());
        auto ct = extract(stego_path, p);
        sodium_memzero(p.key.data(), p.key.size());
        if (ct.is_err()) return Result<Bytes>::err(ct.error().message);

        auto aead_key = stego_subkey(master_key, kAeadLabel);
        const auto& blob = ct.value();
        auto pt = crypto::symmetric::XChaCha20Poly1305::decrypt(
            { blob.data(), blob.size() }, { aead_key.data(), aead_key.size() });
        sodium_memzero(aead_key.data(), aead_key.size());
        if (pt.is_err()) return Result<Bytes>::err(pt.error().message);

        const auto& sb = pt.value();
        return Result<Bytes>::ok(Bytes(sb.data(), sb.data() + sb.size()));
    }

    /// Query the maximum payload capacity of a carrier file.
    [[nodiscard]] static Result<StegoCapacity> capacity(
        std::string_view   cover_path,
        const StegoParams& params = {})
    {
        auto fmt = detect_format(cover_path);
        switch (fmt) {
        case MediaFormat::PPM_IMAGE: {
            auto dims = read_ppm_dims(std::string(cover_path));
            if (dims.is_err()) return Result<StegoCapacity>::err(dims.error().message);
            auto [w, h] = dims.value();
            std::size_t cap = ImageSteganographer::capacity(w, h);
            return Result<StegoCapacity>::ok(StegoCapacity{
                cap, StegoHeader::SIZE,
                "PPM " + std::to_string(w) + "x" + std::to_string(h)
                + " DCT/QIM -> " + std::to_string(cap) + " bytes"
            });
        }
        case MediaFormat::BMP_IMAGE:
        case MediaFormat::PNG_IMAGE:
        case MediaFormat::GIF_IMAGE: {
            // For these formats, capacity depends on image dimensions
            // Return a generic message — exact capacity requires reading the file
            return Result<StegoCapacity>::ok(StegoCapacity{
                0, StegoHeader::SIZE,
                "Capacity depends on image dimensions (read file to determine)"
            });
        }
        case MediaFormat::JPEG_IMAGE: {
            auto cap_res = JpegSteganographer::capacity_from_file(std::string(cover_path));
            if (cap_res.is_err()) return Result<StegoCapacity>::err(cap_res.error().message);
            return Result<StegoCapacity>::ok(StegoCapacity{
                cap_res.value(), StegoHeader::SIZE,
                "JPEG JSteg -> ~" + std::to_string(cap_res.value()) + " bytes"
            });
        }
        case MediaFormat::WAV_AUDIO: {
            auto info = read_wav_sample_count(std::string(cover_path));
            if (info.is_err()) return Result<StegoCapacity>::err(info.error().message);
            auto [samples, channels, rate] = info.value();
            std::size_t cap = AudioSteganographer::capacity(samples / channels, params);
            return Result<StegoCapacity>::ok(StegoCapacity{
                cap, StegoHeader::SIZE,
                "WAV Phase Coding -> " + std::to_string(cap) + " bytes"
            });
        }
        case MediaFormat::FLAC_AUDIO: {
            return Result<StegoCapacity>::ok(StegoCapacity{
                0, StegoHeader::SIZE,
                "FLAC (decode to WAV, capacity depends on sample count)"
            });
        }
        case MediaFormat::MP3_AUDIO: {
            auto cap_res = Mp3Steganographer::capacity_from_file(std::string(cover_path));
            if (cap_res.is_err()) return Result<StegoCapacity>::err(cap_res.error().message);
            return Result<StegoCapacity>::ok(StegoCapacity{
                cap_res.value(), StegoHeader::SIZE,
                "MP3 ancillary -> " + std::to_string(cap_res.value()) + " bytes"
            });
        }
        case MediaFormat::CRVF_VIDEO: {
            auto dims = read_crvf_dims(std::string(cover_path));
            if (dims.is_err()) return Result<StegoCapacity>::err(dims.error().message);
            auto [w, h, fc] = dims.value();
            std::size_t cap = VideoSteganographer::capacity(fc, w, h, params);
            return Result<StegoCapacity>::ok(StegoCapacity{
                cap, StegoHeader::SIZE,
                "CRVF DCT/QIM " + std::to_string(fc) + " frames -> "
                + std::to_string(cap) + " bytes"
            });
        }
        case MediaFormat::AVI_VIDEO: {
            return Result<StegoCapacity>::ok(StegoCapacity{
                0, StegoHeader::SIZE,
                "AVI (uncompressed only, capacity depends on dimensions)"
            });
        }
        case MediaFormat::MP4_VIDEO: {
            return Result<StegoCapacity>::ok(StegoCapacity{
                Mp4Steganographer::capacity(), StegoHeader::SIZE,
                "MP4 free-box container -> ~1MB nominal capacity"
            });
        }
        default:
            return Result<StegoCapacity>::err(
                "StegoEngine::capacity — unsupported format for '"
                + std::string(cover_path) + "'");
        }
    }

    /// Compute PSNR/SNR between cover and stego files.
    [[nodiscard]] static Result<double> quality(
        std::string_view cover_path,
        std::string_view stego_path)
    {
        switch (detect_format(cover_path)) {
        case MediaFormat::PPM_IMAGE: {
            double v = ImageSteganographer::psnr(
                std::string(cover_path), std::string(stego_path));
            if (v < 0) return Result<double>::err("PSNR: file error");
            return Result<double>::ok(v);
        }
        case MediaFormat::BMP_IMAGE: {
            double v = BmpSteganographer::psnr(
                std::string(cover_path), std::string(stego_path));
            if (v < 0) return Result<double>::err("PSNR: file error");
            return Result<double>::ok(v);
        }
        case MediaFormat::PNG_IMAGE: {
            double v = PngSteganographer::psnr(
                std::string(cover_path), std::string(stego_path));
            if (v < 0) return Result<double>::err("PSNR: file error");
            return Result<double>::ok(v);
        }
        case MediaFormat::GIF_IMAGE: {
            double v = GifSteganographer::psnr(
                std::string(cover_path), std::string(stego_path));
            if (v < 0) return Result<double>::err("PSNR: file error");
            return Result<double>::ok(v);
        }
        case MediaFormat::WAV_AUDIO: {
            double v = AudioSteganographer::snr(
                std::string(cover_path), std::string(stego_path));
            if (v < 0) return Result<double>::err("SNR: file error");
            return Result<double>::ok(v);
        }
        default:
            return Result<double>::err(
                "quality: not implemented for this format");
        }
    }

    /// Format detection from file extension.
    [[nodiscard]] static MediaFormat detect_format(std::string_view path) noexcept {
        auto ext = extension_lower(path);
        if (ext == ".ppm")  return MediaFormat::PPM_IMAGE;
        if (ext == ".bmp")  return MediaFormat::BMP_IMAGE;
        if (ext == ".png")  return MediaFormat::PNG_IMAGE;
        if (ext == ".gif")  return MediaFormat::GIF_IMAGE;
        if (ext == ".jpg" || ext == ".jpeg") return MediaFormat::JPEG_IMAGE;
        if (ext == ".wav")  return MediaFormat::WAV_AUDIO;
        if (ext == ".flac") return MediaFormat::FLAC_AUDIO;
        if (ext == ".mp3")  return MediaFormat::MP3_AUDIO;
        if (ext == ".crvf") return MediaFormat::CRVF_VIDEO;
        if (ext == ".avi")  return MediaFormat::AVI_VIDEO;
        if (ext == ".mp4")  return MediaFormat::MP4_VIDEO;
        return MediaFormat::UNKNOWN;
    }

private:
    // Domain-separation label for the AEAD subkey — distinct from the whitening
    // ("...-whiten-v1") and permutation ("...-perm-v1") labels in stego_keyed.hpp,
    // so all three subkeys derived from one master key are independent.
    static constexpr std::string_view kAeadLabel = "cryptolib-stego-aead-v1";

    [[nodiscard]] static Result<std::pair<std::size_t,std::size_t>>
    read_ppm_dims(const std::string& path) {
        std::ifstream f(path);
        if (!f) return Result<std::pair<std::size_t,std::size_t>>::err(
            "capacity: cannot open '" + path + "'");
        std::string magic; f >> magic;
        if (magic != "P6")
            return Result<std::pair<std::size_t,std::size_t>>::err("not a P6 PPM file");
        std::size_t w = 0, h = 0;
        skip_comment(f); f >> w; skip_comment(f); f >> h;
        return Result<std::pair<std::size_t,std::size_t>>::ok({w, h});
    }

    [[nodiscard]] static Result<std::tuple<std::size_t,uint16_t,uint32_t>>
    read_wav_sample_count(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<std::tuple<std::size_t,uint16_t,uint32_t>>::err(
            "capacity: cannot open '" + path + "'");

        auto read_tag = [&]() { char t[4]; f.read(t,4); return std::string(t,4); };
        auto read_u32 = [&]() { uint8_t b[4]; f.read(reinterpret_cast<char*>(b),4);
            return uint32_t(b[0])|uint32_t(b[1])<<8|uint32_t(b[2])<<16|uint32_t(b[3])<<24; };
        auto read_u16 = [&]() { uint8_t b[2]; f.read(reinterpret_cast<char*>(b),2);
            return uint16_t(b[0])|uint16_t(b[1])<<8; };

        if (read_tag() != "RIFF") return Result<std::tuple<std::size_t,uint16_t,uint32_t>>::err("Not RIFF");
        read_u32(); read_tag();
        uint16_t channels = 1; uint32_t rate = 44100; uint32_t data_size = 0;
        while (f) {
            std::string chunk = read_tag(); uint32_t sz = read_u32();
            if (chunk == "fmt ") {
                read_u16(); channels = read_u16(); rate = read_u32();
                f.seekg(static_cast<std::streamoff>(sz - 8), std::ios::cur);
            } else if (chunk == "data") {
                data_size = sz; break;
            } else {
                f.seekg(static_cast<std::streamoff>(sz), std::ios::cur);
            }
        }
        return Result<std::tuple<std::size_t,uint16_t,uint32_t>>::ok(
            {data_size / 2, channels, rate});
    }

    [[nodiscard]] static Result<std::tuple<std::size_t,std::size_t,std::size_t>>
    read_crvf_dims(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return Result<std::tuple<std::size_t,std::size_t,std::size_t>>::err(
            "capacity: cannot open '" + path + "'");
        char magic[4]; f.read(magic, 4);
        if (std::string(magic,4) != "CRVF")
            return Result<std::tuple<std::size_t,std::size_t,std::size_t>>::err("not CRVF");
        uint8_t ver; f.read(reinterpret_cast<char*>(&ver), 1);
        auto ru32 = [&]() { uint8_t b[4]; f.read(reinterpret_cast<char*>(b),4);
            return uint32_t(b[0])|uint32_t(b[1])<<8|uint32_t(b[2])<<16|uint32_t(b[3])<<24; };
        auto ru16 = [&]() { uint8_t b[2]; f.read(reinterpret_cast<char*>(b),2);
            return uint16_t(b[0])|uint16_t(b[1])<<8; };
        uint32_t w = ru32(), h = ru32(); ru32(); ru16(); uint32_t fc = ru32();
        return Result<std::tuple<std::size_t,std::size_t,std::size_t>>::ok({w, h, fc});
    }

    [[nodiscard]] static std::string extension_lower(std::string_view path) noexcept {
        auto pos = path.rfind('.');
        if (pos == std::string_view::npos) return {};
        std::string ext(path.substr(pos));
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        return ext;
    }

    static void skip_comment(std::ifstream& f) {
        char c;
        while (f.get(c)) {
            if (c == '#') { while (f.get(c) && c != '\n') {} }
            else if (std::isspace(static_cast<unsigned char>(c))) { continue; }
            else { f.putback(c); break; }
        }
    }
};

} // namespace crypto::stego
