/**
 * fuzz_packet.cpp — libFuzzer target for EncryptedPacket::deserialise.
 *
 * Pure-buffer decode path on untrusted input. Build with -DCRYPTOLIB_FUZZ=ON
 * (clang), then: ./fuzz_packet -max_total_time=60
 */

#include <cryptolib/cryptolib.hpp>

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto r = crypto::EncryptedPacket::deserialise({data, size});
    if (r.is_ok()) {
        // Touch the parsed fields so the optimiser can't elide the work.
        volatile std::size_t s = r.value().ciphertext.size()
                               + r.value().signature.size()
                               + r.value().kdf_salt.size();
        (void)s;
    }
    return 0;
}
