// Thin WASM-side glue over the C ABI.
//
// Emscripten's cwrap can't pass/return C structs by value (CryptoBuffer,
// CryptoKeyPair, CryptoBufferResult) easily — calling the regular C ABI from
// JS would require manually building the hidden struct-return pointer. These
// wrappers expose primitive-returning entry points with caller-supplied output
// buffers, which JS can call directly.
//
// Naming: `cl_wasm_*`. Returns >= 0 on success (often the output length) or -1
// on failure.

#include "cryptolib_c.h"
#include <cstdint>
#include <cstring>
#include <cstddef>

extern "C" {

int cl_wasm_init(void) { return cryptolib_init(); }

const char* cl_wasm_version(void) { return cryptolib_version(); }

// Generic helper: drain a CryptoBufferResult into a caller-owned buffer.
static int drain(CryptoBufferResult r, uint8_t* out, std::size_t out_max) {
    if (!r.buf.data && r.error) { cryptolib_str_free(r.error); return -1; }
    if (r.buf.len > out_max) { cryptolib_buffer_free(&r.buf); return -1; }
    std::size_t n = r.buf.len;
    if (n) std::memcpy(out, r.buf.data, n);
    cryptolib_buffer_free(&r.buf);
    return static_cast<int>(n);
}

int cl_wasm_sha256(const uint8_t* msg, std::size_t msg_len,
                   uint8_t* out, std::size_t out_max) {
    return drain(cryptolib_sha256(const_cast<uint8_t*>(msg), msg_len), out, out_max);
}

int cl_wasm_sha512(const uint8_t* msg, std::size_t msg_len,
                   uint8_t* out, std::size_t out_max) {
    return drain(cryptolib_sha512(const_cast<uint8_t*>(msg), msg_len), out, out_max);
}

int cl_wasm_random_bytes(std::size_t n, uint8_t* out, std::size_t out_max) {
    return drain(cryptolib_random_bytes(n), out, out_max);
}

// Returns 0 on success, fills the two 32-byte buffers.
int cl_wasm_x25519_keygen(uint8_t* pub32, uint8_t* sec32) {
    CryptoKeyPair kp = cryptolib_x25519_keygen();
    if (!kp.public_key.data || !kp.secret_key.data ||
        kp.public_key.len != 32 || kp.secret_key.len != 32) {
        cryptolib_keypair_free(&kp); return -1;
    }
    std::memcpy(pub32, kp.public_key.data, 32);
    std::memcpy(sec32, kp.secret_key.data, 32);
    cryptolib_keypair_free(&kp);
    return 0;
}

int cl_wasm_x25519_shared(const uint8_t* my_sec, const uint8_t* peer_pub, uint8_t* out32) {
    auto r = cryptolib_x25519_shared_secret(const_cast<uint8_t*>(my_sec), 32,
                                             const_cast<uint8_t*>(peer_pub), 32);
    return drain(r, out32, 32);
}

} // extern "C"
