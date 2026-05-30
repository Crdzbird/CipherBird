// CryptoLib Swift console demo.
//
// Verifies the C ABI from Swift via a bridging header (cryptolib_c.h). The
// SwiftUI app under ../Sources uses the same calls; this is a fast CLI check.
//
// Build (see top-level Makefile target `swift`):
//   swiftc -import-objc-header ../../../cryptolib_c.h main.swift \
//          -L ../../../../build/release -lcryptolib_c \
//          -Xlinker -rpath -Xlinker ../../../../build/release -o swift_demo

import Foundation

func consume(_ r: CryptoBufferResult) -> [UInt8]? {
    guard let data = r.buf.data else {
        if let e = r.error {
            FileHandle.standardError.write(Data("error: \(String(cString: e))\n".utf8))
            cryptolib_str_free(e)
        }
        return nil
    }
    let bytes = Array(UnsafeBufferPointer(start: data, count: r.buf.len))
    var buf = r.buf
    cryptolib_buffer_free(&buf)
    return bytes
}

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib version: \(String(cString: cryptolib_version()))")

// Random bytes
if let r = consume(cryptolib_random_bytes(32)) {
    print("random(32):  \(hex(r))")
}

// SHA-256("abc")
let msg = Array("abc".utf8)
let digest = msg.withUnsafeBufferPointer { consume(cryptolib_sha256($0.baseAddress, $0.count)) } ?? []
print("sha256(abc): \(hex(digest))")

// Vault seal/open round-trip
guard let key = consume(cryptolib_random_bytes(32)) else { fatalError("keygen") }
let vault = key.withUnsafeBufferPointer { cryptolib_vault_create($0.baseAddress, $0.count, 0) }
guard vault != nil else { fatalError("vault_create") }
defer { cryptolib_vault_free(vault) }

let plaintext = Array("hello from swift".utf8)
var errPtr: UnsafeMutablePointer<CChar>? = nil
var packet = plaintext.withUnsafeBufferPointer {
    cryptolib_vault_seal(vault, $0.baseAddress, $0.count, "ctx", &errPtr)
}
if let e = errPtr { fatalError("seal: \(String(cString: e))") }
defer { cryptolib_packet_free(&packet) }

if let opened = consume(cryptolib_vault_open(vault, &packet, "ctx")) {
    print("vault roundtrip: \"\(String(decoding: opened, as: UTF8.self))\"")
}

// Wrong AAD must fail cleanly.
let bad = cryptolib_vault_open(vault, &packet, "wrong")
precondition(bad.buf.data == nil, "wrong AAD should not decrypt")
if let e = bad.error { cryptolib_str_free(e) }

// Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
let factor = consume(cryptolib_random_bytes(32))!   // stands in for a hardware key
let kr = cryptolib_keyring_create()
factor.withUnsafeBufferPointer { _ = cryptolib_keyring_add_device_slot(kr, $0.baseAddress, $0.count) }
_ = cryptolib_keyring_add_passphrase_slot(kr, "cross-device pass", 0)
let blob = consume(cryptolib_keyring_serialise(kr))!
var krErr: UnsafeMutablePointer<CChar>? = nil
let kr2 = blob.withUnsafeBufferPointer { cryptolib_keyring_deserialise($0.baseAddress, $0.count, &krErr) }
let mDev  = factor.withUnsafeBufferPointer { consume(cryptolib_keyring_unlock_with_device(kr2, $0.baseAddress, $0.count)) }!
let mPass = consume(cryptolib_keyring_unlock_with_passphrase(kr2, "cross-device pass"))!
print("keyring slots: \(cryptolib_keyring_slot_count(kr)) · device==passphrase: \(mDev == mPass)")
cryptolib_keyring_free(kr)
cryptolib_keyring_free(kr2)

print("Swift demo OK")
