// Platform factor provider example: a device-bound key from the Apple Keychain
// feeding the CryptoLib keyring's device slot.
//
// This is the DEFAULT single-device path: the master key is wrapped under a
// 32-byte key that lives in the Keychain and never leaves the device. Add a
// passphrase slot (see the other demos) to opt into cross-device.
//
// PRODUCTION HARDENING (one-line change): gate retrieval behind biometrics and
// use the data-protection keychain so Face ID / Touch ID is required to unlock:
//
//   let ac = SecAccessControlCreateWithFlags(nil,
//       kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.userPresence], nil)!
//   query[kSecAttrAccessControl as String]      = ac      // instead of kSecAttrAccessible
//   query[kSecUseDataProtectionKeychain as String] = true // required on iOS
//
// On Apple Silicon / Secure Enclave devices you can instead use
// CryptoKit `SecureEnclave.P256.KeyAgreement` and derive the 32 bytes via HKDF
// over a key agreement with a fixed peer key — fully non-exportable.
//
// Build/run (see Makefile target `swift-keyring`):
//   swiftc -import-objc-header ../../../cryptolib_c.h keyring_device.swift \
//     -framework Security -L ../../../../build/release -lcryptolib_c \
//     -Xlinker -rpath -Xlinker ../../../../build/release -o kd && ./kd

import Foundation
import Security

private let kAccount = "cryptolib.device.factor"
private let kService = "com.cryptolib.keyring"

private func loadFactor() -> [UInt8]? {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: kAccount,
        kSecAttrService as String: kService,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
          let d = item as? Data, d.count == 32 else { return nil }
    return [UInt8](d)
}

/// Returns the device's 32-byte factor key, creating + storing it on first use.
private func deviceFactorKey() -> [UInt8] {
    if let existing = loadFactor() { return existing }
    var key = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
    let add: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: kAccount,
        kSecAttrService as String: kService,
        kSecValueData as String: Data(key),
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    SecItemDelete(add as CFDictionary)
    SecItemAdd(add as CFDictionary, nil)
    return key
}

private func deleteFactor() {
    SecItemDelete([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: kAccount,
        kSecAttrService as String: kService,
    ] as CFDictionary)
}

private func consume(_ r: CryptoBufferResult) -> [UInt8]? {
    guard let d = r.buf.data else { if let e = r.error { cryptolib_str_free(e) }; return nil }
    let out = Array(UnsafeBufferPointer(start: d, count: r.buf.len))
    var b = r.buf
    cryptolib_buffer_free(&b)
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
deleteFactor()  // clean slate for a repeatable demo

// ── Enroll: the Keychain device factor wraps a new keyring's master key ──────
let factor = deviceFactorKey()
let kr = cryptolib_keyring_create()
factor.withUnsafeBufferPointer { _ = cryptolib_keyring_add_device_slot(kr, $0.baseAddress, $0.count) }
let blob = consume(cryptolib_keyring_serialise(kr))!
print("enrolled: \(cryptolib_keyring_slot_count(kr)) device slot · envelope \(blob.count) bytes")

// ── Relaunch: re-fetch the SAME factor from the Keychain and unlock ──────────
let factor2 = deviceFactorKey()  // idempotent
print("keychain factor stable across calls: \(factor == factor2)")
var err: UnsafeMutablePointer<CChar>? = nil
let kr2 = blob.withUnsafeBufferPointer { cryptolib_keyring_deserialise($0.baseAddress, $0.count, &err) }
let master = factor2.withUnsafeBufferPointer {
    consume(cryptolib_keyring_unlock_with_device(kr2, $0.baseAddress, $0.count))
}
print("unlocked master via Keychain factor: \(master != nil) (\(master?.count ?? 0) bytes)")

// ── A wrong device key must fail ─────────────────────────────────────────────
let wrong = [UInt8](repeating: 0, count: 32)
let bad = wrong.withUnsafeBufferPointer { cryptolib_keyring_unlock_with_device(kr2, $0.baseAddress, $0.count) }
print("wrong device key rejected: \(bad.buf.data == nil)")
if let e = bad.error { cryptolib_str_free(e) }

cryptolib_keyring_free(kr)
cryptolib_keyring_free(kr2)
deleteFactor()
print("Device-factor (Keychain) demo OK")
