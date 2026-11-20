// CipherBird Swift console demo.
//
// Verifies the C ABI from Swift via a bridging header (cipherbird_c.h). The
// SwiftUI app under ../Sources uses the same calls; this is a fast CLI check.
//
// Build (see top-level Makefile target `swift`):
//   swiftc -import-objc-header ../../../cipherbird_c.h main.swift \
//          -L ../../../../build/release -lcipherbird_c \
//          -Xlinker -rpath -Xlinker ../../../../build/release -o swift_demo

import Foundation

func consume(_ r: CryptoBufferResult) -> [UInt8]? {
    guard let data = r.buf.data else {
        if let e = r.error {
            FileHandle.standardError.write(Data("error: \(String(cString: e))\n".utf8))
            cipherbird_str_free(e)
        }
        return nil
    }
    let bytes = Array(UnsafeBufferPointer(start: data, count: r.buf.len))
    var buf = r.buf
    cipherbird_buffer_free(&buf)
    return bytes
}

func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

guard cipherbird_init() == 0 else { fatalError("init failed") }
print("CipherBird version: \(String(cString: cipherbird_version()))")

// Random bytes
if let r = consume(cipherbird_random_bytes(32)) {
    print("random(32):  \(hex(r))")
}

// SHA-256("abc")
let msg = Array("abc".utf8)
let digest = msg.withUnsafeBufferPointer { consume(cipherbird_sha256($0.baseAddress, $0.count)) } ?? []
print("sha256(abc): \(hex(digest))")

// Vault seal/open round-trip
guard let key = consume(cipherbird_random_bytes(32)) else { fatalError("keygen") }
let vault = key.withUnsafeBufferPointer { cipherbird_vault_create($0.baseAddress, $0.count, 0) }
guard vault != nil else { fatalError("vault_create") }
defer { cipherbird_vault_free(vault) }

let plaintext = Array("hello from swift".utf8)
var errPtr: UnsafeMutablePointer<CChar>? = nil
var packet = plaintext.withUnsafeBufferPointer {
    cipherbird_vault_seal(vault, $0.baseAddress, $0.count, "ctx", &errPtr)
}
if let e = errPtr { fatalError("seal: \(String(cString: e))") }
defer { cipherbird_packet_free(&packet) }

if let opened = consume(cipherbird_vault_open(vault, &packet, "ctx")) {
    print("vault roundtrip: \"\(String(decoding: opened, as: UTF8.self))\"")
}

// Wrong AAD must fail cleanly.
let bad = cipherbird_vault_open(vault, &packet, "wrong")
precondition(bad.buf.data == nil, "wrong AAD should not decrypt")
if let e = bad.error { cipherbird_str_free(e) }

// Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
let factor = consume(cipherbird_random_bytes(32))!   // stands in for a hardware key
let kr = cipherbird_keyring_create()
factor.withUnsafeBufferPointer { _ = cipherbird_keyring_add_device_slot(kr, $0.baseAddress, $0.count) }
_ = cipherbird_keyring_add_passphrase_slot(kr, "cross-device pass", 0)
let blob = consume(cipherbird_keyring_serialise(kr))!
var krErr: UnsafeMutablePointer<CChar>? = nil
let kr2 = blob.withUnsafeBufferPointer { cipherbird_keyring_deserialise($0.baseAddress, $0.count, &krErr) }
let mDev  = factor.withUnsafeBufferPointer { consume(cipherbird_keyring_unlock_with_device(kr2, $0.baseAddress, $0.count)) }!
let mPass = consume(cipherbird_keyring_unlock_with_passphrase(kr2, "cross-device pass"))!
print("keyring slots: \(cipherbird_keyring_slot_count(kr)) · device==passphrase: \(mDev == mPass)")
cipherbird_keyring_free(kr)
cipherbird_keyring_free(kr2)

// ── Newly exposed feature functions ──
func b(_ s: String) -> [UInt8] { Array(s.utf8) }
func keypair(_ kp: CryptoKeyPair) -> ([UInt8], [UInt8]) {
    var k = kp
    let pub = Array(UnsafeBufferPointer(start: k.public_key.data, count: k.public_key.len))
    let sec = Array(UnsafeBufferPointer(start: k.secret_key.data, count: k.secret_key.len))
    cipherbird_keypair_free(&k)
    return (pub, sec)
}

// Committing AEAD (UtC) — ciphertext binds the key.
let caKey = consume(cipherbird_random_bytes(32))!, caAad = b("ctx")
let caCt = b("commit me").withUnsafeBufferPointer { p in caKey.withUnsafeBufferPointer { k in caAad.withUnsafeBufferPointer { a in
    consume(cipherbird_committing_encrypt(p.baseAddress, p.count, k.baseAddress, k.count, a.baseAddress, a.count)) } } }!
let caPt = caCt.withUnsafeBufferPointer { c in caKey.withUnsafeBufferPointer { k in caAad.withUnsafeBufferPointer { a in
    consume(cipherbird_committing_decrypt(c.baseAddress, c.count, k.baseAddress, k.count, a.baseAddress, a.count)) } } }!
let caBad = caCt.withUnsafeBufferPointer { c in consume(cipherbird_random_bytes(32))!.withUnsafeBufferPointer { k in caAad.withUnsafeBufferPointer { a in
    cipherbird_committing_decrypt(c.baseAddress, c.count, k.baseAddress, k.count, a.baseAddress, a.count) } } }
let caReject = caBad.buf.data == nil
if let e = caBad.error { cipherbird_str_free(e) }
print("committing AEAD: roundtrip=\"\(String(decoding: caPt, as: UTF8.self))\" reject-wrong-key=\(caReject)")

// HKDF-SHA256 + HMAC-SHA256.
let ikm = consume(cipherbird_random_bytes(32))!, salt = b("salt"), info = b("app")
let prk = salt.withUnsafeBufferPointer { s in ikm.withUnsafeBufferPointer { i in
    consume(cipherbird_hkdf_extract(s.baseAddress, s.count, i.baseAddress, i.count)) } }!
let okm = prk.withUnsafeBufferPointer { p in info.withUnsafeBufferPointer { f in
    consume(cipherbird_hkdf_expand(p.baseAddress, p.count, f.baseAddress, f.count, 42)) } }!
let okm1 = ikm.withUnsafeBufferPointer { i in salt.withUnsafeBufferPointer { s in info.withUnsafeBufferPointer { f in
    consume(cipherbird_hkdf_derive(i.baseAddress, i.count, s.baseAddress, s.count, f.baseAddress, f.count, 42)) } } }!
let macMsg = b("mac me")
let mac256 = macMsg.withUnsafeBufferPointer { m in ikm.withUnsafeBufferPointer { k in
    consume(cipherbird_hmac_sha256(m.baseAddress, m.count, k.baseAddress, k.count)) } }!
let macOk = macMsg.withUnsafeBufferPointer { m in mac256.withUnsafeBufferPointer { t in ikm.withUnsafeBufferPointer { k in
    cipherbird_hmac_sha256_verify(m.baseAddress, m.count, t.baseAddress, t.count, k.baseAddress, k.count) == 1 } } }
print("hkdf len=\(okm.count) consistent=\(okm == okm1) · hmac256 verify=\(macOk)")

// Hybrid signature (Ed25519 + ML-DSA-65).
let (hsPub, hsSec) = keypair(cipherbird_hybrid_sig_keygen())
let sMsg = b("sign me")
let hsig = sMsg.withUnsafeBufferPointer { m in hsSec.withUnsafeBufferPointer { s in
    consume(cipherbird_hybrid_sig_sign(m.baseAddress, m.count, s.baseAddress, s.count)) } }!
let hsigOk = sMsg.withUnsafeBufferPointer { m in hsig.withUnsafeBufferPointer { s in hsPub.withUnsafeBufferPointer { p in
    cipherbird_hybrid_sig_verify(m.baseAddress, m.count, s.baseAddress, s.count, p.baseAddress, p.count) == 1 } } }
print("hybrid sig: len=\(hsig.count) verify=\(hsigOk)")

// BLS deterministic keygen from IKM.
let blsIkm = consume(cipherbird_random_bytes(32))!
let (d1Pub, _) = keypair(blsIkm.withUnsafeBufferPointer { cipherbird_bls_keygen_from_ikm($0.baseAddress, $0.count) })
let (d2Pub, _) = keypair(blsIkm.withUnsafeBufferPointer { cipherbird_bls_keygen_from_ikm($0.baseAddress, $0.count) })
print("bls keygen-from-ikm deterministic: \(d1Pub == d2Pub)")

print("Swift demo OK")
