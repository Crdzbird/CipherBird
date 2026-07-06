// CryptoLib Swift — Recipes: composition in practice.
//
// Real-world flows that snap primitives together (no new crypto, just wiring),
// calling the C ABI directly through the bridging header. Build (see the
// top-level Makefile target `swift-recipes`):
//   swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/recipes.swift \
//          -L build/release -lcryptolib_c -Xlinker -rpath -Xlinker build/release -o build/swift_recipes
//
// (Shamir threshold splitting is C++-only — not in the C ABI — so this mirrors
// the other five recipes; see example/recipes.cpp for all six.)
import Foundation

func consume(_ r: CryptoBufferResult) -> [UInt8] {
    guard let d = r.buf.data else { if let e = r.error { cryptolib_str_free(e) }; return [] }
    let out = Array(UnsafeBufferPointer(start: d, count: r.buf.len))
    var b = r.buf; cryptolib_buffer_free(&b)
    return out
}
func take(_ b: CryptoBuffer) -> [UInt8] {
    guard let d = b.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: b.len))
}
extension Array where Element == UInt8 {
    func withC<R>(_ body: ((UnsafePointer<UInt8>?, Int)) -> R) -> R {
        withUnsafeBufferPointer { body(($0.baseAddress, $0.count)) }
    }
}
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

var pass = 0, fail = 0
func check(_ name: String, _ ok: Bool) {
    print("   \(ok ? "✓" : "✗") \(name)"); ok ? (pass += 1) : (fail += 1)
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — Recipes (Swift)")
let aad = Array("recipe/v1".utf8)

// 1. File-as-key vault: deterministic media entropy → master → MolecularVault.
print("\n1. File-as-key vault  (media entropy → MolecularVault)")
do {
    let tmp = NSTemporaryDirectory() + "cryptolib_swift_recipe_key.bin"
    var bytes = [UInt8](); for i in 0..<4096 { bytes.append(UInt8((i * 37 + 11) & 0xff)) }
    FileManager.default.createFile(atPath: tmp, contents: Data(bytes))
    defer { try? FileManager.default.removeItem(atPath: tmp) }

    func masterFromFile() -> [UInt8] {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = tmp.withCString { cryptolib_entropy_from_file_deterministic($0, &err) }
        let dk = cryptolib_entropy_derive_all(h)
        let m = take(dk.vault_master_key)
        var dkv = dk; cryptolib_derived_keys_free(&dkv)
        cryptolib_entropy_free(h)
        return m
    }
    let master = masterFromFile()
    let env = Array("launch codes".utf8).withC { pt in master.withC { k in aad.withC { a in
        consume(cryptolib_molecular_seal_with_key(pt.0, pt.1, k.0, k.1, a.0, a.1)) } } }
    let master2 = masterFromFile() // re-derive on the "other side"
    let opened = env.withC { e in master2.withC { k in aad.withC { a in
        consume(cryptolib_molecular_open_with_key(e.0, e.1, k.0, k.1, a.0, a.1)) } } }
    check("same file re-derives the key and opens the vault", opened == Array("launch codes".utf8))
}

// 2. Post-quantum message: hybrid KEM shared secret → MolecularVault.
print("\n2. Post-quantum message  (hybrid KEM → MolecularVault)")
do {
    var kp = cryptolib_hybrid_kem_keygen()
    let pub = take(kp.public_key), sec = take(kp.secret_key); cryptolib_keypair_free(&kp)
    var err: UnsafeMutablePointer<CChar>? = nil
    let enc = pub.withC { cryptolib_hybrid_kem_encapsulate($0.0, $0.1, &err) }
    let ss = take(enc.shared_secret), ct = take(enc.ciphertext)
    let env = Array("see you at dawn".utf8).withC { pt in ss.withC { k in aad.withC { a in
        consume(cryptolib_molecular_seal_with_key(pt.0, pt.1, k.0, k.1, a.0, a.1)) } } }
    let ss2 = ct.withC { c in sec.withC { s in consume(cryptolib_hybrid_kem_decapsulate(c.0, c.1, s.0, s.1)) } }
    let opened = env.withC { e in ss2.withC { k in aad.withC { a in
        consume(cryptolib_molecular_open_with_key(e.0, e.1, k.0, k.1, a.0, a.1)) } } }
    check("hybrid-KEM secret opens the PQ-sealed message", opened == Array("see you at dawn".utf8))
}

// 3. Sign-then-seal: hybrid signature carried inside a MolecularVault.
print("\n3. Sign-then-seal  (hybrid signature inside MolecularVault)")
do {
    var kp = cryptolib_hybrid_sig_keygen()
    let pub = take(kp.public_key), sec = take(kp.secret_key); cryptolib_keypair_free(&kp)
    let msg = Array("transfer 100 to acct #42".utf8)
    let sig = msg.withC { m in sec.withC { s in consume(cryptolib_hybrid_sig_sign(m.0, m.1, s.0, s.1)) } }
    let bundle = msg + sig
    let env = bundle.withC { pt in aad.withC { a in
        consume(cryptolib_molecular_seal(pt.0, pt.1, "outer passphrase", a.0, a.1, 2, 1 << 20)) } }
    let opened = env.withC { e in aad.withC { a in
        consume(cryptolib_molecular_open(e.0, e.1, "outer passphrase", a.0, a.1)) } }
    let gotMsg = Array(opened[0..<msg.count]), gotSig = Array(opened[msg.count...])
    let ok = gotMsg.withC { m in gotSig.withC { g in pub.withC { p in
        cryptolib_hybrid_sig_verify(m.0, m.1, g.0, g.1, p.0, p.1) } } } == 1
    check("opened → both Ed25519 and ML-DSA signatures verify", ok && gotMsg == msg)
}

// 4. EVM wallet: secp256k1 → Keccak address → sign tx digest → ecrecover.
print("\n4. EVM wallet  (secp256k1 → Keccak address → sign → ecrecover)")
do {
    var w = cryptolib_secp256k1_keygen()
    let pub = take(w.public_key), sec = take(w.secret_key); cryptolib_keypair_free(&w)
    let addrHash = Array(pub[1...]).withC { consume(cryptolib_keccak256($0.0, $0.1)) }
    print("      address 0x\(hex(Array(addrHash[12..<32])))")
    let digest = Array("transfer 1 ETH".utf8).withC { consume(cryptolib_keccak256($0.0, $0.1)) }
    let sig = digest.withC { d in sec.withC { s in consume(cryptolib_secp256k1_sign(d.0, s.0, s.1)) } }
    let recovered = digest.withC { d in sig.withC { s in consume(cryptolib_secp256k1_recover(d.0, s.0)) } }
    check("ecrecover returns the signer public key (65B, v included)", sig.count == 65 && recovered == pub)
}

// 5. Keyring-guarded vault: master under device + passphrase → MolecularVault.
print("\n5. Keyring-guarded vault  (Keyring unlock → MolecularVault key)")
do {
    let deviceKey = consume(cryptolib_random_bytes(32))
    let kr = cryptolib_keyring_create()
    _ = deviceKey.withC { cryptolib_keyring_add_device_slot(kr, $0.0, $0.1) }
    _ = cryptolib_keyring_add_passphrase_slot(kr, "cross-device pass", 0)
    let blob = consume(cryptolib_keyring_serialise(kr))
    var err: UnsafeMutablePointer<CChar>? = nil
    let kr2 = blob.withC { cryptolib_keyring_deserialise($0.0, $0.1, &err) }
    let master = deviceKey.withC { consume(cryptolib_keyring_unlock_with_device(kr2, $0.0, $0.1)) }
    let env = Array("root secret".utf8).withC { pt in master.withC { k in aad.withC { a in
        consume(cryptolib_molecular_seal_with_key(pt.0, pt.1, k.0, k.1, a.0, a.1)) } } }
    let master2 = consume(cryptolib_keyring_unlock_with_passphrase(kr2, "cross-device pass"))
    let opened = env.withC { e in master2.withC { k in aad.withC { a in
        consume(cryptolib_molecular_open_with_key(e.0, e.1, k.0, k.1, a.0, a.1)) } } }
    check("either keyring factor unlocks the same MolecularVault master",
          opened == Array("root secret".utf8) && master == master2)
    cryptolib_keyring_free(kr); cryptolib_keyring_free(kr2)
}

print("\n\(pass) passed, \(fail) failed — recipes \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
