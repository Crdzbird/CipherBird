// CipherBird Swift — FULL showcase of every capability family via the C ABI.
//
// Build/run (see Makefile target `swift-showcase`):
//   swiftc -import-objc-header ../../../cipherbird_c.h showcase.swift \
//     -L ../../../../build/release -lcipherbird_c -Xlinker -rpath -Xlinker ../../../../build/release \
//     -o showcase && ./showcase

import Foundation

// ── Helpers ───────────────────────────────────────────────────────────────────
func consume(_ r: CryptoBufferResult) -> [UInt8] {
    guard let d = r.buf.data else { if let e = r.error { cipherbird_str_free(e) }; return [] }
    let out = Array(UnsafeBufferPointer(start: d, count: r.buf.len))
    var b = r.buf; cipherbird_buffer_free(&b)
    return out
}
func take(_ b: CryptoBuffer) -> [UInt8] {
    guard let d = b.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: b.len))
}
func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
func head(_ b: [UInt8], _ n: Int = 8) -> String { hex(Array(b.prefix(n))) + "…" }
func check(_ label: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(label)") }
extension Array where Element == UInt8 {
    // Passes a single (ptr, count) tuple so call sites use $0.0 / $0.1 (works when nested).
    func withC<R>(_ body: ((UnsafePointer<UInt8>?, Int)) -> R) -> R {
        withUnsafeBufferPointer { body(($0.baseAddress, $0.count)) }
    }
}

guard cipherbird_init() == 0 else { fatalError("init failed") }
print("CipherBird \(String(cString: cipherbird_version())) — Swift full showcase\n")

// ── Hashing ───────────────────────────────────────────────────────────────────
print("HASHING")
let abc: [UInt8] = Array("abc".utf8)
let sha = abc.withC { consume(cipherbird_sha256($0.0, $0.1)) }
check("SHA-256(abc) KAT", hex(sha) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
print("    SHA-512   \(head(abc.withC { consume(cipherbird_sha512($0.0, $0.1)) }))")
print("    BLAKE2b   \(head(abc.withC { consume(cipherbird_blake2b($0.0, $0.1, nil, 0)) }))")
print("    BLAKE3    \(head(abc.withC { consume(cipherbird_blake3($0.0, $0.1, 32)) }))")
let mkey = consume(cipherbird_sym_keygen())
let mac = abc.withC { m in mkey.withC { k in consume(cipherbird_hmac_sha256(m.0, m.1, k.0, k.1)) } }
check("HMAC-SHA256 verify", abc.withC { m in mkey.withC { k in
    mac.withC { mc in cipherbird_hmac_sha256_verify(m.0, m.1, mc.0, mc.1, k.0, k.1) } } } == 1)
let ikm = consume(cipherbird_random_bytes(32))
let okm = ikm.withC { i in consume(cipherbird_hkdf_derive(i.0, i.1, nil, 0, nil, 0, 32)) }
check("HKDF-SHA256 derive (32B)", okm.count == 32)
let phc = consume(cipherbird_argon2id_hash_str("hunter2", 2, 67108864))
let phcStr = String(decoding: phc, as: UTF8.self)
check("Argon2id PHC verify", cipherbird_argon2id_verify_str("hunter2", phcStr) == 1)

// ── Symmetric AEAD ──────────────────────────────────────────────────────────
print("\nSYMMETRIC")
let symKey = consume(cipherbird_sym_keygen())
let pt: [UInt8] = Array("secret payload".utf8)
let xct = pt.withC { p in symKey.withC { k in consume(cipherbird_xchacha20_encrypt(p.0, p.1, k.0, k.1, nil, 0)) } }
let xpt = xct.withC { c in symKey.withC { k in consume(cipherbird_xchacha20_decrypt(c.0, c.1, k.0, k.1, nil, 0)) } }
check("XChaCha20-Poly1305 round-trip", xpt == pt)
if cipherbird_aes256gcm_available() == 1 {
    let act = pt.withC { p in symKey.withC { k in consume(cipherbird_aes256gcm_encrypt(p.0, p.1, k.0, k.1, nil, 0)) } }
    let apt = act.withC { c in symKey.withC { k in consume(cipherbird_aes256gcm_decrypt(c.0, c.1, k.0, k.1, nil, 0)) } }
    check("AES-256-GCM round-trip", apt == pt)
} else { print("    AES-256-GCM unavailable on this CPU") }
// SecretStream
let ssKey = consume(cipherbird_sym_keygen())
let enc = ssKey.withC { cipherbird_stream_enc_create($0.0) }
let header = consume(cipherbird_stream_enc_header(enc))
let c1 = Array("chunk-1".utf8).withC { consume(cipherbird_stream_enc_push(enc, $0.0, $0.1, 0)) }
let c2 = Array("chunk-2".utf8).withC { consume(cipherbird_stream_enc_push(enc, $0.0, $0.1, 3)) } // TAG_FINAL
let dec = ssKey.withC { sk in header.withC { h in cipherbird_stream_dec_create(sk.0, h.0) } }
var tag: UInt8 = 0
let p1 = c1.withC { consume(cipherbird_stream_dec_pull(dec, $0.0, $0.1, &tag)) }
let p2 = c2.withC { consume(cipherbird_stream_dec_pull(dec, $0.0, $0.1, &tag)) }
check("SecretStream chunked round-trip", String(decoding: p1+p2, as: UTF8.self) == "chunk-1chunk-2")
cipherbird_stream_enc_free(enc); cipherbird_stream_dec_free(dec)

// ── Asymmetric ──────────────────────────────────────────────────────────────
print("\nASYMMETRIC")
var ed = cipherbird_ed25519_keygen(); let edPub = take(ed.public_key); let edSec = take(ed.secret_key); cipherbird_keypair_free(&ed)
let sig = abc.withC { m in edSec.withC { s in consume(cipherbird_ed25519_sign(m.0, m.1, s.0, s.1)) } }
check("Ed25519 sign/verify", abc.withC { m in sig.withC { sg in edPub.withC { pk in
    cipherbird_ed25519_verify(m.0, m.1, sg.0, sg.1, pk.0, pk.1) } } } == 1)
var xa = cipherbird_x25519_keygen(); var xb = cipherbird_x25519_keygen()
let xaPub = take(xa.public_key); let xaSec = take(xa.secret_key)
let xbPub = take(xb.public_key); let xbSec = take(xb.secret_key)
cipherbird_keypair_free(&xa); cipherbird_keypair_free(&xb)
let ss1 = xaSec.withC { s in xbPub.withC { p in consume(cipherbird_x25519_shared_secret(s.0, s.1, p.0, p.1)) } }
let ss2 = xbSec.withC { s in xaPub.withC { p in consume(cipherbird_x25519_shared_secret(s.0, s.1, p.0, p.1)) } }
check("X25519 ECDH agreement", ss1 == ss2)
var box = cipherbird_box_keygen(); let boxPub = take(box.public_key); let boxSec = take(box.secret_key); cipherbird_keypair_free(&box)
var sndr = cipherbird_box_keygen(); let sPub = take(sndr.public_key); let sSec = take(sndr.secret_key); cipherbird_keypair_free(&sndr)
let bct = pt.withC { p in boxPub.withC { rp in sSec.withC { ss in consume(cipherbird_box_encrypt(p.0, p.1, rp.0, rp.1, ss.0, ss.1)) } } }
let bpt = bct.withC { c in sPub.withC { sp in boxSec.withC { rs in consume(cipherbird_box_decrypt(c.0, c.1, sp.0, sp.1, rs.0, rs.1)) } } }
check("Box authenticated round-trip", bpt == pt)
let sealed = pt.withC { p in boxPub.withC { rp in consume(cipherbird_sealedbox_encrypt(p.0, p.1, rp.0, rp.1)) } }
let unsealed = sealed.withC { c in boxPub.withC { rp in boxSec.withC { rs in consume(cipherbird_sealedbox_decrypt(c.0, c.1, rp.0, rp.1, rs.0, rs.1)) } } }
check("SealedBox anonymous round-trip", unsealed == pt)

// ── Vaults ──────────────────────────────────────────────────────────────────
print("\nVAULTS")
let vkey = consume(cipherbird_random_bytes(32))
let vault = vkey.withC { cipherbird_vault_create($0.0, $0.1, 0) }
var verr: UnsafeMutablePointer<CChar>? = nil
var pkt = pt.withC { cipherbird_vault_seal(vault, $0.0, $0.1, "ctx", &verr) }
let vopen = consume(cipherbird_vault_open(vault, &pkt, "ctx"))
check("SecureVault 4-layer round-trip", vopen == pt)
cipherbird_packet_free(&pkt); cipherbird_vault_free(vault)
var alice = cipherbird_asym_bundle_generate(); var bob = cipherbird_asym_bundle_generate()
let bobBoxPub = take(bob.box_public); let aliceSignPub = take(alice.sign_public)
var aerr: UnsafeMutablePointer<CChar>? = nil
var apkt = withUnsafePointer(to: &alice) { ap in
    bobBoxPub.withC { bp in pt.withC { p in cipherbird_asym_vault_seal(ap, bp.0, bp.1, p.0, p.1, "ctx", &aerr) } } }
let aopen = withUnsafePointer(to: &bob) { bp in aliceSignPub.withC { sp in
    cipherbird_asym_vault_open(&apkt, bp, sp.0, sp.1, "ctx") } }
check("AsymmetricVault (Alice→Bob) round-trip", consume(aopen) == pt)
cipherbird_packet_free(&apkt); cipherbird_bundle_free(&alice); cipherbird_bundle_free(&bob)

// ── Post-quantum (FIPS 203/204/205) ─────────────────────────────────────────
print("\nPOST-QUANTUM")
var kem = cipherbird_ml_kem_keygen(1); let kemPub = take(kem.public_key); let kemSec = take(kem.secret_key); cipherbird_keypair_free(&kem)
var kerr: UnsafeMutablePointer<CChar>? = nil
let encaps = kemPub.withC { cipherbird_ml_kem_encapsulate($0.0, $0.1, 1, &kerr) }
let ssEnc = take(encaps.shared_secret); let kemCt = take(encaps.ciphertext)
let ssDec = kemCt.withC { c in kemSec.withC { s in consume(cipherbird_ml_kem_decapsulate(c.0, c.1, s.0, s.1, 1)) } }
check("ML-KEM-768 encaps/decaps shared secret", ssEnc == ssDec && ssEnc.count == 32)
var er = encaps; cipherbird_kem_encaps_free(&er)
var hkem = cipherbird_hybrid_kem_keygen(); let hPub = take(hkem.public_key); let hSec = take(hkem.secret_key); cipherbird_keypair_free(&hkem)
var herr: UnsafeMutablePointer<CChar>? = nil
let hEncaps = hPub.withC { cipherbird_hybrid_kem_encapsulate($0.0, $0.1, &herr) }
let hSsEnc = take(hEncaps.shared_secret); let hCt = take(hEncaps.ciphertext)
let hSsDec = hCt.withC { c in hSec.withC { s in consume(cipherbird_hybrid_kem_decapsulate(c.0, c.1, s.0, s.1)) } }
check("Hybrid X25519+ML-KEM-768 encaps/decaps", hSsEnc == hSsDec && hSsEnc.count == 32)
var her = hEncaps; cipherbird_kem_encaps_free(&her)
var dsa = cipherbird_ml_dsa_keygen(1); let dsaPub = take(dsa.public_key); let dsaSec = take(dsa.secret_key); cipherbird_keypair_free(&dsa)
let dsaSig = abc.withC { m in dsaSec.withC { s in consume(cipherbird_ml_dsa_sign(m.0, m.1, s.0, s.1, 1)) } }
check("ML-DSA-65 sign/verify", abc.withC { m in dsaSig.withC { sg in dsaPub.withC { pk in
    cipherbird_ml_dsa_verify(m.0, m.1, sg.0, sg.1, pk.0, pk.1, 1) } } } == 1)
var slh = cipherbird_slh_dsa_keygen(1, 0); let slhPub = take(slh.public_key); let slhSec = take(slh.secret_key); cipherbird_keypair_free(&slh)
let slhSig = abc.withC { m in slhSec.withC { s in consume(cipherbird_slh_dsa_sign(m.0, m.1, s.0, s.1, 1, 0)) } }
check("SLH-DSA-128f sign/verify", abc.withC { m in slhSig.withC { sg in slhPub.withC { pk in
    cipherbird_slh_dsa_verify(m.0, m.1, sg.0, sg.1, pk.0, pk.1, 1, 0) } } } == 1)

// ── BLS12-381 ───────────────────────────────────────────────────────────────
print("\nBLS12-381")
var bls = cipherbird_bls_keygen(); let blsPub = take(bls.public_key); let blsSec = take(bls.secret_key); cipherbird_keypair_free(&bls)
let blsSig = abc.withC { m in blsSec.withC { s in consume(cipherbird_bls_sign(m.0, m.1, s.0, s.1)) } }
check("BLS sign/verify", abc.withC { m in blsSig.withC { sg in blsPub.withC { pk in
    cipherbird_bls_verify(m.0, m.1, sg.0, sg.1, pk.0, pk.1) } } } == 1)

// ── Keyring (envelope / key-slots) ──────────────────────────────────────────
print("\nKEYRING")
let factor = consume(cipherbird_random_bytes(32))
let kr = cipherbird_keyring_create()
factor.withC { _ = cipherbird_keyring_add_device_slot(kr, $0.0, $0.1) }
_ = cipherbird_keyring_add_passphrase_slot(kr, "cross-device pass", 0)
let blob = consume(cipherbird_keyring_serialise(kr))
var krErr: UnsafeMutablePointer<CChar>? = nil
let kr2 = blob.withC { cipherbird_keyring_deserialise($0.0, $0.1, &krErr) }
let mDev = factor.withC { consume(cipherbird_keyring_unlock_with_device(kr2, $0.0, $0.1)) }
let mPass = consume(cipherbird_keyring_unlock_with_passphrase(kr2, "cross-device pass"))
check("Keyring device==passphrase master (\(cipherbird_keyring_slot_count(kr)) slots)", mDev == mPass && mDev.count == 32)
cipherbird_keyring_free(kr); cipherbird_keyring_free(kr2)

print("\nSwift showcase OK")
