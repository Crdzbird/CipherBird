// CryptoLib Swift — HPKE (RFC 9180) hybrid public-key encryption. KEM is
// DHKEM(X25519, HKDF-SHA256); an envelope sealed here opens in any conformant
// HPKE implementation (TLS ECH, MLS, Oblivious HTTP). Build the smoke with the
// Makefile target `swift-hpke`.
import Foundation

enum HpkeError: Error { case failed(String) }

private func hpkeConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw HpkeError.failed(m) }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}

// Marshal a list of optional byte arrays into (pointer, length) pairs.
private func withPtrs<R>(_ datas: [[UInt8]?], _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

private func kpBytes(_ kp: inout CryptoKeyPair) -> (publicKey: [UInt8], secretKey: [UInt8]) {
    let pub = kp.public_key.data != nil ? Array(UnsafeBufferPointer(start: kp.public_key.data, count: kp.public_key.len)) : []
    let sec = kp.secret_key.data != nil ? Array(UnsafeBufferPointer(start: kp.secret_key.data, count: kp.secret_key.len)) : []
    cryptolib_keypair_free(&kp)
    return (pub, sec)
}

/// An established one-directional HPKE context. Stateful; freed on deinit.
final class HpkeContext {
    private var handle: UnsafeMutableRawPointer?
    fileprivate init(_ h: UnsafeMutableRawPointer?) { handle = h }
    deinit { close() }

    func seal(_ plaintext: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([aad, plaintext]) { p in try hpkeConsume(cryptolib_hpke_seal(handle, p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    func open(_ ciphertext: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([aad, ciphertext]) { p in try hpkeConsume(cryptolib_hpke_open(handle, p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    func export(_ exporterContext: [UInt8], _ length: Int) throws -> [UInt8] {
        try withPtrs([exporterContext]) { p in try hpkeConsume(cryptolib_hpke_export(handle, p[0].0, p[0].1, length)) }
    }
    func close() { if let h = handle { cryptolib_hpke_context_free(h); handle = nil } }
}

/// HPKE(RFC 9180). Suite is chosen with the Kdf/Aead/Mode selector constants.
enum Hpke {
    enum Kdf { static let sha256: Int32 = 1; static let sha512: Int32 = 3 }
    enum Aead {
        static let aes128Gcm: Int32 = 1
        static let aes256Gcm: Int32 = 2
        static let chaCha20Poly1305: Int32 = 3
        static let exportOnly: Int32 = 0xFFFF
    }
    enum Mode { static let base: Int32 = 0; static let psk: Int32 = 1; static let auth: Int32 = 2; static let authPsk: Int32 = 3 }

    struct Sender { let enc: [UInt8]; let context: HpkeContext }

    static func keygen() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = cryptolib_hpke_keygen(); return kpBytes(&kp)
    }
    static func deriveKeyPair(_ ikm: [UInt8]) -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = withPtrs([ikm]) { p in cryptolib_hpke_derive_keypair(p[0].0, p[0].1) }
        return kpBytes(&kp)
    }

    static func setupS(kdf: Int32, aead: Int32, mode: Int32, recipientPublic: [UInt8], info: [UInt8],
                       psk: [UInt8]? = nil, pskId: [UInt8]? = nil, senderSecret: [UInt8]? = nil) throws -> Sender {
        var enc = CryptoBuffer()
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = withPtrs([recipientPublic, info, psk, pskId, senderSecret]) { p in
            cryptolib_hpke_setup_s(kdf, aead, mode, p[0].0, p[0].1, p[1].0, p[1].1,
                p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1, &enc, &err)
        }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw HpkeError.failed(m) }
        guard h != nil else { throw HpkeError.failed("hpke setup_s failed") }
        let encBytes = enc.data != nil ? Array(UnsafeBufferPointer(start: enc.data, count: enc.len)) : []
        cryptolib_buffer_free(&enc)
        return Sender(enc: encBytes, context: HpkeContext(h))
    }

    static func setupR(kdf: Int32, aead: Int32, mode: Int32, enc: [UInt8], recipientSecret: [UInt8], info: [UInt8],
                       psk: [UInt8]? = nil, pskId: [UInt8]? = nil, senderPublic: [UInt8]? = nil) throws -> HpkeContext {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = withPtrs([enc, recipientSecret, info, psk, pskId, senderPublic]) { p in
            cryptolib_hpke_setup_r(kdf, aead, mode, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                p[3].0, p[3].1, p[4].0, p[4].1, p[5].0, p[5].1, &err)
        }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw HpkeError.failed(m) }
        guard h != nil else { throw HpkeError.failed("hpke setup_r failed") }
        return HpkeContext(h)
    }

    static func sealBase(kdf: Int32, aead: Int32, recipientPublic: [UInt8], info: [UInt8],
                         plaintext: [UInt8], aad: [UInt8]? = nil) throws -> (enc: [UInt8], ct: [UInt8]) {
        let s = try setupS(kdf: kdf, aead: aead, mode: Mode.base, recipientPublic: recipientPublic, info: info)
        defer { s.context.close() }
        return (s.enc, try s.context.seal(plaintext, aad: aad))
    }
    static func openBase(kdf: Int32, aead: Int32, enc: [UInt8], recipientSecret: [UInt8], info: [UInt8],
                         ciphertext: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        let r = try setupR(kdf: kdf, aead: aead, mode: Mode.base, enc: enc, recipientSecret: recipientSecret, info: info)
        defer { r.close() }
        return try r.open(ciphertext, aad: aad)
    }
}

// ── smoke (compiled/run by `make swift-hpke`) ────────────────────────────────
func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — HPKE (RFC 9180) (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    // RFC 9180 §A.2 (base, ChaCha20Poly1305, HKDF-SHA256)
    let skRm = hexToBytes("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
    let pkRm = hexToBytes("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
    let ikmR = hexToBytes("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df")
    let enc  = hexToBytes("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
    let info = hexToBytes("4f6465206f6e2061204772656369616e2055726e")
    let pt   = hexToBytes("4265617574792069732074727574682c20747275746820626561757479")
    let aad0 = hexToBytes("436f756e742d30")
    let ct0  = hexToBytes("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")
    let exp0 = hexToBytes("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e")

    let dk = Hpke.deriveKeyPair(ikmR)
    ck("KAT DeriveKeyPair", dk.secretKey == skRm && dk.publicKey == pkRm)

    let r = try Hpke.setupR(kdf: Hpke.Kdf.sha256, aead: Hpke.Aead.chaCha20Poly1305, mode: Hpke.Mode.base,
                            enc: enc, recipientSecret: skRm, info: info)
    ck("KAT open ct[0]", try r.open(ct0, aad: aad0) == pt)
    ck("KAT export", try r.export([], 32) == exp0)
    r.close()

    // e2e base + AES-256-GCM single-shot + tamper
    let bob = Hpke.keygen()
    let sealed = try Hpke.sealBase(kdf: Hpke.Kdf.sha256, aead: Hpke.Aead.aes256Gcm,
                                   recipientPublic: bob.publicKey, info: info, plaintext: pt, aad: aad0)
    let out = try Hpke.openBase(kdf: Hpke.Kdf.sha256, aead: Hpke.Aead.aes256Gcm,
                                enc: sealed.enc, recipientSecret: bob.secretKey, info: info, ciphertext: sealed.ct, aad: aad0)
    ck("e2e base AES-256 round trip", out == pt)
    var bad = sealed.ct; bad[bad.count - 1] ^= 1
    var rejected = false
    do { _ = try Hpke.openBase(kdf: Hpke.Kdf.sha256, aead: Hpke.Aead.aes256Gcm,
                               enc: sealed.enc, recipientSecret: bob.secretKey, info: info, ciphertext: bad, aad: aad0) }
    catch { rejected = true }
    ck("tampered ciphertext rejected", rejected)

    // Auth mode, HKDF-SHA512, multi-message + export symmetry
    let alice = Hpke.keygen()
    let s = try Hpke.setupS(kdf: Hpke.Kdf.sha512, aead: Hpke.Aead.chaCha20Poly1305, mode: Hpke.Mode.auth,
                            recipientPublic: bob.publicKey, info: info, senderSecret: alice.secretKey)
    let rr = try Hpke.setupR(kdf: Hpke.Kdf.sha512, aead: Hpke.Aead.chaCha20Poly1305, mode: Hpke.Mode.auth,
                             enc: s.enc, recipientSecret: bob.secretKey, info: info, senderPublic: alice.publicKey)
    var allok = true
    for i in 0..<4 {
        let m = Array("msg\(i)".utf8)
        if try rr.open(try s.context.seal(m)) != m { allok = false }
    }
    ck("auth multi-message round trip", allok)
    let lab = Array("lab".utf8)
    ck("exporter secrets match", try s.context.export(lab, 32) == (try rr.export(lab, 32)))
    s.context.close(); rr.close()
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — HPKE \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
