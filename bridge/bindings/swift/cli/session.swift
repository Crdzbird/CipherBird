// CryptoLib Swift — Session: post-quantum forward-secret ratchet (hybrid KEM
// Double Ratchet). A live channel with forward secrecy + post-compromise
// security, all post-quantum. Build the smoke with the Makefile target
// `swift-session`.
import Foundation

enum SessionError: Error { case failed(String) }

private func sessConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw SessionError.failed(m) }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}
private func withPtrs<R>(_ datas: [[UInt8]?], _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

/// A post-quantum forward-secret ratchet channel. Stateful; freed on deinit.
final class Session {
    private var handle: UnsafeMutableRawPointer?
    private init(_ h: UnsafeMutableRawPointer?) { handle = h }
    deinit { close() }

    /// Responder: generate a prekey (hybrid-KEM keypair). Publish `public`.
    static func generatePrekey() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = cryptolib_session_generate_prekey()
        let pub = Array(UnsafeBufferPointer(start: kp.public_key.data, count: kp.public_key.len))
        let sec = Array(UnsafeBufferPointer(start: kp.secret_key.data, count: kp.secret_key.len))
        cryptolib_keypair_free(&kp)
        return (pub, sec)
    }

    /// Initiator: start a session to the responder's prekey public key.
    static func initiate(_ prekeyPublic: [UInt8]) throws -> Session {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = withPtrs([prekeyPublic]) { p in cryptolib_session_initiate(p[0].0, p[0].1, &err) }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw SessionError.failed(m) }
        guard h != nil else { throw SessionError.failed("session initiate failed") }
        return Session(h)
    }

    /// The handshake message to send to the responder (accept).
    func handshake() throws -> [UInt8] { try sessConsume(cryptolib_session_handshake(handle)) }

    /// Responder: accept a handshake with your prekey (public + secret).
    static func accept(handshake: [UInt8], prekeyPublic: [UInt8], prekeySecret: [UInt8]) throws -> Session {
        var err: UnsafeMutablePointer<CChar>? = nil
        let h = withPtrs([handshake, prekeyPublic, prekeySecret]) { p in
            cryptolib_session_accept(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, &err)
        }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw SessionError.failed(m) }
        guard h != nil else { throw SessionError.failed("session accept failed") }
        return Session(h)
    }

    func encrypt(_ plaintext: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, aad]) { p in
            try sessConsume(cryptolib_session_encrypt(handle, p[0].0, p[0].1, p[1].0, p[1].1))
        }
    }
    func decrypt(_ message: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([message, aad]) { p in
            try sessConsume(cryptolib_session_decrypt(handle, p[0].0, p[0].1, p[1].0, p[1].1))
        }
    }
    func close() { if let h = handle { cryptolib_session_free(h); handle = nil } }
}

// ── smoke (compiled/run by `make swift-session`) ─────────────────────────────
guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — Session ratchet (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    let pre = Session.generatePrekey()
    let alice = try Session.initiate(pre.publicKey)
    let hs = try alice.handshake()
    let bob = try Session.accept(handshake: hs, prekeyPublic: pre.publicKey, prekeySecret: pre.secretKey)

    let o0 = try bob.decrypt(try alice.encrypt(Array("hello bob".utf8)))
    ck("A→B round-trip", o0 == Array("hello bob".utf8))
    let o1 = try alice.decrypt(try bob.encrypt(Array("hi alice".utf8)))
    ck("B→A round-trip (ratchet turn)", o1 == Array("hi alice".utf8))

    let m2 = try alice.encrypt(Array("secret".utf8))
    var bad = m2; bad[bad.count - 1] ^= 1
    var rejected = false
    do { _ = try bob.decrypt(bad) } catch { rejected = true }
    ck("tampered message rejected", rejected)
    let o2 = try bob.decrypt(m2)
    ck("transactional: real message still opens", o2 == Array("secret".utf8))
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — session \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
