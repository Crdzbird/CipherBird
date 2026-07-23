// CryptoLib Swift — ECVRF (RFC 9381) verifiable random function
// (ECVRF-EDWARDS25519-SHA512-TAI). A public-key PRF: prove(sk, alpha) yields a
// unique, unpredictable 64-byte output plus an 80-byte proof anyone can verify
// with the public key. Build the smoke with the Makefile target `swift-ecvrf`.
import Foundation

enum EcvrfError: Error { case failed(String) }

private func ecvrfConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw EcvrfError.failed(m) }
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

/// ECVRF (RFC 9381). All operations are stateless.
enum Ecvrf {
    static func keygen() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = cryptolib_ecvrf_keygen()
        let pub = kp.public_key.data != nil ? Array(UnsafeBufferPointer(start: kp.public_key.data, count: kp.public_key.len)) : []
        let sec = kp.secret_key.data != nil ? Array(UnsafeBufferPointer(start: kp.secret_key.data, count: kp.secret_key.len)) : []
        cryptolib_keypair_free(&kp)
        return (pub, sec)
    }
    static func publicKey(_ sk: [UInt8]) throws -> [UInt8] {
        try withPtrs([sk]) { p in try ecvrfConsume(cryptolib_ecvrf_public_key(p[0].0, p[0].1)) }
    }
    static func prove(_ sk: [UInt8], _ alpha: [UInt8]) throws -> [UInt8] {
        try withPtrs([sk, alpha]) { p in try ecvrfConsume(cryptolib_ecvrf_prove(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    static func proofToHash(_ pi: [UInt8]) throws -> [UInt8] {
        try withPtrs([pi]) { p in try ecvrfConsume(cryptolib_ecvrf_proof_to_hash(p[0].0, p[0].1)) }
    }
    /// Returns the 64-byte beta on success; throws if the proof is invalid.
    static func verify(_ pk: [UInt8], _ alpha: [UInt8], _ pi: [UInt8]) throws -> [UInt8] {
        try withPtrs([pk, alpha, pi]) { p in
            try ecvrfConsume(cryptolib_ecvrf_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }
}

// ── smoke (compiled/run by `make swift-ecvrf`) ───────────────────────────────
func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — ECVRF (RFC 9381) (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    // RFC 9381 Appendix B.3, Example 18 (alpha = "af82")
    let sk = hexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    let pk = hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
    let alpha = hexToBytes("af82")
    let PI = hexToBytes("9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e")
    let BETA = hexToBytes("645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f")

    ck("KAT public key", try Ecvrf.publicKey(sk) == pk)
    let pi = try Ecvrf.prove(sk, alpha)
    ck("KAT prove", pi == PI)
    ck("KAT proof_to_hash", try Ecvrf.proofToHash(pi) == BETA)
    ck("KAT verify", try Ecvrf.verify(pk, alpha, pi) == BETA)

    var bad = pi; bad[70] ^= 1
    var rejected = false
    do { _ = try Ecvrf.verify(pk, alpha, bad) } catch { rejected = true }
    ck("tampered proof rejected", rejected)

    // e2e fresh key
    let kp = Ecvrf.keygen()
    let m = Array("randomness beacon".utf8)
    let p2 = try Ecvrf.prove(kp.secretKey, m)
    ck("e2e verify", try Ecvrf.verify(kp.publicKey, m, p2).count == 64)
    // deterministic
    ck("deterministic", try Ecvrf.prove(kp.secretKey, m) == p2)
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — ECVRF \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
