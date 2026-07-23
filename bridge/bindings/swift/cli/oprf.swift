// CryptoLib Swift — OPRF (RFC 9497, ristretto255-SHA-512, base mode). A two-party
// PRF: the client blinds its input, the server evaluates under its key without
// seeing it, the client unblinds to the PRF output. Build the smoke with the
// Makefile target `swift-oprf`.
import Foundation

enum OprfError: Error { case failed(String) }

private func oprfConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw OprfError.failed(m) }
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

/// OPRF (RFC 9497). Stateless.
enum Oprf {
    struct BlindResult { let blind: [UInt8]; let blindedElement: [UInt8] }

    static func deriveKeyPair(seed: [UInt8], info: [UInt8]? = nil) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = withPtrs([seed, info]) { p in cryptolib_oprf_derive_keypair(p[0].0, p[0].1, p[1].0, p[1].1) }
        let pub = kp.public_key.data != nil ? Array(UnsafeBufferPointer(start: kp.public_key.data, count: kp.public_key.len)) : []
        let sec = kp.secret_key.data != nil ? Array(UnsafeBufferPointer(start: kp.secret_key.data, count: kp.secret_key.len)) : []
        cryptolib_keypair_free(&kp)
        if pub.isEmpty { throw OprfError.failed("oprf derive_keypair failed") }
        return (pub, sec)
    }

    private static func blindOut(_ c0: CryptoOprfBlind) throws -> BlindResult {
        var c = c0
        defer { cryptolib_oprf_blind_free(&c) }
        if let e = c.error { throw OprfError.failed(String(cString: e)) }
        let bl = c.blind.data != nil ? Array(UnsafeBufferPointer(start: c.blind.data, count: c.blind.len)) : []
        let be = c.blinded_element.data != nil ? Array(UnsafeBufferPointer(start: c.blinded_element.data, count: c.blinded_element.len)) : []
        return BlindResult(blind: bl, blindedElement: be)
    }

    static func blind(_ input: [UInt8]) throws -> BlindResult {
        try blindOut(withPtrs([input]) { p in cryptolib_oprf_blind(p[0].0, p[0].1) })
    }
    static func blindWithScalar(_ input: [UInt8], _ blind: [UInt8]) throws -> BlindResult {
        try blindOut(withPtrs([input, blind]) { p in cryptolib_oprf_blind_with_scalar(p[0].0, p[0].1, p[1].0, p[1].1) })
    }
    static func blindEvaluate(sk: [UInt8], blindedElement: [UInt8]) throws -> [UInt8] {
        try withPtrs([sk, blindedElement]) { p in try oprfConsume(cryptolib_oprf_blind_evaluate(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    static func finalize(input: [UInt8], blind: [UInt8], evaluatedElement: [UInt8]) throws -> [UInt8] {
        try withPtrs([input, blind, evaluatedElement]) { p in
            try oprfConsume(cryptolib_oprf_finalize(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }
    static func evaluate(sk: [UInt8], input: [UInt8]) throws -> [UInt8] {
        try withPtrs([sk, input]) { p in try oprfConsume(cryptolib_oprf_evaluate(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
}

// ── smoke (compiled/run by `make swift-oprf`) ────────────────────────────────
func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — OPRF (RFC 9497) (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    let seed = hexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
    let info = hexToBytes("74657374206b6579")
    let kp = try Oprf.deriveKeyPair(seed: seed, info: info)
    ck("derive key", kp.secretKey == hexToBytes("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"))

    let input = hexToBytes("00")
    let blind = hexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")
    let b = try Oprf.blindWithScalar(input, blind)
    ck("blinded element", b.blindedElement == hexToBytes("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"))
    let ev = try Oprf.blindEvaluate(sk: kp.secretKey, blindedElement: b.blindedElement)
    ck("evaluation element", ev == hexToBytes("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"))
    let out = try Oprf.finalize(input: input, blind: blind, evaluatedElement: ev)
    let want = hexToBytes("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
    ck("finalize output", out == want)
    ck("server evaluate matches", try Oprf.evaluate(sk: kp.secretKey, input: input) == want)

    // random blind → same output, different blinded element
    let b2 = try Oprf.blind(input)
    let out2 = try Oprf.finalize(input: input, blind: b2.blind,
        evaluatedElement: try Oprf.blindEvaluate(sk: kp.secretKey, blindedElement: b2.blindedElement))
    ck("random blind consistent", out2 == want && b2.blindedElement != b.blindedElement)
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — OPRF \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
