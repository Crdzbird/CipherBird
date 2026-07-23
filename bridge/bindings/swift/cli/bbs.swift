// CryptoLib Swift — BBS Signatures + selective disclosure (BLS12-381-SHA-256,
// draft-irtf-cfrg-bbs-signatures). Sign a vector of messages; derive a
// zero-knowledge proof revealing only a chosen subset. Build the smoke with the
// Makefile target `swift-bbs`.
import Foundation

enum BbsError: Error { case failed(String) }

private func bbsConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw BbsError.failed(m) }
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

// Marshal [[UInt8]] into a C (const uint8_t* const*, const size_t*, count) triple.
private func withMsgArrays<R>(_ msgs: [[UInt8]],
    _ body: (UnsafePointer<UnsafePointer<UInt8>?>?, UnsafePointer<Int>?, Int) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ ptrs: [UnsafePointer<UInt8>?], _ lens: [Int]) throws -> R {
        if i == msgs.count {
            return try ptrs.withUnsafeBufferPointer { pp in
                try lens.withUnsafeBufferPointer { lp in try body(pp.baseAddress, lp.baseAddress, msgs.count) }
            }
        }
        return try msgs[i].withUnsafeBufferPointer { bp in
            try rec(i + 1, ptrs + [bp.baseAddress], lens + [msgs[i].count])
        }
    }
    return try rec(0, [], [])
}

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256). Stateless.
enum Bbs {
    static func keygen(keyMaterial: [UInt8], keyInfo: [UInt8]? = nil) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        var kp = withPtrs([keyMaterial, keyInfo]) { p in cryptolib_bbs_keygen(p[0].0, p[0].1, p[1].0, p[1].1) }
        let pub = kp.public_key.data != nil ? Array(UnsafeBufferPointer(start: kp.public_key.data, count: kp.public_key.len)) : []
        let sec = kp.secret_key.data != nil ? Array(UnsafeBufferPointer(start: kp.secret_key.data, count: kp.secret_key.len)) : []
        cryptolib_keypair_free(&kp)
        if pub.isEmpty { throw BbsError.failed("bbs keygen failed (key material must be >= 32 bytes)") }
        return (pub, sec)
    }

    static func skToPk(_ sk: [UInt8]) throws -> [UInt8] {
        try withPtrs([sk]) { p in try bbsConsume(cryptolib_bbs_sk_to_pk(p[0].0, p[0].1)) }
    }

    static func sign(sk: [UInt8], pk: [UInt8], header: [UInt8], messages: [[UInt8]]) throws -> [UInt8] {
        try withMsgArrays(messages) { mp, ml, n in
            try withPtrs([sk, pk, header]) { p in
                try bbsConsume(cryptolib_bbs_sign(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, mp, ml, n))
            }
        }
    }

    static func verify(pk: [UInt8], signature: [UInt8], header: [UInt8], messages: [[UInt8]]) -> Bool {
        withMsgArrays(messages) { mp, ml, n in
            withPtrs([pk, signature, header]) { p in
                cryptolib_bbs_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, mp, ml, n) == 1
            }
        }
    }

    static func proofGen(pk: [UInt8], signature: [UInt8], header: [UInt8], ph: [UInt8],
                         messages: [[UInt8]], disclosedIndexes: [UInt64]) throws -> [UInt8] {
        try withMsgArrays(messages) { mp, ml, n in
            try disclosedIndexes.withUnsafeBufferPointer { ip in
                try withPtrs([pk, signature, header, ph]) { p in
                    try bbsConsume(cryptolib_bbs_proof_gen(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                        p[3].0, p[3].1, mp, ml, n, ip.baseAddress, disclosedIndexes.count))
                }
            }
        }
    }

    static func proofVerify(pk: [UInt8], proof: [UInt8], header: [UInt8], ph: [UInt8],
                            disclosedMessages: [[UInt8]], disclosedIndexes: [UInt64]) -> Bool {
        withMsgArrays(disclosedMessages) { mp, ml, n in
            disclosedIndexes.withUnsafeBufferPointer { ip in
                withPtrs([pk, proof, header, ph]) { p in
                    cryptolib_bbs_proof_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                        p[3].0, p[3].1, mp, ml, n, ip.baseAddress, disclosedIndexes.count) == 1
                }
            }
        }
    }
}

// ── smoke (compiled/run by `make swift-bbs`) ─────────────────────────────────
func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — BBS signatures (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    let sk = hexToBytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
    let pk = hexToBytes("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")
    let header = hexToBytes("11223344556677889900aabbccddeeff")
    let M = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02","c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80","7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73","77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c","496694774c5604ab1b2544eababcf0f53278ff50","515ae153e22aae04ad16f759e07237b4","d183ddc6e2665aa4e2f088af","ac55fb33a75909ed","96012096",""].map(hexToBytes)

    ck("sk_to_pk fixture", try Bbs.skToPk(sk) == pk)
    let sig = try Bbs.sign(sk: sk, pk: pk, header: header, messages: M)
    ck("sign 10-message fixture", sig == hexToBytes("8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8"))
    ck("verify", Bbs.verify(pk: pk, signature: sig, header: header, messages: M))

    let ph = hexToBytes("aabbcc")
    let disc: [UInt64] = [0, 3, 7]
    let proof = try Bbs.proofGen(pk: pk, signature: sig, header: header, ph: ph, messages: M, disclosedIndexes: disc)
    let revealed = [M[0], M[3], M[7]]
    ck("selective disclosure verify", Bbs.proofVerify(pk: pk, proof: proof, header: header, ph: ph, disclosedMessages: revealed, disclosedIndexes: disc))
    var bad = M[3]; bad[0] ^= 1
    ck("wrong revealed rejected", !Bbs.proofVerify(pk: pk, proof: proof, header: header, ph: ph, disclosedMessages: [M[0], bad, M[7]], disclosedIndexes: disc))
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — BBS \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
