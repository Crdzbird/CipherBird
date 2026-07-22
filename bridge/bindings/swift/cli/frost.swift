// CryptoLib Swift — FROST(Ed25519, SHA-512) t-of-n threshold signatures
// (RFC 9591). t of n parties jointly produce ONE ordinary Ed25519 signature: no
// single party can sign, any t can, and the result verifies with standard
// Ed25519 against the group public key. Build the smoke with the Makefile target
// `swift-frost`.
import Foundation

enum FrostError: Error { case failed(String) }

private func frostConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw FrostError.failed(m) }
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

private func bytes(_ b: CryptoBuffer) -> [UInt8] {
    guard let d = b.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: b.len))
}

/// FROST(Ed25519, SHA-512) — all methods are stateless; the ceremony state
/// (secret shares, nonces) lives with the caller.
enum Frost {
    struct KeyGen { let groupPublicKey: [UInt8]; let secretShares: [[UInt8]]; let publicShares: [[UInt8]] }
    struct Commitment { let identifier: UInt16; let hiding: [UInt8]; let binding: [UInt8] }
    struct Nonces { let hiding: [UInt8]; let binding: [UInt8] }

    /// Trusted-dealer split: any `t` of `n` shares can sign. Share i (0-based)
    /// has FROST identifier i+1.
    static func keygen(n: UInt16, t: UInt16) throws -> KeyGen {
        var kg = cryptolib_frost_keygen(n, t)
        defer { cryptolib_frost_keygen_free(&kg) }
        if let e = kg.error { throw FrostError.failed(String(cString: e)) }
        let count = Int(kg.count)
        let secs = bytes(kg.secret_shares), pubs = bytes(kg.public_shares)
        var secretShares: [[UInt8]] = [], publicShares: [[UInt8]] = []
        for i in 0..<count {
            secretShares.append(Array(secs[(i * 32)..<(i * 32 + 32)]))
            publicShares.append(Array(pubs[(i * 32)..<(i * 32 + 32)]))
        }
        return KeyGen(groupPublicKey: bytes(kg.group_public_key), secretShares: secretShares, publicShares: publicShares)
    }

    /// Round 1: fresh random nonce pair + public commitment for a share. Keep
    /// the returned nonces secret; publish the commitment.
    static func commit(shareSecret: [UInt8], identifier: UInt16) throws -> (Nonces, Commitment) {
        let c = withPtrs([shareSecret]) { p in cryptolib_frost_commit(p[0].0, p[0].1, identifier) }
        return try commitOut(c, identifier)
    }

    /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
    static func commitWithNonces(identifier: UInt16, hiding: [UInt8], binding: [UInt8]) throws -> (Nonces, Commitment) {
        let c = withPtrs([hiding, binding]) { p in
            cryptolib_frost_commit_with_nonces(identifier, p[0].0, p[0].1, p[1].0, p[1].1)
        }
        return try commitOut(c, identifier)
    }

    private static func commitOut(_ c0: CryptoFrostCommit, _ identifier: UInt16) throws -> (Nonces, Commitment) {
        var c = c0
        defer { cryptolib_frost_commit_free(&c) }
        if let e = c.error { throw FrostError.failed(String(cString: e)) }
        return (Nonces(hiding: bytes(c.hiding_nonce), binding: bytes(c.binding_nonce)),
                Commitment(identifier: identifier, hiding: bytes(c.hiding_commit), binding: bytes(c.binding_commit)))
    }

    // Flatten commitments into the three parallel wire arrays.
    private static func withCommitments<R>(
        _ cs: [Commitment],
        _ body: (UnsafePointer<UInt16>?, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?, Int) throws -> R) rethrows -> R {
        let ids = cs.map { $0.identifier }
        var hid = [UInt8](), bnd = [UInt8]()
        for c in cs { hid.append(contentsOf: c.hiding); bnd.append(contentsOf: c.binding) }
        return try ids.withUnsafeBufferPointer { ip in
            try hid.withUnsafeBufferPointer { hp in
                try bnd.withUnsafeBufferPointer { bp in
                    try body(ip.baseAddress, hp.baseAddress, bp.baseAddress, cs.count)
                }
            }
        }
    }

    /// Round 2: this participant's 32-byte signature share. `commitments` is the
    /// full round-1 set from every participating signer (including self).
    static func sign(identifier: UInt16, shareSecret: [UInt8], groupPublicKey: [UInt8],
                     nonces: Nonces, msg: [UInt8], commitments: [Commitment]) throws -> [UInt8] {
        try withCommitments(commitments) { ids, hid, bnd, n in
            try withPtrs([shareSecret, groupPublicKey, nonces.hiding, nonces.binding, msg]) { p in
                try frostConsume(cryptolib_frost_sign(
                    identifier, p[0].0, p[0].1, p[1].0, p[1].1,
                    p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1, ids, hid, bnd, n))
            }
        }
    }

    /// Aggregate signature shares into one 64-byte Ed25519 signature.
    static func aggregate(groupPublicKey: [UInt8], msg: [UInt8],
                          commitments: [Commitment], sigShares: [[UInt8]]) throws -> [UInt8] {
        var flat = [UInt8](); for s in sigShares { flat.append(contentsOf: s) }
        return try withCommitments(commitments) { ids, hid, bnd, n in
            try withPtrs([groupPublicKey, msg, flat]) { p in
                try frostConsume(cryptolib_frost_aggregate(
                    p[0].0, p[0].1, p[1].0, p[1].1, ids, hid, bnd, n, p[2].0))
            }
        }
    }

    /// Verify an aggregate signature with standard Ed25519.
    static func verify(msg: [UInt8], sig: [UInt8], groupPublicKey: [UInt8]) -> Bool {
        withPtrs([msg, sig, groupPublicKey]) { p in
            cryptolib_frost_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) == 1
        }
    }

    /// Verify one participant's signature share against its public share.
    static func verifyShare(identifier: UInt16, publicShare: [UInt8], sigShare: [UInt8],
                            commitment: Commitment, groupPublicKey: [UInt8], msg: [UInt8],
                            commitments: [Commitment]) -> Bool {
        withCommitments(commitments) { ids, hid, bnd, n in
            withPtrs([publicShare, sigShare, commitment.hiding, commitment.binding, groupPublicKey, msg]) { p in
                cryptolib_frost_verify_share(
                    identifier, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                    p[3].0, p[3].1, p[4].0, p[4].1, p[5].0, p[5].1, ids, hid, bnd, n) == 1
            }
        }
    }
}

// ── smoke (compiled/run by `make swift-frost`) ───────────────────────────────
func hexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — FROST threshold sigs (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    // RFC 9591 §C.1
    let gpk = hexToBytes("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
    let msg = hexToBytes("74657374")
    let s1 = hexToBytes("929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509")
    let s3 = hexToBytes("d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02")
    let h1 = hexToBytes("812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407")
    let b1 = hexToBytes("b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301")
    let h3 = hexToBytes("c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e")
    let b3 = hexToBytes("243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d")
    let ss1 = hexToBytes("001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603")
    let ss3 = hexToBytes("bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007")
    let wantSig = hexToBytes("36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"
                           + "bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b")

    let (_, c1) = try Frost.commitWithNonces(identifier: 1, hiding: h1, binding: b1)
    ck("KAT commit 1", c1.hiding == hexToBytes("b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3")
                    && c1.binding == hexToBytes("67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932"))
    let (_, c3) = try Frost.commitWithNonces(identifier: 3, hiding: h3, binding: b3)
    let cs = [c1, c3]

    let g1 = try Frost.sign(identifier: 1, shareSecret: s1, groupPublicKey: gpk, nonces: Frost.Nonces(hiding: h1, binding: b1), msg: msg, commitments: cs)
    ck("KAT signature share 1", g1 == ss1)
    let g3 = try Frost.sign(identifier: 3, shareSecret: s3, groupPublicKey: gpk, nonces: Frost.Nonces(hiding: h3, binding: b3), msg: msg, commitments: cs)
    ck("KAT signature share 3", g3 == ss3)

    let sig = try Frost.aggregate(groupPublicKey: gpk, msg: msg, commitments: cs, sigShares: [ss1, ss3])
    ck("KAT aggregate signature", sig == wantSig)
    ck("verify ok", Frost.verify(msg: msg, sig: sig, groupPublicKey: gpk))
    ck("verify rejects wrong msg", !Frost.verify(msg: hexToBytes("74657375"), sig: sig, groupPublicKey: gpk))

    // e2e 3-of-5, signers {1,2,4} → indices {0,1,3}
    let kg = try Frost.keygen(n: 5, t: 3)
    ck("keygen 5 shares", kg.secretShares.count == 5 && kg.publicShares.count == 5)
    let em = Array("threshold payload".utf8)
    let idx = [0, 1, 3]
    var nonces: [Frost.Nonces] = [], ecs: [Frost.Commitment] = []
    for i in idx {
        let (n, c) = try Frost.commit(shareSecret: kg.secretShares[i], identifier: UInt16(i + 1))
        nonces.append(n); ecs.append(c)
    }
    var shares: [[UInt8]] = []
    for (k, i) in idx.enumerated() {
        let sh = try Frost.sign(identifier: UInt16(i + 1), shareSecret: kg.secretShares[i], groupPublicKey: kg.groupPublicKey, nonces: nonces[k], msg: em, commitments: ecs)
        ck("per-share verify \(i + 1)", Frost.verifyShare(identifier: UInt16(i + 1), publicShare: kg.publicShares[i], sigShare: sh, commitment: ecs[k], groupPublicKey: kg.groupPublicKey, msg: em, commitments: ecs))
        shares.append(sh)
    }
    let esig = try Frost.aggregate(groupPublicKey: kg.groupPublicKey, msg: em, commitments: ecs, sigShares: shares)
    ck("e2e verify", Frost.verify(msg: em, sig: esig, groupPublicKey: kg.groupPublicKey))
    ck("wrong public share rejected", !Frost.verifyShare(identifier: UInt16(idx[0] + 1), publicShare: kg.publicShares[idx[1]], sigShare: shares[0], commitment: ecs[0], groupPublicKey: kg.groupPublicKey, msg: em, commitments: ecs))
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — FROST \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
