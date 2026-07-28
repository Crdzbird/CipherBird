// CryptoLib Swift — BBS per-verifier pseudonyms + blind issuance
// (draft-irtf-cfrg-bbs-per-verifier-linkability-02 / -blind-signatures-02).
// The pseudonym ciphersuite is applied internally by the C ABI. Scalar inputs
// (proverNyms, nymSecrets, secretProverBlind, signerNymEntropy) are 32-byte
// big-endian. Build/run the smoke with the Makefile target `swift-bbs-pseudonym`.
import Foundation

enum BbsNymError: Error { case failed(String) }

private func nymConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw BbsNymError.failed(m) }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}

// Copy an out-param CryptoBuffer's bytes, then free it.
private func nymTake(_ cb: CryptoBuffer) -> [UInt8] {
    var buf = cb
    defer { cryptolib_buffer_free(&buf) }
    guard let d = cb.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: cb.len))
}

private func withPtrs<R>(_ datas: [[UInt8]?], _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

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

/// BBS per-verifier pseudonyms + blind issuance. Stateless.
enum BbsNym {
    /// Commit committedMessages + proverNyms → (commitmentWithProof, secretProverBlind).
    static func commitWithNym(committed: [[UInt8]], proverNyms: [[UInt8]]) throws -> (commitmentWithProof: [UInt8], secretProverBlind: [UInt8]) {
        try withMsgArrays(committed) { cm, cl, cn in
            try withMsgArrays(proverNyms) { pm, pl, pn in
                var blind = CryptoBuffer()
                let r = cryptolib_bbs_commit_with_nym(cm, cl, cn, pm, pl, pn, &blind)
                let cwp = try nymConsume(r)
                return (cwp, nymTake(blind))
            }
        }
    }

    /// Blind-sign over the commitment + signer messages → 80-byte signature.
    static func blindSignWithNym(sk: [UInt8], pk: [UInt8], commitmentWithProof: [UInt8], header: [UInt8],
                                 messages: [[UInt8]], signerNymEntropy: [UInt8], lengthNymVector: UInt64) throws -> [UInt8] {
        try withMsgArrays(messages) { mp, ml, n in
            try withPtrs([sk, pk, commitmentWithProof, header, signerNymEntropy]) { p in
                try nymConsume(cryptolib_bbs_blind_sign_with_nym(p[0].0, p[0].1, p[1].0, p[1].1,
                    p[2].0, p[2].1, p[3].0, p[3].1, mp, ml, n, p[4].0, p[4].1, lengthNymVector))
            }
        }
    }

    /// nym_secrets = proverNyms with the last element += signerNymEntropy.
    static func finalizeNymSecrets(proverNyms: [[UInt8]], signerNymEntropy: [UInt8]) throws -> [UInt8] {
        try withMsgArrays(proverNyms) { pm, pl, pn in
            try withPtrs([signerNymEntropy]) { p in
                try nymConsume(cryptolib_bbs_finalize_nym_secrets(pm, pl, pn, p[0].0, p[0].1))
            }
        }
    }

    /// Deterministic pseudonym (48-byte compressed G1 point) for a context.
    static func calculatePseudonym(contextId: [UInt8], nymSecrets: [[UInt8]]) throws -> [UInt8] {
        try withMsgArrays(nymSecrets) { nm, nl, nn in
            try withPtrs([contextId]) { p in
                try nymConsume(cryptolib_bbs_calculate_pseudonym(p[0].0, p[0].1, nm, nl, nn))
            }
        }
    }

    /// Pseudonym-bound selective-disclosure proof → (proof, pseudonym).
    static func proofGenWithPseudonym(pk: [UInt8], signature: [UInt8], header: [UInt8], ph: [UInt8], contextId: [UInt8],
                                      signerMessages: [[UInt8]], committedMessages: [[UInt8]], secretProverBlind: [UInt8],
                                      nymSecrets: [[UInt8]], disclosedSignerIndexes: [UInt64],
                                      disclosedCommittedIndexes: [UInt64]) throws -> (proof: [UInt8], pseudonym: [UInt8]) {
        try withMsgArrays(signerMessages) { sm, sl, sn in
            try withMsgArrays(committedMessages) { cm, cl, cn in
                try withMsgArrays(nymSecrets) { nm, nl, nn in
                    try disclosedSignerIndexes.withUnsafeBufferPointer { si in
                        try disclosedCommittedIndexes.withUnsafeBufferPointer { ci in
                            try withPtrs([pk, signature, header, ph, contextId, secretProverBlind]) { p in
                                var nymOut = CryptoBuffer()
                                let r = cryptolib_bbs_proof_gen_with_pseudonym(
                                    p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1,
                                    sm, sl, sn, cm, cl, cn, p[5].0, p[5].1, nm, nl, nn,
                                    si.baseAddress, disclosedSignerIndexes.count,
                                    ci.baseAddress, disclosedCommittedIndexes.count, &nymOut)
                                let proof = try nymConsume(r)
                                return (proof, nymTake(nymOut))
                            }
                        }
                    }
                }
            }
        }
    }

    /// Verify a pseudonym-bound proof. disclosedMessages/disclosedIndexes are the
    /// COMBINED signer+committed disclosures (committed index j passed as j+L+1).
    static func proofVerifyWithPseudonym(pk: [UInt8], proof: [UInt8], header: [UInt8], ph: [UInt8], contextId: [UInt8],
                                         pseudonym: [UInt8], L: UInt64, lengthNymVector: UInt64,
                                         disclosedMessages: [[UInt8]], disclosedIndexes: [UInt64]) -> Bool {
        withMsgArrays(disclosedMessages) { mp, ml, n in
            disclosedIndexes.withUnsafeBufferPointer { ip in
                withPtrs([pk, proof, header, ph, contextId, pseudonym]) { p in
                    cryptolib_bbs_proof_verify_with_pseudonym(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                        p[3].0, p[3].1, p[4].0, p[4].1, p[5].0, p[5].1, L, lengthNymVector,
                        mp, ml, n, ip.baseAddress, disclosedIndexes.count) == 1
                }
            }
        }
    }

    // ── Standalone blind issuance (draft-irtf-cfrg-bbs-blind-signatures-02, no
    // pseudonyms). secretProverBlind is a 32-byte big-endian scalar. ──────────

    /// Commit to committedMessages (the signer never learns them) →
    /// (commitmentWithProof, secretProverBlind).
    static func blindCommit(committed: [[UInt8]]) throws -> (commitmentWithProof: [UInt8], secretProverBlind: [UInt8]) {
        try withMsgArrays(committed) { cm, cl, cn in
            var blind = CryptoBuffer()
            let r = cryptolib_bbs_blind_commit(cm, cl, cn, &blind)
            let cwp = try nymConsume(r)
            return (cwp, nymTake(blind))
        }
    }

    /// Blind-sign over the commitment + signer messages → 80-byte signature.
    static func blindSign(sk: [UInt8], pk: [UInt8], commitmentWithProof: [UInt8], header: [UInt8],
                          messages: [[UInt8]]) throws -> [UInt8] {
        try withMsgArrays(messages) { mp, ml, n in
            try withPtrs([sk, pk, commitmentWithProof, header]) { p in
                try nymConsume(cryptolib_bbs_blind_sign(p[0].0, p[0].1, p[1].0, p[1].1,
                    p[2].0, p[2].1, p[3].0, p[3].1, mp, ml, n))
            }
        }
    }

    /// Verify a blind signature over messages + committedMessages using secretProverBlind.
    static func verifyBlindSign(pk: [UInt8], signature: [UInt8], header: [UInt8],
                               messages: [[UInt8]], committed: [[UInt8]], secretProverBlind: [UInt8]) -> Bool {
        withMsgArrays(messages) { mp, ml, mn in
            withMsgArrays(committed) { cm, cl, cn in
                withPtrs([pk, signature, header, secretProverBlind]) { p in
                    cryptolib_bbs_verify_blind_sign(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1,
                        mp, ml, mn, cm, cl, cn, p[3].0, p[3].1) == 1
                }
            }
        }
    }
}

// ── smoke (compiled/run by `make swift-bbs-pseudonym`) ───────────────────────
func nymHexToBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — BBS pseudonyms + blind issuance (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

do {
    let sk = nymHexToBytes("60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
    let pk = nymHexToBytes("a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")
    let header = nymHexToBytes("11223344556677889900aabbccddeeff")
    let ph = nymHexToBytes("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
    let ctx = nymHexToBytes("bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a")
    let entropy = nymHexToBytes("3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5")
    let proverNym = nymHexToBytes("1234000000000000000000000000000000000000000000000000000000000000")

    let signer: [[UInt8]] = [[0xaa], [0xbb, 0xbb]]
    let committed: [[UInt8]] = [[0xcc, 0xcc, 0xcc], [0xdd]]
    let nyms = [proverNym]

    let (cwp, blind) = try BbsNym.commitWithNym(committed: committed, proverNyms: nyms)
    ck("commitWithNym (blind == 32 B)", !cwp.isEmpty && blind.count == 32)

    let sig = try BbsNym.blindSignWithNym(sk: sk, pk: pk, commitmentWithProof: cwp, header: header,
                                          messages: signer, signerNymEntropy: entropy, lengthNymVector: 1)
    ck("blindSignWithNym (80-byte sig)", sig.count == 80)

    let nymSecrets = try BbsNym.finalizeNymSecrets(proverNyms: nyms, signerNymEntropy: entropy)
    ck("finalizeNymSecrets (32 B)", nymSecrets.count == 32)
    let ns = [nymSecrets]

    let (proof, pseudonym) = try BbsNym.proofGenWithPseudonym(pk: pk, signature: sig, header: header, ph: ph,
        contextId: ctx, signerMessages: signer, committedMessages: committed, secretProverBlind: blind,
        nymSecrets: ns, disclosedSignerIndexes: [0, 1], disclosedCommittedIndexes: [0, 1])
    ck("proofGenWithPseudonym (pseudonym == 48 B)", !proof.isEmpty && pseudonym.count == 48)
    ck("pseudonym matches calculatePseudonym", try pseudonym == BbsNym.calculatePseudonym(contextId: ctx, nymSecrets: ns))

    let dm: [[UInt8]] = [[0xaa], [0xbb, 0xbb], [0xcc, 0xcc, 0xcc], [0xdd]]
    ck("proofVerifyWithPseudonym = VALID",
       BbsNym.proofVerifyWithPseudonym(pk: pk, proof: proof, header: header, ph: ph, contextId: ctx,
           pseudonym: pseudonym, L: 2, lengthNymVector: 1, disclosedMessages: dm, disclosedIndexes: [0, 1, 3, 4]))

    let badctx = nymHexToBytes("aab4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a")
    ck("wrong-context proof rejected",
       !BbsNym.proofVerifyWithPseudonym(pk: pk, proof: proof, header: header, ph: ph, contextId: badctx,
           pseudonym: pseudonym, L: 2, lengthNymVector: 1, disclosedMessages: dm, disclosedIndexes: [0, 1, 3, 4]))

    // ── Standalone blind issuance (no pseudonyms) ────────────────────────────
    let signer2: [[UInt8]] = [Array("age>=18".utf8), Array("region=EU".utf8)]
    let committed2: [[UInt8]] = [Array("ssn=123".utf8), Array("dob=1990".utf8)]
    let (cwp2, blind2) = try BbsNym.blindCommit(committed: committed2)
    ck("blindCommit (blind == 32 B)", !cwp2.isEmpty && blind2.count == 32)
    let sig2 = try BbsNym.blindSign(sk: sk, pk: pk, commitmentWithProof: cwp2, header: header, messages: signer2)
    ck("blindSign (80-byte sig)", sig2.count == 80)
    ck("verifyBlindSign = VALID",
       BbsNym.verifyBlindSign(pk: pk, signature: sig2, header: header, messages: signer2,
           committed: committed2, secretProverBlind: blind2))
    var badBlind = blind2; badBlind[0] ^= 1
    ck("wrong blind rejected",
       !BbsNym.verifyBlindSign(pk: pk, signature: sig2, header: header, messages: signer2,
           committed: committed2, secretProverBlind: badBlind))
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — BBS pseudonyms \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
