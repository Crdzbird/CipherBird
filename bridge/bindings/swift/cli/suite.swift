// CryptoLib Swift — Suite: one-call advanced combinations.
//
// A reusable, ergonomic Swift facade over the cryptolib_suite_* C ABI. Drop this
// file into a target that imports the CryptoLib bridging header (or the
// CryptoLibC module) and call e.g. `Suite.sealSignedPq(...)`. Build the smoke at
// the bottom (see the Makefile target `swift-suite`):
//   swiftc -import-objc-header bridge/cryptolib_c.h bridge/bindings/swift/cli/suite.swift \
//          -L build/release -lcryptolib_c -Xlinker -rpath -Xlinker build/release -o build/swift_suite
import Foundation

enum SuiteError: Error { case failed(String) }

/// One-call advanced combinations. Every seal is authenticated and fails closed;
/// the post-quantum envelopes carry the KEM ciphertext, so a recipient needs only
/// their long-term secret key.
enum Suite {
    // ── result plumbing ──────────────────────────────────────────────────────
    private static func consume(_ r: CryptoBufferResult) throws -> [UInt8] {
        if let e = r.error {
            let m = String(cString: e); cryptolib_str_free(e); throw SuiteError.failed(m)
        }
        var buf = r.buf
        defer { cryptolib_buffer_free(&buf) }
        guard let d = buf.data else { return [] }
        return Array(UnsafeBufferPointer(start: d, count: buf.len))
    }
    private static func take(_ b: CryptoBuffer) -> [UInt8] {
        guard let d = b.data else { return [] }
        return Array(UnsafeBufferPointer(start: d, count: b.len))
    }
    // Pin a list of byte buffers and expose (pointer, count) pairs for a C call.
    private static func withPtrs<R>(_ datas: [[UInt8]?],
                                    _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
        func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
            if i == datas.count { return try body(acc) }
            guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
            return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
        }
        return try rec(0, [])
    }

    // ── 1. Post-quantum message ──────────────────────────────────────────────
    static func sealPq(_ plaintext: [UInt8], recipientKemPublic: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, recipientKemPublic, aad]) { p in
            try consume(cryptolib_suite_seal_pq(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }
    static func openPq(_ envelope: [UInt8], recipientKemSecret: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([envelope, recipientKemSecret, aad]) { p in
            try consume(cryptolib_suite_open_pq(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }

    // ── 2. Signed + PQ (flagship) ────────────────────────────────────────────
    static func sealSignedPq(_ plaintext: [UInt8], recipientKemPublic: [UInt8],
                             signerSigSecret: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, recipientKemPublic, signerSigSecret, aad]) { p in
            try consume(cryptolib_suite_seal_signed_pq(p[0].0, p[0].1, p[1].0, p[1].1,
                                                       p[2].0, p[2].1, p[3].0, p[3].1))
        }
    }
    static func openSignedPq(_ envelope: [UInt8], recipientKemSecret: [UInt8],
                             signerSigPublic: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([envelope, recipientKemSecret, signerSigPublic, aad]) { p in
            try consume(cryptolib_suite_open_signed_pq(p[0].0, p[0].1, p[1].0, p[1].1,
                                                       p[2].0, p[2].1, p[3].0, p[3].1))
        }
    }

    // ── 3. File-as-key ───────────────────────────────────────────────────────
    static func sealWithFile(_ plaintext: [UInt8], path: String, aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, aad]) { p in
            try consume(cryptolib_suite_seal_with_file(p[0].0, p[0].1, path, p[1].0, p[1].1))
        }
    }
    static func openWithFile(_ envelope: [UInt8], path: String, aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([envelope, aad]) { p in
            try consume(cryptolib_suite_open_with_file(p[0].0, p[0].1, path, p[1].0, p[1].1))
        }
    }

    // ── 4. Keyring-guarded (kr is a cryptolib_keyring_create() handle) ────────
    static func sealWithKeyringDevice(_ plaintext: [UInt8], keyring: CryptoKeyringHandle?,
                                      factorKey: [UInt8], aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, factorKey, aad]) { p in
            try consume(cryptolib_suite_seal_with_keyring_device(p[0].0, p[0].1, keyring,
                                                                 p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }
    static func openWithKeyringPassphrase(_ envelope: [UInt8], keyring: CryptoKeyringHandle?,
                                          passphrase: String, aad: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([envelope, aad]) { p in
            try consume(cryptolib_suite_open_with_keyring_passphrase(p[0].0, p[0].1, keyring,
                                                                     passphrase, p[1].0, p[1].1))
        }
    }

    // ── 5. Threshold (k-of-n) ────────────────────────────────────────────────
    static func sealThreshold(_ plaintext: [UInt8], n: Int, k: Int,
                              aad: [UInt8]? = nil) throws -> (envelope: [UInt8], shares: [[UInt8]]) {
        try withPtrs([plaintext, aad]) { p in
            var out = CryptoBuffer()
            let r = cryptolib_suite_seal_threshold(p[0].0, p[0].1, UInt8(n), UInt8(k),
                                                   p[1].0, p[1].1, &out)
            let env = try consume(r)
            let blob = take(out)
            var buf = out; cryptolib_buffer_free(&buf)
            return (env, splitShareRecords(blob))
        }
    }
    static func openThreshold(_ envelope: [UInt8], shares: [[UInt8]], aad: [UInt8]? = nil) throws -> [UInt8] {
        let blob = shares.flatMap { $0 }
        return try withPtrs([envelope, blob, aad]) { p in
            try consume(cryptolib_suite_open_threshold(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1))
        }
    }
    /// Parse [index(1)|ylen(4 LE)|y] records into individual share records.
    static func splitShareRecords(_ blob: [UInt8]) -> [[UInt8]] {
        var out: [[UInt8]] = [], off = 0
        while off + 5 <= blob.count {
            let yl = Int(blob[off + 1]) | Int(blob[off + 2]) << 8 | Int(blob[off + 3]) << 16 | Int(blob[off + 4]) << 24
            let end = off + 5 + yl
            if end > blob.count { break }
            out.append(Array(blob[off..<end])); off = end
        }
        return out
    }

    // ── 6. EVM address ───────────────────────────────────────────────────────
    static func evmAddress(_ secp256k1PublicKey: [UInt8]) throws -> [UInt8] {
        try withPtrs([secp256k1PublicKey]) { p in
            try consume(cryptolib_suite_evm_address(p[0].0, p[0].1))
        }
    }
}

// ── smoke (compiled/run by `make swift-suite`) ───────────────────────────────
guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — Suite (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }
let aad = Array("suite/v1".utf8)

do {
    var kem = cryptolib_hybrid_kem_keygen()
    let kpub = Array(UnsafeBufferPointer(start: kem.public_key.data, count: kem.public_key.len))
    let ksec = Array(UnsafeBufferPointer(start: kem.secret_key.data, count: kem.secret_key.len))
    cryptolib_keypair_free(&kem)
    var sig = cryptolib_hybrid_sig_keygen()
    let spub = Array(UnsafeBufferPointer(start: sig.public_key.data, count: sig.public_key.len))
    let ssec = Array(UnsafeBufferPointer(start: sig.secret_key.data, count: sig.secret_key.len))
    cryptolib_keypair_free(&sig)

    let pt = Array("transfer 100 to acct #42".utf8)
    let env = try Suite.sealSignedPq(pt, recipientKemPublic: kpub, signerSigSecret: ssec, aad: aad)
    let out = try Suite.openSignedPq(env, recipientKemSecret: ksec, signerSigPublic: spub, aad: aad)
    ck("signed_pq roundtrip", out == pt)

    var impostor = cryptolib_hybrid_sig_keygen()
    let ipub = Array(UnsafeBufferPointer(start: impostor.public_key.data, count: impostor.public_key.len))
    cryptolib_keypair_free(&impostor)
    var rejected = false
    do { _ = try Suite.openSignedPq(env, recipientKemSecret: ksec, signerSigPublic: ipub, aad: aad) }
    catch { rejected = true }
    ck("signed_pq rejects wrong signer", rejected)

    let (tenv, shares) = try Suite.sealThreshold(Array("board resolution".utf8), n: 5, k: 3, aad: aad)
    let quorum = [shares[0], shares[2], shares[4]]
    let opened = try Suite.openThreshold(tenv, shares: quorum, aad: aad)
    ck("threshold 3-of-5 (\(shares.count) shares)", opened == Array("board resolution".utf8))

    var below = false
    do { _ = try Suite.openThreshold(tenv, shares: [shares[0], shares[1]], aad: aad) } catch { below = true }
    ck("threshold below quorum fails", below)

    var w = cryptolib_secp256k1_keygen()
    let wpub = Array(UnsafeBufferPointer(start: w.public_key.data, count: w.public_key.len))
    cryptolib_keypair_free(&w)
    let addr = try Suite.evmAddress(wpub)
    ck("evm_address 20 bytes", addr.count == 20)
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — suite \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
