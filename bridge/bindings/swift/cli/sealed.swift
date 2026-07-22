// CryptoLib Swift — Flagship / Fortress sealed messaging.
//
// Two assurance tiers of one construction (encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first). A self-contained,
// drop-in messaging layer over the cryptolib_sealed_* C ABI. Build the smoke with
// the Makefile target `swift-sealed`.
import Foundation

enum SealedError: Error { case failed(String) }

/// Assurance tier. Flagship = X25519+sntrup761 / Ed25519+ML-DSA-65 (default).
/// Fortress = + ML-KEM-768 (triple KEM) + SLH-DSA (triple sig), maximum assurance.
enum SealedTier: Int32 { case flagship = 0, fortress = 1 }

// ── result plumbing (fileprivate to avoid clashing with other CLI files) ──────
private func sealedConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error {
        let m = String(cString: e); cryptolib_str_free(e); throw SealedError.failed(m)
    }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}
private func sealedTake(_ b: CryptoBuffer) -> [UInt8] {
    guard let d = b.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: b.len))
}
private func withPtrs<R>(_ datas: [[UInt8]?],
                         _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

/// Public metadata carried by a sealed envelope (no secrets).
struct SealedInfo {
    let version: UInt8
    let suite: UInt8            // 1 = Flagship, 2 = Fortress
    let streaming: Bool
    let fingerprint: [UInt8]    // BLAKE2b-128 of the recipient public key
    let kemCiphertextLen: Int
}

/// Keyless inspection / addressing.
enum Sealed {
    static func inspect(_ envelope: [UInt8]) -> SealedInfo? {
        envelope.withUnsafeBufferPointer { e in
            let info = cryptolib_sealed_inspect(e.baseAddress, e.count)
            guard info.ok == 1 else { return nil }
            let fp = withUnsafeBytes(of: info.fingerprint) { Array($0) }
            return SealedInfo(version: info.version, suite: info.suite,
                              streaming: info.streaming == 1, fingerprint: fp,
                              kemCiphertextLen: info.kem_ciphertext_len)
        }
    }
    static func addressedTo(_ envelope: [UInt8], recipientPublic: [UInt8]) -> Bool {
        withPtrs([envelope, recipientPublic]) { p in
            cryptolib_sealed_addressed_to(p[0].0, p[0].1, p[1].0, p[1].1) == 1
        }
    }
}

/// A party's keypairs — recipient (KEM) for receiving, sender (signature) for
/// signing. The config/setup handle for the sealed-messaging API.
struct SealedIdentity {
    let tier: SealedTier
    let recipientPublic: [UInt8]
    let recipientSecret: [UInt8]
    let senderPublic: [UInt8]
    let senderSecret: [UInt8]

    static func generate(_ tier: SealedTier) -> SealedIdentity {
        func kp(_ raw: CryptoKeyPair) -> ([UInt8], [UInt8]) {
            var k = raw
            let pub = sealedTake(k.public_key), sec = sealedTake(k.secret_key)
            cryptolib_keypair_free(&k)
            return (pub, sec)
        }
        let (rpub, rsec) = kp(cryptolib_sealed_generate_recipient(tier.rawValue))
        let (spub, ssec) = kp(cryptolib_sealed_generate_sender(tier.rawValue))
        return SealedIdentity(tier: tier, recipientPublic: rpub, recipientSecret: rsec,
                              senderPublic: spub, senderSecret: ssec)
    }

    func seal(_ plaintext: [UInt8], to recipientPublic: [UInt8],
              aad: [UInt8]? = nil, purpose: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([plaintext, recipientPublic, senderSecret, aad, purpose]) { p in
            try sealedConsume(cryptolib_sealed_seal(tier.rawValue, p[0].0, p[0].1,
                p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1))
        }
    }

    func open(_ envelope: [UInt8], from senderPublic: [UInt8],
              aad: [UInt8]? = nil, purpose: [UInt8]? = nil) throws -> [UInt8] {
        try withPtrs([envelope, recipientSecret, recipientPublic, senderPublic, aad, purpose]) { p in
            try sealedConsume(cryptolib_sealed_open(tier.rawValue, p[0].0, p[0].1,
                p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1, p[5].0, p[5].1))
        }
    }

    func streamSealer(to recipientPublic: [UInt8], purpose: [UInt8]? = nil) throws -> SealedStreamSealer {
        try SealedStreamSealer(tier: tier, recipientPublic: recipientPublic,
                               senderSecret: senderSecret, purpose: purpose)
    }
    func streamOpener(preamble: [UInt8], from senderPublic: [UInt8], purpose: [UInt8]? = nil) throws -> SealedStreamOpener {
        try SealedStreamOpener(tier: tier, preamble: preamble, recipientSecret: recipientSecret,
                               recipientPublic: recipientPublic, senderPublic: senderPublic, purpose: purpose)
    }
}

/// Encrypting stream: preamble() once, push() each chunk, finalize() for the last
/// chunk + signed trailer. Freed on deinit or close().
final class SealedStreamSealer {
    private var handle: UnsafeMutableRawPointer?
    init(tier: SealedTier, recipientPublic: [UInt8], senderSecret: [UInt8], purpose: [UInt8]?) throws {
        var err: UnsafeMutablePointer<CChar>? = nil
        handle = withPtrs([recipientPublic, senderSecret, purpose]) { p in
            cryptolib_sealed_sealer_begin(tier.rawValue, p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, &err)
        }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw SealedError.failed(m) }
        guard handle != nil else { throw SealedError.failed("sealer begin failed") }
    }
    func preamble() throws -> [UInt8] { try sealedConsume(cryptolib_sealed_sealer_preamble(handle)) }
    func push(_ chunk: [UInt8]) throws -> [UInt8] {
        try withPtrs([chunk]) { p in try sealedConsume(cryptolib_sealed_sealer_push(handle, p[0].0, p[0].1)) }
    }
    func finalize(_ last: [UInt8]? = nil) throws -> (ciphertext: [UInt8], trailer: [UInt8]) {
        var trailer = CryptoBuffer()
        let ct = try withPtrs([last]) { p in
            try sealedConsume(cryptolib_sealed_sealer_finalize(handle, p[0].0, p[0].1, &trailer))
        }
        let tr = sealedTake(trailer); cryptolib_buffer_free(&trailer)
        return (ct, tr)
    }
    func close() { if let h = handle { cryptolib_sealed_sealer_free(h); handle = nil } }
    deinit { close() }
}

/// Decrypting stream: pull() each chunk (isFinal on the last), then finalize()
/// to verify the sender signature over the whole stream.
final class SealedStreamOpener {
    private var handle: UnsafeMutableRawPointer?
    init(tier: SealedTier, preamble: [UInt8], recipientSecret: [UInt8],
         recipientPublic: [UInt8], senderPublic: [UInt8], purpose: [UInt8]?) throws {
        var err: UnsafeMutablePointer<CChar>? = nil
        handle = withPtrs([preamble, recipientSecret, recipientPublic, senderPublic, purpose]) { p in
            cryptolib_sealed_opener_begin(tier.rawValue, p[0].0, p[0].1, p[1].0, p[1].1,
                p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1, &err)
        }
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw SealedError.failed(m) }
        guard handle != nil else { throw SealedError.failed("opener begin failed") }
    }
    func pull(_ ct: [UInt8]) throws -> (plaintext: [UInt8], isFinal: Bool) {
        var isFinal: Int32 = 0
        let pt = try withPtrs([ct]) { p in
            try sealedConsume(cryptolib_sealed_opener_pull(handle, p[0].0, p[0].1, &isFinal))
        }
        return (pt, isFinal == 1)
    }
    func finalize(_ trailer: [UInt8]) throws {
        _ = try withPtrs([trailer]) { p in
            try sealedConsume(cryptolib_sealed_opener_finalize(handle, p[0].0, p[0].1))
        }
    }
    func close() { if let h = handle { cryptolib_sealed_opener_free(h); handle = nil } }
    deinit { close() }
}

// ── smoke (compiled/run by `make swift-sealed`) ──────────────────────────────
guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — Flagship/Fortress (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

for (tier, name) in [(SealedTier.flagship, "Flagship"), (SealedTier.fortress, "Fortress")] {
    let alice = SealedIdentity.generate(tier)
    let bob = SealedIdentity.generate(tier)
    let aad = Array("ctx".utf8), purpose = Array("note".utf8)
    do {
        let env = try bob.seal(Array("meet at dawn".utf8), to: alice.recipientPublic, aad: aad, purpose: purpose)
        let out = try alice.open(env, from: bob.senderPublic, aad: aad, purpose: purpose)
        ck("\(name) roundtrip", out == Array("meet at dawn".utf8))
        let mal = SealedIdentity.generate(tier)
        var rejected = false
        do { _ = try alice.open(env, from: mal.senderPublic, aad: aad, purpose: purpose) } catch { rejected = true }
        ck("\(name) wrong-signer rejected", rejected)
        let info = Sealed.inspect(env)
        ck("\(name) inspect", info?.suite == (tier == .fortress ? 2 : 1) && info?.streaming == false)
        ck("\(name) addressed_to", Sealed.addressedTo(env, recipientPublic: alice.recipientPublic)
            && !Sealed.addressedTo(env, recipientPublic: mal.recipientPublic))
        // streaming
        let se = try bob.streamSealer(to: alice.recipientPublic, purpose: purpose)
        let pre = try se.preamble()
        let c0 = try se.push(Array("hello ".utf8))
        let (cf, trailer) = try se.finalize(Array("world".utf8))
        let op = try alice.streamOpener(preamble: pre, from: bob.senderPublic, purpose: purpose)
        let (p0, fin0) = try op.pull(c0)
        let (p1, fin1) = try op.pull(cf)
        try op.finalize(trailer)
        ck("\(name) streaming", p0 + p1 == Array("hello world".utf8) && !fin0 && fin1)
    } catch { fail += 1; print("  ✗ \(name) threw: \(error)") }
}

print("\n\(pass) passed, \(fail) failed — sealed \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
