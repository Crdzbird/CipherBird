// CryptoLib Swift — OPAQUE aPAKE (OPAQUE-3DH, ristretto255-SHA-512). Client and
// server agree on a session key from a password that never leaves the client and
// is never stored server-side. Build the smoke with the Makefile `swift-opaque`.
import Foundation

enum OpaqueError: Error { case failed(String) }

private func opaqueConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw OpaqueError.failed(m) }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}
private func bytes(_ b: CryptoBuffer) -> [UInt8] {
    guard let d = b.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: b.len))
}
private func withPtrs<R>(_ datas: [[UInt8]?], _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i] else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH). Stateless; state blobs are
/// returned to and passed back by the caller.
enum Opaque {
    struct RegRequest { let blind: [UInt8]; let request: [UInt8] }
    struct Record { let record: [UInt8]; let exportKey: [UInt8] }
    struct Ke1 { let ke1: [UInt8]; let clientState: [UInt8] }
    struct Ke2 { let ke2: [UInt8]; let serverState: [UInt8] }
    struct Ke3 { let ke3: [UInt8]; let sessionKey: [UInt8]; let exportKey: [UInt8] }

    static func registrationRequest(_ password: [UInt8]) throws -> RegRequest {
        var c = withPtrs([password]) { p in cryptolib_opaque_registration_request(p[0].0, p[0].1) }
        defer { cryptolib_oprf_blind_free(&c) }
        if let e = c.error { throw OpaqueError.failed(String(cString: e)) }
        return RegRequest(blind: bytes(c.blind), request: bytes(c.blinded_element))
    }

    static func registrationResponse(request: [UInt8], serverPublicKey: [UInt8],
                                     credentialIdentifier: [UInt8], oprfSeed: [UInt8]) throws -> [UInt8] {
        try withPtrs([request, serverPublicKey, credentialIdentifier, oprfSeed]) { p in
            try opaqueConsume(cryptolib_opaque_registration_response(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1))
        }
    }

    static func finalizeRequest(password: [UInt8], blind: [UInt8], response: [UInt8],
                                serverIdentity: [UInt8]? = nil, clientIdentity: [UInt8]? = nil) throws -> Record {
        var r = withPtrs([password, blind, response, serverIdentity, clientIdentity]) { p in
            cryptolib_opaque_finalize_request(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1)
        }
        defer { cryptolib_opaque_record_free(&r) }
        if let e = r.error { throw OpaqueError.failed(String(cString: e)) }
        return Record(record: bytes(r.record), exportKey: bytes(r.export_key))
    }

    static func clientInit(_ password: [UInt8]) throws -> Ke1 {
        var r = withPtrs([password]) { p in cryptolib_opaque_client_init(p[0].0, p[0].1) }
        defer { cryptolib_opaque_ke1_free(&r) }
        if let e = r.error { throw OpaqueError.failed(String(cString: e)) }
        return Ke1(ke1: bytes(r.ke1), clientState: bytes(r.client_state))
    }

    static func serverRespond(context: [UInt8], serverPrivateKey: [UInt8], serverPublicKey: [UInt8],
                              record: [UInt8], credentialIdentifier: [UInt8], oprfSeed: [UInt8], ke1: [UInt8],
                              serverIdentity: [UInt8]? = nil, clientIdentity: [UInt8]? = nil) throws -> Ke2 {
        var r = withPtrs([context, serverPrivateKey, serverPublicKey, record, credentialIdentifier, oprfSeed, ke1, serverIdentity, clientIdentity]) { p in
            cryptolib_opaque_server_respond(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1,
                p[4].0, p[4].1, p[5].0, p[5].1, p[6].0, p[6].1, p[7].0, p[7].1, p[8].0, p[8].1)
        }
        defer { cryptolib_opaque_ke2_free(&r) }
        if let e = r.error { throw OpaqueError.failed(String(cString: e)) }
        return Ke2(ke2: bytes(r.ke2), serverState: bytes(r.server_state))
    }

    /// Authenticates the server; throws on a wrong password / server auth failure.
    static func clientFinish(clientState: [UInt8], ke2: [UInt8], context: [UInt8],
                             serverIdentity: [UInt8]? = nil, clientIdentity: [UInt8]? = nil) throws -> Ke3 {
        var r = withPtrs([clientState, ke2, context, serverIdentity, clientIdentity]) { p in
            cryptolib_opaque_client_finish(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1)
        }
        defer { cryptolib_opaque_ke3_free(&r) }
        if let e = r.error { throw OpaqueError.failed(String(cString: e)) }
        return Ke3(ke3: bytes(r.ke3), sessionKey: bytes(r.session_key), exportKey: bytes(r.export_key))
    }

    static func serverFinish(serverState: [UInt8], ke3: [UInt8]) throws -> [UInt8] {
        try withPtrs([serverState, ke3]) { p in try opaqueConsume(cryptolib_opaque_server_finish(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
}

// ── smoke (compiled/run by `make swift-opaque`) ──────────────────────────────
guard cryptolib_init() == 0 else { fatalError("init failed") }
print("CryptoLib \(String(cString: cryptolib_version())) — OPAQUE aPAKE (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }

func rand(_ n: Int) -> [UInt8] { var b = [UInt8](repeating: 0, count: n); _ = SecRandomCopyBytes(kSecRandomDefault, n, &b); return b }

do {
    let password = Array("hunter2".utf8)
    let oprfSeed = rand(64)
    // a valid ristretto255 DH keypair via OPRF DeriveKeyPair
    var skp = withPtrs([rand(32)]) { p in cryptolib_oprf_derive_keypair(p[0].0, p[0].1, nil, 0) }
    let serverPub = bytes(skp.public_key), serverPriv = bytes(skp.secret_key)
    cryptolib_keypair_free(&skp)
    let credID = Array("id".utf8), ctx = Array("app".utf8)

    let rr = try Opaque.registrationRequest(password)
    let resp = try Opaque.registrationResponse(request: rr.request, serverPublicKey: serverPub, credentialIdentifier: credID, oprfSeed: oprfSeed)
    let rec = try Opaque.finalizeRequest(password: password, blind: rr.blind, response: resp)
    ck("registration record/export", rec.record.count == 192 && rec.exportKey.count == 64)

    let ke1 = try Opaque.clientInit(password)
    let ke2 = try Opaque.serverRespond(context: ctx, serverPrivateKey: serverPriv, serverPublicKey: serverPub, record: rec.record, credentialIdentifier: credID, oprfSeed: oprfSeed, ke1: ke1.ke1)
    let ke3 = try Opaque.clientFinish(clientState: ke1.clientState, ke2: ke2.ke2, context: ctx)
    let sk = try Opaque.serverFinish(serverState: ke2.serverState, ke3: ke3.ke3)
    ck("session keys match", sk == ke3.sessionKey)
    ck("export key matches registration", ke3.exportKey == rec.exportKey)

    let ke1b = try Opaque.clientInit(Array("wrongpw".utf8))
    let ke2b = try Opaque.serverRespond(context: ctx, serverPrivateKey: serverPriv, serverPublicKey: serverPub, record: rec.record, credentialIdentifier: credID, oprfSeed: oprfSeed, ke1: ke1b.ke1)
    var rejected = false
    do { _ = try Opaque.clientFinish(clientState: ke1b.clientState, ke2: ke2b.ke2, context: ctx) } catch { rejected = true }
    ck("wrong password rejected", rejected)
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — OPAQUE \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
