/*
 * Validated-module cryptography for the CipherBird plugin on Apple platforms,
 * reached from Dart through dart:ffi (DynamicLibrary.process) by the @_cdecl
 * names below.
 *
 * Every operation here is performed by CryptoKit, CommonCrypto or the
 * Security framework, which Apple implements on top of corecrypto, the
 * module Apple submits to the CMVP (certificate numbers per OS release are
 * listed in docs/AUDIT_SCOPE.md). Nothing in this file touches the bundled
 * engine, so an app that stays on these entry points keeps its approved
 * operations inside Apple's module. Wire formats match the engine's fips
 * profile: AES-256-GCM is nonce(12) | ciphertext | tag(16); P-256 public
 * keys are 65-byte uncompressed points, private keys 32-byte scalars,
 * signatures DER.
 *
 * Every function returns 0 on success or a negative status; output buffers
 * are allocated here and released through cipherbird_fips_free.
 */
import Foundation
import Security
import CommonCrypto
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Objective-C visible on purpose: the -ObjC linker flag keeps this object
/// file, and with it the @_cdecl functions, inside a statically linked app.
@objc(CipherbirdFipsAnchor)
public final class CipherbirdFipsAnchor: NSObject {
    @objc public static let functions: [String] = [
        "cipherbird_fips_module", "cipherbird_fips_digest", "cipherbird_fips_hmac",
        "cipherbird_fips_hkdf", "cipherbird_fips_pbkdf2", "cipherbird_fips_random",
        "cipherbird_fips_aes_gcm_encrypt", "cipherbird_fips_aes_gcm_decrypt",
        "cipherbird_fips_p256_keygen", "cipherbird_fips_p256_ecdh", "cipherbird_fips_p256_sign",
        "cipherbird_fips_p256_verify", "cipherbird_fips_p256_public_key", "cipherbird_fips_free",
    ]
}

private enum FipsStatus: Int32 {
    case ok = 0
    case unsupported = -1
    case authenticationFailed = -4
    case failed = -5
    case badArgument = -6
}

private func bytes(_ p: UnsafePointer<UInt8>?, _ n: Int) -> Data {
    guard let p = p, n > 0 else { return Data() }
    return Data(bytes: p, count: n)
}

private func emit(_ out: Data, _ outPtr: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                  _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let outPtr = outPtr, let outLen = outLen else { return FipsStatus.badArgument.rawValue }
    let block = UnsafeMutablePointer<UInt8>.allocate(capacity: max(out.count, 1))
    out.copyBytes(to: block, count: out.count)
    outPtr.pointee = block
    outLen.pointee = out.count
    return FipsStatus.ok.rawValue
}

/// Wipes and releases a buffer returned by any function in this file.
@_cdecl("cipherbird_fips_free")
public func cipherbird_fips_free(_ p: UnsafeMutablePointer<UInt8>?, _ n: Int) {
    guard let p = p else { return }
    if n > 0 { memset_s(p, n, 0, n) }
    p.deallocate()
}

/// "corecrypto via CryptoKit; <OS> <version>": what performs the operations.
@_cdecl("cipherbird_fips_module")
public func cipherbird_fips_module(_ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                   _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    #if os(iOS)
    let os = "iOS"
    #elseif os(macOS)
    let os = "macOS"
    #else
    let os = "Apple"
    #endif
    let v = ProcessInfo.processInfo.operatingSystemVersion
    let text = "corecrypto via CryptoKit; \(os) \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    return emit(Data(text.utf8), out, outLen)
}

private func digest(_ hash: Int32, _ d: Data) -> Data? {
    switch hash {
    case 0: return Data(SHA256.hash(data: d))
    case 1: return Data(SHA384.hash(data: d))
    case 2: return Data(SHA512.hash(data: d))
    default: return nil
    }
}

@_cdecl("cipherbird_fips_digest")
public func cipherbird_fips_digest(_ hash: Int32, _ data: UnsafePointer<UInt8>?, _ n: Int,
                                   _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                   _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let d = digest(hash, bytes(data, n)) else { return FipsStatus.unsupported.rawValue }
    return emit(d, out, outLen)
}

private func mac<H: HashFunction>(_: H.Type, _ key: Data, _ d: Data) -> Data {
    Data(HMAC<H>.authenticationCode(for: d, using: SymmetricKey(data: key)))
}

@_cdecl("cipherbird_fips_hmac")
public func cipherbird_fips_hmac(_ hash: Int32, _ key: UnsafePointer<UInt8>?, _ keyLen: Int,
                                 _ data: UnsafePointer<UInt8>?, _ n: Int,
                                 _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                 _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard keyLen >= 14 else { return FipsStatus.badArgument.rawValue }
    let k = bytes(key, keyLen), d = bytes(data, n)
    let tag: Data
    switch hash {
    case 0: tag = mac(SHA256.self, k, d)
    case 1: tag = mac(SHA384.self, k, d)
    case 2: tag = mac(SHA512.self, k, d)
    default: return FipsStatus.unsupported.rawValue
    }
    return emit(tag, out, outLen)
}

private func hkdf<H: HashFunction>(_: H.Type, _ ikm: Data, _ salt: Data, _ info: Data, _ count: Int) -> Data {
    let key = HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: count)
    return key.withUnsafeBytes { Data($0) }
}

@_cdecl("cipherbird_fips_hkdf")
public func cipherbird_fips_hkdf(_ hash: Int32, _ ikm: UnsafePointer<UInt8>?, _ ikmLen: Int,
                                 _ salt: UnsafePointer<UInt8>?, _ saltLen: Int,
                                 _ info: UnsafePointer<UInt8>?, _ infoLen: Int, _ count: Int,
                                 _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                 _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard ikmLen > 0, count >= 14, count <= 255 * 64 else { return FipsStatus.badArgument.rawValue }
    let i = bytes(ikm, ikmLen), s = bytes(salt, saltLen), f = bytes(info, infoLen)
    let okm: Data
    switch hash {
    case 0: okm = hkdf(SHA256.self, i, s, f, count)
    case 1: okm = hkdf(SHA384.self, i, s, f, count)
    case 2: okm = hkdf(SHA512.self, i, s, f, count)
    default: return FipsStatus.unsupported.rawValue
    }
    return emit(okm, out, outLen)
}

@_cdecl("cipherbird_fips_pbkdf2")
public func cipherbird_fips_pbkdf2(_ hash: Int32, _ password: UnsafePointer<UInt8>?, _ passwordLen: Int,
                                   _ salt: UnsafePointer<UInt8>?, _ saltLen: Int, _ iterations: UInt32, _ count: Int,
                                   _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                   _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard saltLen >= 16, iterations >= 1000, count >= 14 else { return FipsStatus.badArgument.rawValue }
    let prf: CCPseudoRandomAlgorithm
    switch hash {
    case 0: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
    case 1: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
    case 2: prf = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
    default: return FipsStatus.unsupported.rawValue
    }
    var derived = Data(count: count)
    let s = bytes(salt, saltLen)
    let status = derived.withUnsafeMutableBytes { dk -> Int32 in
        s.withUnsafeBytes { sp -> Int32 in
            password!.withMemoryRebound(to: CChar.self, capacity: max(passwordLen, 1)) { pw in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, passwordLen,
                                     sp.bindMemory(to: UInt8.self).baseAddress, saltLen, prf, iterations,
                                     dk.bindMemory(to: UInt8.self).baseAddress, count)
            }
        }
    }
    guard status == kCCSuccess else { return FipsStatus.failed.rawValue }
    return emit(derived, out, outLen)
}

@_cdecl("cipherbird_fips_random")
public func cipherbird_fips_random(_ count: Int,
                                   _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                   _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard count > 0, count <= 1 << 20 else { return FipsStatus.badArgument.rawValue }
    var buf = Data(count: count)
    let status = buf.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    guard status == errSecSuccess else { return FipsStatus.failed.rawValue }
    return emit(buf, out, outLen)
}

@_cdecl("cipherbird_fips_aes_gcm_encrypt")
public func cipherbird_fips_aes_gcm_encrypt(_ key: UnsafePointer<UInt8>?, _ keyLen: Int,
                                            _ pt: UnsafePointer<UInt8>?, _ ptLen: Int,
                                            _ aad: UnsafePointer<UInt8>?, _ aadLen: Int,
                                            _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                            _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard keyLen == 32 else { return FipsStatus.badArgument.rawValue }
    do {
        let box = try AES.GCM.seal(bytes(pt, ptLen), using: SymmetricKey(data: bytes(key, keyLen)),
                                   authenticating: bytes(aad, aadLen))
        guard let wire = box.combined else { return FipsStatus.failed.rawValue }
        return emit(wire, out, outLen)
    } catch {
        return FipsStatus.failed.rawValue
    }
}

@_cdecl("cipherbird_fips_aes_gcm_decrypt")
public func cipherbird_fips_aes_gcm_decrypt(_ key: UnsafePointer<UInt8>?, _ keyLen: Int,
                                            _ wire: UnsafePointer<UInt8>?, _ wireLen: Int,
                                            _ aad: UnsafePointer<UInt8>?, _ aadLen: Int,
                                            _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                            _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard keyLen == 32, wireLen >= 28 else { return FipsStatus.badArgument.rawValue }
    do {
        let box = try AES.GCM.SealedBox(combined: bytes(wire, wireLen))
        let pt = try AES.GCM.open(box, using: SymmetricKey(data: bytes(key, keyLen)), authenticating: bytes(aad, aadLen))
        return emit(pt, out, outLen)
    } catch {
        return FipsStatus.authenticationFailed.rawValue
    }
}

@_cdecl("cipherbird_fips_p256_keygen")
public func cipherbird_fips_p256_keygen(_ pub: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                        _ pubLen: UnsafeMutablePointer<Int>?,
                                        _ priv: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                        _ privLen: UnsafeMutablePointer<Int>?) -> Int32 {
    let key = P256.KeyAgreement.PrivateKey()
    let s = emit(key.publicKey.x963Representation, pub, pubLen)
    guard s == FipsStatus.ok.rawValue else { return s }
    return emit(key.rawRepresentation, priv, privLen)
}

@_cdecl("cipherbird_fips_p256_ecdh")
public func cipherbird_fips_p256_ecdh(_ priv: UnsafePointer<UInt8>?, _ privLen: Int,
                                      _ peer: UnsafePointer<UInt8>?, _ peerLen: Int,
                                      _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                      _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    do {
        let mine = try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes(priv, privLen))
        let theirs = try P256.KeyAgreement.PublicKey(x963Representation: bytes(peer, peerLen))
        let shared = try mine.sharedSecretFromKeyAgreement(with: theirs)
        return emit(shared.withUnsafeBytes { Data($0) }, out, outLen)
    } catch {
        return FipsStatus.badArgument.rawValue
    }
}

@_cdecl("cipherbird_fips_p256_sign")
public func cipherbird_fips_p256_sign(_ priv: UnsafePointer<UInt8>?, _ privLen: Int,
                                      _ msg: UnsafePointer<UInt8>?, _ msgLen: Int,
                                      _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                      _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    do {
        let key = try P256.Signing.PrivateKey(rawRepresentation: bytes(priv, privLen))
        let sig = try key.signature(for: bytes(msg, msgLen))
        return emit(sig.derRepresentation, out, outLen)
    } catch {
        return FipsStatus.badArgument.rawValue
    }
}

/// 1 when the DER signature verifies, 0 otherwise.
@_cdecl("cipherbird_fips_p256_verify")
public func cipherbird_fips_p256_verify(_ pub: UnsafePointer<UInt8>?, _ pubLen: Int,
                                        _ msg: UnsafePointer<UInt8>?, _ msgLen: Int,
                                        _ sig: UnsafePointer<UInt8>?, _ sigLen: Int) -> Int32 {
    do {
        let key = try P256.Signing.PublicKey(x963Representation: bytes(pub, pubLen))
        let signature = try P256.Signing.ECDSASignature(derRepresentation: bytes(sig, sigLen))
        return key.isValidSignature(signature, for: bytes(msg, msgLen)) ? 1 : 0
    } catch {
        return 0
    }
}

@_cdecl("cipherbird_fips_p256_public_key")
public func cipherbird_fips_p256_public_key(_ priv: UnsafePointer<UInt8>?, _ privLen: Int,
                                            _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                            _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    do {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes(priv, privLen))
        return emit(key.publicKey.x963Representation, out, outLen)
    } catch {
        return FipsStatus.badArgument.rawValue
    }
}
