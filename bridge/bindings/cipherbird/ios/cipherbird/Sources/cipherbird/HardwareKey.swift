// Hardware-backed key wrapping for the CipherBird plugin, reached from Dart
// through dart:ffi (DynamicLibrary.process) by the @_cdecl names below.
//
// A P-256 key is generated inside the Secure Enclave and never leaves it.
// The Dart side hands it 32-byte keyring factors to wrap (ECIES, cofactor
// X9.63 SHA-256 AES-GCM) and gets the wrapped bytes back; unwrapping runs
// in the enclave and, for keys created with biometric gating, only after the
// user passed the system biometric prompt. App Attest produces a separate
// attested key whose assertion binds the enclave public key to a challenge.
//
// Every function returns 0 on success or a negative code from the table in
// HardwareKeyStatus; output buffers are malloc-owned and freed through
// cipherbird_hw_free.
import Foundation
import Security
import LocalAuthentication
#if canImport(DeviceCheck)
import DeviceCheck
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Objective-C visible on purpose: the -ObjC linker flag loads every object
/// file that defines an Objective-C class, which is what keeps the @_cdecl
/// functions in this file inside a statically linked app.
@objc(CipherbirdHardwareKeyAnchor)
public final class CipherbirdHardwareKeyAnchor: NSObject {
    @objc public static let functions: [String] = [
        "cipherbird_hw_create", "cipherbird_hw_exists", "cipherbird_hw_delete",
        "cipherbird_hw_backing", "cipherbird_hw_public_key", "cipherbird_hw_wrap",
        "cipherbird_hw_unwrap", "cipherbird_hw_attest", "cipherbird_hw_free",
    ]
}

private enum HardwareKeyStatus: Int32 {
    case ok = 0
    case unsupported = -1
    case notFound = -2
    case exists = -3
    case authenticationFailed = -4
    case failed = -5
    case badArgument = -6
}

private let keyTagPrefix = "dev.cipherbird.hardware."
private let attestKeyService = "dev.cipherbird.hardware.attest"
private let eciesAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

/// The last platform error, for the Dart side's exception message.
private var lastError = ""

private func fail(_ error: Unmanaged<CFError>?) -> Int32 {
    if let error = error?.takeRetainedValue() {
        lastError = String(describing: error)
    }
    return HardwareKeyStatus.failed.rawValue
}

/// The description of the last failure, as bytes the caller frees.
@_cdecl("cipherbird_hw_last_error")
public func cipherbird_hw_last_error(_ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                     _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    emit(Data(lastError.utf8), out, outLen)
}

private func tag(for label: String) -> Data {
    Data((keyTagPrefix + label).utf8)
}

private func string(_ p: UnsafePointer<CChar>?) -> String? {
    guard let p = p else { return nil }
    return String(cString: p)
}

private func data(_ p: UnsafePointer<UInt8>?, _ n: Int) -> Data {
    guard let p = p, n > 0 else { return Data() }
    return Data(bytes: p, count: n)
}

/// Copies `bytes` into a malloc block the caller frees with cipherbird_hw_free.
private func emit(_ bytes: Data, _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let out = out, let outLen = outLen else { return HardwareKeyStatus.badArgument.rawValue }
    let block = UnsafeMutablePointer<UInt8>.allocate(capacity: max(bytes.count, 1))
    bytes.copyBytes(to: block, count: bytes.count)
    out.pointee = block
    outLen.pointee = bytes.count
    return HardwareKeyStatus.ok.rawValue
}

#if targetEnvironment(simulator)
private let enclaveAvailable = false
#else
private let enclaveAvailable = true
#endif

/// macOS keeps Secure Enclave keys only in the data protection keychain,
/// which needs the host app signed with a team identifier.
private func dataProtection(_ dict: inout [String: Any]) {
    #if os(macOS)
    dict[kSecUseDataProtectionKeychain as String] = true
    #endif
}

private func findKey(_ label: String, context: LAContext? = nil) -> SecKey? {
    var query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag(for: label),
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true,
    ]
    dataProtection(&query)
    if let context = context {
        query[kSecUseAuthenticationContext as String] = context
    }
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item = item else { return nil }
    return (item as! SecKey)
}

/// Creates the key for `label`. `biometric` nonzero requires the current
/// biometric set for every unwrap. Returns `exists` if it is already there.
@_cdecl("cipherbird_hw_create")
public func cipherbird_hw_create(_ labelPtr: UnsafePointer<CChar>?, _ biometric: Int32) -> Int32 {
    guard let label = string(labelPtr), !label.isEmpty else { return HardwareKeyStatus.badArgument.rawValue }
    if findKey(label) != nil { return HardwareKeyStatus.exists.rawValue }
    var flags: SecAccessControlCreateFlags = enclaveAvailable ? [.privateKeyUsage] : []
    if biometric != 0 { flags.insert(.biometryCurrentSet) }
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
        return fail(error)
    }
    var privateAttrs: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag(for: label),
        kSecAttrAccessControl as String: access,
    ]
    var attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
    ]
    if enclaveAvailable {
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }
    attrs[kSecPrivateKeyAttrs as String] = privateAttrs
    dataProtection(&attrs)
    guard SecKeyCreateRandomKey(attrs as CFDictionary, &error) != nil else {
        return fail(error)
    }
    return HardwareKeyStatus.ok.rawValue
}

/// 1 when the key for `label` exists, 0 when not.
@_cdecl("cipherbird_hw_exists")
public func cipherbird_hw_exists(_ labelPtr: UnsafePointer<CChar>?) -> Int32 {
    guard let label = string(labelPtr) else { return 0 }
    return findKey(label) != nil ? 1 : 0
}

/// Removes the key for `label` and its App Attest key id.
@_cdecl("cipherbird_hw_delete")
public func cipherbird_hw_delete(_ labelPtr: UnsafePointer<CChar>?) -> Int32 {
    guard let label = string(labelPtr) else { return HardwareKeyStatus.badArgument.rawValue }
    var query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag(for: label),
    ]
    dataProtection(&query)
    let status = SecItemDelete(query as CFDictionary)
    let attest: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: attestKeyService,
        kSecAttrAccount as String: label,
    ]
    SecItemDelete(attest as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound
        ? HardwareKeyStatus.ok.rawValue : HardwareKeyStatus.failed.rawValue
}

/// Where the key for `label` lives: 1 Secure Enclave, 2 software (simulator
/// only), 0 unknown or missing.
@_cdecl("cipherbird_hw_backing")
public func cipherbird_hw_backing(_ labelPtr: UnsafePointer<CChar>?) -> Int32 {
    guard let label = string(labelPtr), findKey(label) != nil else { return 0 }
    return enclaveAvailable ? 1 : 2
}

/// The X9.63 public key of `label` (65 bytes), for attestation binding.
@_cdecl("cipherbird_hw_public_key")
public func cipherbird_hw_public_key(_ labelPtr: UnsafePointer<CChar>?,
                                     _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                     _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let label = string(labelPtr), let key = findKey(label) else { return HardwareKeyStatus.notFound.rawValue }
    guard let pub = SecKeyCopyPublicKey(key) else { return HardwareKeyStatus.failed.rawValue }
    var error: Unmanaged<CFError>?
    guard let rep = SecKeyCopyExternalRepresentation(pub, &error) as Data? else { return HardwareKeyStatus.failed.rawValue }
    return emit(rep, out, outLen)
}

/// Wraps `input` under the public half of `label`; no user interaction.
@_cdecl("cipherbird_hw_wrap")
public func cipherbird_hw_wrap(_ labelPtr: UnsafePointer<CChar>?,
                               _ input: UnsafePointer<UInt8>?, _ inputLen: Int,
                               _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                               _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let label = string(labelPtr), inputLen > 0 else { return HardwareKeyStatus.badArgument.rawValue }
    guard let key = findKey(label) else { return HardwareKeyStatus.notFound.rawValue }
    guard let pub = SecKeyCopyPublicKey(key), SecKeyIsAlgorithmSupported(pub, .encrypt, eciesAlgorithm) else {
        return HardwareKeyStatus.unsupported.rawValue
    }
    var error: Unmanaged<CFError>?
    guard let wrapped = SecKeyCreateEncryptedData(pub, eciesAlgorithm, data(input, inputLen) as CFData, &error) as Data? else {
        return fail(error)
    }
    return emit(wrapped, out, outLen)
}

/// Unwraps `input` inside the enclave. A biometric-gated key shows the system
/// prompt with `reason`; a failed or cancelled prompt returns
/// `authenticationFailed`.
@_cdecl("cipherbird_hw_unwrap")
public func cipherbird_hw_unwrap(_ labelPtr: UnsafePointer<CChar>?,
                                 _ input: UnsafePointer<UInt8>?, _ inputLen: Int,
                                 _ reasonPtr: UnsafePointer<CChar>?,
                                 _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                 _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let label = string(labelPtr), inputLen > 0 else { return HardwareKeyStatus.badArgument.rawValue }
    let context = LAContext()
    context.localizedReason = string(reasonPtr) ?? "Unlock your keys"
    guard let key = findKey(label, context: context) else { return HardwareKeyStatus.notFound.rawValue }
    var error: Unmanaged<CFError>?
    guard let plain = SecKeyCreateDecryptedData(key, eciesAlgorithm, data(input, inputLen) as CFData, &error) as Data? else {
        if let error = error?.takeRetainedValue() as Error? {
            let code = (error as NSError).code
            if code == Int(errSecUserCanceled) || code == Int(errSecAuthFailed) || code == Int(errSecInteractionNotAllowed) {
                return HardwareKeyStatus.authenticationFailed.rawValue
            }
        }
        return fail(error)
    }
    return emit(plain, out, outLen)
}

/// App Attest: creates (once) an attested key for `label` and returns the
/// attestation object for the server, computed over
/// SHA-256(challenge || enclave public key). The output starts with the
/// attested key id as a NUL-terminated string, followed by the attestation.
@_cdecl("cipherbird_hw_attest")
public func cipherbird_hw_attest(_ labelPtr: UnsafePointer<CChar>?,
                                 _ challenge: UnsafePointer<UInt8>?, _ challengeLen: Int,
                                 _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
                                 _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    #if canImport(DeviceCheck) && canImport(CryptoKit) && !targetEnvironment(simulator)
    guard let label = string(labelPtr), challengeLen > 0 else { return HardwareKeyStatus.badArgument.rawValue }
    if #available(iOS 14.0, macOS 11.0, *) {
        let service = DCAppAttestService.shared
        guard service.isSupported else { return HardwareKeyStatus.unsupported.rawValue }
        guard let key = findKey(label), let pub = SecKeyCopyPublicKey(key),
              let rep = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
            return HardwareKeyStatus.notFound.rawValue
        }
        var bound = data(challenge, challengeLen)
        bound.append(rep)
        let clientDataHash = Data(SHA256.hash(data: bound))
        let gate = DispatchSemaphore(value: 0)
        var keyId: String?
        var attestation: Data?
        var failed = false
        service.generateKey { id, _ in
            keyId = id
            guard let id = id else { failed = true; gate.signal(); return }
            service.attestKey(id, clientDataHash: clientDataHash) { att, _ in
                attestation = att
                failed = att == nil
                gate.signal()
            }
        }
        gate.wait()
        guard !failed, let id = keyId, let att = attestation else { return HardwareKeyStatus.failed.rawValue }
        let record: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: attestKeyService,
            kSecAttrAccount as String: label,
            kSecValueData as String: Data(id.utf8),
        ]
        SecItemDelete(record as CFDictionary)
        SecItemAdd(record as CFDictionary, nil)
        var payload = Data(id.utf8)
        payload.append(0)
        payload.append(att)
        return emit(payload, out, outLen)
    }
    return HardwareKeyStatus.unsupported.rawValue
    #else
    _ = labelPtr; _ = challenge; _ = challengeLen; _ = out; _ = outLen
    return HardwareKeyStatus.unsupported.rawValue
    #endif
}

/// Frees a buffer returned by the functions above, zeroing it first.
@_cdecl("cipherbird_hw_free")
public func cipherbird_hw_free(_ p: UnsafeMutablePointer<UInt8>?, _ n: Int) {
    guard let p = p else { return }
    if n > 0 { p.update(repeating: 0, count: n) }
    p.deallocate()
}
