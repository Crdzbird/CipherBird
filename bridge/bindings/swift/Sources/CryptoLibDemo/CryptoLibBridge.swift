import Foundation
import Observation
import CryptoLibC

// MARK: - Bridge Error

enum CryptoLibError: LocalizedError {
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .operationFailed(let msg): return msg
        }
    }
}

// MARK: - Data Helpers

extension Data {
    /// Hex-encode bytes.
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Truncated hex for display.
    func hexTruncated(_ maxBytes: Int = 16) -> String {
        let full = hexString
        if count <= maxBytes { return full }
        return String(full.prefix(maxBytes * 2)) + "..."
    }
}

// MARK: - Internal Helpers

/// Copy a CryptoBuffer into Data and free the C buffer.
private func copyAndFree(_ buf: inout CryptoBuffer) -> Data {
    guard let ptr = buf.data, buf.len > 0 else { return Data() }
    let data = Data(bytes: ptr, count: buf.len)
    cryptolib_buffer_free(&buf)
    return data
}

/// Check a CryptoBufferResult and return Data or throw.
private func check(_ result: inout CryptoBufferResult) throws -> Data {
    if let err = result.error {
        let msg = String(cString: err)
        cryptolib_str_free(err)
        throw CryptoLibError.operationFailed(msg)
    }
    return copyAndFree(&result.buf)
}

/// Check an error pointer.
private func checkError(_ errPtr: UnsafeMutablePointer<CChar>?) throws {
    if let err = errPtr {
        let msg = String(cString: err)
        cryptolib_str_free(err)
        throw CryptoLibError.operationFailed(msg)
    }
}

// MARK: - Swift Result Types

struct KeyPairResult {
    let publicKey: Data
    let secretKey: Data
}

struct DerivedKeysResult {
    let symmetricKey: Data
    let vaultMasterKey: Data
    let signingSeed: Data
    let boxSeed: Data
    let streamKey: Data
    let rawEntropy: Data
}

struct EntropyInfoResult {
    let path: String
    let fileSize: UInt64
    let chunksRead: UInt64
    let entropyBits: Double
}

struct PacketResult {
    let ciphertext: Data
    let signature: Data
    let kdfSalt: Data
}

// MARK: - CryptoLib Bridge

@Observable
final class CryptoLibBridge {
    var isLoaded = false
    var libraryVersion: String = "unknown"

    /// Initialize the library. Call once at app launch.
    func load() throws {
        let rc = cryptolib_init()
        if rc != 0 {
            throw CryptoLibError.operationFailed("cryptolib_init failed: \(rc)")
        }
        if let v = cryptolib_version() {
            libraryVersion = String(cString: v)
        }
        isLoaded = true
    }

    // MARK: - Random Bytes

    func randomBytes(_ n: Int) throws -> Data {
        var r = cryptolib_random_bytes(n)
        return try check(&r)
    }

    // MARK: - Hashing

    func blake2b(_ msg: Data, key: Data? = nil) throws -> Data {
        return try msg.withUnsafeBytes { msgPtr in
            let msgBase = msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            if let key = key {
                return try key.withUnsafeBytes { keyPtr in
                    let keyBase = keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    var r = cryptolib_blake2b(msgBase, msg.count, keyBase, key.count)
                    return try check(&r)
                }
            } else {
                var r = cryptolib_blake2b(msgBase, msg.count, nil, 0)
                return try check(&r)
            }
        }
    }

    func sha256(_ msg: Data) throws -> Data {
        return try msg.withUnsafeBytes { ptr in
            var r = cryptolib_sha256(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count)
            return try check(&r)
        }
    }

    func sha512(_ msg: Data) throws -> Data {
        return try msg.withUnsafeBytes { ptr in
            var r = cryptolib_sha512(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count)
            return try check(&r)
        }
    }

    func hmacSha512(_ msg: Data, key: Data) throws -> Data {
        return try msg.withUnsafeBytes { msgPtr in
            try key.withUnsafeBytes { keyPtr in
                var r = cryptolib_hmac_sha512(
                    msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                    keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count)
                return try check(&r)
            }
        }
    }

    func argon2idHashStr(_ password: String, ops: UInt64 = 2, mem: Int = 67108864) throws -> String {
        var r = cryptolib_argon2id_hash_str(password, ops, mem)
        let data = try check(&r)
        return String(data: data, encoding: .utf8) ?? ""
    }

    func argon2idVerifyStr(_ password: String, phcStr: String) -> Bool {
        return cryptolib_argon2id_verify_str(password, phcStr) == 1
    }

    // MARK: - Symmetric Encryption

    func symKeygen() throws -> Data {
        var r = cryptolib_sym_keygen()
        return try check(&r)
    }

    func xchacha20Encrypt(_ plaintext: Data, key: Data, aad: Data? = nil) throws -> Data {
        return try plaintext.withUnsafeBytes { ptPtr in
            try key.withUnsafeBytes { keyPtr in
                let pt = ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                let k = keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                if let aad = aad {
                    return try aad.withUnsafeBytes { aadPtr in
                        var r = cryptolib_xchacha20_encrypt(
                            pt, plaintext.count, k, key.count,
                            aadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), aad.count)
                        return try check(&r)
                    }
                } else {
                    var r = cryptolib_xchacha20_encrypt(pt, plaintext.count, k, key.count, nil, 0)
                    return try check(&r)
                }
            }
        }
    }

    func xchacha20Decrypt(_ ciphertext: Data, key: Data, aad: Data? = nil) throws -> Data {
        return try ciphertext.withUnsafeBytes { ctPtr in
            try key.withUnsafeBytes { keyPtr in
                let ct = ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                let k = keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                if let aad = aad {
                    return try aad.withUnsafeBytes { aadPtr in
                        var r = cryptolib_xchacha20_decrypt(
                            ct, ciphertext.count, k, key.count,
                            aadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), aad.count)
                        return try check(&r)
                    }
                } else {
                    var r = cryptolib_xchacha20_decrypt(ct, ciphertext.count, k, key.count, nil, 0)
                    return try check(&r)
                }
            }
        }
    }

    func aes256gcmAvailable() -> Bool {
        return cryptolib_aes256gcm_available() == 1
    }

    func aes256gcmEncrypt(_ plaintext: Data, key: Data, aad: Data? = nil) throws -> Data {
        return try plaintext.withUnsafeBytes { ptPtr in
            try key.withUnsafeBytes { keyPtr in
                let pt = ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                let k = keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                if let aad = aad {
                    return try aad.withUnsafeBytes { aadPtr in
                        var r = cryptolib_aes256gcm_encrypt(
                            pt, plaintext.count, k, key.count,
                            aadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), aad.count)
                        return try check(&r)
                    }
                } else {
                    var r = cryptolib_aes256gcm_encrypt(pt, plaintext.count, k, key.count, nil, 0)
                    return try check(&r)
                }
            }
        }
    }

    func aes256gcmDecrypt(_ ciphertext: Data, key: Data, aad: Data? = nil) throws -> Data {
        return try ciphertext.withUnsafeBytes { ctPtr in
            try key.withUnsafeBytes { keyPtr in
                let ct = ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                let k = keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                if let aad = aad {
                    return try aad.withUnsafeBytes { aadPtr in
                        var r = cryptolib_aes256gcm_decrypt(
                            ct, ciphertext.count, k, key.count,
                            aadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), aad.count)
                        return try check(&r)
                    }
                } else {
                    var r = cryptolib_aes256gcm_decrypt(ct, ciphertext.count, k, key.count, nil, 0)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - Ed25519

    func ed25519Keygen() -> KeyPairResult {
        var kp = cryptolib_ed25519_keygen()
        return KeyPairResult(
            publicKey: copyAndFree(&kp.public_key),
            secretKey: copyAndFree(&kp.secret_key))
    }

    func ed25519Sign(_ msg: Data, secretKey: Data) throws -> Data {
        return try msg.withUnsafeBytes { msgPtr in
            try secretKey.withUnsafeBytes { skPtr in
                var r = cryptolib_ed25519_sign(
                    msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                    skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), secretKey.count)
                return try check(&r)
            }
        }
    }

    func ed25519Verify(_ msg: Data, sig: Data, publicKey: Data) -> Bool {
        return msg.withUnsafeBytes { msgPtr in
            sig.withUnsafeBytes { sigPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    cryptolib_ed25519_verify(
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                        sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), sig.count,
                        pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), publicKey.count) == 1
                }
            }
        }
    }

    // MARK: - Box

    func boxKeygen() -> KeyPairResult {
        var kp = cryptolib_box_keygen()
        return KeyPairResult(
            publicKey: copyAndFree(&kp.public_key),
            secretKey: copyAndFree(&kp.secret_key))
    }

    func boxEncrypt(_ plaintext: Data, recipientPub: Data, senderSec: Data) throws -> Data {
        return try plaintext.withUnsafeBytes { ptPtr in
            try recipientPub.withUnsafeBytes { rpPtr in
                try senderSec.withUnsafeBytes { ssPtr in
                    var r = cryptolib_box_encrypt(
                        ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), plaintext.count,
                        rpPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), recipientPub.count,
                        ssPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), senderSec.count)
                    return try check(&r)
                }
            }
        }
    }

    func boxDecrypt(_ ciphertext: Data, senderPub: Data, recipientSec: Data) throws -> Data {
        return try ciphertext.withUnsafeBytes { ctPtr in
            try senderPub.withUnsafeBytes { spPtr in
                try recipientSec.withUnsafeBytes { rsPtr in
                    var r = cryptolib_box_decrypt(
                        ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), ciphertext.count,
                        spPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), senderPub.count,
                        rsPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), recipientSec.count)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - Media Entropy

    func entropyFromFile(_ path: String, deterministic: Bool = false) throws -> CryptoEntropyHandle {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        let handle: CryptoEntropyHandle?
        if deterministic {
            handle = cryptolib_entropy_from_file_deterministic(path, &errPtr)
        } else {
            handle = cryptolib_entropy_from_file(path, &errPtr)
        }
        try checkError(errPtr)
        guard let h = handle else {
            throw CryptoLibError.operationFailed("entropy handle is nil")
        }
        return h
    }

    func entropyDeriveAll(_ handle: CryptoEntropyHandle) -> DerivedKeysResult {
        var dk = cryptolib_entropy_derive_all(handle)
        return DerivedKeysResult(
            symmetricKey: copyAndFree(&dk.symmetric_key),
            vaultMasterKey: copyAndFree(&dk.vault_master_key),
            signingSeed: copyAndFree(&dk.signing_seed),
            boxSeed: copyAndFree(&dk.box_seed),
            streamKey: copyAndFree(&dk.stream_key),
            rawEntropy: copyAndFree(&dk.raw_entropy))
    }

    func entropySymmetricKey(_ handle: CryptoEntropyHandle) throws -> Data {
        var r = cryptolib_entropy_symmetric_key(handle)
        return try check(&r)
    }

    func entropyInfo(_ handle: CryptoEntropyHandle) -> EntropyInfoResult {
        var info = cryptolib_entropy_info(handle)
        let result = EntropyInfoResult(
            path: info.path.map { String(cString: $0) } ?? "",
            fileSize: info.file_size,
            chunksRead: info.chunks_read,
            entropyBits: info.entropy_bits)
        cryptolib_entropy_info_free(&info)
        return result
    }

    func entropyRefresh(_ handle: CryptoEntropyHandle) {
        cryptolib_entropy_refresh(handle)
    }

    func entropyFree(_ handle: CryptoEntropyHandle) {
        cryptolib_entropy_free(handle)
    }

    // MARK: - Entropy Convenience

    func keyFromFile(_ path: String) throws -> Data {
        var r = cryptolib_key_from_file(path)
        return try check(&r)
    }

    func sealFromFile(_ path: String, plaintext: String, aad: String) throws -> PacketResult {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        var pkt = cryptolib_seal_from_file(path, plaintext, aad, &errPtr)
        try checkError(errPtr)
        return PacketResult(
            ciphertext: copyAndFree(&pkt.ciphertext),
            signature: copyAndFree(&pkt.signature),
            kdfSalt: copyAndFree(&pkt.kdf_salt))
    }

    func openFromFile(_ path: String, packet: PacketResult, aad: String) throws -> Data {
        var cpkt = CryptoPacket()
        return try packet.ciphertext.withUnsafeBytes { ctPtr in
            try packet.signature.withUnsafeBytes { sigPtr in
                try packet.kdfSalt.withUnsafeBytes { saltPtr in
                    // Create mutable copies for the C struct
                    let ctCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.ciphertext.count)
                    ctCopy.initialize(from: ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.ciphertext.count)
                    let sigCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.signature.count)
                    sigCopy.initialize(from: sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.signature.count)
                    let saltCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.kdfSalt.count)
                    saltCopy.initialize(from: saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.kdfSalt.count)
                    defer {
                        ctCopy.deallocate()
                        sigCopy.deallocate()
                        saltCopy.deallocate()
                    }

                    cpkt.ciphertext.data = ctCopy
                    cpkt.ciphertext.len = packet.ciphertext.count
                    cpkt.signature.data = sigCopy
                    cpkt.signature.len = packet.signature.count
                    cpkt.kdf_salt.data = saltCopy
                    cpkt.kdf_salt.len = packet.kdfSalt.count

                    var r = cryptolib_open_from_file(path, &cpkt, aad)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - Vault

    func vaultFromEntropy(_ entropyHandle: CryptoEntropyHandle, kdf: Int32 = 0) throws -> CryptoVaultHandle {
        guard let h = cryptolib_vault_from_entropy(entropyHandle, kdf) else {
            throw CryptoLibError.operationFailed("vault from entropy failed")
        }
        return h
    }

    func vaultSeal(_ vault: CryptoVaultHandle, plaintext: Data, aad: String) throws -> PacketResult {
        var errPtr: UnsafeMutablePointer<CChar>? = nil
        var pkt = plaintext.withUnsafeBytes { ptPtr in
            cryptolib_vault_seal(vault,
                ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                plaintext.count, aad, &errPtr)
        }
        try checkError(errPtr)
        return PacketResult(
            ciphertext: copyAndFree(&pkt.ciphertext),
            signature: copyAndFree(&pkt.signature),
            kdfSalt: copyAndFree(&pkt.kdf_salt))
    }

    func vaultOpen(_ vault: CryptoVaultHandle, packet: PacketResult, aad: String) throws -> Data {
        var cpkt = CryptoPacket()
        return try packet.ciphertext.withUnsafeBytes { ctPtr in
            try packet.signature.withUnsafeBytes { sigPtr in
                try packet.kdfSalt.withUnsafeBytes { saltPtr in
                    let ctCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.ciphertext.count)
                    ctCopy.initialize(from: ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.ciphertext.count)
                    let sigCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.signature.count)
                    sigCopy.initialize(from: sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.signature.count)
                    let saltCopy = UnsafeMutablePointer<UInt8>.allocate(capacity: packet.kdfSalt.count)
                    saltCopy.initialize(from: saltPtr.baseAddress!.assumingMemoryBound(to: UInt8.self), count: packet.kdfSalt.count)
                    defer {
                        ctCopy.deallocate()
                        sigCopy.deallocate()
                        saltCopy.deallocate()
                    }

                    cpkt.ciphertext.data = ctCopy
                    cpkt.ciphertext.len = packet.ciphertext.count
                    cpkt.signature.data = sigCopy
                    cpkt.signature.len = packet.signature.count
                    cpkt.kdf_salt.data = saltCopy
                    cpkt.kdf_salt.len = packet.kdfSalt.count

                    var r = cryptolib_vault_open(vault, &cpkt, aad)
                    return try check(&r)
                }
            }
        }
    }

    func vaultFree(_ vault: CryptoVaultHandle) {
        cryptolib_vault_free(vault)
    }

    // MARK: - SealedBox

    func sealedboxEncrypt(_ plaintext: Data, recipientPub: Data) throws -> Data {
        return try plaintext.withUnsafeBytes { ptPtr in
            try recipientPub.withUnsafeBytes { rpPtr in
                var r = cryptolib_sealedbox_encrypt(
                    ptPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), plaintext.count,
                    rpPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), recipientPub.count)
                return try check(&r)
            }
        }
    }

    func sealedboxDecrypt(_ ciphertext: Data, recipientPub: Data, recipientSec: Data) throws -> Data {
        return try ciphertext.withUnsafeBytes { ctPtr in
            try recipientPub.withUnsafeBytes { rpPtr in
                try recipientSec.withUnsafeBytes { rsPtr in
                    var r = cryptolib_sealedbox_decrypt(
                        ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), ciphertext.count,
                        rpPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), recipientPub.count,
                        rsPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), recipientSec.count)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - X25519

    func x25519Keygen() -> KeyPairResult {
        var kp = cryptolib_x25519_keygen()
        return KeyPairResult(
            publicKey: copyAndFree(&kp.public_key),
            secretKey: copyAndFree(&kp.secret_key))
    }

    func x25519SharedSecret(ourSecret: Data, theirPublic: Data) throws -> Data {
        return try ourSecret.withUnsafeBytes { osPtr in
            try theirPublic.withUnsafeBytes { tpPtr in
                var r = cryptolib_x25519_shared_secret(
                    osPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), ourSecret.count,
                    tpPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), theirPublic.count)
                return try check(&r)
            }
        }
    }

    // MARK: - HMAC Verify

    func hmacSha512Verify(_ msg: Data, mac: Data, key: Data) -> Bool {
        return msg.withUnsafeBytes { msgPtr in
            mac.withUnsafeBytes { macPtr in
                key.withUnsafeBytes { keyPtr in
                    cryptolib_hmac_sha512_verify(
                        msgPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                        macPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), mac.count,
                        keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count) == 1
                }
            }
        }
    }

    // MARK: - HMAC-SHA256 & HKDF-SHA256

    func hmacSha256(_ msg: Data, key: Data) throws -> Data {
        return try msg.withUnsafeBytes { m in
            try key.withUnsafeBytes { k in
                var r = cryptolib_hmac_sha256(
                    m.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                    k.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count)
                return try check(&r)
            }
        }
    }

    func hmacSha256Verify(_ msg: Data, mac: Data, key: Data) -> Bool {
        return msg.withUnsafeBytes { m in
            mac.withUnsafeBytes { t in
                key.withUnsafeBytes { k in
                    cryptolib_hmac_sha256_verify(
                        m.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                        t.baseAddress?.assumingMemoryBound(to: UInt8.self), mac.count,
                        k.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count) == 1
                }
            }
        }
    }

    /// HKDF-SHA256 extract. `salt` may be nil for the all-zero default.
    func hkdfExtract(_ ikm: Data, salt: Data? = nil) throws -> Data {
        return try ikm.withUnsafeBytes { i in
            let ikmBase = i.baseAddress?.assumingMemoryBound(to: UInt8.self)
            if let salt = salt {
                return try salt.withUnsafeBytes { s in
                    var r = cryptolib_hkdf_extract(
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count, ikmBase, ikm.count)
                    return try check(&r)
                }
            }
            var r = cryptolib_hkdf_extract(nil, 0, ikmBase, ikm.count)
            return try check(&r)
        }
    }

    /// HKDF-SHA256 expand. `info` may be nil.
    func hkdfExpand(_ prk: Data, info: Data? = nil, outLen: Int = 32) throws -> Data {
        return try prk.withUnsafeBytes { p in
            let prkBase = p.baseAddress?.assumingMemoryBound(to: UInt8.self)
            if let info = info {
                return try info.withUnsafeBytes { f in
                    var r = cryptolib_hkdf_expand(
                        prkBase, prk.count, f.baseAddress?.assumingMemoryBound(to: UInt8.self), info.count, outLen)
                    return try check(&r)
                }
            }
            var r = cryptolib_hkdf_expand(prkBase, prk.count, nil, 0, outLen)
            return try check(&r)
        }
    }

    /// HKDF-SHA256 one-shot (extract + expand). `salt`/`info` may be nil.
    func hkdfDerive(_ ikm: Data, salt: Data? = nil, info: Data? = nil, outLen: Int = 32) throws -> Data {
        let saltData = salt ?? Data()
        let infoData = info ?? Data()
        return try ikm.withUnsafeBytes { i in
            try saltData.withUnsafeBytes { s in
                try infoData.withUnsafeBytes { f in
                    var r = cryptolib_hkdf_derive(
                        i.baseAddress?.assumingMemoryBound(to: UInt8.self), ikm.count,
                        salt == nil ? nil : s.baseAddress?.assumingMemoryBound(to: UInt8.self), saltData.count,
                        info == nil ? nil : f.baseAddress?.assumingMemoryBound(to: UInt8.self), infoData.count,
                        outLen)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - Committing AEAD (UtC)

    /// Committing AEAD encrypt — ciphertext binds the exact key. `aad` may be nil.
    func committingEncrypt(_ plaintext: Data, key: Data, aad: Data? = nil) throws -> Data {
        let aadData = aad ?? Data()
        return try plaintext.withUnsafeBytes { p in
            try key.withUnsafeBytes { k in
                try aadData.withUnsafeBytes { a in
                    var r = cryptolib_committing_encrypt(
                        p.baseAddress?.assumingMemoryBound(to: UInt8.self), plaintext.count,
                        k.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count,
                        aad == nil ? nil : a.baseAddress?.assumingMemoryBound(to: UInt8.self), aadData.count)
                    return try check(&r)
                }
            }
        }
    }

    /// Committing AEAD decrypt. Throws if the key/aad mismatch or the commitment fails.
    func committingDecrypt(_ ciphertext: Data, key: Data, aad: Data? = nil) throws -> Data {
        let aadData = aad ?? Data()
        return try ciphertext.withUnsafeBytes { c in
            try key.withUnsafeBytes { k in
                try aadData.withUnsafeBytes { a in
                    var r = cryptolib_committing_decrypt(
                        c.baseAddress?.assumingMemoryBound(to: UInt8.self), ciphertext.count,
                        k.baseAddress?.assumingMemoryBound(to: UInt8.self), key.count,
                        aad == nil ? nil : a.baseAddress?.assumingMemoryBound(to: UInt8.self), aadData.count)
                    return try check(&r)
                }
            }
        }
    }

    // MARK: - Hybrid signature (Ed25519 + ML-DSA-65)

    func hybridSigKeygen() -> KeyPairResult {
        var kp = cryptolib_hybrid_sig_keygen()
        return KeyPairResult(
            publicKey: copyAndFree(&kp.public_key),
            secretKey: copyAndFree(&kp.secret_key))
    }

    func hybridSigSign(_ msg: Data, secretKey: Data) throws -> Data {
        return try msg.withUnsafeBytes { m in
            try secretKey.withUnsafeBytes { s in
                var r = cryptolib_hybrid_sig_sign(
                    m.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                    s.baseAddress?.assumingMemoryBound(to: UInt8.self), secretKey.count)
                return try check(&r)
            }
        }
    }

    func hybridSigVerify(_ msg: Data, sig: Data, publicKey: Data) -> Bool {
        return msg.withUnsafeBytes { m in
            sig.withUnsafeBytes { s in
                publicKey.withUnsafeBytes { p in
                    cryptolib_hybrid_sig_verify(
                        m.baseAddress?.assumingMemoryBound(to: UInt8.self), msg.count,
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self), sig.count,
                        p.baseAddress?.assumingMemoryBound(to: UInt8.self), publicKey.count) == 1
                }
            }
        }
    }

    // MARK: - BLS deterministic keygen

    /// Deterministic BLS keygen from input key material (>= 32 bytes).
    func blsKeygenFromIkm(_ ikm: Data) -> KeyPairResult {
        var kp = ikm.withUnsafeBytes { i in
            cryptolib_bls_keygen_from_ikm(i.baseAddress?.assumingMemoryBound(to: UInt8.self), ikm.count)
        }
        return KeyPairResult(
            publicKey: copyAndFree(&kp.public_key),
            secretKey: copyAndFree(&kp.secret_key))
    }

    // MARK: - Secure Equal

    func secureEqual(_ a: Data, _ b: Data) -> Bool {
        return a.withUnsafeBytes { aPtr in
            b.withUnsafeBytes { bPtr in
                cryptolib_secure_equal(
                    aPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), a.count,
                    bPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), b.count) == 1
            }
        }
    }

    // MARK: - Ed25519 from Seed

    func ed25519KeygenFromSeed(_ seed: Data) -> KeyPairResult {
        return seed.withUnsafeBytes { seedPtr in
            var kp = cryptolib_ed25519_keygen_from_seed(
                seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), seed.count)
            return KeyPairResult(
                publicKey: copyAndFree(&kp.public_key),
                secretKey: copyAndFree(&kp.secret_key))
        }
    }

    // MARK: - Steganography

    func stegoEmbed(_ coverPath: String, payload: Data, outputPath: String) throws {
        let r = payload.withUnsafeBytes { payloadPtr in
            cryptolib_stego_embed(coverPath,
                payloadPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                payload.count, outputPath)
        }
        if r.ok == 0 {
            let msg = r.error.map { String(cString: $0) } ?? "unknown error"
            if let err = r.error { cryptolib_str_free(err) }
            throw CryptoLibError.operationFailed(msg)
        }
    }

    func stegoExtract(_ stegoPath: String) throws -> Data {
        var r = cryptolib_stego_extract(stegoPath)
        return try check(&r)
    }

    func stegoCapacity(_ coverPath: String) -> Int {
        return cryptolib_stego_capacity(coverPath)
    }
}
