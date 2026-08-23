// CryptoLib Swift — security profiles and composable recipes.
//
// SecurityProfile sets every algorithm parameter consistently, so "use the
// strongest thing available" is one word rather than a dozen constants.
//
// Recipe stacks the library's protections in combination: derive a key, cascade
// several AEADs, sign, add error correction, hide the result in a carrier.
//
// Composition only — every step is an existing, vetted operation. What the
// recipe adds is the plumbing that is easy to get wrong by hand: every layer is
// keyed by HKDF under a distinct info string so no key is ever reused, the
// header describing the recipe is authenticated as AAD by every layer, the order
// (sign → encrypt → correct → conceal) is fixed rather than caller-selectable,
// and everything fails closed.
//
// The envelope is a library-native format, and is identical across every
// CryptoLib binding: an envelope sealed here opens in Dart, Go or Node.
//
// Build/run the smoke with the Makefile target `swift-security`.
import Foundation

enum RecipeError: Error, CustomStringConvertible {
    case failed(String)
    var description: String { if case .failed(let m) = self { return m }; return "recipe error" }
}

private func rcConsume(_ r: CryptoBufferResult) throws -> [UInt8] {
    if let e = r.error { let m = String(cString: e); cryptolib_str_free(e); throw RecipeError.failed(m) }
    var buf = r.buf
    defer { cryptolib_buffer_free(&buf) }
    guard let d = buf.data else { return [] }
    return Array(UnsafeBufferPointer(start: d, count: buf.len))
}

private func rcCheck(_ r: CryptoResult, _ what: String) throws {
    if r.ok != 1 {
        let m = r.error.map { String(cString: $0) } ?? what
        if let e = r.error { cryptolib_str_free(e) }
        throw RecipeError.failed(m)
    }
    if let e = r.error { cryptolib_str_free(e) }
}

/// Call `body` with pointers for each buffer (nil for empty).
private func withBufs<R>(_ datas: [[UInt8]?], _ body: ([(UnsafePointer<UInt8>?, Int)]) throws -> R) rethrows -> R {
    func rec(_ i: Int, _ acc: [(UnsafePointer<UInt8>?, Int)]) throws -> R {
        if i == datas.count { return try body(acc) }
        guard let d = datas[i], !d.isEmpty else { return try rec(i + 1, acc + [(nil, 0)]) }
        return try d.withUnsafeBufferPointer { try rec(i + 1, acc + [($0.baseAddress, d.count)]) }
    }
    return try rec(0, [])
}

// ── Profiles ─────────────────────────────────────────────────────────────────

/// A coherent set of algorithm parameters, from ordinary to maximal. Every field
/// moves together, so a maximal KEM cannot be paired with an interactive KDF.
enum SecurityProfile: String {
    /// Sound modern defaults, fast enough for interactive use.
    case balanced
    /// Stronger parameters and a two-cipher cascade.
    case high
    /// The strongest option at every choice: category-5 post-quantum parameter
    /// sets, the triple-family sealed tier, a three-layer cascade ending in a
    /// key-committing AEAD, and a memory-hard KDF past interactive comfort.
    case maximum

    /// ML-KEM parameter set (0 = 512, 1 = 768, 2 = 1024).
    var mlKemLevel: Int32 { self == .maximum ? 2 : 1 }
    /// ML-DSA parameter set (0 = 44, 1 = 65, 2 = 87).
    var mlDsaLevel: Int32 { self == .maximum ? 2 : 1 }
    /// SLH-DSA parameter set; `.maximum` takes the small-signature 256-bit variant.
    var slhDsaLevel: Int32 { switch self { case .maximum: return 4; case .high: return 3; case .balanced: return 1 } }
    /// SLH-DSA hash family (0 = SHA-2, 1 = SHAKE).
    var slhDsaHash: Int32 { self == .maximum ? 1 : 0 }
    /// Sealed-messaging tier (0 = Flagship, 1 = Fortress).
    var sealedTier: Int32 { self == .maximum ? 1 : 0 }
    /// Argon2id preset for vault and keyring slots (0 = interactive, 1 = sensitive).
    var kdfPreset: Int32 { self == .balanced ? 0 : 1 }
    /// Argon2id iterations used by `Recipe`.
    var argon2Ops: UInt64 { switch self { case .maximum: return 4; case .high: return 3; case .balanced: return 2 } }
    /// Argon2id memory in bytes. Memory is what actually costs an attacker.
    var argon2Memory: Int {
        switch self {
        case .maximum: return 512 * 1024 * 1024
        case .high: return 256 * 1024 * 1024
        case .balanced: return 64 * 1024 * 1024
        }
    }
    /// The AEAD cascade, innermost first.
    var cascade: [ProtectionLayer] {
        switch self {
        case .maximum: return [.xchacha20Poly1305, .aes256Gcm, .committing]
        case .high: return [.xchacha20Poly1305, .aes256Gcm]
        case .balanced: return [.xchacha20Poly1305]
        }
    }
}

/// One authenticated-encryption layer in a `Recipe` cascade.
enum ProtectionLayer: UInt8 {
    /// XChaCha20-Poly1305 — large nonce, no timing-sensitive tables.
    case xchacha20Poly1305 = 1
    /// AES-256-GCM — a different cipher family from ChaCha.
    case aes256Gcm = 2
    /// Key-committing AEAD (UtC) — binds the ciphertext to exactly one key.
    case committing = 3
    /// A full MolecularVault nested as one layer.
    case molecular = 4

    /// Name used in this layer's HKDF info string. Part of the wire format and
    /// identical in every binding, so it is pinned rather than derived.
    var wireName: String {
        switch self {
        case .xchacha20Poly1305: return "xchacha20Poly1305"
        case .aes256Gcm: return "aes256Gcm"
        case .committing: return "committing"
        case .molecular: return "molecular"
        }
    }
}

/// Origin-authentication algorithm for a `Recipe`.
enum SignatureAlgorithm: UInt8 {
    /// No signature. The AEAD still guarantees integrity, but not who sent it.
    case none = 0
    /// Ed25519.
    case ed25519 = 1
    /// Ed25519 + ML-DSA-65; a forgery needs breaking both families.
    case hybrid = 2
}

private enum KeySource: UInt8 {
    case raw = 0, passphrase = 1, keyFile = 2
    var label: String { switch self { case .raw: return "raw"; case .passphrase: return "passphrase"; case .keyFile: return "keyFile" } }
}

/// Forward-error-correction scheme applied to a finished envelope.
enum RecipeFec: Int32 {
    case none = 0, repetition3 = 1, repetition5 = 2, hamming74 = 3
}

// ── Recipe ───────────────────────────────────────────────────────────────────

/// A composable protection pipeline. Describe what you want once, then `seal`
/// and `open` with the same recipe; the envelope carries its own descriptor.
final class Recipe {
    private static let magic: [UInt8] = Array("CLRC".utf8)
    private static let fecMagic: [UInt8] = Array("CLFC".utf8)
    private static let version: UInt8 = 1
    private static let saltLen = 16

    let profile: SecurityProfile
    private var layers: [ProtectionLayer]
    private var source: KeySource = .raw
    private var rawKey: [UInt8] = []
    private var passphrase: String = ""
    private var keyFilePath: String = ""
    private var signAlgorithm: SignatureAlgorithm = .none
    private var signSecret: [UInt8] = []
    private var signPublic: [UInt8] = []
    private var fec: RecipeFec = .none
    private var argonOps: UInt64
    private var argonMem: Int

    /// Start a recipe at the given profile's settings; every part stays overridable.
    init(_ profile: SecurityProfile = .balanced) {
        self.profile = profile
        self.layers = profile.cascade
        self.argonOps = profile.argon2Ops
        self.argonMem = profile.argon2Memory
    }

    /// A recipe using the strongest option at every choice.
    static func maximumSecurity() -> Recipe { Recipe(.maximum) }

    /// Derive the root key from a passphrase with Argon2id.
    @discardableResult func withPassphrase(_ p: String) -> Recipe { source = .passphrase; passphrase = p; return self }

    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    @discardableResult func withKey(_ key: [UInt8]) throws -> Recipe {
        guard key.count == 32 else { throw RecipeError.failed("cryptolib: root key must be exactly 32 bytes, got \(key.count)") }
        source = .raw; rawKey = key; return self
    }

    /// Derive the root key deterministically from a media file — "the file is the
    /// key". Uses the reproducible entropy path; `key_from_file` mixes in fresh
    /// system entropy and so could never reopen its own envelope.
    @discardableResult func withKeyFile(_ path: String) -> Recipe { source = .keyFile; keyFilePath = path; return self }

    /// Replace the cascade with exactly these layers, innermost first.
    @discardableResult func withLayers(_ l: [ProtectionLayer]) throws -> Recipe {
        guard !l.isEmpty else { throw RecipeError.failed("cryptolib: a recipe needs at least one layer") }
        layers = l; return self
    }

    /// Append one more layer on the outside of the cascade.
    @discardableResult func addLayer(_ l: ProtectionLayer) -> Recipe { layers.append(l); return self }

    /// Override the Argon2id cost. Only meaningful with `withPassphrase`.
    @discardableResult func argon2Cost(ops: UInt64? = nil, memoryBytes: Int? = nil) -> Recipe {
        if let o = ops { argonOps = o }
        if let m = memoryBytes { argonMem = m }
        return self
    }

    /// Sign the plaintext before encryption, so the signature stays confidential.
    @discardableResult func signedBy(_ secretKey: [UInt8], algorithm: SignatureAlgorithm = .ed25519) throws -> Recipe {
        guard algorithm != .none else { throw RecipeError.failed("cryptolib: signedBy needs a real algorithm") }
        signAlgorithm = algorithm; signSecret = secretKey; return self
    }

    /// The public key `open` must verify against. Required whenever the envelope
    /// is signed: otherwise there is a signature and nobody checking it.
    @discardableResult func verifiedBy(_ publicKey: [UInt8]) -> Recipe { signPublic = publicKey; return self }

    /// Apply forward error correction to the finished envelope.
    @discardableResult func withFec(_ scheme: RecipeFec) -> Recipe { fec = scheme; return self }

    /// Human-readable summary — useful in logs and review.
    func describe() -> String {
        var out = "Recipe(\(profile.rawValue))\n"
        out += "  key      : \(source.label)\n"
        out += "  layers   : \(layers.map(\.wireName).joined(separator: " → "))\n"
        out += "  signature: \(signAlgorithm)\n"
        out += "  fec      : \(fec.rawValue)\n"
        if source == .passphrase { out += "  argon2id : ops=\(argonOps), mem=\(argonMem / (1024 * 1024))MiB\n" }
        return out
    }

    /// Protect `plaintext` and return the envelope.
    func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
        let salt = try rcConsume(cryptolib_random_bytes(Recipe.saltLen))
        let header = buildHeader(salt: salt)
        let root = try rootKey(salt: salt, ops: argonOps, mem: argonMem)

        var body = plaintext
        if signAlgorithm != .none {
            guard !signSecret.isEmpty else { throw RecipeError.failed("cryptolib: signing requested without a secret key") }
            let sig = try withBufs([plaintext, signSecret]) { p -> [UInt8] in
                signAlgorithm == .ed25519
                    ? try rcConsume(cryptolib_ed25519_sign(p[0].0, p[0].1, p[1].0, p[1].1))
                    : try rcConsume(cryptolib_hybrid_sig_sign(p[0].0, p[0].1, p[1].0, p[1].1))
            }
            body = Recipe.prefixLengthed(sig, plaintext)
        }
        for (i, layer) in layers.enumerated() {
            body = try applyLayer(layer, index: i, root: root, salt: salt, header: header, data: body, seal: true)
        }
        let envelope = header + body
        return fec == .none ? envelope : try wrapFec(envelope)
    }

    /// Recover the plaintext. Throws on a wrong key, an altered byte, or a bad signature.
    func open(_ envelope: [UInt8]) throws -> [UInt8] {
        let inner = try unwrapFec(envelope)
        let h = try parseHeader(inner)
        let root = try rootKey(salt: h.salt, ops: h.ops, mem: h.memory)

        var body = Array(inner[h.header.count...])
        for i in stride(from: h.layers.count - 1, through: 0, by: -1) {
            body = try applyLayer(h.layers[i], index: i, root: root, salt: h.salt, header: h.header, data: body, seal: false)
        }
        if h.signAlgorithm == .none { return body }

        let (sig, plaintext) = try Recipe.splitLengthed(body)
        guard !signPublic.isEmpty else {
            throw RecipeError.failed("cryptolib: envelope is signed but no public key was supplied — "
                                   + "call verifiedBy so the signature is actually checked")
        }
        let ok = withBufs([plaintext, sig, signPublic]) { p -> Bool in
            h.signAlgorithm == .ed25519
                ? cryptolib_ed25519_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) == 1
                : cryptolib_hybrid_sig_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) == 1
        }
        guard ok else { throw RecipeError.failed("cryptolib: signature verification failed") }
        return plaintext
    }

    /// Seal and hide the envelope inside a carrier. Defence-in-depth, not the boundary.
    func sealIntoCarrier(_ plaintext: [UInt8], coverPath: String, outputPath: String) throws {
        let env = try seal(plaintext)
        try env.withUnsafeBufferPointer { p in
            try rcCheck(cryptolib_stego_embed(coverPath, p.baseAddress, env.count, outputPath), "stego embed failed")
        }
    }

    /// Extract and open an envelope written by `sealIntoCarrier`.
    func openFromCarrier(_ stegoPath: String) throws -> [UInt8] {
        try open(try rcConsume(cryptolib_stego_extract(stegoPath)))
    }

    // ── internals ────────────────────────────────────────────────────────────

    private func rootKey(salt: [UInt8], ops: UInt64, mem: Int) throws -> [UInt8] {
        switch source {
        case .passphrase:
            return try salt.withUnsafeBufferPointer { s in
                try rcConsume(cryptolib_argon2id_derive(passphrase, s.baseAddress, salt.count, 32, ops, mem))
            }
        case .keyFile:
            var err: UnsafeMutablePointer<CChar>?
            let h = cryptolib_entropy_from_file_deterministic(keyFilePath, &err)
            if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw RecipeError.failed(m) }
            guard let handle = h else { throw RecipeError.failed("cryptolib: entropy handle allocation failed") }
            defer { cryptolib_entropy_free(handle) }
            return try rcConsume(cryptolib_entropy_symmetric_key(handle))
        case .raw:
            guard rawKey.count == 32 else {
                throw RecipeError.failed("cryptolib: no key set — call withKey/withPassphrase/withKeyFile")
            }
            return rawKey
        }
    }

    /// HKDF under a distinct info string, so no two layers share key material.
    private func layerKey(root: [UInt8], salt: [UInt8], index: Int, layer: ProtectionLayer) throws -> [UInt8] {
        let info = Array("cryptolib/recipe/v1/layer\(index)/\(layer.wireName)".utf8)
        return try withBufs([root, salt, info]) { p in
            try rcConsume(cryptolib_hkdf_derive(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, 32))
        }
    }

    private func applyLayer(_ layer: ProtectionLayer, index: Int, root: [UInt8], salt: [UInt8],
                            header: [UInt8], data: [UInt8], seal: Bool) throws -> [UInt8] {
        let key = try layerKey(root: root, salt: salt, index: index, layer: layer)
        return try withBufs([data, key, header]) { p in
            let (d, dl) = p[0]
            let (k, kl) = p[1]
            let (a, al) = p[2]
            switch layer {
            case .xchacha20Poly1305:
                return try rcConsume(seal ? cryptolib_xchacha20_encrypt(d, dl, k, kl, a, al)
                                          : cryptolib_xchacha20_decrypt(d, dl, k, kl, a, al))
            case .aes256Gcm:
                return try rcConsume(seal ? cryptolib_aes256gcm_encrypt(d, dl, k, kl, a, al)
                                          : cryptolib_aes256gcm_decrypt(d, dl, k, kl, a, al))
            case .committing:
                return try rcConsume(seal ? cryptolib_committing_encrypt(d, dl, k, kl, a, al)
                                          : cryptolib_committing_decrypt(d, dl, k, kl, a, al))
            case .molecular:
                return try rcConsume(seal ? cryptolib_molecular_seal_with_key(d, dl, k, kl, a, al)
                                          : cryptolib_molecular_open_with_key(d, dl, k, kl, a, al))
            }
        }
    }

    private func buildHeader(salt: [UInt8]) -> [UInt8] {
        var out = Recipe.magic
        out += [Recipe.version, source.rawValue, signAlgorithm.rawValue, UInt8(layers.count)]
        out += layers.map(\.rawValue)
        out += salt
        out += Recipe.be32(UInt32(argonOps))
        out += Recipe.be32(UInt32(argonMem))
        return out
    }

    private struct ParsedHeader {
        let header: [UInt8]
        let layers: [ProtectionLayer]
        let salt: [UInt8]
        let signAlgorithm: SignatureAlgorithm
        let ops: UInt64
        let memory: Int
    }

    private func parseHeader(_ env: [UInt8]) throws -> ParsedHeader {
        guard env.count >= 8 + Recipe.saltLen + 8 else { throw RecipeError.failed("cryptolib: envelope too short") }
        guard Array(env[0..<4]) == Recipe.magic else { throw RecipeError.failed("cryptolib: not a CryptoRecipe envelope") }
        guard env[4] == Recipe.version else { throw RecipeError.failed("cryptolib: unsupported envelope version \(env[4])") }
        guard let src = KeySource(rawValue: env[5]) else { throw RecipeError.failed("cryptolib: unknown key source id \(env[5])") }
        guard src == source else {
            throw RecipeError.failed("cryptolib: envelope was sealed with the \(src.label) key source, "
                                   + "but this recipe is configured for \(source.label)")
        }
        guard let sa = SignatureAlgorithm(rawValue: env[6]) else { throw RecipeError.failed("cryptolib: unknown signature id \(env[6])") }
        let count = Int(env[7])
        let headerLen = 8 + count + Recipe.saltLen + 8
        guard env.count >= headerLen else { throw RecipeError.failed("cryptolib: truncated envelope header") }
        var ls: [ProtectionLayer] = []
        for i in 0..<count {
            guard let l = ProtectionLayer(rawValue: env[8 + i]) else {
                throw RecipeError.failed("cryptolib: unknown protection layer id \(env[8 + i])")
            }
            ls.append(l)
        }
        let salt = Array(env[(8 + count)..<(8 + count + Recipe.saltLen)])
        let costs = Array(env[(8 + count + Recipe.saltLen)..<headerLen])
        return ParsedHeader(header: Array(env[0..<headerLen]), layers: ls, salt: salt, signAlgorithm: sa,
                            ops: UInt64(Recipe.readBe32(costs, 0)), memory: Int(Recipe.readBe32(costs, 4)))
    }

    private func wrapFec(_ envelope: [UInt8]) throws -> [UInt8] {
        let encoded = try envelope.withUnsafeBufferPointer { p in
            try rcConsume(cryptolib_fec_encode(p.baseAddress, envelope.count, fec.rawValue))
        }
        return Recipe.fecMagic + [UInt8(fec.rawValue)] + Recipe.be32(UInt32(envelope.count)) + encoded
    }

    private func unwrapFec(_ data: [UInt8]) throws -> [UInt8] {
        guard data.count >= 9, Array(data[0..<4]) == Recipe.fecMagic else { return data }
        let scheme = Int32(data[4])
        let originalLen = Int(Recipe.readBe32(Array(data[5..<9]), 0))
        let rest = Array(data[9...])
        return try rest.withUnsafeBufferPointer { p in
            try rcConsume(cryptolib_fec_decode(p.baseAddress, rest.count, scheme, originalLen))
        }
    }

    private static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    private static func readBe32(_ b: [UInt8], _ o: Int) -> UInt32 {
        (UInt32(b[o]) << 24) | (UInt32(b[o + 1]) << 16) | (UInt32(b[o + 2]) << 8) | UInt32(b[o + 3])
    }

    private static func prefixLengthed(_ prefix: [UInt8], _ rest: [UInt8]) -> [UInt8] {
        be32(UInt32(prefix.count)) + prefix + rest
    }

    private static func splitLengthed(_ data: [UInt8]) throws -> ([UInt8], [UInt8]) {
        guard data.count >= 4 else { throw RecipeError.failed("cryptolib: malformed signed payload") }
        let n = Int(readBe32(data, 0))
        guard data.count >= 4 + n else { throw RecipeError.failed("cryptolib: malformed signed payload") }
        return (Array(data[4..<(4 + n)]), Array(data[(4 + n)...]))
    }
}

// ── smoke (compiled/run by `make swift-security`) ────────────────────────────

func secNoisePpm(_ w: Int, _ h: Int, _ seed: UInt32) -> Data {
    var out = Data("P6\n\(w) \(h)\n255\n".utf8)
    var s = seed == 0 ? 1 : seed
    var body = [UInt8](repeating: 0, count: w * h * 3)
    for i in 0..<body.count {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5
        body[i] = UInt8(s & 0xFF)
    }
    out.append(contentsOf: body)
    return out
}

guard cryptolib_init() == 0 else { fatalError("init failed") }

// ── Cross-language interop mode ──────────────────────────────────────────────
// `security seal|open <dir>` writes/reads a fixed set of configurations so the
// other bindings can prove the envelope format is identical everywhere.

func secHex(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

let interopKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
let interopSkHex  = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6"
let interopPass   = "interop passphrase"
let interopText   = "cross-language recipe envelope"

func interopConfigs(_ pk: [UInt8], _ sk: [UInt8]) throws -> [(String, Recipe)] {
    let key = secHex(interopKeyHex)
    return [
        ("balanced", try Recipe(.balanced).withKey(key)),
        ("maximum", try Recipe(.maximum).withKey(key)),
        ("signed", try Recipe(.high).withKey(key).signedBy(sk).verifiedBy(pk)),
        ("passphrase", Recipe(.balanced).withPassphrase(interopPass).argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024)),
        ("fec", try Recipe(.balanced).withKey(key).withFec(.repetition3)),
    ]
}

let argv = CommandLine.arguments
if argv.count >= 3, argv[1] == "seal" || argv[1] == "open" {
    let mode = argv[1], dir = argv[2]
    let seed = secHex(interopSkHex)
    var skp = seed.withUnsafeBufferPointer { cryptolib_ed25519_keygen_from_seed($0.baseAddress, seed.count) }
    let ipk = Array(UnsafeBufferPointer(start: skp.public_key.data, count: skp.public_key.len))
    let isk = Array(UnsafeBufferPointer(start: skp.secret_key.data, count: skp.secret_key.len))
    cryptolib_keypair_free(&skp)
    var interopFailures = 0
    do {
        for (name, recipe) in try interopConfigs(ipk, isk) {
            let path = "\(dir)/\(name).bin"
            if mode == "seal" {
                let env = try recipe.seal(Array(interopText.utf8))
                try Data(env).write(to: URL(fileURLWithPath: path))
            } else {
                let raw = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
                let got = try recipe.open(raw)
                let ok = String(decoding: got, as: UTF8.self) == interopText
                print("\(ok ? "  ok  " : " FAIL ") swift opens \(name)")
                if !ok { interopFailures += 1 }
            }
        }
        if mode == "seal" { print("  swift sealed 5 envelopes") }
    } catch {
        print(" FAIL  swift \(mode): \(error)")
        interopFailures += 1
    }
    exit(interopFailures == 0 ? 0 : 1)
}

print("CryptoLib \(String(cString: cryptolib_version())) — security profiles + recipes (Swift)")
var pass = 0, fail = 0
func ck(_ n: String, _ ok: Bool) { print("  \(ok ? "✓" : "✗") \(n)"); ok ? (pass += 1) : (fail += 1) }
func throwsErr(_ f: () throws -> Void) -> Bool { do { try f(); return false } catch { return true } }

let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("cl_sec_\(getpid())")
try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: tmp) }

do {
    let secret = Array("the treaty text nobody may read".utf8)

    // Profiles
    ck("maximum picks the strongest options",
       SecurityProfile.maximum.mlKemLevel == 2 && SecurityProfile.maximum.mlDsaLevel == 2 &&
       SecurityProfile.maximum.slhDsaHash == 1 && SecurityProfile.maximum.sealedTier == 1)
    ck("maximum cascade ends key-committing",
       SecurityProfile.maximum.cascade.count == 3 && SecurityProfile.maximum.cascade.last == .committing)
    ck("profiles are ordered", SecurityProfile.balanced.argon2Memory < SecurityProfile.maximum.argon2Memory)

    // Round-trips
    let key = try rcConsume(cryptolib_random_bytes(32))
    let r = try Recipe(.high).withKey(key)
    ck("raw key round-trip", try r.open(try r.seal(secret)) == secret)

    let pr = Recipe.maximumSecurity().withPassphrase("correct horse battery staple")
        .argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024)
    ck("maximum + passphrase round-trip", try pr.open(try pr.seal(secret)) == secret)

    let keyFile = tmp.appendingPathComponent("key.ppm").path
    try secNoisePpm(96, 96, 0x5EED).write(to: URL(fileURLWithPath: keyFile))
    let sealedByFile = try Recipe(.balanced).withKeyFile(keyFile).seal(secret)
    ck("key file reproducible across recipe objects",
       try Recipe(.balanced).withKeyFile(keyFile).open(sealedByFile) == secret)

    // Composition
    let mol = try Recipe(.balanced).withKey(key).withLayers([.molecular])
    ck("MolecularVault as one layer", try mol.open(try mol.seal(secret)) == secret)

    var idkp = cryptolib_ed25519_keygen()
    let pubk = Array(UnsafeBufferPointer(start: idkp.public_key.data, count: idkp.public_key.len))
    let seck = Array(UnsafeBufferPointer(start: idkp.secret_key.data, count: idkp.secret_key.len))
    cryptolib_keypair_free(&idkp)
    let signed = try Recipe(.high).withKey(key).signedBy(seck).verifiedBy(pubk)
    let senv = try signed.seal(secret)
    ck("signed round-trip", try signed.open(senv) == secret)

    var imp = cryptolib_ed25519_keygen()
    let impPub = Array(UnsafeBufferPointer(start: imp.public_key.data, count: imp.public_key.len))
    cryptolib_keypair_free(&imp)
    ck("wrong signer rejected", throwsErr { _ = try Recipe(.high).withKey(key).verifiedBy(impPub).open(senv) })
    ck("signed envelope refuses to open unverified",
       throwsErr { _ = try Recipe(.high).withKey(key).open(senv) })

    // FEC + carrier
    let fr = try Recipe(.balanced).withKey(key).withFec(.repetition3)
    var fenv = try fr.seal(secret)
    fenv[fenv.count / 2] ^= 1
    ck("FEC corrects a flipped bit", try fr.open(fenv) == secret)

    let cover = tmp.appendingPathComponent("cover.ppm").path
    let carrier = tmp.appendingPathComponent("carrier.ppm").path
    try secNoisePpm(256, 256, 0x0FF1CE).write(to: URL(fileURLWithPath: cover))
    let cr = Recipe.maximumSecurity().withPassphrase("a long passphrase here")
        .argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024)
    try cr.sealIntoCarrier(secret, coverPath: cover, outputPath: carrier)
    ck("pipeline hides itself in a carrier", try cr.openFromCarrier(carrier) == secret)

    // Fails closed
    var tenv = try r.seal(secret)
    tenv[tenv.count - 1] ^= 1
    ck("flipped ciphertext byte rejected", throwsErr { _ = try r.open(tenv) })
    var henv = try r.seal(secret)
    henv[7] = 1
    ck("tampered header rejected (descriptor is AAD)", throwsErr { _ = try r.open(henv) })
    let otherKey = try rcConsume(cryptolib_random_bytes(32))
    ck("wrong key rejected", throwsErr { _ = try Recipe(.high).withKey(otherKey).open(try r.seal(secret)) })
    ck("short key refused", throwsErr { _ = try Recipe(.balanced).withKey([UInt8](repeating: 0, count: 31)) })
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — recipes \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
