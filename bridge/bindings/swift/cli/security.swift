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
    var cascade: [any ProtectionLayer] {
        switch self {
        case .maximum: return [.xchacha20Poly1305, .aes256Gcm, .committing]
        case .high: return [.xchacha20Poly1305, .aes256Gcm]
        case .balanced: return [.xchacha20Poly1305]
        }
    }
}

// ── Extension points ─────────────────────────────────────────────────────────
//
// Three protocols can be adopted and plugged into a `Recipe`:
//   ProtectionLayer  — one authenticated-encryption layer in the cascade.
//   KeySource        — where the 32-byte root key comes from.
//   SignatureScheme  — how the plaintext is signed and verified.
// The library's own implementations adopt the same protocols, so a custom one
// is a first-class citizen. To compose several ciphers into ONE layer, wrap or
// subclass `CascadeLayer`.
//
// What the recipe keeps for itself, whatever you plug in: a layer never chooses
// its key (it receives a fresh 32-byte key per layer per envelope, HKDF-derived
// under salt + wireName); a layer cannot opt out of the AAD; the order is fixed
// (sign → encrypt → correct → conceal); a KeySource must return exactly 32
// bytes; ids 0–127 are reserved — custom parts must use 128–255, enforced so a
// custom part can never shadow a built-in.
//
// Cross-language: built-in ids open in every CryptoLib binding. A custom part
// opens only where the same id + wireName + algorithm is registered — and since
// wireName feeds the key derivation, a mismatched implementation fails the AEAD
// tag rather than yielding garbage.

/// File-private marker: only types in this file can adopt it, so a custom
/// part cannot claim a reserved id by pretending to be built in.
fileprivate protocol CryptoLibBuiltin {}

private let customIdRange: ClosedRange<UInt8> = 128...255

private func requireValidId(_ part: Any, _ id: UInt8, _ what: String) throws {
    if part is CryptoLibBuiltin { return }
    guard customIdRange.contains(id) else {
        throw RecipeError.failed("cryptolib: custom \(what) ids must be in 128..255 (0–127 are reserved), got \(id)")
    }
}

/// One authenticated-encryption layer in a `Recipe` cascade.
///
/// Adopt it to add your own layer, then `Recipe.register(layer:)` it (on the
/// opening side too — the envelope stores only the id). Contract: `seal` must be
/// authenticated encryption that binds `aad`, and `open` must throw on any
/// modification. The key is fresh per layer per envelope — never reuse it.
protocol ProtectionLayer {
    /// Recorded in the envelope header. Built-ins use 1–4; custom 128–255.
    var id: UInt8 { get }
    /// Feeds this layer's HKDF info string. Part of the wire format.
    var wireName: String { get }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8]
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]
}

private func aead(_ data: [UInt8], _ key: [UInt8], _ aad: [UInt8],
                  _ f: (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int) -> CryptoBufferResult) throws -> [UInt8] {
    try withBufs([data, key, aad]) { p in try rcConsume(f(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1)) }
}

/// XChaCha20-Poly1305 — large nonce, no timing-sensitive tables.
struct XChaCha20Layer: ProtectionLayer, CryptoLibBuiltin {
    var id: UInt8 { 1 }
    var wireName: String { "xchacha20Poly1305" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { try aead(plaintext, key, aad, cryptolib_xchacha20_encrypt) }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { try aead(ciphertext, key, aad, cryptolib_xchacha20_decrypt) }
}
/// AES-256-GCM — a different cipher family from ChaCha.
struct Aes256GcmLayer: ProtectionLayer, CryptoLibBuiltin {
    var id: UInt8 { 2 }
    var wireName: String { "aes256Gcm" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { try aead(plaintext, key, aad, cryptolib_aes256gcm_encrypt) }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { try aead(ciphertext, key, aad, cryptolib_aes256gcm_decrypt) }
}
/// Key-committing AEAD (UtC) — binds the ciphertext to exactly one key.
struct CommittingLayer: ProtectionLayer, CryptoLibBuiltin {
    var id: UInt8 { 3 }
    var wireName: String { "committing" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { try aead(plaintext, key, aad, cryptolib_committing_encrypt) }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { try aead(ciphertext, key, aad, cryptolib_committing_decrypt) }
}
/// A full MolecularVault nested as one layer.
struct MolecularLayer: ProtectionLayer, CryptoLibBuiltin {
    var id: UInt8 { 4 }
    var wireName: String { "molecular" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { try aead(plaintext, key, aad, cryptolib_molecular_seal_with_key) }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { try aead(ciphertext, key, aad, cryptolib_molecular_open_with_key) }
}

// Dot-shorthand for the built-ins: `.withLayers([.xchacha20Poly1305, .committing])`.
extension ProtectionLayer where Self == XChaCha20Layer { static var xchacha20Poly1305: XChaCha20Layer { XChaCha20Layer() } }
extension ProtectionLayer where Self == Aes256GcmLayer { static var aes256Gcm: Aes256GcmLayer { Aes256GcmLayer() } }
extension ProtectionLayer where Self == CommittingLayer { static var committing: CommittingLayer { CommittingLayer() } }
extension ProtectionLayer where Self == MolecularLayer { static var molecular: MolecularLayer { MolecularLayer() } }

/// A layer that is itself a mixture of layers — the way to compose several
/// encryptions into one custom type. Subclass it, or instantiate it directly:
///
///     final class BeltAndBraces: CascadeLayer {
///         init() { super.init(id: 201, wireName: "belt-and-braces",
///                             layers: [.xchacha20Poly1305, MyLayer()]) }
///     }
///
/// Each inner layer receives its own sub-key, HKDF-derived from this layer's
/// key under the inner index and wireName, so nesting never collapses two
/// ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
class CascadeLayer: ProtectionLayer {
    let id: UInt8
    let wireName: String
    let layers: [any ProtectionLayer]

    init(id: UInt8, wireName: String, layers: [any ProtectionLayer]) {
        precondition(!layers.isEmpty, "cryptolib: CascadeLayer \(wireName) has no layers")
        self.id = id; self.wireName = wireName; self.layers = layers
    }

    private func subKey(_ key: [UInt8], _ i: Int) throws -> [UInt8] {
        let info = Array("\(wireName)/\(i)/\(layers[i].wireName)".utf8)
        return try withBufs([key, info]) { p in try rcConsume(cryptolib_hkdf_derive(p[0].0, p[0].1, nil, 0, p[1].0, p[1].1, 32)) }
    }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        var body = plaintext
        for (i, l) in layers.enumerated() { body = try l.seal(key: try subKey(key, i), aad: aad, plaintext: body) }
        return body
    }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        var body = ciphertext
        for i in stride(from: layers.count - 1, through: 0, by: -1) { body = try layers[i].open(key: try subKey(key, i), aad: aad, ciphertext: body) }
        return body
    }
}

/// Where a `Recipe`'s 32-byte root key comes from. Adopt it for a hardware
/// token, a KMS, a keyring unlock — anything that can produce the same 32 bytes
/// again when opening. The recipe refuses any other length.
protocol KeySource {
    /// Recorded in the envelope header. Built-ins use 0–2; custom 128–255.
    var id: UInt8 { get }
    var label: String { get }
    /// `salt` is fresh per envelope; ops/memory are the recipe's Argon2id cost.
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8]
}

/// A 32-byte full-entropy key used as-is.
struct RawKeySource: KeySource, CryptoLibBuiltin {
    let key: [UInt8]
    init(_ key: [UInt8]) throws {
        guard key.count == 32 else { throw RecipeError.failed("cryptolib: root key must be exactly 32 bytes, got \(key.count)") }
        self.key = key
    }
    var id: UInt8 { 0 }
    var label: String { "raw" }
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8] { key }
}
/// A passphrase stretched with Argon2id.
struct PassphraseKeySource: KeySource, CryptoLibBuiltin {
    let passphrase: String
    init(_ passphrase: String) { self.passphrase = passphrase }
    var id: UInt8 { 1 }
    var label: String { "passphrase" }
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8] {
        try salt.withUnsafeBufferPointer { s in
            try rcConsume(cryptolib_argon2id_derive(passphrase, s.baseAddress, salt.count, 32, argon2Ops, argon2Memory))
        }
    }
}
/// The key derived deterministically from a media file. Uses the reproducible
/// entropy path; `key_from_file` mixes in fresh system entropy and so could
/// never reopen its own envelope.
struct KeyFileSource: KeySource, CryptoLibBuiltin {
    let path: String
    init(_ path: String) { self.path = path }
    var id: UInt8 { 2 }
    var label: String { "keyFile" }
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8] {
        var err: UnsafeMutablePointer<CChar>?
        let h = cryptolib_entropy_from_file_deterministic(path, &err)
        if let e = err { let m = String(cString: e); cryptolib_str_free(e); throw RecipeError.failed(m) }
        guard let handle = h else { throw RecipeError.failed("cryptolib: entropy handle allocation failed") }
        defer { cryptolib_entropy_free(handle) }
        return try rcConsume(cryptolib_entropy_symmetric_key(handle))
    }
}

/// How a `Recipe` signs and verifies the plaintext. Adopt it for another
/// algorithm; a scheme holding only a public key should throw from `sign`.
/// The signature is applied before encryption, so it stays confidential.
protocol SignatureScheme {
    /// Recorded in the envelope header. Built-ins use 1–2; custom 128–255.
    var id: UInt8 { get }
    var label: String { get }
    func sign(_ message: [UInt8]) throws -> [UInt8]
    func verify(_ message: [UInt8], signature: [UInt8]) -> Bool
}

/// Ed25519: pass `secretKey` to sign, `publicKey` to verify, or both.
struct Ed25519Signature: SignatureScheme, CryptoLibBuiltin {
    var secretKey: [UInt8] = []
    var publicKey: [UInt8] = []
    var id: UInt8 { 1 }
    var label: String { "ed25519" }
    func sign(_ m: [UInt8]) throws -> [UInt8] {
        guard !secretKey.isEmpty else { throw RecipeError.failed("cryptolib: Ed25519Signature has no secret key") }
        return try withBufs([m, secretKey]) { p in try rcConsume(cryptolib_ed25519_sign(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    func verify(_ m: [UInt8], signature: [UInt8]) -> Bool {
        !publicKey.isEmpty && withBufs([m, signature, publicKey]) { p in
            cryptolib_ed25519_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) == 1
        }
    }
}
/// Ed25519 + ML-DSA-65: a forgery needs breaking both families.
struct HybridSignature: SignatureScheme, CryptoLibBuiltin {
    var secretKey: [UInt8] = []
    var publicKey: [UInt8] = []
    var id: UInt8 { 2 }
    var label: String { "hybrid" }
    func sign(_ m: [UInt8]) throws -> [UInt8] {
        guard !secretKey.isEmpty else { throw RecipeError.failed("cryptolib: HybridSignature has no secret key") }
        return try withBufs([m, secretKey]) { p in try rcConsume(cryptolib_hybrid_sig_sign(p[0].0, p[0].1, p[1].0, p[1].1)) }
    }
    func verify(_ m: [UInt8], signature: [UInt8]) -> Bool {
        !publicKey.isEmpty && withBufs([m, signature, publicKey]) { p in
            cryptolib_hybrid_sig_verify(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1) == 1
        }
    }
}

/// Built-in scheme selector for the `signedBy` shorthand.
enum SignatureAlgorithm: UInt8 {
    /// No signature. The AEAD still guarantees integrity, but not who sent it.
    case none = 0
    /// Ed25519.
    case ed25519 = 1
    /// Ed25519 + ML-DSA-65; a forgery needs breaking both families.
    case hybrid = 2
}

/// Forward-error-correction scheme applied to a finished envelope.
enum RecipeFec: Int32 {
    case none = 0, repetition3 = 1, repetition5 = 2, hamming74 = 3
}

// ── Recipe ───────────────────────────────────────────────────────────────────

/// A composable protection pipeline. Describe what you want once, then `seal`
/// and `open` with the same recipe; the envelope carries its own descriptor.
/// Every part is replaceable with your own — see `ProtectionLayer`,
/// `KeySource` and `SignatureScheme`.
final class Recipe {
    private static let magic: [UInt8] = Array("CLRC".utf8)
    private static let fecMagic: [UInt8] = Array("CLFC".utf8)
    private static let version: UInt8 = 1
    private static let saltLen = 16

    private static var layerRegistry: [UInt8: any ProtectionLayer] = [
        1: XChaCha20Layer(), 2: Aes256GcmLayer(), 3: CommittingLayer(), 4: MolecularLayer(),
    ]

    /// Make a custom layer resolvable by id when opening. Required on both the
    /// sealing and the opening side. Re-registering an id under a different
    /// wireName is refused.
    static func register(layer: any ProtectionLayer) throws {
        try requireValidId(layer, layer.id, "layer")
        if let existing = layerRegistry[layer.id], existing.wireName != layer.wireName {
            throw RecipeError.failed("cryptolib: layer id \(layer.id) is already registered as \(existing.wireName)")
        }
        layerRegistry[layer.id] = layer
    }

    private static func resolveLayer(_ id: UInt8) throws -> any ProtectionLayer {
        guard let l = layerRegistry[id] else {
            throw RecipeError.failed("cryptolib: unknown protection layer id \(id) — Recipe.register(layer:) it before opening")
        }
        return l
    }

    let profile: SecurityProfile
    private var layers: [any ProtectionLayer]
    private var source: (any KeySource)?
    private var signer: (any SignatureScheme)?
    private var verifier: (any SignatureScheme)?
    private var verifierKey: [UInt8]?
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

    /// Use any `KeySource` — a built-in or your own.
    @discardableResult func withKeySource(_ s: any KeySource) throws -> Recipe {
        try requireValidId(s, s.id, "key source"); source = s; return self
    }

    /// Derive the root key from a passphrase with Argon2id.
    @discardableResult func withPassphrase(_ p: String) -> Recipe { source = PassphraseKeySource(p); return self }

    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    @discardableResult func withKey(_ key: [UInt8]) throws -> Recipe { source = try RawKeySource(key); return self }

    /// Derive the root key deterministically from a media file — "the file is the key".
    @discardableResult func withKeyFile(_ path: String) -> Recipe { source = KeyFileSource(path); return self }

    /// Replace the cascade with exactly these layers, innermost first.
    @discardableResult func withLayers(_ l: [any ProtectionLayer]) throws -> Recipe {
        guard !l.isEmpty else { throw RecipeError.failed("cryptolib: a recipe needs at least one layer") }
        for x in l { try requireValidId(x, x.id, "layer") }
        layers = l; return self
    }

    /// Append one more layer on the outside of the cascade.
    @discardableResult func addLayer(_ l: any ProtectionLayer) throws -> Recipe {
        try requireValidId(l, l.id, "layer"); layers.append(l); return self
    }

    /// Override the Argon2id cost. Only meaningful with `withPassphrase`.
    @discardableResult func argon2Cost(ops: UInt64? = nil, memoryBytes: Int? = nil) -> Recipe {
        if let o = ops { argonOps = o }
        if let m = memoryBytes { argonMem = m }
        return self
    }

    /// Sign with any `SignatureScheme` — a built-in or your own.
    @discardableResult func signedWith(_ s: any SignatureScheme) throws -> Recipe {
        try requireValidId(s, s.id, "signature scheme"); signer = s; return self
    }

    /// Verify with any `SignatureScheme`. Required for a custom scheme.
    @discardableResult func verifiedWith(_ s: any SignatureScheme) throws -> Recipe {
        try requireValidId(s, s.id, "signature scheme"); verifier = s; verifierKey = nil; return self
    }

    /// Sign the plaintext before encryption with a built-in scheme.
    @discardableResult func signedBy(_ secretKey: [UInt8], algorithm: SignatureAlgorithm = .ed25519) throws -> Recipe {
        switch algorithm {
        case .ed25519: return try signedWith(Ed25519Signature(secretKey: secretKey))
        case .hybrid: return try signedWith(HybridSignature(secretKey: secretKey))
        case .none: throw RecipeError.failed("cryptolib: signedBy needs a real algorithm")
        }
    }

    /// The public key `open` must verify against. Works for either built-in
    /// scheme — the envelope records which one. A custom `SignatureScheme`
    /// must be supplied through `verifiedWith`.
    @discardableResult func verifiedBy(_ publicKey: [UInt8]) -> Recipe { verifier = nil; verifierKey = publicKey; return self }

    /// Apply forward error correction to the finished envelope.
    @discardableResult func withFec(_ scheme: RecipeFec) -> Recipe { fec = scheme; return self }

    /// Human-readable summary — useful in logs and review.
    func describe() -> String {
        var out = "Recipe(\(profile.rawValue))\n"
        out += "  key      : \(source?.label ?? "(unset)")\n"
        out += "  layers   : \(layers.map(\.wireName).joined(separator: " → "))\n"
        out += "  signature: \(signer?.label ?? "none")\n"
        out += "  fec      : \(fec.rawValue)\n"
        if source is PassphraseKeySource { out += "  argon2id : ops=\(argonOps), mem=\(argonMem / (1024 * 1024))MiB\n" }
        return out
    }

    /// Protect `plaintext` and return the envelope.
    func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
        let src = try requireSource()
        let salt = try rcConsume(cryptolib_random_bytes(Recipe.saltLen))
        let header = buildHeader(source: src, salt: salt)
        let root = try rootKey(src, salt: salt, ops: argonOps, mem: argonMem)

        var body = plaintext
        if let s = signer { body = Recipe.prefixLengthed(try s.sign(plaintext), plaintext) }
        for (i, layer) in layers.enumerated() {
            body = try applyLayer(layer, index: i, root: root, salt: salt, header: header, data: body, seal: true)
        }
        let envelope = header + body
        return fec == .none ? envelope : try wrapFec(envelope)
    }

    /// Recover the plaintext. Throws on a wrong key, an altered byte, or a bad signature.
    func open(_ envelope: [UInt8]) throws -> [UInt8] {
        let src = try requireSource()
        let inner = try unwrapFec(envelope)
        let h = try parseHeader(inner, source: src)
        let root = try rootKey(src, salt: h.salt, ops: h.ops, mem: h.memory)

        var body = Array(inner[h.header.count...])
        for i in stride(from: h.layers.count - 1, through: 0, by: -1) {
            body = try applyLayer(h.layers[i], index: i, root: root, salt: h.salt, header: h.header, data: body, seal: false)
        }
        if h.signatureId == SignatureAlgorithm.none.rawValue { return body }

        let (sig, plaintext) = try Recipe.splitLengthed(body)
        guard let v = verifier ?? builtinVerifier(h.signatureId) else {
            if verifierKey != nil {
                throw RecipeError.failed("cryptolib: envelope was signed with scheme id \(h.signatureId), which is not a built-in — "
                                       + "supply that SignatureScheme with verifiedWith")
            }
            throw RecipeError.failed("cryptolib: envelope is signed but no verifier was supplied — "
                                   + "call verifiedBy/verifiedWith so the signature is actually checked")
        }
        guard v.id == h.signatureId else {
            throw RecipeError.failed("cryptolib: envelope was signed with scheme id \(h.signatureId), but the verifier is \(v.label) (id \(v.id))")
        }
        guard v.verify(plaintext, signature: sig) else { throw RecipeError.failed("cryptolib: signature verification failed") }
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

    private func requireSource() throws -> any KeySource {
        guard let s = source else { throw RecipeError.failed("cryptolib: no key set — call withKey/withPassphrase/withKeyFile/withKeySource") }
        return s
    }

    private func builtinVerifier(_ id: UInt8) -> (any SignatureScheme)? {
        guard let pk = verifierKey else { return nil }
        switch id {
        case SignatureAlgorithm.ed25519.rawValue: return Ed25519Signature(publicKey: pk)
        case SignatureAlgorithm.hybrid.rawValue: return HybridSignature(publicKey: pk)
        default: return nil
        }
    }

    private func rootKey(_ src: any KeySource, salt: [UInt8], ops: UInt64, mem: Int) throws -> [UInt8] {
        let root = try src.deriveRoot(salt: salt, argon2Ops: ops, argon2Memory: mem)
        guard root.count == 32 else {
            throw RecipeError.failed("cryptolib: key source \(src.label) produced \(root.count) bytes; the root key must be exactly 32")
        }
        return root
    }

    /// HKDF under a distinct info string, so no two layers share key material.
    private func layerKey(root: [UInt8], salt: [UInt8], index: Int, layer: any ProtectionLayer) throws -> [UInt8] {
        let info = Array("cryptolib/recipe/v1/layer\(index)/\(layer.wireName)".utf8)
        return try withBufs([root, salt, info]) { p in
            try rcConsume(cryptolib_hkdf_derive(p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, 32))
        }
    }

    private func applyLayer(_ layer: any ProtectionLayer, index: Int, root: [UInt8], salt: [UInt8],
                            header: [UInt8], data: [UInt8], seal: Bool) throws -> [UInt8] {
        let key = try layerKey(root: root, salt: salt, index: index, layer: layer)
        return seal ? try layer.seal(key: key, aad: header, plaintext: data)
                    : try layer.open(key: key, aad: header, ciphertext: data)
    }

    private func buildHeader(source: any KeySource, salt: [UInt8]) -> [UInt8] {
        var out = Recipe.magic
        out += [Recipe.version, source.id, signer?.id ?? SignatureAlgorithm.none.rawValue, UInt8(layers.count)]
        out += layers.map(\.id)
        out += salt
        out += Recipe.be32(UInt32(argonOps))
        out += Recipe.be32(UInt32(argonMem))
        return out
    }

    private struct ParsedHeader {
        let header: [UInt8]
        let layers: [any ProtectionLayer]
        let salt: [UInt8]
        let signatureId: UInt8
        let ops: UInt64
        let memory: Int
    }

    private func parseHeader(_ env: [UInt8], source: any KeySource) throws -> ParsedHeader {
        guard env.count >= 8 + Recipe.saltLen + 8 else { throw RecipeError.failed("cryptolib: envelope too short") }
        guard Array(env[0..<4]) == Recipe.magic else { throw RecipeError.failed("cryptolib: not a CryptoRecipe envelope") }
        guard env[4] == Recipe.version else { throw RecipeError.failed("cryptolib: unsupported envelope version \(env[4])") }
        guard env[5] == source.id else {
            throw RecipeError.failed("cryptolib: envelope was sealed with key source id \(env[5]), "
                                   + "but this recipe is configured for \(source.label) (id \(source.id))")
        }
        let count = Int(env[7])
        let headerLen = 8 + count + Recipe.saltLen + 8
        guard env.count >= headerLen else { throw RecipeError.failed("cryptolib: truncated envelope header") }
        var ls: [any ProtectionLayer] = []
        for i in 0..<count { ls.append(try Recipe.resolveLayer(env[8 + i])) }
        let salt = Array(env[(8 + count)..<(8 + count + Recipe.saltLen)])
        let costs = Array(env[(8 + count + Recipe.saltLen)..<headerLen])
        return ParsedHeader(header: Array(env[0..<headerLen]), layers: ls, salt: salt, signatureId: env[6],
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
       SecurityProfile.maximum.cascade.count == 3 && SecurityProfile.maximum.cascade.last?.id == 3)
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


// ── extension points ─────────────────────────────────────────────────────────

struct MyLayer: ProtectionLayer {
    var id: UInt8 { 200 }
    var wireName: String { "my-xchacha" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { try XChaCha20Layer().seal(key: key, aad: aad, plaintext: plaintext) }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { try XChaCha20Layer().open(key: key, aad: aad, ciphertext: ciphertext) }
}
final class BeltAndBraces: CascadeLayer {
    init() { super.init(id: 201, wireName: "belt-and-braces", layers: [.xchacha20Poly1305, .aes256Gcm, MyLayer()]) }
}
struct Impostor: ProtectionLayer {
    var id: UInt8 { 3 }
    var wireName: String { "committing" }
    func seal(key: [UInt8], aad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] { plaintext }
    func open(key: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] { ciphertext }
}
struct TokenSource: KeySource {
    let token: [UInt8]
    var id: UInt8 { 210 }
    var label: String { "token" }
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8] { token }
}
struct WeakSource: KeySource {
    var id: UInt8 { 211 }
    var label: String { "weak" }
    func deriveRoot(salt: [UInt8], argon2Ops: UInt64, argon2Memory: Int) throws -> [UInt8] { [UInt8](repeating: 0, count: 16) }
}
struct PrefixedEd25519: SignatureScheme {
    var sk: [UInt8] = [], pk: [UInt8] = []
    var id: UInt8 { 220 }
    var label: String { "prefixed-ed25519" }
    func sign(_ m: [UInt8]) throws -> [UInt8] { try Ed25519Signature(secretKey: sk).sign(Array("custom:".utf8) + m) }
    func verify(_ m: [UInt8], signature: [UInt8]) -> Bool { Ed25519Signature(publicKey: pk).verify(Array("custom:".utf8) + m, signature: signature) }
}
struct FakeEd25519: SignatureScheme {
    var id: UInt8 { 1 }
    var label: String { "fake" }
    func sign(_ m: [UInt8]) throws -> [UInt8] { [UInt8](repeating: 0, count: 64) }
    func verify(_ m: [UInt8], signature: [UInt8]) -> Bool { true }
}

do {
    let secret = Array("the treaty text nobody may read".utf8)
    let key = try rcConsume(cryptolib_random_bytes(32))

    ck("built-in ids pinned", XChaCha20Layer().id == 1 && Aes256GcmLayer().id == 2 && CommittingLayer().id == 3 &&
       MolecularLayer().id == 4 && PassphraseKeySource("x").id == 1 && Ed25519Signature().id == 1 && HybridSignature().id == 2)

    try Recipe.register(layer: MyLayer())
    let cenv = try Recipe(.balanced).withKey(key).withLayers([MyLayer()]).seal(secret)
    ck("custom layer round-trips via the registry", try Recipe(.balanced).withKey(key).open(cenv) == secret)

    try Recipe.register(layer: BeltAndBraces())
    let br = try Recipe(.balanced).withKey(key).withLayers([BeltAndBraces()])
    let benv = try br.seal(secret)
    ck("cascade subclass mixes three ciphers as one layer", try Recipe(.balanced).withKey(key).open(benv) == secret)
    var bbad = benv; bbad[bbad.count - 1] ^= 1
    ck("cascade fails closed on tamper", throwsErr { _ = try br.open(bbad) })

    let nested = CascadeLayer(id: 202, wireName: "nested", layers: [BeltAndBraces(), .committing])
    try Recipe.register(layer: nested)
    let nenv = try Recipe(.balanced).withKey(key).withLayers([.xchacha20Poly1305, nested]).seal(secret)
    ck("cascades nest, mixed with built-ins", try Recipe(.balanced).withKey(key).open(nenv) == secret)

    ck("reserved layer id refused at register", throwsErr { try Recipe.register(layer: Impostor()) })
    ck("reserved layer id refused at addLayer", throwsErr { _ = try Recipe(.balanced).withKey(key).addLayer(Impostor()) })
    ck("reserved scheme id refused", throwsErr { _ = try Recipe(.balanced).withKey(key).signedWith(FakeEd25519()) })
    try Recipe.register(layer: MyLayer())
    ck("re-registering an id under another wireName refused",
       throwsErr { try Recipe.register(layer: CascadeLayer(id: 200, wireName: "other", layers: [.xchacha20Poly1305])) })

    let e1 = try Recipe(.balanced).withKey(key).withLayers([MyLayer()]).seal(secret)
    let e2 = try Recipe(.balanced).withKey(key).withLayers([CascadeLayer(id: 203, wireName: "renamed", layers: [.xchacha20Poly1305])]).seal(secret)
    ck("wireName feeds the key derivation", e1.count == e2.count && e1 != e2)

    let token = try rcConsume(cryptolib_random_bytes(32))
    let tenv2 = try Recipe(.high).withKeySource(TokenSource(token: token)).seal(secret)
    ck("custom key source round-trips", try Recipe(.high).withKeySource(TokenSource(token: token)).open(tenv2) == secret)
    ck("wrong token rejected", throwsErr { _ = try Recipe(.high).withKeySource(TokenSource(token: try rcConsume(cryptolib_random_bytes(32)))).open(tenv2) })
    ck("header pins the source id", throwsErr { _ = try Recipe(.high).withKey(key).open(tenv2) })
    ck("narrowing key source refused", throwsErr { _ = try Recipe(.balanced).withKeySource(WeakSource()).seal(secret) })

    var kp2 = cryptolib_ed25519_keygen()
    let pk2 = Array(UnsafeBufferPointer(start: kp2.public_key.data, count: kp2.public_key.len))
    let sk2 = Array(UnsafeBufferPointer(start: kp2.secret_key.data, count: kp2.secret_key.len))
    cryptolib_keypair_free(&kp2)
    let senv2 = try Recipe(.balanced).withKey(key).signedWith(PrefixedEd25519(sk: sk2)).seal(secret)
    ck("custom signature scheme round-trips", try Recipe(.balanced).withKey(key).verifiedWith(PrefixedEd25519(pk: pk2)).open(senv2) == secret)
    ck("key-only verifier cannot serve a custom scheme", throwsErr { _ = try Recipe(.balanced).withKey(key).verifiedBy(pk2).open(senv2) })
    ck("unverified custom-signed envelope refused", throwsErr { _ = try Recipe(.balanced).withKey(key).open(senv2) })
    ck("verifier with the wrong scheme id refused",
       throwsErr { _ = try Recipe(.balanced).withKey(key).verifiedWith(Ed25519Signature(publicKey: pk2)).open(senv2) })

    var hkp = cryptolib_hybrid_sig_keygen()
    let hpk = Array(UnsafeBufferPointer(start: hkp.public_key.data, count: hkp.public_key.len))
    let hsk = Array(UnsafeBufferPointer(start: hkp.secret_key.data, count: hkp.secret_key.len))
    cryptolib_keypair_free(&hkp)
    let hr = try Recipe(.balanced).withKey(key).signedBy(hsk, algorithm: .hybrid).verifiedBy(hpk)
    ck("built-in shorthand with key-only verifier", try hr.open(try hr.seal(secret)) == secret)

    let d = try Recipe(.balanced).withKeySource(TokenSource(token: token)).withLayers([BeltAndBraces()]).describe()
    ck("describe names custom parts", d.contains("token") && d.contains("belt-and-braces"))
} catch { fail += 1; print("  ✗ threw: \(error)") }

print("\n\(pass) passed, \(fail) failed — recipes \(fail == 0 ? "OK" : "FAILED")")
exit(fail == 0 ? 0 : 1)
