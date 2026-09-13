//! Security profiles and composable recipes.
//!
//! [`SecurityProfile`] sets every algorithm parameter consistently, so "use the
//! strongest thing available" is one word rather than a dozen constants.
//!
//! [`Recipe`] stacks the library's protections in combination: derive a key,
//! cascade several AEADs, sign, add error correction, hide the result in a
//! carrier.
//!
//! Composition only — every step is an existing, vetted operation. What the
//! recipe adds is the plumbing that is easy to get wrong by hand:
//!
//! * Every layer gets its **own** key, via HKDF with a distinct info string. A
//!   key is never reused across two layers.
//! * The header describing the recipe is authenticated as AAD by **every**
//!   layer, so the descriptor cannot be altered without every layer failing.
//! * Order is fixed and not caller-selectable: sign → encrypt (inner to outer)
//!   → error-correct → conceal. Opening reverses it exactly.
//! * Everything fails closed.
//!
//! The envelope is a library-native format, and is identical across every
//! CryptoLib binding: one sealed here opens in Dart, Go, Node, Swift, Java,
//! Python or Ruby.

use crate as cl;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const MAGIC: &[u8; 4] = b"CLRC";
const FEC_MAGIC: &[u8; 4] = b"CLFC";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;

// ═══ Extension points ═══════════════════════════════════════════════════════
//
// Three traits can be implemented and plugged into a Recipe:
//   ProtectionLayer  — one authenticated-encryption layer in the cascade.
//   KeySource        — where the 32-byte root key comes from.
//   SignatureScheme  — how the plaintext is signed and verified.
// The library's own implementations satisfy the same traits, so a custom one is
// a first-class citizen. To compose several ciphers into ONE layer, wrap a
// CascadeLayer.
//
// What the recipe keeps for itself, whatever you plug in: a layer never chooses
// its key (it receives a fresh 32-byte key per layer per envelope, HKDF-derived
// under salt + wire_name); a layer cannot opt out of the AAD; the order is fixed
// (sign → encrypt → correct → conceal); a KeySource must return exactly 32
// bytes; ids 0–127 are reserved — custom parts must use 128–255, enforced so a
// custom part can never shadow a built-in.
//
// Cross-language: built-in ids open in every CryptoLib binding. A custom part
// opens only where the same id + wire_name + algorithm is registered — and since
// wire_name feeds the key derivation, a mismatched implementation fails the AEAD
// tag rather than yielding garbage.

const CUSTOM_ID_MIN: u8 = 128;

fn require_valid_id(builtin: bool, id: u8, what: &str) -> Result<(), String> {
    if builtin || id >= CUSTOM_ID_MIN { return Ok(()); }
    Err(format!("cryptolib: custom {what} ids must be in 128..=255 (0–127 are reserved), got {id}"))
}

/// One authenticated-encryption layer in a [`Recipe`] cascade.
///
/// Implement it to add your own layer, then [`register_layer`] it (on the
/// opening side too — the envelope stores only the id). Contract: `seal` must
/// be authenticated encryption that binds `aad`, and `open` must fail on any
/// modification. The key is fresh per layer per envelope — never reuse it.
///
/// ```no_run
/// use cryptolib::ProtectionLayer;
/// struct MyLayer;
/// impl ProtectionLayer for MyLayer {
///     fn id(&self) -> u8 { 200 }
///     fn wire_name(&self) -> &str { "my-xchacha" }
///     fn seal(&self, k: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> { cryptolib::xchacha20_encrypt(pt, k, aad) }
///     fn open(&self, k: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> { cryptolib::xchacha20_decrypt(ct, k, aad) }
/// }
/// cryptolib::register_layer(MyLayer).unwrap();
/// ```
pub trait ProtectionLayer: Send + Sync {
    /// Recorded in the envelope header. Built-ins use 1–4; custom 128–255.
    fn id(&self) -> u8;
    /// Feeds this layer's HKDF info string. Part of the wire format.
    fn wire_name(&self) -> &str;
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>;
    /// Library-internal marker. Do not override: it is what lets built-ins use
    /// reserved ids and custom layers not.
    #[doc(hidden)]
    fn __cryptolib_builtin(&self) -> bool { false }
}

/// A boxed [`ProtectionLayer`] — what a [`Recipe`] holds. Any layer converts
/// into one with `.into()`.
pub type Layer = Box<dyn ProtectionLayer>;

impl<T: ProtectionLayer + 'static> From<T> for Box<dyn ProtectionLayer> {
    fn from(l: T) -> Self { Box::new(l) }
}

/// The four library layers. Each is a real AEAD from the C ABI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BuiltinLayer {
    /// XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
    XChaCha20Poly1305,
    /// AES-256-GCM. A different cipher family from ChaCha.
    Aes256Gcm,
    /// Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
    Committing,
    /// A full MolecularVault (cascade + committing) nested as one layer.
    Molecular,
}

impl ProtectionLayer for BuiltinLayer {
    fn id(&self) -> u8 {
        match self {
            BuiltinLayer::XChaCha20Poly1305 => 1,
            BuiltinLayer::Aes256Gcm => 2,
            BuiltinLayer::Committing => 3,
            BuiltinLayer::Molecular => 4,
        }
    }
    /// Pinned explicitly rather than derived from the variant name: it is part
    /// of the wire format, so renaming must not silently change how keys are
    /// derived — envelopes are opened by other language bindings too.
    fn wire_name(&self) -> &str {
        match self {
            BuiltinLayer::XChaCha20Poly1305 => "xchacha20Poly1305",
            BuiltinLayer::Aes256Gcm => "aes256Gcm",
            BuiltinLayer::Committing => "committing",
            BuiltinLayer::Molecular => "molecular",
        }
    }
    fn seal(&self, key: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            BuiltinLayer::XChaCha20Poly1305 => cl::xchacha20_encrypt(pt, key, aad),
            BuiltinLayer::Aes256Gcm => cl::aes256gcm_encrypt(pt, key, aad),
            BuiltinLayer::Committing => cl::committing_encrypt(pt, key, aad),
            BuiltinLayer::Molecular => cl::molecular_seal_with_key(pt, key, aad),
        }
    }
    fn open(&self, key: &[u8], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            BuiltinLayer::XChaCha20Poly1305 => cl::xchacha20_decrypt(ct, key, aad),
            BuiltinLayer::Aes256Gcm => cl::aes256gcm_decrypt(ct, key, aad),
            BuiltinLayer::Committing => cl::committing_decrypt(ct, key, aad),
            BuiltinLayer::Molecular => cl::molecular_open_with_key(ct, key, aad),
        }
    }
    fn __cryptolib_builtin(&self) -> bool { true }
}

fn registry() -> &'static Mutex<HashMap<u8, Arc<dyn ProtectionLayer>>> {
    static REG: OnceLock<Mutex<HashMap<u8, Arc<dyn ProtectionLayer>>>> = OnceLock::new();
    REG.get_or_init(|| {
        let mut m: HashMap<u8, Arc<dyn ProtectionLayer>> = HashMap::new();
        for l in [BuiltinLayer::XChaCha20Poly1305, BuiltinLayer::Aes256Gcm,
                  BuiltinLayer::Committing, BuiltinLayer::Molecular] {
            m.insert(l.id(), Arc::new(l));
        }
        Mutex::new(m)
    })
}

/// Make a custom layer resolvable by id when opening envelopes. Required on
/// both the sealing and the opening side. Re-registering an id under a
/// different wire name is refused.
pub fn register_layer<L: ProtectionLayer + 'static>(layer: L) -> Result<(), String> {
    require_valid_id(layer.__cryptolib_builtin(), layer.id(), "layer")?;
    let mut reg = registry().lock().map_err(|_| "cryptolib: layer registry poisoned")?;
    if let Some(existing) = reg.get(&layer.id()) {
        if existing.wire_name() != layer.wire_name() {
            return Err(format!("cryptolib: layer id {} is already registered as '{}'",
                               layer.id(), existing.wire_name()));
        }
    }
    reg.insert(layer.id(), Arc::new(layer));
    Ok(())
}

fn resolve_layer(id: u8) -> Result<Arc<dyn ProtectionLayer>, String> {
    let reg = registry().lock().map_err(|_| "cryptolib: layer registry poisoned")?;
    reg.get(&id).cloned()
        .ok_or_else(|| format!("cryptolib: unknown protection layer id {id} — register_layer it before opening"))
}

/// A layer that is itself a mixture of layers — the way to compose several
/// encryptions into one custom type. Use it directly, or wrap it in a newtype
/// and delegate:
///
/// ```no_run
/// use cryptolib::{BuiltinLayer, CascadeLayer, ProtectionLayer};
/// let belt_and_braces = CascadeLayer::new(201, "belt-and-braces",
///     vec![BuiltinLayer::XChaCha20Poly1305.into(), BuiltinLayer::Aes256Gcm.into()]);
/// ```
///
/// Each inner layer receives its own sub-key, HKDF-derived from this layer's
/// key under the inner index and wire name, so nesting never collapses two
/// ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
pub struct CascadeLayer {
    id: u8,
    wire_name: String,
    layers: Vec<Layer>,
}

impl CascadeLayer {
    /// `layers` innermost first; must not be empty (checked at seal/open).
    pub fn new(id: u8, wire_name: &str, layers: Vec<Layer>) -> Self {
        CascadeLayer { id, wire_name: wire_name.to_string(), layers }
    }
    /// The inner layers, innermost first.
    pub fn layers(&self) -> &[Layer] { &self.layers }

    fn sub_key(&self, key: &[u8], i: usize) -> Result<Vec<u8>, String> {
        let info = format!("{}/{i}/{}", self.wire_name, self.layers[i].wire_name());
        cl::hkdf_derive(key, &[], info.as_bytes(), 32)
    }
}

impl ProtectionLayer for CascadeLayer {
    fn id(&self) -> u8 { self.id }
    fn wire_name(&self) -> &str { &self.wire_name }
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if self.layers.is_empty() { return Err(format!("cryptolib: CascadeLayer '{}' has no layers", self.wire_name)); }
        let mut body = plaintext.to_vec();
        for (i, l) in self.layers.iter().enumerate() { body = l.seal(&self.sub_key(key, i)?, aad, &body)?; }
        Ok(body)
    }
    fn open(&self, key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if self.layers.is_empty() { return Err(format!("cryptolib: CascadeLayer '{}' has no layers", self.wire_name)); }
        let mut body = ciphertext.to_vec();
        for i in (0..self.layers.len()).rev() { body = self.layers[i].open(&self.sub_key(key, i)?, aad, &body)?; }
        Ok(body)
    }
}

/// Where a [`Recipe`]'s 32-byte root key comes from. Implement it for a
/// hardware token, a KMS, a keyring unlock — anything that can produce the
/// same 32 bytes again when opening. The recipe refuses any other length.
pub trait KeySource: Send + Sync {
    /// Recorded in the envelope header. Built-ins use 0–2; custom 128–255.
    fn id(&self) -> u8;
    fn label(&self) -> &str;
    /// `salt` is fresh per envelope; ops/memory are the recipe's Argon2id cost.
    fn derive_root(&self, salt: &[u8], argon2_ops: u64, argon2_memory: usize) -> Result<Vec<u8>, String>;
    #[doc(hidden)]
    fn __cryptolib_builtin(&self) -> bool { false }
}

/// A 32-byte full-entropy key used as-is (KEM secret, keyring unlock, token).
pub struct RawKeySource(Vec<u8>);
impl RawKeySource {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 32 { return Err(format!("cryptolib: root key must be exactly 32 bytes, got {}", key.len())); }
        Ok(RawKeySource(key.to_vec()))
    }
}
impl KeySource for RawKeySource {
    fn id(&self) -> u8 { 0 }
    fn label(&self) -> &str { "raw" }
    fn derive_root(&self, _: &[u8], _: u64, _: usize) -> Result<Vec<u8>, String> { Ok(self.0.clone()) }
    fn __cryptolib_builtin(&self) -> bool { true }
}

/// A passphrase stretched with Argon2id at the recipe's cost.
pub struct PassphraseKeySource(pub String);
impl KeySource for PassphraseKeySource {
    fn id(&self) -> u8 { 1 }
    fn label(&self) -> &str { "passphrase" }
    fn derive_root(&self, salt: &[u8], ops: u64, mem: usize) -> Result<Vec<u8>, String> {
        cl::argon2id_derive(&self.0, salt, 32, ops, mem)
    }
    fn __cryptolib_builtin(&self) -> bool { true }
}

/// The key derived deterministically from a media file — "the file is the key".
/// Uses the reproducible entropy path; `key_from_file` mixes in fresh system
/// entropy and so could never reopen its own envelope.
pub struct KeyFileSource(pub String);
impl KeySource for KeyFileSource {
    fn id(&self) -> u8 { 2 }
    fn label(&self) -> &str { "keyFile" }
    fn derive_root(&self, _: &[u8], _: u64, _: usize) -> Result<Vec<u8>, String> {
        cl::key_from_file_deterministic(&self.0)
    }
    fn __cryptolib_builtin(&self) -> bool { true }
}

/// How a [`Recipe`] signs and verifies the plaintext. Implement it for another
/// algorithm; a scheme holding only a public key should fail from `sign`. The
/// signature is applied before encryption, so it stays confidential. Custom
/// schemes are verified only through [`Recipe::verified_with`].
pub trait SignatureScheme: Send + Sync {
    /// Recorded in the envelope header. Built-ins use 1–2; custom 128–255.
    fn id(&self) -> u8;
    fn label(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    #[doc(hidden)]
    fn __cryptolib_builtin(&self) -> bool { false }
}

/// Ed25519. Build with [`Ed25519Signature::signer`] or [`Ed25519Signature::verifier`].
pub struct Ed25519Signature { secret: Option<Vec<u8>>, public: Option<Vec<u8>> }
impl Ed25519Signature {
    pub fn signer(secret_key: &[u8]) -> Self { Ed25519Signature { secret: Some(secret_key.to_vec()), public: None } }
    pub fn verifier(public_key: &[u8]) -> Self { Ed25519Signature { secret: None, public: Some(public_key.to_vec()) } }
}
impl SignatureScheme for Ed25519Signature {
    fn id(&self) -> u8 { 1 }
    fn label(&self) -> &str { "ed25519" }
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>, String> {
        let sk = self.secret.as_ref().ok_or("cryptolib: Ed25519Signature has no secret key")?;
        cl::ed25519_sign(m, sk)
    }
    fn verify(&self, m: &[u8], sig: &[u8]) -> bool {
        self.public.as_ref().is_some_and(|pk| cl::ed25519_verify(m, sig, pk))
    }
    fn __cryptolib_builtin(&self) -> bool { true }
}

/// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
pub struct HybridSignature { secret: Option<Vec<u8>>, public: Option<Vec<u8>> }
impl HybridSignature {
    pub fn signer(secret_key: &[u8]) -> Self { HybridSignature { secret: Some(secret_key.to_vec()), public: None } }
    pub fn verifier(public_key: &[u8]) -> Self { HybridSignature { secret: None, public: Some(public_key.to_vec()) } }
}
impl SignatureScheme for HybridSignature {
    fn id(&self) -> u8 { 2 }
    fn label(&self) -> &str { "hybrid" }
    fn sign(&self, m: &[u8]) -> Result<Vec<u8>, String> {
        let sk = self.secret.as_ref().ok_or("cryptolib: HybridSignature has no secret key")?;
        cl::hybrid_sig_sign(m, sk)
    }
    fn verify(&self, m: &[u8], sig: &[u8]) -> bool {
        self.public.as_ref().is_some_and(|pk| cl::hybrid_sig_verify(m, sig, pk))
    }
    fn __cryptolib_builtin(&self) -> bool { true }
}

/// Built-in scheme selector for the [`Recipe::signed_by`] shorthand.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// No signature. The AEAD still guarantees integrity, but not who sent it.
    None,
    /// Ed25519.
    Ed25519,
    /// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
    Hybrid,
}

impl SignatureAlgorithm {
    /// Identifier recorded in the envelope header.
    pub fn id(self) -> u8 {
        match self {
            SignatureAlgorithm::None => 0,
            SignatureAlgorithm::Ed25519 => 1,
            SignatureAlgorithm::Hybrid => 2,
        }
    }
}

/// Forward-error-correction scheme applied to a finished envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FecScheme {
    /// No redundancy. Full capacity, no error tolerance.
    None,
    /// Each bit repeated 3x; corrects 1 error per triple.
    Repetition3,
    /// Each bit repeated 5x; corrects 2 errors per group.
    Repetition5,
    /// Hamming(7,4): corrects 1 error per 7-bit block.
    Hamming74,
}

impl FecScheme {
    /// Wire value passed to the C ABI.
    pub fn id(self) -> i32 {
        match self {
            FecScheme::None => 0,
            FecScheme::Repetition3 => 1,
            FecScheme::Repetition5 => 2,
            FecScheme::Hamming74 => 3,
        }
    }
}

/// A coherent set of algorithm parameters, from ordinary to maximal.
///
/// Every field moves together, so you cannot accidentally pair a maximal KEM
/// with an interactive-cost KDF.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Sound modern defaults. Fast enough for interactive use.
    Balanced,
    /// Stronger parameters and a two-cipher cascade.
    High,
    /// The strongest option at every choice: category-5 post-quantum parameter
    /// sets, the triple-family sealed tier, a three-layer cascade ending in a
    /// key-committing AEAD, and a memory-hard KDF past interactive comfort.
    Maximum,
}

impl SecurityProfile {
    /// ML-KEM parameter set (0 = 512, 1 = 768, 2 = 1024).
    pub fn ml_kem_level(self) -> i32 { if self == SecurityProfile::Maximum { 2 } else { 1 } }
    /// ML-DSA parameter set (0 = 44, 1 = 65, 2 = 87).
    pub fn ml_dsa_level(self) -> i32 { if self == SecurityProfile::Maximum { 2 } else { 1 } }
    /// SLH-DSA parameter set; `Maximum` takes the small-signature 256-bit variant.
    pub fn slh_dsa_level(self) -> i32 {
        match self { SecurityProfile::Maximum => 4, SecurityProfile::High => 3, SecurityProfile::Balanced => 1 }
    }
    /// SLH-DSA hash family (0 = SHA-2, 1 = SHAKE).
    pub fn slh_dsa_hash(self) -> i32 { if self == SecurityProfile::Maximum { 1 } else { 0 } }
    /// Sealed-messaging tier (0 = Flagship, 1 = Fortress).
    pub fn sealed_tier(self) -> i32 { if self == SecurityProfile::Maximum { 1 } else { 0 } }
    /// Argon2id preset for vault and keyring slots (0 = interactive, 1 = sensitive).
    pub fn kdf_preset(self) -> i32 { if self == SecurityProfile::Balanced { 0 } else { 1 } }
    /// Argon2id iteration count used by [`Recipe`].
    pub fn argon2_ops(self) -> u64 {
        match self { SecurityProfile::Maximum => 4, SecurityProfile::High => 3, SecurityProfile::Balanced => 2 }
    }
    /// Argon2id memory cost in bytes. Memory is what actually costs an attacker.
    pub fn argon2_memory(self) -> usize {
        match self {
            SecurityProfile::Maximum => 512 * 1024 * 1024,
            SecurityProfile::High => 256 * 1024 * 1024,
            SecurityProfile::Balanced => 64 * 1024 * 1024,
        }
    }
    /// The AEAD layers this profile applies, innermost first.
    pub fn cascade(self) -> Vec<Layer> {
        let v: Vec<BuiltinLayer> = match self {
            SecurityProfile::Maximum => vec![BuiltinLayer::XChaCha20Poly1305, BuiltinLayer::Aes256Gcm, BuiltinLayer::Committing],
            SecurityProfile::High => vec![BuiltinLayer::XChaCha20Poly1305, BuiltinLayer::Aes256Gcm],
            SecurityProfile::Balanced => vec![BuiltinLayer::XChaCha20Poly1305],
        };
        v.into_iter().map(Into::into).collect()
    }
    fn label(self) -> &'static str {
        match self { SecurityProfile::Maximum => "maximum", SecurityProfile::High => "high", SecurityProfile::Balanced => "balanced" }
    }
}

/// A composable protection pipeline.
///
/// Describe what you want once, then [`Recipe::seal`] and [`Recipe::open`] with
/// the same recipe. The envelope carries its own descriptor, so opening does not
/// depend on remembering which layers were used — only on holding the key.
///
/// ```no_run
/// let r = cryptolib::maximum_security()
///     .with_passphrase("correct horse battery staple");
/// let env = r.seal(b"secret").unwrap();
/// let back = r.open(&env).unwrap();
/// ```
///
/// Every part is replaceable with your own implementation — see
/// [`ProtectionLayer`], [`KeySource`] and [`SignatureScheme`]. Builder methods
/// defer errors to `seal`/`open`.
pub struct Recipe {
    profile: SecurityProfile,
    layers: Vec<Layer>,
    source: Option<Box<dyn KeySource>>,
    signer: Option<Box<dyn SignatureScheme>>,
    verifier: Option<Box<dyn SignatureScheme>>,
    verifier_key: Option<Vec<u8>>,
    fec: FecScheme,
    argon_ops: u64,
    argon_memory: usize,
    err: Option<String>,
}

impl Recipe {
    fn new(profile: SecurityProfile) -> Self {
        Recipe {
            profile,
            layers: profile.cascade(),
            source: None,
            signer: None,
            verifier: None,
            verifier_key: None,
            fec: FecScheme::None,
            argon_ops: profile.argon2_ops(),
            argon_memory: profile.argon2_memory(),
            err: None,
        }
    }

    fn fail(mut self, e: String) -> Self { if self.err.is_none() { self.err = Some(e); } self }

    /// Use any [`KeySource`] — a built-in or your own implementation.
    pub fn with_key_source<S: KeySource + 'static>(mut self, source: S) -> Self {
        if let Err(e) = require_valid_id(source.__cryptolib_builtin(), source.id(), "key source") { return self.fail(e); }
        self.source = Some(Box::new(source));
        self
    }

    /// Derive the root key from a passphrase with Argon2id.
    pub fn with_passphrase(self, passphrase: &str) -> Self {
        self.with_key_source(PassphraseKeySource(passphrase.to_string()))
    }

    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    pub fn with_key(self, key: &[u8]) -> Self {
        match RawKeySource::new(key) {
            Ok(s) => self.with_key_source(s),
            Err(e) => self.fail(e),
        }
    }

    /// Derive the root key deterministically from a media file — "the file is
    /// the key". The same file always yields the same key on any machine.
    pub fn with_key_file(self, path: &str) -> Self { self.with_key_source(KeyFileSource(path.to_string())) }

    /// Replace the cascade with exactly these layers, innermost first.
    pub fn with_layers<L: Into<Layer>>(mut self, layers: impl IntoIterator<Item = L>) -> Self {
        let layers: Vec<Layer> = layers.into_iter().map(Into::into).collect();
        if layers.is_empty() { return self.fail("cryptolib: a recipe needs at least one layer".into()); }
        for l in &layers {
            if let Err(e) = require_valid_id(l.__cryptolib_builtin(), l.id(), "layer") { return self.fail(e); }
        }
        self.layers = layers;
        self
    }

    /// Append one more layer on the outside of the current cascade.
    pub fn add_layer(mut self, layer: impl Into<Layer>) -> Self {
        let l: Layer = layer.into();
        if let Err(e) = require_valid_id(l.__cryptolib_builtin(), l.id(), "layer") { return self.fail(e); }
        self.layers.push(l);
        self
    }

    /// Override the Argon2id cost. Only meaningful with [`Recipe::with_passphrase`].
    pub fn argon2_cost(mut self, ops: u64, memory_bytes: usize) -> Self {
        self.argon_ops = ops;
        self.argon_memory = memory_bytes;
        self
    }

    /// Sign with any [`SignatureScheme`] — a built-in or your own implementation.
    pub fn signed_with<S: SignatureScheme + 'static>(mut self, scheme: S) -> Self {
        if let Err(e) = require_valid_id(scheme.__cryptolib_builtin(), scheme.id(), "signature scheme") { return self.fail(e); }
        self.signer = Some(Box::new(scheme));
        self
    }

    /// Verify with any [`SignatureScheme`]. Required for a custom scheme.
    pub fn verified_with<S: SignatureScheme + 'static>(mut self, scheme: S) -> Self {
        if let Err(e) = require_valid_id(scheme.__cryptolib_builtin(), scheme.id(), "signature scheme") { return self.fail(e); }
        self.verifier = Some(Box::new(scheme));
        self.verifier_key = None;
        self
    }

    /// Sign the plaintext before it is encrypted with a built-in scheme, so the
    /// signature stays confidential and proves who produced it.
    pub fn signed_by(self, secret_key: &[u8], algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => self.signed_with(Ed25519Signature::signer(secret_key)),
            SignatureAlgorithm::Hybrid => self.signed_with(HybridSignature::signer(secret_key)),
            SignatureAlgorithm::None => self.fail("cryptolib: signed_by needs a real algorithm".into()),
        }
    }

    /// The public key [`Recipe::open`] must verify against. Works for either
    /// built-in scheme — the envelope records which one. A custom
    /// [`SignatureScheme`] must be supplied through [`Recipe::verified_with`].
    pub fn verified_by(mut self, public_key: &[u8]) -> Self {
        self.verifier = None;
        self.verifier_key = Some(public_key.to_vec());
        self
    }

    /// Apply forward error correction to the finished envelope.
    pub fn with_fec(mut self, scheme: FecScheme) -> Self { self.fec = scheme; self }

    /// A human-readable summary — handy in logs and code review, where a
    /// silently-weak configuration is the thing to catch.
    pub fn describe(&self) -> String {
        let names: Vec<&str> = self.layers.iter().map(|l| l.wire_name()).collect();
        let src = self.source.as_ref().map(|s| s.label()).unwrap_or("(unset)");
        let sig = self.signer.as_ref().map(|s| s.label()).unwrap_or("none");
        let mut out = format!(
            "Recipe({})\n  key      : {}\n  layers   : {}\n  signature: {}\n  fec      : {}\n",
            self.profile.label(), src, names.join(" -> "), sig, self.fec.id());
        if self.source.as_ref().is_some_and(|s| s.id() == 1 && s.__cryptolib_builtin()) {
            out.push_str(&format!("  argon2id : ops={}, mem={}MiB\n",
                                  self.argon_ops, self.argon_memory / (1024 * 1024)));
        }
        out
    }

    /// Protect `plaintext` and return the envelope.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let src = self.require_source()?;
        let salt = cl::random_bytes(SALT_LEN)?;
        let header = self.build_header(src, &salt);
        let root = Self::root_key(src, &salt, self.argon_ops, self.argon_memory)?;

        let mut body = plaintext.to_vec();
        if let Some(signer) = &self.signer {
            let sig = signer.sign(plaintext)?;
            let mut framed = (sig.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&sig);
            framed.extend_from_slice(plaintext);
            body = framed;
        }
        for (i, layer) in self.layers.iter().enumerate() {
            body = Self::apply_layer(layer.as_ref(), i, &root, &salt, &header, &body, true)?;
        }
        let mut envelope = header;
        envelope.extend_from_slice(&body);
        if self.fec == FecScheme::None { Ok(envelope) } else { self.wrap_fec(&envelope) }
    }

    /// Recover the plaintext. Fails if the key is wrong, a byte was altered, or
    /// a signature is present but does not verify.
    pub fn open(&self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        let src = self.require_source()?;
        let inner = self.unwrap_fec(envelope)?;
        let (header, layers, salt, signature_id, ops, memory) = Self::parse_header(&inner, src)?;
        let root = Self::root_key(src, &salt, ops, memory)?;

        let mut body = inner[header.len()..].to_vec();
        for i in (0..layers.len()).rev() {
            body = Self::apply_layer(layers[i].as_ref(), i, &root, &salt, &header, &body, false)?;
        }
        if signature_id == 0 { return Ok(body); }

        if body.len() < 4 { return Err("cryptolib: malformed signed payload".into()); }
        let n = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        if body.len() < 4 + n { return Err("cryptolib: malformed signed payload".into()); }
        let (sig, plaintext) = (&body[4..4 + n], &body[4 + n..]);
        let builtin = self.builtin_verifier(signature_id);
        let verifier: &dyn SignatureScheme = match (&self.verifier, &builtin) {
            (Some(v), _) => v.as_ref(),
            (None, Some(v)) => v.as_ref(),
            (None, None) if self.verifier_key.is_some() => return Err(format!(
                "cryptolib: envelope was signed with scheme id {signature_id}, which is not a built-in — \
                 supply that SignatureScheme with verified_with")),
            (None, None) => return Err(
                "cryptolib: envelope is signed but no verifier was supplied — \
                 call verified_by/verified_with so the signature is actually checked".into()),
        };
        if verifier.id() != signature_id {
            return Err(format!("cryptolib: envelope was signed with scheme id {signature_id}, but the verifier is '{}' (id {})",
                               verifier.label(), verifier.id()));
        }
        if !verifier.verify(plaintext, sig) { return Err("cryptolib: signature verification failed".into()); }
        Ok(plaintext.to_vec())
    }

    /// Seal and hide the envelope inside a carrier. Defence-in-depth, never the
    /// confidentiality boundary — the envelope is already authenticated-encrypted.
    pub fn seal_into_carrier(&self, plaintext: &[u8], cover_path: &str, output_path: &str)
        -> Result<(), String>
    {
        cl::stego_embed(cover_path, &self.seal(plaintext)?, output_path)
    }

    /// Extract and open an envelope written by [`Recipe::seal_into_carrier`].
    pub fn open_from_carrier(&self, stego_path: &str) -> Result<Vec<u8>, String> {
        self.open(&cl::stego_extract(stego_path)?)
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn require_source(&self) -> Result<&dyn KeySource, String> {
        if let Some(e) = &self.err { return Err(e.clone()); }
        self.source.as_deref()
            .ok_or_else(|| "cryptolib: no key set — call with_key/with_passphrase/with_key_file/with_key_source".into())
    }

    fn builtin_verifier(&self, id: u8) -> Option<Box<dyn SignatureScheme>> {
        let pk = self.verifier_key.as_ref()?;
        match id {
            1 => Some(Box::new(Ed25519Signature::verifier(pk))),
            2 => Some(Box::new(HybridSignature::verifier(pk))),
            _ => None,
        }
    }

    fn root_key(src: &dyn KeySource, salt: &[u8], ops: u64, memory: usize) -> Result<Vec<u8>, String> {
        let root = src.derive_root(salt, ops, memory)?;
        if root.len() != 32 {
            return Err(format!("cryptolib: key source '{}' produced {} bytes; the root key must be exactly 32",
                               src.label(), root.len()));
        }
        Ok(root)
    }

    /// HKDF under a distinct info string, so no two layers share key material.
    fn layer_key(root: &[u8], salt: &[u8], index: usize, layer: &dyn ProtectionLayer)
        -> Result<Vec<u8>, String>
    {
        let info = format!("cryptolib/recipe/v1/layer{index}/{}", layer.wire_name());
        cl::hkdf_derive(root, salt, info.as_bytes(), 32)
    }

    fn apply_layer(layer: &dyn ProtectionLayer, index: usize, root: &[u8], salt: &[u8],
                   header: &[u8], data: &[u8], seal: bool) -> Result<Vec<u8>, String> {
        let key = Self::layer_key(root, salt, index, layer)?;
        if seal { layer.seal(&key, header, data) } else { layer.open(&key, header, data) }
    }

    fn build_header(&self, src: &dyn KeySource, salt: &[u8]) -> Vec<u8> {
        let sig_id = self.signer.as_ref().map(|s| s.id()).unwrap_or(0);
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[VERSION, src.id(), sig_id, self.layers.len() as u8]);
        out.extend(self.layers.iter().map(|l| l.id()));
        out.extend_from_slice(salt);
        out.extend_from_slice(&(self.argon_ops as u32).to_be_bytes());
        out.extend_from_slice(&(self.argon_memory as u32).to_be_bytes());
        out
    }

    #[allow(clippy::type_complexity)]
    fn parse_header(env: &[u8], src: &dyn KeySource)
        -> Result<(Vec<u8>, Vec<Arc<dyn ProtectionLayer>>, Vec<u8>, u8, u64, usize), String>
    {
        if env.len() < 8 + SALT_LEN + 8 { return Err("cryptolib: envelope too short".into()); }
        if &env[0..4] != MAGIC { return Err("cryptolib: not a CryptoRecipe envelope".into()); }
        if env[4] != VERSION {
            return Err(format!("cryptolib: unsupported envelope version {}", env[4]));
        }
        if env[5] != src.id() {
            return Err(format!(
                "cryptolib: envelope was sealed with key source id {}, but this recipe is configured for '{}' (id {})",
                env[5], src.label(), src.id()));
        }
        let signature_id = env[6];
        let count = env[7] as usize;
        let header_len = 8 + count + SALT_LEN + 8;
        if env.len() < header_len { return Err("cryptolib: truncated envelope header".into()); }
        let mut layers = Vec::with_capacity(count);
        for i in 0..count { layers.push(resolve_layer(env[8 + i])?); }
        let salt = env[8 + count..8 + count + SALT_LEN].to_vec();
        let c = &env[8 + count + SALT_LEN..header_len];
        let ops = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as u64;
        let mem = u32::from_be_bytes([c[4], c[5], c[6], c[7]]) as usize;
        Ok((env[..header_len].to_vec(), layers, salt, signature_id, ops, mem))
    }

    fn wrap_fec(&self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        let encoded = cl::fec_encode(envelope, self.fec.id())?;
        let mut out = FEC_MAGIC.to_vec();
        out.push(self.fec.id() as u8);
        out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn unwrap_fec(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 9 || &data[0..4] != FEC_MAGIC { return Ok(data.to_vec()); }
        let scheme = data[4] as i32;
        let original_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
        cl::fec_decode(&data[9..], scheme, original_len)
    }
}

/// Start a [`Recipe`] at the given profile's settings.
pub fn recipe(profile: SecurityProfile) -> Recipe { Recipe::new(profile) }

/// A [`Recipe`] using the strongest option at every choice.
pub fn maximum_security() -> Recipe { Recipe::new(SecurityProfile::Maximum) }
