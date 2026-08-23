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

const MAGIC: &[u8; 4] = b"CLRC";
const FEC_MAGIC: &[u8; 4] = b"CLFC";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;

/// One authenticated-encryption layer in a [`Recipe`] cascade.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProtectionLayer {
    /// XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
    XChaCha20Poly1305,
    /// AES-256-GCM. A different cipher family from ChaCha.
    Aes256Gcm,
    /// Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
    Committing,
    /// A full MolecularVault (cascade + committing) nested as one layer.
    Molecular,
}

impl ProtectionLayer {
    /// Identifier recorded in the envelope header.
    pub fn id(self) -> u8 {
        match self {
            ProtectionLayer::XChaCha20Poly1305 => 1,
            ProtectionLayer::Aes256Gcm => 2,
            ProtectionLayer::Committing => 3,
            ProtectionLayer::Molecular => 4,
        }
    }

    /// Name used in this layer's HKDF info string.
    ///
    /// Pinned explicitly rather than derived from the variant name: it is part
    /// of the wire format, so renaming must not silently change how keys are
    /// derived — envelopes are opened by other language bindings too.
    pub fn wire_name(self) -> &'static str {
        match self {
            ProtectionLayer::XChaCha20Poly1305 => "xchacha20Poly1305",
            ProtectionLayer::Aes256Gcm => "aes256Gcm",
            ProtectionLayer::Committing => "committing",
            ProtectionLayer::Molecular => "molecular",
        }
    }

    fn from_id(id: u8) -> Result<Self, String> {
        match id {
            1 => Ok(ProtectionLayer::XChaCha20Poly1305),
            2 => Ok(ProtectionLayer::Aes256Gcm),
            3 => Ok(ProtectionLayer::Committing),
            4 => Ok(ProtectionLayer::Molecular),
            _ => Err(format!("cryptolib: unknown protection layer id {id}")),
        }
    }
}

/// Origin-authentication algorithm for a [`Recipe`].
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

    fn from_id(id: u8) -> Result<Self, String> {
        match id {
            0 => Ok(SignatureAlgorithm::None),
            1 => Ok(SignatureAlgorithm::Ed25519),
            2 => Ok(SignatureAlgorithm::Hybrid),
            _ => Err(format!("cryptolib: unknown signature id {id}")),
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

#[derive(Copy, Clone, PartialEq, Eq)]
enum KeySource { Raw, Passphrase, KeyFile }

impl KeySource {
    fn id(self) -> u8 {
        match self { KeySource::Raw => 0, KeySource::Passphrase => 1, KeySource::KeyFile => 2 }
    }
    fn label(self) -> &'static str {
        match self { KeySource::Raw => "raw", KeySource::Passphrase => "passphrase", KeySource::KeyFile => "keyFile" }
    }
    fn from_id(id: u8) -> Result<Self, String> {
        match id {
            0 => Ok(KeySource::Raw),
            1 => Ok(KeySource::Passphrase),
            2 => Ok(KeySource::KeyFile),
            _ => Err(format!("cryptolib: unknown key source id {id}")),
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
    pub fn cascade(self) -> Vec<ProtectionLayer> {
        match self {
            SecurityProfile::Maximum => vec![ProtectionLayer::XChaCha20Poly1305,
                                             ProtectionLayer::Aes256Gcm,
                                             ProtectionLayer::Committing],
            SecurityProfile::High => vec![ProtectionLayer::XChaCha20Poly1305, ProtectionLayer::Aes256Gcm],
            SecurityProfile::Balanced => vec![ProtectionLayer::XChaCha20Poly1305],
        }
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
pub struct Recipe {
    profile: SecurityProfile,
    layers: Vec<ProtectionLayer>,
    source: KeySource,
    raw_key: Option<Vec<u8>>,
    passphrase: Option<String>,
    key_file: Option<String>,
    sign_algorithm: SignatureAlgorithm,
    sign_secret: Option<Vec<u8>>,
    sign_public: Option<Vec<u8>>,
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
            source: KeySource::Raw,
            raw_key: None,
            passphrase: None,
            key_file: None,
            sign_algorithm: SignatureAlgorithm::None,
            sign_secret: None,
            sign_public: None,
            fec: FecScheme::None,
            argon_ops: profile.argon2_ops(),
            argon_memory: profile.argon2_memory(),
            err: None,
        }
    }

    /// Derive the root key from a passphrase with Argon2id.
    pub fn with_passphrase(mut self, passphrase: &str) -> Self {
        self.source = KeySource::Passphrase;
        self.passphrase = Some(passphrase.to_string());
        self
    }

    /// Use a 32-byte full-entropy key directly (KEM secret, keyring unlock, token).
    pub fn with_key(mut self, key: &[u8]) -> Self {
        if key.len() != 32 {
            self.err = Some(format!("cryptolib: root key must be exactly 32 bytes, got {}", key.len()));
            return self;
        }
        self.source = KeySource::Raw;
        self.raw_key = Some(key.to_vec());
        self
    }

    /// Derive the root key deterministically from a media file — "the file is
    /// the key". The same file always yields the same key on any machine.
    pub fn with_key_file(mut self, path: &str) -> Self {
        self.source = KeySource::KeyFile;
        self.key_file = Some(path.to_string());
        self
    }

    /// Replace the cascade with exactly these layers, innermost first.
    pub fn with_layers(mut self, layers: &[ProtectionLayer]) -> Self {
        if layers.is_empty() {
            self.err = Some("cryptolib: a recipe needs at least one layer".into());
            return self;
        }
        self.layers = layers.to_vec();
        self
    }

    /// Append one more layer on the outside of the current cascade.
    pub fn add_layer(mut self, layer: ProtectionLayer) -> Self { self.layers.push(layer); self }

    /// Override the Argon2id cost. Only meaningful with [`Recipe::with_passphrase`].
    pub fn argon2_cost(mut self, ops: u64, memory_bytes: usize) -> Self {
        self.argon_ops = ops;
        self.argon_memory = memory_bytes;
        self
    }

    /// Sign the plaintext before it is encrypted, so the signature stays
    /// confidential and proves who produced it.
    pub fn signed_by(mut self, secret_key: &[u8], algorithm: SignatureAlgorithm) -> Self {
        if algorithm == SignatureAlgorithm::None {
            self.err = Some("cryptolib: signed_by needs a real algorithm".into());
            return self;
        }
        self.sign_algorithm = algorithm;
        self.sign_secret = Some(secret_key.to_vec());
        self
    }

    /// The public key [`Recipe::open`] must verify against. Required whenever
    /// the envelope is signed: otherwise there would be a signature and nobody
    /// checking it.
    pub fn verified_by(mut self, public_key: &[u8]) -> Self {
        self.sign_public = Some(public_key.to_vec());
        self
    }

    /// Apply forward error correction to the finished envelope.
    pub fn with_fec(mut self, scheme: FecScheme) -> Self { self.fec = scheme; self }

    /// A human-readable summary — handy in logs and code review, where a
    /// silently-weak configuration is the thing to catch.
    pub fn describe(&self) -> String {
        let names: Vec<&str> = self.layers.iter().map(|l| l.wire_name()).collect();
        let sig = match self.sign_algorithm {
            SignatureAlgorithm::None => "none",
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Hybrid => "hybrid",
        };
        let mut out = format!(
            "Recipe({})\n  key      : {}\n  layers   : {}\n  signature: {}\n  fec      : {}\n",
            self.profile.label(), self.source.label(), names.join(" -> "), sig, self.fec.id());
        if self.source == KeySource::Passphrase {
            out.push_str(&format!("  argon2id : ops={}, mem={}MiB\n",
                                  self.argon_ops, self.argon_memory / (1024 * 1024)));
        }
        out
    }

    /// Protect `plaintext` and return the envelope.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(e) = &self.err { return Err(e.clone()); }
        let salt = cl::random_bytes(SALT_LEN)?;
        let header = self.build_header(&salt);
        let root = self.root_key(&salt, self.argon_ops, self.argon_memory)?;

        let mut body = plaintext.to_vec();
        if self.sign_algorithm != SignatureAlgorithm::None {
            let sk = self.sign_secret.as_ref()
                .ok_or("cryptolib: signing requested without a secret key")?;
            let sig = if self.sign_algorithm == SignatureAlgorithm::Ed25519 {
                cl::ed25519_sign(plaintext, sk)?
            } else {
                cl::hybrid_sig_sign(plaintext, sk)?
            };
            let mut framed = (sig.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&sig);
            framed.extend_from_slice(plaintext);
            body = framed;
        }
        for (i, layer) in self.layers.iter().enumerate() {
            body = self.apply_layer(*layer, i, &root, &salt, &header, &body, true)?;
        }
        let mut envelope = header;
        envelope.extend_from_slice(&body);
        if self.fec == FecScheme::None { Ok(envelope) } else { self.wrap_fec(&envelope) }
    }

    /// Recover the plaintext. Fails if the key is wrong, a byte was altered, or
    /// a signature is present but does not verify.
    pub fn open(&self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(e) = &self.err { return Err(e.clone()); }
        let inner = self.unwrap_fec(envelope)?;
        let (header, layers, salt, sign_algorithm, ops, memory) = self.parse_header(&inner)?;
        let root = self.root_key(&salt, ops, memory)?;

        let mut body = inner[header.len()..].to_vec();
        for i in (0..layers.len()).rev() {
            body = self.apply_layer(layers[i], i, &root, &salt, &header, &body, false)?;
        }
        if sign_algorithm == SignatureAlgorithm::None { return Ok(body); }

        if body.len() < 4 { return Err("cryptolib: malformed signed payload".into()); }
        let n = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
        if body.len() < 4 + n { return Err("cryptolib: malformed signed payload".into()); }
        let (sig, plaintext) = (&body[4..4 + n], &body[4 + n..]);
        let pk = self.sign_public.as_ref().ok_or(
            "cryptolib: envelope is signed but no public key was supplied — \
             call verified_by so the signature is actually checked")?;
        let ok = if sign_algorithm == SignatureAlgorithm::Ed25519 {
            cl::ed25519_verify(plaintext, sig, pk)
        } else {
            cl::hybrid_sig_verify(plaintext, sig, pk)
        };
        if !ok { return Err("cryptolib: signature verification failed".into()); }
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

    fn root_key(&self, salt: &[u8], ops: u64, memory: usize) -> Result<Vec<u8>, String> {
        match self.source {
            KeySource::Passphrase => {
                let p = self.passphrase.as_ref().ok_or("cryptolib: no passphrase set")?;
                cl::argon2id_derive(p, salt, 32, ops, memory)
            }
            KeySource::KeyFile => {
                let p = self.key_file.as_ref().ok_or("cryptolib: no key file set")?;
                cl::key_from_file_deterministic(p)
            }
            KeySource::Raw => self.raw_key.clone()
                .ok_or_else(|| "cryptolib: no key set — call with_key/with_passphrase/with_key_file".into()),
        }
    }

    /// HKDF under a distinct info string, so no two layers share key material.
    fn layer_key(root: &[u8], salt: &[u8], index: usize, layer: ProtectionLayer)
        -> Result<Vec<u8>, String>
    {
        let info = format!("cryptolib/recipe/v1/layer{index}/{}", layer.wire_name());
        cl::hkdf_derive(root, salt, info.as_bytes(), 32)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_layer(&self, layer: ProtectionLayer, index: usize, root: &[u8], salt: &[u8],
                   header: &[u8], data: &[u8], seal: bool) -> Result<Vec<u8>, String> {
        let key = Self::layer_key(root, salt, index, layer)?;
        match (layer, seal) {
            (ProtectionLayer::XChaCha20Poly1305, true) => cl::xchacha20_encrypt(data, &key, header),
            (ProtectionLayer::XChaCha20Poly1305, false) => cl::xchacha20_decrypt(data, &key, header),
            (ProtectionLayer::Aes256Gcm, true) => cl::aes256gcm_encrypt(data, &key, header),
            (ProtectionLayer::Aes256Gcm, false) => cl::aes256gcm_decrypt(data, &key, header),
            (ProtectionLayer::Committing, true) => cl::committing_encrypt(data, &key, header),
            (ProtectionLayer::Committing, false) => cl::committing_decrypt(data, &key, header),
            (ProtectionLayer::Molecular, true) => cl::molecular_seal_with_key(data, &key, header),
            (ProtectionLayer::Molecular, false) => cl::molecular_open_with_key(data, &key, header),
        }
    }

    fn build_header(&self, salt: &[u8]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&[VERSION, self.source.id(), self.sign_algorithm.id(), self.layers.len() as u8]);
        out.extend(self.layers.iter().map(|l| l.id()));
        out.extend_from_slice(salt);
        out.extend_from_slice(&(self.argon_ops as u32).to_be_bytes());
        out.extend_from_slice(&(self.argon_memory as u32).to_be_bytes());
        out
    }

    #[allow(clippy::type_complexity)]
    fn parse_header(&self, env: &[u8])
        -> Result<(Vec<u8>, Vec<ProtectionLayer>, Vec<u8>, SignatureAlgorithm, u64, usize), String>
    {
        if env.len() < 8 + SALT_LEN + 8 { return Err("cryptolib: envelope too short".into()); }
        if &env[0..4] != MAGIC { return Err("cryptolib: not a CryptoRecipe envelope".into()); }
        if env[4] != VERSION {
            return Err(format!("cryptolib: unsupported envelope version {}", env[4]));
        }
        let source = KeySource::from_id(env[5])?;
        if source != self.source {
            return Err(format!(
                "cryptolib: envelope was sealed with the {} key source, but this recipe is configured for {}",
                source.label(), self.source.label()));
        }
        let sign_algorithm = SignatureAlgorithm::from_id(env[6])?;
        let count = env[7] as usize;
        let header_len = 8 + count + SALT_LEN + 8;
        if env.len() < header_len { return Err("cryptolib: truncated envelope header".into()); }
        let mut layers = Vec::with_capacity(count);
        for i in 0..count { layers.push(ProtectionLayer::from_id(env[8 + i])?); }
        let salt = env[8 + count..8 + count + SALT_LEN].to_vec();
        let c = &env[8 + count + SALT_LEN..header_len];
        let ops = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as u64;
        let mem = u32::from_be_bytes([c[4], c[5], c[6], c[7]]) as usize;
        Ok((env[..header_len].to_vec(), layers, salt, sign_algorithm, ops, mem))
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
