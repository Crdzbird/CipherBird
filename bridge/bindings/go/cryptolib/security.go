package cryptolib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Security profiles and composable recipes.
//
// Two things live here:
//
//   - SecurityProfile — one choice that sets every algorithm parameter
//     consistently, so "use the strongest thing available" is a single word
//     rather than a dozen correct-but-easily-mismatched constants.
//
//   - Recipe — a declarative way to stack the library's protections in
//     combination: derive a key, cascade several AEADs, sign, add error
//     correction, hide the result in a carrier.
//
// Composition only — every step is an existing, vetted operation. What the
// recipe adds is the plumbing that is easy to get wrong by hand:
//
//   - Every layer gets its OWN key, via HKDF with a distinct info string.
//     A key is never reused across two layers.
//   - The header describing the recipe is authenticated as AAD by EVERY layer,
//     so the descriptor cannot be altered without every layer failing.
//   - Order is fixed and not caller-selectable: sign → encrypt (inner to outer)
//     → error-correct → conceal. Opening reverses it exactly.
//   - Everything fails closed.
//
// The envelope is a library-native format (like MolecularVault's "MVLT"), not a
// standard. It IS identical across every CryptoLib binding: an envelope sealed
// here opens in Dart, Node or Swift and vice versa.
// ═══════════════════════════════════════════════════════════════════════════════

// SecurityProfile is a coherent set of algorithm parameters, from ordinary to
// maximal. Every field moves together, so you cannot accidentally pair a
// maximal KEM with an interactive-cost KDF.
type SecurityProfile int

const (
	// ProfileBalanced uses sound modern defaults, fast enough for interactive use.
	ProfileBalanced SecurityProfile = iota
	// ProfileHigh uses stronger parameters and a two-cipher cascade.
	ProfileHigh
	// ProfileMaximum takes the strongest option the library offers at every
	// choice: category-5 post-quantum parameter sets, the triple-family sealed
	// tier, a three-layer cascade ending in a key-committing AEAD, and a
	// memory-hard KDF tuned well past interactive comfort.
	ProfileMaximum
)

// ML-KEM parameter sets, as accepted by MlKemKeygen.
const (
	MlKem512  = 0
	MlKem768  = 1
	MlKem1024 = 2
)

// ML-DSA parameter sets, as accepted by MlDsaKeygen.
const (
	MlDsa44 = 0
	MlDsa65 = 1
	MlDsa87 = 2
)

// SLH-DSA parameter sets. "Small" means compact signatures and slower signing;
// "fast" means quicker signing and larger signatures.
const (
	SlhDsaSmall128 = 0
	SlhDsaFast128  = 1
	SlhDsaSmall192 = 2
	SlhDsaFast192  = 3
	SlhDsaSmall256 = 4
	SlhDsaFast256  = 5
)

// SLH-DSA hash families.
const (
	SlhDsaSHA2  = 0
	SlhDsaSHAKE = 1
)

// MlKemLevel returns the ML-KEM parameter set for this profile.
func (p SecurityProfile) MlKemLevel() int {
	if p == ProfileMaximum {
		return MlKem1024
	}
	return MlKem768
}

// MlDsaLevel returns the ML-DSA parameter set for this profile.
func (p SecurityProfile) MlDsaLevel() int {
	if p == ProfileMaximum {
		return MlDsa87
	}
	return MlDsa65
}

// SlhDsaLevel returns the SLH-DSA parameter set. ProfileMaximum takes the
// small-signature variant: it signs more slowly but keeps signatures compact,
// and hash-based security is the point of using it at all.
func (p SecurityProfile) SlhDsaLevel() int {
	switch p {
	case ProfileMaximum:
		return SlhDsaSmall256
	case ProfileHigh:
		return SlhDsaFast192
	default:
		return SlhDsaFast128
	}
}

// SlhDsaHash returns the hash family for SLH-DSA.
func (p SecurityProfile) SlhDsaHash() int {
	if p == ProfileMaximum {
		return SlhDsaSHAKE
	}
	return SlhDsaSHA2
}

// SealedTier returns the sealed-messaging tier; ProfileMaximum uses Fortress.
func (p SecurityProfile) SealedTier() SealedTier {
	if p == ProfileMaximum {
		return Fortress
	}
	return Flagship
}

// KdfPreset returns the Argon2id cost preset for vault and keyring slots.
func (p SecurityProfile) KdfPreset() int {
	if p == ProfileBalanced {
		return KdfInteractive
	}
	return KdfSensitive
}

// Argon2Ops returns the Argon2id iteration count used by Recipe.
func (p SecurityProfile) Argon2Ops() uint64 {
	switch p {
	case ProfileMaximum:
		return 4
	case ProfileHigh:
		return 3
	default:
		return 2
	}
}

// Argon2Memory returns the Argon2id memory cost in bytes used by Recipe.
// Memory is what actually costs an attacker; raise it as far as the slowest
// device you must support can bear.
func (p SecurityProfile) Argon2Memory() uint64 {
	switch p {
	case ProfileMaximum:
		return 512 * 1024 * 1024
	case ProfileHigh:
		return 256 * 1024 * 1024
	default:
		return 64 * 1024 * 1024
	}
}

// Cascade returns the AEAD layers this profile applies, innermost first.
// Independent cipher families mean a break of one does not open the envelope,
// and the key-committing outer layer closes partitioning-oracle and
// Invisible-Salamanders style attacks.
func (p SecurityProfile) Cascade() []ProtectionLayer {
	switch p {
	case ProfileMaximum:
		return []ProtectionLayer{LayerXChaCha20Poly1305, LayerAES256GCM, LayerCommitting}
	case ProfileHigh:
		return []ProtectionLayer{LayerXChaCha20Poly1305, LayerAES256GCM}
	default:
		return []ProtectionLayer{LayerXChaCha20Poly1305}
	}
}

// String renders the profile name.
func (p SecurityProfile) String() string {
	switch p {
	case ProfileMaximum:
		return "maximum"
	case ProfileHigh:
		return "high"
	default:
		return "balanced"
	}
}

// ProtectionLayer is one authenticated-encryption layer in a Recipe cascade.
type ProtectionLayer int

const (
	// LayerXChaCha20Poly1305 has a large nonce and no timing-sensitive tables.
	LayerXChaCha20Poly1305 ProtectionLayer = 1
	// LayerAES256GCM is a different cipher family from ChaCha.
	LayerAES256GCM ProtectionLayer = 2
	// LayerCommitting binds the ciphertext to exactly one key.
	LayerCommitting ProtectionLayer = 3
	// LayerMolecular nests a full MolecularVault as one layer.
	LayerMolecular ProtectionLayer = 4
)

// wireName is the name used in this layer's HKDF info string. It is part of the
// wire format and identical in every binding, so it is pinned here rather than
// derived from the Go identifier.
func (l ProtectionLayer) wireName() string {
	switch l {
	case LayerXChaCha20Poly1305:
		return "xchacha20Poly1305"
	case LayerAES256GCM:
		return "aes256Gcm"
	case LayerCommitting:
		return "committing"
	case LayerMolecular:
		return "molecular"
	default:
		return ""
	}
}

// String renders the layer name.
func (l ProtectionLayer) String() string {
	if n := l.wireName(); n != "" {
		return n
	}
	return fmt.Sprintf("ProtectionLayer(%d)", int(l))
}

// SignatureAlgorithm selects origin authentication for a Recipe.
type SignatureAlgorithm int

const (
	// SigNone adds no signature. The AEAD still guarantees integrity, but not
	// who sent it.
	SigNone SignatureAlgorithm = 0
	// SigEd25519 signs with Ed25519.
	SigEd25519 SignatureAlgorithm = 1
	// SigHybrid signs with Ed25519 + ML-DSA-65; a forgery needs breaking both.
	SigHybrid SignatureAlgorithm = 2
)

type keySource int

const (
	sourceRaw keySource = iota
	sourcePassphrase
	sourceKeyFile
)

func (k keySource) String() string {
	switch k {
	case sourcePassphrase:
		return "passphrase"
	case sourceKeyFile:
		return "keyFile"
	default:
		return "raw"
	}
}

const (
	recipeVersion = 1
	recipeSaltLen = 16
)

var (
	recipeMagic = []byte{'C', 'L', 'R', 'C'}
	fecMagic    = []byte{'C', 'L', 'F', 'C'}
)

// Recipe is a composable protection pipeline.
//
// Describe what you want once, then Seal and Open with the same recipe. The
// envelope carries its own descriptor, so opening does not depend on
// remembering which layers were used — only on holding the key.
//
//	r := cryptolib.NewRecipe(cryptolib.ProfileMaximum).
//	    WithPassphrase("correct horse battery staple").
//	    SignedBy(id.Secret, cryptolib.SigHybrid).
//	    VerifiedBy(id.Public)
//
//	env, err := r.Seal(secret)
//	back, err := r.Open(env)
//
// Builder methods chain and defer errors to Seal/Open.
type Recipe struct {
	profile     SecurityProfile
	layers      []ProtectionLayer
	source      keySource
	rawKey      []byte
	passphrase  string
	keyFilePath string
	signAlgo    SignatureAlgorithm
	signSecret  []byte
	signPublic  []byte
	fec         FecScheme
	argonOps    uint64
	argonMem    uint64
	err         error
}

// NewRecipe starts a Recipe at the given profile's settings. The profile only
// sets defaults — every part stays overridable.
func NewRecipe(profile SecurityProfile) *Recipe {
	return &Recipe{
		profile:  profile,
		layers:   profile.Cascade(),
		fec:      FecNone,
		argonOps: profile.Argon2Ops(),
		argonMem: profile.Argon2Memory(),
	}
}

// MaximumSecurity returns a Recipe using the strongest option at every choice.
func MaximumSecurity() *Recipe { return NewRecipe(ProfileMaximum) }

// WithPassphrase derives the root key from a passphrase with Argon2id.
func (r *Recipe) WithPassphrase(p string) *Recipe {
	r.source, r.passphrase = sourcePassphrase, p
	return r
}

// WithKey uses a 32-byte key directly — from a KEM shared secret, a keyring
// unlock, a hardware token, anywhere. Nothing is stretched; the key must
// already be full-entropy.
func (r *Recipe) WithKey(key []byte) *Recipe {
	if len(key) != 32 {
		r.err = fmt.Errorf("cryptolib: root key must be exactly 32 bytes, got %d", len(key))
		return r
	}
	r.source = sourceRaw
	r.rawKey = append([]byte(nil), key...)
	return r
}

// WithKeyFile derives the root key deterministically from a media file — "the
// file is the key". The same file always yields the same key on any machine and
// nothing is stored.
//
// Check the file first with AssessFileHealth: a low-entropy carrier makes a weak
// key no matter how many layers sit on top.
func (r *Recipe) WithKeyFile(path string) *Recipe {
	r.source, r.keyFilePath = sourceKeyFile, path
	return r
}

// WithLayers replaces the cascade with exactly these layers, innermost first.
func (r *Recipe) WithLayers(layers []ProtectionLayer) *Recipe {
	if len(layers) == 0 {
		r.err = errors.New("cryptolib: a recipe needs at least one layer")
		return r
	}
	r.layers = append([]ProtectionLayer(nil), layers...)
	return r
}

// AddLayer appends one more layer on the outside of the current cascade.
func (r *Recipe) AddLayer(l ProtectionLayer) *Recipe {
	r.layers = append(r.layers, l)
	return r
}

// Argon2Cost overrides the Argon2id cost. Only meaningful with WithPassphrase.
func (r *Recipe) Argon2Cost(ops, memoryBytes uint64) *Recipe {
	r.argonOps, r.argonMem = ops, memoryBytes
	return r
}

// SignedBy signs the plaintext before it is encrypted, proving who produced it.
// The signature travels inside the encryption, so it reveals nothing about the
// sender to an observer.
func (r *Recipe) SignedBy(secretKey []byte, algo SignatureAlgorithm) *Recipe {
	if algo == SigNone {
		r.err = errors.New("cryptolib: SignedBy needs a real algorithm")
		return r
	}
	r.signAlgo = algo
	r.signSecret = append([]byte(nil), secretKey...)
	return r
}

// VerifiedBy sets the public key Open must verify the embedded signature
// against. Required whenever the envelope is signed: without it there would be
// a signature but nobody checking it, so Open fails rather than silently
// accepting.
func (r *Recipe) VerifiedBy(publicKey []byte) *Recipe {
	r.signPublic = append([]byte(nil), publicKey...)
	return r
}

// WithFec applies forward error correction to the finished envelope, so it
// survives a carrier that may be recompressed or resampled.
func (r *Recipe) WithFec(scheme FecScheme) *Recipe {
	r.fec = scheme
	return r
}

// Describe renders a human-readable summary of what this recipe will do —
// handy in logs and code review, where a silently-weak configuration is the
// thing to catch.
func (r *Recipe) Describe() string {
	names := make([]string, len(r.layers))
	for i, l := range r.layers {
		names[i] = l.String()
	}
	sig := "none"
	switch r.signAlgo {
	case SigEd25519:
		sig = "ed25519"
	case SigHybrid:
		sig = "hybrid"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Recipe(%s)\n", r.profile)
	fmt.Fprintf(&b, "  key      : %s\n", r.source)
	fmt.Fprintf(&b, "  layers   : %s\n", strings.Join(names, " → "))
	fmt.Fprintf(&b, "  signature: %s\n", sig)
	fmt.Fprintf(&b, "  fec      : %d\n", int(r.fec))
	if r.source == sourcePassphrase {
		fmt.Fprintf(&b, "  argon2id : ops=%d, mem=%dMiB\n", r.argonOps, r.argonMem/(1024*1024))
	}
	return b.String()
}

// Seal protects plaintext and returns the envelope.
func (r *Recipe) Seal(plaintext []byte) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	salt, err := RandomBytes(recipeSaltLen)
	if err != nil {
		return nil, err
	}
	header := r.buildHeader(salt)
	root, err := r.rootKey(salt, r.argonOps, r.argonMem)
	if err != nil {
		return nil, err
	}

	body := plaintext
	if r.signAlgo != SigNone {
		if len(r.signSecret) == 0 {
			return nil, errors.New("cryptolib: signing requested without a secret key")
		}
		var sig []byte
		if r.signAlgo == SigEd25519 {
			sig, err = Ed25519Sign(plaintext, r.signSecret)
		} else {
			sig, err = HybridSigSign(plaintext, r.signSecret)
		}
		if err != nil {
			return nil, err
		}
		body = prefixLengthed(sig, plaintext)
	}

	for i, layer := range r.layers {
		body, err = r.applyLayer(layer, i, root, salt, header, body, true)
		if err != nil {
			return nil, err
		}
	}

	envelope := append(append([]byte(nil), header...), body...)
	if r.fec == FecNone {
		return envelope, nil
	}
	return r.wrapFec(envelope)
}

// Open recovers the plaintext from an envelope. It fails if the key is wrong, a
// byte was altered, or a signature is present but does not verify.
func (r *Recipe) Open(envelope []byte) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	inner, err := r.unwrapFec(envelope)
	if err != nil {
		return nil, err
	}
	h, err := r.parseHeader(inner)
	if err != nil {
		return nil, err
	}
	root, err := r.rootKey(h.salt, h.ops, h.memory)
	if err != nil {
		return nil, err
	}

	body := inner[len(h.header):]
	for i := len(h.layers) - 1; i >= 0; i-- {
		body, err = r.applyLayer(h.layers[i], i, root, h.salt, h.header, body, false)
		if err != nil {
			return nil, err
		}
	}

	if h.signAlgo == SigNone {
		return body, nil
	}
	sig, plaintext, err := splitLengthed(body)
	if err != nil {
		return nil, err
	}
	if len(r.signPublic) == 0 {
		return nil, errors.New(
			"cryptolib: envelope is signed but no public key was supplied — " +
				"call VerifiedBy so the signature is actually checked")
	}
	ok := false
	if h.signAlgo == SigEd25519 {
		ok = Ed25519Verify(plaintext, sig, r.signPublic)
	} else {
		ok = HybridSigVerify(plaintext, sig, r.signPublic)
	}
	if !ok {
		return nil, errors.New("cryptolib: signature verification failed")
	}
	return plaintext, nil
}

// SealIntoCarrier seals plaintext and hides the envelope inside coverPath,
// writing the result to outputPath.
//
// Concealment is defence-in-depth, never the confidentiality boundary — the
// envelope is already authenticated-encrypted before it is embedded.
func (r *Recipe) SealIntoCarrier(plaintext []byte, coverPath, outputPath string) error {
	env, err := r.Seal(plaintext)
	if err != nil {
		return err
	}
	return StegoEmbed(coverPath, env, outputPath)
}

// OpenFromCarrier extracts and opens an envelope written by SealIntoCarrier.
func (r *Recipe) OpenFromCarrier(stegoPath string) ([]byte, error) {
	env, err := StegoExtract(stegoPath)
	if err != nil {
		return nil, err
	}
	return r.Open(env)
}

// ── internals ────────────────────────────────────────────────────────────────

func (r *Recipe) rootKey(salt []byte, ops, mem uint64) ([]byte, error) {
	switch r.source {
	case sourcePassphrase:
		return Argon2idDerive(r.passphrase, salt, 32, ops, mem)
	case sourceKeyFile:
		// Must be the DETERMINISTIC path: KeyFromFile XORs in fresh system
		// entropy, so it returns a different key on every call and could never
		// reopen its own envelope.
		e, err := EntropyFromFileDeterministic(r.keyFilePath)
		if err != nil {
			return nil, err
		}
		defer e.Close()
		return e.SymmetricKey()
	default:
		if len(r.rawKey) != 32 {
			return nil, errors.New("cryptolib: no key set — call WithKey/WithPassphrase/WithKeyFile")
		}
		return r.rawKey, nil
	}
}

// layerKey derives this layer's key with HKDF under a distinct info string, so
// no two layers ever share key material.
func layerKey(root, salt []byte, index int, layer ProtectionLayer) ([]byte, error) {
	info := fmt.Sprintf("cryptolib/recipe/v1/layer%d/%s", index, layer.wireName())
	return HkdfDerive(root, salt, []byte(info), 32)
}

func (r *Recipe) applyLayer(layer ProtectionLayer, index int, root, salt, header, data []byte, seal bool) ([]byte, error) {
	key, err := layerKey(root, salt, index, layer)
	if err != nil {
		return nil, err
	}
	switch layer {
	case LayerXChaCha20Poly1305:
		if seal {
			return XChaCha20Encrypt(data, key, header)
		}
		return XChaCha20Decrypt(data, key, header)
	case LayerAES256GCM:
		if seal {
			return AES256GCMEncrypt(data, key, header)
		}
		return AES256GCMDecrypt(data, key, header)
	case LayerCommitting:
		if seal {
			return CommittingEncrypt(data, key, header)
		}
		return CommittingDecrypt(data, key, header)
	case LayerMolecular:
		if seal {
			return MolecularSealWithKey(data, key, header)
		}
		return MolecularOpenWithKey(data, key, header)
	default:
		return nil, fmt.Errorf("cryptolib: unknown protection layer %d", int(layer))
	}
}

func (r *Recipe) buildHeader(salt []byte) []byte {
	out := make([]byte, 0, 8+len(r.layers)+recipeSaltLen+8)
	out = append(out, recipeMagic...)
	out = append(out, recipeVersion, byte(r.source), byte(r.signAlgo), byte(len(r.layers)))
	for _, l := range r.layers {
		out = append(out, byte(l))
	}
	out = append(out, salt...)
	costs := make([]byte, 8)
	binary.BigEndian.PutUint32(costs[0:4], uint32(r.argonOps))
	binary.BigEndian.PutUint32(costs[4:8], uint32(r.argonMem))
	return append(out, costs...)
}

type parsedHeader struct {
	header   []byte
	layers   []ProtectionLayer
	salt     []byte
	signAlgo SignatureAlgorithm
	ops      uint64
	memory   uint64
}

func (r *Recipe) parseHeader(env []byte) (*parsedHeader, error) {
	if len(env) < 8+recipeSaltLen+8 {
		return nil, errors.New("cryptolib: envelope too short")
	}
	if string(env[:4]) != string(recipeMagic) {
		return nil, errors.New("cryptolib: not a CryptoRecipe envelope")
	}
	if env[4] != recipeVersion {
		return nil, fmt.Errorf("cryptolib: unsupported envelope version %d", env[4])
	}
	source := keySource(env[5])
	if source != r.source {
		return nil, fmt.Errorf(
			"cryptolib: envelope was sealed with the %s key source, but this recipe is configured for %s",
			source, r.source)
	}
	signAlgo := SignatureAlgorithm(env[6])
	layerCount := int(env[7])
	headerLen := 8 + layerCount + recipeSaltLen + 8
	if len(env) < headerLen {
		return nil, errors.New("cryptolib: truncated envelope header")
	}
	layers := make([]ProtectionLayer, layerCount)
	for i := 0; i < layerCount; i++ {
		l := ProtectionLayer(env[8+i])
		if l.wireName() == "" {
			return nil, fmt.Errorf("cryptolib: unknown protection layer id %d", int(l))
		}
		layers[i] = l
	}
	salt := env[8+layerCount : 8+layerCount+recipeSaltLen]
	costs := env[8+layerCount+recipeSaltLen : headerLen]
	return &parsedHeader{
		header:   env[:headerLen],
		layers:   layers,
		salt:     salt,
		signAlgo: signAlgo,
		ops:      uint64(binary.BigEndian.Uint32(costs[0:4])),
		memory:   uint64(binary.BigEndian.Uint32(costs[4:8])),
	}, nil
}

func (r *Recipe) wrapFec(envelope []byte) ([]byte, error) {
	encoded, err := FecEncode(envelope, r.fec)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 9+len(encoded))
	out = append(out, fecMagic...)
	out = append(out, byte(r.fec))
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(envelope)))
	out = append(out, length...)
	return append(out, encoded...), nil
}

func (r *Recipe) unwrapFec(data []byte) ([]byte, error) {
	if len(data) < 9 || string(data[:4]) != string(fecMagic) {
		return data, nil
	}
	scheme := FecScheme(data[4])
	originalLen := int(binary.BigEndian.Uint32(data[5:9]))
	return FecDecode(data[9:], scheme, originalLen)
}

func prefixLengthed(prefix, rest []byte) []byte {
	out := make([]byte, 4, 4+len(prefix)+len(rest))
	binary.BigEndian.PutUint32(out, uint32(len(prefix)))
	out = append(out, prefix...)
	return append(out, rest...)
}

func splitLengthed(data []byte) (prefix, rest []byte, err error) {
	if len(data) < 4 {
		return nil, nil, errors.New("cryptolib: malformed signed payload")
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if len(data) < 4+n {
		return nil, nil, errors.New("cryptolib: malformed signed payload")
	}
	return data[4 : 4+n], data[4+n:], nil
}
