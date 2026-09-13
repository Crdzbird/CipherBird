package cryptolib

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
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

// ═══════════════════════════════════════════════════════════════════════════════
// Extension points.
//
// Three interfaces can be implemented and plugged into a Recipe:
//   - ProtectionLayer  — one authenticated-encryption layer in the cascade.
//   - KeySource        — where the 32-byte root key comes from.
//   - SignatureScheme  — how the plaintext is signed and verified.
// The library's own implementations satisfy the same interfaces, so a custom
// one is a first-class citizen. To compose several ciphers into ONE layer, embed
// CascadeLayer.
//
// What the recipe keeps for itself, whatever you plug in: a layer never chooses
// its key (it receives a fresh 32-byte key per layer per envelope, HKDF-derived
// under salt + WireName); a layer cannot opt out of the AAD; the order is fixed
// (sign → encrypt → correct → conceal); a KeySource must return exactly 32
// bytes; identifiers 0–127 are reserved — custom parts must use 128–255, and
// that is enforced so a custom part can never shadow a built-in.
//
// Cross-language: built-in ids open in every CryptoLib binding. A custom part
// opens only where the same id + WireName + algorithm is registered — and since
// WireName feeds the key derivation, a mismatched implementation fails the AEAD
// tag rather than yielding garbage.
// ═══════════════════════════════════════════════════════════════════════════════

// builtinMarker has an unexported method, so only this package can satisfy it:
// a custom type cannot claim a reserved identifier by pretending to be built in.
type builtinMarker interface{ cryptolibBuiltin() }

const (
	customIDMin = 128
	customIDMax = 255
)

func requireValidID(part any, id uint8, what string) error {
	if _, ok := part.(builtinMarker); ok {
		return nil
	}
	if id < customIDMin { // uint8 cannot exceed 255
		return fmt.Errorf("cryptolib: custom %s ids must be in %d..%d (0–127 are reserved), got %d",
			what, customIDMin, customIDMax, id)
	}
	return nil
}

// ProtectionLayer is one authenticated-encryption layer in a Recipe cascade.
//
// Implement it to add your own layer, then RegisterLayer it (on the opening
// side too — the envelope stores only the ID). Contract: Seal must be
// authenticated encryption that binds aad, and Open must fail closed on any
// modification. The key is fresh per layer per envelope — never reuse it.
type ProtectionLayer interface {
	// ID is recorded in the envelope header. Built-ins use 1–4; custom 128–255.
	ID() uint8
	// WireName feeds this layer's HKDF info string. Part of the wire format.
	WireName() string
	Seal(key, aad, plaintext []byte) ([]byte, error)
	Open(key, aad, ciphertext []byte) ([]byte, error)
}

type xchachaLayer struct{}
type aesGcmLayer struct{}
type committingLayer struct{}
type molecularLayer struct{}

func (xchachaLayer) cryptolibBuiltin()    {}
func (aesGcmLayer) cryptolibBuiltin()     {}
func (committingLayer) cryptolibBuiltin() {}
func (molecularLayer) cryptolibBuiltin()  {}

func (xchachaLayer) ID() uint8                           { return 1 }
func (xchachaLayer) WireName() string                    { return "xchacha20Poly1305" }
func (xchachaLayer) Seal(k, a, p []byte) ([]byte, error) { return XChaCha20Encrypt(p, k, a) }
func (xchachaLayer) Open(k, a, c []byte) ([]byte, error) { return XChaCha20Decrypt(c, k, a) }

func (aesGcmLayer) ID() uint8                           { return 2 }
func (aesGcmLayer) WireName() string                    { return "aes256Gcm" }
func (aesGcmLayer) Seal(k, a, p []byte) ([]byte, error) { return AES256GCMEncrypt(p, k, a) }
func (aesGcmLayer) Open(k, a, c []byte) ([]byte, error) { return AES256GCMDecrypt(c, k, a) }

func (committingLayer) ID() uint8                           { return 3 }
func (committingLayer) WireName() string                    { return "committing" }
func (committingLayer) Seal(k, a, p []byte) ([]byte, error) { return CommittingEncrypt(p, k, a) }
func (committingLayer) Open(k, a, c []byte) ([]byte, error) { return CommittingDecrypt(c, k, a) }

func (molecularLayer) ID() uint8                           { return 4 }
func (molecularLayer) WireName() string                    { return "molecular" }
func (molecularLayer) Seal(k, a, p []byte) ([]byte, error) { return MolecularSealWithKey(p, k, a) }
func (molecularLayer) Open(k, a, c []byte) ([]byte, error) { return MolecularOpenWithKey(c, k, a) }

// The built-in layers.
var (
	// LayerXChaCha20Poly1305 has a large nonce and no timing-sensitive tables.
	LayerXChaCha20Poly1305 ProtectionLayer = xchachaLayer{}
	// LayerAES256GCM is a different cipher family from ChaCha.
	LayerAES256GCM ProtectionLayer = aesGcmLayer{}
	// LayerCommitting binds the ciphertext to exactly one key.
	LayerCommitting ProtectionLayer = committingLayer{}
	// LayerMolecular nests a full MolecularVault as one layer.
	LayerMolecular ProtectionLayer = molecularLayer{}
)

var (
	layerRegistryMu sync.RWMutex
	layerRegistry   = map[uint8]ProtectionLayer{
		1: LayerXChaCha20Poly1305, 2: LayerAES256GCM, 3: LayerCommitting, 4: LayerMolecular,
	}
)

// RegisterLayer makes a custom layer resolvable by id when opening envelopes.
// Required on both the sealing and the opening side. Re-registering an id
// under a different WireName is refused.
func RegisterLayer(l ProtectionLayer) error {
	if err := requireValidID(l, l.ID(), "layer"); err != nil {
		return err
	}
	layerRegistryMu.Lock()
	defer layerRegistryMu.Unlock()
	if existing, ok := layerRegistry[l.ID()]; ok && existing.WireName() != l.WireName() {
		return fmt.Errorf("cryptolib: layer id %d is already registered as %q", l.ID(), existing.WireName())
	}
	layerRegistry[l.ID()] = l
	return nil
}

func resolveLayer(id uint8) (ProtectionLayer, error) {
	layerRegistryMu.RLock()
	defer layerRegistryMu.RUnlock()
	if l, ok := layerRegistry[id]; ok {
		return l, nil
	}
	return nil, fmt.Errorf("cryptolib: unknown protection layer id %d — RegisterLayer it before opening", id)
}

// CascadeLayer is a layer that is itself a mixture of layers — the way to
// compose several encryptions into one custom type. Embed it:
//
//	type BeltAndBraces struct{ cryptolib.CascadeLayer }
//	func NewBeltAndBraces() BeltAndBraces {
//	    return BeltAndBraces{cryptolib.CascadeLayer{Id: 200, Name: "belt-and-braces",
//	        Layers: []cryptolib.ProtectionLayer{cryptolib.LayerXChaCha20Poly1305, MyLayer{}}}}
//	}
//
// Each inner layer receives its own sub-key, HKDF-derived from this layer's
// key under the inner index and WireName, so nesting never collapses two
// ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
type CascadeLayer struct {
	Id     uint8
	Name   string
	Layers []ProtectionLayer // innermost first
}

func (c CascadeLayer) ID() uint8        { return c.Id }
func (c CascadeLayer) WireName() string { return c.Name }

func (c CascadeLayer) subKey(key []byte, i int) ([]byte, error) {
	return HkdfDerive(key, nil, []byte(fmt.Sprintf("%s/%d/%s", c.Name, i, c.Layers[i].WireName())), 32)
}

func (c CascadeLayer) Seal(key, aad, plaintext []byte) ([]byte, error) {
	if len(c.Layers) == 0 {
		return nil, fmt.Errorf("cryptolib: CascadeLayer %q has no layers", c.Name)
	}
	body := plaintext
	for i, l := range c.Layers {
		k, err := c.subKey(key, i)
		if err != nil {
			return nil, err
		}
		if body, err = l.Seal(k, aad, body); err != nil {
			return nil, err
		}
	}
	return body, nil
}

func (c CascadeLayer) Open(key, aad, ciphertext []byte) ([]byte, error) {
	if len(c.Layers) == 0 {
		return nil, fmt.Errorf("cryptolib: CascadeLayer %q has no layers", c.Name)
	}
	body := ciphertext
	for i := len(c.Layers) - 1; i >= 0; i-- {
		k, err := c.subKey(key, i)
		if err != nil {
			return nil, err
		}
		if body, err = c.Layers[i].Open(k, aad, body); err != nil {
			return nil, err
		}
	}
	return body, nil
}

// KeySource is where a Recipe's 32-byte root key comes from. Implement it for
// a hardware token, a KMS, a keyring unlock — anything that can produce the
// same 32 bytes again when opening. The recipe refuses any other length.
type KeySource interface {
	// ID is recorded in the envelope header. Built-ins use 0–2; custom 128–255.
	ID() uint8
	Label() string
	// DeriveRoot produces the root key. salt is fresh per envelope; ops/memory
	// are the recipe's Argon2id cost for sources that stretch a weak input.
	DeriveRoot(salt []byte, argon2Ops, argon2Memory uint64) ([]byte, error)
}

// RawKeySource uses a 32-byte full-entropy key as-is.
type RawKeySource struct{ Key []byte }

// PassphraseKeySource stretches a passphrase with Argon2id.
type PassphraseKeySource struct{ Passphrase string }

// KeyFileSource derives the key deterministically from a media file. It uses
// the deterministic entropy path: KeyFromFile XORs in fresh system entropy and
// so could never reopen its own envelope.
type KeyFileSource struct{ Path string }

func (RawKeySource) cryptolibBuiltin()        {}
func (PassphraseKeySource) cryptolibBuiltin() {}
func (KeyFileSource) cryptolibBuiltin()       {}

func (RawKeySource) ID() uint8     { return 0 }
func (RawKeySource) Label() string { return "raw" }
func (r RawKeySource) DeriveRoot([]byte, uint64, uint64) ([]byte, error) {
	if len(r.Key) != 32 {
		return nil, fmt.Errorf("cryptolib: root key must be exactly 32 bytes, got %d", len(r.Key))
	}
	return r.Key, nil
}

func (PassphraseKeySource) ID() uint8     { return 1 }
func (PassphraseKeySource) Label() string { return "passphrase" }
func (p PassphraseKeySource) DeriveRoot(salt []byte, ops, mem uint64) ([]byte, error) {
	return Argon2idDerive(p.Passphrase, salt, 32, ops, mem)
}

func (KeyFileSource) ID() uint8     { return 2 }
func (KeyFileSource) Label() string { return "keyFile" }
func (k KeyFileSource) DeriveRoot([]byte, uint64, uint64) ([]byte, error) {
	e, err := EntropyFromFileDeterministic(k.Path)
	if err != nil {
		return nil, err
	}
	defer e.Close()
	return e.SymmetricKey()
}

// SignatureScheme is how a Recipe signs and verifies the plaintext. Implement
// it for another algorithm; a scheme holding only a public key should return
// an error from Sign. The signature is applied before encryption.
type SignatureScheme interface {
	// ID is recorded in the envelope header. Built-ins use 1–2; custom 128–255.
	ID() uint8
	Label() string
	Sign(message []byte) ([]byte, error)
	Verify(message, signature []byte) bool
}

// Ed25519Signature: supply Secret to sign, Public to verify, or both.
type Ed25519Signature struct{ Secret, Public []byte }

// HybridSignature (Ed25519 + ML-DSA-65): a forgery needs breaking both.
type HybridSignature struct{ Secret, Public []byte }

func (Ed25519Signature) cryptolibBuiltin() {}
func (HybridSignature) cryptolibBuiltin()  {}

func (Ed25519Signature) ID() uint8     { return 1 }
func (Ed25519Signature) Label() string { return "ed25519" }
func (s Ed25519Signature) Sign(m []byte) ([]byte, error) {
	if len(s.Secret) == 0 {
		return nil, errors.New("cryptolib: Ed25519Signature has no secret key")
	}
	return Ed25519Sign(m, s.Secret)
}
func (s Ed25519Signature) Verify(m, sig []byte) bool {
	return len(s.Public) > 0 && Ed25519Verify(m, sig, s.Public)
}

func (HybridSignature) ID() uint8     { return 2 }
func (HybridSignature) Label() string { return "hybrid" }
func (s HybridSignature) Sign(m []byte) ([]byte, error) {
	if len(s.Secret) == 0 {
		return nil, errors.New("cryptolib: HybridSignature has no secret key")
	}
	return HybridSigSign(m, s.Secret)
}
func (s HybridSignature) Verify(m, sig []byte) bool {
	return len(s.Public) > 0 && HybridSigVerify(m, sig, s.Public)
}

// SignatureAlgorithm selects a built-in scheme for the SignedBy shorthand.
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
// Every part is replaceable with your own implementation — see
// ProtectionLayer, KeySource and SignatureScheme. Builder methods chain and
// defer errors to Seal/Open.
type Recipe struct {
	profile     SecurityProfile
	layers      []ProtectionLayer
	source      KeySource
	signer      SignatureScheme
	verifier    SignatureScheme
	verifierKey []byte
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

func (r *Recipe) fail(err error) *Recipe {
	if r.err == nil {
		r.err = err
	}
	return r
}

// WithKeySource uses any KeySource — a built-in or your own implementation.
func (r *Recipe) WithKeySource(src KeySource) *Recipe {
	if err := requireValidID(src, src.ID(), "key source"); err != nil {
		return r.fail(err)
	}
	r.source = src
	return r
}

// WithPassphrase derives the root key from a passphrase with Argon2id.
func (r *Recipe) WithPassphrase(p string) *Recipe { return r.WithKeySource(PassphraseKeySource{p}) }

// WithKey uses a 32-byte full-entropy key directly.
func (r *Recipe) WithKey(key []byte) *Recipe {
	if len(key) != 32 {
		return r.fail(fmt.Errorf("cryptolib: root key must be exactly 32 bytes, got %d", len(key)))
	}
	return r.WithKeySource(RawKeySource{append([]byte(nil), key...)})
}

// WithKeyFile derives the root key deterministically from a media file.
func (r *Recipe) WithKeyFile(path string) *Recipe { return r.WithKeySource(KeyFileSource{path}) }

// WithLayers replaces the cascade with exactly these layers, innermost first.
func (r *Recipe) WithLayers(layers []ProtectionLayer) *Recipe {
	if len(layers) == 0 {
		return r.fail(errors.New("cryptolib: a recipe needs at least one layer"))
	}
	for _, l := range layers {
		if err := requireValidID(l, l.ID(), "layer"); err != nil {
			return r.fail(err)
		}
	}
	r.layers = append([]ProtectionLayer(nil), layers...)
	return r
}

// AddLayer appends one more layer on the outside of the current cascade.
func (r *Recipe) AddLayer(l ProtectionLayer) *Recipe {
	if err := requireValidID(l, l.ID(), "layer"); err != nil {
		return r.fail(err)
	}
	r.layers = append(r.layers, l)
	return r
}

// Argon2Cost overrides the Argon2id cost. Only meaningful with a passphrase source.
func (r *Recipe) Argon2Cost(ops, memoryBytes uint64) *Recipe {
	r.argonOps, r.argonMem = ops, memoryBytes
	return r
}

// SignedWith signs with any SignatureScheme — a built-in or your own.
func (r *Recipe) SignedWith(s SignatureScheme) *Recipe {
	if err := requireValidID(s, s.ID(), "signature scheme"); err != nil {
		return r.fail(err)
	}
	r.signer = s
	return r
}

// VerifiedWith verifies with any SignatureScheme. Required for a custom scheme.
func (r *Recipe) VerifiedWith(s SignatureScheme) *Recipe {
	if err := requireValidID(s, s.ID(), "signature scheme"); err != nil {
		return r.fail(err)
	}
	r.verifier, r.verifierKey = s, nil
	return r
}

// SignedBy signs the plaintext before encryption with a built-in scheme.
func (r *Recipe) SignedBy(secretKey []byte, algo SignatureAlgorithm) *Recipe {
	sk := append([]byte(nil), secretKey...)
	switch algo {
	case SigEd25519:
		return r.SignedWith(Ed25519Signature{Secret: sk})
	case SigHybrid:
		return r.SignedWith(HybridSignature{Secret: sk})
	default:
		return r.fail(errors.New("cryptolib: SignedBy needs a real algorithm"))
	}
}

// VerifiedBy sets the public key Open must verify against. Works for either
// built-in scheme — the envelope records which one — so you need only the
// key. A custom SignatureScheme must be supplied through VerifiedWith.
func (r *Recipe) VerifiedBy(publicKey []byte) *Recipe {
	r.verifier, r.verifierKey = nil, append([]byte(nil), publicKey...)
	return r
}

// WithFec applies forward error correction to the finished envelope.
func (r *Recipe) WithFec(scheme FecScheme) *Recipe { r.fec = scheme; return r }

// Describe renders a human-readable summary — handy in logs and code review.
func (r *Recipe) Describe() string {
	names := make([]string, len(r.layers))
	for i, l := range r.layers {
		names[i] = l.WireName()
	}
	src, sig := "(unset)", "none"
	if r.source != nil {
		src = r.source.Label()
	}
	if r.signer != nil {
		sig = r.signer.Label()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Recipe(%s)\n  key      : %s\n  layers   : %s\n  signature: %s\n  fec      : %d\n",
		r.profile, src, strings.Join(names, " → "), sig, int(r.fec))
	if _, ok := r.source.(PassphraseKeySource); ok {
		fmt.Fprintf(&b, "  argon2id : ops=%d, mem=%dMiB\n", r.argonOps, r.argonMem/(1024*1024))
	}
	return b.String()
}

func (r *Recipe) requireSource() (KeySource, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.source == nil {
		return nil, errors.New("cryptolib: no key set — call WithKey/WithPassphrase/WithKeyFile/WithKeySource")
	}
	return r.source, nil
}

// Seal protects plaintext and returns the envelope.
func (r *Recipe) Seal(plaintext []byte) ([]byte, error) {
	src, err := r.requireSource()
	if err != nil {
		return nil, err
	}
	salt, err := RandomBytes(recipeSaltLen)
	if err != nil {
		return nil, err
	}
	header := r.buildHeader(src, salt)
	root, err := r.rootKey(src, salt, r.argonOps, r.argonMem)
	if err != nil {
		return nil, err
	}

	body := plaintext
	if r.signer != nil {
		sig, err := r.signer.Sign(plaintext)
		if err != nil {
			return nil, err
		}
		body = prefixLengthed(sig, plaintext)
	}
	for i, layer := range r.layers {
		if body, err = r.applyLayer(layer, i, root, salt, header, body, true); err != nil {
			return nil, err
		}
	}
	envelope := append(append([]byte(nil), header...), body...)
	if r.fec == FecNone {
		return envelope, nil
	}
	return r.wrapFec(envelope)
}

// Open recovers the plaintext. It fails if the key is wrong, a byte was
// altered, or a signature is present but does not verify.
func (r *Recipe) Open(envelope []byte) ([]byte, error) {
	src, err := r.requireSource()
	if err != nil {
		return nil, err
	}
	inner, err := r.unwrapFec(envelope)
	if err != nil {
		return nil, err
	}
	h, err := r.parseHeader(inner, src)
	if err != nil {
		return nil, err
	}
	root, err := r.rootKey(src, h.salt, h.ops, h.memory)
	if err != nil {
		return nil, err
	}

	body := inner[len(h.header):]
	for i := len(h.layers) - 1; i >= 0; i-- {
		if body, err = r.applyLayer(h.layers[i], i, root, h.salt, h.header, body, false); err != nil {
			return nil, err
		}
	}
	if h.signatureID == uint8(SigNone) {
		return body, nil
	}
	sig, plaintext, err := splitLengthed(body)
	if err != nil {
		return nil, err
	}
	verifier := r.verifier
	if verifier == nil {
		verifier = r.builtinVerifier(h.signatureID)
	}
	if verifier == nil {
		if r.verifierKey != nil {
			return nil, fmt.Errorf("cryptolib: envelope was signed with scheme id %d, which is not a built-in — supply that SignatureScheme with VerifiedWith", h.signatureID)
		}
		return nil, errors.New("cryptolib: envelope is signed but no verifier was supplied — call VerifiedBy/VerifiedWith so the signature is actually checked")
	}
	if verifier.ID() != h.signatureID {
		return nil, fmt.Errorf("cryptolib: envelope was signed with scheme id %d, but the verifier is %q (id %d)",
			h.signatureID, verifier.Label(), verifier.ID())
	}
	if !verifier.Verify(plaintext, sig) {
		return nil, errors.New("cryptolib: signature verification failed")
	}
	return plaintext, nil
}

// SealIntoCarrier seals plaintext and hides the envelope inside coverPath.
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

func (r *Recipe) builtinVerifier(id uint8) SignatureScheme {
	if r.verifierKey == nil {
		return nil
	}
	switch id {
	case uint8(SigEd25519):
		return Ed25519Signature{Public: r.verifierKey}
	case uint8(SigHybrid):
		return HybridSignature{Public: r.verifierKey}
	}
	return nil
}

func (r *Recipe) rootKey(src KeySource, salt []byte, ops, mem uint64) ([]byte, error) {
	root, err := src.DeriveRoot(salt, ops, mem)
	if err != nil {
		return nil, err
	}
	if len(root) != 32 {
		return nil, fmt.Errorf("cryptolib: key source %q produced %d bytes; the root key must be exactly 32",
			src.Label(), len(root))
	}
	return root, nil
}

func layerKey(root, salt []byte, index int, layer ProtectionLayer) ([]byte, error) {
	return HkdfDerive(root, salt, []byte(fmt.Sprintf("cryptolib/recipe/v1/layer%d/%s", index, layer.WireName())), 32)
}

func (r *Recipe) applyLayer(layer ProtectionLayer, index int, root, salt, header, data []byte, seal bool) ([]byte, error) {
	key, err := layerKey(root, salt, index, layer)
	if err != nil {
		return nil, err
	}
	if seal {
		return layer.Seal(key, header, data)
	}
	return layer.Open(key, header, data)
}

func (r *Recipe) buildHeader(src KeySource, salt []byte) []byte {
	sigID := uint8(SigNone)
	if r.signer != nil {
		sigID = r.signer.ID()
	}
	out := make([]byte, 0, 8+len(r.layers)+recipeSaltLen+8)
	out = append(out, recipeMagic...)
	out = append(out, recipeVersion, src.ID(), sigID, byte(len(r.layers)))
	for _, l := range r.layers {
		out = append(out, l.ID())
	}
	out = append(out, salt...)
	costs := make([]byte, 8)
	binary.BigEndian.PutUint32(costs[0:4], uint32(r.argonOps))
	binary.BigEndian.PutUint32(costs[4:8], uint32(r.argonMem))
	return append(out, costs...)
}

type parsedHeader struct {
	header      []byte
	layers      []ProtectionLayer
	salt        []byte
	signatureID uint8
	ops         uint64
	memory      uint64
}

func (r *Recipe) parseHeader(env []byte, src KeySource) (*parsedHeader, error) {
	if len(env) < 8+recipeSaltLen+8 {
		return nil, errors.New("cryptolib: envelope too short")
	}
	if string(env[:4]) != string(recipeMagic) {
		return nil, errors.New("cryptolib: not a CryptoRecipe envelope")
	}
	if env[4] != recipeVersion {
		return nil, fmt.Errorf("cryptolib: unsupported envelope version %d", env[4])
	}
	if env[5] != src.ID() {
		return nil, fmt.Errorf("cryptolib: envelope was sealed with key source id %d, but this recipe is configured for %q (id %d)",
			env[5], src.Label(), src.ID())
	}
	layerCount := int(env[7])
	headerLen := 8 + layerCount + recipeSaltLen + 8
	if len(env) < headerLen {
		return nil, errors.New("cryptolib: truncated envelope header")
	}
	layers := make([]ProtectionLayer, layerCount)
	for i := 0; i < layerCount; i++ {
		l, err := resolveLayer(env[8+i])
		if err != nil {
			return nil, err
		}
		layers[i] = l
	}
	costs := env[8+layerCount+recipeSaltLen : headerLen]
	return &parsedHeader{
		header:      env[:headerLen],
		layers:      layers,
		salt:        env[8+layerCount : 8+layerCount+recipeSaltLen],
		signatureID: env[6],
		ops:         uint64(binary.BigEndian.Uint32(costs[0:4])),
		memory:      uint64(binary.BigEndian.Uint32(costs[4:8])),
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
	return FecDecode(data[9:], FecScheme(data[4]), int(binary.BigEndian.Uint32(data[5:9])))
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
