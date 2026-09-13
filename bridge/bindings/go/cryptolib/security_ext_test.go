package cryptolib

import (
	"bytes"
	"strings"
	"testing"
)

// A user layer: a real AEAD (the library's XChaCha20) under its own identity.
type myLayer struct{}

func (myLayer) ID() uint8                           { return 200 }
func (myLayer) WireName() string                    { return "my-xchacha" }
func (myLayer) Seal(k, a, p []byte) ([]byte, error) { return XChaCha20Encrypt(p, k, a) }
func (myLayer) Open(k, a, c []byte) ([]byte, error) { return XChaCha20Decrypt(c, k, a) }

// A user mixture: three ciphers as ONE layer, by embedding CascadeLayer.
type beltAndBraces struct{ CascadeLayer }

func newBeltAndBraces() beltAndBraces {
	return beltAndBraces{CascadeLayer{Id: 201, Name: "belt-and-braces",
		Layers: []ProtectionLayer{LayerXChaCha20Poly1305, LayerAES256GCM, myLayer{}}}}
}

type impostor struct{}

func (impostor) ID() uint8                           { return 3 }
func (impostor) WireName() string                    { return "committing" }
func (impostor) Seal(_, _, p []byte) ([]byte, error) { return p, nil }
func (impostor) Open(_, _, c []byte) ([]byte, error) { return c, nil }

type tokenSource struct{ token []byte }

func (tokenSource) ID() uint8                                           { return 210 }
func (tokenSource) Label() string                                       { return "token" }
func (t tokenSource) DeriveRoot([]byte, uint64, uint64) ([]byte, error) { return t.token, nil }

type weakSource struct{}

func (weakSource) ID() uint8                                         { return 211 }
func (weakSource) Label() string                                     { return "weak" }
func (weakSource) DeriveRoot([]byte, uint64, uint64) ([]byte, error) { return make([]byte, 16), nil }

type prefixedEd25519 struct{ sk, pk []byte }

func (prefixedEd25519) ID() uint8                       { return 220 }
func (prefixedEd25519) Label() string                   { return "prefixed-ed25519" }
func tag(m []byte) []byte                               { return append([]byte("custom:"), m...) }
func (p prefixedEd25519) Sign(m []byte) ([]byte, error) { return Ed25519Sign(tag(m), p.sk) }
func (p prefixedEd25519) Verify(m, s []byte) bool       { return Ed25519Verify(tag(m), s, p.pk) }

type fakeEd25519 struct{}

func (fakeEd25519) ID() uint8                   { return 1 }
func (fakeEd25519) Label() string               { return "fake" }
func (fakeEd25519) Sign([]byte) ([]byte, error) { return make([]byte, 64), nil }
func (fakeEd25519) Verify(_, _ []byte) bool     { return true }

func TestExtBuiltinIdsPinned(t *testing.T) {
	if LayerXChaCha20Poly1305.ID() != 1 || LayerAES256GCM.ID() != 2 || LayerCommitting.ID() != 3 || LayerMolecular.ID() != 4 {
		t.Fatal("built-in layer ids moved")
	}
	if (PassphraseKeySource{}).ID() != 1 || (Ed25519Signature{}).ID() != 1 || (HybridSignature{}).ID() != 2 {
		t.Fatal("built-in source/scheme ids moved")
	}
}

func TestExtCustomLayerAndCascade(t *testing.T) {
	secret := []byte("the treaty text nobody may read")
	if err := RegisterLayer(myLayer{}); err != nil {
		t.Fatal(err)
	}
	key, _ := RandomBytes(32)
	env, err := NewRecipe(ProfileBalanced).WithKey(key).WithLayers([]ProtectionLayer{myLayer{}}).Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := NewRecipe(ProfileBalanced).WithKey(key).Open(env); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("custom layer via registry: %v", err)
	}

	if err := RegisterLayer(newBeltAndBraces()); err != nil {
		t.Fatal(err)
	}
	r := NewRecipe(ProfileBalanced).WithKey(key).WithLayers([]ProtectionLayer{newBeltAndBraces()})
	cenv, err := r.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := NewRecipe(ProfileBalanced).WithKey(key).Open(cenv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("cascade: %v", err)
	}
	bad := append([]byte(nil), cenv...)
	bad[len(bad)-1] ^= 1
	if _, err := r.Open(bad); err == nil {
		t.Fatal("cascade must fail closed on tamper")
	}
	// Nest a cascade inside a cascade, mixed with a built-in outer layer.
	nested := CascadeLayer{Id: 202, Name: "nested", Layers: []ProtectionLayer{newBeltAndBraces(), LayerCommitting}}
	if err := RegisterLayer(nested); err != nil {
		t.Fatal(err)
	}
	nenv, _ := NewRecipe(ProfileBalanced).WithKey(key).WithLayers([]ProtectionLayer{LayerXChaCha20Poly1305, nested}).Seal(secret)
	if got, err := NewRecipe(ProfileBalanced).WithKey(key).Open(nenv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("nested cascade: %v", err)
	}
}

func TestExtGuardrails(t *testing.T) {
	secret := []byte("x")
	key, _ := RandomBytes(32)
	if err := RegisterLayer(impostor{}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved id must be refused at register: %v", err)
	}
	if _, err := NewRecipe(ProfileBalanced).WithKey(key).AddLayer(impostor{}).Seal(secret); err == nil {
		t.Fatal("reserved id must be refused at AddLayer")
	}
	_ = RegisterLayer(myLayer{}) // idempotent
	if err := RegisterLayer(CascadeLayer{Id: 200, Name: "other", Layers: []ProtectionLayer{LayerXChaCha20Poly1305}}); err == nil {
		t.Fatal("re-registering an id under another name must be refused")
	}
	// wireName feeds the key derivation: same algorithm, different name → different bytes.
	e1, _ := NewRecipe(ProfileBalanced).WithKey(key).WithLayers([]ProtectionLayer{myLayer{}}).Seal(secret)
	e2, _ := NewRecipe(ProfileBalanced).WithKey(key).WithLayers([]ProtectionLayer{CascadeLayer{Id: 203, Name: "renamed", Layers: []ProtectionLayer{LayerXChaCha20Poly1305}}}).Seal(secret)
	if len(e1) != len(e2) || bytes.Equal(e1, e2) {
		t.Fatal("wireName must change the derived key")
	}
	if _, err := NewRecipe(ProfileBalanced).WithKeySource(weakSource{}).Seal(secret); err == nil || !strings.Contains(err.Error(), "exactly 32") {
		t.Fatalf("narrowing key source must be refused: %v", err)
	}
	if _, err := NewRecipe(ProfileBalanced).WithKey(key).SignedWith(fakeEd25519{}).Seal(secret); err == nil {
		t.Fatal("scheme claiming a built-in id must be refused")
	}
}

func TestExtCustomKeySourceAndSigner(t *testing.T) {
	secret := []byte("the treaty text nobody may read")
	token, _ := RandomBytes(32)
	env, err := NewRecipe(ProfileHigh).WithKeySource(tokenSource{token}).Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := NewRecipe(ProfileHigh).WithKeySource(tokenSource{token}).Open(env); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("token source: %v", err)
	}
	other, _ := RandomBytes(32)
	if _, err := NewRecipe(ProfileHigh).WithKeySource(tokenSource{other}).Open(env); err == nil {
		t.Fatal("wrong token must be rejected")
	}
	if _, err := NewRecipe(ProfileHigh).WithKey(other).Open(env); err == nil || !strings.Contains(err.Error(), "key source id 210") {
		t.Fatalf("header must pin the source id: %v", err)
	}

	id := Ed25519Keygen()
	key, _ := RandomBytes(32)
	senv, err := NewRecipe(ProfileBalanced).WithKey(key).SignedWith(prefixedEd25519{sk: id.Secret}).Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := NewRecipe(ProfileBalanced).WithKey(key).VerifiedWith(prefixedEd25519{pk: id.Public}).Open(senv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("custom scheme: %v", err)
	}
	if _, err := NewRecipe(ProfileBalanced).WithKey(key).VerifiedBy(id.Public).Open(senv); err == nil || !strings.Contains(err.Error(), "scheme id 220") {
		t.Fatalf("key-only verifier cannot serve a custom scheme: %v", err)
	}
	if _, err := NewRecipe(ProfileBalanced).WithKey(key).Open(senv); err == nil {
		t.Fatal("unverified signed envelope must be refused")
	}
	// Built-in shorthand: VerifiedBy infers the scheme from the envelope.
	hid := HybridSigKeygen()
	hr := NewRecipe(ProfileBalanced).WithKey(key).SignedBy(hid.Secret, SigHybrid).VerifiedBy(hid.Public)
	henv, _ := hr.Seal(secret)
	if got, err := hr.Open(henv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("built-in shorthand: %v", err)
	}
	d := NewRecipe(ProfileBalanced).WithKeySource(tokenSource{token}).WithLayers([]ProtectionLayer{newBeltAndBraces()}).Describe()
	if !strings.Contains(d, "token") || !strings.Contains(d, "belt-and-braces") {
		t.Fatalf("describe must name custom parts:\n%s", d)
	}
}
