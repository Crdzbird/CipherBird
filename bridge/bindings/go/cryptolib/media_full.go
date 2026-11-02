//go:build !cryptolib_bank

// The media, entropy, generator and sntrup entry points: present in the full
// profile only. Build with -tags cryptolib_bank to link against a bank-profile
// library, which lacks their symbols.

package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// VaultFromEntropy creates a vault from a MediaEntropy handle.
func VaultFromEntropy(me *Entropy, kdf int) (*Vault, error) {
	h := C.cryptolib_vault_from_entropy(me.handle, C.int(kdf))
	runtime.KeepAlive(me) // keep the entropy handle alive across the C call
	if h == nil {
		return nil, errors.New("cryptolib: vault from entropy failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, func(v *Vault) { v.Close() })
	return v, nil
}

// SealBoosted encrypts plaintext with an entropy boost (two-factor: master key + media file).
func (v *Vault) SealBoosted(plaintext []byte, aad string, boost *Entropy) (*Packet, error) {
	defer runtime.KeepAlive(v)
	defer runtime.KeepAlive(boost)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	var cerr *C.char
	cp := C.cryptolib_vault_seal_boosted(v.handle,
		u8(plaintext), C.size_t(len(plaintext)),
		caad, boost.handle, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	pkt := packetFromC(cp)
	return &pkt, nil
}

// OpenBoosted decrypts a vault packet with an entropy boost.
func (v *Vault) OpenBoosted(pkt *Packet, aad string, boost *Entropy) ([]byte, error) {
	defer runtime.KeepAlive(v)
	defer runtime.KeepAlive(boost)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	return checkBufResult(C.cryptolib_vault_open_boosted(v.handle, &cp, caad, boost.handle))
}

// EntropyFromFile harvests entropy from a file (LavaRand mode).
// Different keys every call — best for session keys.
func EntropyFromFile(path string) (*Entropy, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	var cerr *C.char
	h := C.cryptolib_entropy_from_file(cp, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	e := &Entropy{handle: h}
	runtime.SetFinalizer(e, func(e *Entropy) { e.Close() })
	return e, nil
}

// EntropyFromFileDeterministic harvests entropy from a file (deterministic).
// Same file always produces same keys — best for cross-process key agreement.
func EntropyFromFileDeterministic(path string) (*Entropy, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	var cerr *C.char
	h := C.cryptolib_entropy_from_file_deterministic(cp, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	e := &Entropy{handle: h}
	runtime.SetFinalizer(e, func(e *Entropy) { e.Close() })
	return e, nil
}

// EntropyFromFiles harvests combined entropy from multiple files (LavaRand).
func EntropyFromFiles(paths []string) (*Entropy, error) {
	if len(paths) == 0 {
		return nil, errors.New("cryptolib: EntropyFromFiles requires at least one path")
	}
	cPaths := make([]*C.char, len(paths))
	for i, p := range paths {
		cPaths[i] = C.CString(p)
		defer C.free(unsafe.Pointer(cPaths[i]))
	}
	var cerr *C.char
	h := C.cryptolib_entropy_from_files(&cPaths[0], C.size_t(len(paths)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	e := &Entropy{handle: h}
	runtime.SetFinalizer(e, func(e *Entropy) { e.Close() })
	return e, nil
}

// DeriveAll returns all 6 domain-separated keys at once.
func (e *Entropy) DeriveAll() DerivedKeys {
	defer runtime.KeepAlive(e)
	dk := C.cryptolib_entropy_derive_all(e.handle)
	return DerivedKeys{
		SymmetricKey:   goBytes(dk.symmetric_key),
		VaultMasterKey: goBytes(dk.vault_master_key),
		SigningSeed:    goBytes(dk.signing_seed),
		BoxSeed:        goBytes(dk.box_seed),
		StreamKey:      goBytes(dk.stream_key),
		RawEntropy:     goBytes(dk.raw_entropy),
	}
}

// SymmetricKey derives a 32-byte symmetric encryption key.
func (e *Entropy) SymmetricKey() ([]byte, error) {
	defer runtime.KeepAlive(e)
	return checkBufResult(C.cryptolib_entropy_symmetric_key(e.handle))
}

// Raw returns the 64-byte raw mixed entropy.
func (e *Entropy) Raw() ([]byte, error) {
	defer runtime.KeepAlive(e)
	return checkBufResult(C.cryptolib_entropy_raw(e.handle))
}

// Boost returns the 32-byte entropy boost key (for two-factor vault).
func (e *Entropy) Boost() ([]byte, error) {
	defer runtime.KeepAlive(e)
	return checkBufResult(C.cryptolib_entropy_boost(e.handle))
}

// Info returns metadata about the entropy source.
func (e *Entropy) Info() EntropyInfo {
	defer runtime.KeepAlive(e)
	ci := C.cryptolib_entropy_info(e.handle)
	info := EntropyInfo{
		Path:        C.GoString(ci.path),
		FileSize:    uint64(ci.file_size),
		ChunksRead:  uint64(ci.chunks_read),
		EntropyBits: float64(ci.entropy_bits),
	}
	C.cryptolib_entropy_info_free(&ci)
	return info
}

// Refresh re-mixes fresh system entropy in-place (for long-lived sessions).
func (e *Entropy) Refresh() {
	defer runtime.KeepAlive(e)
	C.cryptolib_entropy_refresh(e.handle)
}

// Close destroys the entropy handle. Idempotent; cancels the finalizer.
func (e *Entropy) Close() {
	runtime.SetFinalizer(e, nil)
	if e.handle != nil {
		C.cryptolib_entropy_free(e.handle)
		e.handle = nil
	}
}

// ── Convenience functions (no handle needed) ─────────────────────────────────

// KeyFromFile derives a 32-byte key from any file.
func KeyFromFile(path string) ([]byte, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	return checkBufResult(C.cryptolib_key_from_file(cp))
}

// SealFromFile encrypts plaintext using a file as the key (one-liner).
func SealFromFile(path, plaintext, aad string) (*Packet, error) {
	cpath := C.CString(path)
	cpt := cstrSecret(plaintext)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(cpath))
	defer wipeFreeStr(cpt)
	defer C.free(unsafe.Pointer(caad))
	var cerr *C.char
	cp := C.cryptolib_seal_from_file(cpath, cpt, caad, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	pkt := packetFromC(cp)
	return &pkt, nil
}

// OpenFromFile decrypts a packet using a file as the key.
func OpenFromFile(path string, pkt *Packet, aad string) ([]byte, error) {
	cpath := C.CString(path)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(cpath))
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	return checkBufResult(C.cryptolib_open_from_file(cpath, &cp, caad))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Steganography
// ═══════════════════════════════════════════════════════════════════════════════

// StegoEmbed hides payload bytes inside a cover media file.
func StegoEmbed(coverPath string, payload []byte, outputPath string) error {
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	r := C.cryptolib_stego_embed(cc,
		u8(payload), C.size_t(len(payload)),
		co)
	if r.ok == 0 {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		return errors.New(msg)
	}
	return nil
}

// StegoExtract retrieves hidden bytes from a stego media file.
func StegoExtract(stegoPath string) ([]byte, error) {
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_stego_extract(cs))
}

// StegoCapacity returns the maximum payload size for a cover file.
func StegoCapacity(coverPath string) int {
	cc := C.CString(coverPath)
	defer C.free(unsafe.Pointer(cc))
	return int(C.cryptolib_stego_capacity(cc))
}

// StegoEmbedKeyed hides payload bytes with key-derived whitening (and, for
// .ppm carriers, block permutation), so no 'CSTG' signature survives. The same
// key must be supplied to StegoExtractKeyed. The payload should still be
// encrypted — the key governs concealment, not confidentiality.
func StegoEmbedKeyed(coverPath string, payload []byte, outputPath string, key []byte) error {
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	r := C.cryptolib_stego_embed_keyed(cc,
		u8(payload), C.size_t(len(payload)), co,
		u8(key), C.size_t(len(key)))
	return checkResult(r)
}

// StegoExtractKeyed retrieves a keyed-embedded payload. A wrong key fails fast.
func StegoExtractKeyed(stegoPath string, key []byte) ([]byte, error) {
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_stego_extract_keyed(cs, u8(key), C.size_t(len(key))))
}

// StegoEmbedEncrypted AEAD-seals plaintext under a key derived from masterKey,
// then hides the ciphertext (always-encrypt: no cleartext in the carrier). The
// carrier must be .ppm. Use StegoExtractDecrypt with the same key to recover.
func StegoEmbedEncrypted(coverPath string, plaintext []byte, outputPath string, masterKey []byte) error {
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	r := C.cryptolib_stego_embed_encrypted(cc,
		u8(plaintext), C.size_t(len(plaintext)), co,
		u8(masterKey), C.size_t(len(masterKey)))
	return checkResult(r)
}

// StegoExtractDecrypt extracts and AEAD-opens a carrier written by
// StegoEmbedEncrypted. Wrong key or tampering returns an error.
func StegoExtractDecrypt(stegoPath string, masterKey []byte) ([]byte, error) {
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_stego_extract_decrypt(cs, u8(masterKey), C.size_t(len(masterKey))))
}

// PhysicalSeal is the two-factor "the photo is the key" seal: keyMediaPath is
// conditioned into AEAD + stego keys, plaintext (binding aad) is sealed and
// hidden in a SEPARATE coverPath, written to outputPath. Both the key-media and
// the stego carrier are required to recover the message.
func PhysicalSeal(keyMediaPath string, plaintext, aad []byte, coverPath, outputPath string) error {
	km := C.CString(keyMediaPath)
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(km))
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	r := C.cryptolib_physical_seal(km,
		u8(plaintext), C.size_t(len(plaintext)),
		u8(aad), C.size_t(len(aad)),
		cc, co)
	return checkResult(r)
}

// PhysicalOpen recovers a PhysicalSeal message: reconstruct keys from
// keyMediaPath, extract from stegoPath, and AEAD-open under aad.
func PhysicalOpen(keyMediaPath string, aad []byte, stegoPath string) ([]byte, error) {
	km := C.CString(keyMediaPath)
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(km))
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_physical_open(km, u8(aad), C.size_t(len(aad)), cs))
}

// FecEncode applies forward error correction to data.
func FecEncode(data []byte, scheme FecScheme) ([]byte, error) {
	return checkBufResult(C.cryptolib_fec_encode(u8(data), C.size_t(len(data)), C.int(scheme)))
}

// FecDecode recovers originalLen bytes from FEC-encoded data, correcting bit
// errors within the scheme's capability. Returns an error if data is too short.
func FecDecode(data []byte, scheme FecScheme, originalLen int) ([]byte, error) {
	return checkBufResult(C.cryptolib_fec_decode(u8(data), C.size_t(len(data)), C.int(scheme), C.size_t(originalLen)))
}

// StegoInspect checks whether a file is a structurally valid media carrier and
// whether its content matches its extension.
func StegoInspect(path string) (FileInspection, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	r := C.cryptolib_stego_inspect(cp)
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		if r.detail != nil {
			C.cryptolib_str_free(r.detail)
		}
		return FileInspection{}, errors.New(msg)
	}
	fi := FileInspection{
		Parses:     r.parses != 0,
		Format:     uint8(r.format),
		ExtMatches: r.ext_matches != 0,
		Width:      uint64(r.width),
		Height:     uint64(r.height),
		FileSize:   uint64(r.file_size),
		Detail:     C.GoString(r.detail),
	}
	if r.detail != nil {
		C.cryptolib_str_free(r.detail)
	}
	return fi, nil
}

// StegoContentDigest returns the 32-byte BLAKE2b of the whole file. Store it and
// recompute later to detect ANY change (reference-based tamper detection).
func StegoContentDigest(path string) ([]byte, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	return checkBufResult(C.cryptolib_stego_content_digest(cp))
}

// StegoDetectHidden runs the heuristic hidden-data probe over a file. See the
// caveats in the returned Note — this is an indicator, not proof.
func StegoDetectHidden(path string) (HiddenDataReport, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	r := C.cryptolib_stego_detect_hidden(cp)
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		if r.note != nil {
			C.cryptolib_str_free(r.note)
		}
		return HiddenDataReport{}, errors.New(msg)
	}
	rep := HiddenDataReport{
		CryptolibPayload:       r.cryptolib_payload != 0,
		LsbChiSquare:           float64(r.lsb_chi_square),
		LsbEmbeddingLikelihood: float64(r.lsb_embedding_likelihood),
		SamplesAnalysed:        uint64(r.samples_analysed),
		Note:                   C.GoString(r.note),
	}
	if r.note != nil {
		C.cryptolib_str_free(r.note)
	}
	return rep, nil
}

// AssessFileHealth runs the SP 800-90B health tests over a media file. maxBytes
// caps the sample size (0 = default 1 MiB). Use before trusting a file as a
// deterministic key source.
func AssessFileHealth(path string, maxBytes int) (HealthReport, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	r := C.cryptolib_entropy_assess_file_health(cp, C.size_t(maxBytes))
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		return HealthReport{}, errors.New(msg)
	}
	return HealthReport{
		MinEntropyPerByte: float64(r.min_entropy_per_byte),
		LongestRun:        uint64(r.longest_run),
		MaxWindowCount:    uint64(r.max_window_count),
		RctPassed:         r.rct_passed != 0,
		AptPassed:         r.apt_passed != 0,
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// ImageFactorSeal (C2) — a shared reference image as an OPRF-gated second factor
// ═══════════════════════════════════════════════════════════════════════════════

// ImageFactorSeal seals plaintext (binding aad) under OPRF(oprfSecretSeed,
// referenceImage), hiding the ciphertext in coverPath → outputPath. Two factors
// are required to open: the OPRF secret AND the exact reference image.
func ImageFactorSeal(oprfSecretSeed []byte, referenceImagePath string, plaintext, aad []byte, coverPath, outputPath string) error {
	ri := C.CString(referenceImagePath)
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(ri))
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	return checkResult(C.cryptolib_image_factor_seal(
		u8(oprfSecretSeed), C.size_t(len(oprfSecretSeed)), ri,
		u8(plaintext), C.size_t(len(plaintext)),
		u8(aad), C.size_t(len(aad)), cc, co))
}

// ImageFactorOpen recovers an ImageFactorSeal message. Wrong secret / wrong
// reference image / tamper → error.
func ImageFactorOpen(oprfSecretSeed []byte, referenceImagePath string, aad []byte, stegoPath string) ([]byte, error) {
	ri := C.CString(referenceImagePath)
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(ri))
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_image_factor_open(
		u8(oprfSecretSeed), C.size_t(len(oprfSecretSeed)), ri,
		u8(aad), C.size_t(len(aad)), cs))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HpkeStegoSeal (C3) — keyed stego bound to an HPKE session
// ═══════════════════════════════════════════════════════════════════════════════

// HpkeStegoSeal seals plaintext to recipient public key pkR, hiding the
// ciphertext in coverPath → outputPath, and returns the PUBLIC KEM encapsulation
// `enc` (transmit it alongside the carrier). Get pkR from HpkeKeygen.
func HpkeStegoSeal(pkR, plaintext, aad, info []byte, coverPath, outputPath string) ([]byte, error) {
	cc := C.CString(coverPath)
	co := C.CString(outputPath)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(co))
	return checkBufResult(C.cryptolib_hpke_stego_seal(
		u8(pkR), C.size_t(len(pkR)),
		u8(plaintext), C.size_t(len(plaintext)),
		u8(aad), C.size_t(len(aad)),
		u8(info), C.size_t(len(info)), cc, co))
}

// HpkeStegoOpen rebuilds the session from enc + recipient secret skR, extracts,
// and AEAD-opens. Only the holder of skR can.
func HpkeStegoOpen(skR, enc, aad, info []byte, stegoPath string) ([]byte, error) {
	cs := C.CString(stegoPath)
	defer C.free(unsafe.Pointer(cs))
	return checkBufResult(C.cryptolib_hpke_stego_open(
		u8(skR), C.size_t(len(skR)),
		u8(enc), C.size_t(len(enc)),
		u8(aad), C.size_t(len(aad)),
		u8(info), C.size_t(len(info)), cs))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HMAC-DRBG (A3) — stateful accumulator/beacon
// ═══════════════════════════════════════════════════════════════════════════════

// NewDrbg instantiates an HMAC-DRBG from entropy (>= 32 bytes), an optional
// nonce, and an optional personalization string.
func NewDrbg(entropy, nonce, personalization []byte) (*Drbg, error) {
	var cerr *C.char
	h := C.cryptolib_drbg_instantiate(
		u8(entropy), C.size_t(len(entropy)),
		u8(nonce), C.size_t(len(nonce)),
		u8(personalization), C.size_t(len(personalization)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	d := &Drbg{handle: h}
	runtime.SetFinalizer(d, func(d *Drbg) { d.Close() })
	return d, nil
}

// Generate returns numBytes pseudo-random bytes (<= 65536), optional additional input.
func (d *Drbg) Generate(numBytes int, additional []byte) ([]byte, error) {
	r, err := checkBufResult(C.cryptolib_drbg_generate(
		d.handle, C.size_t(numBytes), u8(additional), C.size_t(len(additional))))
	runtime.KeepAlive(d)
	return r, err
}

// Reseed folds fresh entropy into the state.
func (d *Drbg) Reseed(entropy, additional []byte) error {
	err := checkResult(C.cryptolib_drbg_reseed(
		d.handle, u8(entropy), C.size_t(len(entropy)), u8(additional), C.size_t(len(additional))))
	runtime.KeepAlive(d)
	return err
}

// Close frees the native handle (idempotent).
func (d *Drbg) Close() {
	runtime.SetFinalizer(d, nil)
	if d.handle != nil {
		C.cryptolib_drbg_free(d.handle)
		d.handle = nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Fortuna pool (A5) — stateful entropy accumulator
// ═══════════════════════════════════════════════════════════════════════════════

// NewFortuna creates a new, unseeded pool.
func NewFortuna() *Fortuna {
	f := &Fortuna{handle: C.cryptolib_fortuna_new()}
	runtime.SetFinalizer(f, func(f *Fortuna) { f.Close() })
	return f
}

// AddEntropy adds an entropy event from logical source sourceID.
func (f *Fortuna) AddEntropy(sourceID byte, data []byte) {
	C.cryptolib_fortuna_add_entropy(f.handle, C.uint8_t(sourceID), u8(data), C.size_t(len(data)))
	runtime.KeepAlive(f)
}

// Generate returns numBytes; errors if the pool has never been seeded.
func (f *Fortuna) Generate(numBytes int) ([]byte, error) {
	r, err := checkBufResult(C.cryptolib_fortuna_generate(f.handle, C.size_t(numBytes)))
	runtime.KeepAlive(f)
	return r, err
}

// Reseed forces a reseed now (folds in the catch-up-scheduled pools).
func (f *Fortuna) Reseed() { C.cryptolib_fortuna_reseed(f.handle); runtime.KeepAlive(f) }

// ReseedCount returns the number of reseeds so far (0 = never seeded).
func (f *Fortuna) ReseedCount() uint64 {
	n := uint64(C.cryptolib_fortuna_reseed_count(f.handle))
	runtime.KeepAlive(f)
	return n
}

// Close frees the native handle (idempotent).
func (f *Fortuna) Close() {
	runtime.SetFinalizer(f, nil)
	if f.handle != nil {
		C.cryptolib_fortuna_free(f.handle)
		f.handle = nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Post-Quantum — ML-KEM (FIPS 203), ML-DSA (204), SLH-DSA (205)
// ═══════════════════════════════════════════════════════════════════════════════

// SntrupX25519Keygen generates an X25519 + sntrup761 hybrid keypair. sntrup761
// (NTRU Prime) is a different lattice family than ML-KEM — defense-in-diversity.
func SntrupX25519Keygen() KeyPair {
	kp := C.cryptolib_sntrup_x25519_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// SntrupX25519Encapsulate produces a ciphertext + 32-byte hybrid shared secret.
func SntrupX25519Encapsulate(publicKey []byte) (*KemResult, error) {
	var cerr *C.char
	r := C.cryptolib_sntrup_x25519_encapsulate(
		u8(publicKey), C.size_t(len(publicKey)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	return &KemResult{Ciphertext: goBytes(r.ciphertext), SharedSecret: goBytes(r.shared_secret)}, nil
}

// SntrupX25519Decapsulate recovers the shared secret from a ciphertext + secret key.
func SntrupX25519Decapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sntrup_x25519_decapsulate(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(secretKey), C.size_t(len(secretKey))))
}

// EntropyFromFilesDeterministic harvests entropy from multiple files in
// deterministic mode (no system-entropy mixing), yielding reproducible keys for
// the same inputs.
func EntropyFromFilesDeterministic(paths []string) (*Entropy, error) {
	if len(paths) == 0 {
		return nil, errors.New("cryptolib: EntropyFromFilesDeterministic requires at least one path")
	}
	cPaths := make([]*C.char, len(paths))
	for i, p := range paths {
		cPaths[i] = C.CString(p)
		defer C.free(unsafe.Pointer(cPaths[i]))
	}
	var cerr *C.char
	h := C.cryptolib_entropy_from_files_deterministic(&cPaths[0], C.size_t(len(paths)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	e := &Entropy{handle: h}
	runtime.SetFinalizer(e, func(e *Entropy) { e.Close() })
	return e, nil
}

// AsymBundle derives a full asymmetric key bundle (X25519 + Ed25519) from this
// entropy source.
func (e *Entropy) AsymBundle() (AsymBundle, error) {
	defer runtime.KeepAlive(e)
	var cerr *C.char
	cb := C.cryptolib_entropy_asym_bundle(e.handle, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return AsymBundle{}, errors.New(msg)
	}
	return AsymBundle{
		BoxPublic:  goBytes(cb.box_public),
		BoxSecret:  goBytes(cb.box_secret),
		SignPublic: goBytes(cb.sign_public),
		SignSecret: goBytes(cb.sign_secret),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// MolecularVault — maximum-assurance layered encryption
//
// Cascade of XChaCha20-Poly1305 ∘ AES-256-GCM-SIV under a key-committing outer
// layer, keyed by Argon2id(passphrase) or a caller-supplied 32-byte master.
// Composition of vetted primitives only — no new cryptography. Requires the
// native library to be built with OpenSSL (for the GCM-SIV layer).
// ═══════════════════════════════════════════════════════════════════════════════

func init() {
	keyFromFileDeterministicFn = func(path string) ([]byte, error) {
		e, err := EntropyFromFileDeterministic(path)
		if err != nil {
			return nil, err
		}
		defer e.Close()
		return e.SymmetricKey()
	}
	stegoEmbedFn = StegoEmbed
	stegoExtractFn = StegoExtract
	fecEncodeFn = FecEncode
	fecDecodeFn = FecDecode
}
