// Package cryptolib provides Go bindings for the CryptoLib C++ library
// via cgo. It wraps the C FFI bridge (libcryptolib_c) and provides
// idiomatic Go types and error handling.
//
// Before using, build the shared library:
//
//	cd /path/to/cryptolib
//	cmake -B build/release -DCMAKE_BUILD_TYPE=Release
//	cmake --build build/release --target cryptolib_c
//
// Then set the dynamic library path:
//
//	export DYLD_LIBRARY_PATH=/path/to/cryptolib/build/release  # macOS
//	export LD_LIBRARY_PATH=/path/to/cryptolib/build/release    # Linux
package cryptolib

/*
#cgo CFLAGS: -I${SRCDIR}/../../../
#cgo LDFLAGS: -L${SRCDIR}/../../../../build/release -lcryptolib_c

#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Init
// ═══════════════════════════════════════════════════════════════════════════════

// Init initialises libsodium. Call once at program start.
func Init() error {
	if C.cryptolib_init() != 0 {
		return errors.New("cryptolib: init failed")
	}
	return nil
}

// Version returns the library version string.
func Version() string {
	return C.GoString(C.cryptolib_version())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Buffer helpers
// ═══════════════════════════════════════════════════════════════════════════════

// goBytes copies a CryptoBuffer into a Go []byte and frees the C buffer.
func goBytes(buf C.CryptoBuffer) []byte {
	if buf.data == nil || buf.len == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	C.cryptolib_buffer_free(&buf)
	return out
}

// checkBufResult converts a CryptoBufferResult to ([]byte, error).
func checkBufResult(r C.CryptoBufferResult) ([]byte, error) {
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		return nil, errors.New(msg)
	}
	return goBytes(r.buf), nil
}

// Hex returns the hex encoding of a byte slice.
func Hex(b []byte) string {
	return hex.EncodeToString(b)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Random bytes
// ═══════════════════════════════════════════════════════════════════════════════

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	return checkBufResult(C.cryptolib_random_bytes(C.size_t(n)))
}

// SecureEqual performs constant-time comparison of two byte slices.
func SecureEqual(a, b []byte) bool {
	var ap, bp *C.uint8_t
	if len(a) > 0 {
		ap = (*C.uint8_t)(unsafe.Pointer(&a[0]))
	}
	if len(b) > 0 {
		bp = (*C.uint8_t)(unsafe.Pointer(&b[0]))
	}
	return C.cryptolib_secure_equal(ap, C.size_t(len(a)), bp, C.size_t(len(b))) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hashing
// ═══════════════════════════════════════════════════════════════════════════════

// Blake2b computes a BLAKE2b-512 hash. key may be nil for unkeyed hashing.
func Blake2b(msg, key []byte) ([]byte, error) {
	var kp *C.uint8_t
	var kl C.size_t
	if len(key) > 0 {
		kp = (*C.uint8_t)(unsafe.Pointer(&key[0]))
		kl = C.size_t(len(key))
	}
	return checkBufResult(C.cryptolib_blake2b(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		kp, kl))
}

// SHA256 computes a SHA-256 hash.
func SHA256(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sha256(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg))))
}

// SHA512 computes a SHA-512 hash.
func SHA512(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sha512(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg))))
}

// HmacSHA512 computes an HMAC-SHA512.
func HmacSHA512(msg, key []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hmac_sha512(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key))))
}

// HmacSHA512Verify verifies an HMAC-SHA512.
func HmacSHA512Verify(msg, mac, key []byte) bool {
	return C.cryptolib_hmac_sha512_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&mac[0])), C.size_t(len(mac)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key))) == 1
}

// Argon2idHashStr hashes a password to PHC string format.
func Argon2idHashStr(password string, ops uint64, mem uint64) (string, error) {
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cp))
	r := C.cryptolib_argon2id_hash_str(cp, C.uint64_t(ops), C.size_t(mem))
	b, err := checkBufResult(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Argon2idVerifyStr verifies a password against a PHC string.
func Argon2idVerifyStr(password, phcStr string) bool {
	cp := C.CString(password)
	cs := C.CString(phcStr)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	return C.cryptolib_argon2id_verify_str(cp, cs) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// Symmetric encryption
// ═══════════════════════════════════════════════════════════════════════════════

// SymKeygen generates a 32-byte random symmetric key.
func SymKeygen() ([]byte, error) {
	return checkBufResult(C.cryptolib_sym_keygen())
}

// XChaCha20Encrypt encrypts with XChaCha20-Poly1305. aad may be nil.
func XChaCha20Encrypt(plaintext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_xchacha20_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		aadp, aadl))
}

// XChaCha20Decrypt decrypts XChaCha20-Poly1305 ciphertext.
func XChaCha20Decrypt(ciphertext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_xchacha20_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		aadp, aadl))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Symmetric encryption — AES-256-GCM
// ═══════════════════════════════════════════════════════════════════════════════

// AES256GCMAvailable returns true if AES-256-GCM is supported on this CPU.
func AES256GCMAvailable() bool {
	return C.cryptolib_aes256gcm_available() != 0
}

// AES256GCMEncrypt encrypts with AES-256-GCM. aad may be nil.
func AES256GCMEncrypt(plaintext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_aes256gcm_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		aadp, aadl))
}

// AES256GCMDecrypt decrypts AES-256-GCM ciphertext.
func AES256GCMDecrypt(ciphertext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_aes256gcm_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		aadp, aadl))
}

// ═══════════════════════════════════════════════════════════════════════════════
// SecretStream — chunked streaming AEAD
// ═══════════════════════════════════════════════════════════════════════════════

// Stream tag constants.
const (
	TagMessage uint8 = 0
	TagFinal   uint8 = 3
)

// StreamEncryptor wraps a streaming AEAD encryptor handle.
type StreamEncryptor struct {
	handle C.CryptoStreamEncHandle
}

// NewStreamEncryptor creates a streaming encryptor from a 32-byte key.
func NewStreamEncryptor(key []byte) *StreamEncryptor {
	h := C.cryptolib_stream_enc_create((*C.uint8_t)(unsafe.Pointer(&key[0])))
	if h == nil {
		return nil
	}
	s := &StreamEncryptor{handle: h}
	runtime.SetFinalizer(s, func(s *StreamEncryptor) { s.Close() })
	return s
}

// Header returns the 24-byte stream header that must be sent to the decryptor.
func (s *StreamEncryptor) Header() ([]byte, error) {
	return checkBufResult(C.cryptolib_stream_enc_header(s.handle))
}

// Push encrypts a chunk. Use TagMessage for intermediate chunks, TagFinal for the last.
func (s *StreamEncryptor) Push(plaintext []byte, tag uint8) ([]byte, error) {
	return checkBufResult(C.cryptolib_stream_enc_push(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		C.uint8_t(tag)))
}

// Close destroys the encryptor handle.
func (s *StreamEncryptor) Close() {
	if s.handle != nil {
		C.cryptolib_stream_enc_free(s.handle)
		s.handle = nil
	}
}

// StreamDecryptor wraps a streaming AEAD decryptor handle.
type StreamDecryptor struct {
	handle C.CryptoStreamDecHandle
}

// NewStreamDecryptor creates a streaming decryptor from a 32-byte key and 24-byte header.
func NewStreamDecryptor(key, header []byte) *StreamDecryptor {
	h := C.cryptolib_stream_dec_create(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&header[0])))
	if h == nil {
		return nil
	}
	s := &StreamDecryptor{handle: h}
	runtime.SetFinalizer(s, func(s *StreamDecryptor) { s.Close() })
	return s
}

// Pull decrypts a chunk. Returns plaintext and the tag byte.
func (s *StreamDecryptor) Pull(ciphertext []byte) (plaintext []byte, tag uint8, err error) {
	var ctag C.uint8_t
	r := C.cryptolib_stream_dec_pull(
		s.handle,
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		&ctag)
	pt, e := checkBufResult(r)
	return pt, uint8(ctag), e
}

// Close destroys the decryptor handle.
func (s *StreamDecryptor) Close() {
	if s.handle != nil {
		C.cryptolib_stream_dec_free(s.handle)
		s.handle = nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric — Ed25519
// ═══════════════════════════════════════════════════════════════════════════════

// KeyPair holds a public/secret key pair.
type KeyPair struct {
	Public []byte
	Secret []byte
}

// Ed25519Keygen generates an Ed25519 signing keypair.
func Ed25519Keygen() KeyPair {
	kp := C.cryptolib_ed25519_keygen()
	return KeyPair{
		Public: goBytes(kp.public_key),
		Secret: goBytes(kp.secret_key),
	}
}

// Ed25519KeygenFromSeed generates an Ed25519 keypair from a 32-byte seed (deterministic).
func Ed25519KeygenFromSeed(seed []byte) KeyPair {
	kp := C.cryptolib_ed25519_keygen_from_seed(
		(*C.uint8_t)(unsafe.Pointer(&seed[0])), C.size_t(len(seed)))
	return KeyPair{
		Public: goBytes(kp.public_key),
		Secret: goBytes(kp.secret_key),
	}
}

// Ed25519Sign signs a message with an Ed25519 secret key.
func Ed25519Sign(msg, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ed25519_sign(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey))))
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(msg, sig, publicKey []byte) bool {
	return C.cryptolib_ed25519_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey))) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric — Box (authenticated encryption)
// ═══════════════════════════════════════════════════════════════════════════════

// BoxKeygen generates a Box (X25519) keypair.
func BoxKeygen() KeyPair {
	kp := C.cryptolib_box_keygen()
	return KeyPair{
		Public: goBytes(kp.public_key),
		Secret: goBytes(kp.secret_key),
	}
}

// BoxEncrypt performs sender→recipient authenticated encryption.
func BoxEncrypt(plaintext, recipientPub, senderSec []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_box_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&recipientPub[0])), C.size_t(len(recipientPub)),
		(*C.uint8_t)(unsafe.Pointer(&senderSec[0])), C.size_t(len(senderSec))))
}

// BoxDecrypt decrypts a Box ciphertext.
func BoxDecrypt(ciphertext, senderPub, recipientSec []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_box_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&senderPub[0])), C.size_t(len(senderPub)),
		(*C.uint8_t)(unsafe.Pointer(&recipientSec[0])), C.size_t(len(recipientSec))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric — SealedBox (anonymous sender)
// ═══════════════════════════════════════════════════════════════════════════════

// SealedBoxEncrypt encrypts with an anonymous sender (only recipient can decrypt).
func SealedBoxEncrypt(plaintext, recipientPub []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sealedbox_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		(*C.uint8_t)(unsafe.Pointer(&recipientPub[0])), C.size_t(len(recipientPub))))
}

// SealedBoxDecrypt decrypts a SealedBox ciphertext.
func SealedBoxDecrypt(ciphertext, recipientPub, recipientSec []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sealedbox_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&recipientPub[0])), C.size_t(len(recipientPub)),
		(*C.uint8_t)(unsafe.Pointer(&recipientSec[0])), C.size_t(len(recipientSec))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric — X25519 key agreement
// ═══════════════════════════════════════════════════════════════════════════════

// X25519Keygen generates an X25519 key agreement keypair.
func X25519Keygen() KeyPair {
	kp := C.cryptolib_x25519_keygen()
	return KeyPair{
		Public: goBytes(kp.public_key),
		Secret: goBytes(kp.secret_key),
	}
}

// X25519SharedSecret computes a 32-byte shared secret from our secret key and their public key.
func X25519SharedSecret(ourSecret, theirPublic []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_x25519_shared_secret(
		(*C.uint8_t)(unsafe.Pointer(&ourSecret[0])), C.size_t(len(ourSecret)),
		(*C.uint8_t)(unsafe.Pointer(&theirPublic[0])), C.size_t(len(theirPublic))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Vault — 4-layer pipeline
// ═══════════════════════════════════════════════════════════════════════════════

// KDF presets.
const (
	KdfInteractive = 0
	KdfSensitive   = 1
)

// Vault wraps a SecureVault handle.
type Vault struct {
	handle C.CryptoVaultHandle
}

// NewVault creates a vault from a 32-byte master key.
func NewVault(masterKey []byte, kdf int) (*Vault, error) {
	h := C.cryptolib_vault_create(
		(*C.uint8_t)(unsafe.Pointer(&masterKey[0])), C.size_t(len(masterKey)),
		C.int(kdf))
	if h == nil {
		return nil, errors.New("cryptolib: vault creation failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, func(v *Vault) { v.Close() })
	return v, nil
}

// VaultFromEntropy creates a vault from a MediaEntropy handle.
func VaultFromEntropy(me *Entropy, kdf int) (*Vault, error) {
	h := C.cryptolib_vault_from_entropy(me.handle, C.int(kdf))
	if h == nil {
		return nil, errors.New("cryptolib: vault from entropy failed")
	}
	v := &Vault{handle: h}
	runtime.SetFinalizer(v, func(v *Vault) { v.Close() })
	return v, nil
}

// Packet holds a serialisable encrypted vault output.
type Packet struct {
	Ciphertext []byte
	Signature  []byte
	KdfSalt    []byte
}

func packetFromC(cp C.CryptoPacket) Packet {
	return Packet{
		Ciphertext: goBytes(cp.ciphertext),
		Signature:  goBytes(cp.signature),
		KdfSalt:    goBytes(cp.kdf_salt),
	}
}

func (p *Packet) toC() C.CryptoPacket {
	var cp C.CryptoPacket
	if len(p.Ciphertext) > 0 {
		cp.ciphertext.data = (*C.uint8_t)(C.CBytes(p.Ciphertext))
		cp.ciphertext.len = C.size_t(len(p.Ciphertext))
	}
	if len(p.Signature) > 0 {
		cp.signature.data = (*C.uint8_t)(C.CBytes(p.Signature))
		cp.signature.len = C.size_t(len(p.Signature))
	}
	if len(p.KdfSalt) > 0 {
		cp.kdf_salt.data = (*C.uint8_t)(C.CBytes(p.KdfSalt))
		cp.kdf_salt.len = C.size_t(len(p.KdfSalt))
	}
	return cp
}

func (p *Packet) freeC(cp *C.CryptoPacket) {
	C.free(unsafe.Pointer(cp.ciphertext.data))
	C.free(unsafe.Pointer(cp.signature.data))
	C.free(unsafe.Pointer(cp.kdf_salt.data))
}

// Seal encrypts plaintext through the 4-layer vault pipeline.
func (v *Vault) Seal(plaintext []byte, aad string) (*Packet, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	var cerr *C.char
	cp := C.cryptolib_vault_seal(v.handle,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		caad, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	pkt := packetFromC(cp)
	return &pkt, nil
}

// Open decrypts a vault packet.
func (v *Vault) Open(pkt *Packet, aad string) ([]byte, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	return checkBufResult(C.cryptolib_vault_open(v.handle, &cp, caad))
}

// PublicKey returns the vault's Ed25519 public key.
func (v *Vault) PublicKey() ([]byte, error) {
	return checkBufResult(C.cryptolib_vault_public_key(v.handle))
}

// SealBoosted encrypts plaintext with an entropy boost (two-factor: master key + media file).
func (v *Vault) SealBoosted(plaintext []byte, aad string, boost *Entropy) (*Packet, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	var cerr *C.char
	cp := C.cryptolib_vault_seal_boosted(v.handle,
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
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
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	return checkBufResult(C.cryptolib_vault_open_boosted(v.handle, &cp, caad, boost.handle))
}

// Close destroys the vault handle.
func (v *Vault) Close() {
	if v.handle != nil {
		C.cryptolib_vault_free(v.handle)
		v.handle = nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keyring — envelope encryption with key-slots (device / passphrase)
// ═══════════════════════════════════════════════════════════════════════════════

// Keyring wraps a random master key in unlock slots. Default is one device slot;
// add a passphrase slot to enable cross-device unlock.
type Keyring struct {
	handle C.CryptoKeyringHandle
}

// NewKeyring creates a keyring with a fresh random master key.
func NewKeyring() *Keyring {
	k := &Keyring{handle: C.cryptolib_keyring_create()}
	runtime.SetFinalizer(k, func(k *Keyring) { k.Close() })
	return k
}

// AddDeviceSlot wraps the master key under a >=32-byte hardware factor key.
func (k *Keyring) AddDeviceSlot(factor []byte) bool {
	if len(factor) == 0 {
		return false
	}
	return C.cryptolib_keyring_add_device_slot(k.handle,
		(*C.uint8_t)(unsafe.Pointer(&factor[0])), C.size_t(len(factor))) == 1
}

// AddPassphraseSlot wraps the master key under Argon2id. kdf: 0=interactive, 1=sensitive.
func (k *Keyring) AddPassphraseSlot(passphrase string, kdf int) bool {
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	return C.cryptolib_keyring_add_passphrase_slot(k.handle, cpw, C.int(kdf)) == 1
}

// SlotCount returns the number of slots.
func (k *Keyring) SlotCount() int { return int(C.cryptolib_keyring_slot_count(k.handle)) }

// RemoveSlot revokes a slot by index.
func (k *Keyring) RemoveSlot(index int) bool {
	return C.cryptolib_keyring_remove_slot(k.handle, C.size_t(index)) == 1
}

// Serialise returns the envelope blob (contains no plaintext key).
func (k *Keyring) Serialise() ([]byte, error) {
	return checkBufResult(C.cryptolib_keyring_serialise(k.handle))
}

// DeserialiseKeyring parses an envelope blob into a (locked) keyring.
func DeserialiseKeyring(blob []byte) (*Keyring, error) {
	if len(blob) == 0 {
		return nil, errors.New("cryptolib: empty keyring blob")
	}
	var cerr *C.char
	h := C.cryptolib_keyring_deserialise(
		(*C.uint8_t)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)), &cerr)
	if h == nil {
		msg := "cryptolib: keyring deserialise failed"
		if cerr != nil {
			msg = C.GoString(cerr)
			C.cryptolib_str_free(cerr)
		}
		return nil, errors.New(msg)
	}
	k := &Keyring{handle: h}
	runtime.SetFinalizer(k, func(k *Keyring) { k.Close() })
	return k, nil
}

// UnlockWithDevice recovers the master key using a device factor key.
func (k *Keyring) UnlockWithDevice(factor []byte) ([]byte, error) {
	if len(factor) == 0 {
		return nil, errors.New("cryptolib: empty factor key")
	}
	return checkBufResult(C.cryptolib_keyring_unlock_with_device(k.handle,
		(*C.uint8_t)(unsafe.Pointer(&factor[0])), C.size_t(len(factor))))
}

// UnlockWithPassphrase recovers the master key using a passphrase.
func (k *Keyring) UnlockWithPassphrase(passphrase string) ([]byte, error) {
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	return checkBufResult(C.cryptolib_keyring_unlock_with_passphrase(k.handle, cpw))
}

// Close destroys the keyring handle.
func (k *Keyring) Close() {
	if k.handle != nil {
		C.cryptolib_keyring_free(k.handle)
		k.handle = nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric Vault — Alice→Bob authenticated encryption
// ═══════════════════════════════════════════════════════════════════════════════

// AsymBundle holds Box (X25519) + Sign (Ed25519) key material.
type AsymBundle struct {
	BoxPublic  []byte
	BoxSecret  []byte
	SignPublic []byte
	SignSecret []byte
}

// AsymBundleGenerate creates a full asymmetric key bundle (X25519 + Ed25519).
func AsymBundleGenerate() AsymBundle {
	cb := C.cryptolib_asym_bundle_generate()
	return AsymBundle{
		BoxPublic:  goBytes(cb.box_public),
		BoxSecret:  goBytes(cb.box_secret),
		SignPublic: goBytes(cb.sign_public),
		SignSecret: goBytes(cb.sign_secret),
	}
}

func (b *AsymBundle) toC() C.CryptoAsymBundle {
	var cb C.CryptoAsymBundle
	if len(b.BoxPublic) > 0 {
		cb.box_public.data = (*C.uint8_t)(C.CBytes(b.BoxPublic))
		cb.box_public.len = C.size_t(len(b.BoxPublic))
	}
	if len(b.BoxSecret) > 0 {
		cb.box_secret.data = (*C.uint8_t)(C.CBytes(b.BoxSecret))
		cb.box_secret.len = C.size_t(len(b.BoxSecret))
	}
	if len(b.SignPublic) > 0 {
		cb.sign_public.data = (*C.uint8_t)(C.CBytes(b.SignPublic))
		cb.sign_public.len = C.size_t(len(b.SignPublic))
	}
	if len(b.SignSecret) > 0 {
		cb.sign_secret.data = (*C.uint8_t)(C.CBytes(b.SignSecret))
		cb.sign_secret.len = C.size_t(len(b.SignSecret))
	}
	return cb
}

func (b *AsymBundle) freeC(cb *C.CryptoAsymBundle) {
	C.free(unsafe.Pointer(cb.box_public.data))
	C.free(unsafe.Pointer(cb.box_secret.data))
	C.free(unsafe.Pointer(cb.sign_public.data))
	C.free(unsafe.Pointer(cb.sign_secret.data))
}

// AsymVaultSeal encrypts plaintext from sender to recipient with signature.
func AsymVaultSeal(sender *AsymBundle, recipientBoxPub, plaintext []byte, aad string) (*Packet, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cs := sender.toC()
	defer sender.freeC(&cs)
	var cerr *C.char
	cp := C.cryptolib_asym_vault_seal(&cs,
		(*C.uint8_t)(unsafe.Pointer(&recipientBoxPub[0])), C.size_t(len(recipientBoxPub)),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		caad, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	pkt := packetFromC(cp)
	return &pkt, nil
}

// AsymVaultOpen decrypts a packet and verifies the sender's signature.
func AsymVaultOpen(pkt *Packet, recipient *AsymBundle, senderSignPub []byte, aad string) ([]byte, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	cr := recipient.toC()
	defer recipient.freeC(&cr)
	return checkBufResult(C.cryptolib_asym_vault_open(&cp, &cr,
		(*C.uint8_t)(unsafe.Pointer(&senderSignPub[0])), C.size_t(len(senderSignPub)),
		caad))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Argon2id — key derivation
// ═══════════════════════════════════════════════════════════════════════════════

// Argon2idDerive derives a key from a password and salt using Argon2id.
func Argon2idDerive(password string, salt []byte, keyLen int, ops uint64, mem uint64) ([]byte, error) {
	cp := C.CString(password)
	defer C.free(unsafe.Pointer(cp))
	return checkBufResult(C.cryptolib_argon2id_derive(cp,
		(*C.uint8_t)(unsafe.Pointer(&salt[0])), C.size_t(len(salt)),
		C.size_t(keyLen), C.uint64_t(ops), C.size_t(mem)))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Media Entropy — LavaRand-inspired key derivation from files
// ═══════════════════════════════════════════════════════════════════════════════

// Entropy wraps a MediaEntropy handle. Create from any media file
// (photo, audio, video) to derive cryptographic keys from physical noise.
type Entropy struct {
	handle C.CryptoEntropyHandle
}

// EntropyInfo holds metadata about the entropy source.
type EntropyInfo struct {
	Path        string
	FileSize    uint64
	ChunksRead  uint64
	EntropyBits float64
}

// DerivedKeys holds all 6 domain-separated keys from one media file.
type DerivedKeys struct {
	SymmetricKey   []byte // 32 B — XChaCha20/AES-256
	VaultMasterKey []byte // 32 B — SecureVault master
	SigningSeed    []byte // 32 B — Ed25519 seed
	BoxSeed        []byte // 32 B — X25519 seed
	StreamKey      []byte // 32 B — SecretStream
	RawEntropy     []byte // 64 B — raw mixed entropy
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
	return checkBufResult(C.cryptolib_entropy_symmetric_key(e.handle))
}

// Raw returns the 64-byte raw mixed entropy.
func (e *Entropy) Raw() ([]byte, error) {
	return checkBufResult(C.cryptolib_entropy_raw(e.handle))
}

// Boost returns the 32-byte entropy boost key (for two-factor vault).
func (e *Entropy) Boost() ([]byte, error) {
	return checkBufResult(C.cryptolib_entropy_boost(e.handle))
}

// Info returns metadata about the entropy source.
func (e *Entropy) Info() EntropyInfo {
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
	C.cryptolib_entropy_refresh(e.handle)
}

// Close destroys the entropy handle.
func (e *Entropy) Close() {
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
	cpt := C.CString(plaintext)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(cpath))
	defer C.free(unsafe.Pointer(cpt))
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
		(*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)),
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

// ═══════════════════════════════════════════════════════════════════════════════
// Pretty-print helper for examples
// ═══════════════════════════════════════════════════════════════════════════════

// Print prints a labelled hex-encoded value.
func Print(label string, data []byte) {
	fmt.Printf("  %-24s %s\n", label+":", Hex(data))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Post-Quantum — ML-KEM (FIPS 203), ML-DSA (204), SLH-DSA (205)
// ═══════════════════════════════════════════════════════════════════════════════

// KemResult holds a KEM encapsulation (ciphertext + shared secret).
type KemResult struct {
	Ciphertext   []byte
	SharedSecret []byte
}

// MlKemKeygen generates an ML-KEM keypair. level: 0=512, 1=768, 2=1024.
func MlKemKeygen(level int) KeyPair {
	kp := C.cryptolib_ml_kem_keygen(C.int(level))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// MlKemEncapsulate produces a ciphertext + shared secret for a public key.
func MlKemEncapsulate(publicKey []byte, level int) (*KemResult, error) {
	var cerr *C.char
	r := C.cryptolib_ml_kem_encapsulate(
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey)), C.int(level), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	return &KemResult{Ciphertext: goBytes(r.ciphertext), SharedSecret: goBytes(r.shared_secret)}, nil
}

// MlKemDecapsulate recovers the shared secret from a ciphertext + secret key.
func MlKemDecapsulate(ciphertext, secretKey []byte, level int) ([]byte, error) {
	return checkBufResult(C.cryptolib_ml_kem_decapsulate(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey)), C.int(level)))
}

// HybridKemKeygen generates an X25519 + ML-KEM-768 hybrid keypair (concatenated
// layout). Secure while either the classical or post-quantum half is unbroken.
func HybridKemKeygen() KeyPair {
	kp := C.cryptolib_hybrid_kem_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// HybridKemEncapsulate produces a ciphertext + 32-byte hybrid shared secret.
func HybridKemEncapsulate(publicKey []byte) (*KemResult, error) {
	var cerr *C.char
	r := C.cryptolib_hybrid_kem_encapsulate(
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	return &KemResult{Ciphertext: goBytes(r.ciphertext), SharedSecret: goBytes(r.shared_secret)}, nil
}

// HybridKemDecapsulate recovers the shared secret from a ciphertext + secret key.
func HybridKemDecapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hybrid_kem_decapsulate(
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey))))
}

// MlDsaKeygen generates an ML-DSA signing keypair. level: 0=44, 1=65, 2=87.
func MlDsaKeygen(level int) KeyPair {
	kp := C.cryptolib_ml_dsa_keygen(C.int(level))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// MlDsaSign signs a message with an ML-DSA secret key.
func MlDsaSign(msg, secretKey []byte, level int) ([]byte, error) {
	return checkBufResult(C.cryptolib_ml_dsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey)), C.int(level)))
}

// MlDsaVerify verifies an ML-DSA signature.
func MlDsaVerify(msg, sig, publicKey []byte, level int) bool {
	return C.cryptolib_ml_dsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey)), C.int(level)) == 1
}

// SlhDsaKeygen generates an SLH-DSA keypair. level: 0..5, hash: 0=SHA2,1=SHAKE.
func SlhDsaKeygen(level, hash int) KeyPair {
	kp := C.cryptolib_slh_dsa_keygen(C.int(level), C.int(hash))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// SlhDsaSign signs a message with an SLH-DSA secret key.
func SlhDsaSign(msg, secretKey []byte, level, hash int) ([]byte, error) {
	return checkBufResult(C.cryptolib_slh_dsa_sign(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey)), C.int(level), C.int(hash)))
}

// SlhDsaVerify verifies an SLH-DSA signature.
func SlhDsaVerify(msg, sig, publicKey []byte, level, hash int) bool {
	return C.cryptolib_slh_dsa_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey)), C.int(level), C.int(hash)) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLS12-381 signatures
// ═══════════════════════════════════════════════════════════════════════════════

// BlsKeygen generates a BLS12-381 keypair (sk=32B, pk=48B).
func BlsKeygen() KeyPair {
	kp := C.cryptolib_bls_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// BlsSign signs a message (96-byte G2 signature).
func BlsSign(msg, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_bls_sign(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey))))
}

// BlsVerify verifies a BLS signature.
func BlsVerify(msg, sig, publicKey []byte) bool {
	return C.cryptolib_bls_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])), C.size_t(len(publicKey))) == 1
}
