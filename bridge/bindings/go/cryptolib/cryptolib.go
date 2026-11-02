package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
#include <string.h>

// Overwrites n bytes at p with zeros in a way the compiler keeps, then frees p.
static void cl_wipe_free(void* p, size_t n) {
    if (!p) return;
    volatile unsigned char* q = (volatile unsigned char*)p;
    while (n--) *q++ = 0;
    free(p);
}
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
// Secret handling
// ═══════════════════════════════════════════════════════════════════════════════

// Secret is key material the caller owns. Wipe overwrites it with zeros once
// it is no longer needed; a plain []byte lingers until the collector reuses it.
type Secret []byte

// Wipe overwrites the bytes with zeros.
func (s Secret) Wipe() {
	for i := range s {
		s[i] = 0
	}
}

// Bytes returns the underlying slice without copying.
func (s Secret) Bytes() []byte { return []byte(s) }

// cstrSecret copies a secret string into C memory as a NUL-terminated string.
// Release it with wipeFreeStr, which zeroes the copy before freeing it.
func cstrSecret(s string) *C.char { return C.CString(s) }

// cbytesZ copies a secret byte slice into C memory with a NUL terminator, so
// it can be handed to a const char* parameter. Release it with wipeFreeStr.
func cbytesZ(b []byte) *C.char {
	p := (*C.char)(C.malloc(C.size_t(len(b) + 1)))
	buf := unsafe.Slice((*byte)(unsafe.Pointer(p)), len(b)+1)
	copy(buf, b)
	buf[len(b)] = 0
	return p
}

// wipeFreeStr zeroes a NUL-terminated C string and frees it.
func wipeFreeStr(p *C.char) {
	if p == nil {
		return
	}
	C.cl_wipe_free(unsafe.Pointer(p), C.strlen(p)+1)
}

// wipeFree zeroes n bytes of C memory and frees it.
func wipeFree(p unsafe.Pointer, n int) {
	C.cl_wipe_free(p, C.size_t(n))
}

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
// The C buffer is freed on every path (including the defensive guards), so no
// allocation escapes. The length is taken through a native Go int rather than
// C.int to avoid 32-bit truncation of a size_t on 64-bit platforms.
func goBytes(buf C.CryptoBuffer) []byte {
	if buf.data == nil || buf.len == 0 {
		// Still free: a zero-length buffer may carry a non-nil allocation.
		C.cryptolib_buffer_free(&buf)
		return nil
	}
	defer C.cryptolib_buffer_free(&buf)
	n := int(buf.len)
	if n < 0 { // size_t exceeded the Go int range — refuse rather than misread.
		return nil
	}
	// Copy out of C memory into a fresh, GC-managed slice.
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(buf.data)), n)...)
}

// u8 returns a *C.uint8_t for a byte slice, or nil for an empty slice
// (avoids indexing &b[0] on a zero-length slice, which panics).
func u8(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// checkBufResult converts a CryptoBufferResult to ([]byte, error).
func checkBufResult(r C.CryptoBufferResult) ([]byte, error) {
	if r.error != nil {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		// Defensive: if the C side set both an error and a (partial) buffer,
		// free the buffer too so nothing leaks on the error path.
		C.cryptolib_buffer_free(&r.buf)
		return nil, errors.New(msg)
	}
	return goBytes(r.buf), nil
}

// checkResult turns a CryptoResult (ok/error) into a Go error, freeing the
// heap-allocated error string.
func checkResult(r C.CryptoResult) error {
	if r.ok == 0 {
		msg := C.GoString(r.error)
		C.cryptolib_str_free(r.error)
		return errors.New(msg)
	}
	return nil
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
	if n < 0 {
		// A negative int would wrap to a huge size_t in C; reject early.
		return nil, errors.New("cryptolib: RandomBytes requires n >= 0")
	}
	return checkBufResult(C.cryptolib_random_bytes(C.size_t(n)))
}

// SecureEqual performs constant-time comparison of two byte slices.
func SecureEqual(a, b []byte) bool {
	var ap, bp *C.uint8_t
	if len(a) > 0 {
		ap = u8(a)
	}
	if len(b) > 0 {
		bp = u8(b)
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
		kp = u8(key)
		kl = C.size_t(len(key))
	}
	return checkBufResult(C.cryptolib_blake2b(
		u8(msg), C.size_t(len(msg)),
		kp, kl))
}

// SHA256 computes a SHA-256 hash.
func SHA256(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sha256(
		u8(msg), C.size_t(len(msg))))
}

// SHA512 computes a SHA-512 hash.
func SHA512(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sha512(
		u8(msg), C.size_t(len(msg))))
}

// HmacSHA512 computes an HMAC-SHA512.
func HmacSHA512(msg, key []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hmac_sha512(
		u8(msg), C.size_t(len(msg)),
		u8(key), C.size_t(len(key))))
}

// HmacSHA512Verify verifies an HMAC-SHA512.
func HmacSHA512Verify(msg, mac, key []byte) bool {
	return C.cryptolib_hmac_sha512_verify(
		u8(msg), C.size_t(len(msg)),
		u8(mac), C.size_t(len(mac)),
		u8(key), C.size_t(len(key))) == 1
}

// Argon2idHashStr hashes a password to PHC string format. The C copy of the
// password is wiped after the call; the Go string itself cannot be.
func Argon2idHashStr(password string, ops uint64, mem uint64) (string, error) {
	cp := cstrSecret(password)
	defer wipeFreeStr(cp)
	return argon2idHashStrC(cp, ops, mem)
}

// Argon2idHashStrBytes is Argon2idHashStr for a password held as bytes the
// caller can wipe afterwards.
func Argon2idHashStrBytes(password []byte, ops uint64, mem uint64) (string, error) {
	cp := cbytesZ(password)
	defer wipeFreeStr(cp)
	return argon2idHashStrC(cp, ops, mem)
}

func argon2idHashStrC(cp *C.char, ops uint64, mem uint64) (string, error) {
	r := C.cryptolib_argon2id_hash_str(cp, C.uint64_t(ops), C.size_t(mem))
	b, err := checkBufResult(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Argon2idVerifyStr verifies a password against a PHC string.
func Argon2idVerifyStr(password, phcStr string) bool {
	cp := cstrSecret(password)
	defer wipeFreeStr(cp)
	return argon2idVerifyC(cp, phcStr)
}

// Argon2idVerifyStrBytes is Argon2idVerifyStr for a password held as bytes.
func Argon2idVerifyStrBytes(password []byte, phcStr string) bool {
	cp := cbytesZ(password)
	defer wipeFreeStr(cp)
	return argon2idVerifyC(cp, phcStr)
}

func argon2idVerifyC(cp *C.char, phcStr string) bool {
	cs := C.CString(phcStr)
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
		aadp = u8(aad)
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_xchacha20_encrypt(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(key), C.size_t(len(key)),
		aadp, aadl))
}

// XChaCha20Decrypt decrypts XChaCha20-Poly1305 ciphertext.
func XChaCha20Decrypt(ciphertext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = u8(aad)
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_xchacha20_decrypt(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(key), C.size_t(len(key)),
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
		aadp = u8(aad)
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_aes256gcm_encrypt(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(key), C.size_t(len(key)),
		aadp, aadl))
}

// AES256GCMDecrypt decrypts AES-256-GCM ciphertext.
func AES256GCMDecrypt(ciphertext, key, aad []byte) ([]byte, error) {
	var aadp *C.uint8_t
	var aadl C.size_t
	if len(aad) > 0 {
		aadp = u8(aad)
		aadl = C.size_t(len(aad))
	}
	return checkBufResult(C.cryptolib_aes256gcm_decrypt(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(key), C.size_t(len(key)),
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
	h := C.cryptolib_stream_enc_create(u8(key))
	if h == nil {
		return nil
	}
	s := &StreamEncryptor{handle: h}
	runtime.SetFinalizer(s, func(s *StreamEncryptor) { s.Close() })
	return s
}

// Header returns the 24-byte stream header that must be sent to the decryptor.
func (s *StreamEncryptor) Header() ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_stream_enc_header(s.handle))
}

// Push encrypts a chunk. Use TagMessage for intermediate chunks, TagFinal for the last.
func (s *StreamEncryptor) Push(plaintext []byte, tag uint8) ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_stream_enc_push(
		s.handle,
		u8(plaintext), C.size_t(len(plaintext)),
		C.uint8_t(tag)))
}

// Close destroys the encryptor handle. Idempotent and safe to call after the
// finalizer would have run (the finalizer is cancelled here).
func (s *StreamEncryptor) Close() {
	runtime.SetFinalizer(s, nil)
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
		u8(key),
		u8(header))
	if h == nil {
		return nil
	}
	s := &StreamDecryptor{handle: h}
	runtime.SetFinalizer(s, func(s *StreamDecryptor) { s.Close() })
	return s
}

// Pull decrypts a chunk. Returns plaintext and the tag byte.
func (s *StreamDecryptor) Pull(ciphertext []byte) (plaintext []byte, tag uint8, err error) {
	defer runtime.KeepAlive(s)
	var ctag C.uint8_t
	r := C.cryptolib_stream_dec_pull(
		s.handle,
		u8(ciphertext), C.size_t(len(ciphertext)),
		&ctag)
	pt, e := checkBufResult(r)
	return pt, uint8(ctag), e
}

// Close destroys the decryptor handle. Idempotent; cancels the finalizer.
func (s *StreamDecryptor) Close() {
	runtime.SetFinalizer(s, nil)
	if s.handle != nil {
		C.cryptolib_stream_dec_free(s.handle)
		s.handle = nil
	}
}

// StreamEncrypt is a one-shot convenience over the streaming AEAD: it encrypts a
// slice of plaintext chunks under key and returns the 24-byte stream header plus
// one ciphertext chunk per input (the last chunk is tagged FINAL). The handle is
// created and freed internally. For incremental/streaming use, use
// NewStreamEncryptor directly.
func StreamEncrypt(key []byte, plaintextChunks [][]byte) (header []byte, chunks [][]byte, err error) {
	enc := NewStreamEncryptor(key)
	if enc == nil {
		return nil, nil, errors.New("cryptolib: stream encryptor creation failed (key must be 32 bytes)")
	}
	defer enc.Close()
	header, err = enc.Header()
	if err != nil {
		return nil, nil, err
	}
	chunks = make([][]byte, len(plaintextChunks))
	for i, pt := range plaintextChunks {
		tag := TagMessage
		if i == len(plaintextChunks)-1 {
			tag = TagFinal
		}
		ct, e := enc.Push(pt, tag)
		if e != nil {
			return nil, nil, e
		}
		chunks[i] = ct
	}
	return header, chunks, nil
}

// StreamDecrypt is a one-shot convenience over the streaming AEAD: it decrypts a
// slice of ciphertext chunks under key and header, returning one plaintext chunk
// per input. The handle is created and freed internally. For incremental use,
// use NewStreamDecryptor directly.
func StreamDecrypt(key, header []byte, ciphertextChunks [][]byte) ([][]byte, error) {
	dec := NewStreamDecryptor(key, header)
	if dec == nil {
		return nil, errors.New("cryptolib: stream decryptor creation failed (bad key or header)")
	}
	defer dec.Close()
	out := make([][]byte, len(ciphertextChunks))
	for i, ct := range ciphertextChunks {
		pt, _, e := dec.Pull(ct)
		if e != nil {
			return nil, e
		}
		out[i] = pt
	}
	return out, nil
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
		u8(seed), C.size_t(len(seed)))
	return KeyPair{
		Public: goBytes(kp.public_key),
		Secret: goBytes(kp.secret_key),
	}
}

// Ed25519Sign signs a message with an Ed25519 secret key.
func Ed25519Sign(msg, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ed25519_sign(
		u8(msg), C.size_t(len(msg)),
		u8(secretKey), C.size_t(len(secretKey))))
}

// Ed25519Verify verifies an Ed25519 signature.
func Ed25519Verify(msg, sig, publicKey []byte) bool {
	return C.cryptolib_ed25519_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey))) == 1
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
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientPub), C.size_t(len(recipientPub)),
		u8(senderSec), C.size_t(len(senderSec))))
}

// BoxDecrypt decrypts a Box ciphertext.
func BoxDecrypt(ciphertext, senderPub, recipientSec []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_box_decrypt(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(senderPub), C.size_t(len(senderPub)),
		u8(recipientSec), C.size_t(len(recipientSec))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Asymmetric — SealedBox (anonymous sender)
// ═══════════════════════════════════════════════════════════════════════════════

// SealedBoxEncrypt encrypts with an anonymous sender (only recipient can decrypt).
func SealedBoxEncrypt(plaintext, recipientPub []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sealedbox_encrypt(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientPub), C.size_t(len(recipientPub))))
}

// SealedBoxDecrypt decrypts a SealedBox ciphertext.
func SealedBoxDecrypt(ciphertext, recipientPub, recipientSec []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_sealedbox_decrypt(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(recipientPub), C.size_t(len(recipientPub)),
		u8(recipientSec), C.size_t(len(recipientSec))))
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
		u8(ourSecret), C.size_t(len(ourSecret)),
		u8(theirPublic), C.size_t(len(theirPublic))))
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
		u8(masterKey), C.size_t(len(masterKey)),
		C.int(kdf))
	if h == nil {
		return nil, errors.New("cryptolib: vault creation failed")
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
	defer runtime.KeepAlive(v)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	var cerr *C.char
	cp := C.cryptolib_vault_seal(v.handle,
		u8(plaintext), C.size_t(len(plaintext)),
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
	defer runtime.KeepAlive(v)
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cp := pkt.toC()
	defer pkt.freeC(&cp)
	return checkBufResult(C.cryptolib_vault_open(v.handle, &cp, caad))
}

// PublicKey returns the vault's Ed25519 public key.
func (v *Vault) PublicKey() ([]byte, error) {
	defer runtime.KeepAlive(v)
	return checkBufResult(C.cryptolib_vault_public_key(v.handle))
}

// Close destroys the vault handle. Idempotent; cancels the finalizer.
func (v *Vault) Close() {
	runtime.SetFinalizer(v, nil)
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
	defer runtime.KeepAlive(k)
	if len(factor) == 0 {
		return false
	}
	return C.cryptolib_keyring_add_device_slot(k.handle,
		u8(factor), C.size_t(len(factor))) == 1
}

// AddPassphraseSlot wraps the master key under Argon2id. kdf: 0=interactive, 1=sensitive.
func (k *Keyring) AddPassphraseSlot(passphrase string, kdf int) bool {
	defer runtime.KeepAlive(k)
	cpw := cstrSecret(passphrase)
	defer wipeFreeStr(cpw)
	return C.cryptolib_keyring_add_passphrase_slot(k.handle, cpw, C.int(kdf)) == 1
}

// AddPassphraseSlotBytes is AddPassphraseSlot for a passphrase held as bytes.
func (k *Keyring) AddPassphraseSlotBytes(passphrase []byte, kdf int) bool {
	defer runtime.KeepAlive(k)
	cpw := cbytesZ(passphrase)
	defer wipeFreeStr(cpw)
	return C.cryptolib_keyring_add_passphrase_slot(k.handle, cpw, C.int(kdf)) == 1
}

// SlotCount returns the number of slots.
func (k *Keyring) SlotCount() int {
	defer runtime.KeepAlive(k)
	return int(C.cryptolib_keyring_slot_count(k.handle))
}

// RemoveSlot revokes a slot by index.
func (k *Keyring) RemoveSlot(index int) bool {
	defer runtime.KeepAlive(k)
	if index < 0 {
		return false // a negative index would wrap to a huge size_t in C
	}
	return C.cryptolib_keyring_remove_slot(k.handle, C.size_t(index)) == 1
}

// Serialise returns the envelope blob (contains no plaintext key).
func (k *Keyring) Serialise() ([]byte, error) {
	defer runtime.KeepAlive(k)
	return checkBufResult(C.cryptolib_keyring_serialise(k.handle))
}

// DeserialiseKeyring parses an envelope blob into a (locked) keyring.
func DeserialiseKeyring(blob []byte) (*Keyring, error) {
	if len(blob) == 0 {
		return nil, errors.New("cryptolib: empty keyring blob")
	}
	var cerr *C.char
	h := C.cryptolib_keyring_deserialise(
		u8(blob), C.size_t(len(blob)), &cerr)
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
	defer runtime.KeepAlive(k)
	if len(factor) == 0 {
		return nil, errors.New("cryptolib: empty factor key")
	}
	return checkBufResult(C.cryptolib_keyring_unlock_with_device(k.handle,
		u8(factor), C.size_t(len(factor))))
}

// UnlockWithPassphrase recovers the master key using a passphrase. Wipe the
// returned master key (Secret(master).Wipe()) once it has been used.
func (k *Keyring) UnlockWithPassphrase(passphrase string) ([]byte, error) {
	defer runtime.KeepAlive(k)
	cpw := cstrSecret(passphrase)
	defer wipeFreeStr(cpw)
	return checkBufResult(C.cryptolib_keyring_unlock_with_passphrase(k.handle, cpw))
}

// UnlockWithPassphraseBytes is UnlockWithPassphrase for a passphrase held as bytes.
func (k *Keyring) UnlockWithPassphraseBytes(passphrase []byte) ([]byte, error) {
	defer runtime.KeepAlive(k)
	cpw := cbytesZ(passphrase)
	defer wipeFreeStr(cpw)
	return checkBufResult(C.cryptolib_keyring_unlock_with_passphrase(k.handle, cpw))
}

// Close destroys the keyring handle. Idempotent; cancels the finalizer.
func (k *Keyring) Close() {
	runtime.SetFinalizer(k, nil)
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
	wipeFree(unsafe.Pointer(cb.box_secret.data), int(cb.box_secret.len))
	C.free(unsafe.Pointer(cb.sign_public.data))
	wipeFree(unsafe.Pointer(cb.sign_secret.data), int(cb.sign_secret.len))
}

// AsymVaultSeal encrypts plaintext from sender to recipient with signature.
func AsymVaultSeal(sender *AsymBundle, recipientBoxPub, plaintext []byte, aad string) (*Packet, error) {
	caad := C.CString(aad)
	defer C.free(unsafe.Pointer(caad))
	cs := sender.toC()
	defer sender.freeC(&cs)
	var cerr *C.char
	cp := C.cryptolib_asym_vault_seal(&cs,
		u8(recipientBoxPub), C.size_t(len(recipientBoxPub)),
		u8(plaintext), C.size_t(len(plaintext)),
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
		u8(senderSignPub), C.size_t(len(senderSignPub)),
		caad))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Argon2id — key derivation
// ═══════════════════════════════════════════════════════════════════════════════

// Argon2idDerive derives a key from a password and salt using Argon2id.
func Argon2idDerive(password string, salt []byte, keyLen int, ops uint64, mem uint64) ([]byte, error) {
	cp := cstrSecret(password)
	defer wipeFreeStr(cp)
	return checkBufResult(C.cryptolib_argon2id_derive(cp,
		u8(salt), C.size_t(len(salt)),
		C.size_t(keyLen), C.uint64_t(ops), C.size_t(mem)))
}

// Argon2idDeriveBytes is Argon2idDerive for a password held as bytes the
// caller can wipe afterwards.
func Argon2idDeriveBytes(password []byte, salt []byte, keyLen int, ops uint64, mem uint64) ([]byte, error) {
	cp := cbytesZ(password)
	defer wipeFreeStr(cp)
	return checkBufResult(C.cryptolib_argon2id_derive(cp,
		u8(salt), C.size_t(len(salt)),
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

// FecScheme selects a forward-error-correction code for the stego robustness knob.
type FecScheme int

const (
	FecNone        FecScheme = 0 // no correction
	FecRepetition3 FecScheme = 1 // corrects 1 flip/bit, 3x size
	FecRepetition5 FecScheme = 2 // corrects 2 flips/bit, 5x size
	FecHamming74   FecScheme = 3 // corrects 1 flip per 7-bit block, 1.75x size
)

// FileInspection reports a media carrier's structural validity (see StegoInspect).
type FileInspection struct {
	Parses     bool   // recognised, structurally plausible carrier
	Format     uint8  // MediaFormat inferred from content (0xFF = unknown)
	ExtMatches bool   // content format matches the file extension
	Width      uint64 // images only
	Height     uint64
	FileSize   uint64
	Detail     string // human summary
}

// HiddenDataReport is a HEURISTIC hidden-data probe. CryptolibPayload is
// definitive (an unkeyed cryptolib payload was recovered); LsbEmbeddingLikelihood
// is a 0..1 heuristic with the caveats in Note — never a proof.
type HiddenDataReport struct {
	CryptolibPayload       bool
	LsbChiSquare           float64
	LsbEmbeddingLikelihood float64
	SamplesAnalysed        uint64
	Note                   string
}

// HealthReport is a NIST SP 800-90B source-health assessment (see AssessFileHealth).
type HealthReport struct {
	MinEntropyPerByte float64 // Most-Common-Value lower bound, 0..8 bits/byte
	LongestRun        uint64
	MaxWindowCount    uint64
	RctPassed         bool
	AptPassed         bool
}

// Healthy reports whether the source clears minBits per byte AND both local tests passed.
func (h HealthReport) Healthy(minBits float64) bool {
	return h.MinEntropyPerByte >= minBits && h.RctPassed && h.AptPassed
}

// Drbg is a stateful HMAC-DRBG (SP 800-90A). Close it (or let the finalizer) to
// free the native handle.
type Drbg struct {
	handle C.CryptoDrbgHandle
}

// Fortuna is a stateful Fortuna-style entropy pool. Close it (or let the
// finalizer) to free the native handle.
type Fortuna struct {
	handle C.CryptoFortunaHandle
}

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
		u8(publicKey), C.size_t(len(publicKey)), C.int(level), &cerr)
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
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(secretKey), C.size_t(len(secretKey)), C.int(level)))
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
		u8(publicKey), C.size_t(len(publicKey)), &cerr)
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
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(secretKey), C.size_t(len(secretKey))))
}

// MlDsaKeygen generates an ML-DSA signing keypair. level: 0=44, 1=65, 2=87.
func MlDsaKeygen(level int) KeyPair {
	kp := C.cryptolib_ml_dsa_keygen(C.int(level))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// MlDsaSign signs a message with an ML-DSA secret key.
func MlDsaSign(msg, secretKey []byte, level int) ([]byte, error) {
	return checkBufResult(C.cryptolib_ml_dsa_sign(
		u8(msg), C.size_t(len(msg)),
		u8(secretKey), C.size_t(len(secretKey)), C.int(level)))
}

// MlDsaVerify verifies an ML-DSA signature.
func MlDsaVerify(msg, sig, publicKey []byte, level int) bool {
	return C.cryptolib_ml_dsa_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey)), C.int(level)) == 1
}

// SlhDsaKeygen generates an SLH-DSA keypair. level: 0..5, hash: 0=SHA2,1=SHAKE.
func SlhDsaKeygen(level, hash int) KeyPair {
	kp := C.cryptolib_slh_dsa_keygen(C.int(level), C.int(hash))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// SlhDsaSign signs a message with an SLH-DSA secret key.
func SlhDsaSign(msg, secretKey []byte, level, hash int) ([]byte, error) {
	return checkBufResult(C.cryptolib_slh_dsa_sign(
		u8(msg), C.size_t(len(msg)),
		u8(secretKey), C.size_t(len(secretKey)), C.int(level), C.int(hash)))
}

// SlhDsaVerify verifies an SLH-DSA signature.
func SlhDsaVerify(msg, sig, publicKey []byte, level, hash int) bool {
	return C.cryptolib_slh_dsa_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey)), C.int(level), C.int(hash)) == 1
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
		u8(msg), C.size_t(len(msg)),
		u8(secretKey), C.size_t(len(secretKey))))
}

// BlsVerify verifies a BLS signature.
func BlsVerify(msg, sig, publicKey []byte) bool {
	return C.cryptolib_bls_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey))) == 1
}

// BlsKeygenFromIkm deterministically derives a BLS keypair from input key
// material (>= 32 bytes). Same IKM yields the same key.
func BlsKeygenFromIkm(ikm []byte) KeyPair {
	kp := C.cryptolib_bls_keygen_from_ikm(u8(ikm), C.size_t(len(ikm)))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Committing AEAD (UtC: key-committing XChaCha20-Poly1305)
// ═══════════════════════════════════════════════════════════════════════════════

// CommittingEncrypt encrypts so the ciphertext binds the exact key (resists
// partitioning-oracle / invisible-salamander attacks). key is 32 bytes; aad
// may be nil.
func CommittingEncrypt(plaintext, key, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_committing_encrypt(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(key), C.size_t(len(key)),
		u8(aad), C.size_t(len(aad))))
}

// CommittingDecrypt decrypts a committing-AEAD ciphertext. Returns an error if
// the key/aad don't match or the commitment check fails.
func CommittingDecrypt(ciphertext, key, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_committing_decrypt(
		u8(ciphertext), C.size_t(len(ciphertext)),
		u8(key), C.size_t(len(key)),
		u8(aad), C.size_t(len(aad))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// HMAC-SHA256 & HKDF-SHA256
// ═══════════════════════════════════════════════════════════════════════════════

// HmacSHA256 computes an HMAC-SHA256 tag (32 bytes). key should be >= 32 bytes.
func HmacSHA256(msg, key []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hmac_sha256(
		u8(msg), C.size_t(len(msg)), u8(key), C.size_t(len(key))))
}

// HmacSHA256Verify verifies an HMAC-SHA256 tag in constant time.
func HmacSHA256Verify(msg, mac, key []byte) bool {
	return C.cryptolib_hmac_sha256_verify(
		u8(msg), C.size_t(len(msg)),
		u8(mac), C.size_t(len(mac)),
		u8(key), C.size_t(len(key))) == 1
}

// HkdfExtract performs HKDF-SHA256 extract (PRK = HMAC(salt, IKM)). salt may be
// nil for the all-zero default.
func HkdfExtract(ikm, salt []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hkdf_extract(
		u8(salt), C.size_t(len(salt)), u8(ikm), C.size_t(len(ikm))))
}

// HkdfExpand performs HKDF-SHA256 expand, deriving outLen bytes from prk and
// optional info context.
func HkdfExpand(prk, info []byte, outLen int) ([]byte, error) {
	return checkBufResult(C.cryptolib_hkdf_expand(
		u8(prk), C.size_t(len(prk)), u8(info), C.size_t(len(info)), C.size_t(outLen)))
}

// HkdfDerive is the HKDF-SHA256 one-shot (extract + expand). salt and info may
// be nil.
func HkdfDerive(ikm, salt, info []byte, outLen int) ([]byte, error) {
	return checkBufResult(C.cryptolib_hkdf_derive(
		u8(ikm), C.size_t(len(ikm)),
		u8(salt), C.size_t(len(salt)),
		u8(info), C.size_t(len(info)), C.size_t(outLen)))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hybrid signature (Ed25519 + ML-DSA-65)
// ═══════════════════════════════════════════════════════════════════════════════

// HybridSigKeygen generates an Ed25519+ML-DSA-65 hybrid signing keypair
// (concatenated layout: ed25519_part || ml_dsa_part).
func HybridSigKeygen() KeyPair {
	kp := C.cryptolib_hybrid_sig_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// HybridSigSign produces a hybrid signature; both component signatures are
// required to verify.
func HybridSigSign(msg, secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_hybrid_sig_sign(
		u8(msg), C.size_t(len(msg)), u8(secretKey), C.size_t(len(secretKey))))
}

// HybridSigVerify verifies a hybrid signature (both classical and PQ parts).
func HybridSigVerify(msg, sig, publicKey []byte) bool {
	return C.cryptolib_hybrid_sig_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey))) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE3 (hash / keyed MAC / key-derivation, all with extendable output length)
// ═══════════════════════════════════════════════════════════════════════════════

// Blake3 hashes msg, producing outLen bytes (defaults to 32 when outLen <= 0).
// Pass a larger outLen to use BLAKE3 as an XOF.
func Blake3(msg []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		outLen = 32
	}
	return checkBufResult(C.cryptolib_blake3(u8(msg), C.size_t(len(msg)), C.size_t(outLen)))
}

// Blake3Keyed computes a BLAKE3 keyed MAC. key must be exactly 32 bytes.
// outLen defaults to 32 when <= 0.
func Blake3Keyed(msg, key []byte, outLen int) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cryptolib: BLAKE3 keyed MAC requires a 32-byte key, got %d", len(key))
	}
	if outLen <= 0 {
		outLen = 32
	}
	return checkBufResult(C.cryptolib_blake3_keyed(
		u8(msg), C.size_t(len(msg)),
		u8(key), C.size_t(len(key)), C.size_t(outLen)))
}

// Blake3DeriveKey derives key material from a hard-coded, application-unique
// context string and input key material ikm. outLen defaults to 32 when <= 0.
func Blake3DeriveKey(context string, ikm []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		outLen = 32
	}
	cc := C.CString(context)
	defer C.free(unsafe.Pointer(cc))
	return checkBufResult(C.cryptolib_blake3_derive_key(
		cc, u8(ikm), C.size_t(len(ikm)), C.size_t(outLen)))
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLS12-381 aggregation
// ═══════════════════════════════════════════════════════════════════════════════

// cByteSlices marshals a [][]byte into the C array-of-pointers + array-of-lengths
// pair expected by the variadic-count C ABI functions. The returned free closure
// releases every allocation and must be called (defer) by the caller.
func cByteSlices(items [][]byte) (ptrs **C.uint8_t, lens *C.size_t, free func()) {
	n := len(items)
	pMem := C.malloc(C.size_t(uintptr(n) * unsafe.Sizeof(uintptr(0))))
	lMem := C.malloc(C.size_t(uintptr(n) * unsafe.Sizeof(C.size_t(0))))
	pArr := unsafe.Slice((**C.uint8_t)(pMem), n)
	lArr := unsafe.Slice((*C.size_t)(lMem), n)
	bufs := make([]unsafe.Pointer, n)
	for i, b := range items {
		if len(b) > 0 {
			bufs[i] = C.CBytes(b)
		} else {
			bufs[i] = C.malloc(1) // distinct non-nil pointer for an empty item
		}
		pArr[i] = (*C.uint8_t)(bufs[i])
		lArr[i] = C.size_t(len(b))
	}
	return (**C.uint8_t)(pMem), (*C.size_t)(lMem), func() {
		for _, p := range bufs {
			C.free(p)
		}
		C.free(pMem)
		C.free(lMem)
	}
}

// BlsAggregate combines several BLS signatures into a single 96-byte aggregate.
func BlsAggregate(sigs [][]byte) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, errors.New("cryptolib: BlsAggregate requires at least one signature")
	}
	ptrs, lens, free := cByteSlices(sigs)
	defer free()
	return checkBufResult(C.cryptolib_bls_aggregate(ptrs, lens, C.size_t(len(sigs))))
}

// BlsAggregateVerify verifies an aggregate signature over distinct
// (message, publicKey) pairs. messages and publicKeys must have equal length.
func BlsAggregateVerify(messages, publicKeys [][]byte, aggSig []byte) bool {
	if len(messages) == 0 || len(messages) != len(publicKeys) {
		return false
	}
	mp, ml, freeM := cByteSlices(messages)
	defer freeM()
	pp, pl, freeP := cByteSlices(publicKeys)
	defer freeP()
	return C.cryptolib_bls_aggregate_verify(
		mp, ml, pp, pl, C.size_t(len(messages)),
		u8(aggSig), C.size_t(len(aggSig))) == 1
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVM / Bitcoin interop: Keccak-256, RIPEMD-160, secp256k1 ECDSA
// ═══════════════════════════════════════════════════════════════════════════════

// Keccak256 computes the original-padding Keccak-256 digest (32 bytes) used by
// Ethereum (NOT NIST SHA3-256).
func Keccak256(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_keccak256(u8(msg), C.size_t(len(msg))))
}

// Ripemd160 computes RIPEMD-160 (20 bytes). Bitcoin HASH160 = ripemd160(sha256(x)).
func Ripemd160(msg []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ripemd160(u8(msg), C.size_t(len(msg))))
}

// Secp256k1Keygen generates a secp256k1 keypair (sk = 32 bytes,
// pk = 65 bytes uncompressed: 0x04 ‖ X ‖ Y).
func Secp256k1Keygen() KeyPair {
	kp := C.cryptolib_secp256k1_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// Secp256k1Pubkey derives the public key from a 32-byte secret key. When
// compressed is true a 33-byte (0x02/0x03 ‖ X) key is returned, otherwise the
// 65-byte uncompressed form.
func Secp256k1Pubkey(secretKey []byte, compressed bool) ([]byte, error) {
	c := C.int(0)
	if compressed {
		c = 1
	}
	return checkBufResult(C.cryptolib_secp256k1_pubkey(
		u8(secretKey), C.size_t(len(secretKey)), c))
}

// Secp256k1Sign produces a 65-byte recoverable, low-S ECDSA signature
// (r ‖ s ‖ recid) over a 32-byte message digest using RFC6979 deterministic
// nonces. digest32 must be exactly 32 bytes.
func Secp256k1Sign(digest32, secretKey []byte) ([]byte, error) {
	if len(digest32) != 32 {
		return nil, fmt.Errorf("cryptolib: secp256k1 sign requires a 32-byte digest, got %d", len(digest32))
	}
	return checkBufResult(C.cryptolib_secp256k1_sign(
		u8(digest32), u8(secretKey), C.size_t(len(secretKey))))
}

// Secp256k1Verify verifies an ECDSA signature (64-byte r‖s or 65-byte
// recoverable) over a 32-byte digest. High-S signatures are rejected.
func Secp256k1Verify(digest32, sig, publicKey []byte) bool {
	if len(digest32) != 32 {
		return false
	}
	return C.cryptolib_secp256k1_verify(
		u8(digest32), u8(sig), C.size_t(len(sig)),
		u8(publicKey), C.size_t(len(publicKey))) == 1
}

// Secp256k1Recover recovers the 65-byte uncompressed public key from a 32-byte
// digest and a 65-byte recoverable signature (Ethereum ecrecover).
func Secp256k1Recover(digest32, sig65 []byte) ([]byte, error) {
	if len(digest32) != 32 {
		return nil, fmt.Errorf("cryptolib: secp256k1 recover requires a 32-byte digest, got %d", len(digest32))
	}
	if len(sig65) != 65 {
		return nil, fmt.Errorf("cryptolib: secp256k1 recover requires a 65-byte signature, got %d", len(sig65))
	}
	return checkBufResult(C.cryptolib_secp256k1_recover(u8(digest32), u8(sig65)))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Packet serialisation (flat-bytes wire form for vault packets)
// ═══════════════════════════════════════════════════════════════════════════════

// Serialise flattens a packet to its portable wire representation.
func (p *Packet) Serialise() ([]byte, error) {
	cp := p.toC()
	defer p.freeC(&cp)
	return checkBufResult(C.cryptolib_packet_serialise(&cp))
}

// PacketDeserialise parses a packet from its wire representation.
func PacketDeserialise(data []byte) (*Packet, error) {
	var cerr *C.char
	cp := C.cryptolib_packet_deserialise(u8(data), C.size_t(len(data)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	p := packetFromC(cp)
	return &p, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Media entropy: deterministic multi-file harvest + asymmetric bundle derivation
// ═══════════════════════════════════════════════════════════════════════════════

// MolecularSeal encrypts plaintext under a passphrase. ops/mem are the Argon2id
// work factors; pass 0 for either to use the library's SENSITIVE preset. For
// high-value secrets raise mem toward 1<<30 (1 GiB) to make guessing far
// costlier. The returned envelope is self-describing (carries salt + params).
func MolecularSeal(plaintext []byte, passphrase string, aad []byte, ops uint64, mem int) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("cryptolib: MolecularSeal requires a passphrase")
	}
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	m := mem
	if m < 0 {
		m = 0
	}
	return checkBufResult(C.cryptolib_molecular_seal(
		u8(plaintext), C.size_t(len(plaintext)), cpw,
		u8(aad), C.size_t(len(aad)),
		C.uint64_t(ops), C.size_t(m)))
}

// MolecularOpen decrypts a passphrase-sealed envelope. AAD must match exactly;
// a wrong passphrase, wrong AAD, or any tampering fails closed with an error.
func MolecularOpen(envelope []byte, passphrase string, aad []byte) ([]byte, error) {
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	return checkBufResult(C.cryptolib_molecular_open(
		u8(envelope), C.size_t(len(envelope)), cpw,
		u8(aad), C.size_t(len(aad))))
}

// MolecularSealWithKey encrypts under a 32-byte full-entropy master key (for
// example one agreed via HybridKemEncapsulate). No Argon2id is applied — the key
// is expected to already be full-entropy.
func MolecularSealWithKey(plaintext, masterKey, aad []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("cryptolib: MolecularVault master key must be 32 bytes, got %d", len(masterKey))
	}
	return checkBufResult(C.cryptolib_molecular_seal_with_key(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(masterKey), C.size_t(len(masterKey)),
		u8(aad), C.size_t(len(aad))))
}

// MolecularOpenWithKey decrypts a raw-key-sealed envelope.
func MolecularOpenWithKey(envelope, masterKey, aad []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("cryptolib: MolecularVault master key must be 32 bytes, got %d", len(masterKey))
	}
	return checkBufResult(C.cryptolib_molecular_open_with_key(
		u8(envelope), C.size_t(len(envelope)),
		u8(masterKey), C.size_t(len(masterKey)),
		u8(aad), C.size_t(len(aad))))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Suite — one-call advanced combinations (needs OpenSSL + PQ in the native lib)
// ═══════════════════════════════════════════════════════════════════════════════

// SuiteSealPq encapsulates to the recipient's hybrid-KEM public key and seals the
// plaintext under the shared secret. The envelope carries the KEM ciphertext, so
// SuiteOpenPq needs only the recipient's secret key. Secure while EITHER X25519
// or ML-KEM-768 remains unbroken (harvest-now-decrypt-later resistant).
func SuiteSealPq(plaintext, recipientKemPublic, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_seal_pq(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientKemPublic), C.size_t(len(recipientKemPublic)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteSealPqSntrup is like SuiteSealPq but uses the X25519+sntrup761 hybrid KEM
// (a different lattice family, for diversity). SuiteOpenPq auto-detects the KEM
// from the envelope, so the same open works for both.
func SuiteSealPqSntrup(plaintext, recipientKemPublic, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_seal_pq_sntrup(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientKemPublic), C.size_t(len(recipientKemPublic)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteOpenPq opens a SuiteSealPq / SuiteSealPqSntrup envelope with the
// recipient's hybrid-KEM secret (KEM chosen from the envelope's suite id).
func SuiteOpenPq(envelope, recipientKemSecret, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_open_pq(
		u8(envelope), C.size_t(len(envelope)),
		u8(recipientKemSecret), C.size_t(len(recipientKemSecret)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteSealSignedPq is the flagship: post-quantum confidentiality (hybrid KEM)
// PLUS post-quantum authenticity (Ed25519+ML-DSA-65 signature). SuiteOpenSignedPq
// returns the plaintext only if the signature verifies.
func SuiteSealSignedPq(plaintext, recipientKemPublic, signerSigSecret, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_seal_signed_pq(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientKemPublic), C.size_t(len(recipientKemPublic)),
		u8(signerSigSecret), C.size_t(len(signerSigSecret)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteSealSignedPqSntrup is the flagship with the X25519+sntrup761 hybrid KEM.
// SuiteOpenSignedPq auto-detects the KEM from the envelope.
func SuiteSealSignedPqSntrup(plaintext, recipientKemPublic, signerSigSecret, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_seal_signed_pq_sntrup(
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientKemPublic), C.size_t(len(recipientKemPublic)),
		u8(signerSigSecret), C.size_t(len(signerSigSecret)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteOpenSignedPq decrypts and then verifies; a signature mismatch returns an
// error and no plaintext.
func SuiteOpenSignedPq(envelope, recipientKemSecret, signerSigPublic, aad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_open_signed_pq(
		u8(envelope), C.size_t(len(envelope)),
		u8(recipientKemSecret), C.size_t(len(recipientKemSecret)),
		u8(signerSigPublic), C.size_t(len(signerSigPublic)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteSealWithFile derives the key deterministically from a file's media entropy
// ("your file is the key") and seals the plaintext under it.
func SuiteSealWithFile(plaintext []byte, path string, aad []byte) ([]byte, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	return checkBufResult(C.cryptolib_suite_seal_with_file(
		u8(plaintext), C.size_t(len(plaintext)), cp, u8(aad), C.size_t(len(aad))))
}

// SuiteOpenWithFile re-derives the key from the same file and opens the envelope.
func SuiteOpenWithFile(envelope []byte, path string, aad []byte) ([]byte, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	return checkBufResult(C.cryptolib_suite_open_with_file(
		u8(envelope), C.size_t(len(envelope)), cp, u8(aad), C.size_t(len(aad))))
}

// SuiteSealWithKeyringDevice unlocks the keyring's master via a device factor and
// seals under it (the master never lives in plaintext at rest).
func SuiteSealWithKeyringDevice(plaintext []byte, kr *Keyring, factorKey, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(kr)
	return checkBufResult(C.cryptolib_suite_seal_with_keyring_device(
		u8(plaintext), C.size_t(len(plaintext)), kr.handle,
		u8(factorKey), C.size_t(len(factorKey)), u8(aad), C.size_t(len(aad))))
}

// SuiteOpenWithKeyringDevice unlocks via a device factor and opens the envelope.
func SuiteOpenWithKeyringDevice(envelope []byte, kr *Keyring, factorKey, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(kr)
	return checkBufResult(C.cryptolib_suite_open_with_keyring_device(
		u8(envelope), C.size_t(len(envelope)), kr.handle,
		u8(factorKey), C.size_t(len(factorKey)), u8(aad), C.size_t(len(aad))))
}

// SuiteSealWithKeyringPassphrase unlocks the keyring's master via a passphrase slot.
func SuiteSealWithKeyringPassphrase(plaintext []byte, kr *Keyring, passphrase string, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(kr)
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	return checkBufResult(C.cryptolib_suite_seal_with_keyring_passphrase(
		u8(plaintext), C.size_t(len(plaintext)), kr.handle, cpw, u8(aad), C.size_t(len(aad))))
}

// SuiteOpenWithKeyringPassphrase unlocks via a passphrase slot and opens the envelope.
func SuiteOpenWithKeyringPassphrase(envelope []byte, kr *Keyring, passphrase string, aad []byte) ([]byte, error) {
	defer runtime.KeepAlive(kr)
	cpw := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpw))
	return checkBufResult(C.cryptolib_suite_open_with_keyring_passphrase(
		u8(envelope), C.size_t(len(envelope)), kr.handle, cpw, u8(aad), C.size_t(len(aad))))
}

// SuiteSealThreshold seals under a fresh random master, then splits that master
// into n Shamir shares of which any k reconstruct it. Returns the envelope and
// the n individual share records; distribute the shares, keep the envelope
// anywhere. Reconstruct with SuiteOpenThreshold using any k of the shares.
func SuiteSealThreshold(plaintext []byte, n, k int, aad []byte) (envelope []byte, shares [][]byte, err error) {
	var sharesBuf C.CryptoBuffer
	r := C.cryptolib_suite_seal_threshold(
		u8(plaintext), C.size_t(len(plaintext)), C.uint8_t(n), C.uint8_t(k),
		u8(aad), C.size_t(len(aad)), &sharesBuf)
	envelope, err = checkBufResult(r)
	if err != nil {
		C.cryptolib_buffer_free(&sharesBuf)
		return nil, nil, err
	}
	shares = splitShareRecords(goBytes(sharesBuf)) // goBytes frees sharesBuf
	return envelope, shares, nil
}

// SuiteOpenThreshold reconstructs the master from any k of the shares (each a
// record from SuiteSealThreshold) and opens the envelope.
func SuiteOpenThreshold(envelope []byte, shares [][]byte, aad []byte) ([]byte, error) {
	var blob []byte
	for _, s := range shares {
		blob = append(blob, s...)
	}
	return checkBufResult(C.cryptolib_suite_open_threshold(
		u8(envelope), C.size_t(len(envelope)), u8(blob), C.size_t(len(blob)),
		u8(aad), C.size_t(len(aad))))
}

// SuiteEvmAddress derives the 20-byte EVM address from a 65-byte uncompressed
// secp256k1 public key (last 20 bytes of Keccak-256(pubkey[1:])).
func SuiteEvmAddress(secp256k1PublicKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_suite_evm_address(
		u8(secp256k1PublicKey), C.size_t(len(secp256k1PublicKey))))
}

// splitShareRecords parses a concatenation of [index(1)|ylen(4 LE)|y] records
// into individual share byte-slices (each a complete, distributable record).
func splitShareRecords(blob []byte) [][]byte {
	var out [][]byte
	for off := 0; off+5 <= len(blob); {
		ylen := int(blob[off+1]) | int(blob[off+2])<<8 | int(blob[off+3])<<16 | int(blob[off+4])<<24
		end := off + 5 + ylen
		if end > len(blob) {
			break
		}
		rec := make([]byte, end-off)
		copy(rec, blob[off:end])
		out = append(out, rec)
		off = end
	}
	return out
}
