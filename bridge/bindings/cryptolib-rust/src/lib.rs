//! CryptoLib for Rust — safe wrappers over the C ABI.
//!
//! ```no_run
//! cryptolib::init();
//! assert_eq!(cryptolib::version(), "3.0.0");
//! let (pub_, sec) = cryptolib::hybrid_kem_keygen();
//! let (ct, ss)   = cryptolib::hybrid_kem_encapsulate(&pub_).unwrap();
//! let ss2        = cryptolib::hybrid_kem_decapsulate(&ct, &sec).unwrap();
//! assert_eq!(ss, ss2);
//! ```

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
#[derive(Copy, Clone)]
struct CryptoBuffer { data: *mut u8, len: usize }

#[repr(C)]
#[derive(Copy, Clone)]
struct CryptoBufferResult { buf: CryptoBuffer, error: *mut c_char }

#[repr(C)]
#[derive(Copy, Clone)]
struct CryptoKeyPair { public_key: CryptoBuffer, secret_key: CryptoBuffer }

#[repr(C)]
#[derive(Copy, Clone)]
struct CryptoKemEncapsResult { ciphertext: CryptoBuffer, shared_secret: CryptoBuffer }

#[repr(C)]
#[derive(Copy, Clone)]
struct CryptoResult { ok: c_int, error: *mut c_char }

extern "C" {
    fn cryptolib_init() -> c_int;
    fn cryptolib_version() -> *const c_char;
    fn cryptolib_random_bytes(n: usize) -> CryptoBufferResult;
    fn cryptolib_sha256(msg: *const u8, len: usize) -> CryptoBufferResult;

    fn cryptolib_hybrid_kem_keygen() -> CryptoKeyPair;
    fn cryptolib_hybrid_kem_encapsulate(pk: *const u8, len: usize,
                                        out_err: *mut *mut c_char) -> CryptoKemEncapsResult;
    fn cryptolib_hybrid_kem_decapsulate(ct: *const u8, ct_len: usize,
                                        sk: *const u8, sk_len: usize) -> CryptoBufferResult;

    fn cryptolib_buffer_free(buf: *mut CryptoBuffer);
    fn cryptolib_keypair_free(kp: *mut CryptoKeyPair);
    fn cryptolib_kem_encaps_free(r: *mut CryptoKemEncapsResult);
    fn cryptolib_str_free(s: *mut c_void);

    // Primitives the composable Recipe pipeline is built from.
    fn cryptolib_argon2id_derive(password: *const c_char, salt: *const u8, salt_len: usize,
                                 key_len: usize, ops: u64, mem: usize) -> CryptoBufferResult;
    fn cryptolib_hkdf_derive(ikm: *const u8, ikm_len: usize, salt: *const u8, salt_len: usize,
                             info: *const u8, info_len: usize, out_len: usize) -> CryptoBufferResult;
    fn cryptolib_xchacha20_encrypt(pt: *const u8, pt_len: usize, key: *const u8, key_len: usize,
                                   aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_xchacha20_decrypt(ct: *const u8, ct_len: usize, key: *const u8, key_len: usize,
                                   aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_aes256gcm_encrypt(pt: *const u8, pt_len: usize, key: *const u8, key_len: usize,
                                   aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_aes256gcm_decrypt(ct: *const u8, ct_len: usize, key: *const u8, key_len: usize,
                                   aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_committing_encrypt(pt: *const u8, pt_len: usize, key: *const u8, key_len: usize,
                                    aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_committing_decrypt(ct: *const u8, ct_len: usize, key: *const u8, key_len: usize,
                                    aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_molecular_seal_with_key(pt: *const u8, pt_len: usize, key: *const u8, key_len: usize,
                                         aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_molecular_open_with_key(ct: *const u8, ct_len: usize, key: *const u8, key_len: usize,
                                         aad: *const u8, aad_len: usize) -> CryptoBufferResult;
    fn cryptolib_ed25519_keygen() -> CryptoKeyPair;
    fn cryptolib_ed25519_keygen_from_seed(seed: *const u8, len: usize) -> CryptoKeyPair;
    fn cryptolib_ed25519_sign(msg: *const u8, msg_len: usize,
                              sk: *const u8, sk_len: usize) -> CryptoBufferResult;
    fn cryptolib_ed25519_verify(msg: *const u8, msg_len: usize, sig: *const u8, sig_len: usize,
                                pk: *const u8, pk_len: usize) -> c_int;
    fn cryptolib_hybrid_sig_keygen() -> CryptoKeyPair;
    fn cryptolib_hybrid_sig_sign(msg: *const u8, msg_len: usize,
                                 sk: *const u8, sk_len: usize) -> CryptoBufferResult;
    fn cryptolib_hybrid_sig_verify(msg: *const u8, msg_len: usize, sig: *const u8, sig_len: usize,
                                   pk: *const u8, pk_len: usize) -> c_int;
    fn cryptolib_entropy_from_file_deterministic(path: *const c_char,
                                                 out_err: *mut *mut c_char) -> *mut c_void;
    fn cryptolib_entropy_symmetric_key(h: *mut c_void) -> CryptoBufferResult;
    fn cryptolib_entropy_free(h: *mut c_void);
    fn cryptolib_stego_embed(cover: *const c_char, payload: *const u8, len: usize,
                             out: *const c_char) -> CryptoResult;
    fn cryptolib_stego_extract(path: *const c_char) -> CryptoBufferResult;
    fn cryptolib_fec_encode(data: *const u8, len: usize, scheme: c_int) -> CryptoBufferResult;
    fn cryptolib_fec_decode(data: *const u8, len: usize, scheme: c_int,
                            original_len: usize) -> CryptoBufferResult;
}

unsafe fn read_buf(b: CryptoBuffer) -> Vec<u8> {
    if b.data.is_null() || b.len == 0 { return Vec::new(); }
    std::slice::from_raw_parts(b.data, b.len).to_vec()
}

unsafe fn consume(mut r: CryptoBufferResult) -> Result<Vec<u8>, String> {
    if (r.buf.data.is_null() || r.buf.len == 0) && !r.error.is_null() {
        let msg = CStr::from_ptr(r.error).to_string_lossy().into_owned();
        cryptolib_str_free(r.error as *mut c_void);
        return Err(msg);
    }
    let out = read_buf(r.buf);
    cryptolib_buffer_free(&mut r.buf);
    Ok(out)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Initialise libsodium / liboqs runtime state. Idempotent.
pub fn init() {
    // Safety: extern C call, no aliasing.
    let rc = unsafe { cryptolib_init() };
    assert_eq!(rc, 0, "cryptolib_init failed");
}

/// The native library version string (e.g. `"3.0.0"`).
pub fn version() -> &'static str {
    unsafe { CStr::from_ptr(cryptolib_version()).to_str().unwrap_or("?") }
}

/// `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_random_bytes(n)) }
}

/// SHA-256 digest of `msg` (32 bytes).
pub fn sha256(msg: &[u8]) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_sha256(msg.as_ptr(), msg.len())) }
}

/// Generate an X25519 + ML-KEM-768 hybrid keypair → `(public, secret)`.
pub fn hybrid_kem_keygen() -> (Vec<u8>, Vec<u8>) {
    unsafe {
        let mut kp = cryptolib_hybrid_kem_keygen();
        let pub_ = read_buf(kp.public_key);
        let sec  = read_buf(kp.secret_key);
        cryptolib_keypair_free(&mut kp);
        (pub_, sec)
    }
}

/// Encapsulate to a hybrid public key → `(ciphertext, 32-byte shared_secret)`.
pub fn hybrid_kem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    unsafe {
        let mut err: *mut c_char = std::ptr::null_mut();
        let mut r = cryptolib_hybrid_kem_encapsulate(public_key.as_ptr(), public_key.len(), &mut err);
        if !err.is_null() {
            let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
            cryptolib_str_free(err as *mut c_void);
            return Err(msg);
        }
        let ct = read_buf(r.ciphertext);
        let ss = read_buf(r.shared_secret);
        cryptolib_kem_encaps_free(&mut r);
        Ok((ct, ss))
    }
}

/// Recover the 32-byte shared secret from a hybrid ciphertext + secret key.
pub fn hybrid_kem_decapsulate(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        consume(cryptolib_hybrid_kem_decapsulate(
            ciphertext.as_ptr(), ciphertext.len(),
            secret_key.as_ptr(), secret_key.len(),
        ))
    }
}

// ── Primitives used by Recipe ────────────────────────────────────────────────

use std::ffi::CString;

macro_rules! aead_fn {
    ($name:ident, $c:ident, $doc:expr) => {
        #[doc = $doc]
        pub fn $name(data: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
            unsafe {
                consume($c(data.as_ptr(), data.len(), key.as_ptr(), key.len(),
                           aad.as_ptr(), aad.len()))
            }
        }
    };
}

aead_fn!(xchacha20_encrypt, cryptolib_xchacha20_encrypt, "XChaCha20-Poly1305 AEAD encryption.");
aead_fn!(xchacha20_decrypt, cryptolib_xchacha20_decrypt, "XChaCha20-Poly1305 AEAD decryption. Fails closed.");
aead_fn!(aes256gcm_encrypt, cryptolib_aes256gcm_encrypt, "AES-256-GCM AEAD encryption.");
aead_fn!(aes256gcm_decrypt, cryptolib_aes256gcm_decrypt, "AES-256-GCM AEAD decryption. Fails closed.");
aead_fn!(committing_encrypt, cryptolib_committing_encrypt, "Key-committing AEAD (UtC): binds the ciphertext to exactly one key.");
aead_fn!(committing_decrypt, cryptolib_committing_decrypt, "Key-committing AEAD decryption. Fails closed.");
aead_fn!(molecular_seal_with_key, cryptolib_molecular_seal_with_key, "MolecularVault cascade under a raw 32-byte master key.");
aead_fn!(molecular_open_with_key, cryptolib_molecular_open_with_key, "Open a MolecularVault envelope. Fails closed.");

/// Stretch a passphrase into a key with Argon2id.
pub fn argon2id_derive(password: &str, salt: &[u8], key_len: usize, ops: u64, memory_bytes: usize)
    -> Result<Vec<u8>, String>
{
    let c = CString::new(password).map_err(|e| e.to_string())?;
    unsafe { consume(cryptolib_argon2id_derive(c.as_ptr(), salt.as_ptr(), salt.len(), key_len, ops, memory_bytes)) }
}

/// One-shot HKDF: extract + expand to `out_len` bytes.
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    unsafe {
        consume(cryptolib_hkdf_derive(ikm.as_ptr(), ikm.len(), salt.as_ptr(), salt.len(),
                                      info.as_ptr(), info.len(), out_len))
    }
}

unsafe fn keypair(mut kp: CryptoKeyPair) -> (Vec<u8>, Vec<u8>) {
    let pub_ = read_buf(kp.public_key);
    let sec = read_buf(kp.secret_key);
    cryptolib_keypair_free(&mut kp);
    (pub_, sec)
}

/// Ed25519 keypair from the OS CSPRNG → `(public, secret)`.
pub fn ed25519_keygen() -> (Vec<u8>, Vec<u8>) { unsafe { keypair(cryptolib_ed25519_keygen()) } }

/// Ed25519 keypair derived deterministically from a 32-byte seed.
pub fn ed25519_keygen_from_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    unsafe { keypair(cryptolib_ed25519_keygen_from_seed(seed.as_ptr(), seed.len())) }
}

/// Ed25519 signature. `secret_key` is the 64-byte secret, not the seed.
pub fn ed25519_sign(msg: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_ed25519_sign(msg.as_ptr(), msg.len(), secret_key.as_ptr(), secret_key.len())) }
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(msg: &[u8], sig: &[u8], public_key: &[u8]) -> bool {
    unsafe {
        cryptolib_ed25519_verify(msg.as_ptr(), msg.len(), sig.as_ptr(), sig.len(),
                                 public_key.as_ptr(), public_key.len()) == 1
    }
}

/// Ed25519 + ML-DSA-65 keypair: a forgery needs breaking both families.
pub fn hybrid_sig_keygen() -> (Vec<u8>, Vec<u8>) { unsafe { keypair(cryptolib_hybrid_sig_keygen()) } }

/// Hybrid Ed25519 + ML-DSA-65 signature.
pub fn hybrid_sig_sign(msg: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_hybrid_sig_sign(msg.as_ptr(), msg.len(), secret_key.as_ptr(), secret_key.len())) }
}

/// Verify a hybrid signature; both legs must hold.
pub fn hybrid_sig_verify(msg: &[u8], sig: &[u8], public_key: &[u8]) -> bool {
    unsafe {
        cryptolib_hybrid_sig_verify(msg.as_ptr(), msg.len(), sig.as_ptr(), sig.len(),
                                    public_key.as_ptr(), public_key.len()) == 1
    }
}

/// Derive a 32-byte key deterministically from a media file — "the file is the
/// key". Reproducible on any machine; nothing is stored.
///
/// Uses the deterministic entropy path deliberately: `key_from_file` mixes in
/// fresh system entropy and so could never reopen its own envelope.
pub fn key_from_file_deterministic(path: &str) -> Result<Vec<u8>, String> {
    let c = CString::new(path).map_err(|e| e.to_string())?;
    unsafe {
        let mut err: *mut c_char = std::ptr::null_mut();
        let h = cryptolib_entropy_from_file_deterministic(c.as_ptr(), &mut err);
        if !err.is_null() {
            let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
            cryptolib_str_free(err as *mut c_void);
            return Err(msg);
        }
        if h.is_null() { return Err("cryptolib: entropy handle allocation failed".into()); }
        let out = consume(cryptolib_entropy_symmetric_key(h));
        cryptolib_entropy_free(h);
        out
    }
}

/// Hide `payload` inside a media carrier.
pub fn stego_embed(cover_path: &str, payload: &[u8], output_path: &str) -> Result<(), String> {
    let c = CString::new(cover_path).map_err(|e| e.to_string())?;
    let o = CString::new(output_path).map_err(|e| e.to_string())?;
    unsafe {
        let r = cryptolib_stego_embed(c.as_ptr(), payload.as_ptr(), payload.len(), o.as_ptr());
        if r.ok == 1 { return Ok(()); }
        let msg = if r.error.is_null() { "stego embed failed".to_string() }
                  else { CStr::from_ptr(r.error).to_string_lossy().into_owned() };
        if !r.error.is_null() { cryptolib_str_free(r.error as *mut c_void); }
        Err(msg)
    }
}

/// Recover a payload hidden by [`stego_embed`].
pub fn stego_extract(stego_path: &str) -> Result<Vec<u8>, String> {
    let c = CString::new(stego_path).map_err(|e| e.to_string())?;
    unsafe { consume(cryptolib_stego_extract(c.as_ptr())) }
}

/// Forward-error-correct `data` under a [`FecScheme`] value.
pub fn fec_encode(data: &[u8], scheme: i32) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_fec_encode(data.as_ptr(), data.len(), scheme)) }
}

/// Reverse [`fec_encode`], recovering `original_length` bytes.
pub fn fec_decode(data: &[u8], scheme: i32, original_length: usize) -> Result<Vec<u8>, String> {
    unsafe { consume(cryptolib_fec_decode(data.as_ptr(), data.len(), scheme, original_length)) }
}

mod security;
pub use security::{BuiltinLayer, CascadeLayer, Ed25519Signature, FecScheme, HybridSignature,
                   KeyFileSource, KeySource, Layer, PassphraseKeySource, ProtectionLayer,
                   RawKeySource, Recipe, SecurityProfile, SignatureAlgorithm, SignatureScheme,
                   maximum_security, recipe, register_layer};
