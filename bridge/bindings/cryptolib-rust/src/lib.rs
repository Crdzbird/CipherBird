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
