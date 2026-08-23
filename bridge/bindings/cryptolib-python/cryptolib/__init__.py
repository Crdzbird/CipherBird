"""
CryptoLib for Python — ctypes bindings over the C ABI.

The native library is bundled in the package under
``cryptolib/_native/<plat>-<arch>/`` and loaded automatically; consumers never
provide a path:

    >>> import cryptolib
    >>> cryptolib.init()
    >>> cryptolib.version()
    '3.0.0'
    >>> cryptolib.sha256(b'abc').hex()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
"""

import ctypes as _C
import os as _os
import platform as _platform
import sys as _sys
from ctypes import (
    POINTER, Structure, c_char_p, c_int, c_size_t, c_uint8, c_void_p,
)

__version__ = "3.0.0"


def _resolve_lib_path() -> str:
    env = _os.environ.get("CRYPTOLIB_DYLIB")
    if env:
        return env
    sysname = {"darwin": "darwin", "linux": "linux", "win32": "win32"}.get(
        _sys.platform, _sys.platform
    )
    arch = _platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(arch, arch)
    ext = {"darwin": "dylib", "win32": "dll"}.get(sysname, "so")
    here = _os.path.dirname(_os.path.abspath(__file__))
    return _os.path.join(here, "_native", f"{sysname}-{arch}", f"libcryptolib_c.{ext}")


_lib = _C.CDLL(_resolve_lib_path())


# ── C structs ────────────────────────────────────────────────────────────────
class _CryptoBuffer(Structure):
    _fields_ = [("data", c_void_p), ("len", c_size_t)]


class _CryptoBufferResult(Structure):
    _fields_ = [("buf", _CryptoBuffer), ("error", c_void_p)]


class _CryptoKeyPair(Structure):
    _fields_ = [("public_key", _CryptoBuffer), ("secret_key", _CryptoBuffer)]


class _CryptoKemEncapsResult(Structure):
    _fields_ = [("ciphertext", _CryptoBuffer), ("shared_secret", _CryptoBuffer)]


class _CryptoResult(Structure):
    _fields_ = [("ok", c_int), ("error", c_void_p)]


# ── Function signatures ──────────────────────────────────────────────────────
def _bind(name, restype, argtypes):
    fn = getattr(_lib, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


_init        = _bind("cryptolib_init",          c_int, [])
_version     = _bind("cryptolib_version",       c_char_p, [])
_random      = _bind("cryptolib_random_bytes",  _CryptoBufferResult, [c_size_t])
_sha256      = _bind("cryptolib_sha256",        _CryptoBufferResult, [POINTER(c_uint8), c_size_t])
_hyKg        = _bind("cryptolib_hybrid_kem_keygen",       _CryptoKeyPair,         [])
_hyEn        = _bind("cryptolib_hybrid_kem_encapsulate",  _CryptoKemEncapsResult, [POINTER(c_uint8), c_size_t, POINTER(c_void_p)])
_hyDe        = _bind("cryptolib_hybrid_kem_decapsulate",  _CryptoBufferResult,    [POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t])
_buffer_free = _bind("cryptolib_buffer_free",       None, [POINTER(_CryptoBuffer)])
_kp_free     = _bind("cryptolib_keypair_free",      None, [POINTER(_CryptoKeyPair)])
_kem_free    = _bind("cryptolib_kem_encaps_free",   None, [POINTER(_CryptoKemEncapsResult)])
_str_free    = _bind("cryptolib_str_free",          None, [c_void_p])

# Primitives the composable Recipe pipeline is built from.
_U8 = POINTER(c_uint8)
_AEAD_ARGS = [_U8, c_size_t, _U8, c_size_t, _U8, c_size_t]
_argon2id   = _bind("cryptolib_argon2id_derive", _CryptoBufferResult,
                    [c_char_p, _U8, c_size_t, c_size_t, _C.c_uint64, c_size_t])
_hkdf       = _bind("cryptolib_hkdf_derive", _CryptoBufferResult,
                    [_U8, c_size_t, _U8, c_size_t, _U8, c_size_t, c_size_t])
_xenc       = _bind("cryptolib_xchacha20_encrypt", _CryptoBufferResult, _AEAD_ARGS)
_xdec       = _bind("cryptolib_xchacha20_decrypt", _CryptoBufferResult, _AEAD_ARGS)
_aesenc     = _bind("cryptolib_aes256gcm_encrypt", _CryptoBufferResult, _AEAD_ARGS)
_aesdec     = _bind("cryptolib_aes256gcm_decrypt", _CryptoBufferResult, _AEAD_ARGS)
_cmtenc     = _bind("cryptolib_committing_encrypt", _CryptoBufferResult, _AEAD_ARGS)
_cmtdec     = _bind("cryptolib_committing_decrypt", _CryptoBufferResult, _AEAD_ARGS)
_molseal    = _bind("cryptolib_molecular_seal_with_key", _CryptoBufferResult, _AEAD_ARGS)
_molopen    = _bind("cryptolib_molecular_open_with_key", _CryptoBufferResult, _AEAD_ARGS)
_edkg       = _bind("cryptolib_ed25519_keygen", _CryptoKeyPair, [])
_edkgseed   = _bind("cryptolib_ed25519_keygen_from_seed", _CryptoKeyPair, [_U8, c_size_t])
_edsign     = _bind("cryptolib_ed25519_sign", _CryptoBufferResult, [_U8, c_size_t, _U8, c_size_t])
_edverify   = _bind("cryptolib_ed25519_verify", c_int, [_U8, c_size_t, _U8, c_size_t, _U8, c_size_t])
_hysigkg    = _bind("cryptolib_hybrid_sig_keygen", _CryptoKeyPair, [])
_hysign     = _bind("cryptolib_hybrid_sig_sign", _CryptoBufferResult, [_U8, c_size_t, _U8, c_size_t])
_hyverify   = _bind("cryptolib_hybrid_sig_verify", c_int, [_U8, c_size_t, _U8, c_size_t, _U8, c_size_t])
_entdet     = _bind("cryptolib_entropy_from_file_deterministic", c_void_p, [c_char_p, POINTER(c_void_p)])
_entsym     = _bind("cryptolib_entropy_symmetric_key", _CryptoBufferResult, [c_void_p])
_entfree    = _bind("cryptolib_entropy_free", None, [c_void_p])
_stegoemb   = _bind("cryptolib_stego_embed", _CryptoResult, [c_char_p, _U8, c_size_t, c_char_p])
_stegoext   = _bind("cryptolib_stego_extract", _CryptoBufferResult, [c_char_p])
_fecenc     = _bind("cryptolib_fec_encode", _CryptoBufferResult, [_U8, c_size_t, c_int])
_fecdec     = _bind("cryptolib_fec_decode", _CryptoBufferResult, [_U8, c_size_t, c_int, c_size_t])


# ── Helpers ──────────────────────────────────────────────────────────────────
def _read_buf(cb: _CryptoBuffer) -> bytes:
    if not cb.data or cb.len == 0:
        return b""
    return bytes((c_uint8 * cb.len).from_address(cb.data))


def _consume(r: _CryptoBufferResult) -> bytes:
    if (not r.buf.data or r.buf.len == 0) and r.error:
        msg = _C.string_at(r.error).decode("utf-8", errors="replace")
        _str_free(r.error)
        raise RuntimeError(msg)
    out = _read_buf(r.buf)
    _buffer_free(_C.byref(r.buf))
    return out


def _u8p(b: bytes):
    arr = (c_uint8 * len(b)).from_buffer_copy(b)
    return _C.cast(arr, POINTER(c_uint8)), arr  # keep arr alive


# ── Public API ───────────────────────────────────────────────────────────────
def init() -> None:
    """Initialise libsodium / liboqs runtime state. Idempotent."""
    if _init() != 0:
        raise RuntimeError("cryptolib_init failed")


def version() -> str:
    """The native library version, e.g. '3.0.0'."""
    return _version().decode("ascii")


def random_bytes(n: int) -> bytes:
    """`n` cryptographically secure random bytes."""
    return _consume(_random(n))


def sha256(message: bytes) -> bytes:
    """SHA-256 digest of `message` (32 bytes)."""
    p, _keep = _u8p(message)
    return _consume(_sha256(p, len(message)))


def hybrid_kem_keygen() -> tuple[bytes, bytes]:
    """Generate an X25519 + ML-KEM-768 hybrid keypair → (public, secret)."""
    kp = _hyKg()
    pub = _read_buf(kp.public_key)
    sec = _read_buf(kp.secret_key)
    _kp_free(_C.byref(kp))
    return pub, sec


def hybrid_kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate to a hybrid public key → (ciphertext, 32-byte shared_secret)."""
    p, _keep = _u8p(public_key)
    err = c_void_p()
    r = _hyEn(p, len(public_key), _C.byref(err))
    if err.value:
        msg = _C.string_at(err).decode("utf-8", errors="replace")
        _str_free(err)
        raise RuntimeError(msg)
    ct = _read_buf(r.ciphertext)
    ss = _read_buf(r.shared_secret)
    _kem_free(_C.byref(r))
    return ct, ss


def hybrid_kem_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Recover the 32-byte shared secret from a hybrid ciphertext + secret key."""
    cp, _k1 = _u8p(ciphertext)
    sp, _k2 = _u8p(secret_key)
    return _consume(_hyDe(cp, len(ciphertext), sp, len(secret_key)))




# ── Primitives used by Recipe ────────────────────────────────────────────────
def argon2id_derive(password: str, salt: bytes, key_len: int = 32,
                    ops: int = 2, memory_bytes: int = 67108864) -> bytes:
    """Stretch a passphrase into a key with Argon2id."""
    sp, _k = _u8p(salt)
    return _consume(_argon2id(password.encode(), sp, len(salt), key_len, ops, memory_bytes))


def hkdf_derive(ikm: bytes, salt: bytes = b"", info: bytes = b"", out_len: int = 32) -> bytes:
    """One-shot HKDF: extract + expand to `out_len` bytes."""
    ip, _k1 = _u8p(ikm)
    sp, _k2 = _u8p(salt)
    fp, _k3 = _u8p(info)
    return _consume(_hkdf(ip, len(ikm), sp, len(salt), fp, len(info), out_len))


def _aead(fn, data: bytes, key: bytes, aad: bytes) -> bytes:
    dp, _k1 = _u8p(data)
    kp, _k2 = _u8p(key)
    ap, _k3 = _u8p(aad)
    return _consume(fn(dp, len(data), kp, len(key), ap, len(aad)))


def xchacha20_encrypt(pt: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """XChaCha20-Poly1305 AEAD encryption."""
    return _aead(_xenc, pt, key, aad)


def xchacha20_decrypt(ct: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """XChaCha20-Poly1305 AEAD decryption. Fails closed."""
    return _aead(_xdec, ct, key, aad)


def aes256gcm_encrypt(pt: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM AEAD encryption."""
    return _aead(_aesenc, pt, key, aad)


def aes256gcm_decrypt(ct: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM AEAD decryption. Fails closed."""
    return _aead(_aesdec, ct, key, aad)


def committing_encrypt(pt: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Key-committing AEAD (UtC): binds the ciphertext to exactly one key."""
    return _aead(_cmtenc, pt, key, aad)


def committing_decrypt(ct: bytes, key: bytes, aad: bytes = b"") -> bytes:
    """Key-committing AEAD decryption. Fails closed."""
    return _aead(_cmtdec, ct, key, aad)


def molecular_seal_with_key(pt: bytes, master_key: bytes, aad: bytes = b"") -> bytes:
    """MolecularVault cascade under a raw 32-byte master key."""
    return _aead(_molseal, pt, master_key, aad)


def molecular_open_with_key(ct: bytes, master_key: bytes, aad: bytes = b"") -> bytes:
    """Open a MolecularVault envelope. Fails closed."""
    return _aead(_molopen, ct, master_key, aad)


def _keypair(kp) -> tuple[bytes, bytes]:
    pub, sec = _read_buf(kp.public_key), _read_buf(kp.secret_key)
    _kp_free(_C.byref(kp))
    return pub, sec


def ed25519_keygen() -> tuple[bytes, bytes]:
    """Ed25519 keypair from the OS CSPRNG → (public, secret)."""
    return _keypair(_edkg())


def ed25519_keygen_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Ed25519 keypair derived deterministically from a 32-byte seed."""
    p, _k = _u8p(seed)
    return _keypair(_edkgseed(p, len(seed)))


def ed25519_sign(msg: bytes, secret_key: bytes) -> bytes:
    """Ed25519 signature. `secret_key` is the 64-byte secret, not the seed."""
    mp, _k1 = _u8p(msg)
    sp, _k2 = _u8p(secret_key)
    return _consume(_edsign(mp, len(msg), sp, len(secret_key)))


def ed25519_verify(msg: bytes, sig: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature."""
    mp, _k1 = _u8p(msg)
    gp, _k2 = _u8p(sig)
    pp, _k3 = _u8p(public_key)
    return _edverify(mp, len(msg), gp, len(sig), pp, len(public_key)) == 1


def hybrid_sig_keygen() -> tuple[bytes, bytes]:
    """Ed25519 + ML-DSA-65 keypair: a forgery needs breaking both families."""
    return _keypair(_hysigkg())


def hybrid_sig_sign(msg: bytes, secret_key: bytes) -> bytes:
    """Hybrid Ed25519 + ML-DSA-65 signature."""
    mp, _k1 = _u8p(msg)
    sp, _k2 = _u8p(secret_key)
    return _consume(_hysign(mp, len(msg), sp, len(secret_key)))


def hybrid_sig_verify(msg: bytes, sig: bytes, public_key: bytes) -> bool:
    """Verify a hybrid signature; both legs must hold."""
    mp, _k1 = _u8p(msg)
    gp, _k2 = _u8p(sig)
    pp, _k3 = _u8p(public_key)
    return _hyverify(mp, len(msg), gp, len(sig), pp, len(public_key)) == 1


def key_from_file_deterministic(path: str) -> bytes:
    """
    Derive a 32-byte key deterministically from a media file — "the file is the
    key". Reproducible on any machine; nothing is stored.

    Uses the deterministic entropy path deliberately: ``key_from_file`` mixes in
    fresh system entropy and so could never reopen its own envelope.
    """
    err = c_void_p()
    h = _entdet(path.encode(), _C.byref(err))
    if err.value:
        msg = _C.string_at(err).decode("utf-8", errors="replace")
        _str_free(err)
        raise RuntimeError(msg)
    if not h:
        raise RuntimeError("cryptolib: entropy handle allocation failed")
    try:
        return _consume(_entsym(h))
    finally:
        _entfree(h)


def stego_embed(cover_path: str, payload: bytes, output_path: str) -> None:
    """Hide `payload` inside a media carrier."""
    pp, _k = _u8p(payload)
    r = _stegoemb(cover_path.encode(), pp, len(payload), output_path.encode())
    if r.ok != 1:
        msg = _C.string_at(r.error).decode("utf-8", errors="replace") if r.error else "stego embed failed"
        if r.error:
            _str_free(r.error)
        raise RuntimeError(msg)


def stego_extract(stego_path: str) -> bytes:
    """Recover a payload hidden by `stego_embed`."""
    return _consume(_stegoext(stego_path.encode()))


def fec_encode(data: bytes, scheme: int) -> bytes:
    """Forward-error-correct `data` under a `FecScheme` value."""
    p, _k = _u8p(data)
    return _consume(_fecenc(p, len(data), scheme))


def fec_decode(data: bytes, scheme: int, original_length: int) -> bytes:
    """Reverse `fec_encode`, recovering `original_length` bytes."""
    p, _k = _u8p(data)
    return _consume(_fecdec(p, len(data), scheme, original_length))


from ._security import (  # noqa: E402
    FecScheme, ProtectionLayer, Recipe, SecurityProfile, SignatureAlgorithm,
    maximum_security, recipe,
)

__all__ = [
    "init", "version", "random_bytes", "sha256",
    "hybrid_kem_keygen", "hybrid_kem_encapsulate", "hybrid_kem_decapsulate",
    # Recipe primitives
    "argon2id_derive", "hkdf_derive",
    "xchacha20_encrypt", "xchacha20_decrypt",
    "aes256gcm_encrypt", "aes256gcm_decrypt",
    "committing_encrypt", "committing_decrypt",
    "molecular_seal_with_key", "molecular_open_with_key",
    "ed25519_keygen", "ed25519_keygen_from_seed", "ed25519_sign", "ed25519_verify",
    "hybrid_sig_keygen", "hybrid_sig_sign", "hybrid_sig_verify",
    "key_from_file_deterministic", "stego_embed", "stego_extract",
    "fec_encode", "fec_decode",
    # Composition
    "SecurityProfile", "ProtectionLayer", "SignatureAlgorithm", "FecScheme",
    "Recipe", "recipe", "maximum_security",
]
