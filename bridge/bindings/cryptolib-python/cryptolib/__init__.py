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


__all__ = [
    "init", "version", "random_bytes", "sha256",
    "hybrid_kem_keygen", "hybrid_kem_encapsulate", "hybrid_kem_decapsulate",
]
