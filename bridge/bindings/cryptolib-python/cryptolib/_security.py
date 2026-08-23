"""
Security profiles and composable recipes.

``SecurityProfile`` sets every algorithm parameter consistently, so "use the
strongest thing available" is one word rather than a dozen constants.

``Recipe`` stacks the library's protections in combination: derive a key,
cascade several AEADs, sign, add error correction, hide the result in a carrier.

Composition only — every step is an existing, vetted operation. What the recipe
adds is the plumbing that is easy to get wrong by hand:

* Every layer gets its **own** key, via HKDF with a distinct info string. A key
  is never reused across two layers.
* The header describing the recipe is authenticated as AAD by **every** layer,
  so the descriptor cannot be altered without every layer failing.
* Order is fixed and not caller-selectable: sign -> encrypt (inner to outer) ->
  error-correct -> conceal. Opening reverses it exactly.
* Everything fails closed.

The envelope is a library-native format, and is identical across every CryptoLib
binding: an envelope sealed here opens in Dart, Go, Node, Swift or Java.
"""

from __future__ import annotations

import enum as _enum
import os as _os
import struct as _struct
from typing import Sequence

from . import (
    aes256gcm_decrypt as _aes_dec,
    aes256gcm_encrypt as _aes_enc,
    argon2id_derive as _argon2id,
    committing_decrypt as _cmt_dec,
    committing_encrypt as _cmt_enc,
    ed25519_sign as _ed_sign,
    ed25519_verify as _ed_verify,
    fec_decode as _fec_decode,
    fec_encode as _fec_encode,
    hkdf_derive as _hkdf,
    hybrid_sig_sign as _hy_sign,
    hybrid_sig_verify as _hy_verify,
    key_from_file_deterministic as _key_from_file,
    molecular_open_with_key as _mol_open,
    molecular_seal_with_key as _mol_seal,
    random_bytes as _random_bytes,
    stego_embed as _stego_embed,
    stego_extract as _stego_extract,
    xchacha20_decrypt as _x_dec,
    xchacha20_encrypt as _x_enc,
)

_MAGIC = b"CLRC"
_FEC_MAGIC = b"CLFC"
_VERSION = 1
_SALT_LEN = 16


class ProtectionLayer(_enum.Enum):
    """One authenticated-encryption layer in a :class:`Recipe` cascade."""

    #: XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
    XCHACHA20_POLY1305 = (1, "xchacha20Poly1305")
    #: AES-256-GCM. A different cipher family from ChaCha.
    AES256_GCM = (2, "aes256Gcm")
    #: Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
    COMMITTING = (3, "committing")
    #: A full MolecularVault (cascade + committing) nested as one layer.
    MOLECULAR = (4, "molecular")

    def __init__(self, layer_id: int, wire_name: str) -> None:
        self.id = layer_id
        #: Name used in this layer's HKDF info string. Pinned explicitly rather
        #: than derived from the member name: it is part of the wire format, so
        #: renaming must not change how keys are derived.
        self.wire_name = wire_name

    @classmethod
    def from_id(cls, layer_id: int) -> "ProtectionLayer":
        for layer in cls:
            if layer.id == layer_id:
                return layer
        raise ValueError(f"cryptolib: unknown protection layer id {layer_id}")


class SignatureAlgorithm(_enum.IntEnum):
    """Origin-authentication algorithm for a :class:`Recipe`."""

    #: No signature. The AEAD still guarantees integrity, but not who sent it.
    NONE = 0
    #: Ed25519.
    ED25519 = 1
    #: Ed25519 + ML-DSA-65. A forgery needs breaking both families.
    HYBRID = 2


class FecScheme(_enum.IntEnum):
    """Forward-error-correction scheme applied to a finished envelope."""

    NONE = 0
    REPETITION3 = 1
    REPETITION5 = 2
    HAMMING74 = 3


class _KeySource(_enum.IntEnum):
    RAW = 0
    PASSPHRASE = 1
    KEY_FILE = 2

    @property
    def label(self) -> str:
        return {0: "raw", 1: "passphrase", 2: "keyFile"}[int(self)]


class SecurityProfile(_enum.Enum):
    """
    A coherent set of algorithm parameters, from ordinary to maximal.

    Every field moves together, so you cannot accidentally pair a maximal KEM
    with an interactive-cost KDF.
    """

    #: Sound modern defaults. Fast enough for interactive use.
    BALANCED = "balanced"
    #: Stronger parameters and a two-cipher cascade.
    HIGH = "high"
    #: The strongest option at every choice: category-5 post-quantum parameter
    #: sets, the triple-family sealed tier, a three-layer cascade ending in a
    #: key-committing AEAD, and a memory-hard KDF past interactive comfort.
    MAXIMUM = "maximum"

    @property
    def ml_kem_level(self) -> int:
        """ML-KEM parameter set (0 = 512, 1 = 768, 2 = 1024)."""
        return 2 if self is SecurityProfile.MAXIMUM else 1

    @property
    def ml_dsa_level(self) -> int:
        """ML-DSA parameter set (0 = 44, 1 = 65, 2 = 87)."""
        return 2 if self is SecurityProfile.MAXIMUM else 1

    @property
    def slh_dsa_level(self) -> int:
        """SLH-DSA parameter set; MAXIMUM takes the small-signature 256-bit variant."""
        return {SecurityProfile.MAXIMUM: 4, SecurityProfile.HIGH: 3, SecurityProfile.BALANCED: 1}[self]

    @property
    def slh_dsa_hash(self) -> int:
        """SLH-DSA hash family (0 = SHA-2, 1 = SHAKE)."""
        return 1 if self is SecurityProfile.MAXIMUM else 0

    @property
    def sealed_tier(self) -> int:
        """Sealed-messaging tier (0 = Flagship, 1 = Fortress)."""
        return 1 if self is SecurityProfile.MAXIMUM else 0

    @property
    def kdf_preset(self) -> int:
        """Argon2id preset for vault and keyring slots (0 = interactive, 1 = sensitive)."""
        return 0 if self is SecurityProfile.BALANCED else 1

    @property
    def argon2_ops(self) -> int:
        """Argon2id iteration count used by :class:`Recipe`."""
        return {SecurityProfile.MAXIMUM: 4, SecurityProfile.HIGH: 3, SecurityProfile.BALANCED: 2}[self]

    @property
    def argon2_memory(self) -> int:
        """
        Argon2id memory cost in bytes. Memory is what actually costs an attacker;
        raise it as far as the slowest device you must support can bear.
        """
        return {
            SecurityProfile.MAXIMUM: 512 * 1024 * 1024,
            SecurityProfile.HIGH: 256 * 1024 * 1024,
            SecurityProfile.BALANCED: 64 * 1024 * 1024,
        }[self]

    @property
    def cascade(self) -> list[ProtectionLayer]:
        """
        The AEAD layers this profile applies, innermost first.

        Independent cipher families mean a break of one does not open the
        envelope, and the key-committing outer layer closes partitioning-oracle
        and Invisible-Salamanders style attacks.
        """
        if self is SecurityProfile.MAXIMUM:
            return [ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM,
                    ProtectionLayer.COMMITTING]
        if self is SecurityProfile.HIGH:
            return [ProtectionLayer.XCHACHA20_POLY1305, ProtectionLayer.AES256_GCM]
        return [ProtectionLayer.XCHACHA20_POLY1305]


class Recipe:
    """
    A composable protection pipeline.

    Describe what you want once, then :meth:`seal` and :meth:`open` with the same
    recipe. The envelope carries its own descriptor, so opening does not depend
    on remembering which layers were used — only on holding the key.

        >>> r = cryptolib.maximum_security().with_passphrase("correct horse battery staple")
        >>> back = r.open(r.seal(b"secret"))

    Builder methods return ``self`` so calls chain. Not thread-safe.
    """

    def __init__(self, profile: SecurityProfile = SecurityProfile.BALANCED) -> None:
        self.profile = profile
        self._layers = list(profile.cascade)
        self._source = _KeySource.RAW
        self._raw_key: bytes | None = None
        self._passphrase: str | None = None
        self._key_file: str | None = None
        self._sign_algorithm = SignatureAlgorithm.NONE
        self._sign_secret: bytes | None = None
        self._sign_public: bytes | None = None
        self._fec = FecScheme.NONE
        self._argon_ops = profile.argon2_ops
        self._argon_memory = profile.argon2_memory

    # ── Key source (exactly one) ─────────────────────────────────────────────

    def with_passphrase(self, passphrase: str) -> "Recipe":
        """Derive the root key from a passphrase with Argon2id."""
        self._source, self._passphrase = _KeySource.PASSPHRASE, passphrase
        return self

    def with_key(self, key: bytes) -> "Recipe":
        """
        Use a 32-byte key directly — from a KEM shared secret, a keyring unlock,
        a hardware token, anywhere. Nothing is stretched; the key must already be
        full-entropy.
        """
        if len(key) != 32:
            raise ValueError(f"cryptolib: root key must be exactly 32 bytes, got {len(key)}")
        self._source, self._raw_key = _KeySource.RAW, bytes(key)
        return self

    def with_key_file(self, path: str) -> "Recipe":
        """
        Derive the root key deterministically from a media file — "the file is
        the key". The same file always yields the same key on any machine.
        """
        self._source, self._key_file = _KeySource.KEY_FILE, path
        return self

    # ── Layers ───────────────────────────────────────────────────────────────

    def with_layers(self, layers: Sequence[ProtectionLayer]) -> "Recipe":
        """Replace the cascade with exactly these layers, innermost first."""
        if not layers:
            raise ValueError("cryptolib: a recipe needs at least one layer")
        self._layers = list(layers)
        return self

    def add_layer(self, layer: ProtectionLayer) -> "Recipe":
        """Append one more layer on the outside of the current cascade."""
        self._layers.append(layer)
        return self

    def argon2_cost(self, ops: int | None = None, memory_bytes: int | None = None) -> "Recipe":
        """Override the Argon2id cost. Only meaningful with :meth:`with_passphrase`."""
        if ops is not None:
            self._argon_ops = ops
        if memory_bytes is not None:
            self._argon_memory = memory_bytes
        return self

    # ── Authenticity ─────────────────────────────────────────────────────────

    def signed_by(self, secret_key: bytes,
                  algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519) -> "Recipe":
        """
        Sign the plaintext before it is encrypted, proving who produced it. The
        signature travels inside the encryption, so it reveals nothing about the
        sender to an observer.
        """
        if algorithm is SignatureAlgorithm.NONE:
            raise ValueError("cryptolib: signed_by needs a real algorithm")
        self._sign_algorithm, self._sign_secret = algorithm, bytes(secret_key)
        return self

    def verified_by(self, public_key: bytes) -> "Recipe":
        """
        The public key :meth:`open` must verify the embedded signature against.

        Required whenever the envelope is signed: without it there would be a
        signature but nobody checking it, so :meth:`open` fails rather than
        silently accepting.
        """
        self._sign_public = bytes(public_key)
        return self

    def with_fec(self, scheme: FecScheme) -> "Recipe":
        """Apply forward error correction to the finished envelope."""
        self._fec = scheme
        return self

    # ── Seal / open ──────────────────────────────────────────────────────────

    def seal(self, plaintext: bytes) -> bytes:
        """Protect `plaintext` and return the envelope."""
        salt = _random_bytes(_SALT_LEN)
        header = self._build_header(salt)
        root = self._root_key(salt, self._argon_ops, self._argon_memory)

        body = plaintext
        if self._sign_algorithm is not SignatureAlgorithm.NONE:
            if self._sign_secret is None:
                raise RuntimeError("cryptolib: signing requested without a secret key")
            sig = (_ed_sign(plaintext, self._sign_secret)
                   if self._sign_algorithm is SignatureAlgorithm.ED25519
                   else _hy_sign(plaintext, self._sign_secret))
            body = _struct.pack(">I", len(sig)) + sig + plaintext

        for index, layer in enumerate(self._layers):
            body = self._apply_layer(layer, index, root, salt, header, body, seal=True)

        envelope = header + body
        return envelope if self._fec is FecScheme.NONE else self._wrap_fec(envelope)

    def open(self, envelope: bytes) -> bytes:
        """
        Recover the plaintext. Raises if the key is wrong, a byte was altered, or
        a signature is present but does not verify.
        """
        inner = self._unwrap_fec(bytes(envelope))
        header, layers, salt, sign_algorithm, ops, memory = self._parse_header(inner)
        root = self._root_key(salt, ops, memory)

        body = inner[len(header):]
        for index in range(len(layers) - 1, -1, -1):
            body = self._apply_layer(layers[index], index, root, salt, header, body, seal=False)

        if sign_algorithm is SignatureAlgorithm.NONE:
            return body

        if len(body) < 4:
            raise ValueError("cryptolib: malformed signed payload")
        n = _struct.unpack(">I", body[:4])[0]
        if len(body) < 4 + n:
            raise ValueError("cryptolib: malformed signed payload")
        sig, plaintext = body[4:4 + n], body[4 + n:]
        if self._sign_public is None:
            raise RuntimeError(
                "cryptolib: envelope is signed but no public key was supplied — "
                "call verified_by so the signature is actually checked")
        ok = (_ed_verify(plaintext, sig, self._sign_public)
              if sign_algorithm is SignatureAlgorithm.ED25519
              else _hy_verify(plaintext, sig, self._sign_public))
        if not ok:
            raise ValueError("cryptolib: signature verification failed")
        return plaintext

    def seal_into_carrier(self, plaintext: bytes, cover_path: str, output_path: str) -> None:
        """
        Seal `plaintext` and hide the envelope inside `cover_path`.

        Concealment is defence-in-depth, never the confidentiality boundary — the
        envelope is already authenticated-encrypted before it is embedded.
        """
        _stego_embed(cover_path, self.seal(plaintext), output_path)

    def open_from_carrier(self, stego_path: str) -> bytes:
        """Extract and open an envelope written by :meth:`seal_into_carrier`."""
        return self.open(_stego_extract(stego_path))

    def describe(self) -> str:
        """
        A human-readable summary of what this recipe will do — handy in logs and
        code review, where a silently-weak configuration is the thing to catch.
        """
        layers = " -> ".join(layer.wire_name for layer in self._layers)
        out = (f"Recipe({self.profile.value})\n"
               f"  key      : {self._source.label}\n"
               f"  layers   : {layers}\n"
               f"  signature: {self._sign_algorithm.name.lower()}\n"
               f"  fec      : {int(self._fec)}\n")
        if self._source is _KeySource.PASSPHRASE:
            out += f"  argon2id : ops={self._argon_ops}, mem={self._argon_memory // (1024 * 1024)}MiB\n"
        return out

    # ── Internals ────────────────────────────────────────────────────────────

    def _root_key(self, salt: bytes, ops: int, memory: int) -> bytes:
        if self._source is _KeySource.PASSPHRASE:
            if self._passphrase is None:
                raise RuntimeError("cryptolib: no passphrase set")
            return _argon2id(self._passphrase, salt, 32, ops, memory)
        if self._source is _KeySource.KEY_FILE:
            if self._key_file is None:
                raise RuntimeError("cryptolib: no key file set")
            return _key_from_file(self._key_file)
        if self._raw_key is None:
            raise RuntimeError("cryptolib: no key set — call with_key/with_passphrase/with_key_file")
        return self._raw_key

    @staticmethod
    def _layer_key(root: bytes, salt: bytes, index: int, layer: ProtectionLayer) -> bytes:
        """HKDF under a distinct info string, so no two layers share key material."""
        info = f"cryptolib/recipe/v1/layer{index}/{layer.wire_name}".encode()
        return _hkdf(root, salt, info, 32)

    def _apply_layer(self, layer: ProtectionLayer, index: int, root: bytes, salt: bytes,
                     header: bytes, data: bytes, *, seal: bool) -> bytes:
        key = self._layer_key(root, salt, index, layer)
        table = {
            ProtectionLayer.XCHACHA20_POLY1305: (_x_enc, _x_dec),
            ProtectionLayer.AES256_GCM: (_aes_enc, _aes_dec),
            ProtectionLayer.COMMITTING: (_cmt_enc, _cmt_dec),
            ProtectionLayer.MOLECULAR: (_mol_seal, _mol_open),
        }
        fn = table[layer][0 if seal else 1]
        return fn(data, key, header)

    def _build_header(self, salt: bytes) -> bytes:
        head = bytes([_VERSION, int(self._source), int(self._sign_algorithm), len(self._layers)])
        ids = bytes(layer.id for layer in self._layers)
        return (_MAGIC + head + ids + salt
                + _struct.pack(">II", self._argon_ops, self._argon_memory))

    def _parse_header(self, env: bytes):
        if len(env) < 8 + _SALT_LEN + 8:
            raise ValueError("cryptolib: envelope too short")
        if env[:4] != _MAGIC:
            raise ValueError("cryptolib: not a CryptoRecipe envelope")
        if env[4] != _VERSION:
            raise ValueError(f"cryptolib: unsupported envelope version {env[4]}")
        source = _KeySource(env[5])
        if source is not self._source:
            raise ValueError(
                f"cryptolib: envelope was sealed with the {source.label} key source, "
                f"but this recipe is configured for {self._source.label}")
        sign_algorithm = SignatureAlgorithm(env[6])
        count = env[7]
        header_len = 8 + count + _SALT_LEN + 8
        if len(env) < header_len:
            raise ValueError("cryptolib: truncated envelope header")
        layers = [ProtectionLayer.from_id(env[8 + i]) for i in range(count)]
        salt = env[8 + count:8 + count + _SALT_LEN]
        ops, memory = _struct.unpack(">II", env[8 + count + _SALT_LEN:header_len])
        return env[:header_len], layers, salt, sign_algorithm, ops, memory

    def _wrap_fec(self, envelope: bytes) -> bytes:
        encoded = _fec_encode(envelope, int(self._fec))
        return _FEC_MAGIC + bytes([int(self._fec)]) + _struct.pack(">I", len(envelope)) + encoded

    @staticmethod
    def _unwrap_fec(data: bytes) -> bytes:
        if len(data) < 9 or data[:4] != _FEC_MAGIC:
            return data
        scheme = FecScheme(data[4])
        original_len = _struct.unpack(">I", data[5:9])[0]
        return _fec_decode(data[9:], int(scheme), original_len)


def recipe(profile: SecurityProfile = SecurityProfile.BALANCED) -> Recipe:
    """Start a :class:`Recipe` at the given profile's settings."""
    return Recipe(profile)


def maximum_security() -> Recipe:
    """A :class:`Recipe` using the strongest option at every choice."""
    return Recipe(SecurityProfile.MAXIMUM)
