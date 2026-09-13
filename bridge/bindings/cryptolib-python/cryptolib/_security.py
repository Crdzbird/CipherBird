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

import abc as _abc
import enum as _enum
import struct as _struct
from typing import Callable, Sequence

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


# ── Extension points ─────────────────────────────────────────────────────────
#
# Three abstract base classes can be subclassed and plugged into a Recipe:
#   ProtectionLayer  — one authenticated-encryption layer in the cascade.
#   KeySource        — where the 32-byte root key comes from.
#   SignatureScheme  — how the plaintext is signed and verified.
# The library's own implementations subclass the same bases, so a custom one is
# a first-class citizen. To compose several ciphers into ONE layer, subclass
# CascadeLayer.
#
# What the recipe keeps for itself, whatever you plug in: a layer never chooses
# its key (it receives a fresh 32-byte key per layer per envelope, HKDF-derived
# under salt + wire_name); a layer cannot opt out of the AAD; the order is fixed
# (sign -> encrypt -> correct -> conceal); a KeySource must return exactly 32
# bytes; ids 0–127 are reserved — custom parts must use 128–255, enforced so a
# custom part can never shadow a built-in.
#
# Cross-language: built-in ids open in every CryptoLib binding. A custom part
# opens only where the same id + wire_name + algorithm is registered — and since
# wire_name feeds the key derivation, a mismatched implementation fails the AEAD
# tag rather than yielding garbage.

_CUSTOM_ID_MIN, _CUSTOM_ID_MAX = 128, 255


class _Builtin:
    """Module-private marker: only this module's parts carry it, so a subclass
    cannot claim a reserved id by pretending to be built in."""


def _require_valid_id(part: object, part_id: int, what: str) -> None:
    if isinstance(part, _Builtin):
        return
    if not isinstance(part_id, int) or not _CUSTOM_ID_MIN <= part_id <= _CUSTOM_ID_MAX:
        raise ValueError(f"cryptolib: custom {what} ids must be in {_CUSTOM_ID_MIN}..{_CUSTOM_ID_MAX} "
                         f"(0–127 are reserved), got {part_id}")


class ProtectionLayer(_abc.ABC):
    """
    One authenticated-encryption layer in a :class:`Recipe` cascade.

    Subclass it to add your own layer, then :meth:`register` it (on the opening
    side too — the envelope stores only the id). Contract: :meth:`seal` must be
    authenticated encryption that binds ``aad``, and :meth:`open` must raise on
    any modification. The key is fresh per layer per envelope — never reuse it.

        >>> class MyLayer(ProtectionLayer):
        ...     id = 200
        ...     wire_name = "my-xchacha"
        ...     def seal(self, key, aad, plaintext): return cryptolib.xchacha20_encrypt(plaintext, key, aad)
        ...     def open(self, key, aad, ciphertext): return cryptolib.xchacha20_decrypt(ciphertext, key, aad)
        >>> ProtectionLayer.register(MyLayer())
    """

    #: Recorded in the envelope header. Built-ins use 1–4; custom 128–255.
    id: int
    #: Feeds this layer's HKDF info string. Part of the wire format.
    wire_name: str

    # Built-in singletons, assigned below the class body.
    XCHACHA20_POLY1305: "ProtectionLayer"
    AES256_GCM: "ProtectionLayer"
    COMMITTING: "ProtectionLayer"
    MOLECULAR: "ProtectionLayer"

    @_abc.abstractmethod
    def seal(self, key: bytes, aad: bytes, plaintext: bytes) -> bytes: ...

    @_abc.abstractmethod
    def open(self, key: bytes, aad: bytes, ciphertext: bytes) -> bytes: ...

    _registry: dict[int, "ProtectionLayer"] = {}

    @classmethod
    def register(cls, layer: "ProtectionLayer") -> None:
        """Make a custom layer resolvable by id when opening. Re-registering an id
        under a different wire name is refused."""
        _require_valid_id(layer, layer.id, "layer")
        existing = ProtectionLayer._registry.get(layer.id)
        if existing is not None and existing.wire_name != layer.wire_name:
            raise ValueError(f"cryptolib: layer id {layer.id} is already registered as '{existing.wire_name}'")
        ProtectionLayer._registry[layer.id] = layer

    @classmethod
    def from_id(cls, layer_id: int) -> "ProtectionLayer":
        try:
            return ProtectionLayer._registry[layer_id]
        except KeyError:
            raise ValueError(f"cryptolib: unknown protection layer id {layer_id} — "
                             "ProtectionLayer.register() it before opening") from None

    def __repr__(self) -> str:
        return f"<ProtectionLayer {self.wire_name} id={self.id}>"


class _BuiltinLayer(ProtectionLayer, _Builtin):
    def __init__(self, layer_id: int, wire_name: str,
                 enc: Callable[[bytes, bytes, bytes], bytes], dec: Callable[[bytes, bytes, bytes], bytes]) -> None:
        self.id, self.wire_name, self._enc, self._dec = layer_id, wire_name, enc, dec

    def seal(self, key: bytes, aad: bytes, plaintext: bytes) -> bytes:
        return self._enc(plaintext, key, aad)

    def open(self, key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        return self._dec(ciphertext, key, aad)


#: XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
ProtectionLayer.XCHACHA20_POLY1305 = _BuiltinLayer(1, "xchacha20Poly1305", _x_enc, _x_dec)
#: AES-256-GCM. A different cipher family from ChaCha.
ProtectionLayer.AES256_GCM = _BuiltinLayer(2, "aes256Gcm", _aes_enc, _aes_dec)
#: Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
ProtectionLayer.COMMITTING = _BuiltinLayer(3, "committing", _cmt_enc, _cmt_dec)
#: A full MolecularVault (cascade + committing) nested as one layer.
ProtectionLayer.MOLECULAR = _BuiltinLayer(4, "molecular", _mol_seal, _mol_open)
ProtectionLayer._registry.update({
    1: ProtectionLayer.XCHACHA20_POLY1305, 2: ProtectionLayer.AES256_GCM,
    3: ProtectionLayer.COMMITTING, 4: ProtectionLayer.MOLECULAR,
})


class CascadeLayer(ProtectionLayer):
    """
    A layer that is itself a mixture of layers — the way to compose several
    encryptions into one custom type. Subclass it, or instantiate it directly:

        >>> class BeltAndBraces(CascadeLayer):
        ...     def __init__(self):
        ...         super().__init__(201, "belt-and-braces",
        ...                          [ProtectionLayer.XCHACHA20_POLY1305, MyLayer()])

    Each inner layer receives its own sub-key, HKDF-derived from this layer's
    key under the inner index and wire name, so nesting never collapses two
    ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
    """

    def __init__(self, layer_id: int, wire_name: str, layers: Sequence[ProtectionLayer]) -> None:
        if not layers:
            raise ValueError(f"cryptolib: CascadeLayer '{wire_name}' has no layers")
        self.id, self.wire_name, self.layers = layer_id, wire_name, list(layers)

    def _sub_key(self, key: bytes, i: int) -> bytes:
        return _hkdf(key, b"", f"{self.wire_name}/{i}/{self.layers[i].wire_name}".encode(), 32)

    def seal(self, key: bytes, aad: bytes, plaintext: bytes) -> bytes:
        body = plaintext
        for i, layer in enumerate(self.layers):
            body = layer.seal(self._sub_key(key, i), aad, body)
        return body

    def open(self, key: bytes, aad: bytes, ciphertext: bytes) -> bytes:
        body = ciphertext
        for i in range(len(self.layers) - 1, -1, -1):
            body = self.layers[i].open(self._sub_key(key, i), aad, body)
        return body


class KeySource(_abc.ABC):
    """
    Where a :class:`Recipe`'s 32-byte root key comes from.

    Subclass it for a hardware token, a KMS, a keyring unlock — anything that
    can produce the same 32 bytes again when opening. The recipe refuses any
    other length.
    """

    #: Recorded in the envelope header. Built-ins use 0–2; custom 128–255.
    id: int
    #: Human-readable name, used by :meth:`Recipe.describe`.
    label: str

    @_abc.abstractmethod
    def derive_root(self, salt: bytes, argon2_ops: int, argon2_memory: int) -> bytes:
        """``salt`` is fresh per envelope; ops/memory are the recipe's Argon2id cost."""


class RawKeySource(KeySource, _Builtin):
    """A 32-byte full-entropy key used as-is (KEM secret, keyring unlock, token)."""
    id, label = 0, "raw"

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(f"cryptolib: root key must be exactly 32 bytes, got {len(key)}")
        self._key = bytes(key)

    def derive_root(self, salt: bytes, argon2_ops: int, argon2_memory: int) -> bytes:
        return self._key


class PassphraseKeySource(KeySource, _Builtin):
    """A passphrase stretched with Argon2id at the recipe's cost."""
    id, label = 1, "passphrase"

    def __init__(self, passphrase: str) -> None:
        self._passphrase = passphrase

    def derive_root(self, salt: bytes, argon2_ops: int, argon2_memory: int) -> bytes:
        return _argon2id(self._passphrase, salt, 32, argon2_ops, argon2_memory)


class KeyFileSource(KeySource, _Builtin):
    """The key derived deterministically from a media file — "the file is the key".
    Uses the reproducible entropy path; ``key_from_file`` mixes in fresh system
    entropy and so could never reopen its own envelope."""
    id, label = 2, "keyFile"

    def __init__(self, path: str) -> None:
        self._path = path

    def derive_root(self, salt: bytes, argon2_ops: int, argon2_memory: int) -> bytes:
        return _key_from_file(self._path)


class SignatureScheme(_abc.ABC):
    """
    How a :class:`Recipe` signs and verifies the plaintext.

    Subclass it for another algorithm; a scheme holding only a public key should
    raise from :meth:`sign`. The signature is applied before encryption, so it
    stays confidential. Custom schemes are verified only through
    :meth:`Recipe.verified_with`.
    """

    #: Recorded in the envelope header. Built-ins use 1–2; custom 128–255.
    id: int
    #: Human-readable name, used by :meth:`Recipe.describe`.
    label: str

    @_abc.abstractmethod
    def sign(self, message: bytes) -> bytes: ...

    @_abc.abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool: ...


class Ed25519Signature(SignatureScheme, _Builtin):
    """Ed25519. Pass ``secret_key`` to sign, ``public_key`` to verify, or both."""
    id, label = 1, "ed25519"

    def __init__(self, secret_key: bytes | None = None, public_key: bytes | None = None) -> None:
        self._sk = None if secret_key is None else bytes(secret_key)
        self._pk = None if public_key is None else bytes(public_key)

    def sign(self, message: bytes) -> bytes:
        if self._sk is None:
            raise RuntimeError("cryptolib: Ed25519Signature has no secret key")
        return _ed_sign(message, self._sk)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._pk is not None and _ed_verify(message, signature, self._pk)


class HybridSignature(SignatureScheme, _Builtin):
    """Ed25519 + ML-DSA-65. A forgery needs breaking both families."""
    id, label = 2, "hybrid"

    def __init__(self, secret_key: bytes | None = None, public_key: bytes | None = None) -> None:
        self._sk = None if secret_key is None else bytes(secret_key)
        self._pk = None if public_key is None else bytes(public_key)

    def sign(self, message: bytes) -> bytes:
        if self._sk is None:
            raise RuntimeError("cryptolib: HybridSignature has no secret key")
        return _hy_sign(message, self._sk)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._pk is not None and _hy_verify(message, signature, self._pk)


class SignatureAlgorithm(_enum.IntEnum):
    """Built-in scheme selector for the :meth:`Recipe.signed_by` shorthand."""

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

    Every part is replaceable with your own subclass — see
    :class:`ProtectionLayer`, :class:`KeySource` and :class:`SignatureScheme`.
    Builder methods return ``self`` so calls chain. Not thread-safe.
    """

    def __init__(self, profile: SecurityProfile = SecurityProfile.BALANCED) -> None:
        self.profile = profile
        self._layers = list(profile.cascade)
        self._source: KeySource | None = None
        self._signer: SignatureScheme | None = None
        self._verifier: SignatureScheme | None = None
        self._verifier_key: bytes | None = None
        self._fec = FecScheme.NONE
        self._argon_ops = profile.argon2_ops
        self._argon_memory = profile.argon2_memory

    # ── Key source (exactly one) ─────────────────────────────────────────────

    def with_key_source(self, source: KeySource) -> "Recipe":
        """Use any :class:`KeySource` — a built-in or your own subclass."""
        if not isinstance(source, KeySource):
            raise TypeError("cryptolib: with_key_source expects a KeySource")
        _require_valid_id(source, source.id, "key source")
        self._source = source
        return self

    def with_passphrase(self, passphrase: str) -> "Recipe":
        """Derive the root key from a passphrase with Argon2id."""
        return self.with_key_source(PassphraseKeySource(passphrase))

    def with_key(self, key: bytes) -> "Recipe":
        """
        Use a 32-byte key directly — from a KEM shared secret, a keyring unlock,
        a hardware token, anywhere. Nothing is stretched; the key must already be
        full-entropy.
        """
        return self.with_key_source(RawKeySource(key))

    def with_key_file(self, path: str) -> "Recipe":
        """
        Derive the root key deterministically from a media file — "the file is
        the key". The same file always yields the same key on any machine.
        """
        return self.with_key_source(KeyFileSource(path))

    # ── Layers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _check_layer(layer: ProtectionLayer) -> None:
        if not isinstance(layer, ProtectionLayer):
            raise TypeError("cryptolib: layers must be ProtectionLayer instances")
        _require_valid_id(layer, layer.id, "layer")

    def with_layers(self, layers: Sequence[ProtectionLayer]) -> "Recipe":
        """Replace the cascade with exactly these layers, innermost first."""
        if not layers:
            raise ValueError("cryptolib: a recipe needs at least one layer")
        for layer in layers:
            self._check_layer(layer)
        self._layers = list(layers)
        return self

    def add_layer(self, layer: ProtectionLayer) -> "Recipe":
        """Append one more layer on the outside of the current cascade."""
        self._check_layer(layer)
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

    def signed_with(self, scheme: SignatureScheme) -> "Recipe":
        """Sign with any :class:`SignatureScheme` — a built-in or your own subclass."""
        if not isinstance(scheme, SignatureScheme):
            raise TypeError("cryptolib: signed_with expects a SignatureScheme")
        _require_valid_id(scheme, scheme.id, "signature scheme")
        self._signer = scheme
        return self

    def verified_with(self, scheme: SignatureScheme) -> "Recipe":
        """Verify with any :class:`SignatureScheme`. Required for a custom scheme."""
        if not isinstance(scheme, SignatureScheme):
            raise TypeError("cryptolib: verified_with expects a SignatureScheme")
        _require_valid_id(scheme, scheme.id, "signature scheme")
        self._verifier, self._verifier_key = scheme, None
        return self

    def signed_by(self, secret_key: bytes,
                  algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519) -> "Recipe":
        """
        Sign the plaintext before it is encrypted with a built-in scheme, proving
        who produced it. The signature travels inside the encryption, so it
        reveals nothing about the sender to an observer.
        """
        if algorithm is SignatureAlgorithm.ED25519:
            return self.signed_with(Ed25519Signature(secret_key=secret_key))
        if algorithm is SignatureAlgorithm.HYBRID:
            return self.signed_with(HybridSignature(secret_key=secret_key))
        raise ValueError("cryptolib: signed_by needs a real algorithm")

    def verified_by(self, public_key: bytes) -> "Recipe":
        """
        The public key :meth:`open` must verify the embedded signature against.
        Works for either built-in scheme — the envelope records which one. A
        custom :class:`SignatureScheme` must be supplied through
        :meth:`verified_with`.

        Required whenever the envelope is signed: without it there would be a
        signature but nobody checking it, so :meth:`open` fails rather than
        silently accepting.
        """
        self._verifier, self._verifier_key = None, bytes(public_key)
        return self

    def with_fec(self, scheme: FecScheme) -> "Recipe":
        """Apply forward error correction to the finished envelope."""
        self._fec = scheme
        return self

    # ── Seal / open ──────────────────────────────────────────────────────────

    def seal(self, plaintext: bytes) -> bytes:
        """Protect `plaintext` and return the envelope."""
        source = self._require_source()
        salt = _random_bytes(_SALT_LEN)
        header = self._build_header(source, salt)
        root = self._root_key(source, salt, self._argon_ops, self._argon_memory)

        body = bytes(plaintext)
        if self._signer is not None:
            sig = self._signer.sign(body)
            body = _struct.pack(">I", len(sig)) + sig + body

        for index, layer in enumerate(self._layers):
            body = self._apply_layer(layer, index, root, salt, header, body, seal=True)

        envelope = header + body
        return envelope if self._fec is FecScheme.NONE else self._wrap_fec(envelope)

    def open(self, envelope: bytes) -> bytes:
        """
        Recover the plaintext. Raises if the key is wrong, a byte was altered, or
        a signature is present but does not verify.
        """
        source = self._require_source()
        inner = self._unwrap_fec(bytes(envelope))
        header, layers, salt, signature_id, ops, memory = self._parse_header(inner, source)
        root = self._root_key(source, salt, ops, memory)

        body = inner[len(header):]
        for index in range(len(layers) - 1, -1, -1):
            body = self._apply_layer(layers[index], index, root, salt, header, body, seal=False)

        if signature_id == 0:
            return body

        if len(body) < 4:
            raise ValueError("cryptolib: malformed signed payload")
        n = _struct.unpack(">I", body[:4])[0]
        if len(body) < 4 + n:
            raise ValueError("cryptolib: malformed signed payload")
        sig, plaintext = body[4:4 + n], body[4 + n:]
        verifier = self._verifier or self._builtin_verifier(signature_id)
        if verifier is None:
            if self._verifier_key is not None:
                raise RuntimeError(
                    f"cryptolib: envelope was signed with scheme id {signature_id}, which is not a "
                    "built-in — supply that SignatureScheme with verified_with()")
            raise RuntimeError(
                "cryptolib: envelope is signed but no verifier was supplied — "
                "call verified_by/verified_with so the signature is actually checked")
        if verifier.id != signature_id:
            raise ValueError(f"cryptolib: envelope was signed with scheme id {signature_id}, "
                             f"but the verifier is '{verifier.label}' (id {verifier.id})")
        if not verifier.verify(plaintext, sig):
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
               f"  key      : {self._source.label if self._source else '(unset)'}\n"
               f"  layers   : {layers}\n"
               f"  signature: {self._signer.label if self._signer else 'none'}\n"
               f"  fec      : {int(self._fec)}\n")
        if isinstance(self._source, PassphraseKeySource):
            out += f"  argon2id : ops={self._argon_ops}, mem={self._argon_memory // (1024 * 1024)}MiB\n"
        return out

    # ── Internals ────────────────────────────────────────────────────────────

    def _require_source(self) -> KeySource:
        if self._source is None:
            raise RuntimeError("cryptolib: no key set — call with_key/with_passphrase/with_key_file/with_key_source")
        return self._source

    def _builtin_verifier(self, signature_id: int) -> SignatureScheme | None:
        if self._verifier_key is None:
            return None
        if signature_id == SignatureAlgorithm.ED25519:
            return Ed25519Signature(public_key=self._verifier_key)
        if signature_id == SignatureAlgorithm.HYBRID:
            return HybridSignature(public_key=self._verifier_key)
        return None

    def _root_key(self, source: KeySource, salt: bytes, ops: int, memory: int) -> bytes:
        root = bytes(source.derive_root(salt, ops, memory))
        if len(root) != 32:
            raise ValueError(f"cryptolib: key source '{source.label}' produced {len(root)} bytes; "
                             "the root key must be exactly 32")
        return root

    @staticmethod
    def _layer_key(root: bytes, salt: bytes, index: int, layer: ProtectionLayer) -> bytes:
        """HKDF under a distinct info string, so no two layers share key material."""
        info = f"cryptolib/recipe/v1/layer{index}/{layer.wire_name}".encode()
        return _hkdf(root, salt, info, 32)

    def _apply_layer(self, layer: ProtectionLayer, index: int, root: bytes, salt: bytes,
                     header: bytes, data: bytes, *, seal: bool) -> bytes:
        key = self._layer_key(root, salt, index, layer)
        return layer.seal(key, header, data) if seal else layer.open(key, header, data)

    def _build_header(self, source: KeySource, salt: bytes) -> bytes:
        signature_id = self._signer.id if self._signer is not None else 0
        head = bytes([_VERSION, source.id, signature_id, len(self._layers)])
        ids = bytes(layer.id for layer in self._layers)
        return (_MAGIC + head + ids + salt
                + _struct.pack(">II", self._argon_ops, self._argon_memory))

    def _parse_header(self, env: bytes, source: KeySource):
        if len(env) < 8 + _SALT_LEN + 8:
            raise ValueError("cryptolib: envelope too short")
        if env[:4] != _MAGIC:
            raise ValueError("cryptolib: not a CryptoRecipe envelope")
        if env[4] != _VERSION:
            raise ValueError(f"cryptolib: unsupported envelope version {env[4]}")
        if env[5] != source.id:
            raise ValueError(
                f"cryptolib: envelope was sealed with key source id {env[5]}, "
                f"but this recipe is configured for '{source.label}' (id {source.id})")
        signature_id = env[6]
        count = env[7]
        header_len = 8 + count + _SALT_LEN + 8
        if len(env) < header_len:
            raise ValueError("cryptolib: truncated envelope header")
        layers = [ProtectionLayer.from_id(env[8 + i]) for i in range(count)]
        salt = env[8 + count:8 + count + _SALT_LEN]
        ops, memory = _struct.unpack(">II", env[8 + count + _SALT_LEN:header_len])
        return env[:header_len], layers, salt, signature_id, ops, memory

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
