part of '../cipher_bird.dart';

/// One authenticated-encryption layer in a [CipherBirdRecipe] cascade.
///
/// Subclass it to add your own layer, then [ProtectionLayer.register] it (on
/// the opening side too - the envelope stores only the [ProtectionLayer.id]):
///
/// ```dart
/// class MyLayer extends ProtectionLayer {
///   const MyLayer();
///   @override int get id => 200;
///   @override String get wireName => 'my-layer';
///   @override Uint8List seal(CipherBird lib, Uint8List key, Uint8List aad, Uint8List pt) =>
///       lib.xchacha20Encrypt(pt, key, aad);
///   @override Uint8List open(CipherBird lib, Uint8List key, Uint8List aad, Uint8List ct) =>
///       lib.xchacha20Decrypt(ct, key, aad);
/// }
/// ProtectionLayer.register(const MyLayer());
/// ```
///
/// **Contract:** [seal] must be authenticated encryption that binds `aad`, and
/// [open] must fail closed on any modification of ciphertext or aad. The
/// `key` is fresh per layer per envelope - never reuse it elsewhere. To build
/// a layer out of several ciphers, extend [CascadeLayer] instead.
abstract class ProtectionLayer {
  const ProtectionLayer();

  /// XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
  static const ProtectionLayer xchacha20Poly1305 = XChaCha20Layer();

  /// AES-256-GCM. A different cipher family from ChaCha.
  static const ProtectionLayer aes256Gcm = Aes256GcmLayer();

  /// Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
  static const ProtectionLayer committing = CommittingLayer();

  /// A full MolecularVault (cascade + committing) nested as one layer.
  static const ProtectionLayer molecular = MolecularLayer();

  /// Identifier recorded in the envelope header. Built-ins use 1–4; custom
  /// layers must use 128–255.
  int get id;

  /// Name used in this layer's HKDF info string. Part of the wire format:
  /// change it and every existing envelope using this layer stops opening.
  String get wireName;

  /// Authenticated-encrypt [plaintext] under [key], binding [aad].
  Uint8List seal(
    CipherBird lib,
    Uint8List key,
    Uint8List aad,
    Uint8List plaintext,
  );

  /// Reverse [seal]. Must throw on any modification.
  Uint8List open(
    CipherBird lib,
    Uint8List key,
    Uint8List aad,
    Uint8List ciphertext,
  );

  static final Map<int, ProtectionLayer> _registry = {
    1: xchacha20Poly1305,
    2: aes256Gcm,
    3: committing,
    4: molecular,
  };

  /// Make a custom layer resolvable by id when opening envelopes. Required on
  /// both the sealing and the opening side. Re-registering the same id with a
  /// different implementation is refused.
  static void register(ProtectionLayer layer) {
    _requireValidId(layer, layer.id, 'layer');
    final existing = _registry[layer.id];
    if (existing != null && existing.wireName != layer.wireName) {
      throw StateError(
        'cipherbird: layer id ${layer.id} is already registered as "${existing.wireName}"',
      );
    }
    _registry[layer.id] = layer;
  }

  static ProtectionLayer _resolve(int id) =>
      _registry[id] ??
      (throw Exception(
        'cipherbird: unknown protection layer id $id - register() it before opening',
      ));

  @override
  String toString() => wireName;
}
