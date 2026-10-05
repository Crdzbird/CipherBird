part of '../../cryptolib.dart';

/// A composable protection pipeline.
///
/// Describe what you want once, then [seal] and [open] with the same recipe.
/// The envelope carries its own descriptor, so opening does not depend on
/// remembering which layers were used - only on holding the key.
///
/// ```dart
/// final recipe = lib.recipe(SecurityProfile.maximum)
///     .withPassphrase('correct horse battery staple')
///     .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
///     .verifiedBy(id.publicKey);
///
/// final envelope = recipe.seal(secret);
/// final back = recipe.open(envelope);
/// ```
///
/// Every part is replaceable with your own subclass - see [ProtectionLayer],
/// [KeySource] and [SignatureScheme]. Builder methods return the same
/// instance, so calls chain.
extension CryptoRecipeKeyDerivation on CryptoRecipe {
  /// For [verifiedBy]: build the built-in scheme the envelope names, around the
  /// supplied public key. Custom ids resolve to nothing - they need verifiedWith.
  SignatureScheme? _builtinVerifier(int signatureId) {
    final pk = _verifierKey;
    if (pk == null) {
      return null;
    }
    if (signatureId == SignatureAlgorithm.ed25519.id) {
      return Ed25519Signature(publicKey: pk);
    }
    if (signatureId == SignatureAlgorithm.hybrid.id) {
      return HybridSignature(publicKey: pk);
    }
    return null;
  }

  Uint8List _rootKey(KeySource source, Uint8List salt, int ops, int mem) {
    final root = source.deriveRoot(_lib, salt, ops, mem);
    if (root.length != 32) {
      throw StateError(
        'cryptolib: key source "${source.label}" produced ${root.length} bytes; the root key must be exactly 32',
      );
    }
    return root;
  }

  /// Per-layer key: HKDF over the root with a distinct info string, so no two
  /// layers ever share key material.
  Uint8List _layerKey(
    Uint8List root,
    Uint8List salt,
    int index,
    ProtectionLayer layer,
  ) => _lib.hkdfDerive(
    root,
    salt: salt,
    info: Uint8List.fromList(
      'cryptolib/recipe/v1/layer$index/${layer.wireName}'.codeUnits,
    ),
  );

  Uint8List _applyLayer(
    ProtectionLayer layer,
    int index,
    Uint8List root,
    Uint8List salt,
    Uint8List header,
    Uint8List data, {
    required bool seal,
  }) {
    final key = _layerKey(root, salt, index, layer);
    return seal
        ? layer.seal(_lib, key, header, data)
        : layer.open(_lib, key, header, data);
  }
}
