part of '../../cipher_bird.dart';

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
extension CipherBirdRecipeBuilder on CipherBirdRecipe {
  /// Replace the cascade with exactly these layers, innermost first.
  CipherBirdRecipe withLayers(List<ProtectionLayer> layers) {
    if (layers.isEmpty) {
      throw ArgumentError.value(
        layers,
        'layers',
        'a recipe needs at least one layer',
      );
    }
    for (final l in layers) {
      _requireValidId(l, l.id, 'layer');
    }
    _layers = List.of(layers);
    return this;
  }

  /// Append one more layer on the outside of the current cascade.
  CipherBirdRecipe addLayer(ProtectionLayer layer) {
    _requireValidId(layer, layer.id, 'layer');
    _layers.add(layer);
    return this;
  }

  /// Override the Argon2id cost. Only meaningful with a passphrase source.
  CipherBirdRecipe argon2Cost({int? ops, int? memoryBytes}) {
    _argon2Ops = ops;
    _argon2Memory = memoryBytes;
    return this;
  }

  /// Sign with any [SignatureScheme] - a built-in or your own subclass.
  CipherBirdRecipe signedWith(SignatureScheme scheme) {
    _requireValidId(scheme, scheme.id, 'signature scheme');
    _signer = scheme;
    return this;
  }

  /// Verify with any [SignatureScheme]. Required whenever the envelope is
  /// signed: without it there is a signature but nobody checking it, so [open]
  /// refuses rather than silently accepting.
  CipherBirdRecipe verifiedWith(SignatureScheme scheme) {
    _requireValidId(scheme, scheme.id, 'signature scheme');
    _verifier = scheme;
    _verifierKey = null;
    return this;
  }

  /// Sign the plaintext before it is encrypted, proving who produced it.
  /// Shorthand for [signedWith] with a built-in scheme.
  CipherBirdRecipe signedBy(
    Uint8List secretKey, {
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
  }) {
    final sk = Uint8List.fromList(secretKey);
    return switch (algorithm) {
      SignatureAlgorithm.ed25519 => signedWith(Ed25519Signature(secretKey: sk)),
      SignatureAlgorithm.hybrid => signedWith(HybridSignature(secretKey: sk)),
      SignatureAlgorithm.none => throw ArgumentError.value(
        algorithm,
        'algorithm',
        'use signedBy with a real algorithm',
      ),
    };
  }

  /// The public key [open] must verify the embedded signature against.
  ///
  /// Works for either built-in scheme: the envelope records which one it was
  /// signed with, so you need only the key. A custom [SignatureScheme] must be
  /// supplied through [verifiedWith] instead.
  CipherBirdRecipe verifiedBy(Uint8List publicKey) {
    _verifier = null;
    _verifierKey = Uint8List.fromList(publicKey);
    return this;
  }
}
