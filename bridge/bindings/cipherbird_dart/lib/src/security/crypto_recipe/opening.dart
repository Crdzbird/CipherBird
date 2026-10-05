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
extension CipherBirdRecipeOpening on CipherBirdRecipe {
  /// Recover the plaintext from [envelope]. Throws if the key is wrong, a byte
  /// was altered, or a signature is present but does not verify.
  Uint8List open(Uint8List envelope) {
    final source =
        _source ??
        (throw StateError(
          'cipherbird: no key set - call withKey/withPassphrase/withKeyFile/withKeySource',
        ));
    final inner = _unwrapFec(envelope);
    final parsed = _parseHeader(inner, source);
    final header = parsed.header;
    final root = _rootKey(source, parsed.salt, parsed.ops, parsed.memory);

    var body = Uint8List.sublistView(inner, header.length);
    for (var i = parsed.layers.length - 1; i >= 0; i--) {
      body = _applyLayer(
        parsed.layers[i],
        i,
        root,
        parsed.salt,
        header,
        body,
        seal: false,
      );
    }

    if (parsed.signatureId == SignatureAlgorithm.none.id) {
      return body;
    }

    final (sig, plaintext) = CipherBirdRecipe._splitLengthed(body);
    final verifier = _verifier ?? _builtinVerifier(parsed.signatureId);
    if (verifier == null) {
      if (_verifierKey != null) {
        throw Exception(
          'cipherbird: envelope was signed with scheme id ${parsed.signatureId}, which is '
          'not a built-in - supply that SignatureScheme with verifiedWith()',
        );
      }
      throw StateError(
        'cipherbird: envelope is signed but no verifier was supplied - '
        'call verifiedBy()/verifiedWith() so the signature is actually checked',
      );
    }
    if (verifier.id != parsed.signatureId) {
      throw Exception(
        'cipherbird: envelope was signed with scheme id ${parsed.signatureId}, '
        'but the verifier is "${verifier.label}" (id ${verifier.id})',
      );
    }
    if (!verifier.verify(_lib, plaintext, sig)) {
      throw Exception('cipherbird: signature verification failed');
    }
    return plaintext;
  }

  /// Seal [plaintext] and hide the envelope inside [coverPath], writing the
  /// result to [outputPath].
  ///
  /// Concealment is defence-in-depth, never the confidentiality boundary - the
  /// envelope is already authenticated-encrypted before it is embedded.
  void sealIntoCarrier(
    Uint8List plaintext, {
    required String coverPath,
    required String outputPath,
  }) {
    _lib.stegoEmbed(coverPath, seal(plaintext), outputPath);
  }

  /// Extract and open an envelope previously written by [sealIntoCarrier].
  Uint8List openFromCarrier(String stegoPath) =>
      open(_lib.stegoExtract(stegoPath));
}
