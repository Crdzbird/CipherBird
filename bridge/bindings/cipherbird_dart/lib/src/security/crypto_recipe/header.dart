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
extension CipherBirdRecipeHeader on CipherBirdRecipe {
  Uint8List _buildHeader(KeySource source, Uint8List salt, int ops, int mem) {
    final out = BytesBuilder()
      ..add(CipherBirdRecipe._magic)
      ..addByte(CipherBirdRecipe._version)
      ..addByte(source.id)
      ..addByte(_signer?.id ?? SignatureAlgorithm.none.id)
      ..addByte(_layers.length);
    for (final l in _layers) {
      out.addByte(l.id);
    }
    out.add(salt);
    final costs = ByteData(8)
      ..setUint32(0, ops)
      ..setUint32(4, mem);
    out.add(costs.buffer.asUint8List());
    return out.toBytes();
  }

  _ParsedHeader _parseHeader(Uint8List env, KeySource source) {
    if (env.length < 8 + CipherBirdRecipe._saltLen + 8) {
      throw Exception('cipherbird: envelope too short');
    }
    for (var i = 0; i < 4; i++) {
      if (env[i] != CipherBirdRecipe._magic[i]) {
        throw Exception('cipherbird: not a CipherBirdRecipe envelope');
      }
    }
    if (env[4] != CipherBirdRecipe._version) {
      throw Exception('cipherbird: unsupported envelope version ${env[4]}');
    }
    final sourceId = env[5];
    if (sourceId != source.id) {
      throw Exception(
        'cipherbird: envelope was sealed with key source id $sourceId, '
        'but this recipe is configured for "${source.label}" (id ${source.id})',
      );
    }
    final signatureId = env[6];
    final layerCount = env[7];
    final headerLen = 8 + layerCount + CipherBirdRecipe._saltLen + 8;
    if (env.length < headerLen) {
      throw Exception('cipherbird: truncated envelope header');
    }
    final layers = [
      for (var i = 0; i < layerCount; i++) ProtectionLayer._resolve(env[8 + i]),
    ];
    final salt = Uint8List.fromList(
      env.sublist(8 + layerCount, 8 + layerCount + CipherBirdRecipe._saltLen),
    );
    final costs = ByteData.sublistView(
      env,
      8 + layerCount + CipherBirdRecipe._saltLen,
      headerLen,
    );
    return _ParsedHeader(
      header: Uint8List.fromList(env.sublist(0, headerLen)),
      layers: layers,
      salt: salt,
      signatureId: signatureId,
      ops: costs.getUint32(0),
      memory: costs.getUint32(4),
    );
  }
}
