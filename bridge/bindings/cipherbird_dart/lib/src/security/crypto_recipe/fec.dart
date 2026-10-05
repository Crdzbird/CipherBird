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
extension CipherBirdRecipeFec on CipherBirdRecipe {
  Uint8List _unwrapFec(Uint8List data) {
    if (data.length < 9) {
      return data;
    }
    for (var i = 0; i < 4; i++) {
      if (data[i] != CipherBirdRecipe._fecMagic[i]) {
        return data;
      }
    }
    final scheme = FecScheme.values.firstWhere(
      (s) => s.value == data[4],
      orElse: () =>
          throw Exception('cipherbird: unknown FEC scheme ${data[4]}'),
    );
    final originalLen = ByteData.sublistView(data, 5, 9).getUint32(0);
    return _lib.fecDecode(Uint8List.sublistView(data, 9), scheme, originalLen);
  }

  Uint8List _wrapFec(Uint8List envelope) {
    final encoded = _lib.fecEncode(envelope, _fec);
    final out = BytesBuilder()
      ..add(CipherBirdRecipe._fecMagic)
      ..addByte(_fec.value);
    final len = ByteData(4)..setUint32(0, envelope.length);
    out
      ..add(len.buffer.asUint8List())
      ..add(encoded);
    return out.toBytes();
  }
}
