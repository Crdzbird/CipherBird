part of '../../cipher_bird.dart';

/// A hybrid X25519 + ML-KEM-768 key pair: a shared key that stays secret if
/// *either* half holds (harvest-now-decrypt-later resistant).
///
/// Two ways to use it:
///
/// ```dart
/// final me = KemKeyPair.generate();
/// final blob = KemKeyPair.encryptFor(me.publicKey, 'hello'.bytes);
/// final back = me.decrypt(blob);
///
/// final (ciphertext, key) = KemKeyPair.encapsulate(me.publicKey);
/// final sameKey = me.decapsulate(ciphertext);
/// ```
extension KemKeyPairDecryption on KemKeyPair {
  /// Recipient side: recover the key agreed in [KemKeyPair.encapsulate].
  SymmetricKey decapsulate(List<int> ciphertext) => SymmetricKey._(
    _lib,
    _lib.hkdfDerive(
      _lib.hybridKemDecapsulate(ciphertext.u8, secretKey),
      info: KemKeyPair._info.bytes,
    ),
  );

  /// Open a blob made by [KemKeyPair.encryptFor] for this key pair.
  Uint8List decrypt(List<int> blob, {List<int>? aad}) {
    final b = blob.u8;
    if (b.length < 4) {
      throw ArgumentError('cipherbird: malformed blob');
    }
    final n = ByteData.sublistView(b).getUint32(0);
    if (b.length < 4 + n) {
      throw ArgumentError('cipherbird: malformed blob');
    }
    return decapsulate(
      Uint8List.sublistView(b, 4, 4 + n),
    ).decrypt(Uint8List.sublistView(b, 4 + n), aad: aad);
  }

  /// [decrypt] for strings made by [KemKeyPair.encryptTextFor].
  String decryptText(String blobBase64, {String? aad}) =>
      decrypt(blobBase64.base64Bytes, aad: aad?.bytes).text;
}
