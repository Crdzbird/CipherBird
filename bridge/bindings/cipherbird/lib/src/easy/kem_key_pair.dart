part of '../cryptolib.dart';

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
final class KemKeyPair {
  KemKeyPair._(this._lib, this._pair);

  /// A fresh key pair.
  factory KemKeyPair.generate([CryptoLib? lib]) {
    final l = _easyLib(lib);
    return KemKeyPair._(l, l.hybridKemKeygen());
  }

  /// Wrap existing key bytes.
  factory KemKeyPair.fromBytes({
    required List<int> publicKey,
    required List<int> secretKey,
    CryptoLib? lib,
  }) => KemKeyPair._(
    _easyLib(lib),
    KeyPairResult(publicKey: publicKey.u8, secretKey: secretKey.u8),
  );

  static const _info = 'cryptolib/easy/kem/v1';

  final CryptoLib _lib;

  final KeyPairResult _pair;

  /// Sender side: agree on a key with the owner of [recipientPublicKey].
  /// Send the ciphertext; keep the key.
  static (Uint8List ciphertext, SymmetricKey key) encapsulate(
    List<int> recipientPublicKey, [
    CryptoLib? lib,
  ]) {
    final l = _easyLib(lib);
    final (ct, ss) = l.hybridKemEncapsulate(recipientPublicKey.u8);
    return (ct, SymmetricKey._(l, l.hkdfDerive(ss, info: _info.bytes)));
  }

  /// One-call public-key encryption: a self-contained blob only the owner of
  /// [recipientPublicKey] can open with [decrypt]. The blob is the KEM
  /// ciphertext followed by a key-committing AEAD of [plaintext]; [aad] is
  /// authenticated and must be repeated on [decrypt].
  static Uint8List encryptFor(
    List<int> recipientPublicKey,
    List<int> plaintext, {
    List<int>? aad,
    CryptoLib? lib,
  }) {
    final (ct, key) = encapsulate(recipientPublicKey, lib);
    final body = key.encrypt(plaintext, aad: aad);
    final out = Uint8List(4 + ct.length + body.length);
    ByteData.sublistView(out).setUint32(0, ct.length);
    out
      ..setRange(4, 4 + ct.length, ct)
      ..setRange(4 + ct.length, out.length, body);
    return out;
  }

  /// [encryptFor] for strings; returns base64.
  static String encryptTextFor(
    List<int> recipientPublicKey,
    String plaintext, {
    String? aad,
    CryptoLib? lib,
  }) => encryptFor(
    recipientPublicKey,
    plaintext.bytes,
    aad: aad?.bytes,
    lib: lib,
  ).base64;

  /// Public key bytes - share freely.
  Uint8List get publicKey => _pair.publicKey;

  /// Secret key bytes - never leave the device.
  Uint8List get secretKey => _pair.secretKey;
}
