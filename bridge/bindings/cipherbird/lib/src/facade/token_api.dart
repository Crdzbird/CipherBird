part of '../cipher_bird.dart';

/// Tokens: PASETO v4.local and the cb1 tokens, CipherBird's own.
extension type TokenApi(CipherBird _l) {
  /// PASETO v4.local, byte for byte the PASETO v4 specification.
  String v4LocalEncrypt(
    Uint8List key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _l.pasetoV4LocalEncrypt(
    key,
    message,
    footer: footer,
    implicit: implicit,
  );

  /// Open a PASETO v4.local token.
  Uint8List v4LocalDecrypt(
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _l.pasetoV4LocalDecrypt(
    token,
    key,
    expectedFooter: expectedFooter,
    implicit: implicit,
  );

  /// cb1.local: v4.local with BLAKE3.
  String cb1LocalEncrypt(
    Uint8List key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _l.cb1LocalEncrypt(key, message, footer: footer, implicit: implicit);

  /// Open a cb1.local token.
  Uint8List cb1LocalDecrypt(
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _l.cb1LocalDecrypt(
    token,
    key,
    expectedFooter: expectedFooter,
    implicit: implicit,
  );

  /// cb1.public: v4.public with the Ed25519 + ML-DSA-65 hybrid signature.
  String cb1PublicSign(
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _l.cb1PublicSign(
    secretKey,
    message,
    footer: footer,
    implicit: implicit,
  );

  /// Verify a cb1.public token and return its message.
  Uint8List cb1PublicVerify(
    String token,
    Uint8List publicKey, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _l.cb1PublicVerify(
    token,
    publicKey,
    expectedFooter: expectedFooter,
    implicit: implicit,
  );
}
