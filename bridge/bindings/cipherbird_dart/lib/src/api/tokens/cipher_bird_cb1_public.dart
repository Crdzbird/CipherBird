part of '../../cipher_bird.dart';

/// cb1.public on CipherBird: PASETO v4.public with the Ed25519 + ML-DSA-65
/// hybrid signature in place of Ed25519.
///
/// Keys are the pairs of [hybridSigKeygen]: public key 1984 bytes, secret
/// key 4096 bytes, signature 3373 bytes. The signature covers
/// PAE("cb1.public.", m, f, i) and verifies only if both halves verify, so
/// a token stays unforgeable while either Ed25519 or ML-DSA-65 is unbroken.
/// The message travels in clear. Library-native: present in the full
/// profile, [TokenStatus.unavailable] in the bank profile.
extension CipherBirdCb1Public on CipherBird {
  /// Sign [message] with [secretKey]; [footer] travels in clear and is
  /// signed, [implicit] is signed but never stored.
  String cb1PublicSign(
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _tokenSeal(
    'cryptolib_cb1_public_sign_len',
    'cryptolib_cb1_public_sign',
    'cb1.public',
    secretKey,
    message,
    footer,
    implicit,
  );

  /// Verify [token] against [publicKey] and return its message; throws a
  /// [TokenException] with [TokenStatus.invalid] for every failure that
  /// depends on the token, the signature included.
  Uint8List cb1PublicVerify(
    String token,
    Uint8List publicKey, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _tokenOpen(
    'cryptolib_cb1_public_verify_cap',
    'cryptolib_cb1_public_verify',
    'cb1.public',
    token,
    publicKey,
    expectedFooter,
    implicit,
  );
}
