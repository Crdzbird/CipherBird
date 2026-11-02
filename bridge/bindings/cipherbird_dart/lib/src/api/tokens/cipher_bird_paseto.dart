part of '../../cipher_bird.dart';

/// PASETO v4.local on CipherBird, conformant to the PASETO v4 specification.
///
/// The whole construction runs inside the engine in one call: a fresh nonce
/// from its CSPRNG, the keyed BLAKE2b derivations, XChaCha20, and the tag
/// over the pre-authentication encoding. Tokens are ASCII strings.
extension CipherBirdPaseto on CipherBird {
  /// Seal [message] under a 32-byte [key]. [footer] travels in clear and is
  /// authenticated; [implicit] is authenticated but never stored. Each may
  /// be up to 64 MiB.
  String pasetoV4LocalEncrypt(
    Uint8List key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _tokenSeal(
    'cryptolib_paseto_v4_local_encrypt_len',
    'cryptolib_paseto_v4_local_encrypt',
    'PASETO v4.local',
    key,
    message,
    footer,
    implicit,
  );

  /// Open [token] under [key]. [expectedFooter] must equal the token's footer
  /// exactly (null means the token must carry none) and [implicit] the
  /// assertion used at encryption; the tag is checked in constant time before
  /// anything is decrypted. Throws a [TokenException] with
  /// [TokenStatus.invalid] for every failure that depends on the token.
  Uint8List pasetoV4LocalDecrypt(
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _tokenOpen(
    'cryptolib_paseto_v4_local_decrypt_cap',
    'cryptolib_paseto_v4_local_decrypt',
    'PASETO v4.local',
    token,
    key,
    expectedFooter,
    implicit,
  );
}
