part of '../../cipher_bird.dart';

/// cb1.local on CipherBird: PASETO v4.local with BLAKE3 in place of BLAKE2b.
///
/// The key material is derived with keyed BLAKE3 over `cb1-encryption-key`
/// and `cb1-auth-key` with the nonce, the message is encrypted with
/// XChaCha20 and the tag is a keyed BLAKE3 over PAE("cb1.local.", n, c, f,
/// i). A PASETO parser rejects the token by its header, and these methods
/// reject PASETO tokens the same way. Library-native: present in the full
/// profile, [TokenStatus.unavailable] in the bank profile.
extension CipherBirdCb1Local on CipherBird {
  /// Seal [message] under a 32-byte [key]; see [pasetoV4LocalEncrypt] for
  /// the footer and implicit assertion.
  String cb1LocalEncrypt(
    Uint8List key,
    Uint8List message, {
    Uint8List? footer,
    Uint8List? implicit,
  }) => _tokenSeal(
    'cryptolib_cb1_local_encrypt_len',
    'cryptolib_cb1_local_encrypt',
    'cb1.local',
    key,
    message,
    footer,
    implicit,
  );

  /// Open [token] under [key]; the contract of [pasetoV4LocalDecrypt].
  Uint8List cb1LocalDecrypt(
    String token,
    Uint8List key, {
    Uint8List? expectedFooter,
    Uint8List? implicit,
  }) => _tokenOpen(
    'cryptolib_cb1_local_decrypt_cap',
    'cryptolib_cb1_local_decrypt',
    'cb1.local',
    token,
    key,
    expectedFooter,
    implicit,
  );
}
