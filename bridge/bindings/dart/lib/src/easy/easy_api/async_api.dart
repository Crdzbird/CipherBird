part of '../../../cryptolib_ffi.dart';

/// Off-thread variants of the slow easy-mode operations (Argon2id).
///
/// Each call runs on `runner`; the default spawns a background isolate so a
/// 64 MiB passphrase stretch never blocks the UI. Pass
/// [CryptoLibInlineRunner] in tests.
extension EasyApiAsync on EasyApi {
  /// [SymmetricKey.fromPassphrase] on a worker.
  Future<SymmetricKey> symmetricKeyFromPassphraseAsync(
    String passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
    CryptoLibRunner runner = const CryptoLibIsolateRunner(),
  }) async {
    if (salt.length < 16) {
      throw ArgumentError.value(
        salt.length,
        'salt',
        'use at least 16 random bytes',
      );
    }
    final key = await runner.run(
      _derivePassphraseInWorker,
      (passphrase, salt, profile.argon2Ops, profile.argon2Memory),
      cost: profile.argon2Memory,
    );
    return SymmetricKey.fromBytes(key, _l);
  }

  /// [hashPassword] on a worker.
  Future<String> hashPasswordAsync(
    String password, {
    SecurityProfile profile = SecurityProfile.balanced,
    CryptoLibRunner runner = const CryptoLibIsolateRunner(),
  }) =>
      runner.run(
        _hashPasswordInWorker,
        (password, profile.argon2Ops, profile.argon2Memory),
        cost: profile.argon2Memory,
      );

  /// [verifyPassword] on a worker.
  Future<bool> verifyPasswordAsync(
    String password,
    String phcHash, {
    CryptoLibRunner runner = const CryptoLibIsolateRunner(),
  }) =>
      runner.run(_verifyPasswordInWorker, (password, phcHash), cost: 1 << 30);
}
