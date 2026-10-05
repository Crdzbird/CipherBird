part of '../../cipher_bird.dart';

/// Off-thread variants of the slow easy-mode operations (Argon2id).
///
/// Each call runs its job on `runner`: the default moves it to a background
/// isolate natively and to a web worker in the browser, so a 64 MiB
/// passphrase stretch never blocks the UI. Pass [CipherBirdInlineRunner] in
/// tests.
extension EasyApiAsync on EasyApi {
  /// [SymmetricKey.fromPassphrase] on a worker.
  Future<SymmetricKey> symmetricKeyFromPassphraseAsync(
    String passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) async {
    if (salt.length < 16) {
      throw ArgumentError.value(
        salt.length,
        'salt',
        'use at least 16 random bytes',
      );
    }
    final key = await runner.run(
      Argon2DeriveJob(
        passphrase,
        salt,
        ops: profile.argon2Ops,
        memory: profile.argon2Memory,
      ),
    );
    return SymmetricKey.fromBytes(key, _l);
  }

  /// [hashPassword] on a worker.
  Future<String> hashPasswordAsync(
    String password, {
    SecurityProfile profile = SecurityProfile.balanced,
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(Argon2HashJob(password, profile: profile));

  /// [verifyPassword] on a worker.
  Future<bool> verifyPasswordAsync(
    String password,
    String phcHash, {
    CipherBirdRunner runner = const CipherBirdIsolateRunner(),
  }) => runner.run(Argon2VerifyJob(password, phcHash));
}
