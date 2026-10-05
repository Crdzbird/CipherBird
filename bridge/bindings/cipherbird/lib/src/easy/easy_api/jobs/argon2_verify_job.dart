part of '../../../cipher_bird.dart';

/// Argon2id PHC verification as a [CipherBirdJob].
final class Argon2VerifyJob extends CipherBirdJob<bool> {
  /// Checks [password] against [phcHash].
  const Argon2VerifyJob(this.password, this.phcHash);

  final String password;
  final String phcHash;

  @override
  int get cost => 1 << 30;

  @override
  String get op => 'argon2id_verify_str';

  @override
  Map<String, Object?> get arguments => {
    'password': password,
    'phc': phcHash,
  };

  @override
  bool execute() => CipherBird.instance.easy.verifyPassword(password, phcHash);

  @override
  bool decode(Object? reply) => reply! as bool;
}
