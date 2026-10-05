part of '../../../cipher_bird.dart';

/// Argon2id password hashing to a PHC string as a [CipherBirdJob].
final class Argon2HashJob extends CipherBirdJob<String> {
  /// Hashes [password] with the given [profile].
  const Argon2HashJob(this.password, {required this.profile});

  final String password;
  final SecurityProfile profile;

  @override
  int get cost => profile.argon2Memory;

  @override
  String get op => 'argon2id_hash_str';

  @override
  Map<String, Object?> get arguments => {
    'password': password,
    'ops': profile.argon2Ops,
    'mem': profile.argon2Memory,
  };

  @override
  String execute() =>
      CipherBird.instance.easy.hashPassword(password, profile: profile);

  @override
  String decode(Object? reply) => reply! as String;
}
