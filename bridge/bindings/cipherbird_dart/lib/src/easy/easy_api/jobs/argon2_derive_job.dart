part of '../../../cipher_bird.dart';

/// Argon2id key derivation as a [CipherBirdJob].
final class Argon2DeriveJob extends CipherBirdJob<Uint8List> {
  /// Derives [keyLength] bytes from [passphrase] and [salt].
  const Argon2DeriveJob(
    this.passphrase,
    this.salt, {
    required this.ops,
    required this.memory,
    this.keyLength = 32,
  });

  final String passphrase;
  final Uint8List salt;
  final int ops;
  final int memory;
  final int keyLength;

  @override
  int get cost => memory;

  @override
  String get op => 'argon2id_derive';

  @override
  Map<String, Object?> get arguments => {
    'password': passphrase,
    'salt': salt,
    'keyLen': keyLength,
    'ops': ops,
    'mem': memory,
  };

  @override
  Uint8List execute() => CipherBird.instance.argon2idDerive(
    passphrase,
    salt,
    keyLen: keyLength,
    ops: ops,
    mem: memory,
  );

  @override
  Uint8List decode(Object? reply) => Uint8List.fromList(
    (reply! as List<Object?>).cast<int>(),
  );
}
