part of '../cipher_bird.dart';

/// A passphrase stretched with Argon2id at the recipe's cost.
final class PassphraseKeySource extends KeySource with _Builtin {
  const PassphraseKeySource(this.passphrase);
  final String passphrase;
  @override
  int get id => 1;
  @override
  String get label => 'passphrase';
  @override
  Uint8List deriveRoot(CipherBird lib, Uint8List salt, int ops, int mem) =>
      lib.argon2idDerive(passphrase, salt, ops: ops, mem: mem);
}
