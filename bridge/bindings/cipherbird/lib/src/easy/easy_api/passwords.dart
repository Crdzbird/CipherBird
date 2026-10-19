part of '../../cipher_bird.dart';

/// Easy-mode password entry points that take the password as UTF-8 bytes,
/// so the caller can wipe it once used.
extension EasyApiPasswords on EasyApi {
  /// A [SymmetricKey] stretched from a passphrase given as bytes.
  SymmetricKey symmetricKeyFromPassphraseBytes(
    Uint8List passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
  }) => SymmetricKey.fromPassphraseBytes(
    passphrase,
    salt: salt,
    profile: profile,
    lib: _l,
  );

  /// [EasyApi.hashPassword] with the password as bytes.
  String hashPasswordBytes(
    Uint8List password, {
    SecurityProfile profile = SecurityProfile.balanced,
  }) {
    final raw = _l.argon2idHashStrBytes(
      password,
      ops: profile.argon2Ops,
      mem: profile.argon2Memory,
    );
    final end = raw.indexOf(0);
    return utf8.decode(end < 0 ? raw : Uint8List.sublistView(raw, 0, end));
  }

  /// True if [password] matches a PHC string from [EasyApi.hashPassword].
  bool verifyPasswordBytes(Uint8List password, String phcHash) =>
      _l.argon2idVerifyStrBytes(password, phcHash);
}
