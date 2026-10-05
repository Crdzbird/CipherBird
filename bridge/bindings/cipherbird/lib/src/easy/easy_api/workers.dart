part of '../../cryptolib.dart';

Uint8List _derivePassphraseInWorker((String, Uint8List, int, int) m) {
  final (passphrase, salt, ops, mem) = m;
  return CryptoLib.instance.argon2idDerive(
    passphrase,
    salt,
    ops: ops,
    mem: mem,
  );
}

String _hashPasswordInWorker((String, int, int) m) {
  final (password, ops, mem) = m;
  return CryptoLib.instance.easy.hashPassword(
    password,
    profile: _profileFor(ops, mem),
  );
}

bool _verifyPasswordInWorker((String, String) m) =>
    CryptoLib.instance.easy.verifyPassword(m.$1, m.$2);

SecurityProfile _profileFor(int ops, int mem) =>
    SecurityProfile.values.firstWhere(
      (p) => p.argon2Ops == ops && p.argon2Memory == mem,
      orElse: () => SecurityProfile.balanced,
    );
