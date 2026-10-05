import 'dart:io';

import 'package:cipherbird_dart/cipherbird_dart.dart';

void main() {
  final key = SymmetricKey.generate();
  final box = key.encryptText('meet at dawn');
  stdout.writeln('ciphertext: $box');
  stdout.writeln('decrypted: ${key.decryptText(box)}');

  final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
  final signature = signer.signText('release 1.0.0');
  stdout.writeln(
    'hybrid signature valid: ${signer.verifyKey.verifyText('release 1.0.0', signature)}',
  );

  final me = KemKeyPair.generate();
  final blob = KemKeyPair.encryptTextFor(me.publicKey, 'for your eyes only');
  stdout.writeln('opened with my secret key: ${me.decryptText(blob)}');

  final lib = CipherBird.instance;
  final phc = lib.easy.hashPassword('hunter2');
  stdout.writeln(
    'password verified: ${lib.easy.verifyPassword('hunter2', phc)}',
  );
  stdout.writeln('sha256("abc"): ${lib.easy.sha256Hex('abc')}');

  final recipe = lib.maximumSecurity().withKey(key.bytes);
  final envelope = recipe.seal('treaty'.bytes);
  stdout.writeln('recipe round-trip: ${recipe.open(envelope).text}');
  stdout.write(recipe.describe());
}
