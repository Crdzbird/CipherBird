// MolecularVault plugin API — verified against the host dylib.
// Run: CIPHERBIRD_LIBRARY=/abs/build/release/libcipherbird.dylib flutter test test/molecular_test.dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final lib = CipherBird.instance;
  final aad = Uint8List.fromList(utf8.encode('ctx:v1'));
  Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));

  test('passphrase seal -> open round-trips', () {
    final pt = bytes('molecular secret 🔐');
    final env = lib.molecularSeal(
      pt,
      'correct horse',
      aad: aad,
      ops: 2,
      mem: 1 << 20,
    );
    final back = lib.molecularOpen(env, 'correct horse', aad: aad);
    expect(utf8.decode(back), utf8.decode(pt));
    expect(env.length, greaterThan(30)); // header + cascade overhead
  });

  test('wrong passphrase / wrong AAD / tamper all fail closed', () {
    final env = lib.molecularSeal(
      bytes('x'),
      'pw',
      aad: aad,
      ops: 2,
      mem: 1 << 20,
    );
    expect(() => lib.molecularOpen(env, 'nope', aad: aad), throwsA(anything));
    expect(
      () => lib.molecularOpen(env, 'pw', aad: bytes('other')),
      throwsA(anything),
    );
    final bad = Uint8List.fromList(env)..[env.length - 1] ^= 1;
    expect(() => lib.molecularOpen(bad, 'pw', aad: aad), throwsA(anything));
  });

  test('random salt -> distinct ciphertext for identical inputs', () {
    final a = lib.molecularSeal(bytes('same'), 'pw', ops: 2, mem: 1 << 20);
    final b = lib.molecularSeal(bytes('same'), 'pw', ops: 2, mem: 1 << 20);
    expect(a, isNot(equals(b)));
  });

  test('raw-key mode composes with the hybrid PQC KEM', () {
    final kp = lib.hybridKemKeygen();
    final (ct, ss) = lib.hybridKemEncapsulate(kp.publicKey);
    final env = lib.molecularSealWithKey(bytes('pq secret'), ss, aad: aad);
    final recovered = lib.hybridKemDecapsulate(ct, kp.secretKey);
    final out = lib.molecularOpenWithKey(env, recovered, aad: aad);
    expect(utf8.decode(out), 'pq secret');
  });
}
