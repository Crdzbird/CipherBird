import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

void main() {
  final lib = CipherBird.instance;
  Uint8List B(String s) => Uint8List.fromList(s.codeUnits);
  test('session ratchet roundtrip + turn + transactional', () {
    final pre = lib.generateSessionPrekey();
    final alice = lib.initiateSession(pre.publicKey);
    final bob = lib.acceptSession(
      alice.handshake(),
      pre.publicKey,
      pre.secretKey,
    );
    expect(
      String.fromCharCodes(bob.decrypt(alice.encrypt(B('hello bob')))),
      'hello bob',
    );
    expect(
      String.fromCharCodes(alice.decrypt(bob.encrypt(B('hi alice')))),
      'hi alice',
    );
    final m2 = alice.encrypt(B('secret'));
    final bad = Uint8List.fromList(m2);
    bad[bad.length - 1] ^= 1;
    expect(() => bob.decrypt(bad), throwsException);
    expect(String.fromCharCodes(bob.decrypt(m2)), 'secret'); // transactional
    alice.close();
    bob.close();
  });
}
