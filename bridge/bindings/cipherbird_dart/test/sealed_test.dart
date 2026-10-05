import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

void main() {
  final lib = CipherBird.instance;
  Uint8List B(String s) => Uint8List.fromList(s.codeUnits);
  for (final tier in [SealedTier.flagship, SealedTier.fortress]) {
    test('sealed roundtrip + streaming ${tier.name}', () {
      final alice = lib.newIdentity(tier), bob = lib.newIdentity(tier);
      final aad = B('ctx'), purpose = B('note');
      final env = bob.seal(
        B('meet at dawn'),
        alice.recipientPublic,
        aad: aad,
        purpose: purpose,
      );
      expect(
        String.fromCharCodes(
          alice.open(env, bob.senderPublic, aad: aad, purpose: purpose),
        ),
        'meet at dawn',
      );
      final mal = lib.newIdentity(tier);
      expect(
        () => alice.open(env, mal.senderPublic, aad: aad, purpose: purpose),
        throwsException,
      );
      final info = lib.sealedInspect(env)!;
      expect(info.suite, tier);
      expect(lib.sealedAddressedTo(env, alice.recipientPublic), true);
      expect(lib.sealedAddressedTo(env, mal.recipientPublic), false);
      final se = bob.newStreamSealer(alice.recipientPublic, purpose: purpose);
      final pre = se.preamble();
      final c0 = se.push(B('hello '));
      final (cf, trailer) = se.finalize(B('world'));
      se.close();
      final op = alice.newStreamOpener(pre, bob.senderPublic, purpose: purpose);
      final (p0, fin0) = op.pull(c0);
      final (p1, fin1) = op.pull(cf);
      op.finalize(trailer);
      op.close();
      expect(
        String.fromCharCodes(p0) + String.fromCharCodes(p1),
        'hello world',
      );
      expect(fin0, false);
      expect(fin1, true);
    });
  }
}
