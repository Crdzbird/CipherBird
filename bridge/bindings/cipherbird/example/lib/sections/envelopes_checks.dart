import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

final class EnvelopesChecks {
  const EnvelopesChecks._();

  static List<Check> build(CipherBird lib) => [
    Check('Suite v2 seal and open', () async {
      final bob = lib.xwingKeygen();
      final alice = lib.hybridSigKeygen();
      final env = lib.suite2Seal(
        ascii('wire 100 EUR'),
        bob.publicKey,
        alice.secretKey,
        aad: ascii('ctx'),
      );
      final pt = lib.suite2Open(
        env,
        bob.secretKey,
        bob.publicKey,
        alice.publicKey,
        aad: ascii('ctx'),
      );
      demand(same(pt, ascii('wire 100 EUR')), 'mismatch');
      return 'suite 0x${lib.suite2SuiteOf(env).toRadixString(16)}, ${env.length}-byte envelope';
    }),
    Check('Suite v2 refuses re-addressing', () async {
      final bob = lib.xwingKeygen();
      final carol = lib.xwingKeygen();
      final alice = lib.hybridSigKeygen();
      final env = lib.suite2Seal(
        ascii('for bob'),
        bob.publicKey,
        alice.secretKey,
      );
      try {
        lib.suite2Open(env, bob.secretKey, carol.publicKey, alice.publicKey);
      } on Exception {
        return 'the signature covers the recipient key';
      }
      throw StateError('re-addressed');
    }),
    Check('Session v2 authenticated handshake', () async {
      final alice = lib.hybridSigKeygen();
      final bob = lib.hybridSigKeygen();
      final prekey = lib.generateSession2Prekey(bob.secretKey);
      final a = lib.initiateSession2(
        prekey.publicKey,
        bob.publicKey,
        alice.publicKey,
        alice.secretKey,
      );
      final hs = a.handshake();
      final claimed = lib.claimedSession2Initiator(hs);
      demand(same(claimed, alice.publicKey), 'claimed identity');
      final b = lib.acceptSession2(
        hs,
        prekey.publicKey,
        prekey.secretKey,
        bob.publicKey,
        bob.secretKey,
        claimed,
      );
      final p1 = b.decrypt(a.encrypt(ascii('first')));
      final p2 = a.decrypt(b.encrypt(ascii('reply')));
      a.close();
      b.close();
      demand(same(p1, ascii('first')) && same(p2, ascii('reply')), 'ratchet');
      return '${hs.length}-byte handshake, both directions ratchet';
    }),
    Check('Session v2 rejects an unexpected initiator', () async {
      final mallory = lib.hybridSigKeygen();
      final alice = lib.hybridSigKeygen();
      final bob = lib.hybridSigKeygen();
      final prekey = lib.generateSession2Prekey(bob.secretKey);
      final m = lib.initiateSession2(
        prekey.publicKey,
        bob.publicKey,
        mallory.publicKey,
        mallory.secretKey,
      );
      final hs = m.handshake();
      m.close();
      try {
        lib.acceptSession2(
          hs,
          prekey.publicKey,
          prekey.secretKey,
          bob.publicKey,
          bob.secretKey,
          alice.publicKey,
        );
      } on Exception {
        return 'Bob expected Alice and refused Mallory';
      }
      throw StateError('accepted an unexpected identity');
    }),
  ];
}
