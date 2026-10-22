import 'dart:typed_data';
import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  Uint8List bytes(String s) => Uint8List.fromList(s.codeUnits);

  test('suite v2 binds the recipient and the aad', () {
    final bob = lib.xwingKeygen();
    final carol = lib.xwingKeygen();
    final alice = lib.hybridSigKeygen();
    final env = lib.suite2Seal(
      bytes('wire 100 EUR'),
      bob.publicKey,
      alice.secretKey,
      aad: bytes('ctx'),
    );
    expect(lib.suite2SuiteOf(env), Suite2Id.xWingSig.value);
    final pt = lib.suite2Open(
      env,
      bob.secretKey,
      bob.publicKey,
      alice.publicKey,
      aad: bytes('ctx'),
    );
    expect(String.fromCharCodes(pt), 'wire 100 EUR');
    expect(
      () => lib.suite2Open(
        env,
        bob.secretKey,
        carol.publicKey,
        alice.publicKey,
        aad: bytes('ctx'),
      ),
      throwsException,
    );
    expect(
      () => lib.suite2Open(env, bob.secretKey, bob.publicKey, alice.publicKey),
      throwsException,
    );
  });

  test('session v2 authenticates both ends', () {
    final alice = lib.hybridSigKeygen();
    final bob = lib.hybridSigKeygen();
    final mallory = lib.hybridSigKeygen();
    final prekey = lib.generateSession2Prekey(bob.secretKey);
    expect(
      lib.verifySession2Prekey(prekey.publicKey, bob.publicKey).length,
      1216,
    );
    expect(
      () => lib.verifySession2Prekey(prekey.publicKey, mallory.publicKey),
      throwsException,
    );
    final a = lib.initiateSession2(
      prekey.publicKey,
      bob.publicKey,
      alice.publicKey,
      alice.secretKey,
    );
    final hs = a.handshake();
    expect(lib.claimedSession2Initiator(hs), alice.publicKey);
    expect(
      () => lib.acceptSession2(
        hs,
        prekey.publicKey,
        prekey.secretKey,
        bob.publicKey,
        bob.secretKey,
        mallory.publicKey,
      ),
      throwsException,
    );
    final b = lib.acceptSession2(
      hs,
      prekey.publicKey,
      prekey.secretKey,
      bob.publicKey,
      bob.secretKey,
      alice.publicKey,
    );
    expect(String.fromCharCodes(b.decrypt(a.encrypt(bytes('hello')))), 'hello');
    expect(String.fromCharCodes(a.decrypt(b.encrypt(bytes('reply')))), 'reply');
    a.close();
    b.close();
  });

  test('fips layer is absent outside the fips profile', () {
    expect(lib.fipsAvailable, isFalse);
    expect(lib.fipsStatus().loaded, isFalse);
    expect(
      () => lib.fipsDigest(FipsHash.sha256, bytes('abc')),
      throwsException,
    );
    expect(lib.fipsEnvelopeCreate, throwsException);
  });
}
