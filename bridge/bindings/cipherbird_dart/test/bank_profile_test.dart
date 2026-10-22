import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  Uint8List bytes(String s) => Uint8List.fromList(s.codeUnits);

  test('x-wing round trip and seed expansion', () {
    final bob = lib.xwingKeygen();
    expect(bob.publicKey.length, 1216);
    expect(bob.secretKey.length, 32);
    final (ct, ss) = lib.xwingEncapsulate(bob.publicKey);
    expect(ct.length, 1120);
    expect(lib.xwingDecapsulate(ct, bob.secretKey), ss);
    expect(lib.xwingKeypairFromSeed(bob.secretKey).publicKey, bob.publicKey);
  });

  test('hpke with ml-kem-768 and x-wing', () {
    for (final kem in [HpkeKem.mlKem768, HpkeKem.xWing]) {
      expect(lib.hpkeKemAvailable(kem), isTrue);
      final kp = lib.hpkeKeygenKem(kem);
      final s = lib.hpkeSetupSKem(
        kem,
        HpkeKdf.sha256,
        HpkeAead.aes256Gcm,
        HpkeMode.base,
        kp.publicKey,
        bytes('info'),
      );
      final ct = s.context.seal(bytes('payload'), aad: bytes('aad'));
      final r = lib.hpkeSetupRKem(
        kem,
        HpkeKdf.sha256,
        HpkeAead.aes256Gcm,
        HpkeMode.base,
        s.enc,
        kp.secretKey,
        bytes('info'),
      );
      expect(String.fromCharCodes(r.open(ct, aad: bytes('aad'))), 'payload');
      s.context.close();
      r.close();
    }
    expect(SecurityProfile.balanced.hpkeKem, HpkeKem.xWing);
  });
}
