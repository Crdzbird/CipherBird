import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// X-Wing and HPKE with every KEM the bank profile offers.
final class PostQuantumChecks {
  const PostQuantumChecks._();

  static List<Check> build(CipherBird lib) => [
    Check('X-Wing key pair and encapsulation', () async {
      final bob = lib.xwingKeygen();
      final (ct, ss) = lib.xwingEncapsulate(bob.publicKey);
      demand(
        same(lib.xwingDecapsulate(ct, bob.secretKey), ss),
        'secret mismatch',
      );
      return 'pk ${bob.publicKey.length} B, seed ${bob.secretKey.length} B, ct ${ct.length} B';
    }),
    Check('X-Wing seed regenerates the key pair', () async {
      final bob = lib.xwingKeygen();
      final again = lib.xwingKeypairFromSeed(bob.secretKey);
      demand(same(again.publicKey, bob.publicKey), 'public key differs');
      return 'deterministic expansion from 32 bytes';
    }),
    for (final kem in HpkeKem.values)
      Check('HPKE base mode with ${kem.name}', () async {
        demand(lib.hpkeKemAvailable(kem), 'KEM unavailable');
        final kp = lib.hpkeKeygenKem(kem);
        final s = lib.hpkeSetupSKem(
          kem,
          HpkeKdf.sha256,
          HpkeAead.aes256Gcm,
          HpkeMode.base,
          kp.publicKey,
          ascii('statement'),
        );
        final ct = s.context.seal(ascii('balance: 42'), aad: ascii('ctx'));
        final r = lib.hpkeSetupRKem(
          kem,
          HpkeKdf.sha256,
          HpkeAead.aes256Gcm,
          HpkeMode.base,
          s.enc,
          kp.secretKey,
          ascii('statement'),
        );
        final pt = r.open(ct, aad: ascii('ctx'));
        s.context.close();
        r.close();
        demand(same(pt, ascii('balance: 42')), 'mismatch');
        return 'enc ${s.enc.length} B, KEM id 0x${kem.value.toRadixString(16)}';
      }),
    Check('ML-DSA-65 standalone signature', () async {
      final kp = lib.mlDsaKeygen(MlDsaLevel.level65);
      final sig = lib.mlDsaSign(ascii('msg'), kp.secretKey, MlDsaLevel.level65);
      demand(
        lib.mlDsaVerify(ascii('msg'), sig, kp.publicKey, MlDsaLevel.level65),
        'verify',
      );
      return '${sig.length}-byte signature verifies';
    }),
  ];
}
