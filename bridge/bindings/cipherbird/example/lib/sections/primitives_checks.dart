import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// Hashing, symmetric and classical public-key operations through the
/// easy API, plus a keyring round trip.
final class PrimitivesChecks {
  const PrimitivesChecks._();

  static List<Check> build(CipherBird lib) => [
    Check('SHA-256 known answer', () async {
      final h = lib.easy.sha256Hex('abc');
      demand(h.startsWith('ba7816bf'), 'unexpected digest $h');
      return h;
    }),
    Check('SymmetricKey text round trip', () async {
      final key = SymmetricKey.generate();
      demand(key.decryptText(key.encryptText('hi')) == 'hi', 'mismatch');
      return 'XChaCha20-Poly1305 under a fresh 32-byte key';
    }),
    Check('Hybrid signature (Ed25519 + ML-DSA-65)', () async {
      final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
      final sig = signer.signText('release');
      demand(signer.verifyKey.verifyText('release', sig), 'does not verify');
      return '${sig.length}-byte signature verifies';
    }),
    Check('Hybrid KEM public-key encryption', () async {
      final me = KemKeyPair.generate();
      final ct = KemKeyPair.encryptTextFor(me.publicKey, 'secret');
      demand(me.decryptText(ct) == 'secret', 'mismatch');
      return 'X25519 + ML-KEM-768 to my own public key';
    }),
    Check('Flagship sealed messaging', () async {
      final alice = lib.easy.identity();
      final bob = lib.easy.identity();
      final env = bob.sealText('meet at dawn', to: alice.recipientPublic);
      demand(
        alice.openText(env, from: bob.senderPublic) == 'meet at dawn',
        'mismatch',
      );
      return 'Bob to Alice, sender authenticated';
    }),
    Check('Keyring with a passphrase slot', () async {
      final kr = lib.keyringCreate();
      demand(
        lib.keyringAddPassphraseSlot(kr, 'pw', KdfPreset.interactive),
        'slot',
      );
      final blob = lib.keyringSerialise(kr);
      lib.keyringFree(kr);
      final again = lib.keyringDeserialise(blob);
      final master = lib.keyringUnlockWithPassphrase(again, 'pw');
      lib.keyringFree(again);
      return '${blob.length}-byte envelope unlocks a ${master.length}-byte master';
    }),
  ];
}
