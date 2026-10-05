import 'package:cipherbird/cipherbird.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await CryptoLib.preload();
  runApp(const ExampleApp());
}

final class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  List<(String, bool)> _checks() {
    final lib = CryptoLib.instance;
    final key = SymmetricKey.generate();
    final signer = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
    final me = KemKeyPair.generate();
    final alice = lib.easy.identity();
    final bob = lib.easy.identity();
    final envelope = bob.sealText('meet at dawn', to: alice.recipientPublic);
    return [
      ('CryptoLib ${lib.version()} loaded', lib.version().isNotEmpty),
      (
        'SHA-256 known answer',
        lib.easy.sha256Hex('abc') ==
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      ),
      (
        'SymmetricKey text round-trip',
        key.decryptText(key.encryptText('hi')) == 'hi',
      ),
      (
        'Hybrid signature verifies',
        signer.verifyKey.verifyText('release', signer.signText('release')),
      ),
      (
        'Hybrid KEM public-key encryption',
        me.decryptText(KemKeyPair.encryptTextFor(me.publicKey, 'secret')) ==
            'secret',
      ),
      (
        'Flagship sealed messaging',
        alice.openText(envelope, from: bob.senderPublic) == 'meet at dawn',
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    final results = _checks();
    final allOk = results.every((r) => r.$2);
    debugPrint('CRYPTOLIB_SELFTEST: ${allOk ? 'OK' : 'FAILED'}');
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('cipherbird')),
        body: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Text(
              allOk ? 'CryptoLib loaded' : 'CryptoLib failed',
              style: TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.bold,
                color: allOk ? Colors.green : Colors.red,
              ),
            ),
            const SizedBox(height: 16),
            for (final (label, ok) in results)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: Text('${ok ? 'pass' : 'fail'}  $label'),
              ),
          ],
        ),
      ),
    );
  }
}
