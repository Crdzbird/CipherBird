import 'dart:typed_data';
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter/material.dart';
import 'package:cryptolib_flutter/cryptolib_flutter.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Optional warm-up on a background isolate (fire-and-forget). The UI below
  // uses the synchronous CryptoLib.instance regardless of whether this has
  // finished — no await needed for any crypto call.
  CryptoLib.preload();
  runApp(const MyApp());
}

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // No path, no setup, no await: the lazily-initialized synchronous singleton
  // self-initializes on first use (warm already if preload() ran).
  List<(String, bool)> _run() {
    final lib = CryptoLib.instance;
    final results = <(String, bool)>[];

    results.add(('version == 3.0.0', lib.version() == '3.0.0'));

    final sha = _hex(lib.sha256(Uint8List.fromList('abc'.codeUnits)));
    results.add((
      'SHA-256("abc") KAT',
      sha == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    ));

    final kp = lib.hybridKemKeygen();
    final (ct, ssEnc) = lib.hybridKemEncapsulate(kp.publicKey);
    final ssDec = lib.hybridKemDecapsulate(ct, kp.secretKey);
    results.add((
      'Hybrid X25519+ML-KEM-768 round-trip',
      _eq(ssEnc, ssDec) && ssEnc.length == 32,
    ));

    // Newly added (full-parity) surface:
    final keccak = _hex(lib.keccak256(Uint8List.fromList('abc'.codeUnits)));
    results.add((
      'Keccak-256("abc") KAT (EVM)',
      keccak == '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
    ));

    final ecKp = lib.secp256k1Keygen();
    final digest = lib.keccak256(Uint8List.fromList('tx'.codeUnits));
    final sig = lib.secp256k1Sign(digest, ecKp.secretKey); // 65: r‖s‖v
    final recovered = lib.secp256k1Recover(digest, sig);
    results.add((
      'secp256k1 sign + ecrecover (EVM/BTC)',
      _eq(recovered, ecKp.publicKey) && sig.length == 65,
    ));

    final hsk = lib.hybridSigKeygen();
    final hMsg = Uint8List.fromList('sign me'.codeUnits);
    final hSig = lib.hybridSigSign(hMsg, hsk.secretKey);
    results.add((
      'Hybrid Ed25519+ML-DSA-65 signature',
      lib.hybridSigVerify(hMsg, hSig, hsk.publicKey),
    ));

    return results;
  }

  @override
  Widget build(BuildContext context) {
    late final List<(String, bool)> results;
    String? error;
    try {
      results = _run();
    } catch (e) {
      results = const [];
      error = e.toString();
    }
    final allOk = error == null && results.every((r) => r.$2);

    // Console marker for headless verification (visible via `simctl launch
    // --console` / `flutter run`).
    debugPrint('CRYPTOLIB_SELFTEST: ${allOk ? 'OK' : 'FAILED'}'
        '${error != null ? ' ($error)' : ''}');
    for (final r in results) {
      debugPrint('  ${r.$2 ? '✓' : '✗'} ${r.$1}');
    }

    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('cryptolib_flutter')),
        body: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                allOk ? 'CryptoLib loaded ✓' : 'CryptoLib FAILED',
                style: TextStyle(
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                  color: allOk ? Colors.green : Colors.red,
                ),
              ),
              const SizedBox(height: 16),
              if (error != null)
                Text(error, style: const TextStyle(color: Colors.red))
              else
                ...results.map((r) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Text('${r.$2 ? "✓" : "✗"}  ${r.$1}'),
                    )),
            ],
          ),
        ),
      ),
    );
  }
}
