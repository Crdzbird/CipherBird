import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:cryptolib_flutter/cryptolib_flutter.dart';

void main() => runApp(const MyApp());

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

  // No path, no setup: the plugin bundles the native library and the loader
  // resolves it by platform convention.
  List<(String, bool)> _run() {
    final lib = CryptoLib.load();
    lib.init();
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
