// Verifies the preload + lazy-synchronous-singleton contract.
//
// Run on the host (loads the desktop dylib via the CRYPTOLIB_DYLIB override):
//   CRYPTOLIB_DYLIB=/path/to/libcryptolib_c.dylib flutter test
import 'dart:typed_data';

import 'package:cryptolib_flutter/cryptolib_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test('synchronous API works with NO preload (lazy self-init)', () {
    // First touch of `instance` must open + init the lib synchronously.
    final v = CryptoLib.instance.version();
    expect(v, '3.0.0');
    // A real crypto call, still synchronous — no await anywhere.
    final h = CryptoLib.instance.sha256(Uint8List.fromList('abc'.codeUnits));
    expect(
      _hex(h),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  test('preload() warms in a background isolate and returns true', () async {
    final ok = await CryptoLib.preload();
    expect(ok, isTrue);
  });

  test('synchronous API works (and is consistent) AFTER preload', () async {
    await CryptoLib.preload();
    // No await on the crypto calls themselves.
    final lib = CryptoLib.instance;
    expect(lib.version(), '3.0.0');
    final a = lib.sha256(Uint8List.fromList('preload'.codeUnits));
    final b = lib.sha256(Uint8List.fromList('preload'.codeUnits));
    expect(_hex(a), _hex(b));
    expect(a.length, 32);
  });

  test('preload is idempotent — repeated calls all succeed', () async {
    expect(await CryptoLib.preload(), isTrue);
    expect(await CryptoLib.preload(), isTrue);
    // And the singleton is still usable synchronously.
    expect(CryptoLib.instance.randomBytes(16).length, 16);
  });
}
