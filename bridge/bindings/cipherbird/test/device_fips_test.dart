import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird/src/hardware/fips/native_fips_backend.dart';
import 'package:flutter_test/flutter_test.dart';

import 'support/recording_fips_backend.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  test(
    'DeviceFips forwards every call to its backend with the defaults',
    () async {
      final b = RecordingFipsBackend();
      final fips = DeviceFips.platform(backend: b);
      expect((await fips.module()).module, 'fake');
      await fips.digest(FipsHash.sha384, Uint8List(3));
      await fips.hmac(FipsHash.sha256, Uint8List(32), Uint8List(1));
      await fips.hkdf(FipsHash.sha256, Uint8List(22), count: 42);
      await fips.pbkdf2(FipsHash.sha256, Uint8List(8), Uint8List(16));
      expect(b.calls, [
        'digest:sha384:3',
        'hmac:32',
        'hkdf:42:null:null',
        'pbkdf2:600000:32',
      ]);
      expect(
        (await fips.aesGcmEncrypt(Uint8List(32), Uint8List(5))).length,
        33,
      );
      expect((await fips.p256Keygen()).publicKey.length, 65);
    },
  );

  test('an unsupported platform throws a stable code', () async {
    final fips = DeviceFips.platform(
      backend: const UnsupportedFipsBackend('x'),
    );
    await expectLater(
      fips.random(8),
      throwsA(
        isA<FipsException>().having((e) => e.code, 'code', 'unsupported'),
      ),
    );
  });

  test('the engine backend needs the fips profile', () {
    expect(CipherBird.instance.fipsAvailable, isFalse);
    expect(
      () => NativeFipsBackend(CipherBird.instance),
      throwsA(isA<FipsException>()),
    );
  });
}
