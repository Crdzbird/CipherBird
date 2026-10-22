import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  const isWeb = bool.fromEnvironment('dart.library.js_interop');

  group('LiveEntropy', () {
    test(
      'fails closed, credits noise, rejects a blank chunk with a reason',
      () {
        final live = lib.liveEntropy();
        try {
          expect(
            () => live.generate(32),
            throwsA(predicate((e) => '$e'.contains('not ready'))),
          );
          final blank = live.feed(Uint8List(4096));
          expect(blank.accepted, isFalse);
          expect(blank.rctCutoff, 31);
          expect(blank.reason, contains('mixed in but not credited'));
          final good = live.feed(lib.randomBytes(8192), sourceId: 1);
          expect(good.accepted, isTrue);
          expect(good.ready, isTrue);
          expect(good.creditedBits, greaterThan(256));
          final a = live.generate(32);
          final b = live.generate(32);
          expect(a, isNot(equals(b)));
          final s = live.status();
          expect(s.chunksFed, 2);
          expect(s.chunksAccepted, 1);
          expect(s.reseeds, 1);
          expect(s.lastReason, isEmpty);
        } finally {
          live.close();
          live.close();
        }
      },
    );

    test('the facade and a permissive policy', () {
      final live = lib.rng.live(
        minBitsPerByte: 0,
        requireRct: false,
        minCreditedBits: 64,
      );
      try {
        final blank = live.feed(Uint8List(4096));
        expect(blank.accepted, isTrue);
        expect(blank.creditedBits, 0);
        expect(blank.ready, isFalse);
        expect(live.feed(lib.randomBytes(2048)).ready, isTrue);
        expect(live.generate(16).length, 16);
      } finally {
        live.close();
      }
    });
  });

  group('HealthReport v2', () {
    test('carries the cutoffs and a summary', () {
      if (isWeb) {
        return;
      }
      final dir = Directory.systemTemp.createTempSync('cl_health_');
      final path = '${dir.path}/noise.bin';
      File(path).writeAsBytesSync(lib.randomBytes(65536));
      final h = lib.assessFileHealth(path);
      expect(h.rctCutoff, 31);
      expect(h.sampleBytes, 65536);
      expect(h.floorBitsPerByte, 1.0);
      expect(h.summary, contains('cutoff 31'));
      final strict = lib.assessFileHealth(path, floorBitsPerByte: 7.9);
      expect(strict.rctCutoff, 5);
      dir.deleteSync(recursive: true);
    });
  });
}
