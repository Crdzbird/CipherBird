@Timeout(Duration(minutes: 10))
library;

import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

double opsPerSecond(void Function() op) {
  op();
  final sw = Stopwatch()..start();
  var runs = 0;
  while (sw.elapsedMilliseconds < 1500) {
    op();
    runs++;
  }
  return runs / (sw.elapsedMicroseconds / 1e6);
}

void main() {
  test('small input latency through the Dart layer', () async {
    await CipherBird.preload();
    final lib = CipherBird.instance;
    final msg = Uint8List.fromList(List<int>.filled(32, 0x5a));
    final key = lib.randomBytes(32);
    final ed = lib.ed25519Keygen();
    final rows = <String, double>{
      'sha256 32 B': opsPerSecond(() => lib.sha256(msg)),
      'blake3 32 B': opsPerSecond(() => lib.blake3(msg)),
      'xchacha20 encrypt 32 B': opsPerSecond(() => lib.xchacha20Encrypt(msg, key)),
      'hmac-sha256 32 B': opsPerSecond(() => lib.hmacSha256(msg, key)),
      'ed25519 sign 32 B': opsPerSecond(() => lib.ed25519Sign(msg, ed.secretKey)),
      'randomBytes 32': opsPerSecond(() => lib.randomBytes(32)),
    };
    for (final e in rows.entries) {
      print('SMALL ${e.key} | ${(1e6 / e.value).toStringAsFixed(2)} us');
    }
  });
}
