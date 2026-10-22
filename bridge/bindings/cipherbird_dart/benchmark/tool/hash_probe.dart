import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

/// Times the three digests on 1 MiB for one second each and prints MB/s,
/// for comparing two engine builds: run once with CIPHERBIRD_LIBRARY set
/// and once without.
Future<void> main() async {
  await CipherBird.preload();
  final lib = CipherBird.instance;
  final mib = Uint8List(1 << 20);
  for (var i = 0; i < mib.length; i++) {
    mib[i] = i & 0xff;
  }
  final ops = <String, void Function()>{
    'SHA-256': () => lib.sha256(mib),
    'BLAKE2b': () => lib.blake2b(mib),
    'BLAKE3': () => lib.blake3(mib),
    'XChaCha20': () => lib.xchacha20Encrypt(mib, Uint8List(32)),
    'AES-GCM': () => lib.aes256gcmEncrypt(mib, Uint8List(32)),
  };
  for (final entry in ops.entries) {
    entry.value();
    final sw = Stopwatch()..start();
    var n = 0;
    while (sw.elapsedMilliseconds < 1000) {
      entry.value();
      n++;
    }
    stdout.writeln(
      '${entry.key}: ${(n / (sw.elapsedMicroseconds / 1e6)).toStringAsFixed(0)} MB/s',
    );
  }
}
