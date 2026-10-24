@TestOn('browser')
library;

import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

/// The page holds no engine: every call goes to the worker.
Future<void> main() async {
  await CipherBird.preload(workerOnly: true);
  final lib = CipherBird.instance;
  final msg = Uint8List.fromList('only the worker sees the engine'.codeUnits);

  test('synchronous calls refuse and say why', () {
    expect(
      () => lib.sha256(msg),
      throwsA(predicate((e) => '$e'.contains('worker only'))),
    );
  });

  test('asynchronous calls run on the worker', () async {
    final key = await lib.keyFromBytesAsync(
      Uint8List.fromList(List.generate(4096, (i) => (i * 7) & 0xFF)),
    );
    expect(key, hasLength(32));
    final ml = await lib.mlDsaKeygenAsync(MlDsaLevel.level65);
    final sig = await lib.mlDsaSignAsync(msg, ml.secretKey, MlDsaLevel.level65);
    expect(sig, isNotEmpty);
    final cover = Uint8List.fromList(
      [
        'P6\n128 128\n255\n'.codeUnits,
        List.generate(128 * 128 * 3, (i) => (i * 31 + i ~/ 7) & 0xFF),
      ].expand((b) => b).toList(),
    );
    final hidden = await lib.stegoEmbedEncryptedBytesAsync(
      cover,
      MediaFormat.ppmImage,
      msg,
      key,
    );
    expect(
      await lib.stegoExtractDecryptBytesAsync(
        hidden,
        MediaFormat.ppmImage,
        key,
      ),
      msg,
    );
  });

  test('the approval boundary follows the mode', () {
    expect(lib.approvedFor(ProtectedDataClass.ephemeral), isTrue);
    expect(lib.approvedFor(ProtectedDataClass.longLivedKeys), isTrue);
    expect(lib.approvedFor(ProtectedDataClass.cardData), isFalse);
    expect(
      () => lib.requireApprovedFor(ProtectedDataClass.cardData),
      throwsUnsupportedError,
    );
  });
}
