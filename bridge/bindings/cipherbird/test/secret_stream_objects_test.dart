import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  const isWeb = bool.fromEnvironment('dart.library.js_interop');
  Uint8List counting(int n, int start) =>
      Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));
  Uint8List chunkOf(int index, int size) {
    final out = Uint8List(size);
    for (var j = 0; j < size; j++) {
      out[j] = (index * 31 + j * 7) & 0xff;
    }
    return out;
  }

  final key = counting(32, 0x40);
  final otherKey = counting(32, 0x41);
  Matcher fails(SecretStreamError error) => throwsA(
    isA<SecretStreamException>().having((e) => e.error, 'error', error),
  );

  ({Uint8List header, List<Uint8List> chunks}) write(
    List<Uint8List> plain, {
    Uint8List? under,
  }) {
    final enc = lib.secretStreamEncryptor(under ?? key);
    final out = <Uint8List>[];
    for (var i = 0; i < plain.length - 1; i++) {
      out.add(enc.push(plain[i]));
    }
    out.add(enc.finish(plain.last));
    final header = enc.header;
    enc.close();
    return (header: header, chunks: out);
  }

  final plain = [for (var i = 0; i < 6; i++) chunkOf(i, 100 + i)];

  group('incremental SecretStream', () {
    test('round trip, sizes, tags and the final chunk', () {
      final enc = lib.secretStreamEncryptor(key);
      expect(enc.header.length, CipherBirdSecretStreamObjects.headerBytes);
      expect(enc.isFinished, isFalse);
      final c0 = enc.push(plain[0]);
      final c1 = enc.push(plain[1], tag: SecretStreamTag.push);
      final c2 = enc.push(plain[2], tag: SecretStreamTag.rekey);
      final c3 = enc.push(Uint8List(0));
      final c4 = enc.finish(plain[4]);
      expect(c0.length, plain[0].length + 17);
      expect(c3.length, CipherBirdSecretStreamObjects.chunkOverhead);
      expect(enc.isFinished, isTrue);
      final dec = lib.secretStreamDecryptor(key, enc.header);
      final r0 = dec.pull(c0);
      expect(r0.plaintext, plain[0]);
      expect(r0.tag, SecretStreamTag.message);
      expect(r0.isFinal, isFalse);
      expect(dec.pull(c1).tag, SecretStreamTag.push);
      final r2 = dec.pull(c2);
      expect(r2.plaintext, plain[2]);
      expect(r2.tag, SecretStreamTag.rekey);
      expect(dec.pull(c3).plaintext, isEmpty);
      expect(dec.isFinished, isFalse);
      final r4 = dec.pull(c4);
      expect(r4.plaintext, plain[4]);
      expect(r4.isFinal, isTrue);
      expect(dec.isFinished, isTrue);
      enc.close();
      dec.close();
      final bare = lib.secretStreamEncryptor(key);
      final only = bare.finish();
      final reader = lib.secretStreamDecryptor(key, bare.header);
      expect(reader.pull(only).isFinal, isTrue);
      expect(lib.aead.streamEncryptor(key).header.length, 24);
    });

    test('two streams under one key differ, header and chunks', () {
      final a = write(plain);
      final b = write(plain);
      expect(a.header, isNot(b.header));
      expect(a.chunks.first, isNot(b.chunks.first));
    });

    test('byte compatible with the whole-list calls, both ways', () {
      final (header, chunks) = lib.streamEncrypt(key, plain);
      expect(lib.streamDecrypt(key, header, chunks), plain);
      final dec = lib.secretStreamDecryptor(key, header);
      for (var i = 0; i < chunks.length; i++) {
        final r = dec.pull(chunks[i]);
        expect(r.plaintext, plain[i]);
        expect(r.isFinal, i == chunks.length - 1);
      }
      dec.close();
      final mine = write(plain);
      expect(lib.streamDecrypt(key, mine.header, mine.chunks), plain);
      expect(chunks.map((c) => c.length), mine.chunks.map((c) => c.length));
      expect(lib.aead.streamDecrypt(key, mine.header, mine.chunks), plain);
      final (h0, c0) = lib.streamEncrypt(key, const []);
      expect(h0.length, 24);
      expect(c0, isEmpty);
      expect(
        () => lib.streamEncrypt(counting(31, 0), plain),
        fails(SecretStreamError.argument),
      );
      expect(
        () => lib.streamDecrypt(key, counting(23, 0), chunks),
        fails(SecretStreamError.argument),
      );
    });

    test('a truncated stream is detected by the missing final tag', () {
      final s = write(plain);
      final dec = lib.secretStreamDecryptor(key, s.header);
      for (final c in s.chunks.take(s.chunks.length - 1)) {
        expect(dec.pull(c).isFinal, isFalse);
      }
      expect(dec.isFinished, isFalse);
      dec.close();
      final cut = Uint8List.sublistView(s.chunks.last, 0, 40);
      final dec2 = lib.secretStreamDecryptor(key, s.header);
      for (final c in s.chunks.take(s.chunks.length - 1)) {
        dec2.pull(c);
      }
      expect(() => dec2.pull(cut), fails(SecretStreamError.invalid));
      expect(dec2.isFinished, isFalse);
      expect(dec2.pull(s.chunks.last).isFinal, isTrue);
      dec2.close();
    });

    test('reordered, duplicated, tampered and foreign chunks are refused', () {
      final s = write(plain);
      final other = write(plain);
      final dec = lib.secretStreamDecryptor(key, s.header);
      expect(() => dec.pull(s.chunks[1]), fails(SecretStreamError.invalid));
      expect(dec.pull(s.chunks[0]).plaintext, plain[0]);
      expect(() => dec.pull(s.chunks[0]), fails(SecretStreamError.invalid));
      expect(() => dec.pull(s.chunks[2]), fails(SecretStreamError.invalid));
      expect(() => dec.pull(other.chunks[1]), fails(SecretStreamError.invalid));
      for (final bit in [0, 7, 8 * 50, 8 * s.chunks[1].length - 1]) {
        final bad = Uint8List.fromList(s.chunks[1]);
        bad[bit ~/ 8] ^= 1 << (bit % 8);
        expect(() => dec.pull(bad), fails(SecretStreamError.invalid));
      }
      final longer = Uint8List.fromList([...s.chunks[1], 0]);
      expect(() => dec.pull(longer), fails(SecretStreamError.invalid));
      expect(() => dec.pull(Uint8List(0)), fails(SecretStreamError.invalid));
      expect(() => dec.pull(Uint8List(16)), fails(SecretStreamError.invalid));
      expect(
        () => dec.pull(s.chunks.last),
        fails(SecretStreamError.invalid),
      );
      for (var i = 1; i < plain.length; i++) {
        expect(dec.pull(s.chunks[i]).plaintext, plain[i]);
      }
      expect(dec.isFinished, isTrue);
      dec.close();
      final wrongKey = lib.secretStreamDecryptor(otherKey, s.header);
      expect(
        () => wrongKey.pull(s.chunks[0]),
        fails(SecretStreamError.invalid),
      );
      wrongKey.close();
      final wrongHeader = lib.secretStreamDecryptor(key, other.header);
      expect(
        () => wrongHeader.pull(s.chunks[0]),
        fails(SecretStreamError.invalid),
      );
      wrongHeader.close();
    });

    test('typed errors after the final chunk, after close, and for sizes', () {
      final enc = lib.secretStreamEncryptor(key);
      final first = enc.push(plain[0]);
      final last = enc.finish();
      expect(() => enc.push(plain[1]), fails(SecretStreamError.finished));
      expect(enc.finish, fails(SecretStreamError.finished));
      final header = enc.header;
      enc.close();
      expect(enc.isClosed, isTrue);
      enc.close();
      expect(() => enc.push(plain[1]), fails(SecretStreamError.closed));
      expect(enc.header, header);
      final dec = lib.secretStreamDecryptor(key, header);
      dec.pull(first);
      expect(dec.pull(last).isFinal, isTrue);
      expect(() => dec.pull(first), fails(SecretStreamError.finished));
      dec.close();
      dec.close();
      expect(dec.isClosed, isTrue);
      expect(() => dec.pull(first), fails(SecretStreamError.closed));
      final open = lib.secretStreamEncryptor(key)..close();
      expect(() => open.push(plain[0]), fails(SecretStreamError.closed));
      for (final n in [0, 16, 31, 33, 64]) {
        expect(
          () => lib.secretStreamEncryptor(Uint8List(n)),
          fails(SecretStreamError.argument),
        );
        expect(
          () => lib.secretStreamDecryptor(Uint8List(n), header),
          fails(SecretStreamError.argument),
        );
      }
      for (final n in [0, 23, 25]) {
        expect(
          () => lib.secretStreamDecryptor(key, Uint8List(n)),
          fails(SecretStreamError.argument),
        );
      }
      expect(
        '${const SecretStreamException(SecretStreamError.closed)}',
        contains('closed'),
      );
    });

    test('objects dropped without close are left to the finalizer', () {
      for (var i = 0; i < 2000; i++) {
        final enc = lib.secretStreamEncryptor(key);
        final c = enc.push(plain[0]);
        final dec = lib.secretStreamDecryptor(key, enc.header);
        expect(dec.pull(c).plaintext, plain[0]);
      }
    });

    test('a recording-sized stream passes through in flat memory', () {
      const chunkSize = 64 * 1024;
      const chunks = isWeb ? 64 : 3200;
      int rss() => isWeb ? 0 : ProcessInfo.currentRss;
      final enc = lib.secretStreamEncryptor(key);
      final dec = lib.secretStreamDecryptor(key, enc.header);
      var baseline = 0;
      var peak = 0;
      var total = 0;
      for (var i = 0; i < chunks; i++) {
        final p = chunkOf(i, chunkSize);
        final last = i == chunks - 1;
        final c = last ? enc.finish(p) : enc.push(p);
        final r = dec.pull(c);
        if (i % 97 == 0 || last) {
          expect(r.plaintext, p, reason: 'chunk $i');
        }
        expect(r.plaintext.length, chunkSize);
        expect(r.isFinal, last);
        total += r.plaintext.length;
        if (i == 400) {
          baseline = rss();
        }
        if (i > 400 && i % 50 == 0) {
          final now = rss();
          peak = now > peak ? now : peak;
        }
      }
      enc.close();
      dec.close();
      expect(dec.isFinished, isTrue);
      expect(total, chunks * chunkSize);
      if (!isWeb) {
        final grown = (peak - baseline) / (1024 * 1024);
        final megabytes = total / (1024 * 1024);
        printOnFailure('rss grew $grown MiB over $megabytes MiB');
        expect(megabytes, 200);
        expect(grown, lessThan(48));
        stdout.writeln(
          'secret stream: ${megabytes.toStringAsFixed(0)} MiB in 64 KiB '
          'chunks, resident memory grew ${grown.toStringAsFixed(1)} MiB '
          'after warm-up',
        );
      }
    });
  });
}
