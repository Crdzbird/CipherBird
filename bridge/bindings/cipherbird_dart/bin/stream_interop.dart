/// Cross-language SecretStream interop: write a chunked stream to a file, or
/// read one and report what it held. The Go program
/// bridge/bindings/go/streaminterop speaks the same file layout, and
/// scripts/verify_stream_interop.sh runs each against the other.
///
///     dart run bin/stream_interop.dart write <file> <chunks> <dylib>
///     dart run bin/stream_interop.dart read <file> <dylib>
///
/// File layout: the 24-byte stream header, then for every chunk a 4-byte
/// big-endian ciphertext length and the ciphertext. Plaintext chunk i is
/// 64 KiB of (i*31 + j*7) mod 256; the last chunk is half that size and
/// carries the final tag. Both commands print
///
///     digest <hex> chunks <n> final <true|false>
///
/// where digest starts as 32 zero bytes and becomes
/// SHA-256(digest || SHA-256(chunk)) for every plaintext chunk in order.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

const keyHex =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const int chunkSize = 64 * 1024;

Never fail(String message) {
  stderr.writeln('FAIL $message');
  exit(1);
}

Uint8List hx(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);

String hex(Uint8List b) =>
    b.map((v) => v.toRadixString(16).padLeft(2, '0')).join();

Uint8List chunkOf(int index, int size) {
  final out = Uint8List(size);
  for (var j = 0; j < size; j++) {
    out[j] = (index * 31 + j * 7) & 0xff;
  }
  return out;
}

Uint8List mix(CipherBird lib, Uint8List digest, Uint8List chunk) =>
    lib.sha256(Uint8List.fromList([...digest, ...lib.sha256(chunk)]));

void write(CipherBird lib, String path, int chunks) {
  final enc = lib.secretStreamEncryptor(hx(keyHex));
  final file = File(path).openSync(mode: FileMode.write);
  var digest = Uint8List(32);
  try {
    file.writeFromSync(enc.header);
    for (var i = 0; i < chunks; i++) {
      final last = i == chunks - 1;
      final plain = chunkOf(i, last ? chunkSize ~/ 2 : chunkSize);
      final ct = last ? enc.finish(plain) : enc.push(plain);
      final length = ByteData(4)..setUint32(0, ct.length);
      file
        ..writeFromSync(length.buffer.asUint8List())
        ..writeFromSync(ct);
      digest = mix(lib, digest, plain);
    }
  } finally {
    file.closeSync();
    enc.close();
  }
  print('digest ${hex(digest)} chunks $chunks final true');
}

void read(CipherBird lib, String path) {
  final file = File(path).openSync();
  var digest = Uint8List(32);
  var chunks = 0;
  SecretStreamDecryptor? dec;
  try {
    final header = file.readSync(24);
    if (header.length != 24) fail('header is cut short');
    final reader = dec = lib.secretStreamDecryptor(hx(keyHex), header);
    while (true) {
      final length = file.readSync(4);
      if (length.isEmpty) break;
      if (length.length != 4) fail('length is cut short');
      if (reader.isFinished) fail('data after the final chunk');
      final size = ByteData.sublistView(length).getUint32(0);
      final ct = file.readSync(size);
      if (ct.length != size) fail('chunk $chunks is cut short');
      try {
        digest = mix(lib, digest, reader.pull(ct).plaintext);
      } on SecretStreamException catch (e) {
        fail('chunk $chunks rejected: $e');
      }
      chunks++;
    }
    print('digest ${hex(digest)} chunks $chunks final ${reader.isFinished}');
  } finally {
    file.closeSync();
    dec?.close();
  }
}

void main(List<String> args) {
  if (args.length == 4 && args[0] == 'write') {
    final n = int.tryParse(args[2]);
    if (n == null || n < 1) fail('chunks must be a positive number');
    return write(CipherBird.load(args[3]), args[1], n);
  }
  if (args.length == 3 && args[0] == 'read') {
    return read(CipherBird.load(args[2]), args[1]);
  }
  fail(
    'usage: stream_interop.dart write <file> <chunks> <dylib> | '
    'read <file> <dylib>',
  );
}
