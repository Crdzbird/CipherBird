// Dart/Flutter "party" for the Go <-> Flutter/Dart interop example.
//
// This uses package:cryptolib_dart — the exact same dart:ffi binding the
// Flutter plugin ships, so its behaviour is identical to a real Flutter app.
//
// Usage: dart run bin/interop_party.dart <dylib> <cmd> [args...]
//
//	<dylib> keygen                                       -> "<pubHex> <secHex>"
//	<dylib> enc <recipientPubHex> <senderSecHex> <msg>   -> "<ciphertextHex>"
//	<dylib> dec <senderPubHex> <recipientSecHex> <ctHex> -> decrypted UTF-8
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

Uint8List unhex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String hexOf(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void die(String msg) {
  stderr.writeln('dart-party: $msg');
  exit(1);
}

void main(List<String> args) {
  if (args.length < 2) {
    die('usage: <dylib> keygen | enc <recipPub> <senderSec> <msg> '
        '| dec <senderPub> <recipSec> <ct>');
  }
  final lib = CryptoLib.load(args[0]);
  lib.init();
  final cmd = args[1];

  switch (cmd) {
    case 'keygen':
      final kp = lib.boxKeygen();
      stdout.writeln('${hexOf(kp.publicKey)} ${hexOf(kp.secretKey)}');
    case 'enc':
      if (args.length != 5)
        die('enc needs <recipientPubHex> <senderSecHex> <msg>');
      final ct = lib.boxEncrypt(
        Uint8List.fromList(utf8.encode(args[4])),
        unhex(args[2]),
        unhex(args[3]),
      );
      stdout.writeln(hexOf(ct));
    case 'dec':
      if (args.length != 5)
        die('dec needs <senderPubHex> <recipientSecHex> <ctHex>');
      final pt = lib.boxDecrypt(unhex(args[4]), unhex(args[2]), unhex(args[3]));
      stdout.writeln(utf8.decode(pt));
    default:
      die('unknown command: $cmd');
  }
}
