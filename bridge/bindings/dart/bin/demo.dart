// Standalone dart:ffi console demo for CryptoLib.
//
// Reuses the same bindings the Flutter plugin uses (lib/cryptolib_ffi.dart).
// Run (see Makefile target `dart`):
//   dart pub get
//   dart run bin/demo.dart <path-to-libcryptolib_c.dylib>

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main(List<String> args) {
  final path =
      args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib';

  final lib = CryptoLib.load(path);
  lib.init();
  stdout.writeln('CryptoLib version: ${lib.version()}');
  stdout.writeln('random(32):  ${hex(lib.randomBytes(32))}');
  stdout.writeln(
      'sha256(abc): ${hex(lib.sha256(Uint8List.fromList('abc'.codeUnits)))}');

  final vault = lib.vaultCreate(lib.randomBytes(32));
  final pkt = lib.vaultSeal(
      vault, Uint8List.fromList('hello from dart'.codeUnits), 'ctx');
  final opened = lib.vaultOpen(vault, pkt, 'ctx');
  stdout.writeln('vault roundtrip: "${String.fromCharCodes(opened)}"');

  lib.vaultFree(vault);

  // Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
  final factor = lib.randomBytes(32); // stands in for a hardware factor key
  final kr = lib.keyringCreate();
  lib.keyringAddDeviceSlot(kr, factor);
  lib.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
  final blob = lib.keyringSerialise(kr);
  final kr2 = lib.keyringDeserialise(blob);
  final mDev = lib.keyringUnlockWithDevice(kr2, factor);
  final mPass = lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
  stdout.writeln('keyring slots: ${lib.keyringSlotCount(kr)} '
      '· device==passphrase master: ${hex(mDev) == hex(mPass)}');
  lib.keyringFree(kr);
  lib.keyringFree(kr2);

  stdout.writeln('Dart demo OK');
}
