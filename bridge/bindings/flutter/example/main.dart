/// CryptoLib Flutter/Dart Example
///
/// Demonstrates using the CryptoLib C FFI bridge from Dart.
///
/// Build the shared library first:
///   cd /path/to/cryptolib
///   cmake -B build/release -DCMAKE_BUILD_TYPE=Release
///   cmake --build build/release --target cryptolib_c
///
/// Run:
///   cd bridge/flutter
///   dart run example/main.dart /path/to/libcryptolib_c.dylib [path/to/photo.jpg]
import 'dart:io';
import 'dart:typed_data';

import '../lib/cryptolib_ffi.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    print('Usage: dart run example/main.dart <path/to/libcryptolib_c.dylib> [photo.jpg]');
    print('');
    print('  First argument:  path to the compiled shared library');
    print('  Second argument: (optional) path to a media file for entropy demos');
    exit(1);
  }

  final libPath = args[0];
  final photoPath = args.length > 1 ? args[1] : null;

  // ── Load and initialise ──────────────────────────────────────────────────
  final lib = CryptoLib.load(libPath);
  lib.init();
  print('CryptoLib ${lib.version()} — Dart/Flutter example\n');

  // ── 1. Hashing ───────────────────────────────────────────────────────────
  print('═══ Hashing ═══');
  final msg = Uint8List.fromList('The quick brown fox jumps over the lazy dog'.codeUnits);
  final hash = lib.blake2b(msg);
  print('  BLAKE2b-512:       ${toHex(hash).substring(0, 48)}...');
  final sha = lib.sha256(msg);
  print('  SHA-256:           ${toHex(sha)}');

  // ── 2. Symmetric encryption ──────────────────────────────────────────────
  print('\n═══ Symmetric Encryption ═══');
  final key = lib.symKeygen();
  print('  Key:               ${toHex(key).substring(0, 32)}...');

  final plaintext = Uint8List.fromList('Dart says hello to XChaCha20!'.codeUnits);
  final ct = lib.xchacha20Encrypt(plaintext, key);
  print('  Ciphertext:        ${toHex(ct).substring(0, 48)}...');

  final pt = lib.xchacha20Decrypt(ct, key);
  print('  Decrypted:         ${String.fromCharCodes(pt)}');

  // ── 3. Media Entropy ─────────────────────────────────────────────────────
  print('\n═══ Media Entropy — Your Files Are Your Keys ═══');

  if (photoPath == null) {
    print('  No media file provided. Pass a photo/audio path as second argument.');
    print('  Example: dart run example/main.dart libcryptolib_c.dylib ~/Photos/vacation.jpg');
    print('\nDone.');
    return;
  }

  print('  Entropy source: $photoPath\n');

  // 3a. Derive a key from the file
  final fileKey = lib.keyFromFile(photoPath);
  print('  Derived key:       ${toHex(fileKey)}');

  // 3b. Encrypt with the file-derived key
  final secret = Uint8List.fromList('Only someone with this file can read this.'.codeUnits);
  final fileCt = lib.xchacha20Encrypt(secret, fileKey);
  final filePt = lib.xchacha20Decrypt(fileCt, fileKey);
  print('  Decrypted:         ${String.fromCharCodes(filePt)}');
  print('  ✓ Encrypted/decrypted using file-derived key');

  // 3c. One-liner: seal_from_file / open_from_file
  print('\n  ── Convenience one-liner ──');
  final pkt = lib.sealFromFile(photoPath, 'Sealed by my photo!', 'dart-demo');
  final opened = lib.openFromFile(photoPath, pkt, 'dart-demo');
  print('  Opened:            ${String.fromCharCodes(opened)}');
  print('  ✓ seal_from_file / open_from_file round-trip');

  // 3d. Full entropy handle — get info
  print('\n  ── Full entropy handle ──');
  final me = lib.entropyFromFileDeterministic(photoPath);
  final info = lib.entropyInfo(me);
  print('  File size:         ${info.fileSize} bytes');
  print('  Entropy estimate:  ${info.entropyBits.toInt()} bits');

  // 3e. Build vault from entropy
  print('\n  ── Vault from entropy ──');
  final vault = lib.vaultFromEntropy(me);
  final vaultPt = Uint8List.fromList('Vault-encrypted with file entropy'.codeUnits);
  final vaultPkt = lib.vaultSeal(vault, vaultPt, 'dart:vault');
  final vaultDec = lib.vaultOpen(vault, vaultPkt, 'dart:vault');
  print('  Vault decrypted:   ${String.fromCharCodes(vaultDec)}');
  print('  ✓ Full 4-layer vault pipeline from file entropy');

  // Cleanup
  lib.vaultFree(vault);
  lib.entropyFree(me);

  print('\nDone.');
}
