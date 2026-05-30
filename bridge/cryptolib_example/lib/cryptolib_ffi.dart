// Minimal Dart FFI bindings for cryptolib.
//
// Loads the native library from:
//   • iOS:     process-linked (symbols are part of the app binary via the
//              vendored CryptoLib.xcframework → Embed & Sign)
//   • Android: libcryptolib_c.so (placed in android/app/src/main/jniLibs/<abi>/)
//   • macOS:   libcryptolib_c.dylib (the existing Homebrew build)
//
// Exposes only a handful of C FFI functions — enough to prove the bridge
// works end-to-end on every platform. See bridge/flutter/lib/cryptolib_ffi.dart
// for the full surface (~74 functions).

import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

/// libcryptolib_c loaded on whichever platform we're running on.
DynamicLibrary _openLib() {
  if (Platform.isIOS) {
    // On iOS the static archive from CryptoLib.xcframework is linked into
    // the app binary — symbols are resolvable against the process itself.
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libcryptolib_c.so');
  }
  if (Platform.isMacOS) {
    return DynamicLibrary.open('libcryptolib_c.dylib');
  }
  if (Platform.isLinux) {
    return DynamicLibrary.open('libcryptolib_c.so');
  }
  throw UnsupportedError('Unsupported platform: ${Platform.operatingSystem}');
}

final DynamicLibrary _dylib = _openLib();

// ─── C struct mirrors ──────────────────────────────────────────────────────

final class CryptoBuffer extends Struct {
  external Pointer<Uint8> data;
  @Size()
  external int len;
}

final class CryptoBufferResult extends Struct {
  external CryptoBuffer buf;
  external Pointer<Utf8> error;
}

// ─── C function signatures ─────────────────────────────────────────────────

typedef _InitC = Int32 Function();
typedef _InitDart = int Function();

typedef _VersionC = Pointer<Utf8> Function();
typedef _VersionDart = Pointer<Utf8> Function();

typedef _Blake2bC = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> key, Size keyLen);
typedef _Blake2bDart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> key, int keyLen);

typedef _SymKeygenC = CryptoBufferResult Function();
typedef _SymKeygenDart = CryptoBufferResult Function();

typedef _EncryptC = CryptoBufferResult Function(
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Uint8> key, Size keyLen,
    Pointer<Uint8> aad, Size aadLen);
typedef _EncryptDart = CryptoBufferResult Function(
    Pointer<Uint8> pt, int ptLen,
    Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> aad, int aadLen);

typedef _FreeBufC = Void Function(Pointer<CryptoBuffer> buf);
typedef _FreeBufDart = void Function(Pointer<CryptoBuffer> buf);

typedef _FreeStrC = Void Function(Pointer<Utf8> str);
typedef _FreeStrDart = void Function(Pointer<Utf8> str);

typedef _BoolSpanC = Int32 Function(
    Pointer<Uint8> a, Size aLen, Pointer<Uint8> b, Size bLen);
typedef _BoolSpanDart = int Function(
    Pointer<Uint8> a, int aLen, Pointer<Uint8> b, int bLen);

// ─── Lookups (lazy, cached) ────────────────────────────────────────────────

final _init        = _dylib.lookupFunction<_InitC, _InitDart>('cryptolib_init');
final _version     = _dylib.lookupFunction<_VersionC, _VersionDart>('cryptolib_version');
final _blake2b     = _dylib.lookupFunction<_Blake2bC, _Blake2bDart>('cryptolib_blake2b');
final _symKeygen   = _dylib.lookupFunction<_SymKeygenC, _SymKeygenDart>('cryptolib_sym_keygen');
final _xchaEncrypt = _dylib.lookupFunction<_EncryptC, _EncryptDart>('cryptolib_xchacha20_encrypt');
final _xchaDecrypt = _dylib.lookupFunction<_EncryptC, _EncryptDart>('cryptolib_xchacha20_decrypt');
final _bufFree     = _dylib.lookupFunction<_FreeBufC, _FreeBufDart>('cryptolib_buffer_free');
final _strFree     = _dylib.lookupFunction<_FreeStrC, _FreeStrDart>('cryptolib_str_free');
final _secEqual    = _dylib.lookupFunction<_BoolSpanC, _BoolSpanDart>('cryptolib_secure_equal');

// ─── Helpers ────────────────────────────────────────────────────────────────

class CryptoException implements Exception {
  final String message;
  CryptoException(this.message);
  @override
  String toString() => 'CryptoException: $message';
}

/// Copy a returned CryptoBuffer into a Dart [Uint8List] and free the C buffer.
Uint8List _takeBuf(CryptoBuffer buf) {
  if (buf.data == nullptr || buf.len == 0) return Uint8List(0);
  final out = Uint8List(buf.len);
  out.setAll(0, buf.data.asTypedList(buf.len));
  final p = calloc<CryptoBuffer>()
    ..ref.data = buf.data
    ..ref.len = buf.len;
  _bufFree(p);
  calloc.free(p);
  return out;
}

/// Unwrap a CryptoBufferResult to Uint8List or throw on error.
Uint8List _unwrap(CryptoBufferResult r) {
  if (r.error != nullptr) {
    final msg = r.error.toDartString();
    _strFree(r.error);
    throw CryptoException(msg);
  }
  return _takeBuf(r.buf);
}

/// Copy a Dart Uint8List into a freshly-malloc'd native buffer.
/// Caller must `calloc.free(ptr)` when done.
Pointer<Uint8> _toNative(Uint8List data) {
  final p = calloc<Uint8>(data.length);
  if (data.isNotEmpty) {
    p.asTypedList(data.length).setAll(0, data);
  }
  return p;
}

// ─── Public API ─────────────────────────────────────────────────────────────

class CryptoLib {
  /// Initialise libsodium. Call once at startup.
  static void init() {
    if (_init() != 0) throw CryptoException('cryptolib_init failed');
  }

  /// Version string baked into the native library.
  static String version() => _version().toDartString();

  /// BLAKE2b-512 hash of [msg]. Returns 64-byte digest.
  static Uint8List blake2b(Uint8List msg) {
    final p = _toNative(msg);
    try {
      return _unwrap(_blake2b(p, msg.length, nullptr, 0));
    } finally {
      calloc.free(p);
    }
  }

  /// Generate a fresh 32-byte symmetric key (CSPRNG).
  static Uint8List symKeygen() => _unwrap(_symKeygen());

  /// XChaCha20-Poly1305 encrypt. Output = nonce(24) ‖ ciphertext ‖ MAC(16).
  static Uint8List xchaEncrypt(Uint8List plaintext, Uint8List key, {Uint8List? aad}) {
    final pp = _toNative(plaintext);
    final kk = _toNative(key);
    final aa = aad != null && aad.isNotEmpty ? _toNative(aad) : nullptr;
    final aaLen = aad?.length ?? 0;
    try {
      return _unwrap(_xchaEncrypt(pp, plaintext.length, kk, key.length, aa, aaLen));
    } finally {
      calloc.free(pp);
      calloc.free(kk);
      if (aa != nullptr) calloc.free(aa);
    }
  }

  /// XChaCha20-Poly1305 decrypt. Input must include the nonce prefix.
  static Uint8List xchaDecrypt(Uint8List ciphertext, Uint8List key, {Uint8List? aad}) {
    final pc = _toNative(ciphertext);
    final kk = _toNative(key);
    final aa = aad != null && aad.isNotEmpty ? _toNative(aad) : nullptr;
    final aaLen = aad?.length ?? 0;
    try {
      return _unwrap(_xchaDecrypt(pc, ciphertext.length, kk, key.length, aa, aaLen));
    } finally {
      calloc.free(pc);
      calloc.free(kk);
      if (aa != nullptr) calloc.free(aa);
    }
  }

  /// Constant-time equality check.
  static bool secureEqual(Uint8List a, Uint8List b) {
    final pa = _toNative(a);
    final pb = _toNative(b);
    try {
      return _secEqual(pa, a.length, pb, b.length) == 1;
    } finally {
      calloc.free(pa);
      calloc.free(pb);
    }
  }
}

/// Hex encoding helper.
String toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
