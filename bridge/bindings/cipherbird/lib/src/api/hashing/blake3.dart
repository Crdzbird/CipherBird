part of '../../cipher_bird.dart';

/// Hashing operations.
extension CipherBirdBlake3 on CipherBird {
  /// BLAKE3 keyed MAC. [key] must be exactly 32 bytes. [outLen] defaults to 32.
  Uint8List blake3Keyed(Uint8List msg, Uint8List key, {int outLen = 32}) {
    if (key.length != 32) {
      throw ArgumentError(
        'BLAKE3 keyed MAC requires a 32-byte key, got ${key.length}',
      );
    }
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_blake3_keyed')(pm, msg.length, pk, key.length, outLen),
      );
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// BLAKE3 key derivation. [context] is a hard-coded, application-unique
  /// domain-separation string; [ikm] is the input key material. [outLen]
  /// defaults to 32.
  Uint8List blake3DeriveKey(String context, Uint8List ikm, {int outLen = 32}) {
    final cc = context.toNativeUtf8();
    final pk = _toNative(ikm);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_blake3_derive_key')(cc, pk, ikm.length, outLen),
      );
    } finally {
      calloc.free(cc);
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// BLAKE3 hash. [outLen] is the extendable output length in bytes
  /// (defaults to 32). Pass a larger value to use BLAKE3 as an XOF.
  Uint8List blake3(Uint8List msg, {int outLen = 32}) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Uint8>, Size, Size),
          CipherBirdBufferResult Function(Pointer<Uint8>, int, int)
        >('cryptolib_blake3')(pm, msg.length, outLen),
      );
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
    }
  }
}
